#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::collections::VecDeque;
use std::fs;
use std::mem;
use std::sync::{
    Arc, Once,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_bindings::{
    KVM_PIT_SPEAKER_DUMMY, Msrs, kvm_fpu, kvm_lapic_state, kvm_msr_entry, kvm_pit_config,
    kvm_segment, kvm_sregs, kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use mimobox_core::SandboxConfig;
use tracing::{debug, info};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::vm::{GuestCommandResult, MicrovmConfig, MicrovmError};

const ZERO_PAGE_ADDR: u64 = 0x7_000;
const CMDLINE_ADDR: u64 = 0x20_000;
const ROOTFS_METADATA_ADDR: u64 = 0x30_000;
const BOOT_READY_TIMEOUT_SECS: u64 = 30;
#[cfg(target_arch = "x86_64")]
const BOOT_STACK_POINTER: u64 = 0x8_000;
#[cfg(target_arch = "x86_64")]
const BOOT_GDT_OFFSET: u64 = 0x500;
#[cfg(target_arch = "x86_64")]
const BOOT_IDT_OFFSET: u64 = 0x520;
#[cfg(target_arch = "x86_64")]
const BOOT_PML4_START: u64 = 0x9000;
#[cfg(target_arch = "x86_64")]
const BOOT_PDPTE_START: u64 = 0xa000;
#[cfg(target_arch = "x86_64")]
const BOOT_PDE_START: u64 = 0xb000;
#[cfg(target_arch = "x86_64")]
const BOOT_GDT_MAX: usize = 4;
#[cfg(target_arch = "x86_64")]
const KVM_IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;
#[cfg(target_arch = "x86_64")]
const KVM_TSS_ADDR: usize = 0xfffb_d000;
const DEFAULT_CMDLINE: &str = "console=ttyS0 i8042.nokbd reboot=t panic=1 pci=off rdinit=/init";
const SERIAL_PORT_COM1: u16 = 0x3f8;
const SERIAL_PORT_LAST: u16 = SERIAL_PORT_COM1 + 7;
const SERIAL_READY_LINE: &str = "READY";
const SERIAL_EXEC_PREFIX: &str = "EXEC:";
const SERIAL_OUTPUT_PREFIX: &str = "OUTPUT:";
const SERIAL_EXIT_PREFIX: &str = "EXIT:";
const SERIAL_TIMEOUT_EXIT_CODE: i32 = 124;
const WATCHDOG_SIGNAL: libc::c_int = libc::SIGUSR1;
const I8042_PORT_B_REG: u16 = 0x61;
const I8042_COMMAND_REG: u16 = 0x64;
const I8042_PORT_B_PIT_TICK: u8 = 0x20;
const I8042_RESET_CMD: u8 = 0xfe;
const PCI_CONFIG_ADDRESS_REG: u16 = 0xcf8;
const PCI_CONFIG_DATA_REG_START: u16 = 0xcfc;
const PCI_CONFIG_DATA_REG_END: u16 = 0xcff;
const UART_REG_DATA: u16 = 0;
const UART_REG_INTERRUPT_ENABLE: u16 = 1;
const UART_REG_INTERRUPT_IDENT: u16 = 2;
const UART_REG_LINE_CONTROL: u16 = 3;
const UART_REG_MODEM_CONTROL: u16 = 4;
const UART_REG_LINE_STATUS: u16 = 5;
const UART_REG_MODEM_STATUS: u16 = 6;
const UART_REG_SCRATCH: u16 = 7;
const UART_LCR_DLAB: u8 = 0x80;
const UART_LSR_DATA_READY: u8 = 0x01;
const UART_LSR_THR_EMPTY: u8 = 0x20;
const UART_LSR_TRANSMITTER_EMPTY: u8 = 0x40;
#[cfg(target_arch = "x86_64")]
const EFER_LME: u64 = 0x100;
#[cfg(target_arch = "x86_64")]
const EFER_LMA: u64 = 0x400;
#[cfg(target_arch = "x86_64")]
const X86_CR0_PE: u64 = 0x1;
#[cfg(target_arch = "x86_64")]
const X86_CR0_PG: u64 = 0x8000_0000;
#[cfg(target_arch = "x86_64")]
const X86_CR4_PAE: u64 = 0x20;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_SYSENTER_CS: u32 = 0x174;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_SYSENTER_EIP: u32 = 0x176;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_TSC: u32 = 0x10;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_MISC_ENABLE: u32 = 0x1a0;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_MISC_ENABLE_FAST_STRING: u64 = 1;
#[cfg(target_arch = "x86_64")]
const MSR_MTRR_DEF_TYPE: u32 = 0x2ff;
#[cfg(target_arch = "x86_64")]
const MSR_STAR: u32 = 0xc000_0081;
#[cfg(target_arch = "x86_64")]
const MSR_LSTAR: u32 = 0xc000_0082;
#[cfg(target_arch = "x86_64")]
const MSR_CSTAR: u32 = 0xc000_0083;
#[cfg(target_arch = "x86_64")]
const MSR_SYSCALL_MASK: u32 = 0xc000_0084;
#[cfg(target_arch = "x86_64")]
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;
#[cfg(target_arch = "x86_64")]
const APIC_LVT0_REG_OFFSET: usize = 0x350;
#[cfg(target_arch = "x86_64")]
const APIC_LVT1_REG_OFFSET: usize = 0x360;
#[cfg(target_arch = "x86_64")]
const APIC_MODE_EXTINT: i32 = 0x7;
#[cfg(target_arch = "x86_64")]
const APIC_MODE_NMI: i32 = 0x4;
const ZERO_PAGE_LEN: usize = 4096;
const PT_LOAD: u32 = 1;
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const SETUP_HDR_TYPE_OF_LOADER: usize = 0x210;
const SETUP_HDR_LOADFLAGS: usize = 0x211;
const SETUP_HDR_CODE32_START: usize = 0x214;
const SETUP_HDR_RAMDISK_IMAGE: usize = 0x218;
const SETUP_HDR_RAMDISK_SIZE: usize = 0x21c;
const SETUP_HDR_CMD_LINE_PTR: usize = 0x228;
const ZERO_PAGE_E820_ENTRIES: usize = 0x1e8;
const ZERO_PAGE_SENTINEL: usize = 0x1ef;
const SETUP_HDR_BOOT_FLAG: usize = 0x1fe;
const SETUP_HDR_HEADER_MAGIC: usize = 0x202;
const ZERO_PAGE_EXT_RAMDISK_IMAGE: usize = 0x0c0;
const ZERO_PAGE_EXT_RAMDISK_SIZE: usize = 0x0c4;
const ZERO_PAGE_EXT_CMD_LINE_PTR: usize = 0x0c8;
const ZERO_PAGE_E820_TABLE: usize = 0x2d0;
const SETUP_HDR_KERNEL_ALIGNMENT: usize = 0x230;
const E820_ENTRY_SIZE: usize = 20;
const E820_RAM: u32 = 1;
const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;
const EBDA_START: u64 = 0x0009_fc00;
const HIMEM_START: u64 = 0x0010_0000;

/// 命令通道类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmTransport {
    Serial,
    Vsock,
}

/// KVM 后端生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmLifecycle {
    Created,
    Ready,
    Running,
    Destroyed,
}

/// `KVM_RUN` 循环处理后的退出原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmExitReason {
    Io,
    Hlt,
    Shutdown,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedKernel {
    entry_point: u64,
    high_watermark: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SerialDevice {
    rx_fifo: VecDeque<u8>,
    interrupt_enable: u8,
    line_control: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    divisor_latch_low: u8,
    divisor_latch_high: u8,
}

impl Default for SerialDevice {
    fn default() -> Self {
        Self {
            rx_fifo: VecDeque::new(),
            interrupt_enable: 0,
            line_control: 0x03,
            modem_control: 0x03,
            modem_status: 0xb0,
            scratch: 0,
            divisor_latch_low: 0,
            divisor_latch_high: 0,
        }
    }
}

impl SerialDevice {
    fn queue_input(&mut self, bytes: &[u8]) {
        self.rx_fifo.extend(bytes.iter().copied());
    }

    fn read(&mut self, port: u16) -> Result<u8, MicrovmError> {
        let register = port
            .checked_sub(SERIAL_PORT_COM1)
            .ok_or_else(|| MicrovmError::Backend(format!("非法串口读端口: {port:#x}")))?;

        let value = match register {
            UART_REG_DATA => {
                if self.dlab_enabled() {
                    self.divisor_latch_low
                } else {
                    self.rx_fifo.pop_front().unwrap_or_default()
                }
            }
            UART_REG_INTERRUPT_ENABLE => {
                if self.dlab_enabled() {
                    self.divisor_latch_high
                } else {
                    self.interrupt_enable
                }
            }
            UART_REG_INTERRUPT_IDENT => {
                if self.rx_fifo.is_empty() {
                    0x01
                } else {
                    0x04
                }
            }
            UART_REG_LINE_CONTROL => self.line_control,
            UART_REG_MODEM_CONTROL => self.modem_control,
            UART_REG_LINE_STATUS => self.line_status(),
            UART_REG_MODEM_STATUS => self.modem_status,
            UART_REG_SCRATCH => self.scratch,
            other => {
                return Err(MicrovmError::Backend(format!(
                    "未实现的串口读寄存器: {other:#x}"
                )));
            }
        };

        Ok(value)
    }

    fn write(&mut self, port: u16, value: u8) -> Result<Option<u8>, MicrovmError> {
        let register = port
            .checked_sub(SERIAL_PORT_COM1)
            .ok_or_else(|| MicrovmError::Backend(format!("非法串口写端口: {port:#x}")))?;

        match register {
            UART_REG_DATA => {
                if self.dlab_enabled() {
                    self.divisor_latch_low = value;
                    Ok(None)
                } else {
                    Ok(Some(value))
                }
            }
            UART_REG_INTERRUPT_ENABLE => {
                if self.dlab_enabled() {
                    self.divisor_latch_high = value;
                } else {
                    self.interrupt_enable = value;
                }
                Ok(None)
            }
            UART_REG_INTERRUPT_IDENT => Ok(None),
            UART_REG_LINE_CONTROL => {
                self.line_control = value;
                Ok(None)
            }
            UART_REG_MODEM_CONTROL => {
                self.modem_control = value;
                Ok(None)
            }
            UART_REG_LINE_STATUS | UART_REG_MODEM_STATUS => Ok(None),
            UART_REG_SCRATCH => {
                self.scratch = value;
                Ok(None)
            }
            other => Err(MicrovmError::Backend(format!(
                "未实现的串口写寄存器: {other:#x}"
            ))),
        }
    }

    fn restore(&mut self, fifo: Vec<u8>, registers: [u8; 7]) {
        self.rx_fifo = fifo.into_iter().collect();
        self.interrupt_enable = registers[0];
        self.line_control = registers[1];
        self.modem_control = registers[2];
        self.modem_status = registers[3];
        self.scratch = registers[4];
        self.divisor_latch_low = registers[5];
        self.divisor_latch_high = registers[6];
    }

    fn snapshot_registers(&self) -> [u8; 7] {
        [
            self.interrupt_enable,
            self.line_control,
            self.modem_control,
            self.modem_status,
            self.scratch,
            self.divisor_latch_low,
            self.divisor_latch_high,
        ]
    }

    fn dlab_enabled(&self) -> bool {
        (self.line_control & UART_LCR_DLAB) != 0
    }

    fn line_status(&self) -> u8 {
        let mut status = UART_LSR_THR_EMPTY | UART_LSR_TRANSMITTER_EMPTY;
        if !self.rx_fifo.is_empty() {
            status |= UART_LSR_DATA_READY;
        }
        status
    }
}

#[derive(Debug, Default)]
struct CommandResponse {
    stdout: Vec<u8>,
}

#[derive(Debug)]
enum RunLoopOutcome {
    Exit(KvmExitReason),
    CommandDone(GuestCommandResult),
}

static WATCHDOG_SIGNAL_HANDLER_INIT: Once = Once::new();

extern "C" fn handle_watchdog_signal(_: libc::c_int) {}

#[derive(Debug)]
struct VcpuRunWatchdog {
    cancel: Option<mpsc::Sender<()>>,
    fired: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl VcpuRunWatchdog {
    fn start(vcpu: &mut VcpuFd, timeout: Duration) -> Self {
        install_watchdog_signal_handler();

        let immediate_exit_ptr = (&mut vcpu.get_kvm_run().immediate_exit as *mut u8) as usize;
        // SAFETY: `pthread_self` 仅返回当前线程标识，不触碰 Rust 内存模型。
        let target_thread = unsafe { libc::pthread_self() };
        vcpu.set_kvm_immediate_exit(0);

        let (tx, rx) = mpsc::channel();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        let handle = thread::spawn(move || {
            if rx.recv_timeout(timeout).is_err() {
                fired_clone.store(true, Ordering::SeqCst);

                // SAFETY: `immediate_exit_ptr` 指向当前 vCPU 对应 `kvm_run` 映射中的
                // `immediate_exit` 字段。watchdog 生命周期严格包裹一次 run loop，
                // 在 `drop` 时会先通知线程停止再 join，确保该指针不会在映射失效后被访问。
                unsafe {
                    std::ptr::write_volatile(immediate_exit_ptr as *mut u8, 1);
                    libc::pthread_kill(target_thread, WATCHDOG_SIGNAL);
                }
            }
        });

        Self {
            cancel: Some(tx),
            fired,
            handle: Some(handle),
        }
    }

    fn timed_out(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl Drop for VcpuRunWatchdog {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Linux KVM 后端基础实现。
pub struct KvmBackend {
    base_config: SandboxConfig,
    config: MicrovmConfig,
    kvm: Kvm,
    vm_fd: VmFd,
    vcpus: Vec<VcpuFd>,
    guest_memory: GuestMemoryMmap,
    kernel_bytes: Vec<u8>,
    rootfs_bytes: Vec<u8>,
    transport: KvmTransport,
    lifecycle: KvmLifecycle,
    last_command_payload: Vec<u8>,
    loaded_kernel: LoadedKernel,
    boot_params_addr: u64,
    cmdline_addr: u64,
    initrd_addr: u64,
    guest_booted: bool,
    guest_ready: bool,
    serial_device: SerialDevice,
    serial_buffer: Vec<u8>,
    last_exit_reason: Option<KvmExitReason>,
    last_io_detail: Option<String>,
    recent_io_details: VecDeque<String>,
}

impl KvmBackend {
    /// 执行 `KVM_CREATE_VM`，分配 guest memory 并创建 vCPU。
    pub fn create_vm(
        base_config: SandboxConfig,
        config: MicrovmConfig,
    ) -> Result<Self, MicrovmError> {
        config.validate()?;
        info!(
            vcpu_count = config.vcpu_count,
            memory_mb = config.memory_mb,
            "创建 KVM microVM"
        );

        let kvm = Kvm::new().map_err(to_backend_error)?;
        let vm_fd = kvm.create_vm().map_err(to_backend_error)?;

        #[cfg(target_arch = "x86_64")]
        {
            vm_fd.create_irq_chip().map_err(to_backend_error)?;
            let pit_config = kvm_pit_config {
                flags: KVM_PIT_SPEAKER_DUMMY,
                ..Default::default()
            };
            vm_fd.create_pit2(pit_config).map_err(to_backend_error)?;
            vm_fd
                .set_identity_map_address(KVM_IDENTITY_MAP_ADDR)
                .map_err(to_backend_error)?;
            vm_fd
                .set_tss_address(KVM_TSS_ADDR)
                .map_err(to_backend_error)?;
        }

        let guest_memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), config.memory_bytes()?)])
                .map_err(to_backend_error)?;

        let kernel_bytes = fs::read(&config.kernel_path)?;
        let rootfs_bytes = fs::read(&config.rootfs_path)?;
        validate_initrd_image(&rootfs_bytes)?;

        let mut vcpus = Vec::with_capacity(usize::from(config.vcpu_count));
        for vcpu_index in 0..u64::from(config.vcpu_count) {
            let vcpu = vm_fd.create_vcpu(vcpu_index).map_err(to_backend_error)?;
            vcpus.push(vcpu);
        }

        let mut backend = Self {
            base_config,
            config,
            kvm,
            vm_fd,
            vcpus,
            guest_memory,
            kernel_bytes,
            rootfs_bytes,
            transport: KvmTransport::Serial,
            lifecycle: KvmLifecycle::Created,
            last_command_payload: Vec::new(),
            loaded_kernel: LoadedKernel {
                entry_point: 0,
                high_watermark: 0,
            },
            boot_params_addr: ZERO_PAGE_ADDR,
            cmdline_addr: CMDLINE_ADDR,
            initrd_addr: 0,
            guest_booted: false,
            guest_ready: false,
            serial_device: SerialDevice::default(),
            serial_buffer: Vec::new(),
            last_exit_reason: None,
            last_io_detail: None,
            recent_io_details: VecDeque::with_capacity(16),
        };
        backend.register_guest_memory()?;
        backend.load_kernel()?;
        backend.load_initrd()?;
        backend.write_boot_params()?;
        backend.load_rootfs_metadata()?;
        backend.lifecycle = KvmLifecycle::Ready;
        Ok(backend)
    }

    fn register_guest_memory(&self) -> Result<(), MicrovmError> {
        let host_addr = self
            .guest_memory
            .get_host_address(GuestAddress(0))
            .map_err(to_backend_error)? as u64;
        let memory_size = u64::try_from(self.config.memory_bytes()?)
            .map_err(|_| MicrovmError::Backend("guest memory 长度无法转换为 u64".into()))?;
        let memory_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size,
            userspace_addr: host_addr,
            flags: 0,
        };

        // SAFETY: `userspace_addr` 来自 `GuestMemoryMmap` 当前持有的连续映射，
        // `guest_memory` 生命周期覆盖整个 `KvmBackend`，且当前仅注册一个不重叠的 slot 0。
        unsafe {
            self.vm_fd
                .set_user_memory_region(memory_region)
                .map_err(to_backend_error)?;
        }
        Ok(())
    }

    fn configure_boot_vcpus(&self) -> Result<(), MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            let supported_cpuid = self
                .kvm
                .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
                .map_err(to_backend_error)?;

            for vcpu in &self.vcpus {
                vcpu.set_cpuid2(&supported_cpuid)
                    .map_err(to_backend_error)?;
                configure_linux_boot_sregs(&self.guest_memory, vcpu)?;
                configure_boot_fpu(vcpu)?;
                configure_boot_msrs(vcpu)?;
                configure_lapic(vcpu)?;

                let mut regs = vcpu.get_regs().map_err(to_backend_error)?;
                regs.rip = self.loaded_kernel.entry_point;
                regs.rsp = BOOT_STACK_POINTER;
                regs.rbp = BOOT_STACK_POINTER;
                regs.rsi = self.boot_params_addr;
                regs.rflags = 0x2;
                vcpu.set_regs(&regs).map_err(to_backend_error)?;
            }

            return Ok(());
        }

        #[allow(unreachable_code)]
        Err(MicrovmError::Backend(
            "当前 KVM bring-up 仅支持 x86_64".into(),
        ))
    }

    /// 返回累积的串口输出。
    pub fn serial_output(&self) -> &[u8] {
        &self.serial_buffer
    }

    /// 初始化 vCPU 启动寄存器并进入真实 `KVM_RUN` 循环。
    pub fn boot(&mut self) -> Result<KvmExitReason, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle("KVM 后端未处于 Ready 状态".into()));
        }
        if self.guest_ready {
            return Ok(KvmExitReason::Io);
        }

        self.lifecycle = KvmLifecycle::Running;
        let exit_reason = (|| {
            if !self.guest_booted {
                self.configure_boot_vcpus()?;
            }
            self.run_until_boot_ready()
        })();
        self.lifecycle = KvmLifecycle::Ready;
        let exit_reason = exit_reason?;
        self.guest_booted = true;
        self.guest_ready = exit_reason == KvmExitReason::Io;
        Ok(exit_reason)
    }

    /// 将内核镜像按 ELF `PT_LOAD` 段装载到 guest memory。
    pub fn load_kernel(&mut self) -> Result<(), MicrovmError> {
        debug!(
            bytes = self.kernel_bytes.len(),
            "按 ELF 装载 guest 内核镜像"
        );

        let entry_point = read_u64_at(&self.kernel_bytes, 24)?;
        let phoff = usize_from_u64(read_u64_at(&self.kernel_bytes, 32)?)?;
        let phentsize = usize::from(read_u16_at(&self.kernel_bytes, 54)?);
        let phnum = usize::from(read_u16_at(&self.kernel_bytes, 56)?);

        validate_elf_header(&self.kernel_bytes, phoff, phentsize, phnum)?;

        let mut loaded_segment = false;
        let mut high_watermark = 0u64;
        for index in 0..phnum {
            let ph_start = phoff
                .checked_add(index.checked_mul(phentsize).ok_or_else(|| {
                    MicrovmError::Backend("ELF program header 偏移计算溢出".into())
                })?)
                .ok_or_else(|| MicrovmError::Backend("ELF program header 偏移计算溢出".into()))?;
            let ph = checked_slice(&self.kernel_bytes, ph_start, phentsize)?;
            let program_type = read_u32_at(ph, 0)?;
            if program_type != PT_LOAD {
                continue;
            }

            let file_offset = usize_from_u64(read_u64_at(ph, 8)?)?;
            let guest_addr = {
                let physical = read_u64_at(ph, 24)?;
                if physical == 0 {
                    read_u64_at(ph, 16)?
                } else {
                    physical
                }
            };
            let file_size = usize_from_u64(read_u64_at(ph, 32)?)?;
            let mem_size = usize_from_u64(read_u64_at(ph, 40)?)?;
            if mem_size < file_size {
                return Err(MicrovmError::Backend(format!(
                    "ELF 段 memsz 小于 filesz: memsz={mem_size}, filesz={file_size}"
                )));
            }

            let segment_bytes = checked_slice(&self.kernel_bytes, file_offset, file_size)?;
            self.write_guest_bytes(guest_addr, segment_bytes)?;
            self.zero_guest_range(
                guest_addr
                    .checked_add(u64::try_from(file_size).map_err(|_| {
                        MicrovmError::Backend("ELF 段文件长度无法转换为 u64".into())
                    })?)
                    .ok_or_else(|| MicrovmError::Backend("ELF 段地址计算溢出".into()))?,
                mem_size - file_size,
            )?;
            loaded_segment = true;
            high_watermark = high_watermark.max(
                guest_addr
                    .checked_add(u64::try_from(mem_size).map_err(|_| {
                        MicrovmError::Backend("ELF 段内存长度无法转换为 u64".into())
                    })?)
                    .ok_or_else(|| MicrovmError::Backend("ELF 段地址计算溢出".into()))?,
            );
        }

        if !loaded_segment {
            return Err(MicrovmError::Backend(
                "ELF 镜像中不存在可装载的 PT_LOAD 段".into(),
            ));
        }

        self.loaded_kernel = LoadedKernel {
            entry_point,
            high_watermark,
        };
        Ok(())
    }

    /// 将 rootfs(initrd) 装载到 guest memory。
    fn load_initrd(&mut self) -> Result<(), MicrovmError> {
        let proposed = align_up(
            self.loaded_kernel
                .high_watermark
                .checked_add(0x20_0000)
                .ok_or_else(|| MicrovmError::Backend("initrd 装载地址计算溢出".into()))?,
            0x1000,
        )?;
        self.write_guest_bytes(proposed, &self.rootfs_bytes)?;
        self.initrd_addr = proposed;
        Ok(())
    }

    /// 构造 zero page / `boot_params`，并写入命令行和 initrd 信息。
    fn write_boot_params(&mut self) -> Result<(), MicrovmError> {
        let mut cmdline = DEFAULT_CMDLINE.as_bytes().to_vec();
        cmdline.push(0);
        self.write_guest_bytes(self.cmdline_addr, &cmdline)?;

        let mut zero_page = vec![0u8; ZERO_PAGE_LEN];
        zero_page[ZERO_PAGE_SENTINEL] = 0xff;
        zero_page[ZERO_PAGE_E820_ENTRIES] = 0;
        write_u16(&mut zero_page, SETUP_HDR_BOOT_FLAG, KERNEL_BOOT_FLAG_MAGIC)?;
        write_u32(&mut zero_page, SETUP_HDR_HEADER_MAGIC, KERNEL_HDR_MAGIC)?;
        zero_page[SETUP_HDR_TYPE_OF_LOADER] = 0xff;
        zero_page[SETUP_HDR_LOADFLAGS] = 0x80;
        write_u32(
            &mut zero_page,
            SETUP_HDR_KERNEL_ALIGNMENT,
            KERNEL_MIN_ALIGNMENT_BYTES,
        )?;
        write_u32(
            &mut zero_page,
            SETUP_HDR_CODE32_START,
            lower_u32(self.loaded_kernel.entry_point)?,
        )?;
        write_u32(
            &mut zero_page,
            SETUP_HDR_RAMDISK_IMAGE,
            lower_u32(self.initrd_addr)?,
        )?;
        write_u32(
            &mut zero_page,
            SETUP_HDR_RAMDISK_SIZE,
            u32_from_len(self.rootfs_bytes.len(), "initrd 大小超过 u32 上限")?,
        )?;
        write_u32(
            &mut zero_page,
            SETUP_HDR_CMD_LINE_PTR,
            lower_u32(self.cmdline_addr)?,
        )?;
        write_u32(
            &mut zero_page,
            ZERO_PAGE_EXT_RAMDISK_IMAGE,
            upper_u32(self.initrd_addr)?,
        )?;
        write_u32(
            &mut zero_page,
            ZERO_PAGE_EXT_RAMDISK_SIZE,
            upper_u32(
                u64::try_from(self.rootfs_bytes.len())
                    .map_err(|_| MicrovmError::Backend("initrd 大小无法转换为 u64".into()))?,
            )?,
        )?;
        write_u32(
            &mut zero_page,
            ZERO_PAGE_EXT_CMD_LINE_PTR,
            upper_u32(self.cmdline_addr)?,
        )?;
        let memory_end = u64::try_from(self.config.memory_bytes()?)
            .map_err(|_| MicrovmError::Backend("guest memory 长度无法转换为 u64".into()))?;
        let mut e820_entries = 0usize;

        if memory_end > 0 {
            let lowmem_size = memory_end.min(EBDA_START);
            if lowmem_size > 0 {
                encode_e820_entry(
                    &mut zero_page[ZERO_PAGE_E820_TABLE..ZERO_PAGE_E820_TABLE + E820_ENTRY_SIZE],
                    0,
                    lowmem_size,
                    E820_RAM,
                )?;
                e820_entries += 1;
            }
        }

        if memory_end > HIMEM_START {
            let start = ZERO_PAGE_E820_TABLE
                .checked_add(
                    e820_entries
                        .checked_mul(E820_ENTRY_SIZE)
                        .ok_or_else(|| MicrovmError::Backend("E820 偏移计算溢出".into()))?,
                )
                .ok_or_else(|| MicrovmError::Backend("E820 偏移计算溢出".into()))?;
            encode_e820_entry(
                &mut zero_page[start..start + E820_ENTRY_SIZE],
                HIMEM_START,
                memory_end - HIMEM_START,
                E820_RAM,
            )?;
            e820_entries += 1;
        }

        zero_page[ZERO_PAGE_E820_ENTRIES] = u8::try_from(e820_entries)
            .map_err(|_| MicrovmError::Backend("E820 条目数量超过 u8 上限".into()))?;

        self.write_guest_bytes(self.boot_params_addr, &zero_page)
    }

    /// 将 rootfs 元信息写入 guest memory，便于测试验证 guest 布局。
    fn load_rootfs_metadata(&mut self) -> Result<(), MicrovmError> {
        let metadata = format!(
            "rootfs={};size={};initrd={:#x};cmdline={:#x};transport={:?}",
            self.config.rootfs_path.display(),
            self.rootfs_bytes.len(),
            self.initrd_addr,
            self.cmdline_addr,
            self.transport
        );
        self.write_guest_bytes(ROOTFS_METADATA_ADDR, metadata.as_bytes())
    }

    /// 通过 guest-init 串口协议执行命令。
    pub fn run_command(&mut self, cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle("KVM 后端未处于 Ready 状态".into()));
        }
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig("命令不能为空".into()));
        }

        self.ensure_guest_ready()?;

        let payload = encode_command_payload(cmd, self.base_config.timeout_secs)?;
        self.serial_device.queue_input(&payload);
        self.last_command_payload = payload;

        self.lifecycle = KvmLifecycle::Running;
        let result = self.run_until_command_result();
        self.lifecycle = KvmLifecycle::Ready;
        result
    }

    /// 导出快照所需的内存和 vCPU 状态。
    pub fn snapshot_state(&self) -> Result<(Vec<u8>, Vec<u8>), MicrovmError> {
        let memory = self.dump_guest_memory()?;
        let vcpu_state = encode_runtime_state(self)?;
        Ok((memory, vcpu_state))
    }

    /// 从快照恢复 guest memory 和 vCPU 状态。
    pub fn restore_state(&mut self, memory: &[u8], vcpu_state: &[u8]) -> Result<(), MicrovmError> {
        self.restore_guest_memory(memory)?;
        restore_runtime_state(self, vcpu_state)?;
        self.lifecycle = KvmLifecycle::Ready;
        Ok(())
    }

    /// 关闭 VM 并释放生命周期状态。
    pub fn shutdown(&mut self) -> Result<(), MicrovmError> {
        self.last_command_payload.clear();
        self.serial_device = SerialDevice::default();
        self.guest_booted = false;
        self.guest_ready = false;
        self.lifecycle = KvmLifecycle::Destroyed;
        Ok(())
    }

    fn ensure_guest_ready(&mut self) -> Result<(), MicrovmError> {
        if self.guest_ready {
            return Ok(());
        }

        let exit_reason = self.boot()?;
        if exit_reason != KvmExitReason::Io {
            return Err(MicrovmError::Backend(format!(
                "guest 未进入命令循环即退出: {exit_reason:?}"
            )));
        }
        Ok(())
    }

    fn start_watchdog(&mut self, timeout: Duration) -> Result<VcpuRunWatchdog, MicrovmError> {
        let vcpu = self
            .vcpus
            .first_mut()
            .ok_or_else(|| MicrovmError::Backend("至少需要一个 vCPU".into()))?;
        Ok(VcpuRunWatchdog::start(vcpu, timeout))
    }

    fn run_until_boot_ready(&mut self) -> Result<KvmExitReason, MicrovmError> {
        let mut line_buffer = Vec::new();
        let boot_timeout_secs = self
            .base_config
            .timeout_secs
            .unwrap_or(BOOT_READY_TIMEOUT_SECS)
            .max(BOOT_READY_TIMEOUT_SECS);
        let watchdog = self.start_watchdog(Duration::from_secs(boot_timeout_secs))?;

        loop {
            match self.run_vcpu_step(&mut line_buffer, None, &watchdog) {
                Ok(RunLoopOutcome::Exit(exit_reason)) => {
                    if exit_reason != KvmExitReason::Io {
                        return Ok(exit_reason);
                    }
                    if self.guest_ready {
                        return Ok(KvmExitReason::Io);
                    }
                }
                Ok(RunLoopOutcome::CommandDone(_)) => {
                    return Err(MicrovmError::Backend(
                        "boot 阶段不应收到命令完成事件".into(),
                    ));
                }
                Err(err) if watchdog.timed_out() => {
                    return Err(MicrovmError::Backend(format!(
                        "guest 启动超时: {err}; last_exit={:?}; last_io={:?}; io_history={:?}; serial={}",
                        self.last_exit_reason,
                        self.last_io_detail,
                        self.recent_io_details,
                        preview_serial_output(&self.serial_buffer),
                    )));
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn run_until_command_result(&mut self) -> Result<GuestCommandResult, MicrovmError> {
        let mut line_buffer = Vec::new();
        let mut response = CommandResponse::default();
        let watchdog = self.start_watchdog(Duration::from_secs(
            self.base_config
                .timeout_secs
                .unwrap_or(30)
                .saturating_add(5),
        ))?;

        loop {
            match self.run_vcpu_step(&mut line_buffer, Some(&mut response), &watchdog) {
                Ok(RunLoopOutcome::CommandDone(result)) => return Ok(result),
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io)) => {}
                Ok(RunLoopOutcome::Exit(exit_reason)) => {
                    return Err(MicrovmError::Backend(format!(
                        "guest 在返回 EXIT 帧前异常退出: {exit_reason:?}"
                    )));
                }
                Err(_) if watchdog.timed_out() => {
                    self.guest_ready = false;
                    return Ok(GuestCommandResult {
                        stdout: std::mem::take(&mut response.stdout),
                        stderr: Vec::new(),
                        exit_code: None,
                        timed_out: true,
                    });
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn run_vcpu_step(
        &mut self,
        line_buffer: &mut Vec<u8>,
        response: Option<&mut CommandResponse>,
        watchdog: &VcpuRunWatchdog,
    ) -> Result<RunLoopOutcome, MicrovmError> {
        let serial_device = &mut self.serial_device;
        let serial_buffer = &mut self.serial_buffer;
        let guest_ready = &mut self.guest_ready;
        let last_exit_reason = &mut self.last_exit_reason;
        let last_io_detail = &mut self.last_io_detail;
        let recent_io_details = &mut self.recent_io_details;
        let vcpu = self
            .vcpus
            .first_mut()
            .ok_or_else(|| MicrovmError::Backend("至少需要一个 vCPU".into()))?;

        let exit = match vcpu.run() {
            Ok(exit) => exit,
            Err(err) if watchdog.timed_out() => {
                return Err(MicrovmError::Backend(format!(
                    "KVM_RUN 被 watchdog 中断: {err}"
                )));
            }
            Err(err) => return Err(to_backend_error(err)),
        };

        match exit {
            VcpuExit::IoOut(port, data) if is_serial_port(port) => {
                push_io_detail(
                    last_io_detail,
                    recent_io_details,
                    format!("serial out port={port:#x} size={}", data.len()),
                );
                let action = handle_serial_write(
                    serial_device,
                    serial_buffer,
                    guest_ready,
                    port,
                    data,
                    line_buffer,
                    response,
                )?;
                if let Some(result) = action {
                    return Ok(RunLoopOutcome::CommandDone(result));
                }
                *last_exit_reason = Some(KvmExitReason::Io);
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
            }
            VcpuExit::IoIn(port, data) if is_serial_port(port) => {
                push_io_detail(
                    last_io_detail,
                    recent_io_details,
                    format!("serial in port={port:#x} size={}", data.len()),
                );
                handle_serial_read(serial_device, port, data)?;
                *last_exit_reason = Some(KvmExitReason::Io);
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
            }
            VcpuExit::MmioRead(addr, data) => {
                push_io_detail(
                    last_io_detail,
                    recent_io_details,
                    format!("mmio read addr={addr:#x} size={}", data.len()),
                );
                data.fill(0);
                debug!(addr, size = data.len(), "guest 触发 MMIO 读退出");
                *last_exit_reason = Some(KvmExitReason::Io);
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
            }
            VcpuExit::MmioWrite(addr, data) => {
                push_io_detail(
                    last_io_detail,
                    recent_io_details,
                    format!("mmio write addr={addr:#x} size={}", data.len()),
                );
                debug!(addr, size = data.len(), "guest 触发 MMIO 写退出");
                *last_exit_reason = Some(KvmExitReason::Io);
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
            }
            VcpuExit::Hlt => {
                *last_exit_reason = Some(KvmExitReason::Hlt);
                Ok(RunLoopOutcome::Exit(KvmExitReason::Hlt))
            }
            VcpuExit::Shutdown => {
                *last_exit_reason = Some(KvmExitReason::Shutdown);
                Ok(RunLoopOutcome::Exit(KvmExitReason::Shutdown))
            }
            VcpuExit::InternalError => {
                *last_exit_reason = Some(KvmExitReason::InternalError);
                Err(MicrovmError::Backend(
                    "vCPU 进入 KVM_EXIT_INTERNAL_ERROR".into(),
                ))
            }
            VcpuExit::IoOut(port, data) => {
                push_io_detail(
                    last_io_detail,
                    recent_io_details,
                    format!("pio out port={port:#x} size={}", data.len()),
                );
                if port == PCI_CONFIG_ADDRESS_REG {
                    debug!(port, size = data.len(), "忽略 PCI 配置地址写");
                    *last_exit_reason = Some(KvmExitReason::Io);
                    return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                }
                if port == I8042_COMMAND_REG && data.len() == 1 && data[0] == I8042_RESET_CMD {
                    *last_exit_reason = Some(KvmExitReason::Shutdown);
                    return Ok(RunLoopOutcome::Exit(KvmExitReason::Shutdown));
                }
                debug!(port, size = data.len(), "忽略非串口 PIO 写退出");
                *last_exit_reason = Some(KvmExitReason::Io);
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
            }
            VcpuExit::IoIn(port, data) => {
                push_io_detail(
                    last_io_detail,
                    recent_io_details,
                    format!("pio in port={port:#x} size={}", data.len()),
                );
                match port {
                    I8042_PORT_B_REG if data.len() == 1 => data[0] = I8042_PORT_B_PIT_TICK,
                    I8042_COMMAND_REG if data.len() == 1 => data[0] = 0,
                    PCI_CONFIG_DATA_REG_START..=PCI_CONFIG_DATA_REG_END => data.fill(0xff),
                    _ => data.fill(0),
                }
                debug!(port, size = data.len(), "响应非串口 PIO 读退出");
                *last_exit_reason = Some(KvmExitReason::Io);
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
            }
            other => {
                *last_exit_reason = Some(KvmExitReason::InternalError);
                Err(MicrovmError::Backend(format!(
                    "未处理的 vCPU 退出: {other:?}"
                )))
            }
        }
    }

    fn dump_guest_memory(&self) -> Result<Vec<u8>, MicrovmError> {
        let mut memory = vec![0u8; self.config.memory_bytes()?];
        self.guest_memory
            .read_slice(&mut memory, GuestAddress(0))
            .map_err(to_backend_error)?;
        Ok(memory)
    }

    fn restore_guest_memory(&self, memory: &[u8]) -> Result<(), MicrovmError> {
        let expected_len = self.config.memory_bytes()?;
        if memory.len() != expected_len {
            return Err(MicrovmError::SnapshotFormat(format!(
                "guest memory 长度不匹配: 快照为 {}，当前为 {}",
                memory.len(),
                expected_len
            )));
        }

        self.guest_memory
            .write_slice(memory, GuestAddress(0))
            .map_err(to_backend_error)
    }

    fn write_guest_bytes(&self, guest_addr: u64, bytes: &[u8]) -> Result<(), MicrovmError> {
        self.guest_memory
            .write_slice(bytes, GuestAddress(guest_addr))
            .map_err(to_backend_error)
    }

    fn zero_guest_range(&self, guest_addr: u64, len: usize) -> Result<(), MicrovmError> {
        const ZEROES: [u8; 4096] = [0; 4096];
        let mut written = 0usize;
        while written < len {
            let chunk = ZEROES.len().min(len - written);
            let chunk_addr = guest_addr
                .checked_add(u64::try_from(written).map_err(|_| {
                    MicrovmError::Backend("guest memory 清零偏移无法转换为 u64".into())
                })?)
                .ok_or_else(|| MicrovmError::Backend("guest memory 清零地址计算溢出".into()))?;
            self.write_guest_bytes(chunk_addr, &ZEROES[..chunk])?;
            written += chunk;
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn read_guest_bytes(&self, guest_addr: u64, len: usize) -> Result<Vec<u8>, MicrovmError> {
        let mut bytes = vec![0u8; len];
        self.guest_memory
            .read_slice(&mut bytes, GuestAddress(guest_addr))
            .map_err(to_backend_error)?;
        Ok(bytes)
    }

    #[allow(dead_code)]
    fn vcpu_count(&self) -> usize {
        self.vcpus.len()
    }

    #[allow(dead_code)]
    fn _vm_fd(&self) -> &VmFd {
        &self.vm_fd
    }

    #[allow(dead_code)]
    fn _kvm(&self) -> &Kvm {
        &self.kvm
    }
}

#[cfg(target_arch = "x86_64")]
fn configure_linux_boot_sregs(
    guest_memory: &GuestMemoryMmap,
    vcpu: &VcpuFd,
) -> Result<(), MicrovmError> {
    let mut sregs = vcpu.get_sregs().map_err(to_backend_error)?;
    configure_segments_and_sregs(guest_memory, &mut sregs)?;
    setup_page_tables(guest_memory, &mut sregs)?;
    vcpu.set_sregs(&sregs).map_err(to_backend_error)
}

#[cfg(target_arch = "x86_64")]
fn configure_boot_fpu(vcpu: &VcpuFd) -> Result<(), MicrovmError> {
    let fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };
    vcpu.set_fpu(&fpu).map_err(to_backend_error)
}

#[cfg(target_arch = "x86_64")]
fn configure_boot_msrs(vcpu: &VcpuFd) -> Result<(), MicrovmError> {
    let entries = [
        kvm_msr_entry {
            index: MSR_IA32_SYSENTER_CS,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_SYSENTER_ESP,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_SYSENTER_EIP,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_STAR,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_CSTAR,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_KERNEL_GS_BASE,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_SYSCALL_MASK,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_LSTAR,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_TSC,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            data: MSR_IA32_MISC_ENABLE_FAST_STRING,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_MTRR_DEF_TYPE,
            data: (1u64 << 11) | 0x6,
            ..Default::default()
        },
    ];
    let msrs = Msrs::from_entries(&entries).map_err(to_backend_error)?;
    let written = vcpu.set_msrs(&msrs).map_err(to_backend_error)?;
    if written != entries.len() {
        return Err(MicrovmError::Backend(format!(
            "启动 MSR 仅写入 {written}/{} 项",
            entries.len()
        )));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn configure_lapic(vcpu: &VcpuFd) -> Result<(), MicrovmError> {
    let mut klapic = vcpu.get_lapic().map_err(to_backend_error)?;
    set_klapic_delivery_mode(&mut klapic, APIC_LVT0_REG_OFFSET, APIC_MODE_EXTINT)?;
    set_klapic_delivery_mode(&mut klapic, APIC_LVT1_REG_OFFSET, APIC_MODE_NMI)?;
    vcpu.set_lapic(&klapic).map_err(to_backend_error)
}

#[cfg(target_arch = "x86_64")]
fn configure_segments_and_sregs(
    guest_memory: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
) -> Result<(), MicrovmError> {
    let gdt_table: [u64; BOOT_GDT_MAX] = [
        gdt_entry(0, 0, 0),
        gdt_entry(0xa09b, 0, 0xfffff),
        gdt_entry(0xc093, 0, 0xfffff),
        gdt_entry(0x808b, 0, 0xfffff),
    ];
    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

    write_gdt_table(guest_memory, &gdt_table)?;
    write_idt_value(guest_memory, 0)?;

    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = u16::try_from(mem::size_of_val(&gdt_table) - 1)
        .map_err(|_| MicrovmError::Backend("GDT 长度无法转换为 u16".into()))?;
    sregs.idt.base = BOOT_IDT_OFFSET;
    sregs.idt.limit = u16::try_from(mem::size_of::<u64>() - 1)
        .map_err(|_| MicrovmError::Backend("IDT 长度无法转换为 u16".into()))?;
    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;
    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn setup_page_tables(
    guest_memory: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
) -> Result<(), MicrovmError> {
    guest_memory
        .write_obj(BOOT_PDPTE_START | 0x03u64, GuestAddress(BOOT_PML4_START))
        .map_err(to_backend_error)?;
    guest_memory
        .write_obj(BOOT_PDE_START | 0x03u64, GuestAddress(BOOT_PDPTE_START))
        .map_err(to_backend_error)?;

    for index in 0..512u64 {
        guest_memory
            .write_obj(
                (index << 21) | 0x83u64,
                GuestAddress(BOOT_PDE_START + (index * 8)),
            )
            .map_err(to_backend_error)?;
    }

    sregs.cr3 = BOOT_PML4_START;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn write_gdt_table(guest_memory: &GuestMemoryMmap, table: &[u64]) -> Result<(), MicrovmError> {
    for (index, entry) in table.iter().enumerate() {
        let addr = BOOT_GDT_OFFSET
            .checked_add(
                u64::try_from(index)
                    .map_err(|_| MicrovmError::Backend("GDT 索引无法转换为 u64".into()))?
                    .checked_mul(
                        u64::try_from(mem::size_of::<u64>())
                            .map_err(|_| MicrovmError::Backend("u64 大小无法转换为 u64".into()))?,
                    )
                    .ok_or_else(|| MicrovmError::Backend("GDT 地址计算溢出".into()))?,
            )
            .ok_or_else(|| MicrovmError::Backend("GDT 地址计算溢出".into()))?;
        guest_memory
            .write_obj(*entry, GuestAddress(addr))
            .map_err(to_backend_error)?;
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn write_idt_value(guest_memory: &GuestMemoryMmap, value: u64) -> Result<(), MicrovmError> {
    guest_memory
        .write_obj(value, GuestAddress(BOOT_IDT_OFFSET))
        .map_err(to_backend_error)
}

#[cfg(target_arch = "x86_64")]
fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000) << 32)
        | ((u64::from(flags) & 0x0000_f0ff) << 40)
        | ((u64::from(limit) & 0x000f_0000) << 32)
        | ((u64::from(base) & 0x00ff_ffff) << 16)
        | (u64::from(limit) & 0x0000_ffff)
}

#[cfg(target_arch = "x86_64")]
fn kvm_segment_from_gdt(entry: u64, table_index: u8) -> kvm_segment {
    kvm_segment {
        base: gdt_base(entry),
        limit: gdt_limit(entry),
        selector: u16::from(table_index) * 8,
        type_: ((entry >> 40) & 0x0f) as u8,
        present: ((entry >> 47) & 0x01) as u8,
        dpl: ((entry >> 45) & 0x03) as u8,
        db: ((entry >> 54) & 0x01) as u8,
        s: ((entry >> 44) & 0x01) as u8,
        l: ((entry >> 53) & 0x01) as u8,
        g: ((entry >> 55) & 0x01) as u8,
        avl: ((entry >> 52) & 0x01) as u8,
        padding: 0,
        unusable: if ((entry >> 47) & 0x01) == 0 { 1 } else { 0 },
    }
}

#[cfg(target_arch = "x86_64")]
fn gdt_base(entry: u64) -> u64 {
    ((entry & 0xff00_0000_0000_0000) >> 32)
        | ((entry & 0x0000_00ff_0000_0000) >> 16)
        | ((entry & 0x0000_0000_ffff_0000) >> 16)
}

#[cfg(target_arch = "x86_64")]
fn gdt_limit(entry: u64) -> u32 {
    let limit = (((entry & 0x000f_0000_0000_0000) >> 32) | (entry & 0x0000_0000_0000_ffff)) as u32;
    if ((entry >> 55) & 0x01) == 0 {
        limit
    } else {
        (limit << 12) | 0x0fff
    }
}

#[cfg(target_arch = "x86_64")]
fn get_klapic_reg(klapic: &kvm_lapic_state, reg_offset: usize) -> Result<i32, MicrovmError> {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic
        .regs
        .get(range)
        .ok_or_else(|| MicrovmError::Backend(format!("无效 LAPIC 寄存器偏移: {reg_offset:#x}")))?;
    Ok(read_le_i32(reg))
}

#[cfg(target_arch = "x86_64")]
fn set_klapic_reg(
    klapic: &mut kvm_lapic_state,
    reg_offset: usize,
    value: i32,
) -> Result<(), MicrovmError> {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic
        .regs
        .get_mut(range)
        .ok_or_else(|| MicrovmError::Backend(format!("无效 LAPIC 寄存器偏移: {reg_offset:#x}")))?;
    write_le_i32(reg, value);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn set_klapic_delivery_mode(
    klapic: &mut kvm_lapic_state,
    reg_offset: usize,
    mode: i32,
) -> Result<(), MicrovmError> {
    let reg_value = get_klapic_reg(klapic, reg_offset)?;
    set_klapic_reg(klapic, reg_offset, (reg_value & !0x700) | (mode << 8))
}

#[cfg(target_arch = "x86_64")]
fn read_le_i32(input: &[i8]) -> i32 {
    let mut array = [0u8; 4];
    for (byte, read) in array.iter_mut().zip(input.iter().copied()) {
        *byte = read as u8;
    }
    i32::from_le_bytes(array)
}

#[cfg(target_arch = "x86_64")]
fn write_le_i32(output: &mut [i8], value: i32) {
    for (byte, written) in output.iter_mut().zip(value.to_le_bytes().iter().copied()) {
        *byte = written as i8;
    }
}

fn encode_runtime_state(backend: &KvmBackend) -> Result<Vec<u8>, MicrovmError> {
    let mut state = Vec::new();
    let serial_fifo = backend
        .serial_device
        .rx_fifo
        .iter()
        .copied()
        .collect::<Vec<_>>();

    state.extend_from_slice(b"KVMSNAP2");
    encode_vcpu_ids(&mut state, &backend.vcpus)?;
    state.push(u8::from(backend.guest_booted));
    state.push(u8::from(backend.guest_ready));
    state.push(exit_reason_to_u8(backend.last_exit_reason));
    append_bytes(&mut state, &backend.last_command_payload)?;
    append_bytes(&mut state, &backend.serial_buffer)?;
    append_bytes(&mut state, &serial_fifo)?;
    state.extend_from_slice(&backend.serial_device.snapshot_registers());
    state.extend_from_slice(&backend.loaded_kernel.entry_point.to_le_bytes());
    state.extend_from_slice(&backend.loaded_kernel.high_watermark.to_le_bytes());
    state.extend_from_slice(&backend.boot_params_addr.to_le_bytes());
    state.extend_from_slice(&backend.cmdline_addr.to_le_bytes());
    state.extend_from_slice(&backend.initrd_addr.to_le_bytes());
    Ok(state)
}

fn restore_runtime_state(backend: &mut KvmBackend, state: &[u8]) -> Result<(), MicrovmError> {
    let mut cursor = ByteCursor::new(state);
    if cursor.read_exact(8)? != b"KVMSNAP2" {
        return Err(MicrovmError::SnapshotFormat(
            "KVM 运行时快照 magic 不匹配".into(),
        ));
    }

    restore_vcpu_ids(&backend.vcpus, &mut cursor)?;
    backend.guest_booted = cursor.read_u8()? != 0;
    backend.guest_ready = cursor.read_u8()? != 0;
    backend.last_exit_reason = exit_reason_from_u8(cursor.read_u8()?)?;
    backend.last_command_payload = cursor.read_bytes()?;
    backend.serial_buffer = cursor.read_bytes()?;
    let serial_fifo = cursor.read_bytes()?;
    let mut serial_registers = [0u8; 7];
    let serial_registers_len = serial_registers.len();
    serial_registers.copy_from_slice(cursor.read_exact(serial_registers_len)?);
    backend.serial_device.restore(serial_fifo, serial_registers);
    backend.loaded_kernel = LoadedKernel {
        entry_point: cursor.read_u64()?,
        high_watermark: cursor.read_u64()?,
    };
    backend.boot_params_addr = cursor.read_u64()?;
    backend.cmdline_addr = cursor.read_u64()?;
    backend.initrd_addr = cursor.read_u64()?;
    if !cursor.is_eof() {
        return Err(MicrovmError::SnapshotFormat(
            "KVM 运行时快照尾部存在未识别数据".into(),
        ));
    }
    Ok(())
}

fn encode_vcpu_ids(out: &mut Vec<u8>, vcpus: &[VcpuFd]) -> Result<(), MicrovmError> {
    let count = u32::try_from(vcpus.len())
        .map_err(|_| MicrovmError::Backend("vCPU 数量超过 u32 上限".into()))?;
    out.extend_from_slice(&count.to_le_bytes());
    for (index, _) in vcpus.iter().enumerate() {
        out.extend_from_slice(&(index as u64).to_le_bytes());
    }
    Ok(())
}

fn restore_vcpu_ids(vcpus: &[VcpuFd], cursor: &mut ByteCursor<'_>) -> Result<(), MicrovmError> {
    let count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| MicrovmError::SnapshotFormat("快照中的 vCPU 数量无法转换为 usize".into()))?;
    if count != vcpus.len() {
        return Err(MicrovmError::SnapshotFormat(format!(
            "vCPU 数量不匹配: 快照为 {count}，当前后端为 {}",
            vcpus.len()
        )));
    }

    for (index, _) in vcpus.iter().enumerate() {
        let encoded_id = cursor.read_u64()?;
        if encoded_id != index as u64 {
            return Err(MicrovmError::SnapshotFormat(format!(
                "vCPU ID 不匹配: 快照为 {encoded_id}，当前为 {}",
                index
            )));
        }
    }
    Ok(())
}

fn validate_initrd_image(bytes: &[u8]) -> Result<(), MicrovmError> {
    if bytes.len() < GZIP_MAGIC.len() || bytes[..2] != GZIP_MAGIC {
        return Err(MicrovmError::Backend(
            "rootfs 必须是 gzip 压缩的 cpio initrd".into(),
        ));
    }
    Ok(())
}

fn validate_elf_header(
    bytes: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
) -> Result<(), MicrovmError> {
    if bytes.len() < 64 {
        return Err(MicrovmError::Backend(
            "内核镜像长度不足，无法解析 ELF header".into(),
        ));
    }
    if &bytes[..4] != b"\x7fELF" {
        return Err(MicrovmError::Backend("内核镜像不是 ELF 格式".into()));
    }
    if bytes[4] != 2 {
        return Err(MicrovmError::Backend(
            "仅支持 64 位 ELF vmlinux 镜像".into(),
        ));
    }
    if bytes[5] != 1 {
        return Err(MicrovmError::Backend("仅支持小端 ELF vmlinux 镜像".into()));
    }

    let table_len = phentsize
        .checked_mul(phnum)
        .ok_or_else(|| MicrovmError::Backend("ELF program header 表长度溢出".into()))?;
    let _ = checked_slice(bytes, phoff, table_len)?;
    Ok(())
}

fn encode_e820_entry(
    dst: &mut [u8],
    addr: u64,
    size: u64,
    entry_type: u32,
) -> Result<(), MicrovmError> {
    if dst.len() != E820_ENTRY_SIZE {
        return Err(MicrovmError::Backend("E820 条目长度不正确".into()));
    }
    dst[..8].copy_from_slice(&addr.to_le_bytes());
    dst[8..16].copy_from_slice(&size.to_le_bytes());
    dst[16..20].copy_from_slice(&entry_type.to_le_bytes());
    Ok(())
}

fn append_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), MicrovmError> {
    let len = u32_from_len(bytes.len(), "字节块长度超过 u32 上限")?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn exit_reason_to_u8(reason: Option<KvmExitReason>) -> u8 {
    match reason {
        None => 0,
        Some(KvmExitReason::Io) => 1,
        Some(KvmExitReason::Hlt) => 2,
        Some(KvmExitReason::Shutdown) => 3,
        Some(KvmExitReason::InternalError) => 4,
    }
}

fn exit_reason_from_u8(value: u8) -> Result<Option<KvmExitReason>, MicrovmError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(KvmExitReason::Io)),
        2 => Ok(Some(KvmExitReason::Hlt)),
        3 => Ok(Some(KvmExitReason::Shutdown)),
        4 => Ok(Some(KvmExitReason::InternalError)),
        other => Err(MicrovmError::SnapshotFormat(format!(
            "未知 KVM 退出原因编码: {other}"
        ))),
    }
}

fn encode_command_payload(
    cmd: &[String],
    timeout_secs: Option<u64>,
) -> Result<Vec<u8>, MicrovmError> {
    let command = build_guest_command(cmd, timeout_secs)?;
    let frame = format!("{SERIAL_EXEC_PREFIX}{command}\n");
    Ok(frame.into_bytes())
}

fn is_serial_port(port: u16) -> bool {
    (SERIAL_PORT_COM1..=SERIAL_PORT_LAST).contains(&port)
}

fn take_serial_line(line_buffer: &mut Vec<u8>) -> String {
    let line = String::from_utf8_lossy(line_buffer).into_owned();
    line_buffer.clear();
    line
}

fn parse_guest_protocol_line(
    line: &str,
    response: &mut CommandResponse,
) -> Result<Option<GuestCommandResult>, MicrovmError> {
    if let Some(payload) = line.strip_prefix(SERIAL_OUTPUT_PREFIX) {
        response.stdout.extend(decode_guest_output(payload)?);
        return Ok(None);
    }

    if let Some(payload) = line.strip_prefix(SERIAL_EXIT_PREFIX) {
        let exit_code = payload.parse::<i32>().map_err(|err| {
            MicrovmError::Backend(format!("guest EXIT 帧不是合法整数: {payload}: {err}"))
        })?;
        let timed_out = exit_code == SERIAL_TIMEOUT_EXIT_CODE;
        let stdout = if timed_out {
            response.stdout.clear();
            Vec::new()
        } else {
            std::mem::take(&mut response.stdout)
        };
        return Ok(Some(GuestCommandResult {
            stdout,
            stderr: Vec::new(),
            exit_code: if timed_out { None } else { Some(exit_code) },
            timed_out,
        }));
    }

    Ok(None)
}

fn decode_guest_output(payload: &str) -> Result<Vec<u8>, MicrovmError> {
    let bytes = payload.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte != b'\\' {
            decoded.push(byte);
            index += 1;
            continue;
        }

        index += 1;
        let escaped = *bytes
            .get(index)
            .ok_or_else(|| MicrovmError::Backend("guest OUTPUT 帧以不完整转义结尾".into()))?;
        match escaped {
            b'\\' => decoded.push(b'\\'),
            b'n' => decoded.push(b'\n'),
            b'r' => decoded.push(b'\r'),
            b't' => decoded.push(b'\t'),
            b'x' => {
                let hi = *bytes.get(index + 1).ok_or_else(|| {
                    MicrovmError::Backend("guest OUTPUT 帧缺少十六进制高位".into())
                })?;
                let lo = *bytes.get(index + 2).ok_or_else(|| {
                    MicrovmError::Backend("guest OUTPUT 帧缺少十六进制低位".into())
                })?;
                decoded.push((parse_hex_digit(hi)? << 4) | parse_hex_digit(lo)?);
                index += 2;
            }
            other => {
                return Err(MicrovmError::Backend(format!(
                    "guest OUTPUT 帧包含未知转义: \\{}",
                    char::from(other)
                )));
            }
        }
        index += 1;
    }

    Ok(decoded)
}

fn parse_hex_digit(value: u8) -> Result<u8, MicrovmError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        other => Err(MicrovmError::Backend(format!(
            "guest OUTPUT 帧包含非法十六进制字符: {}",
            char::from(other)
        ))),
    }
}

fn build_guest_command(cmd: &[String], timeout_secs: Option<u64>) -> Result<String, MicrovmError> {
    if cmd.is_empty() {
        return Err(MicrovmError::InvalidConfig("命令不能为空".into()));
    }

    let command = join_shell_command(cmd);
    if let Some(timeout_secs) = timeout_secs {
        if timeout_secs == 0 {
            return Err(MicrovmError::InvalidConfig("timeout_secs 不能为 0".into()));
        }
        return Ok(format!(
            "status=0; /bin/timeout -s KILL {timeout_secs} /bin/sh -lc {} || status=$?; \
if [ \"$status\" -eq 124 ] || [ \"$status\" -eq 137 ] || [ \"$status\" -eq 143 ]; then exit 124; fi; \
exit \"$status\"",
            shell_escape(&command),
        ));
    }

    Ok(command)
}

fn join_shell_command(cmd: &[String]) -> String {
    cmd.iter()
        .map(|arg| shell_escape(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_escape(input: &str) -> String {
    if input.is_empty() {
        return "''".to_string();
    }

    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn preview_serial_output(serial: &[u8]) -> String {
    if serial.is_empty() {
        return "<empty>".to_string();
    }

    let max_len = 4096usize;
    let start = serial.len().saturating_sub(max_len);
    let snippet = String::from_utf8_lossy(&serial[start..]).replace('\n', "\\n");
    if start == 0 {
        snippet
    } else {
        format!("...{snippet}")
    }
}

fn push_io_detail(
    last_io_detail: &mut Option<String>,
    recent_io_details: &mut VecDeque<String>,
    detail: String,
) {
    *last_io_detail = Some(detail.clone());
    if recent_io_details.len() == 16 {
        let _ = recent_io_details.pop_front();
    }
    recent_io_details.push_back(detail);
}

fn install_watchdog_signal_handler() {
    WATCHDOG_SIGNAL_HANDLER_INIT.call_once(|| {
        // SAFETY: 仅注册一个 no-op 信号处理器用于打断阻塞的 `KVM_RUN`。
        // 处理器本身不访问共享状态，不执行分配，也不会与 Rust 栈对象交互。
        unsafe {
            libc::signal(
                WATCHDOG_SIGNAL,
                handle_watchdog_signal as *const () as libc::sighandler_t,
            );
        }
    });
}

fn handle_serial_write(
    serial_device: &mut SerialDevice,
    serial_buffer: &mut Vec<u8>,
    guest_ready: &mut bool,
    port: u16,
    data: &[u8],
    line_buffer: &mut Vec<u8>,
    response: Option<&mut CommandResponse>,
) -> Result<Option<GuestCommandResult>, MicrovmError> {
    let mut response = response;

    for &value in data {
        if let Some(tx_byte) = serial_device.write(port, value)? {
            serial_buffer.push(tx_byte);
            if tx_byte == b'\n' {
                let line = take_serial_line(line_buffer);
                if line == SERIAL_READY_LINE {
                    *guest_ready = true;
                    continue;
                }

                if let Some(response) = response.as_deref_mut()
                    && let Some(result) = parse_guest_protocol_line(&line, response)?
                {
                    return Ok(Some(result));
                }
                continue;
            }

            if tx_byte != b'\r' {
                line_buffer.push(tx_byte);
            }
        }
    }

    Ok(None)
}

fn handle_serial_read(
    serial_device: &mut SerialDevice,
    port: u16,
    data: &mut [u8],
) -> Result<(), MicrovmError> {
    for slot in data.iter_mut() {
        *slot = serial_device.read(port)?;
    }
    Ok(())
}

fn checked_slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], MicrovmError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| MicrovmError::Backend("字节区间长度计算溢出".into()))?;
    bytes.get(offset..end).ok_or_else(|| {
        MicrovmError::Backend(format!(
            "字节区间越界: offset={offset}, len={len}, total={}",
            bytes.len()
        ))
    })
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, MicrovmError> {
    let mut raw = [0u8; 2];
    raw.copy_from_slice(checked_slice(bytes, offset, 2)?);
    Ok(u16::from_le_bytes(raw))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, MicrovmError> {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(checked_slice(bytes, offset, 4)?);
    Ok(u32::from_le_bytes(raw))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64, MicrovmError> {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(checked_slice(bytes, offset, 8)?);
    Ok(u64::from_le_bytes(raw))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), MicrovmError> {
    let dst = bytes
        .get_mut(offset..offset + 2)
        .ok_or_else(|| MicrovmError::Backend("boot_params 写入越界".into()))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), MicrovmError> {
    let dst = bytes
        .get_mut(offset..offset + 4)
        .ok_or_else(|| MicrovmError::Backend("boot_params 写入越界".into()))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn align_up(value: u64, align: u64) -> Result<u64, MicrovmError> {
    if align == 0 {
        return Err(MicrovmError::Backend("对齐粒度不能为 0".into()));
    }
    let adjusted = value
        .checked_add(align - 1)
        .ok_or_else(|| MicrovmError::Backend("地址对齐计算溢出".into()))?;
    Ok(adjusted / align * align)
}

fn lower_u32(value: u64) -> Result<u32, MicrovmError> {
    Ok((value & 0xffff_ffff) as u32)
}

fn upper_u32(value: u64) -> Result<u32, MicrovmError> {
    Ok((value >> 32) as u32)
}

fn usize_from_u64(value: u64) -> Result<usize, MicrovmError> {
    usize::try_from(value).map_err(|_| MicrovmError::Backend("u64 无法转换为 usize".into()))
}

fn u32_from_len(len: usize, message: &str) -> Result<u32, MicrovmError> {
    u32::try_from(len).map_err(|_| MicrovmError::Backend(message.into()))
}

fn to_backend_error(err: impl std::fmt::Display) -> MicrovmError {
    MicrovmError::Backend(err.to_string())
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], MicrovmError> {
        let slice = checked_slice(self.bytes, self.offset, len)
            .map_err(|err| MicrovmError::SnapshotFormat(err.to_string()))?;
        self.offset += len;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, MicrovmError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, MicrovmError> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn read_u64(&mut self) -> Result<u64, MicrovmError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, MicrovmError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| {
            MicrovmError::SnapshotFormat("快照中的字节块长度无法转换为 usize".into())
        })?;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
