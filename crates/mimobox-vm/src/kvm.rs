#![cfg(all(target_os = "linux", feature = "kvm"))]

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid_count;
use std::collections::VecDeque;
use std::fs;
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, Once, OnceLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_bindings::{
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, KVM_PIT_SPEAKER_DUMMY, Msrs,
    kvm_clock_data, kvm_cpuid_entry2, kvm_fpu, kvm_irqchip, kvm_lapic_state, kvm_mp_state,
    kvm_msr_entry, kvm_pit_config, kvm_pit_state2, kvm_regs, kvm_segment, kvm_sregs,
    kvm_userspace_memory_region, kvm_vcpu_events, kvm_xcrs, kvm_xsave,
};
#[cfg(target_arch = "x86_64")]
use kvm_ioctls::Cap;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use mimobox_core::SandboxConfig;
use tracing::{debug, info};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::vm::{GuestCommandResult, MicrovmConfig, MicrovmError};

const ZERO_PAGE_ADDR: u64 = 0x7_000;
const CMDLINE_ADDR: u64 = 0x20_000;
const ROOTFS_METADATA_ADDR: u64 = 0x30_000;
const KVM_RUNTIME_STATE_MAGIC_V2: &[u8; 8] = b"KVMSNAP2";
const KVM_RUNTIME_STATE_MAGIC_V3: &[u8; 8] = b"KVMSNAP3";
const BOOT_READY_TIMEOUT_SECS: u64 = 30;
static ASSET_CACHE: OnceLock<Mutex<AssetCache>> = OnceLock::new();
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
const DEFAULT_CMDLINE: &str = "console=ttyS0 8250.nr_uarts=1 i8042.nokbd no_timer_check fastboot quiet rcupdate.rcu_expedited=1 mitigations=off tsc=reliable nokaslr nomodule reboot=t panic=1 pci=off rdinit=/init";
const SERIAL_PORT_COM1: u16 = 0x3f8;
const SERIAL_PORT_LAST: u16 = SERIAL_PORT_COM1 + 7;
const SERIAL_READY_LINE: &str = "READY";
const SERIAL_EXEC_PREFIX: &str = "EXEC:";
const SERIAL_OUTPUT_PREFIX: &str = "OUTPUT:";
const SERIAL_EXIT_PREFIX: &str = "EXIT:";
#[cfg(any(debug_assertions, feature = "boot-profile"))]
const SERIAL_BOOT_TIME_PREFIX: &str = "BOOT_TIME:";
const WATCHDOG_SIGNAL: libc::c_int = libc::SIGUSR1;
const PIC_MASTER_COMMAND_REG: u16 = 0x20;
const PIC_MASTER_DATA_REG: u16 = 0x21;
const PIT_CHANNEL0_DATA_REG: u16 = 0x40;
const PIT_MODE_COMMAND_REG: u16 = 0x43;
const I8042_PORT_B_REG: u16 = 0x61;
const I8042_COMMAND_REG: u16 = 0x64;
const I8042_PORT_B_PIT_TICK: u8 = 0x20;
const I8042_RESET_CMD: u8 = 0xfe;
const RTC_INDEX_REG: u16 = 0x70;
const RTC_DATA_REG: u16 = 0x71;
const PIC_SLAVE_COMMAND_REG: u16 = 0xa0;
const PIC_SLAVE_DATA_REG: u16 = 0xa1;
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
const MSR_IA32_APICBASE: u32 = 0x1b;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_MISC_ENABLE: u32 = 0x1a0;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_APICBASE_BSP: u64 = 1 << 8;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_APICBASE_ENABLE: u64 = 1 << 11;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_APICBASE_BASE: u64 = 0xfee0_0000;
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
const APIC_SPIV_REG_OFFSET: usize = 0x0f0;
#[cfg(target_arch = "x86_64")]
const APIC_SPIV_VECTOR_MASK: i32 = 0x00ff;
#[cfg(target_arch = "x86_64")]
const APIC_SPIV_SW_ENABLE: i32 = 0x0100;
#[cfg(target_arch = "x86_64")]
const APIC_LVT0_REG_OFFSET: usize = 0x350;
#[cfg(target_arch = "x86_64")]
const APIC_LVT1_REG_OFFSET: usize = 0x360;
#[cfg(target_arch = "x86_64")]
const APIC_MODE_EXTINT: i32 = 0x7;
#[cfg(target_arch = "x86_64")]
const APIC_MODE_NMI: i32 = 0x4;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF_KVM_SIGNATURE: u32 = 0x4000_0000;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF_KVM_FEATURES: u32 = 0x4000_0001;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF_TIMING_INFO: u32 = 0x4000_0010;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF1_FUNCTION: u32 = 0x1;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF1_EDX_APIC: u32 = 1 << 9;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF1_ECX_TSC_DEADLINE: u32 = 1 << 24;
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

/// 缓存冷启动阶段重复读取的内核与 rootfs 字节，避免每次创建 VM 都访问磁盘。
#[derive(Debug, Default)]
struct AssetCache {
    kernel: Option<(PathBuf, u64, Arc<[u8]>)>,
    rootfs: Option<(PathBuf, u64, Arc<[u8]>)>,
}

impl AssetCache {
    fn global() -> &'static Mutex<AssetCache> {
        ASSET_CACHE.get_or_init(|| Mutex::new(AssetCache::default()))
    }

    fn load(
        path: &Path,
        slot: &mut Option<(PathBuf, u64, Arc<[u8]>)>,
    ) -> Result<Arc<[u8]>, MicrovmError> {
        let metadata = fs::metadata(path).map_err(|err| {
            MicrovmError::Backend(format!("读取资源元数据失败: {}: {err}", path.display()))
        })?;
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        if let Some((cached_path, cached_mtime, cached_bytes)) = slot
            && cached_path.as_path() == path
            && *cached_mtime == mtime
        {
            return Ok(Arc::clone(cached_bytes));
        }

        let bytes: Arc<[u8]> = fs::read(path)
            .map_err(|err| {
                MicrovmError::Backend(format!("读取资源文件失败: {}: {err}", path.display()))
            })?
            .into();
        *slot = Some((path.to_path_buf(), mtime, Arc::clone(&bytes)));
        Ok(bytes)
    }

    fn get_kernel(path: &Path) -> Result<Arc<[u8]>, MicrovmError> {
        let mut cache = match Self::global().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::load(path, &mut cache.kernel)
    }

    fn get_rootfs(path: &Path) -> Result<Arc<[u8]>, MicrovmError> {
        let mut cache = match Self::global().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::load(path, &mut cache.rootfs)
    }
}

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

#[cfg(any(debug_assertions, feature = "boot-profile"))]
#[derive(Debug, Clone, Default)]
struct GuestBootProfile {
    init_entry_ns: Option<u64>,
    mounts_done_ns: Option<u64>,
    uart_access_done_ns: Option<u64>,
    init_ok_ns: Option<u64>,
    ready_ns: Option<u64>,
    command_loop_ns: Option<u64>,
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
impl GuestBootProfile {
    fn record(&mut self, stage: &str, timestamp_ns: u64) {
        match stage {
            "init_entry" => self.init_entry_ns = Some(timestamp_ns),
            "mounts_done" => self.mounts_done_ns = Some(timestamp_ns),
            "uart_access_done" => self.uart_access_done_ns = Some(timestamp_ns),
            "init_ok" => self.init_ok_ns = Some(timestamp_ns),
            "ready" => self.ready_ns = Some(timestamp_ns),
            "command_loop" => self.command_loop_ns = Some(timestamp_ns),
            _ => {}
        }
    }

    fn command_loop_recorded(&self) -> bool {
        self.command_loop_ns.is_some()
    }
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
#[derive(Debug, Clone, Default)]
struct BootProfile {
    t_total_start: Option<Instant>,
    t_kvm_open: Option<Instant>,
    t_vm_create: Option<Instant>,
    t_memory_setup: Option<Instant>,
    t_kernel_load: Option<Instant>,
    t_rootfs_load: Option<Instant>,
    t_vcpu_setup: Option<Instant>,
    t_boot_start: Option<Instant>,
    t_boot_ready: Option<Instant>,
    t_total_end: Option<Instant>,
    memory_alloc_duration: Duration,
    memory_register_duration: Duration,
    kernel_load_duration: Duration,
    rootfs_load_duration: Duration,
    vcpu_create_duration: Duration,
    vcpu_config_duration: Duration,
    boot_params_duration: Duration,
    guest: GuestBootProfile,
    host_logged: bool,
    guest_extension_logged: bool,
    capture_guest_boot_lines: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct CreateVmProfile {
    kvm_fd_open: Duration,
    kvm_create_vm: Duration,
    vm_arch_setup: Duration,
    guest_memory_mmap: Duration,
    kernel_asset_read: Duration,
    rootfs_asset_read: Duration,
    kernel_elf_load: Duration,
    rootfs_write: Duration,
    kvm_set_user_memory_region: Duration,
    vcpu_creation: Duration,
    vcpu_register_config: Duration,
    cpuid_config: Duration,
    boot_params: Duration,
    create_vm_total: Duration,
    boot_wait: Duration,
}

impl CreateVmProfile {
    fn profiled_create_vm_total(&self) -> Duration {
        self.kvm_fd_open
            + self.kvm_create_vm
            + self.vm_arch_setup
            + self.guest_memory_mmap
            + self.kernel_asset_read
            + self.rootfs_asset_read
            + self.kernel_elf_load
            + self.rootfs_write
            + self.kvm_set_user_memory_region
            + self.vcpu_creation
            + self.boot_params
    }

    fn create_vm_misc(&self) -> Duration {
        self.create_vm_total
            .checked_sub(self.profiled_create_vm_total())
            .unwrap_or_default()
    }

    fn cold_start_total(&self) -> Duration {
        self.create_vm_total + self.cpuid_config + self.vcpu_register_config + self.boot_wait
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct RestoreProfile {
    kvm_fd_open: Duration,
    kvm_create_vm: Duration,
    vm_arch_setup: Duration,
    guest_memory_mmap: Duration,
    kvm_set_user_memory_region: Duration,
    vcpu_creation: Duration,
    cpuid_config: Duration,
    memory_state_write: Duration,
    vcpu_state_restore: Duration,
    device_state_restore: Duration,
    resume_kvm_run: Option<Duration>,
}

impl RestoreProfile {
    fn total_without_resume(&self) -> Duration {
        self.kvm_fd_open
            + self.kvm_create_vm
            + self.vm_arch_setup
            + self.guest_memory_mmap
            + self.kvm_set_user_memory_region
            + self.vcpu_creation
            + self.cpuid_config
            + self.memory_state_write
            + self.vcpu_state_restore
            + self.device_state_restore
    }

    fn total_with_resume(&self) -> Duration {
        self.total_without_resume() + self.resume_kvm_run.unwrap_or_default()
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct VcpuSetupProfile {
    cpuid_config: Duration,
    register_config: Duration,
}

#[derive(Debug, Default, Clone, Copy)]
struct RuntimeRestoreProfile {
    vcpu_state_restore: Duration,
    device_state_restore: Duration,
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
impl BootProfile {
    fn start() -> Self {
        Self {
            t_total_start: Some(Instant::now()),
            capture_guest_boot_lines: true,
            ..Default::default()
        }
    }

    fn mark_kvm_open(&mut self) {
        self.t_kvm_open = Some(Instant::now());
    }

    fn mark_vm_create(&mut self) {
        self.t_vm_create = Some(Instant::now());
    }

    fn mark_memory_setup(&mut self) {
        self.t_memory_setup = Some(Instant::now());
    }

    fn mark_kernel_load(&mut self) {
        self.t_kernel_load = Some(Instant::now());
    }

    fn mark_rootfs_load(&mut self) {
        self.t_rootfs_load = Some(Instant::now());
    }

    fn mark_vcpu_setup(&mut self) {
        self.t_vcpu_setup = Some(Instant::now());
    }

    fn mark_boot_start(&mut self) {
        self.t_boot_start = Some(Instant::now());
    }

    fn mark_boot_ready(&mut self) {
        let now = Instant::now();
        self.t_boot_ready = Some(now);
        self.t_total_end = Some(now);
    }

    fn add_vcpu_create_duration(&mut self, started_at: Instant) {
        self.vcpu_create_duration += started_at.elapsed();
    }

    fn add_memory_alloc_duration(&mut self, started_at: Instant) {
        self.memory_alloc_duration += started_at.elapsed();
    }

    fn add_memory_register_duration(&mut self, started_at: Instant) {
        self.memory_register_duration += started_at.elapsed();
    }

    fn add_kernel_load_duration(&mut self, started_at: Instant) {
        self.kernel_load_duration += started_at.elapsed();
    }

    fn add_rootfs_load_duration(&mut self, started_at: Instant) {
        self.rootfs_load_duration += started_at.elapsed();
    }

    fn add_vcpu_config_duration(&mut self, started_at: Instant) {
        self.vcpu_config_duration += started_at.elapsed();
    }

    fn add_boot_params_duration(&mut self, started_at: Instant) {
        self.boot_params_duration += started_at.elapsed();
    }

    fn should_parse_guest_line(&self) -> bool {
        self.capture_guest_boot_lines
    }

    fn record_guest_time(&mut self, stage: &str, timestamp_ns: u64) {
        self.guest.record(stage, timestamp_ns);
    }

    fn close_guest_capture(&mut self) {
        self.capture_guest_boot_lines = false;
    }

    fn host_total_duration(&self) -> Option<Duration> {
        duration_between(self.t_total_start, self.t_total_end)
    }

    fn host_step_duration(&self, start: Option<Instant>, end: Option<Instant>) -> Option<Duration> {
        duration_between(start, end)
    }

    fn memory_step_duration(&self) -> Duration {
        self.memory_alloc_duration + self.memory_register_duration
    }

    fn kernel_step_duration(&self) -> Duration {
        self.kernel_load_duration
    }

    fn rootfs_step_duration(&self) -> Duration {
        self.rootfs_load_duration
    }

    fn vcpu_step_duration(&self) -> Duration {
        self.vcpu_create_duration + self.vcpu_config_duration
    }

    fn guest_command_loop_recorded(&self) -> bool {
        self.guest.command_loop_recorded()
    }
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
    kernel_bytes: Arc<[u8]>,
    rootfs_bytes: Arc<[u8]>,
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
    create_vm_profile: Option<CreateVmProfile>,
    pending_restore_profile: Option<RestoreProfile>,
    #[cfg(any(debug_assertions, feature = "boot-profile"))]
    boot_profile: BootProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendCreateMode {
    ColdStart,
    SnapshotRestore,
}

impl KvmBackend {
    /// 执行 `KVM_CREATE_VM`，分配 guest memory 并创建 vCPU。
    pub fn create_vm(
        base_config: SandboxConfig,
        config: MicrovmConfig,
    ) -> Result<Self, MicrovmError> {
        Self::create_vm_with_mode(base_config, config, BackendCreateMode::ColdStart)
    }

    pub(crate) fn create_vm_for_restore(
        base_config: SandboxConfig,
        config: MicrovmConfig,
    ) -> Result<Self, MicrovmError> {
        Self::create_vm_with_mode(base_config, config, BackendCreateMode::SnapshotRestore)
    }

    fn create_vm_with_mode(
        base_config: SandboxConfig,
        config: MicrovmConfig,
        mode: BackendCreateMode,
    ) -> Result<Self, MicrovmError> {
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        let mut boot_profile = BootProfile::start();
        let create_started_at = Instant::now();
        let mut create_vm_profile = CreateVmProfile::default();
        let mut restore_profile = RestoreProfile::default();

        config.validate()?;
        info!(
            vcpu_count = config.vcpu_count,
            memory_mb = config.memory_mb,
            "创建 KVM microVM"
        );

        let kvm_open_started_at = Instant::now();
        let kvm = Kvm::new().map_err(to_backend_error)?;
        let kvm_open_elapsed = kvm_open_started_at.elapsed();
        create_vm_profile.kvm_fd_open = kvm_open_elapsed;
        restore_profile.kvm_fd_open = kvm_open_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        boot_profile.mark_kvm_open();

        let vm_create_started_at = Instant::now();
        let vm_fd = kvm.create_vm().map_err(to_backend_error)?;
        let vm_create_elapsed = vm_create_started_at.elapsed();
        create_vm_profile.kvm_create_vm = vm_create_elapsed;
        restore_profile.kvm_create_vm = vm_create_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        boot_profile.mark_vm_create();

        let vm_arch_setup_started_at = Instant::now();
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
        let vm_arch_setup_elapsed = vm_arch_setup_started_at.elapsed();
        create_vm_profile.vm_arch_setup = vm_arch_setup_elapsed;
        restore_profile.vm_arch_setup = vm_arch_setup_elapsed;

        let memory_alloc_started_at = Instant::now();
        let guest_memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), config.memory_bytes()?)])
                .map_err(to_backend_error)?;
        let guest_memory_mmap_elapsed = memory_alloc_started_at.elapsed();
        create_vm_profile.guest_memory_mmap = guest_memory_mmap_elapsed;
        restore_profile.guest_memory_mmap = guest_memory_mmap_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        boot_profile.add_memory_alloc_duration(memory_alloc_started_at);

        let (kernel_bytes, rootfs_bytes) = match mode {
            BackendCreateMode::ColdStart => {
                let kernel_asset_started_at = Instant::now();
                let kernel_bytes = AssetCache::get_kernel(config.kernel_path.as_path())?;
                let kernel_asset_elapsed = kernel_asset_started_at.elapsed();
                create_vm_profile.kernel_asset_read = kernel_asset_elapsed;
                #[cfg(any(debug_assertions, feature = "boot-profile"))]
                boot_profile.add_kernel_load_duration(kernel_asset_started_at);

                let rootfs_asset_started_at = Instant::now();
                let rootfs_bytes = AssetCache::get_rootfs(config.rootfs_path.as_path())?;
                validate_initrd_image(&rootfs_bytes)?;
                let rootfs_asset_elapsed = rootfs_asset_started_at.elapsed();
                create_vm_profile.rootfs_asset_read = rootfs_asset_elapsed;
                #[cfg(any(debug_assertions, feature = "boot-profile"))]
                boot_profile.add_rootfs_load_duration(rootfs_asset_started_at);
                (kernel_bytes, rootfs_bytes)
            }
            BackendCreateMode::SnapshotRestore => (
                Arc::<[u8]>::from(Vec::<u8>::new()),
                Arc::<[u8]>::from(Vec::<u8>::new()),
            ),
        };
        let mut vcpus = Vec::with_capacity(usize::from(config.vcpu_count));
        let vcpu_create_started_at = Instant::now();
        for vcpu_index in 0..u64::from(config.vcpu_count) {
            let vcpu = vm_fd.create_vcpu(vcpu_index).map_err(to_backend_error)?;
            vcpus.push(vcpu);
        }
        let vcpu_creation_elapsed = vcpu_create_started_at.elapsed();
        create_vm_profile.vcpu_creation = vcpu_creation_elapsed;
        restore_profile.vcpu_creation = vcpu_creation_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        boot_profile.add_vcpu_create_duration(vcpu_create_started_at);

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
            create_vm_profile: None,
            pending_restore_profile: None,
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            boot_profile,
        };
        let memory_register_started_at = Instant::now();
        backend.register_guest_memory()?;
        let memory_register_elapsed = memory_register_started_at.elapsed();
        create_vm_profile.kvm_set_user_memory_region = memory_register_elapsed;
        restore_profile.kvm_set_user_memory_region = memory_register_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        {
            backend
                .boot_profile
                .add_memory_register_duration(memory_register_started_at);
            backend.boot_profile.mark_memory_setup();
        }

        if mode == BackendCreateMode::ColdStart {
            let kernel_load_started_at = Instant::now();
            backend.load_kernel()?;
            create_vm_profile.kernel_elf_load = kernel_load_started_at.elapsed();
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            {
                backend
                    .boot_profile
                    .add_kernel_load_duration(kernel_load_started_at);
                backend.boot_profile.mark_kernel_load();
            }

            let rootfs_load_started_at = Instant::now();
            backend.load_initrd()?;
            create_vm_profile.rootfs_write = rootfs_load_started_at.elapsed();
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            {
                backend
                    .boot_profile
                    .add_rootfs_load_duration(rootfs_load_started_at);
                backend.boot_profile.mark_rootfs_load();
            }

            let boot_params_started_at = Instant::now();
            backend.write_boot_params()?;
            backend.load_rootfs_metadata()?;
            create_vm_profile.boot_params = boot_params_started_at.elapsed();
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            backend
                .boot_profile
                .add_boot_params_duration(boot_params_started_at);

            create_vm_profile.create_vm_total = create_started_at.elapsed();
            backend.create_vm_profile = Some(create_vm_profile);
        } else {
            backend.pending_restore_profile = Some(restore_profile);
        }

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

    #[cfg(target_arch = "x86_64")]
    fn build_boot_cpuid(&self) -> Result<kvm_bindings::CpuId, MicrovmError> {
        let supported_cpuid = self
            .kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(to_backend_error)?;
        let mut entries = supported_cpuid.as_slice().to_vec();
        apply_host_passthrough_cpuid(&self.kvm, &mut entries);

        if let Some(tsc_khz) = self.boot_tsc_khz() {
            // 当前稳定可获取的是 TSC 频率；LAPIC 频率缺少统一可靠的宿主查询接口，
            // 先保守置 0，优先让 guest 命中 TSC 快路径。
            if !inject_hypervisor_timing_cpuid(&mut entries, tsc_khz, 0) {
                debug!(
                    entry_count = entries.len(),
                    tsc_khz, "CPUID 条目已满，跳过注入 timing leaf"
                );
            }
        }

        entries.sort_by_key(|entry| (entry.function, entry.index));
        kvm_bindings::CpuId::from_entries(&entries).map_err(to_backend_error)
    }

    #[cfg(target_arch = "x86_64")]
    fn boot_tsc_khz(&self) -> Option<u32> {
        if !self.kvm.check_extension(Cap::GetTscKhz) {
            return None;
        }

        let vcpu = match self.vcpus.first() {
            Some(vcpu) => vcpu,
            None => return None,
        };

        match vcpu.get_tsc_khz() {
            Ok(0) => None,
            Ok(tsc_khz) => Some(tsc_khz),
            Err(err) => {
                debug!(error = %err, "读取 vCPU TSC 频率失败，跳过 timing leaf");
                None
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn apply_boot_cpuid_to_vcpus(&self) -> Result<(), MicrovmError> {
        let supported_cpuid = self.build_boot_cpuid()?;
        for vcpu in &self.vcpus {
            vcpu.set_cpuid2(&supported_cpuid)
                .map_err(to_backend_error)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn configure_boot_vcpu_registers(&self) -> Result<(), MicrovmError> {
        for (vcpu_index, vcpu) in self.vcpus.iter().enumerate() {
            configure_linux_boot_sregs(&self.guest_memory, vcpu)?;
            configure_boot_fpu(vcpu)?;
            configure_boot_msrs(vcpu, vcpu_index == 0)?;
            configure_lapic(vcpu)?;

            let mut regs = vcpu.get_regs().map_err(to_backend_error)?;
            regs.rip = self.loaded_kernel.entry_point;
            regs.rsp = BOOT_STACK_POINTER;
            regs.rbp = BOOT_STACK_POINTER;
            regs.rsi = self.boot_params_addr;
            regs.rflags = 0x2;
            vcpu.set_regs(&regs).map_err(to_backend_error)?;
        }
        Ok(())
    }

    fn configure_boot_vcpus(&self) -> Result<VcpuSetupProfile, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            let cpuid_started_at = Instant::now();
            self.apply_boot_cpuid_to_vcpus()?;
            let cpuid_config = cpuid_started_at.elapsed();

            let register_started_at = Instant::now();
            self.configure_boot_vcpu_registers()?;
            let register_config = register_started_at.elapsed();

            return Ok(VcpuSetupProfile {
                cpuid_config,
                register_config,
            });
        }

        #[allow(unreachable_code)]
        Err(MicrovmError::Backend(
            "当前 KVM bring-up 仅支持 x86_64".into(),
        ))
    }

    fn prepare_restored_vcpus(&self) -> Result<Duration, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            let cpuid_started_at = Instant::now();
            self.apply_boot_cpuid_to_vcpus()?;
            return Ok(cpuid_started_at.elapsed());
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

    /// 返回 guest 是否已经进入 READY 状态。
    pub fn is_guest_ready(&self) -> bool {
        self.lifecycle == KvmLifecycle::Ready && self.guest_ready
    }

    /// 清理池化复用时不应泄漏到下一次借出的宿主侧状态。
    pub fn clear_pool_artifacts(&mut self) {
        self.serial_buffer.clear();
        self.last_command_payload.clear();
        self.last_exit_reason = None;
        self.last_io_detail = None;
        self.recent_io_details.clear();
    }

    fn emit_create_vm_profile(&mut self) {
        let Some(profile) = self.create_vm_profile.take() else {
            return;
        };

        eprintln!(
            "[mimobox-vm][create_vm] total={:?} cold_start_total={:?} boot_wait={:?}",
            profile.create_vm_total,
            profile.cold_start_total(),
            profile.boot_wait,
        );
        eprintln!(
            "[mimobox-vm][create_vm] 1.kvm_fd_open={:?} 2.kvm_create_vm={:?} arch_setup={:?}",
            profile.kvm_fd_open, profile.kvm_create_vm, profile.vm_arch_setup,
        );
        eprintln!(
            "[mimobox-vm][create_vm] 3.guest_memory_mmap={:?} 4.kernel_elf_load={:?} 5.rootfs_write={:?}",
            profile.guest_memory_mmap, profile.kernel_elf_load, profile.rootfs_write,
        );
        eprintln!(
            "[mimobox-vm][create_vm] 6.kvm_set_user_memory_region={:?} 7.vcpu_creation={:?}",
            profile.kvm_set_user_memory_region, profile.vcpu_creation,
        );
        eprintln!(
            "[mimobox-vm][create_vm] 8.vcpu_register_config={:?} 9.cpuid_config={:?} 10.boot_params={:?}",
            profile.vcpu_register_config, profile.cpuid_config, profile.boot_params,
        );
        eprintln!(
            "[mimobox-vm][create_vm] asset_read: kernel={:?} rootfs={:?} create_vm_misc={:?}",
            profile.kernel_asset_read,
            profile.rootfs_asset_read,
            profile.create_vm_misc(),
        );
    }

    fn take_or_seed_restore_profile(&mut self) -> RestoreProfile {
        if let Some(profile) = self.pending_restore_profile.take() {
            return profile;
        }

        let mut profile = RestoreProfile::default();
        if let Some(create_vm_profile) = self.create_vm_profile.take() {
            profile.kvm_fd_open = create_vm_profile.kvm_fd_open;
            profile.kvm_create_vm = create_vm_profile.kvm_create_vm;
            profile.vm_arch_setup = create_vm_profile.vm_arch_setup;
            profile.guest_memory_mmap = create_vm_profile.guest_memory_mmap;
            profile.kvm_set_user_memory_region = create_vm_profile.kvm_set_user_memory_region;
            profile.vcpu_creation = create_vm_profile.vcpu_creation;
        }
        profile
    }

    fn emit_restore_profile_without_resume(&self, profile: &RestoreProfile) {
        eprintln!(
            "[mimobox-vm][snapshot-restore] total_without_resume={:?}",
            profile.total_without_resume(),
        );
        eprintln!(
            "[mimobox-vm][snapshot-restore] kvm_fd_open={:?} 1.kvm_create_vm={:?} arch_setup={:?}",
            profile.kvm_fd_open, profile.kvm_create_vm, profile.vm_arch_setup,
        );
        eprintln!(
            "[mimobox-vm][snapshot-restore] 2.guest_memory_mmap={:?} kvm_set_user_memory_region={:?} vcpu_creation={:?}",
            profile.guest_memory_mmap, profile.kvm_set_user_memory_region, profile.vcpu_creation,
        );
        eprintln!(
            "[mimobox-vm][snapshot-restore] 3.memory_state_write={:?} cpuid_config={:?}",
            profile.memory_state_write, profile.cpuid_config,
        );
        eprintln!(
            "[mimobox-vm][snapshot-restore] 4.vcpu_state_restore={:?} 5.device_state_restore={:?}",
            profile.vcpu_state_restore, profile.device_state_restore,
        );
        eprintln!("[mimobox-vm][snapshot-restore] 6.resume_kvm_run=待首个 KVM_RUN 实测");
    }

    fn finish_restore_resume_profile(&mut self, resume_kvm_run: Duration) {
        let Some(mut profile) = self.pending_restore_profile.take() else {
            return;
        };
        if profile.resume_kvm_run.is_some() {
            self.pending_restore_profile = Some(profile);
            return;
        }
        profile.resume_kvm_run = Some(resume_kvm_run);
        eprintln!(
            "[mimobox-vm][snapshot-restore] 6.resume_kvm_run={:?} total_with_resume={:?}",
            resume_kvm_run,
            profile.total_with_resume(),
        );
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
        let exit_reason: Result<KvmExitReason, MicrovmError> = (|| {
            if !self.guest_booted {
                #[cfg(any(debug_assertions, feature = "boot-profile"))]
                let vcpu_config_started_at = Instant::now();
                let vcpu_setup = self.configure_boot_vcpus()?;
                if let Some(profile) = self.create_vm_profile.as_mut() {
                    profile.vcpu_register_config = vcpu_setup.register_config;
                    profile.cpuid_config = vcpu_setup.cpuid_config;
                }
                #[cfg(any(debug_assertions, feature = "boot-profile"))]
                {
                    self.boot_profile
                        .add_vcpu_config_duration(vcpu_config_started_at);
                    self.boot_profile.mark_vcpu_setup();
                }
            }
            let boot_wait_started_at = Instant::now();
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            self.boot_profile.mark_boot_start();
            let exit_reason = self.run_until_boot_ready()?;
            if let Some(profile) = self.create_vm_profile.as_mut() {
                profile.boot_wait = boot_wait_started_at.elapsed();
            }
            Ok(exit_reason)
        })();
        self.lifecycle = KvmLifecycle::Ready;
        let exit_reason = exit_reason?;
        self.guest_booted = true;
        self.guest_ready = exit_reason == KvmExitReason::Io;
        if self.guest_ready {
            self.emit_create_vm_profile();
        }
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        if self.guest_ready {
            log_boot_profile(&mut self.boot_profile);
        }
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
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        if self.boot_profile.host_logged && !self.boot_profile.guest_extension_logged {
            self.boot_profile.close_guest_capture();
        }
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
        let mut restore_profile = self.take_or_seed_restore_profile();

        let restore_memory_started_at = Instant::now();
        self.restore_guest_memory(memory)?;
        restore_profile.memory_state_write = restore_memory_started_at.elapsed();

        restore_profile.cpuid_config = self.prepare_restored_vcpus()?;

        let runtime_restore_profile = restore_runtime_state(self, vcpu_state)?;
        restore_profile.vcpu_state_restore = runtime_restore_profile.vcpu_state_restore;
        restore_profile.device_state_restore = runtime_restore_profile.device_state_restore;
        self.lifecycle = KvmLifecycle::Ready;
        self.emit_restore_profile_without_resume(&restore_profile);
        self.pending_restore_profile = Some(restore_profile);
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
            self.base_config.timeout_secs.unwrap_or(30),
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
        let should_track_io_detail = response.is_some();
        let measure_restore_resume = self.pending_restore_profile.is_some();
        let restore_resume_started_at = measure_restore_resume.then(Instant::now);
        let run_result = {
            let vcpu = self
                .vcpus
                .first_mut()
                .ok_or_else(|| MicrovmError::Backend("至少需要一个 vCPU".into()))?;
            vcpu.run()
        };
        let outcome = (|| -> Result<RunLoopOutcome, MicrovmError> {
            let exit = match run_result {
                Ok(exit) => exit,
                Err(err) if watchdog.timed_out() => {
                    return Err(MicrovmError::Backend(format!(
                        "KVM_RUN 被 watchdog 中断: {err}"
                    )));
                }
                Err(err) => return Err(to_backend_error(err)),
            };

            let serial_device = &mut self.serial_device;
            let serial_buffer = &mut self.serial_buffer;
            let guest_ready = &mut self.guest_ready;
            let last_exit_reason = &mut self.last_exit_reason;
            let last_io_detail = &mut self.last_io_detail;
            let recent_io_details = &mut self.recent_io_details;
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            let boot_profile = &mut self.boot_profile;

            match exit {
                VcpuExit::IoOut(port, data) if is_serial_port(port) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("serial out port={port:#x} size={}", data.len()),
                        );
                    }
                    #[cfg(any(debug_assertions, feature = "boot-profile"))]
                    let action = handle_serial_write(
                        serial_device,
                        serial_buffer,
                        guest_ready,
                        boot_profile,
                        port,
                        data,
                        line_buffer,
                        response,
                    )?;
                    #[cfg(not(any(debug_assertions, feature = "boot-profile")))]
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
                    #[cfg(any(debug_assertions, feature = "boot-profile"))]
                    if boot_profile.host_logged
                        && !boot_profile.guest_extension_logged
                        && boot_profile.guest_command_loop_recorded()
                    {
                        log_guest_boot_profile_extension(boot_profile);
                    }
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::IoIn(port, data) if is_serial_port(port) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("serial in port={port:#x} size={}", data.len()),
                        );
                    }
                    handle_serial_read(serial_device, port, data)?;
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::MmioRead(addr, data) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("mmio read addr={addr:#x} size={}", data.len()),
                        );
                    }
                    data.fill(0);
                    debug!(addr, size = data.len(), "guest 触发 MMIO 读退出");
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("mmio write addr={addr:#x} size={}", data.len()),
                        );
                    }
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
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("pio out port={port:#x} size={}", data.len()),
                        );
                    }
                    if !*guest_ready && is_boot_legacy_pio_port(port) {
                        *last_exit_reason = Some(KvmExitReason::Io);
                        return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                    }
                    if port == PCI_CONFIG_ADDRESS_REG {
                        debug!(port, size = data.len(), "忽略 PCI 配置地址写");
                        *last_exit_reason = Some(KvmExitReason::Io);
                        return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                    }
                    if port == I8042_COMMAND_REG
                        && data.len() == 1
                        && data[0] == I8042_RESET_CMD
                    {
                        *last_exit_reason = Some(KvmExitReason::Shutdown);
                        return Ok(RunLoopOutcome::Exit(KvmExitReason::Shutdown));
                    }
                    debug!(port, size = data.len(), "忽略非串口 PIO 写退出");
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::IoIn(port, data) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("pio in port={port:#x} size={}", data.len()),
                        );
                    }
                    if !*guest_ready && emulate_boot_legacy_pio_read(port, data) {
                        *last_exit_reason = Some(KvmExitReason::Io);
                        return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                    }
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
        })();
        if let Some(started_at) = restore_resume_started_at {
            self.finish_restore_resume_profile(started_at.elapsed());
        }
        outcome
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
        const ZEROES: [u8; 65536] = [0; 65536];
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
fn inject_hypervisor_timing_cpuid(
    entries: &mut Vec<kvm_cpuid_entry2>,
    tsc_khz: u32,
    lapic_khz: u32,
) -> bool {
    let has_signature = entries
        .iter()
        .any(|entry| entry.function == CPUID_LEAF_KVM_SIGNATURE && entry.index == 0);
    let has_timing = entries
        .iter()
        .any(|entry| entry.function == CPUID_LEAF_TIMING_INFO && entry.index == 0);
    let missing_entries = usize::from(!has_signature) + usize::from(!has_timing);
    if entries.len() + missing_entries > KVM_MAX_CPUID_ENTRIES {
        return false;
    }

    if let Some(signature) = entries
        .iter_mut()
        .find(|entry| entry.function == CPUID_LEAF_KVM_SIGNATURE && entry.index == 0)
    {
        signature.eax = signature.eax.max(CPUID_LEAF_TIMING_INFO);
    } else {
        entries.push(kvm_cpuid_entry2 {
            function: CPUID_LEAF_KVM_SIGNATURE,
            index: 0,
            eax: CPUID_LEAF_TIMING_INFO.max(CPUID_LEAF_KVM_FEATURES),
            ebx: 0x4b4d_564b,
            ecx: 0x564b_4d56,
            edx: 0x0000_004d,
            ..Default::default()
        });
    }

    let timing_leaf = kvm_cpuid_entry2 {
        function: CPUID_LEAF_TIMING_INFO,
        index: 0,
        eax: tsc_khz,
        ebx: lapic_khz,
        ..Default::default()
    };
    if let Some(entry) = entries
        .iter_mut()
        .find(|entry| entry.function == CPUID_LEAF_TIMING_INFO && entry.index == 0)
    {
        *entry = timing_leaf;
    } else {
        entries.push(timing_leaf);
    }

    true
}

#[cfg(target_arch = "x86_64")]
fn apply_host_passthrough_cpuid(kvm: &Kvm, entries: &mut [kvm_cpuid_entry2]) {
    let (host_leaf1_ecx, host_leaf1_edx) = host_passthrough_cpuid_bits(kvm);

    for entry in entries {
        if entry.function != CPUID_LEAF1_FUNCTION || entry.index != 0 {
            continue;
        }

        // 这里保留 KVM 过滤后的可用特性集合，只把对冷启动最关键的
        // TSC deadline/APIC 位显式对齐到宿主机能力，避免 guest 回落到更慢的校准路径。
        entry.ecx |= host_leaf1_ecx;
        entry.edx |= host_leaf1_edx;
        return;
    }
}

#[cfg(target_arch = "x86_64")]
fn host_passthrough_cpuid_bits(kvm: &Kvm) -> (u32, u32) {
    // SAFETY: `cpuid` 仅查询宿主机的只读 CPU 特性叶子，不涉及内存别名或未初始化数据。
    let host_leaf1 = unsafe { __cpuid_count(CPUID_LEAF1_FUNCTION, 0) };
    let tsc_deadline = if kvm.check_extension(Cap::TscDeadlineTimer) {
        host_leaf1.ecx & CPUID_LEAF1_ECX_TSC_DEADLINE
    } else {
        0
    };
    let apic = host_leaf1.edx & CPUID_LEAF1_EDX_APIC;
    (tsc_deadline, apic)
}

#[cfg(target_arch = "x86_64")]
fn configure_boot_msrs(vcpu: &VcpuFd, is_bootstrap_processor: bool) -> Result<(), MicrovmError> {
    let apicbase = MSR_IA32_APICBASE_BASE
        | MSR_IA32_APICBASE_ENABLE
        | if is_bootstrap_processor {
            MSR_IA32_APICBASE_BSP
        } else {
            0
        };
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
            index: MSR_IA32_APICBASE,
            data: apicbase,
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
    let spiv = get_klapic_reg(&klapic, APIC_SPIV_REG_OFFSET)?;
    let vector = match spiv & APIC_SPIV_VECTOR_MASK {
        0 => APIC_SPIV_VECTOR_MASK,
        value => value,
    };
    set_klapic_reg(
        &mut klapic,
        APIC_SPIV_REG_OFFSET,
        (spiv & !(APIC_SPIV_VECTOR_MASK | APIC_SPIV_SW_ENABLE)) | vector | APIC_SPIV_SW_ENABLE,
    )?;
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

    state.extend_from_slice(KVM_RUNTIME_STATE_MAGIC_V3);
    encode_vcpu_ids(&mut state, &backend.vcpus)?;
    encode_vm_state(&mut state, backend)?;
    encode_vcpu_states(&mut state, &backend.vcpus)?;
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

fn restore_runtime_state(
    backend: &mut KvmBackend,
    state: &[u8],
) -> Result<RuntimeRestoreProfile, MicrovmError> {
    let mut cursor = ByteCursor::new(state);
    let magic = cursor.read_exact(8)?;
    if magic == KVM_RUNTIME_STATE_MAGIC_V2 {
        return restore_runtime_state_v2(backend, &mut cursor);
    }
    if magic == KVM_RUNTIME_STATE_MAGIC_V3 {
        return restore_runtime_state_v3(backend, &mut cursor);
    }
    Err(MicrovmError::SnapshotFormat(
        "KVM 运行时快照 magic 不匹配".into(),
    ))
}

fn restore_runtime_state_v2(
    backend: &mut KvmBackend,
    cursor: &mut ByteCursor<'_>,
) -> Result<RuntimeRestoreProfile, MicrovmError> {
    restore_vcpu_ids(&backend.vcpus, cursor)?;
    let device_state_started_at = Instant::now();
    restore_runtime_tail(backend, cursor)?;
    Ok(RuntimeRestoreProfile {
        vcpu_state_restore: Duration::ZERO,
        device_state_restore: device_state_started_at.elapsed(),
    })
}

fn restore_runtime_tail(
    backend: &mut KvmBackend,
    cursor: &mut ByteCursor<'_>,
) -> Result<(), MicrovmError> {
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

fn restore_runtime_state_v3(
    backend: &mut KvmBackend,
    cursor: &mut ByteCursor<'_>,
) -> Result<RuntimeRestoreProfile, MicrovmError> {
    restore_vcpu_ids(&backend.vcpus, cursor)?;
    let device_state_started_at = Instant::now();
    restore_vm_state(backend, cursor)?;
    let mut device_state_restore = device_state_started_at.elapsed();

    let vcpu_state_started_at = Instant::now();
    restore_vcpu_states(&backend.vcpus, cursor)?;
    let vcpu_state_restore = vcpu_state_started_at.elapsed();

    let runtime_tail_started_at = Instant::now();
    restore_runtime_tail(backend, cursor)?;
    device_state_restore += runtime_tail_started_at.elapsed();

    Ok(RuntimeRestoreProfile {
        vcpu_state_restore,
        device_state_restore,
    })
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

fn encode_vm_state(out: &mut Vec<u8>, backend: &KvmBackend) -> Result<(), MicrovmError> {
    let clock = backend.vm_fd.get_clock().map_err(to_backend_error)?;
    append_pod(out, &clock);

    let pit = backend.vm_fd.get_pit2().map_err(to_backend_error)?;
    append_pod(out, &pit);

    for chip_id in [
        KVM_IRQCHIP_PIC_MASTER,
        KVM_IRQCHIP_PIC_SLAVE,
        KVM_IRQCHIP_IOAPIC,
    ] {
        let mut irqchip = kvm_irqchip {
            chip_id,
            ..Default::default()
        };
        backend
            .vm_fd
            .get_irqchip(&mut irqchip)
            .map_err(to_backend_error)?;
        append_pod(out, &irqchip);
    }

    Ok(())
}

fn restore_vm_state(
    backend: &mut KvmBackend,
    cursor: &mut ByteCursor<'_>,
) -> Result<(), MicrovmError> {
    let clock: kvm_clock_data = read_pod(cursor)?;
    backend
        .vm_fd
        .set_clock(&clock)
        .map_err(|err| MicrovmError::Backend(format!("恢复 KVM 时钟失败: {err}")))?;

    let pit_state: kvm_pit_state2 = read_pod(cursor)?;
    backend
        .vm_fd
        .set_pit2(&pit_state)
        .map_err(|err| MicrovmError::Backend(format!("恢复 PIT 状态失败: {err}")))?;

    for expected_chip_id in [
        KVM_IRQCHIP_PIC_MASTER,
        KVM_IRQCHIP_PIC_SLAVE,
        KVM_IRQCHIP_IOAPIC,
    ] {
        let irqchip: kvm_irqchip = read_pod(cursor)?;
        if irqchip.chip_id != expected_chip_id {
            return Err(MicrovmError::SnapshotFormat(format!(
                "irqchip ID 不匹配: 快照为 {}，期望 {expected_chip_id}",
                irqchip.chip_id
            )));
        }
        backend.vm_fd.set_irqchip(&irqchip).map_err(|err| {
            MicrovmError::Backend(format!("恢复 irqchip({expected_chip_id}) 状态失败: {err}"))
        })?;
    }

    Ok(())
}

fn encode_vcpu_states(out: &mut Vec<u8>, vcpus: &[VcpuFd]) -> Result<(), MicrovmError> {
    for vcpu in vcpus {
        encode_vcpu_state(out, vcpu)?;
    }
    Ok(())
}

fn encode_vcpu_state(out: &mut Vec<u8>, vcpu: &VcpuFd) -> Result<(), MicrovmError> {
    append_pod(out, &vcpu.get_regs().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_sregs().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_fpu().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_lapic().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_mp_state().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_xsave().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_xcrs().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_vcpu_events().map_err(to_backend_error)?);
    append_msr_entries(out, &snapshot_vcpu_msrs(vcpu)?)?;
    Ok(())
}

fn restore_vcpu_states(vcpus: &[VcpuFd], cursor: &mut ByteCursor<'_>) -> Result<(), MicrovmError> {
    for vcpu in vcpus {
        restore_vcpu_state(vcpu, cursor)?;
    }
    Ok(())
}

fn restore_vcpu_state(vcpu: &VcpuFd, cursor: &mut ByteCursor<'_>) -> Result<(), MicrovmError> {
    let regs: kvm_regs = read_pod(cursor)?;
    let sregs: kvm_sregs = read_pod(cursor)?;
    let fpu: kvm_fpu = read_pod(cursor)?;
    let lapic: kvm_lapic_state = read_pod(cursor)?;
    let mp_state: kvm_mp_state = read_pod(cursor)?;
    let xsave: kvm_xsave = read_pod(cursor)?;
    let xcrs: kvm_xcrs = read_pod(cursor)?;
    let vcpu_events: kvm_vcpu_events = read_pod(cursor)?;
    let msr_entries = read_msr_entries(cursor)?;

    vcpu.set_sregs(&sregs)
        .map_err(|err| MicrovmError::Backend(format!("恢复 sregs 失败: {err}")))?;
    vcpu.set_regs(&regs)
        .map_err(|err| MicrovmError::Backend(format!("恢复 regs 失败: {err}")))?;
    vcpu.set_fpu(&fpu)
        .map_err(|err| MicrovmError::Backend(format!("恢复 fpu 失败: {err}")))?;
    vcpu.set_lapic(&lapic)
        .map_err(|err| MicrovmError::Backend(format!("恢复 lapic 失败: {err}")))?;
    vcpu.set_mp_state(mp_state)
        .map_err(|err| MicrovmError::Backend(format!("恢复 mp_state 失败: {err}")))?;
    vcpu.set_xsave(&xsave)
        .map_err(|err| MicrovmError::Backend(format!("恢复 xsave 失败: {err}")))?;
    vcpu.set_xcrs(&xcrs)
        .map_err(|err| MicrovmError::Backend(format!("恢复 xcrs 失败: {err}")))?;
    vcpu.set_vcpu_events(&vcpu_events)
        .map_err(|err| MicrovmError::Backend(format!("恢复 vcpu_events 失败: {err}")))?;
    restore_vcpu_msrs(vcpu, &msr_entries)?;
    Ok(())
}

fn snapshot_vcpu_msrs(vcpu: &VcpuFd) -> Result<Vec<kvm_msr_entry>, MicrovmError> {
    let template = tracked_msr_entries_template();
    let mut msrs = Msrs::from_entries(&template).map_err(to_backend_error)?;
    let read = vcpu.get_msrs(&mut msrs).map_err(to_backend_error)?;
    if read != template.len() {
        return Err(MicrovmError::Backend(format!(
            "快照 MSR 仅读取 {read}/{} 项",
            template.len()
        )));
    }
    Ok(msrs.as_slice().to_vec())
}

fn restore_vcpu_msrs(vcpu: &VcpuFd, entries: &[kvm_msr_entry]) -> Result<(), MicrovmError> {
    let msrs = Msrs::from_entries(entries).map_err(to_backend_error)?;
    let written = vcpu.set_msrs(&msrs).map_err(to_backend_error)?;
    if written != entries.len() {
        return Err(MicrovmError::Backend(format!(
            "恢复 MSR 仅写入 {written}/{} 项",
            entries.len()
        )));
    }
    Ok(())
}

fn tracked_msr_entries_template() -> [kvm_msr_entry; 12] {
    [
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
            index: MSR_IA32_APICBASE,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_MTRR_DEF_TYPE,
            data: 0,
            ..Default::default()
        },
    ]
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

fn append_msr_entries(out: &mut Vec<u8>, entries: &[kvm_msr_entry]) -> Result<(), MicrovmError> {
    let len = u32_from_len(entries.len(), "MSR 条目数量超过 u32 上限")?;
    out.extend_from_slice(&len.to_le_bytes());
    for entry in entries {
        append_pod(out, entry);
    }
    Ok(())
}

fn read_msr_entries(cursor: &mut ByteCursor<'_>) -> Result<Vec<kvm_msr_entry>, MicrovmError> {
    let len = usize::try_from(cursor.read_u32()?)
        .map_err(|_| MicrovmError::SnapshotFormat("MSR 条目数量无法转换为 usize".into()))?;
    let mut entries = Vec::with_capacity(len);
    for _ in 0..len {
        entries.push(read_pod(cursor)?);
    }
    Ok(entries)
}

fn append_pod<T>(out: &mut Vec<u8>, value: &T) {
    // SAFETY: KVM 绑定结构是可按字节复制的内核 ABI 数据。当前快照仅用于同架构、
    // 同进程版本的 restore，直接保存原始字节不会引入别名或生命周期问题。
    let bytes = unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>())
    };
    out.extend_from_slice(bytes);
}

fn read_pod<T: Default>(cursor: &mut ByteCursor<'_>) -> Result<T, MicrovmError> {
    let bytes = cursor.read_exact(mem::size_of::<T>())?;
    let mut value = T::default();
    // SAFETY: `value` 先以 `Default` 零初始化，再用等长字节覆盖。源字节来自同一 ABI
    // 的 `append_pod` 序列化结果，因此布局和大小匹配。
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut value as *mut T).cast::<u8>(),
            bytes.len(),
        );
    }
    Ok(value)
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
    let mut frame = format!("{SERIAL_EXEC_PREFIX}{}:", command.len()).into_bytes();
    frame.extend_from_slice(command.as_bytes());
    frame.push(b'\n');
    Ok(frame)
}

fn is_serial_port(port: u16) -> bool {
    (SERIAL_PORT_COM1..=SERIAL_PORT_LAST).contains(&port)
}

fn is_boot_legacy_pio_port(port: u16) -> bool {
    matches!(
        port,
        PIC_MASTER_COMMAND_REG | PIC_MASTER_DATA_REG | PIT_CHANNEL0_DATA_REG
            ..=PIT_MODE_COMMAND_REG
                | RTC_INDEX_REG
                | RTC_DATA_REG
                | PIC_SLAVE_COMMAND_REG
                | PIC_SLAVE_DATA_REG
    )
}

fn emulate_boot_legacy_pio_read(port: u16, data: &mut [u8]) -> bool {
    if !is_boot_legacy_pio_port(port) {
        return false;
    }

    data.fill(0);
    true
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
        return Ok(Some(GuestCommandResult {
            stdout: std::mem::take(&mut response.stdout),
            stderr: Vec::new(),
            exit_code: Some(exit_code),
            timed_out: false,
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

    if let Some(timeout_secs) = timeout_secs
        && timeout_secs == 0
    {
        return Err(MicrovmError::InvalidConfig("timeout_secs 不能为 0".into()));
    }

    Ok(join_shell_command(cmd))
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

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn duration_between(start: Option<Instant>, end: Option<Instant>) -> Option<Duration> {
    let start = start?;
    let end = end?;
    Some(end.saturating_duration_since(start))
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn format_duration(duration: Duration) -> String {
    if duration.as_millis() > 0 {
        return format!("{}ms", duration.as_millis());
    }
    if duration.as_micros() > 0 {
        return format!("{}us", duration.as_micros());
    }
    format!("{}ns", duration.as_nanos())
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn format_share(duration: Duration, total: Duration) -> String {
    if total.is_zero() {
        return "0.0%".to_string();
    }

    format!(
        "{:.1}%",
        duration.as_secs_f64() / total.as_secs_f64() * 100.0
    )
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn log_host_boot_profile_line(label: &str, duration: Duration, total: Duration) {
    info!(
        "[boot-profile] {:<12} {:>8} ({})",
        format!("{label}:"),
        format_duration(duration),
        format_share(duration, total)
    );
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn log_guest_boot_profile_line(label: &str, delta_ns: u64, total_ns: u64) {
    let delta = Duration::from_nanos(delta_ns);
    let total = Duration::from_nanos(total_ns);
    info!(
        "[boot-profile][guest] {:<16} +{:>8} (total {})",
        format!("{label}:"),
        format_duration(delta),
        format_duration(total)
    );
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn parse_guest_boot_time_line(line: &str, boot_profile: &mut BootProfile) -> bool {
    let Some(payload) = line.strip_prefix(SERIAL_BOOT_TIME_PREFIX) else {
        return false;
    };
    let Some((stage, raw_ns)) = payload.split_once(':') else {
        debug!(line, "忽略格式非法的 guest BOOT_TIME 行");
        return true;
    };
    let Ok(timestamp_ns) = raw_ns.parse::<u64>() else {
        debug!(line, "忽略时间戳非法的 guest BOOT_TIME 行");
        return true;
    };

    boot_profile.record_guest_time(stage, timestamp_ns);
    true
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn log_guest_boot_profile(boot_profile: &BootProfile) {
    let Some(init_entry_ns) = boot_profile.guest.init_entry_ns else {
        return;
    };

    let mut previous_ns = init_entry_ns;
    for (label, maybe_ns) in [
        ("init_entry", boot_profile.guest.init_entry_ns),
        ("mounts_done", boot_profile.guest.mounts_done_ns),
        ("uart_access", boot_profile.guest.uart_access_done_ns),
        ("init_ok", boot_profile.guest.init_ok_ns),
        ("ready", boot_profile.guest.ready_ns),
    ] {
        let Some(timestamp_ns) = maybe_ns else {
            continue;
        };
        let delta_ns = timestamp_ns.saturating_sub(previous_ns);
        let total_ns = timestamp_ns.saturating_sub(init_entry_ns);
        log_guest_boot_profile_line(label, delta_ns, total_ns);
        previous_ns = timestamp_ns;
    }
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn log_guest_boot_profile_extension(boot_profile: &mut BootProfile) {
    let Some(init_entry_ns) = boot_profile.guest.init_entry_ns else {
        return;
    };
    let Some(command_loop_ns) = boot_profile.guest.command_loop_ns else {
        return;
    };
    let previous_ns = boot_profile
        .guest
        .ready_ns
        .or(boot_profile.guest.init_ok_ns)
        .or(boot_profile.guest.uart_access_done_ns)
        .or(boot_profile.guest.mounts_done_ns)
        .unwrap_or(init_entry_ns);
    let delta_ns = command_loop_ns.saturating_sub(previous_ns);
    let total_ns = command_loop_ns.saturating_sub(init_entry_ns);
    log_guest_boot_profile_line("command_loop", delta_ns, total_ns);
    boot_profile.guest_extension_logged = true;
    boot_profile.close_guest_capture();
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn log_boot_profile(boot_profile: &mut BootProfile) {
    if boot_profile.host_logged {
        return;
    }

    let Some(total) = boot_profile.host_total_duration() else {
        return;
    };
    info!("[boot-profile] total:        {}", format_duration(total));

    let kvm_open = boot_profile
        .host_step_duration(boot_profile.t_total_start, boot_profile.t_kvm_open)
        .unwrap_or_default();
    let vm_create = boot_profile
        .host_step_duration(boot_profile.t_kvm_open, boot_profile.t_vm_create)
        .unwrap_or_default();
    let memory = boot_profile.memory_step_duration();
    let kernel_load = boot_profile.kernel_step_duration();
    let rootfs_load = boot_profile.rootfs_step_duration();
    let boot_params = boot_profile.boot_params_duration;
    let vcpu_setup = boot_profile.vcpu_step_duration();
    let boot_wait = boot_profile
        .host_step_duration(boot_profile.t_boot_start, boot_profile.t_boot_ready)
        .unwrap_or_default();
    let accounted = kvm_open
        + vm_create
        + memory
        + kernel_load
        + rootfs_load
        + boot_params
        + vcpu_setup
        + boot_wait;
    let host_misc = total.saturating_sub(accounted);

    log_host_boot_profile_line("kvm_open", kvm_open, total);
    log_host_boot_profile_line("vm_create", vm_create, total);
    log_host_boot_profile_line("memory", memory, total);
    log_host_boot_profile_line("kernel_load", kernel_load, total);
    log_host_boot_profile_line("rootfs_load", rootfs_load, total);
    log_host_boot_profile_line("boot_params", boot_params, total);
    log_host_boot_profile_line("vcpu_setup", vcpu_setup, total);
    log_host_boot_profile_line("boot_wait", boot_wait, total);
    if !host_misc.is_zero() {
        log_host_boot_profile_line("host_misc", host_misc, total);
    }

    log_guest_boot_profile(boot_profile);
    if boot_profile.guest_command_loop_recorded() {
        log_guest_boot_profile_extension(boot_profile);
    }

    boot_profile.host_logged = true;
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

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn handle_serial_write(
    serial_device: &mut SerialDevice,
    serial_buffer: &mut Vec<u8>,
    guest_ready: &mut bool,
    boot_profile: &mut BootProfile,
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
                if boot_profile.should_parse_guest_line()
                    && parse_guest_boot_time_line(&line, boot_profile)
                {
                    continue;
                }
                if line == SERIAL_READY_LINE {
                    *guest_ready = true;
                    boot_profile.mark_boot_ready();
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

#[cfg(not(any(debug_assertions, feature = "boot-profile")))]
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

#[cfg(test)]
mod tests {
    #[cfg(any(debug_assertions, feature = "boot-profile"))]
    use super::{BootProfile, parse_guest_boot_time_line};
    #[cfg(target_arch = "x86_64")]
    use super::{
        CPUID_LEAF_KVM_FEATURES, CPUID_LEAF_KVM_SIGNATURE, CPUID_LEAF_TIMING_INFO,
        MSR_IA32_APICBASE, inject_hypervisor_timing_cpuid, tracked_msr_entries_template,
    };
    use super::{
        CommandResponse, DEFAULT_CMDLINE, SERIAL_EXEC_PREFIX, build_guest_command,
        encode_command_payload, parse_guest_protocol_line,
    };
    #[cfg(target_arch = "x86_64")]
    use kvm_bindings::kvm_cpuid_entry2;

    #[test]
    fn test_encode_command_payload_uses_length_prefixed_frame() {
        let command = vec![
            "/bin/printf".to_string(),
            "%s".to_string(),
            "hello\nworld".to_string(),
        ];

        let payload = encode_command_payload(&command, Some(1)).expect("编码命令帧必须成功");
        let command_line = build_guest_command(&command, Some(1)).expect("构建 shell 命令必须成功");
        let header = format!("{SERIAL_EXEC_PREFIX}{}:", command_line.len());
        let mut expected = header.into_bytes();
        expected.extend_from_slice(command_line.as_bytes());
        expected.push(b'\n');

        assert_eq!(payload, expected);
        assert!(
            payload
                .windows(b"hello\nworld".len())
                .any(|window| window == b"hello\nworld"),
            "长度前缀帧必须保留命令参数中的换行字节"
        );
    }

    #[test]
    fn test_exit_code_124_is_not_mapped_to_timeout() {
        let mut response = CommandResponse::default();

        let result = parse_guest_protocol_line("EXIT:124", &mut response)
            .expect("解析 EXIT 帧必须成功")
            .expect("EXIT 帧必须产生命令结果");

        assert_eq!(result.exit_code, Some(124));
        assert!(!result.timed_out, "退出码 124 只能表示用户命令退出码");
        assert!(result.stdout.is_empty(), "纯 EXIT 帧不应携带 stdout");
    }

    #[test]
    fn test_default_cmdline_contains_boot_latency_toggles() {
        for token in [
            "pci=off",
            "8250.nr_uarts=1",
            "no_timer_check",
            "fastboot",
            "quiet",
            "rcupdate.rcu_expedited=1",
            "mitigations=off",
            "tsc=reliable",
            "nokaslr",
            "nomodule",
        ] {
            assert!(
                DEFAULT_CMDLINE.split_whitespace().any(|item| item == token),
                "默认 cmdline 必须包含 {token}"
            );
        }
    }

    #[cfg(any(debug_assertions, feature = "boot-profile"))]
    #[test]
    fn test_parse_guest_boot_time_line_records_known_stage() {
        let mut boot_profile = BootProfile::start();

        let consumed = parse_guest_boot_time_line("BOOT_TIME:ready:12345", &mut boot_profile);

        assert!(consumed, "BOOT_TIME 行必须被 host 剖析逻辑消费");
        assert_eq!(boot_profile.guest.ready_ns, Some(12345));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_inject_hypervisor_timing_cpuid_updates_signature_and_adds_timing_leaf() {
        let mut entries = vec![
            kvm_cpuid_entry2 {
                function: CPUID_LEAF_KVM_SIGNATURE,
                index: 0,
                eax: CPUID_LEAF_KVM_FEATURES,
                ebx: 1,
                ecx: 2,
                edx: 3,
                ..Default::default()
            },
            kvm_cpuid_entry2 {
                function: 0x1,
                index: 0,
                ..Default::default()
            },
        ];

        assert!(inject_hypervisor_timing_cpuid(&mut entries, 2_900_000, 0));

        let signature = entries
            .iter()
            .find(|entry| entry.function == CPUID_LEAF_KVM_SIGNATURE && entry.index == 0)
            .expect("必须保留 hypervisor 签名叶");
        assert_eq!(signature.eax, CPUID_LEAF_TIMING_INFO);
        assert_eq!(signature.ebx, 1);
        assert_eq!(signature.ecx, 2);
        assert_eq!(signature.edx, 3);

        let timing = entries
            .iter()
            .find(|entry| entry.function == CPUID_LEAF_TIMING_INFO && entry.index == 0)
            .expect("必须注入 timing leaf");
        assert_eq!(timing.eax, 2_900_000);
        assert_eq!(timing.ebx, 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_inject_hypervisor_timing_cpuid_adds_missing_signature_leaf() {
        let mut entries = vec![kvm_cpuid_entry2 {
            function: 0x1,
            index: 0,
            ..Default::default()
        }];

        assert!(inject_hypervisor_timing_cpuid(&mut entries, 1_234_567, 0));

        let signature = entries
            .iter()
            .find(|entry| entry.function == CPUID_LEAF_KVM_SIGNATURE && entry.index == 0)
            .expect("缺失签名叶时必须自动补齐");
        assert_eq!(signature.eax, CPUID_LEAF_TIMING_INFO);
        assert_eq!(signature.ebx, 0x4b4d_564b);
        assert_eq!(signature.ecx, 0x564b_4d56);
        assert_eq!(signature.edx, 0x0000_004d);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_tracked_msrs_include_apicbase() {
        assert!(
            tracked_msr_entries_template()
                .iter()
                .any(|entry| entry.index == MSR_IA32_APICBASE),
            "快照/恢复需要跟踪 APICBASE MSR"
        );
    }
}
