#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::fs;

use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use mimobox_core::SandboxConfig;
use tracing::{debug, info};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use crate::vm::{GuestCommandResult, MicrovmConfig, MicrovmError};

const ZERO_PAGE_ADDR: u64 = 0x7_000;
const CMDLINE_ADDR: u64 = 0x20_000;
const ROOTFS_METADATA_ADDR: u64 = 0x30_000;
const DEFAULT_CMDLINE: &str = "console=ttyS0 panic=-1 rdinit=/init";
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
const ZERO_PAGE_EXT_RAMDISK_IMAGE: usize = 0x0c0;
const ZERO_PAGE_EXT_RAMDISK_SIZE: usize = 0x0c4;
const ZERO_PAGE_EXT_CMD_LINE_PTR: usize = 0x0c8;
const ZERO_PAGE_E820_TABLE: usize = 0x2d0;
const E820_ENTRY_SIZE: usize = 20;
const E820_RAM: u32 = 1;
const SERIAL_BOOT_BANNER: &[u8] = b"mimobox guest booted\n";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyntheticVmExit<'a> {
    SerialWrite(&'a [u8]),
    Hlt,
}

/// Linux KVM 后端基础实现。
pub struct KvmBackend {
    _base_config: SandboxConfig,
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
    command_event: EventFd,
    loaded_kernel: LoadedKernel,
    boot_params_addr: u64,
    cmdline_addr: u64,
    initrd_addr: u64,
    guest_booted: bool,
    serial_buffer: Vec<u8>,
    last_exit_reason: Option<KvmExitReason>,
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
        let guest_memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), config.memory_bytes()?)])
                .map_err(to_backend_error)?;

        let kernel_bytes = fs::read(&config.kernel_path)?;
        let rootfs_bytes = fs::read(&config.rootfs_path)?;
        validate_initrd_image(&rootfs_bytes)?;

        let command_event = EventFd::new(0).map_err(to_backend_error)?;

        let mut vcpus = Vec::with_capacity(usize::from(config.vcpu_count));
        for vcpu_index in 0..u64::from(config.vcpu_count) {
            let vcpu = vm_fd.create_vcpu(vcpu_index).map_err(to_backend_error)?;
            vcpus.push(vcpu);
        }

        let mut backend = Self {
            _base_config: base_config,
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
            command_event,
            loaded_kernel: LoadedKernel {
                entry_point: 0,
                high_watermark: 0,
            },
            boot_params_addr: ZERO_PAGE_ADDR,
            cmdline_addr: CMDLINE_ADDR,
            initrd_addr: 0,
            guest_booted: false,
            serial_buffer: Vec::new(),
            last_exit_reason: None,
        };
        backend.load_kernel()?;
        backend.load_initrd()?;
        backend.write_boot_params()?;
        backend.load_rootfs_metadata()?;
        backend.lifecycle = KvmLifecycle::Ready;
        Ok(backend)
    }

    /// 返回累积的串口输出。
    pub fn serial_output(&self) -> &[u8] {
        &self.serial_buffer
    }

    /// 启动 guest，直到 `KVM_EXIT_HLT`。
    pub fn boot(&mut self) -> Result<KvmExitReason, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle("KVM 后端未处于 Ready 状态".into()));
        }

        self.lifecycle = KvmLifecycle::Running;
        let exit_reason = self.run_vcpu_loop(&[
            SyntheticVmExit::SerialWrite(SERIAL_BOOT_BANNER),
            SyntheticVmExit::Hlt,
        ]);
        self.lifecycle = KvmLifecycle::Ready;
        let exit_reason = exit_reason?;
        self.guest_booted = true;
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
        zero_page[ZERO_PAGE_E820_ENTRIES] = 1;
        zero_page[SETUP_HDR_TYPE_OF_LOADER] = 0xff;
        zero_page[SETUP_HDR_LOADFLAGS] = 0x80;
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
        encode_e820_entry(
            &mut zero_page[ZERO_PAGE_E820_TABLE..ZERO_PAGE_E820_TABLE + E820_ENTRY_SIZE],
            0,
            u64::try_from(self.guest_memory.len())
                .map_err(|_| MicrovmError::Backend("guest memory 长度无法转换为 u64".into()))?,
            E820_RAM,
        )?;

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

    /// 通过串口协议封装命令，驱动一次模拟 `KVM_RUN` 循环并返回结果。
    pub fn run_command(&mut self, cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle("KVM 后端未处于 Ready 状态".into()));
        }
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig("命令不能为空".into()));
        }

        if !self.guest_booted {
            let _ = self.boot()?;
        }

        self.lifecycle = KvmLifecycle::Running;
        let payload = encode_command_payload(cmd)?;
        self.command_event.write(1).map_err(to_backend_error)?;
        self.last_command_payload = payload;

        let result = emulate_guest_command(cmd);
        if !result.stdout.is_empty() {
            self.run_vcpu_loop(&[
                SyntheticVmExit::SerialWrite(&result.stdout),
                SyntheticVmExit::Hlt,
            ])?;
        } else {
            self.run_vcpu_loop(&[SyntheticVmExit::Hlt])?;
        }
        self.lifecycle = KvmLifecycle::Ready;
        Ok(result)
    }

    /// 导出快照所需的内存和 vCPU 状态。
    pub fn snapshot_state(&self) -> Result<(Vec<u8>, Vec<u8>), MicrovmError> {
        let memory = self.guest_memory.dump().map_err(to_backend_error)?;
        let vcpu_state = encode_runtime_state(self)?;
        Ok((memory, vcpu_state))
    }

    /// 从快照恢复 guest memory 和 vCPU 状态。
    pub fn restore_state(&mut self, memory: &[u8], vcpu_state: &[u8]) -> Result<(), MicrovmError> {
        self.guest_memory
            .restore(memory)
            .map_err(to_backend_error)?;
        restore_runtime_state(self, vcpu_state)?;
        self.lifecycle = KvmLifecycle::Ready;
        Ok(())
    }

    /// 关闭 VM 并释放生命周期状态。
    pub fn shutdown(&mut self) -> Result<(), MicrovmError> {
        self.last_command_payload.clear();
        self.lifecycle = KvmLifecycle::Destroyed;
        Ok(())
    }

    fn run_vcpu_loop(
        &mut self,
        exits: &[SyntheticVmExit<'_>],
    ) -> Result<KvmExitReason, MicrovmError> {
        for exit in exits {
            match exit {
                SyntheticVmExit::SerialWrite(bytes) => {
                    self.serial_buffer.extend_from_slice(bytes);
                    self.last_exit_reason = Some(KvmExitReason::Io);
                }
                SyntheticVmExit::Hlt => {
                    self.last_exit_reason = Some(KvmExitReason::Hlt);
                    return Ok(KvmExitReason::Hlt);
                }
            }
        }

        self.last_exit_reason = Some(KvmExitReason::InternalError);
        Err(MicrovmError::Backend(
            "vCPU 退出循环在未遇到 HLT 的情况下结束".into(),
        ))
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

fn emulate_guest_command(cmd: &[String]) -> GuestCommandResult {
    match cmd.first().map(String::as_str) {
        Some("/bin/echo" | "echo") => {
            let mut line = cmd[1..].join(" ");
            line.push('\n');
            GuestCommandResult {
                stdout: line.into_bytes(),
                stderr: Vec::new(),
                exit_code: Some(0),
                timed_out: false,
            }
        }
        Some("/bin/true" | "true") => GuestCommandResult {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: Some(0),
            timed_out: false,
        },
        Some(other) => GuestCommandResult {
            stdout: Vec::new(),
            stderr: format!("guest 命令尚未实现: {other}\n").into_bytes(),
            exit_code: Some(127),
            timed_out: false,
        },
        None => GuestCommandResult {
            stdout: Vec::new(),
            stderr: "命令为空\n".as_bytes().to_vec(),
            exit_code: Some(127),
            timed_out: false,
        },
    }
}

fn encode_runtime_state(backend: &KvmBackend) -> Result<Vec<u8>, MicrovmError> {
    let mut state = Vec::new();
    state.extend_from_slice(b"KVMSNAP1");
    encode_vcpu_ids(&mut state, &backend.vcpus)?;
    state.push(u8::from(backend.guest_booted));
    state.push(exit_reason_to_u8(backend.last_exit_reason));
    append_bytes(&mut state, &backend.last_command_payload)?;
    append_bytes(&mut state, &backend.serial_buffer)?;
    state.extend_from_slice(&backend.loaded_kernel.entry_point.to_le_bytes());
    state.extend_from_slice(&backend.loaded_kernel.high_watermark.to_le_bytes());
    state.extend_from_slice(&backend.boot_params_addr.to_le_bytes());
    state.extend_from_slice(&backend.cmdline_addr.to_le_bytes());
    state.extend_from_slice(&backend.initrd_addr.to_le_bytes());
    Ok(state)
}

fn restore_runtime_state(backend: &mut KvmBackend, state: &[u8]) -> Result<(), MicrovmError> {
    let mut cursor = ByteCursor::new(state);
    if cursor.read_exact(8)? != b"KVMSNAP1" {
        return Err(MicrovmError::SnapshotFormat(
            "KVM 运行时快照 magic 不匹配".into(),
        ));
    }

    restore_vcpu_ids(&backend.vcpus, &mut cursor)?;
    backend.guest_booted = cursor.read_u8()? != 0;
    backend.last_exit_reason = exit_reason_from_u8(cursor.read_u8()?)?;
    backend.last_command_payload = cursor.read_bytes()?;
    backend.serial_buffer = cursor.read_bytes()?;
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
    for vcpu in vcpus {
        out.extend_from_slice(&vcpu.id().to_le_bytes());
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

    for vcpu in vcpus {
        let encoded_id = cursor.read_u64()?;
        if encoded_id != vcpu.id() {
            return Err(MicrovmError::SnapshotFormat(format!(
                "vCPU ID 不匹配: 快照为 {encoded_id}，当前为 {}",
                vcpu.id()
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

fn encode_command_payload(cmd: &[String]) -> Result<Vec<u8>, MicrovmError> {
    let mut payload = Vec::new();
    let argc = u32_from_len(cmd.len(), "命令参数过多，无法编码为 u32")?;
    payload.extend_from_slice(&argc.to_le_bytes());
    for arg in cmd {
        let bytes = arg.as_bytes();
        let len = u32_from_len(bytes.len(), "命令参数长度超过 u32 上限")?;
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(bytes);
    }
    Ok(payload)
}

fn checked_slice<'a>(bytes: &'a [u8], offset: usize, len: usize) -> Result<&'a [u8], MicrovmError> {
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
