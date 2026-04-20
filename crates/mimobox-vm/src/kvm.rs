#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::fs;

use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use mimobox_core::SandboxConfig;
use tracing::{debug, info};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use crate::vm::{GuestCommandResult, MicrovmConfig, MicrovmError};

const KERNEL_LOAD_ADDR: u64 = 0x10_0000;
const ROOTFS_METADATA_ADDR: u64 = 0x20_0000;

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
    command_event: EventFd,
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

        let kvm = Kvm::new().map_err(|err| MicrovmError::Backend(err.to_string()))?;
        let vm_fd = kvm
            .create_vm()
            .map_err(|err| MicrovmError::Backend(err.to_string()))?;
        let guest_memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), config.memory_bytes()?)])
                .map_err(|err| MicrovmError::Backend(err.to_string()))?;

        let kernel_bytes = fs::read(&config.kernel_path)?;
        let rootfs_bytes = fs::read(&config.rootfs_path)?;
        let command_event =
            EventFd::new(0).map_err(|err| MicrovmError::Backend(err.to_string()))?;

        let mut vcpus = Vec::with_capacity(usize::from(config.vcpu_count));
        for vcpu_index in 0..u64::from(config.vcpu_count) {
            let vcpu = vm_fd
                .create_vcpu(vcpu_index)
                .map_err(|err| MicrovmError::Backend(err.to_string()))?;
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
            transport: KvmTransport::Vsock,
            lifecycle: KvmLifecycle::Created,
            last_command_payload: Vec::new(),
            command_event,
        };
        backend.load_kernel()?;
        backend.load_rootfs_metadata()?;
        backend.lifecycle = KvmLifecycle::Ready;
        Ok(backend)
    }

    /// 将内核镜像装载到 guest memory。
    pub fn load_kernel(&mut self) -> Result<(), MicrovmError> {
        debug!(bytes = self.kernel_bytes.len(), "装载 guest 内核镜像");
        let max_len = self
            .guest_memory
            .len()
            .checked_sub(KERNEL_LOAD_ADDR as usize)
            .ok_or_else(|| MicrovmError::Backend("guest memory 小于内核装载基址".into()))?;
        if self.kernel_bytes.len() > max_len {
            return Err(MicrovmError::Backend(format!(
                "内核镜像过大，无法装载到 guest memory: {} > {}",
                self.kernel_bytes.len(),
                max_len
            )));
        }

        self.guest_memory
            .write_slice(&self.kernel_bytes, GuestAddress(KERNEL_LOAD_ADDR))
            .map_err(|err| MicrovmError::Backend(err.to_string()))
    }

    /// 将 rootfs 元信息写入 guest memory，作为后续 block/vsock 初始化材料。
    fn load_rootfs_metadata(&mut self) -> Result<(), MicrovmError> {
        let metadata = format!(
            "rootfs={};size={};transport={:?}",
            self.config.rootfs_path.display(),
            self.rootfs_bytes.len(),
            self.transport
        );
        self.guest_memory
            .write_slice(metadata.as_bytes(), GuestAddress(ROOTFS_METADATA_ADDR))
            .map_err(|err| MicrovmError::Backend(err.to_string()))
    }

    /// 通过串口/vsock 协议封装命令并返回当前骨架阶段的执行结果。
    pub fn run_command(&mut self, cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle("KVM 后端未处于 Ready 状态".into()));
        }
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig("命令不能为空".into()));
        }

        self.lifecycle = KvmLifecycle::Running;
        let payload = encode_command_payload(cmd)?;
        self.command_event
            .write(1)
            .map_err(|err| MicrovmError::Backend(err.to_string()))?;
        self.last_command_payload = payload.clone();
        debug!(
            payload_bytes = payload.len(),
            "已向 guest 命令通道写入命令事件"
        );

        let timeout = self.base_config.timeout_secs.unwrap_or_default();
        let stderr = format!(
            "guest runner 尚未接入，已通过 {:?} 生成命令载荷（{} 字节，timeout={}s）",
            self.transport,
            payload.len(),
            timeout
        );

        self.lifecycle = KvmLifecycle::Ready;
        Ok(GuestCommandResult {
            stdout: Vec::new(),
            stderr: stderr.into_bytes(),
            exit_code: Some(127),
            timed_out: false,
        })
    }

    /// 导出快照所需的内存和 vCPU 状态。
    pub fn snapshot_state(&self) -> Result<(Vec<u8>, Vec<u8>), MicrovmError> {
        let memory = self
            .guest_memory
            .dump()
            .map_err(|err| MicrovmError::Backend(err.to_string()))?;
        let vcpu_state = encode_vcpu_state(&self.vcpus)?;
        Ok((memory, vcpu_state))
    }

    /// 从快照恢复 guest memory 和 vCPU 状态。
    pub fn restore_state(&mut self, memory: &[u8], vcpu_state: &[u8]) -> Result<(), MicrovmError> {
        self.guest_memory
            .restore(memory)
            .map_err(|err| MicrovmError::Backend(err.to_string()))?;
        restore_vcpu_state(&self.vcpus, vcpu_state)?;
        self.lifecycle = KvmLifecycle::Ready;
        Ok(())
    }

    /// 关闭 VM 并释放生命周期状态。
    pub fn shutdown(&mut self) -> Result<(), MicrovmError> {
        self.last_command_payload.clear();
        self.lifecycle = KvmLifecycle::Destroyed;
        Ok(())
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

fn encode_command_payload(cmd: &[String]) -> Result<Vec<u8>, MicrovmError> {
    let mut payload = Vec::new();
    let argc = u32::try_from(cmd.len())
        .map_err(|_| MicrovmError::Backend("命令参数过多，无法编码为 u32".into()))?;
    payload.extend_from_slice(&argc.to_le_bytes());
    for arg in cmd {
        let bytes = arg.as_bytes();
        let len = u32::try_from(bytes.len())
            .map_err(|_| MicrovmError::Backend("命令参数长度超过 u32 上限".into()))?;
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(bytes);
    }
    Ok(payload)
}

fn encode_vcpu_state(vcpus: &[VcpuFd]) -> Result<Vec<u8>, MicrovmError> {
    let mut state = Vec::new();
    let count = u32::try_from(vcpus.len())
        .map_err(|_| MicrovmError::Backend("vCPU 数量超过 u32 上限".into()))?;
    state.extend_from_slice(&count.to_le_bytes());
    for vcpu in vcpus {
        state.extend_from_slice(&vcpu.id().to_le_bytes());
    }
    Ok(state)
}

fn restore_vcpu_state(vcpus: &[VcpuFd], state: &[u8]) -> Result<(), MicrovmError> {
    if state.len() < 4 {
        return Err(MicrovmError::SnapshotFormat("vCPU 状态数据长度不足".into()));
    }

    let mut count_bytes = [0u8; 4];
    count_bytes.copy_from_slice(&state[..4]);
    let encoded_count = u32::from_le_bytes(count_bytes) as usize;
    if encoded_count != vcpus.len() {
        return Err(MicrovmError::SnapshotFormat(format!(
            "vCPU 数量不匹配: 快照为 {}，当前后端为 {}",
            encoded_count,
            vcpus.len()
        )));
    }

    let expected_len = 4usize
        .checked_add(
            encoded_count
                .checked_mul(8)
                .ok_or_else(|| MicrovmError::SnapshotFormat("vCPU 状态长度计算溢出".into()))?,
        )
        .ok_or_else(|| MicrovmError::SnapshotFormat("vCPU 状态长度计算溢出".into()))?;
    if state.len() != expected_len {
        return Err(MicrovmError::SnapshotFormat(format!(
            "vCPU 状态长度不匹配: 期望 {}，实际 {}",
            expected_len,
            state.len()
        )));
    }

    for (index, vcpu) in vcpus.iter().enumerate() {
        let start = 4 + index * 8;
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&state[start..start + 8]);
        let encoded_id = u64::from_le_bytes(id_bytes);
        if encoded_id != vcpu.id() {
            return Err(MicrovmError::SnapshotFormat(format!(
                "vCPU ID 不匹配: 快照为 {}，当前为 {}",
                encoded_id,
                vcpu.id()
            )));
        }
    }

    Ok(())
}
