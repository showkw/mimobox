#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use kvm_bindings::kvm_userspace_memory_region;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use mimobox_core::SandboxConfig;
use thiserror::Error;
use tracing::warn;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

#[cfg(target_arch = "x86_64")]
use crate::kvm::{KVM_IDENTITY_MAP_ADDR, KVM_TSS_ADDR};
use crate::kvm::{KvmBackend, RestoreProfile, restore_runtime_state};
use crate::{
    GuestCommandResult, GuestExecOptions, HttpRequest, HttpResponse, MicrovmConfig, MicrovmError,
    MicrovmSnapshot, StreamEvent,
};

pub(crate) struct EmptyVmSlot {
    kvm: Kvm,
    vm_fd: VmFd,
    vcpus: Vec<VcpuFd>,
    guest_memory: GuestMemoryMmap,
    config: MicrovmConfig,
    base_config: SandboxConfig,
}

impl EmptyVmSlot {
    pub(crate) fn new(
        base_config: SandboxConfig,
        config: MicrovmConfig,
    ) -> Result<Self, MicrovmError> {
        config.validate()?;

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
        KvmBackend::try_enable_huge_pages(&guest_memory);

        let mut vcpus = Vec::with_capacity(usize::from(config.vcpu_count));
        for vcpu_index in 0..u64::from(config.vcpu_count) {
            let vcpu = vm_fd.create_vcpu(vcpu_index).map_err(to_backend_error)?;
            vcpus.push(vcpu);
        }

        register_guest_memory(&vm_fd, &guest_memory, &config)?;

        Ok(Self {
            kvm,
            vm_fd,
            vcpus,
            guest_memory,
            config,
            base_config,
        })
    }

    pub(crate) fn into_restored_backend(
        self,
        memory: &[u8],
        vcpu_state: &[u8],
    ) -> Result<KvmBackend, MicrovmError> {
        let mut backend = KvmBackend::from_slot_components(
            self.kvm,
            self.vm_fd,
            self.vcpus,
            self.guest_memory,
            self.base_config,
            self.config,
        );
        backend.set_pending_restore_profile(RestoreProfile::default());

        let mut restore_profile = backend.take_or_seed_restore_profile();

        let restore_memory_started_at = Instant::now();
        backend.restore_guest_memory(memory)?;
        restore_profile.memory_state_write = restore_memory_started_at.elapsed();

        restore_profile.cpuid_config = backend.prepare_restored_vcpus()?;

        let runtime_restore_profile = restore_runtime_state(&mut backend, vcpu_state)?;
        restore_profile.vcpu_state_restore = runtime_restore_profile.vcpu_state_restore;
        restore_profile.device_state_restore = runtime_restore_profile.device_state_restore;

        backend.set_lifecycle_ready();
        backend.emit_restore_profile_without_resume(&restore_profile);
        backend.set_pending_restore_profile(restore_profile);
        Ok(backend)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// snapshot restore 池配置。
pub struct RestorePoolConfig {
    /// 初始化时预热的最小空壳 VM 数量。
    pub min_size: usize,
    /// 恢复池允许保留的最大空壳 VM 数量。
    pub max_size: usize,
}

#[derive(Debug, Error)]
/// snapshot restore 池错误。
pub enum RestorePoolError {
    /// 恢复池配置不合法。
    #[error("恢复池配置无效: min_size={min_size}, max_size={max_size}")]
    InvalidConfig {
        /// 非法的最小空闲目标值。
        min_size: usize,
        /// 非法的最大容量值。
        max_size: usize,
    },

    /// 内部共享状态锁已中毒。
    #[error("恢复池状态锁已中毒")]
    StatePoisoned,

    /// 底层 microVM 错误。
    #[error(transparent)]
    Microvm(#[from] MicrovmError),
}

#[derive(Default)]
struct RestorePoolState {
    idle: VecDeque<EmptyVmSlot>,
    in_use_count: usize,
}

struct RestorePoolInner {
    base_config: SandboxConfig,
    config: MicrovmConfig,
    pool_config: RestorePoolConfig,
    state: Mutex<RestorePoolState>,
}

impl RestorePoolInner {
    fn lock_state(&self) -> Result<MutexGuard<'_, RestorePoolState>, RestorePoolError> {
        self.state
            .lock()
            .map_err(|_| RestorePoolError::StatePoisoned)
    }

    fn create_slot(&self) -> Result<EmptyVmSlot, RestorePoolError> {
        EmptyVmSlot::new(self.base_config.clone(), self.config.clone()).map_err(Into::into)
    }

    fn rollback_in_use(&self) {
        match self.state.lock() {
            Ok(mut state) => {
                state.in_use_count = state.in_use_count.saturating_sub(1);
            }
            Err(_) => {
                warn!("回滚恢复池 in_use 计数失败：状态锁已中毒");
            }
        }
    }

    fn push_idle_slot(&self, slot: EmptyVmSlot) -> Result<bool, RestorePoolError> {
        let mut state = self.lock_state()?;
        if state.idle.len() >= self.pool_config.max_size {
            return Ok(false);
        }
        state.idle.push_back(slot);
        Ok(true)
    }

    fn warm(&self, target_idle_size: usize) -> Result<(), RestorePoolError> {
        let target_idle_size = target_idle_size.min(self.pool_config.max_size);
        let current_idle = self.lock_state()?.idle.len();
        if current_idle >= target_idle_size {
            return Ok(());
        }

        let create_count = target_idle_size.saturating_sub(current_idle);
        let mut slots = Vec::with_capacity(create_count);
        for _ in 0..create_count {
            slots.push(self.create_slot()?);
        }

        let mut state = self.lock_state()?;
        let available = self.pool_config.max_size.saturating_sub(state.idle.len());
        let keep_count = available.min(slots.len());
        for slot in slots.drain(..keep_count) {
            state.idle.push_back(slot);
        }
        Ok(())
    }

    fn replenish_if_needed(&self) {
        let should_replenish = match self.state.lock() {
            Ok(state) => state.idle.len() < self.pool_config.min_size,
            Err(_) => {
                warn!("检查恢复池补充条件失败：状态锁已中毒");
                return;
            }
        };

        if !should_replenish {
            return;
        }

        match self.create_slot() {
            Ok(slot) => match self.push_idle_slot(slot) {
                Ok(true) => {}
                Ok(false) => {}
                Err(err) => warn!("回填空壳 VM 失败: {err}"),
            },
            Err(err) => warn!("创建空壳 VM 失败，无法回填恢复池: {err}"),
        }
    }

    fn release_backend(&self, mut backend: KvmBackend) {
        if let Err(err) = backend.shutdown() {
            warn!("销毁恢复态 VM 失败: {err}");
        }

        match self.state.lock() {
            Ok(mut state) => {
                state.in_use_count = state.in_use_count.saturating_sub(1);
            }
            Err(_) => {
                warn!("释放恢复态 VM 失败：状态锁已中毒");
                return;
            }
        }

        self.replenish_if_needed();
    }
}

#[derive(Clone)]
/// 基于快照恢复的 microVM 恢复池。
pub struct RestorePool {
    inner: Arc<RestorePoolInner>,
}

impl RestorePool {
    /// 创建一个用于 snapshot restore 的空壳 VM 恢复池。
    pub fn new(
        base_config: SandboxConfig,
        config: MicrovmConfig,
        pool_config: RestorePoolConfig,
    ) -> Result<Self, RestorePoolError> {
        if pool_config.max_size == 0 || pool_config.min_size > pool_config.max_size {
            return Err(RestorePoolError::InvalidConfig {
                min_size: pool_config.min_size,
                max_size: pool_config.max_size,
            });
        }

        config.validate()?;

        let pool = Self {
            inner: Arc::new(RestorePoolInner {
                base_config,
                config,
                pool_config,
                state: Mutex::new(RestorePoolState::default()),
            }),
        };

        if pool.inner.pool_config.min_size > 0 {
            pool.inner.warm(pool.inner.pool_config.min_size)?;
        }

        Ok(pool)
    }

    /// 使用内存页和 vCPU 状态恢复一个 microVM。
    pub fn restore(
        &self,
        memory: &[u8],
        vcpu_state: &[u8],
    ) -> Result<PooledRestoreVm, RestorePoolError> {
        let slot = {
            let mut state = self.inner.lock_state()?;
            state.in_use_count += 1;
            state.idle.pop_back()
        };

        let slot = match slot {
            Some(slot) => slot,
            None => match self.inner.create_slot() {
                Ok(slot) => slot,
                Err(err) => {
                    self.inner.rollback_in_use();
                    return Err(err);
                }
            },
        };

        let backend = match slot.into_restored_backend(memory, vcpu_state) {
            Ok(backend) => backend,
            Err(err) => {
                self.inner.rollback_in_use();
                self.inner.replenish_if_needed();
                return Err(err.into());
            }
        };

        Ok(PooledRestoreVm {
            backend: Some(backend),
            pool: Arc::clone(&self.inner),
        })
    }

    /// 从完整快照字节恢复一个 microVM。
    pub fn restore_from_bytes(&self, data: &[u8]) -> Result<PooledRestoreVm, RestorePoolError> {
        let snapshot = MicrovmSnapshot::restore(data)?;
        let (_, _, memory, vcpu_state) = snapshot.into_parts();
        self.restore(memory.as_slice(), vcpu_state.as_slice())
    }

    /// 返回当前恢复池中的空闲槽位数量。
    pub fn idle_count(&self) -> usize {
        match self.inner.state.lock() {
            Ok(state) => state.idle.len(),
            Err(_) => {
                warn!("查询恢复池空闲槽位失败：状态锁已中毒");
                0
            }
        }
    }

    /// 将恢复池预热到至少 `target` 个空壳 VM。
    pub fn warm(&self, target: usize) -> Result<(), RestorePoolError> {
        self.inner.warm(target)
    }
}

/// 从 `RestorePool` 借出的恢复态 microVM 句柄。
pub struct PooledRestoreVm {
    backend: Option<KvmBackend>,
    pool: Arc<RestorePoolInner>,
}

impl PooledRestoreVm {
    /// 执行命令并等待完成。
    pub fn execute(&mut self, cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        self.execute_with_options(cmd, GuestExecOptions::default())
    }

    /// 执行命令并应用命令级选项。
    pub fn execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<GuestCommandResult, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.run_command_with_options(cmd, &options),
            None => Err(MicrovmError::Lifecycle("恢复态 VM 已被释放".into())),
        }
    }

    /// 以流式事件形式执行命令。
    pub fn stream_execute(
        &mut self,
        cmd: &[String],
    ) -> Result<std::sync::mpsc::Receiver<StreamEvent>, MicrovmError> {
        self.stream_execute_with_options(cmd, GuestExecOptions::default())
    }

    /// 以流式事件形式执行命令，并应用命令级选项。
    pub fn stream_execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<std::sync::mpsc::Receiver<StreamEvent>, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.run_command_streaming_with_options(cmd, &options),
            None => Err(MicrovmError::Lifecycle("恢复态 VM 已被释放".into())),
        }
    }

    /// 读取 guest 内文件内容。
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.read_file(path),
            None => Err(MicrovmError::Lifecycle("恢复态 VM 已被释放".into())),
        }
    }

    /// 向 guest 内写入文件内容。
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.write_file(path, data),
            None => Err(MicrovmError::Lifecycle("恢复态 VM 已被释放".into())),
        }
    }

    /// 通过宿主受控 HTTP 代理发起请求。
    pub fn http_request(&mut self, request: HttpRequest) -> Result<HttpResponse, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.http_request(request),
            None => Err(MicrovmError::Lifecycle("恢复态 VM 已被释放".into())),
        }
    }

    /// 导出当前恢复态 VM 的快照字节。
    pub fn snapshot(&self) -> Result<Vec<u8>, MicrovmError> {
        match self.backend.as_ref() {
            Some(backend) => backend.snapshot_bytes(),
            None => Err(MicrovmError::Lifecycle("恢复态 VM 已被释放".into())),
        }
    }
}

impl Drop for PooledRestoreVm {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() {
            self.pool.release_backend(backend);
        }
    }
}

fn register_guest_memory(
    vm_fd: &VmFd,
    guest_memory: &GuestMemoryMmap,
    config: &MicrovmConfig,
) -> Result<(), MicrovmError> {
    let host_addr = guest_memory
        .get_host_address(GuestAddress(0))
        .map_err(to_backend_error)? as u64;
    let memory_size = u64::try_from(config.memory_bytes()?)
        .map_err(|_| MicrovmError::Backend("guest memory 长度无法转换为 u64".into()))?;
    let memory_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size,
        userspace_addr: host_addr,
        flags: 0,
    };

    // SAFETY: `userspace_addr` 直接来自当前 `GuestMemoryMmap` 持有的有效 mmap，
    // 生命周期覆盖整个空壳 slot，且这里只注册唯一的 slot 0，不会与其他 region 重叠。
    unsafe {
        vm_fd
            .set_user_memory_region(memory_region)
            .map_err(to_backend_error)?;
    }
    Ok(())
}

fn to_backend_error(err: impl std::fmt::Display) -> MicrovmError {
    MicrovmError::Backend(err.to_string())
}
