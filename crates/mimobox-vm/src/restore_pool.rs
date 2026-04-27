#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use kvm_bindings::kvm_userspace_memory_region;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use mimobox_core::{DirEntry, FileStat, SandboxConfig, SandboxError, SandboxSnapshot};
use thiserror::Error;
use tracing::warn;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

#[cfg(target_arch = "x86_64")]
use crate::kvm::{KVM_IDENTITY_MAP_ADDR, KVM_TSS_ADDR};
use crate::kvm::{KvmBackend, RestoreProfile, restore_runtime_state};
use crate::vm::LifecycleError;
use crate::{
    GuestCommandResult, GuestExecOptions, HttpRequest, HttpResponse, MicrovmConfig, MicrovmError,
    MicrovmSnapshot, StreamEvent,
};

/// Pre-created KVM VM shell that has memory and vCPUs registered but no restored guest state.
pub(crate) struct EmptyVmSlot {
    kvm: Kvm,
    vm_fd: VmFd,
    vcpus: Vec<VcpuFd>,
    guest_memory: GuestMemoryMmap,
    config: MicrovmConfig,
    base_config: SandboxConfig,
}

impl EmptyVmSlot {
    /// Creates an empty VM slot ready to accept snapshot memory and runtime state.
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

    /// Converts this empty slot into a restored backend using in-memory snapshot data.
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

/// Configuration for the snapshot restore pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestorePoolConfig {
    /// Minimum number of empty VM shells to prewarm and keep available.
    pub min_size: usize,
    /// Maximum number of empty VM shells retained by the restore pool.
    pub max_size: usize,
}

/// Error returned by [`RestorePool`] operations.
#[derive(Debug, Error)]
pub enum RestorePoolError {
    /// Restore pool configuration is invalid.
    #[error("invalid restore pool config: min_size={min_size}, max_size={max_size}")]
    InvalidConfig {
        /// Invalid minimum idle target.
        min_size: usize,
        /// Invalid maximum capacity.
        max_size: usize,
    },

    /// Internal shared state lock is poisoned.
    #[error("restore pool state lock poisoned")]
    StatePoisoned,

    /// Underlying microVM error.
    #[error(transparent)]
    Microvm(
        /// Source microVM error.
        #[from]
        MicrovmError,
    ),
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

impl Drop for RestorePoolInner {
    fn drop(&mut self) {
        // 获取 idle 队列中所有空壳 VM 并丢弃，释放 KVM/VmFd/VcpuFd 资源。
        let idle = match self.state.lock() {
            Ok(mut state) => std::mem::take(&mut state.idle),
            Err(_) => {
                warn!("RestorePool drop 时状态锁已中毒，无法清理 idle slot");
                return;
            }
        };
        let count = idle.len();
        drop(idle);
        if count > 0 {
            tracing::debug!(count, "RestorePool drop 清理完成");
        }
    }
}

/// Pool of empty VM shells optimized for snapshot restoration.
///
/// Unlike [`crate::pool::VmPool`], this pool does not keep fully booted guests.
/// Instead, it keeps KVM VM shells with memory and vCPU structures allocated so
/// snapshot state can be restored with less setup latency.
#[derive(Clone)]
pub struct RestorePool {
    inner: Arc<RestorePoolInner>,
}

impl RestorePool {
    /// Creates a pool of empty VM shells for snapshot restore.
    ///
    /// The pool validates capacity limits and microVM assets, then warms the
    /// configured minimum number of empty slots.
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

    /// Restores a microVM from guest memory pages and serialized vCPU state.
    ///
    /// A pre-created slot is used when available; otherwise the pool creates one on
    /// demand and rolls back accounting if restoration fails.
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

    /// Restores a microVM from full self-describing snapshot bytes.
    pub fn restore_from_bytes(&self, data: &[u8]) -> Result<PooledRestoreVm, RestorePoolError> {
        let snapshot = MicrovmSnapshot::restore(data)?;
        let (_, _, memory, vcpu_state) = snapshot.into_parts();
        self.restore(memory.as_slice(), vcpu_state.as_slice())
    }

    /// Restores a microVM from a [`SandboxSnapshot`].
    ///
    /// File-backed snapshots use the optimized file path when the build supports it;
    /// otherwise the snapshot is loaded into memory before restoration.
    pub fn restore_snapshot(
        &self,
        snapshot: &SandboxSnapshot,
    ) -> Result<PooledRestoreVm, RestorePoolError> {
        if let Some(memory_path) = snapshot.memory_file_path() {
            {
                let snapshot = MicrovmSnapshot::from_memory_file(memory_path)?;
                let (_, _, memory, vcpu_state) = snapshot.into_parts();
                return self.restore(memory.as_slice(), vcpu_state.as_slice());
            }
        }

        let data = snapshot.as_bytes().map_err(map_snapshot_access_error)?;
        self.restore_from_bytes(data)
    }

    /// Returns the current number of idle slots in the restore pool.
    ///
    /// If the internal lock is poisoned, this method logs the condition and returns
    /// `0` rather than panicking.
    pub fn idle_count(&self) -> usize {
        match self.inner.state.lock() {
            Ok(state) => state.idle.len(),
            Err(_) => {
                warn!("查询恢复池空闲槽位失败：状态锁已中毒");
                0
            }
        }
    }

    /// Warms the restore pool to at least `target` empty VM shells.
    ///
    /// The effective target is capped by [`RestorePoolConfig::max_size`].
    pub fn warm(&self, target: usize) -> Result<(), RestorePoolError> {
        self.inner.warm(target)
    }
}

/// Restored microVM handle borrowed from a [`RestorePool`].
///
/// Dropping the handle shuts down the restored VM and allows the pool to replenish
/// an empty slot if needed.
pub struct PooledRestoreVm {
    backend: Option<KvmBackend>,
    pool: Arc<RestorePoolInner>,
}

impl PooledRestoreVm {
    /// Executes a guest command and waits for completion.
    pub fn execute(&mut self, cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        self.execute_with_options(cmd, GuestExecOptions::default())
    }

    /// Executes a guest command with command-level options.
    ///
    /// Returns [`LifecycleError::Released`] through [`MicrovmError::Lifecycle`] when
    /// the restored handle has already been released.
    pub fn execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<GuestCommandResult, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.run_command_with_options(cmd, &options),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "restored VM has been released".into(),
            ))),
        }
    }

    /// Executes a guest command and returns a receiver for streaming output events.
    pub fn stream_execute(
        &mut self,
        cmd: &[String],
    ) -> Result<std::sync::mpsc::Receiver<StreamEvent>, MicrovmError> {
        self.stream_execute_with_options(cmd, GuestExecOptions::default())
    }

    /// Executes a guest command as streaming output events with command-level options.
    pub fn stream_execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<std::sync::mpsc::Receiver<StreamEvent>, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.run_command_streaming_with_options(cmd, &options),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "restored VM has been released".into(),
            ))),
        }
    }

    /// Reads file contents from the restored guest filesystem.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.read_file(path),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "restored VM has been released".into(),
            ))),
        }
    }

    /// Writes file contents into the restored guest filesystem.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.write_file(path, data),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "restored VM has been released".into(),
            ))),
        }
    }

    /// Lists directory entries from the restored guest filesystem.
    pub fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, MicrovmError> {
        crate::guest_file_ops::list_dir(path, |cmd| self.execute(cmd))
    }

    /// Returns whether a guest path exists.
    pub fn file_exists(&mut self, path: &str) -> Result<bool, MicrovmError> {
        crate::guest_file_ops::file_exists(path, |cmd| self.execute(cmd))
    }

    /// Removes a file from the restored guest filesystem.
    pub fn remove_file(&mut self, path: &str) -> Result<(), MicrovmError> {
        crate::guest_file_ops::remove_file(path, |cmd| self.execute(cmd))
    }

    /// Renames or moves a file inside the restored guest filesystem.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), MicrovmError> {
        crate::guest_file_ops::rename(from, to, |cmd| self.execute(cmd))
    }

    /// Returns restored guest file metadata.
    pub fn stat(&mut self, path: &str) -> Result<FileStat, MicrovmError> {
        crate::guest_file_ops::stat(path, |cmd| self.execute(cmd))
    }

    /// Runs one guest `PING`/`PONG` readiness probe and returns the round-trip duration.
    pub fn ping(&mut self) -> Result<Duration, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.ping(),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "restored VM has been released".into(),
            ))),
        }
    }

    /// Sends a request through the host-controlled HTTP proxy for the restored VM.
    pub fn http_request(&mut self, request: HttpRequest) -> Result<HttpResponse, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => backend.http_request(request),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "restored VM has been released".into(),
            ))),
        }
    }

    /// Exports a file-backed snapshot of the current restored VM.
    pub fn snapshot(&self) -> Result<SandboxSnapshot, MicrovmError> {
        match self.backend.as_ref() {
            Some(backend) => backend.snapshot_to_file(),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "restored VM has been released".into(),
            ))),
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
    let memory_size = u64::try_from(config.memory_bytes()?).map_err(|_| {
        MicrovmError::Backend("guest memory size cannot be converted to u64".into())
    })?;
    let memory_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size,
        userspace_addr: host_addr,
        flags: 0,
    };

    // SAFETY: `userspace_addr` comes directly from a valid mmap owned by the current
    // `GuestMemoryMmap`. Its lifetime covers the entire empty slot, and this only
    // registers slot 0, so it cannot overlap with other regions.
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

fn map_snapshot_access_error(error: SandboxError) -> RestorePoolError {
    let error = match error {
        SandboxError::Io(error) => MicrovmError::Io(error),
        SandboxError::InvalidSnapshot => {
            MicrovmError::SnapshotFormat("invalid sandbox snapshot".into())
        }
        other => MicrovmError::SnapshotFormat(other.to_string()),
    };
    RestorePoolError::Microvm(error)
}
