//! microVM prewarm pool.
//!
//! Provides thread-safe `KvmBackend` prewarming and reuse so commands do not need to
//! recreate and boot a VM for every execution.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::vm::LifecycleError;
use crate::{
    GuestCommandResult, GuestExecOptions, HttpRequest, HttpResponse, MicrovmConfig, MicrovmError,
    StreamEvent,
};
use mimobox_core::{DirEntry, FileStat, SandboxConfig, SandboxSnapshot};

#[cfg(all(target_os = "linux", feature = "kvm"))]
use crate::{KvmBackend, KvmExitReason};

/// Configuration for a fully booted microVM prewarm pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmPoolConfig {
    /// Minimum number of idle VMs to prewarm and keep available.
    pub min_size: usize,
    /// Maximum number of idle VMs retained by the pool.
    pub max_size: usize,
    /// Maximum duration an idle VM may be retained before eviction.
    pub max_idle_duration: Duration,
    /// Release interval used for health checks; `None` disables release-time checks.
    pub health_check_interval: Option<u32>,
}

impl Default for VmPoolConfig {
    fn default() -> Self {
        Self {
            min_size: 1,
            max_size: 16,
            max_idle_duration: Duration::from_secs(30),
            health_check_interval: None,
        }
    }
}

/// Runtime statistics for a [`VmPool`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmPoolStats {
    /// Number of acquisitions satisfied by an already idle VM.
    pub hit_count: u64,
    /// Number of acquisitions that had to create a new VM.
    pub miss_count: u64,
    /// Number of VMs evicted because of timeout, failed health checks, or capacity pressure.
    pub evict_count: u64,
    /// Current number of idle VMs retained by the pool.
    pub idle_count: usize,
    /// Current number of VM handles checked out from the pool.
    pub in_use_count: usize,
}

/// Error returned by [`VmPool`] operations.
#[derive(Debug, Error)]
pub enum PoolError {
    /// Pool capacity configuration is invalid.
    #[error("invalid pool config: min_size={min_size}, max_size={max_size}")]
    InvalidConfig {
        /// Invalid minimum idle target.
        min_size: usize,
        /// Invalid maximum capacity.
        max_size: usize,
    },

    /// Internal shared state lock is poisoned.
    #[error("warm pool state lock poisoned")]
    StatePoisoned,

    /// Underlying microVM error.
    #[error(transparent)]
    Microvm(
        /// Source microVM error.
        #[from]
        MicrovmError,
    ),
}

struct IdleVm {
    backend: Backend,
    last_used: Instant,
}

impl IdleVm {
    fn new(backend: Backend) -> Self {
        Self {
            backend,
            last_used: Instant::now(),
        }
    }
}

#[derive(Default)]
struct PoolState {
    idle: VecDeque<IdleVm>,
    in_use_count: usize,
    hit_count: u64,
    miss_count: u64,
    evict_count: u64,
    recycle_count: u64,
}

impl PoolState {
    fn snapshot(&self) -> VmPoolStats {
        VmPoolStats {
            hit_count: self.hit_count,
            miss_count: self.miss_count,
            evict_count: self.evict_count,
            idle_count: self.idle.len(),
            in_use_count: self.in_use_count,
        }
    }

    fn should_health_check_on_recycle(&mut self, health_check_interval: Option<u32>) -> bool {
        self.recycle_count = self.recycle_count.saturating_add(1);
        match health_check_interval {
            Some(interval) if interval > 0 => {
                self.recycle_count.is_multiple_of(u64::from(interval))
            }
            _ => false,
        }
    }
}

struct VmPoolInner {
    base_config: SandboxConfig,
    config: MicrovmConfig,
    pool_config: VmPoolConfig,
    health_check_command: Vec<String>,
    state: Mutex<PoolState>,
}

impl Drop for VmPoolInner {
    fn drop(&mut self) {
        // 获取 idle 队列中所有 VM 并逐个 shutdown，释放 KVM fd。
        let idle = match self.state.lock() {
            Ok(mut state) => std::mem::take(&mut state.idle),
            Err(_) => {
                tracing::warn!("VmPool drop: state lock poisoned; cannot clean idle VMs");
                return;
            }
        };
        let count = idle.len();
        for entry in idle {
            destroy_idle_entry(entry, "VmPool drop cleanup");
        }
        if count > 0 {
            tracing::debug!(count, "VmPool drop cleanup completed");
        }
    }
}

impl VmPoolInner {
    fn lock_state(&self) -> Result<MutexGuard<'_, PoolState>, PoolError> {
        self.state.lock().map_err(|_| PoolError::StatePoisoned)
    }

    fn rollback_in_use(&self) {
        match self.state.lock() {
            Ok(mut state) => {
                state.in_use_count = state.in_use_count.saturating_sub(1);
            }
            Err(_) => {
                tracing::warn!(
                    "failed to roll back in_use count: VM warm pool state lock poisoned"
                );
            }
        }
    }

    fn take_expired_idle(&self) -> Result<Vec<IdleVm>, PoolError> {
        let mut state = self.lock_state()?;
        let now = Instant::now();
        let mut expired = Vec::new();

        loop {
            let should_evict = match state.idle.front() {
                Some(entry) => {
                    now.saturating_duration_since(entry.last_used)
                        >= self.pool_config.max_idle_duration
                }
                None => false,
            };

            if !should_evict {
                break;
            }

            if let Some(entry) = state.idle.pop_front() {
                state.evict_count += 1;
                expired.push(entry);
            } else {
                break;
            }
        }

        Ok(expired)
    }

    fn push_idle_after_release(&self, backend: Backend) -> Option<IdleVm> {
        match self.state.lock() {
            Ok(mut state) => {
                let evicted = if state.idle.len() >= self.pool_config.max_size {
                    let entry = state.idle.pop_front();
                    if entry.is_some() {
                        state.evict_count += 1;
                    }
                    entry
                } else {
                    None
                };

                state.idle.push_back(IdleVm::new(backend));
                evicted
            }
            Err(_) => {
                tracing::warn!(
                    "failed to recycle VM: cannot return it to idle queue; destroying VM"
                );
                destroy_backend(backend, "state lock poisoned");
                None
            }
        }
    }

    fn replenish_if_needed(&self) {
        let should_replenish = match self.state.lock() {
            Ok(state) => state.idle.len() < self.pool_config.min_size,
            Err(_) => {
                tracing::warn!(
                    "failed to check whether VM replenishment is needed: state lock poisoned"
                );
                return;
            }
        };

        if !should_replenish {
            return;
        }

        match create_backend(&self.base_config, &self.config) {
            Ok(backend) => {
                let evicted = self.push_idle_after_release(backend);
                if let Some(entry) = evicted {
                    destroy_idle_entry(entry, "capacity eviction during VM replenishment");
                }
            }
            Err(err) => {
                tracing::warn!("failed to replenish warm VM: {err}");
            }
        }
    }

    fn recycle(&self, mut backend: Backend) {
        let should_health_check = match self.state.lock() {
            Ok(mut state) => {
                state.in_use_count = state.in_use_count.saturating_sub(1);
                state.should_health_check_on_recycle(self.pool_config.health_check_interval)
            }
            Err(_) => {
                tracing::warn!("failed to recycle VM: state lock poisoned; destroying VM");
                destroy_backend(backend, "state lock poisoned");
                return;
            }
        };

        if !backend_is_reusable(&backend) {
            self.mark_evict();
            destroy_backend(backend, "VM is unhealthy and cannot be reused");
            self.replenish_if_needed();
            return;
        }

        if should_health_check {
            match health_check_backend(&mut backend, &self.health_check_command) {
                Ok(true) => {}
                Ok(false) => {
                    self.mark_evict();
                    destroy_backend(backend, "health check failed");
                    self.replenish_if_needed();
                    return;
                }
                Err(err) => {
                    tracing::warn!("VM health check failed during recycle; evicting: {err}");
                    self.mark_evict();
                    destroy_backend(backend, "health check error");
                    self.replenish_if_needed();
                    return;
                }
            }
        }

        let guest_cleaned = clear_backend_artifacts(&mut backend);
        if !guest_cleaned || !backend_is_reusable(&backend) {
            self.mark_evict();
            destroy_backend(backend, "VM guest cleanup failed; cannot safely reuse");
            self.replenish_if_needed();
            return;
        }

        let evicted = self.push_idle_after_release(backend);
        if let Some(entry) = evicted {
            destroy_idle_entry(entry, "LRU capacity eviction");
        }
    }

    fn mark_evict(&self) {
        match self.state.lock() {
            Ok(mut state) => {
                state.evict_count += 1;
            }
            Err(_) => {
                tracing::warn!("failed to record eviction count: VM warm pool state lock poisoned");
            }
        }
    }
}

/// Thread-safe pool of fully booted microVMs.
///
/// `VmPool` amortizes VM creation and boot cost by keeping ready guests in an idle
/// queue. A borrowed [`PooledVm`] returns to the pool automatically when dropped if
/// the backend is still reusable.
#[derive(Clone)]
pub struct VmPool {
    inner: Arc<VmPoolInner>,
}

impl VmPool {
    /// Creates a microVM prewarm pool with the default [`SandboxConfig`].
    pub fn new(config: MicrovmConfig, pool_config: VmPoolConfig) -> Result<Self, PoolError> {
        Self::new_with_base(SandboxConfig::default(), config, pool_config)
    }

    /// Creates a microVM prewarm pool with an explicit base sandbox configuration.
    ///
    /// The pool validates capacity limits, platform support, and microVM assets
    /// before warming the configured minimum number of guests.
    pub fn new_with_base(
        base_config: SandboxConfig,
        config: MicrovmConfig,
        pool_config: VmPoolConfig,
    ) -> Result<Self, PoolError> {
        if pool_config.max_size == 0 || pool_config.min_size > pool_config.max_size {
            return Err(PoolError::InvalidConfig {
                min_size: pool_config.min_size,
                max_size: pool_config.max_size,
            });
        }

        ensure_pool_supported()?;
        config.validate()?;

        let pool = Self {
            inner: Arc::new(VmPoolInner {
                base_config,
                config,
                pool_config,
                health_check_command: vec!["/bin/true".to_string()],
                state: Mutex::new(PoolState::default()),
            }),
        };

        if pool_config.min_size > 0 {
            pool.warm(pool_config.min_size)?;
        }

        Ok(pool)
    }

    /// Acquires an executable microVM instance from the pool.
    ///
    /// Expired idle VMs are evicted first. If no reusable idle VM is available, a new
    /// backend is created and counted as a miss.
    pub fn acquire(&self) -> Result<PooledVm, PoolError> {
        let _span = tracing::info_span!("pool_acquire").entered();
        #[cfg(feature = "boot-profile")]
        let acquire_started_at = Instant::now();
        #[cfg(feature = "boot-profile")]
        let expired_cleanup_started_at = Instant::now();
        let expired = self.inner.take_expired_idle()?;
        #[cfg(feature = "boot-profile")]
        let expired_idle_cleanup = expired_cleanup_started_at.elapsed();
        for entry in expired {
            destroy_idle_entry(entry, "idle timeout");
        }

        #[cfg(feature = "boot-profile")]
        let state_checkout_started_at = Instant::now();
        let reused = {
            let mut state = self.inner.lock_state()?;
            if let Some(entry) = state.idle.pop_back() {
                state.hit_count += 1;
                state.in_use_count += 1;
                Some(entry.backend)
            } else {
                state.miss_count += 1;
                state.in_use_count += 1;
                None
            }
        };
        #[cfg(feature = "boot-profile")]
        let state_checkout = state_checkout_started_at.elapsed();

        #[cfg(feature = "boot-profile")]
        let backend_prepare_started_at = Instant::now();
        #[cfg(feature = "boot-profile")]
        let reused_hit = reused.is_some();
        #[allow(clippy::question_mark)]
        let backend = match reused {
            Some(backend) => backend,
            None => match create_backend(&self.inner.base_config, &self.inner.config) {
                Ok(backend) => backend,
                Err(err) => {
                    self.inner.rollback_in_use();
                    return Err(err.into());
                }
            },
        };
        #[cfg(feature = "boot-profile")]
        let backend_prepare = backend_prepare_started_at.elapsed();

        #[cfg(feature = "boot-profile")]
        tracing::info!(
            expired_idle_cleanup = ?expired_idle_cleanup,
            state_checkout = ?state_checkout,
            backend_prepare = ?backend_prepare,
            reused = reused_hit,
            total = ?acquire_started_at.elapsed(),
            "[pool.acquire] performance overview"
        );

        Ok(PooledVm {
            backend: Some(backend),
            pool: Arc::clone(&self.inner),
        })
    }

    /// Warms the idle pool to at least `count` VMs.
    ///
    /// The effective target is capped by [`VmPoolConfig::max_size`]. The return value
    /// is the number of new VMs inserted into the idle queue.
    pub fn warm(&self, count: usize) -> Result<usize, PoolError> {
        let expired = self.inner.take_expired_idle()?;
        for entry in expired {
            destroy_idle_entry(entry, "idle timeout");
        }

        let target_idle_size = count.min(self.inner.pool_config.max_size);
        let current_idle = self.inner.lock_state()?.idle.len();
        if current_idle >= target_idle_size {
            return Ok(0);
        }

        let create_count = target_idle_size.saturating_sub(current_idle);
        let mut created = Vec::with_capacity(create_count);
        for _ in 0..create_count {
            created.push(create_backend(&self.inner.base_config, &self.inner.config)?);
        }

        let mut extra = Vec::new();
        let mut inserted = 0usize;
        {
            let mut state = self.inner.lock_state()?;
            let available = self
                .inner
                .pool_config
                .max_size
                .saturating_sub(state.idle.len());
            let keep_count = available.min(created.len());

            for backend in created.drain(..keep_count) {
                state.idle.push_back(IdleVm::new(backend));
                inserted += 1;
            }

            extra.extend(created);
        }

        for backend in extra {
            destroy_backend(backend, "prewarm exceeds capacity");
        }

        Ok(inserted)
    }

    /// Returns a snapshot of the current pool statistics.
    pub fn stats(&self) -> Result<VmPoolStats, PoolError> {
        Ok(self.inner.lock_state()?.snapshot())
    }
}

/// microVM handle borrowed from a [`VmPool`].
///
/// The handle is single-use with respect to ownership: once dropped, its backend is
/// either recycled into the pool or destroyed, and the handle cannot be used again.
pub struct PooledVm {
    backend: Option<Backend>,
    pool: Arc<VmPoolInner>,
}

impl PooledVm {
    /// Executes a guest command and waits for completion.
    pub fn execute(&mut self, cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        let _span = tracing::info_span!("pool_execute").entered();
        self.execute_with_options(cmd, GuestExecOptions::default())
    }

    /// Executes a guest command with command-level options.
    ///
    /// Returns [`LifecycleError::Released`] through [`MicrovmError::Lifecycle`] when
    /// the pooled handle has already been returned to the pool.
    pub fn execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<GuestCommandResult, MicrovmError> {
        let _span = tracing::info_span!("pool_execute").entered();
        #[cfg(feature = "boot-profile")]
        let execute_started_at = Instant::now();
        let result = match self.backend.as_mut() {
            Some(backend) => execute_backend(backend, cmd, &options),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "VM has been released".into(),
            ))),
        };
        #[cfg(feature = "boot-profile")]
        tracing::info!(
            total = ?execute_started_at.elapsed(),
            success = result.is_ok(),
            "[pool.execute] performance overview"
        );
        result
    }

    /// Executes a guest command and returns a receiver for streaming output events.
    pub fn stream_execute(
        &mut self,
        cmd: &[String],
    ) -> Result<std::sync::mpsc::Receiver<StreamEvent>, MicrovmError> {
        let _span = tracing::info_span!("pool_execute").entered();
        self.stream_execute_with_options(cmd, GuestExecOptions::default())
    }

    /// Executes a guest command as streaming output events with command-level options.
    pub fn stream_execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<std::sync::mpsc::Receiver<StreamEvent>, MicrovmError> {
        let _span = tracing::info_span!("pool_execute").entered();
        match self.backend.as_mut() {
            Some(backend) => stream_execute_backend(backend, cmd, &options),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "VM has been released".into(),
            ))),
        }
    }

    /// Reads file contents from the borrowed guest filesystem.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => read_file_backend(backend, path),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "VM has been released".into(),
            ))),
        }
    }

    /// Writes file contents into the borrowed guest filesystem.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => write_file_backend(backend, path, data),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "VM has been released".into(),
            ))),
        }
    }

    /// Lists directory entries from the borrowed guest filesystem.
    pub fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, MicrovmError> {
        crate::guest_file_ops::list_dir(path, |cmd| self.execute(cmd))
    }

    /// Returns whether a guest path exists.
    pub fn file_exists(&mut self, path: &str) -> Result<bool, MicrovmError> {
        crate::guest_file_ops::file_exists(path, |cmd| self.execute(cmd))
    }

    /// Removes a file from the borrowed guest filesystem.
    pub fn remove_file(&mut self, path: &str) -> Result<(), MicrovmError> {
        crate::guest_file_ops::remove_file(path, |cmd| self.execute(cmd))
    }

    /// Renames or moves a file inside the borrowed guest filesystem.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), MicrovmError> {
        crate::guest_file_ops::rename(from, to, |cmd| self.execute(cmd))
    }

    /// Returns guest file metadata.
    pub fn stat(&mut self, path: &str) -> Result<FileStat, MicrovmError> {
        crate::guest_file_ops::stat(path, |cmd| self.execute(cmd))
    }

    /// Runs one guest `PING`/`PONG` readiness probe and returns the round-trip duration.
    pub fn ping(&mut self) -> Result<Duration, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => ping_backend(backend),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "VM has been released".into(),
            ))),
        }
    }

    /// Sends a request through the host-controlled HTTP proxy for the borrowed VM.
    pub fn http_request(&mut self, request: HttpRequest) -> Result<HttpResponse, MicrovmError> {
        match self.backend.as_mut() {
            Some(backend) => http_request_backend(backend, request),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "VM has been released".into(),
            ))),
        }
    }

    /// Exports a file-backed snapshot of the current borrowed VM.
    pub fn snapshot(&self) -> Result<SandboxSnapshot, MicrovmError> {
        match self.backend.as_ref() {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Some(backend) => backend.snapshot_to_file(),
            #[cfg(not(all(target_os = "linux", feature = "kvm")))]
            Some(_) => Err(MicrovmError::UnsupportedPlatform),
            None => Err(MicrovmError::Lifecycle(LifecycleError::Released(
                "VM has been released".into(),
            ))),
        }
    }
}

impl Drop for PooledVm {
    fn drop(&mut self) {
        #[cfg(feature = "boot-profile")]
        let drop_started_at = Instant::now();
        if let Some(backend) = self.backend.take() {
            self.pool.recycle(backend);
        }
        #[cfg(feature = "boot-profile")]
        tracing::info!(
            total = ?drop_started_at.elapsed(),
            "[pool.drop] performance overview"
        );
    }
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
type Backend = KvmBackend;

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
struct Backend;

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn ensure_pool_supported() -> Result<(), MicrovmError> {
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn ensure_pool_supported() -> Result<(), MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn create_backend(
    base_config: &SandboxConfig,
    config: &MicrovmConfig,
) -> Result<Backend, MicrovmError> {
    let mut backend = KvmBackend::create_vm(base_config.clone(), config.clone())?;
    let exit_reason = backend.boot()?;
    if exit_reason != KvmExitReason::Io || !backend.is_guest_ready() {
        return Err(MicrovmError::Backend(format!(
            "prewarmed VM guest did not enter READY state: {exit_reason:?}"
        )));
    }
    if !backend.clear_pool_artifacts() {
        return Err(MicrovmError::Backend(
            "prewarmed VM guest cleanup failed; cannot safely add to pool".into(),
        ));
    }
    Ok(backend)
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn create_backend(
    _base_config: &SandboxConfig,
    _config: &MicrovmConfig,
) -> Result<Backend, MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn health_check_backend(
    backend: &mut Backend,
    health_check_command: &[String],
) -> Result<bool, MicrovmError> {
    let result = backend.run_command(health_check_command)?;
    Ok(!result.timed_out && result.exit_code == Some(0))
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn health_check_backend(
    _backend: &mut Backend,
    _health_check_command: &[String],
) -> Result<bool, MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn destroy_backend(mut backend: Backend, reason: &str) {
    if let Err(err) = backend.shutdown() {
        tracing::warn!("failed to destroy VM ({reason}): {err}");
    }
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn destroy_backend(_backend: Backend, _reason: &str) {}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn destroy_idle_entry(entry: IdleVm, reason: &str) {
    destroy_backend(entry.backend, reason);
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn destroy_idle_entry(_entry: IdleVm, _reason: &str) {}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn execute_backend(
    backend: &mut Backend,
    cmd: &[String],
    options: &GuestExecOptions,
) -> Result<GuestCommandResult, MicrovmError> {
    backend.run_command_with_options(cmd, options)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn stream_execute_backend(
    backend: &mut Backend,
    cmd: &[String],
    options: &GuestExecOptions,
) -> Result<std::sync::mpsc::Receiver<StreamEvent>, MicrovmError> {
    backend.run_command_streaming_with_options(cmd, options)
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn execute_backend(
    _backend: &mut Backend,
    _cmd: &[String],
    _options: &GuestExecOptions,
) -> Result<GuestCommandResult, MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn stream_execute_backend(
    _backend: &mut Backend,
    _cmd: &[String],
    _options: &GuestExecOptions,
) -> Result<std::sync::mpsc::Receiver<StreamEvent>, MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn read_file_backend(backend: &mut Backend, path: &str) -> Result<Vec<u8>, MicrovmError> {
    backend.read_file(path)
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn read_file_backend(_backend: &mut Backend, _path: &str) -> Result<Vec<u8>, MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn write_file_backend(backend: &mut Backend, path: &str, data: &[u8]) -> Result<(), MicrovmError> {
    backend.write_file(path, data)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn ping_backend(backend: &mut Backend) -> Result<Duration, MicrovmError> {
    backend.ping()
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn write_file_backend(
    _backend: &mut Backend,
    _path: &str,
    _data: &[u8],
) -> Result<(), MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn ping_backend(_backend: &mut Backend) -> Result<Duration, MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn http_request_backend(
    backend: &mut Backend,
    request: HttpRequest,
) -> Result<HttpResponse, MicrovmError> {
    backend.http_request(request)
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn http_request_backend(
    _backend: &mut Backend,
    _request: HttpRequest,
) -> Result<HttpResponse, MicrovmError> {
    Err(MicrovmError::UnsupportedPlatform)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn backend_is_reusable(backend: &Backend) -> bool {
    backend.is_guest_ready()
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn backend_is_reusable(_backend: &Backend) -> bool {
    false
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn clear_backend_artifacts(backend: &mut Backend) -> bool {
    backend.clear_pool_artifacts()
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn clear_backend_artifacts(_backend: &mut Backend) -> bool {
    false
}
