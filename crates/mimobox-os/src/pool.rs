//! Sandbox warm pool.
//!
//! Provides a thread-safe sandbox object pool with the following goals:
//! - Pre-warmed creation to reduce creation cost on the hot path.
//! - Microsecond-level idle sandbox acquisition through `acquire()`.
//! - Automatic RAII-based recycling.
//! - Hit, miss, and eviction statistics.
//! - Reclamation based on idle duration and LRU behavior.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};
use thiserror::Error;

#[cfg(target_os = "linux")]
use crate::linux::LinuxSandbox as PlatformSandbox;
#[cfg(target_os = "macos")]
use crate::macos::MacOsSandbox as PlatformSandbox;

#[cfg(target_os = "linux")]
fn default_health_check_command() -> Vec<String> {
    vec!["/bin/true".to_string()]
}

#[cfg(target_os = "macos")]
fn default_health_check_command() -> Vec<String> {
    vec!["/usr/bin/true".to_string()]
}

/// Configuration for a [`SandboxPool`].
///
/// The pool keeps up to [`PoolConfig::max_size`] idle sandboxes and can
/// pre-create [`PoolConfig::min_size`] instances during construction. Idle
/// entries older than [`PoolConfig::max_idle_duration`] are evicted during
/// maintenance operations such as [`SandboxPool::warm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// Minimum number of idle sandboxes pre-warmed during initialization.
    pub min_size: usize,
    /// Maximum number of idle sandboxes the pool may retain.
    pub max_size: usize,
    /// Maximum duration an idle sandbox may be retained.
    pub max_idle_duration: Duration,
    /// Number of recycles after which a health check runs; `None` disables health checks.
    pub health_check_interval: Option<u32>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_size: 1,
            max_size: 16,
            max_idle_duration: Duration::from_secs(30),
            health_check_interval: None,
        }
    }
}

/// Point-in-time statistics for a [`SandboxPool`].
///
/// Counters are cumulative for the lifetime of the pool. Size fields describe
/// the state observed when [`SandboxPool::stats`] took the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Number of times `acquire()` hits the idle pool.
    pub hit_count: u64,
    /// Number of times `acquire()` misses and creates a new sandbox.
    pub miss_count: u64,
    /// Number of evictions due to timeout, failed health checks, or capacity pressure.
    pub evict_count: u64,
    /// Current number of idle sandboxes.
    pub idle_count: usize,
    /// Current number of checked-out sandboxes.
    pub in_use_count: usize,
}

/// Error returned by warm pool operations.
#[derive(Debug, Error)]
pub enum PoolError {
    /// The pool configuration is invalid.
    #[error("invalid pool config: min_size={min_size}, max_size={max_size}")]
    InvalidConfig {
        /// Invalid minimum pre-warmed count.
        min_size: usize,
        /// Invalid maximum capacity.
        max_size: usize,
    },

    /// The shared state lock is poisoned.
    #[error("warm pool state lock poisoned")]
    StatePoisoned,

    /// Underlying sandbox error.
    #[error(transparent)]
    Sandbox(
        /// Error returned by the platform sandbox implementation.
        #[from]
        SandboxError,
    ),
}

struct IdleSandbox {
    sandbox: PlatformSandbox,
    last_used: Instant,
}

impl IdleSandbox {
    fn new(sandbox: PlatformSandbox) -> Self {
        Self {
            sandbox,
            last_used: Instant::now(),
        }
    }
}

#[derive(Default)]
struct PoolState {
    idle: VecDeque<IdleSandbox>,
    in_use_count: usize,
    hit_count: u64,
    miss_count: u64,
    evict_count: u64,
    recycle_count: u64,
}

impl PoolState {
    fn snapshot(&self) -> PoolStats {
        PoolStats {
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

struct PoolInner {
    sandbox_config: SandboxConfig,
    pool_config: PoolConfig,
    health_check_command: Vec<String>,
    state: Mutex<PoolState>,
}

impl PoolInner {
    fn lock_state(&self) -> Result<MutexGuard<'_, PoolState>, PoolError> {
        self.state.lock().map_err(|_| PoolError::StatePoisoned)
    }

    fn rollback_in_use(&self) {
        match self.state.lock() {
            Ok(mut state) => {
                state.in_use_count = state.in_use_count.saturating_sub(1);
            }
            Err(_) => {
                tracing::warn!("回滚 in_use 计数失败：预热池状态锁已中毒");
            }
        }
    }

    fn recycle(&self, sandbox: PlatformSandbox) {
        match self.pool_config.health_check_interval {
            Some(interval) if interval > 0 => {
                self.recycle_with_periodic_health_check(sandbox, interval)
            }
            _ => self.recycle_without_health_check(sandbox),
        }
    }

    fn recycle_without_health_check(&self, sandbox: PlatformSandbox) {
        match self.state.lock() {
            Ok(mut state) => {
                state.in_use_count = state.in_use_count.saturating_sub(1);
            }
            Err(_) => {
                tracing::warn!("回收沙箱失败：预热池状态锁已中毒，直接销毁沙箱");
                Self::destroy_sandbox(sandbox, "状态锁已中毒");
                return;
            }
        }

        let evicted_entry = self.push_idle_after_release(sandbox);
        if let Some(entry) = evicted_entry {
            Self::destroy_idle_entry(entry, "LRU 容量淘汰");
        }
    }

    fn recycle_with_periodic_health_check(
        &self,
        mut sandbox: PlatformSandbox,
        health_check_interval: u32,
    ) {
        let should_health_check = match self.state.lock() {
            Ok(mut state) => {
                state.in_use_count = state.in_use_count.saturating_sub(1);
                state.should_health_check_on_recycle(Some(health_check_interval))
            }
            Err(_) => {
                tracing::warn!("回收沙箱失败：预热池状态锁已中毒，直接销毁沙箱");
                Self::destroy_sandbox(sandbox, "状态锁已中毒");
                return;
            }
        };

        if should_health_check {
            let is_healthy = match self.health_check(&mut sandbox) {
                Ok(value) => value,
                Err(err) => {
                    tracing::warn!("沙箱健康检查失败，回收时直接驱逐: {err}");
                    false
                }
            };

            if !is_healthy {
                match self.state.lock() {
                    Ok(mut state) => {
                        state.evict_count += 1;
                    }
                    Err(_) => {
                        tracing::warn!("记录健康检查驱逐失败：预热池状态锁已中毒");
                    }
                }

                Self::destroy_sandbox(sandbox, "健康检查失败");
                return;
            }
        }

        let evicted_entry = self.push_idle_after_release(sandbox);
        if let Some(entry) = evicted_entry {
            Self::destroy_idle_entry(entry, "LRU 容量淘汰");
        }
    }

    fn take_expired_idle(&self) -> Result<Vec<IdleSandbox>, PoolError> {
        let mut state = self.lock_state()?;
        let now = Instant::now();
        let mut expired_entries = Vec::new();

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
                expired_entries.push(entry);
            } else {
                break;
            }
        }

        Ok(expired_entries)
    }

    fn push_idle_after_release(&self, sandbox: PlatformSandbox) -> Option<IdleSandbox> {
        match self.state.lock() {
            Ok(mut state) => {
                let evicted_entry = if state.idle.len() >= self.pool_config.max_size {
                    let entry = state.idle.pop_front();
                    if entry.is_some() {
                        state.evict_count += 1;
                    }
                    entry
                } else {
                    None
                };

                state.idle.push_back(IdleSandbox::new(sandbox));
                evicted_entry
            }
            Err(_) => {
                tracing::warn!("回收沙箱失败：无法重新放回 idle 队列，直接销毁沙箱");
                Self::destroy_sandbox(sandbox, "状态锁已中毒");
                None
            }
        }
    }

    fn health_check(&self, sandbox: &mut PlatformSandbox) -> Result<bool, SandboxError> {
        let result = sandbox.execute(&self.health_check_command)?;
        Ok(!result.timed_out && result.exit_code == Some(0))
    }

    fn destroy_sandbox(sandbox: PlatformSandbox, reason: &str) {
        if let Err(err) = sandbox.destroy() {
            tracing::warn!("销毁沙箱失败 ({reason}): {err}");
        }
    }

    fn destroy_idle_entry(entry: IdleSandbox, reason: &str) {
        Self::destroy_sandbox(entry.sandbox, reason);
    }
}

/// Thread-safe warm pool for OS-level sandboxes.
///
/// `SandboxPool` can be cloned and shared across multiple threads. The hot path holds the mutex
/// only while acquiring an idle sandbox. Checked-out sandboxes are returned to
/// the pool automatically when their [`PooledSandbox`] handle is dropped.
#[derive(Clone)]
pub struct SandboxPool {
    inner: Arc<PoolInner>,
}

impl SandboxPool {
    /// Creates a new warm pool and automatically warms it to `min_size`.
    ///
    /// Returns [`PoolError::InvalidConfig`] when `max_size` is zero or when
    /// `min_size` is greater than `max_size`.
    pub fn new(config: SandboxConfig, pool_config: PoolConfig) -> Result<Self, PoolError> {
        if pool_config.max_size == 0 || pool_config.min_size > pool_config.max_size {
            return Err(PoolError::InvalidConfig {
                min_size: pool_config.min_size,
                max_size: pool_config.max_size,
            });
        }

        let pool = Self {
            inner: Arc::new(PoolInner {
                sandbox_config: config,
                pool_config,
                health_check_command: default_health_check_command(),
                state: Mutex::new(PoolState::default()),
            }),
        };

        if pool_config.min_size > 0 {
            pool.warm(pool_config.min_size)?;
        }

        Ok(pool)
    }

    /// Returns the immutable pool configuration used by this pool.
    pub fn pool_config(&self) -> PoolConfig {
        self.inner.pool_config
    }

    /// Returns a statistics snapshot for the current pool state.
    pub fn stats(&self) -> Result<PoolStats, PoolError> {
        Ok(self.inner.lock_state()?.snapshot())
    }

    /// Returns the current number of idle sandboxes retained by the pool.
    pub fn idle_len(&self) -> Result<usize, PoolError> {
        Ok(self.inner.lock_state()?.idle.len())
    }

    /// Warms the pool to the specified number of idle sandboxes.
    ///
    /// The requested target is capped at [`PoolConfig::max_size`]. Expired idle
    /// entries are evicted before new sandboxes are created.
    ///
    /// Returns the number of sandboxes actually inserted into the idle pool by
    /// this call.
    pub fn warm(&self, target_idle_size: usize) -> Result<usize, PoolError> {
        let target_idle_size = target_idle_size.min(self.inner.pool_config.max_size);
        let expired = self.inner.take_expired_idle()?;

        for entry in expired {
            PoolInner::destroy_idle_entry(entry, "空闲超时");
        }

        let current_idle = self.idle_len()?;
        if current_idle >= target_idle_size {
            return Ok(0);
        }

        let create_count = target_idle_size.saturating_sub(current_idle);
        let mut created = Vec::with_capacity(create_count);

        for _ in 0..create_count {
            created.push(PlatformSandbox::new(self.inner.sandbox_config.clone())?);
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

            for sandbox in created.drain(..keep_count) {
                state.idle.push_back(IdleSandbox::new(sandbox));
                inserted += 1;
            }

            extra.extend(created);
        }

        for sandbox in extra {
            PoolInner::destroy_sandbox(sandbox, "预热超出容量");
        }

        Ok(inserted)
    }

    /// Acquires a sandbox from the pool.
    ///
    /// Reuses an idle object on pool hit and creates a new platform sandbox on
    /// demand when the pool is empty. The returned [`PooledSandbox`] recycles
    /// itself back into the pool on drop.
    pub fn acquire(&self) -> Result<PooledSandbox, PoolError> {
        let reused = {
            let mut state = self.inner.lock_state()?;
            if let Some(entry) = state.idle.pop_back() {
                state.hit_count += 1;
                state.in_use_count += 1;
                Some(entry.sandbox)
            } else {
                state.miss_count += 1;
                state.in_use_count += 1;
                None
            }
        };

        let sandbox = match reused {
            Some(sandbox) => sandbox,
            None => match PlatformSandbox::new(self.inner.sandbox_config.clone()) {
                Ok(sandbox) => sandbox,
                Err(err) => {
                    self.inner.rollback_in_use();
                    return Err(err.into());
                }
            },
        };

        Ok(PooledSandbox {
            sandbox: Some(sandbox),
            pool: Arc::clone(&self.inner),
        })
    }
}

/// Handle for a sandbox checked out from a [`SandboxPool`].
///
/// Recycles the sandbox according to pool configuration on drop; by default, only memory cleanup
/// runs and no health check is performed.
pub struct PooledSandbox {
    sandbox: Option<PlatformSandbox>,
    pool: Arc<PoolInner>,
}

impl PooledSandbox {
    /// Executes a command in the checked-out sandbox.
    ///
    /// The command vector must follow the same contract as
    /// [`mimobox_core::Sandbox::execute`]: the first element is the executable
    /// path and the remaining elements are arguments.
    pub fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        match self.sandbox.as_mut() {
            Some(sandbox) => sandbox.execute(cmd),
            None => Err(SandboxError::new("sandbox has been released")),
        }
    }
}

impl Drop for PooledSandbox {
    fn drop(&mut self) {
        if let Some(sandbox) = self.sandbox.take() {
            self.pool.recycle(sandbox);
        }
    }
}

fn percentile_us(samples: &[f64], percentile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    let last_index = samples.len().saturating_sub(1);
    let raw_index = ((last_index as f64) * percentile).round() as usize;
    let index = raw_index.min(last_index);
    samples[index]
}

/// Runs a simple pool benchmark comparing cold-start and hot-acquire latency.
///
/// `pool_size` controls how many idle sandboxes are pre-warmed. `iterations`
/// controls how many cold and hot samples are collected before printing p50 and
/// p99 latency summaries.
pub fn run_pool_benchmark(
    pool_size: usize,
    iterations: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = SandboxConfig::default();
    config.memory_limit_mb = Some(256);

    let pool_config = PoolConfig {
        min_size: 0,
        max_size: pool_size.max(1),
        ..PoolConfig::default()
    };

    let pool = SandboxPool::new(config.clone(), pool_config)?;
    let warmed = pool.warm(pool_size.max(1))?;

    println!("=== 预热池性能基准测试 ===");
    println!("预热完成：requested={pool_size}, created={warmed}");

    let mut cold_acquire_times = Vec::with_capacity(iterations);
    let mut hot_acquire_times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        let sandbox = PlatformSandbox::new(config.clone())?;
        cold_acquire_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        sandbox.destroy()?;
    }

    for _ in 0..iterations {
        let start = Instant::now();
        let sandbox = pool.acquire()?;
        hot_acquire_times.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        drop(sandbox);
    }

    cold_acquire_times.sort_by(f64::total_cmp);
    hot_acquire_times.sort_by(f64::total_cmp);

    println!(
        "冷启动 acquire: p50={:.1}us p99={:.1}us",
        percentile_us(&cold_acquire_times, 0.50),
        percentile_us(&cold_acquire_times, 0.99)
    );
    println!(
        "热获取 acquire: p50={:.1}us p99={:.1}us",
        percentile_us(&hot_acquire_times, 0.50),
        percentile_us(&hot_acquire_times, 0.99)
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn test_pool_config(
        min_size: usize,
        max_size: usize,
        max_idle_duration: Duration,
        health_check_interval: Option<u32>,
    ) -> PoolConfig {
        PoolConfig {
            min_size,
            max_size,
            max_idle_duration,
            health_check_interval,
        }
    }

    #[test]
    fn test_pool_config_default_is_reasonable() {
        let config = PoolConfig::default();
        assert_eq!(config.min_size, 1);
        assert_eq!(config.max_size, 16);
        assert_eq!(config.max_idle_duration, Duration::from_secs(30));
        assert_eq!(config.health_check_interval, None);
    }

    #[test]
    fn test_health_check_interval_only_triggers_on_configured_recycles() {
        let mut state = PoolState::default();
        let should_check = (0..6)
            .map(|_| state.should_health_check_on_recycle(Some(3)))
            .collect::<Vec<_>>();

        assert_eq!(should_check, vec![false, false, true, false, false, true]);
    }

    #[test]
    fn test_new_prewarms_to_min_size() {
        let pool = SandboxPool::new(
            SandboxConfig::default(),
            test_pool_config(2, 4, Duration::from_secs(30), None),
        )
        .expect("创建池失败");

        assert_eq!(pool.idle_len().expect("读取空闲数量失败"), 2);
    }

    #[test]
    fn test_acquire_updates_hit_and_miss_stats() {
        let pool = SandboxPool::new(
            SandboxConfig::default(),
            test_pool_config(0, 2, Duration::from_secs(30), None),
        )
        .expect("创建池失败");

        {
            let sandbox = pool.acquire().expect("首次 acquire 失败");
            drop(sandbox);
        }

        {
            let sandbox = pool.acquire().expect("第二次 acquire 失败");
            drop(sandbox);
        }

        let stats = pool.stats().expect("读取统计失败");
        assert_eq!(stats.miss_count, 1);
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.idle_count, 1);
        assert_eq!(stats.in_use_count, 0);
    }

    #[test]
    fn test_lru_eviction_when_pool_is_full() {
        let pool = SandboxPool::new(
            SandboxConfig::default(),
            test_pool_config(0, 2, Duration::from_secs(30), None),
        )
        .expect("创建池失败");
        pool.warm(2).expect("预热失败");

        let first = pool.acquire().expect("获取第一个沙箱失败");
        let second = pool.acquire().expect("获取第二个沙箱失败");
        let third = pool.acquire().expect("获取第三个沙箱失败");

        drop(first);
        drop(second);
        drop(third);

        let stats = pool.stats().expect("读取统计失败");
        assert_eq!(stats.idle_count, 2);
        assert_eq!(stats.evict_count, 1);
    }

    #[test]
    fn test_warm_evicts_stale_idle_sandboxes() {
        let pool = SandboxPool::new(
            SandboxConfig::default(),
            test_pool_config(0, 2, Duration::from_millis(5), None),
        )
        .expect("创建池失败");
        pool.warm(1).expect("预热失败");

        thread::sleep(Duration::from_millis(20));

        let created = pool.warm(1).expect("维护预热失败");
        assert_eq!(created, 1);

        let stats = pool.stats().expect("读取统计失败");
        assert_eq!(stats.evict_count, 1);
        assert_eq!(stats.miss_count, 0);
        assert_eq!(stats.hit_count, 0);
        assert_eq!(stats.idle_count, 1);
    }

    #[test]
    fn test_invalid_config_is_rejected() {
        let result = SandboxPool::new(
            SandboxConfig::default(),
            test_pool_config(2, 1, Duration::from_secs(30), None),
        );

        assert!(matches!(
            result,
            Err(PoolError::InvalidConfig {
                min_size: 2,
                max_size: 1
            })
        ));
    }
}
