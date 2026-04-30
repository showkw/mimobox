#[cfg(any(target_os = "linux", target_os = "macos"))]
mod pool_tests {
    use std::error::Error;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use mimobox_core::{NamespaceDegradation, SandboxConfig};
    #[cfg(target_os = "macos")]
    use mimobox_core::{Sandbox, SandboxError};
    #[cfg(target_os = "macos")]
    use mimobox_os::MacOsSandbox;
    use mimobox_os::{PoolConfig, SandboxPool};
    #[cfg(target_os = "macos")]
    use std::sync::OnceLock;

    fn pool_config(min_size: usize, max_size: usize) -> PoolConfig {
        PoolConfig {
            min_size,
            max_size,
            max_idle_duration: Duration::from_secs(5),
            health_check_interval: None,
        }
    }

    fn sandbox_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(5);
        config.memory_limit_mb = Some(128);
        config.namespace_degradation = NamespaceDegradation::AllowDegradation;
        config
    }

    #[cfg(target_os = "linux")]
    fn true_command() -> Vec<String> {
        vec!["/bin/true".to_string()]
    }

    #[cfg(target_os = "macos")]
    fn true_command() -> Vec<String> {
        vec!["/usr/bin/true".to_string()]
    }

    #[cfg(target_os = "linux")]
    fn should_skip_runtime_tests() -> bool {
        false
    }

    #[cfg(target_os = "macos")]
    fn should_skip_runtime_tests() -> bool {
        if let Some(reason) = seatbelt_runtime_skip_reason() {
            eprintln!("跳过 macOS Seatbelt 预热池集成测试: {reason}");
            return true;
        }

        false
    }

    #[cfg(target_os = "macos")]
    fn seatbelt_runtime_skip_reason() -> Option<&'static str> {
        static SKIP_REASON: OnceLock<Option<String>> = OnceLock::new();

        SKIP_REASON
            .get_or_init(|| {
                let mut sandbox =
                    MacOsSandbox::new(sandbox_config()).expect("创建 macOS 沙箱探测实例失败");

                match sandbox.execute(&true_command()) {
                    Ok(_) => None,
                    Err(SandboxError::SecurityPolicy { message })
                        if message.contains("Seatbelt") =>
                    {
                        Some(message)
                    }
                    Err(err) => panic!("macOS Seatbelt 最小探测失败: {err}"),
                }
            })
            .as_deref()
    }

    #[test]
    fn sandbox_pool_prewarms_acquires_and_recycles() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let pool = SandboxPool::new(sandbox_config(), pool_config(1, 2))?;
        assert_eq!(pool.idle_len()?, 1);

        {
            let mut sandbox = pool.acquire()?;
            let result = sandbox.execute(&true_command())?;

            if result.exit_code == Some(125) {
                eprintln!(
                    "skipping: execvp failed, CI environment may lack complete filesystem isolation"
                );
                return Ok(());
            }
            assert_eq!(result.exit_code, Some(0));
            assert!(!result.timed_out);
        }

        let stats = pool.stats()?;
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 0);
        assert_eq!(stats.in_use_count, 0);
        assert_eq!(stats.idle_count, 1);

        Ok(())
    }

    #[test]
    fn sandbox_pool_is_safe_under_concurrency() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let pool = SandboxPool::new(sandbox_config(), pool_config(2, 4))?;
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || -> Result<(), String> {
                barrier.wait();
                let mut sandbox = pool.acquire().map_err(|error| error.to_string())?;
                let result = sandbox
                    .execute(&true_command())
                    .map_err(|error| error.to_string())?;

                if result.exit_code == Some(125) {
                    eprintln!(
                        "skipping: execvp failed, CI environment may lack \
                         complete filesystem isolation"
                    );
                    return Ok(());
                }
                if result.exit_code != Some(0) || result.timed_out {
                    return Err(format!(
                        "unexpected result: exit_code={:?}, timed_out={}",
                        result.exit_code, result.timed_out
                    ));
                }

                Ok(())
            }));
        }

        barrier.wait();

        for handle in handles {
            let joined = handle
                .join()
                .map_err(|_| std::io::Error::other("线程执行 panic"))?;
            if let Err(message) = joined {
                return Err(std::io::Error::other(message).into());
            }
        }

        let stats = pool.stats()?;
        assert_eq!(stats.hit_count + stats.miss_count, 4);
        assert_eq!(stats.in_use_count, 0);
        assert!(stats.idle_count <= 4);

        Ok(())
    }

    #[test]
    fn sandbox_pool_handles_exhaustion_without_blocking() -> Result<(), Box<dyn Error>> {
        let pool = SandboxPool::new(sandbox_config(), pool_config(0, 1))?;
        let first = pool.acquire()?;
        let second = pool.acquire()?;

        let during_use = pool.stats()?;
        assert_eq!(during_use.miss_count, 2);
        assert_eq!(during_use.in_use_count, 2);
        assert_eq!(during_use.idle_count, 0);

        drop(first);
        drop(second);

        let after_release = pool.stats()?;
        assert_eq!(after_release.in_use_count, 0);
        assert_eq!(after_release.idle_count, 1);
        assert!(after_release.evict_count >= 1);

        Ok(())
    }
}
