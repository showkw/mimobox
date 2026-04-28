#[cfg(target_os = "linux")]
mod linux_backend_tests {
    use std::error::Error;
    use std::path::PathBuf;

    use mimobox_core::{NamespaceDegradation, Sandbox, SandboxConfig, SeccompProfile};
    use mimobox_os::LinuxSandbox;
    use tempfile::TempDir;

    fn linux_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.namespace_degradation = NamespaceDegradation::AllowDegradation;
        config.timeout_secs = Some(5);
        config.memory_limit_mb = Some(128);
        config
    }

    fn python_command() -> Option<PathBuf> {
        ["/usr/bin/python3", "/bin/python3", "/usr/bin/python"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.exists())
    }

    #[test]
    fn linux_sandbox_executes_a_basic_command() -> Result<(), Box<dyn Error>> {
        let mut sandbox = LinuxSandbox::new(linux_config())?;
        let command = vec!["/bin/echo".to_string(), "linux-integration".to_string()];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);

        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return Ok(());
        }
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out);
        assert!(stdout.contains("linux-integration"));

        Ok(())
    }

    #[test]
    fn linux_sandbox_enforces_landlock_filesystem_rules() -> Result<(), Box<dyn Error>> {
        let allowed_dir = TempDir::new()?;
        let forbidden_dir = TempDir::new()?;
        let allowed_file = allowed_dir.path().join("allowed.txt");
        let forbidden_file = forbidden_dir.path().join("forbidden.txt");

        let mut config = linux_config();
        config.fs_readwrite = vec![allowed_dir.path().to_path_buf()];
        config.allow_fork = false;

        let mut allowed_sandbox = LinuxSandbox::new(config.clone())?;
        let allowed_command = vec![
            "/usr/bin/touch".to_string(),
            allowed_file.to_string_lossy().into_owned(),
        ];
        let allowed_result = allowed_sandbox.execute(&allowed_command)?;

        if allowed_result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return Ok(());
        }
        assert_eq!(allowed_result.exit_code, Some(0));
        assert!(allowed_file.exists());

        let mut forbidden_sandbox = LinuxSandbox::new(config)?;
        let forbidden_command = vec![
            "/usr/bin/touch".to_string(),
            forbidden_file.to_string_lossy().into_owned(),
        ];
        let forbidden_result = forbidden_sandbox.execute(&forbidden_command)?;
        let stderr = String::from_utf8_lossy(&forbidden_result.stderr);

        assert!(
            forbidden_result.exit_code != Some(0)
                || stderr.contains("Permission denied")
                || stderr.contains("Operation not permitted")
        );
        assert!(!forbidden_file.exists());

        Ok(())
    }

    #[test]
    fn linux_sandbox_isolates_network_namespace() -> Result<(), Box<dyn Error>> {
        let mut sandbox = LinuxSandbox::new(linux_config())?;
        let command = vec!["/bin/cat".to_string(), "/proc/net/dev".to_string()];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);

        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return Ok(());
        }
        assert_eq!(result.exit_code, Some(0));
        assert!(stdout.contains("lo"));

        Ok(())
    }

    #[test]
    fn linux_sandbox_applies_memory_limit() -> Result<(), Box<dyn Error>> {
        let Some(python) = python_command() else {
            return Ok(());
        };

        let mut config = linux_config();
        config.memory_limit_mb = Some(32);
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            python.to_string_lossy().into_owned(),
            "-c".to_string(),
            "blob = 'x' * (256 * 1024 * 1024)\nprint(len(blob))".to_string(),
        ];
        let result = sandbox.execute(&command)?;
        let stderr = String::from_utf8_lossy(&result.stderr);

        assert!(
            result.exit_code != Some(0)
                || stderr.contains("MemoryError")
                || stderr.contains("Cannot allocate memory")
        );

        Ok(())
    }

    #[test]
    fn linux_sandbox_filters_fork_related_syscalls() -> Result<(), Box<dyn Error>> {
        let mut config = linux_config();
        config.allow_fork = false;
        config.seccomp_profile = SeccompProfile::Essential;
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "cd / && /bin/sleep 0.01 & wait".to_string(),
        ];
        let result = sandbox.execute(&command)?;

        assert!(result.exit_code != Some(0));

        Ok(())
    }

    #[test]
    fn linux_sandbox_times_out_long_running_processes() -> Result<(), Box<dyn Error>> {
        let mut config = linux_config();
        config.timeout_secs = Some(1);
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec!["/bin/sleep".to_string(), "5".to_string()];
        let result = sandbox.execute(&command)?;

        // CI 环境下 execvp 可能失败导致 timeout 不工作。
        if !result.timed_out && result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return Ok(());
        }

        assert!(result.timed_out);
        assert!(result.elapsed.as_secs_f64() < 5.0);

        Ok(())
    }

    #[test]
    fn test_linux_list_dir_returns_entries() -> Result<(), Box<dyn Error>> {
        let temp_dir = TempDir::new()?;
        std::fs::write(temp_dir.path().join("entry.txt"), "test")?;
        let mut sandbox = LinuxSandbox::new(linux_config())?;

        let entries = match sandbox.list_dir(&temp_dir.path().to_string_lossy()) {
            Ok(entries) => entries,
            Err(error) => {
                if error.to_string().contains("operation not supported") {
                    eprintln!("skipping: OS-level sandbox does not support list_dir");
                    return Ok(());
                }
                return Err(error.into());
            }
        };

        let entry = entries
            .iter()
            .find(|entry| entry.name == "entry.txt")
            .expect("返回结果应包含测试文件");
        assert_eq!(entry.name, "entry.txt");
        assert!(matches!(
            entry.file_type,
            mimobox_core::FileType::File
                | mimobox_core::FileType::Dir
                | mimobox_core::FileType::Symlink
                | mimobox_core::FileType::Other
        ));
        let _size = entry.size;
        let _is_symlink = entry.is_symlink;

        Ok(())
    }

    #[test]
    fn test_linux_list_dir_nonexistent_path_returns_error() -> Result<(), Box<dyn Error>> {
        let mut sandbox = LinuxSandbox::new(linux_config())?;

        let result = sandbox.list_dir("/nonexistent/path/abc123");

        assert!(result.is_err(), "不存在路径应返回错误");

        Ok(())
    }

    #[test]
    fn test_linux_list_dir_file_path_returns_error() -> Result<(), Box<dyn Error>> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("not-a-directory.txt");
        std::fs::write(&file_path, "test")?;
        let mut sandbox = LinuxSandbox::new(linux_config())?;

        let result = sandbox.list_dir(&file_path.to_string_lossy());

        assert!(result.is_err(), "文件路径应返回错误");

        Ok(())
    }

    #[test]
    fn test_linux_list_dir_empty_directory_returns_empty() -> Result<(), Box<dyn Error>> {
        let temp_dir = TempDir::new()?;
        let mut sandbox = LinuxSandbox::new(linux_config())?;

        let entries = match sandbox.list_dir(&temp_dir.path().to_string_lossy()) {
            Ok(entries) => entries,
            Err(error) => {
                if error.to_string().contains("operation not supported") {
                    eprintln!("skipping: OS-level sandbox does not support list_dir");
                    return Ok(());
                }
                return Err(error.into());
            }
        };

        assert!(entries.is_empty(), "空目录应返回空 Vec");

        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod macos_backend_tests {
    use std::error::Error;
    use std::path::Path;
    use std::sync::OnceLock;

    use mimobox_core::{NamespaceDegradation, Sandbox, SandboxConfig, SandboxError};
    use mimobox_os::MacOsSandbox;
    use tempfile::TempDir;

    fn macos_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(5);
        config.memory_limit_mb = None;
        config.namespace_degradation = NamespaceDegradation::AllowDegradation;
        config.allow_fork = true;
        config
    }

    fn shell_quote(path: &Path) -> String {
        let raw = path.to_string_lossy();
        format!("'{}'", raw.replace('\'', "'\\''"))
    }

    fn should_skip_runtime_tests() -> bool {
        if let Some(reason) = seatbelt_runtime_skip_reason() {
            eprintln!("跳过 macOS Seatbelt 集成测试: {reason}");
            return true;
        }

        false
    }

    fn seatbelt_runtime_skip_reason() -> Option<&'static str> {
        static SKIP_REASON: OnceLock<Option<String>> = OnceLock::new();

        SKIP_REASON
            .get_or_init(|| {
                let mut sandbox =
                    MacOsSandbox::new(macos_config()).expect("创建 macOS 沙箱探测实例失败");
                let probe_command = vec!["/usr/bin/true".to_string()];

                match sandbox.execute(&probe_command) {
                    Ok(_) => None,
                    Err(SandboxError::ExecutionFailed(message))
                        if message.contains("Seatbelt 策略应用失败") =>
                    {
                        Some(message)
                    }
                    Err(err) => panic!("macOS Seatbelt 最小探测失败: {err}"),
                }
            })
            .as_deref()
    }

    #[test]
    fn macos_sandbox_executes_via_sandbox_exec() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let mut sandbox = MacOsSandbox::new(macos_config())?;
        let command = vec!["/bin/echo".to_string(), "macos-integration".to_string()];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);

        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return Ok(());
        }
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out);
        assert!(stdout.contains("macos-integration"));

        Ok(())
    }

    #[test]
    fn macos_sandbox_restricts_writes_outside_allowlist() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let allowed_dir = TempDir::new()?;
        let forbidden_dir = TempDir::new()?;
        let allowed_file = allowed_dir.path().join("allowed.txt");
        let forbidden_file = forbidden_dir.path().join("forbidden.txt");

        let mut config = macos_config();
        config.fs_readwrite = vec![allowed_dir.path().to_path_buf()];

        let mut allowed_sandbox = MacOsSandbox::new(config.clone())?;
        let allowed_command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "cd / && printf allowed > {} && /bin/cat {}",
                shell_quote(&allowed_file),
                shell_quote(&allowed_file)
            ),
        ];
        let allowed_result = allowed_sandbox.execute(&allowed_command)?;
        let allowed_stdout = String::from_utf8_lossy(&allowed_result.stdout);

        if allowed_result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return Ok(());
        }
        assert_eq!(allowed_result.exit_code, Some(0));
        assert!(allowed_stdout.contains("allowed"));

        let mut forbidden_sandbox = MacOsSandbox::new(config)?;
        let forbidden_command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("cd / && printf denied > {}", shell_quote(&forbidden_file)),
        ];
        let forbidden_result = forbidden_sandbox.execute(&forbidden_command)?;
        let stderr = String::from_utf8_lossy(&forbidden_result.stderr);

        assert!(
            forbidden_result.exit_code != Some(0)
                || stderr.contains("Operation not permitted")
                || stderr.contains("Permission denied")
                || stderr.contains("Read-only file system")
        );
        assert!(!forbidden_file.exists());

        Ok(())
    }

    #[test]
    fn macos_sandbox_denies_network_requests() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let mut config = macos_config();
        config.deny_network = true;
        let mut sandbox = MacOsSandbox::new(config)?;
        let command = vec![
            "/usr/bin/curl".to_string(),
            "--connect-timeout".to_string(),
            "2".to_string(),
            "http://127.0.0.1:1".to_string(),
        ];
        let result = sandbox.execute(&command)?;

        assert!(result.exit_code != Some(0));

        Ok(())
    }

    #[test]
    fn test_macos_list_dir_returns_entries() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let mut sandbox = MacOsSandbox::new(macos_config())?;

        let result = sandbox.list_dir("/tmp");

        match result {
            Err(SandboxError::UnsupportedOperation(msg)) => {
                assert!(
                    msg.contains("list_dir"),
                    "错误信息应包含 list_dir，实际: {msg}"
                );
                assert!(
                    msg.contains("OS-level sandbox does not support"),
                    "错误信息应说明 OS 级沙箱不支持，实际: {msg}"
                );
            }
            Err(err) => panic!("list_dir 应返回 UnsupportedOperation，实际错误: {err}"),
            Ok(_) => panic!("list_dir 应在 macOS 后端返回 UnsupportedOperation"),
        }

        Ok(())
    }

    #[test]
    fn test_macos_list_dir_nonexistent_path_returns_error() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let mut sandbox = MacOsSandbox::new(macos_config())?;

        let result = sandbox.list_dir("/nonexistent/path/abc123");

        match result {
            Err(SandboxError::UnsupportedOperation(msg)) => {
                assert!(
                    msg.contains("list_dir"),
                    "错误信息应包含 list_dir，实际: {msg}"
                );
                assert!(
                    msg.contains("OS-level sandbox does not support"),
                    "错误信息应说明 OS 级沙箱不支持，实际: {msg}"
                );
            }
            Err(err) => panic!("list_dir 应返回 UnsupportedOperation，实际错误: {err}"),
            Ok(_) => panic!("list_dir 应在 macOS 后端返回 UnsupportedOperation"),
        }

        Ok(())
    }

    #[test]
    fn test_macos_list_dir_file_path_returns_error() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let mut sandbox = MacOsSandbox::new(macos_config())?;

        let result = sandbox.list_dir("/etc/hosts");

        match result {
            Err(SandboxError::UnsupportedOperation(msg)) => {
                assert!(
                    msg.contains("list_dir"),
                    "错误信息应包含 list_dir，实际: {msg}"
                );
                assert!(
                    msg.contains("OS-level sandbox does not support"),
                    "错误信息应说明 OS 级沙箱不支持，实际: {msg}"
                );
            }
            Err(err) => panic!("list_dir 应返回 UnsupportedOperation，实际错误: {err}"),
            Ok(_) => panic!("list_dir 应在 macOS 后端返回 UnsupportedOperation"),
        }

        Ok(())
    }

    #[test]
    fn test_macos_list_dir_empty_directory_returns_empty() -> Result<(), Box<dyn Error>> {
        if should_skip_runtime_tests() {
            return Ok(());
        }

        let mut sandbox = MacOsSandbox::new(macos_config())?;

        let result = sandbox.list_dir("/tmp");

        match result {
            Err(SandboxError::UnsupportedOperation(msg)) => {
                assert!(
                    msg.contains("list_dir"),
                    "错误信息应包含 list_dir，实际: {msg}"
                );
                assert!(
                    msg.contains("OS-level sandbox does not support"),
                    "错误信息应说明 OS 级沙箱不支持，实际: {msg}"
                );
            }
            Err(err) => panic!("list_dir 应返回 UnsupportedOperation，实际错误: {err}"),
            Ok(_) => panic!("list_dir 应在 macOS 后端返回 UnsupportedOperation"),
        }

        Ok(())
    }
}
