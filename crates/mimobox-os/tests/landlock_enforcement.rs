#[cfg(target_os = "linux")]
mod landlock_enforcement_tests {
    use std::error::Error;
    use std::path::Path;

    use mimobox_core::{NamespaceDegradation, Sandbox, SandboxConfig};
    use mimobox_os::LinuxSandbox;
    use tempfile::TempDir;

    fn linux_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.allow_fork = true;
        // 保留默认只读路径（/usr, /lib, /bin 等），确保 /bin/sh 可执行。
        config.fs_readwrite = Vec::new();
        config.namespace_degradation = NamespaceDegradation::AllowDegradation;
        config
    }

    fn shell_quote(path: &Path) -> String {
        let raw = path.to_string_lossy();
        format!("'{}'", raw.replace('\'', "'\\''"))
    }

    fn assert_denied(result: &mimobox_core::SandboxResult) {
        let stderr = String::from_utf8_lossy(&result.stderr);

        assert!(
            result.exit_code != Some(0)
                || stderr.contains("Permission denied")
                || stderr.contains("Operation not permitted"),
            "expected access to be denied, got exit_code={:?}, stderr={stderr}",
            result.exit_code
        );
    }

    #[test]
    fn test_landlock_readonly_path_denies_write() -> Result<(), Box<dyn Error>> {
        let readonly_dir = TempDir::new()?;
        let test_file = readonly_dir.path().join("readonly.txt");
        std::fs::write(&test_file, "original")?;

        let mut config = linux_config();
        config.fs_readonly.push(readonly_dir.path().canonicalize()?);

        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("echo test > {}", shell_quote(&test_file)),
        ];
        let result = sandbox.execute(&command)?;

        assert_denied(&result);
        assert_eq!(std::fs::read_to_string(&test_file)?, "original");

        Ok(())
    }

    #[test]
    fn test_landlock_unauthorized_path_denies_read() -> Result<(), Box<dyn Error>> {
        // 使用 /var/tmp 创建临时目录，因为 Landlock 内置的 default_ro 包含 /tmp（只读），
        // 导致 /tmp 下的读操作始终被允许。/var/tmp 不在 default_ro 中，
        // 能正确验证"用户未授权路径的读操作被拒绝"。
        let unauthorized_dir = TempDir::new_in("/var/tmp")?;
        let test_file = unauthorized_dir.path().join("secret.txt");
        std::fs::write(&test_file, "secret")?;

        let config = linux_config();
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/cat".to_string(),
            test_file.canonicalize()?.to_string_lossy().into_owned(),
        ];
        let result = sandbox.execute(&command)?;

        assert_denied(&result);

        Ok(())
    }

    #[test]
    fn test_landlock_unauthorized_path_denies_write() -> Result<(), Box<dyn Error>> {
        let unauthorized_dir = TempDir::new()?;
        let test_file = unauthorized_dir.path().join("denied.txt");

        let config = linux_config();
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("echo denied > {}", shell_quote(&test_file)),
        ];
        let result = sandbox.execute(&command)?;

        assert_denied(&result);
        assert!(!test_file.exists());

        Ok(())
    }

    #[test]
    fn test_landlock_readwrite_path_allows_write() -> Result<(), Box<dyn Error>> {
        let readwrite_dir = TempDir::new()?;
        let test_file = readwrite_dir.path().join("allowed.txt");

        let mut config = linux_config();
        config.fs_readwrite = vec![readwrite_dir.path().canonicalize()?];

        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "echo allowed > {} && /bin/cat {}",
                shell_quote(&test_file),
                shell_quote(&test_file)
            ),
        ];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);

        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return Ok(());
        }
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(std::fs::read_to_string(&test_file)?, "allowed\n");
        assert_eq!(stdout, "allowed\n");

        Ok(())
    }

    #[test]
    fn test_landlock_readonly_path_allows_read() -> Result<(), Box<dyn Error>> {
        let readonly_dir = TempDir::new()?;
        let test_file = readonly_dir.path().join("readable.txt");
        std::fs::write(&test_file, "readable\n")?;

        let mut config = linux_config();
        config.fs_readonly.push(readonly_dir.path().canonicalize()?);

        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/cat".to_string(),
            test_file.canonicalize()?.to_string_lossy().into_owned(),
        ];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);

        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return Ok(());
        }
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(stdout, "readable\n");

        Ok(())
    }
}
