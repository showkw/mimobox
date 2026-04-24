#[cfg(target_os = "linux")]
mod landlock_enforcement_tests {
    use std::error::Error;
    use std::path::Path;

    use mimobox_core::{Sandbox, SandboxConfig};
    use mimobox_os::LinuxSandbox;
    use tempfile::TempDir;

    fn linux_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.allow_fork = true;
        config.fs_readonly = Vec::new();
        config.fs_readwrite = Vec::new();
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
        config.fs_readonly = vec![readonly_dir.path().canonicalize()?];

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
        let unauthorized_dir = TempDir::new()?;
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
        config.fs_readonly = vec![readonly_dir.path().canonicalize()?];

        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/cat".to_string(),
            test_file.canonicalize()?.to_string_lossy().into_owned(),
        ];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);

        assert_eq!(result.exit_code, Some(0));
        assert_eq!(stdout, "readable\n");

        Ok(())
    }
}
