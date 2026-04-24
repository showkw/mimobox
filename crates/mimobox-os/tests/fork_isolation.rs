#[cfg(target_os = "linux")]
mod fork_isolation_tests {
    use std::error::Error;
    use std::path::{Path, PathBuf};

    use mimobox_core::{Sandbox, SandboxConfig, SeccompProfile};
    use mimobox_os::LinuxSandbox;
    use tempfile::TempDir;

    fn isolated_config(readwrite_paths: Vec<PathBuf>) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        // 清空用户配置的只读路径，验证每个沙箱实例只获得自己声明的读写目录。
        config.fs_readonly = vec![];
        config.fs_readwrite = readwrite_paths;
        config.timeout_secs = Some(10);
        config.seccomp_profile = SeccompProfile::Essential;
        config.allow_fork = true;
        config
    }

    fn quoted_path(path: &Path) -> String {
        format!("{path:?}")
    }

    fn run_shell(
        config: SandboxConfig,
        script: String,
    ) -> Result<mimobox_core::SandboxResult, Box<dyn Error>> {
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        Ok(sandbox.execute(&command)?)
    }

    #[test]
    fn test_sandbox_filesystem_isolation_between_instances() -> Result<(), Box<dyn Error>> {
        let dir_a = TempDir::new()?;
        let dir_b = TempDir::new()?;
        let dir_a = dir_a.path().canonicalize()?;
        let dir_b = dir_b.path().canonicalize()?;

        let a_success = dir_a.join("success.txt");
        let a_fail = dir_b.join("fail.txt");
        let b_success = dir_b.join("success.txt");
        let b_fail = dir_a.join("fail.txt");

        let result_a = run_shell(
            isolated_config(vec![dir_a.clone()]),
            format!(
                "printf a > {success} && ! printf a > {fail}",
                success = quoted_path(&a_success),
                fail = quoted_path(&a_fail),
            ),
        )?;

        assert_eq!(
            result_a.exit_code,
            Some(0),
            "sandbox_a 应只能写入 dir_a: stdout={}, stderr={}",
            String::from_utf8_lossy(&result_a.stdout),
            String::from_utf8_lossy(&result_a.stderr),
        );

        let result_b = run_shell(
            isolated_config(vec![dir_b.clone()]),
            format!(
                "printf b > {success} && ! printf b > {fail}",
                success = quoted_path(&b_success),
                fail = quoted_path(&b_fail),
            ),
        )?;

        assert_eq!(
            result_b.exit_code,
            Some(0),
            "sandbox_b 应只能写入 dir_b: stdout={}, stderr={}",
            String::from_utf8_lossy(&result_b.stdout),
            String::from_utf8_lossy(&result_b.stderr),
        );

        assert_eq!(std::fs::read_to_string(&a_success)?, "a");
        assert_eq!(std::fs::read_to_string(&b_success)?, "b");
        assert!(!a_fail.exists(), "sandbox_a 不应能写入 dir_b");
        assert!(!b_fail.exists(), "sandbox_b 不应能写入 dir_a");

        Ok(())
    }

    #[test]
    fn test_sandbox_pid_namespace_isolation() -> Result<(), Box<dyn Error>> {
        let result_a = run_shell(isolated_config(vec![]), "echo $$".to_string())?;
        let result_b = run_shell(isolated_config(vec![]), "echo $$".to_string())?;

        assert_eq!(
            result_a.exit_code,
            Some(0),
            "sandbox_a 获取 PID 失败: stderr={}",
            String::from_utf8_lossy(&result_a.stderr),
        );
        assert_eq!(
            result_b.exit_code,
            Some(0),
            "sandbox_b 获取 PID 失败: stderr={}",
            String::from_utf8_lossy(&result_b.stderr),
        );

        let pid_a: u32 = String::from_utf8_lossy(&result_a.stdout).trim().parse()?;
        let pid_b: u32 = String::from_utf8_lossy(&result_b.stdout).trim().parse()?;

        assert_eq!(
            pid_a, 1,
            "sandbox_a 中 shell 应作为新 PID namespace 的 init 进程"
        );
        assert_eq!(
            pid_b, 1,
            "sandbox_b 中 shell 应作为新 PID namespace 的 init 进程"
        );

        Ok(())
    }

    #[test]
    fn test_sandbox_process_visibility_isolation() -> Result<(), Box<dyn Error>> {
        // 需要 /proc 只读访问以便 awk 读取 /proc/self/status。
        // Landlock 内置的 default_ro 仅包含 /proc/self（符号链接路径），
        // 在 unshare(CLONE_NEWPID)+fork 后路径解析可能不匹配，
        // 导致 gawk 无法读取 /proc/self/maps 进而 fallback 到 mincore (syscall 27)，
        // 被 Seccomp 阻止 (SIGSYS)。显式授权整个 /proc 只读可解决此问题。
        let config_with_proc = {
            let mut c = isolated_config(vec![]);
            c.fs_readonly = vec!["/proc".into()];
            c
        };

        let result_a = run_shell(
            config_with_proc.clone(),
            "awk '/^NSpid:/ { print $NF }' /proc/self/status".to_string(),
        )?;
        let result_b = run_shell(
            config_with_proc,
            "awk '/^NSpid:/ { print $NF }' /proc/self/status".to_string(),
        )?;

        assert_eq!(
            result_a.exit_code,
            Some(0),
            "sandbox_a 读取 /proc/self/status 失败: stderr={}",
            String::from_utf8_lossy(&result_a.stderr),
        );
        assert_eq!(
            result_b.exit_code,
            Some(0),
            "sandbox_b 读取 /proc/self/status 失败: stderr={}",
            String::from_utf8_lossy(&result_b.stderr),
        );

        let pid_a: u32 = String::from_utf8_lossy(&result_a.stdout).trim().parse()?;
        let pid_b: u32 = String::from_utf8_lossy(&result_b.stdout).trim().parse()?;

        assert_eq!(pid_a, 1, "sandbox_a 在自身 PID namespace 内应看到 PID 1");
        assert_eq!(pid_b, 1, "sandbox_b 在自身 PID namespace 内应看到 PID 1");

        Ok(())
    }
}
