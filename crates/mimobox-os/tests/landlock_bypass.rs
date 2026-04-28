#[cfg(target_os = "linux")]
mod landlock_bypass_tests {
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use mimobox_core::{Sandbox, SandboxConfig};
    use mimobox_os::LinuxSandbox;
    use tempfile::TempDir;

    fn linux_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.allow_fork = true;
        // 保留默认只读路径（/usr, /lib, /bin 等），确保 /bin/sh 可执行。
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

    fn authorize_tmp_readonly(config: &mut SandboxConfig) {
        // 绕过测试需要把 /tmp 作为只读授权入口；写权限仍保持空列表。
        config.fs_readonly.push("/tmp".into());
    }

    #[test]
    fn test_proc_self_mem_bypass() -> Result<(), Box<dyn Error>> {
        let config = linux_config();
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf x > /proc/self/mem".to_string(),
        ];
        let result = sandbox.execute(&command)?;

        assert_denied(&result);

        Ok(())
    }

    #[test]
    fn test_symlink_bypass_to_unauthorized() -> Result<(), Box<dyn Error>> {
        let unauthorized_dir = TempDir::new_in("/var/tmp")?;
        let secret_file = unauthorized_dir.path().join("secret.txt");
        fs::write(&secret_file, "secret\n")?;

        let link_dir = TempDir::new_in("/tmp")?;
        let link_path = link_dir.path().join("secret-link.txt");
        symlink(&secret_file, &link_path)?;

        let mut config = linux_config();
        authorize_tmp_readonly(&mut config);

        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("/bin/cat {}", shell_quote(&link_path)),
        ];
        let result = sandbox.execute(&command)?;

        assert_denied(&result);

        Ok(())
    }

    /// 验证 Landlock 正确追踪 symlink 目标路径。
    ///
    /// 当 symlink 位于未授权目录（/var/tmp）但目标文件位于已授权的只读目录（/tmp）时，
    /// Landlock 检查的是目标路径而非链接本身路径，因此读取应当成功。
    /// 这不是绕过，而是 Landlock 正确的安全语义。
    #[test]
    fn test_symlink_to_authorized_target_allows_read() -> Result<(), Box<dyn Error>> {
        let authorized_dir = TempDir::new_in("/tmp")?;
        let public_file = authorized_dir.path().join("public.txt");
        fs::write(&public_file, "public\n")?;

        let unauthorized_dir = TempDir::new_in("/var/tmp")?;
        let link_path = unauthorized_dir.path().join("public-link.txt");
        symlink(&public_file, &link_path)?;

        let mut config = linux_config();
        authorize_tmp_readonly(&mut config);

        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("/bin/cat {}", shell_quote(&link_path)),
        ];
        let result = sandbox.execute(&command)?;

        // CI 容器环境 execvp /bin/sh 返回 125，无法验证 Landlock 行为。
        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack \
                 complete filesystem isolation"
            );
            return Ok(());
        }

        // Landlock 检查 symlink 的目标路径（在授权的 /tmp 下），读取应该成功。
        assert_eq!(
            result.exit_code,
            Some(0),
            "expected successful read via symlink to authorized target"
        );
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("public"),
            "stdout should contain file content, got: {stdout}"
        );

        Ok(())
    }

    #[test]
    #[ignore = "需要 Linux 5.6+ openat2/RESOLVE_IN_ROOT 支持，默认跳过手动验证"]
    fn test_openat2_resolve_in_root_bypass() -> Result<(), Box<dyn Error>> {
        let unauthorized_dir = TempDir::new_in("/var/tmp")?;
        let secret_file = unauthorized_dir.path().join("openat2-secret.txt");
        fs::write(&secret_file, "secret\n")?;

        let script = format!(
            r#"
import ctypes
import os

SYS_openat2 = 437
AT_FDCWD = -100
RESOLVE_IN_ROOT = 0x10

class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ulonglong),
        ("mode", ctypes.c_ulonglong),
        ("resolve", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL(None, use_errno=True)
how = OpenHow(os.O_RDONLY, 0, RESOLVE_IN_ROOT)
fd = libc.syscall(
    SYS_openat2,
    AT_FDCWD,
    ctypes.c_char_p({path}.encode()),
    ctypes.byref(how),
    ctypes.sizeof(how),
)
if fd >= 0:
    os.close(fd)
    os._exit(0)

errno = ctypes.get_errno()
os.write(2, (os.strerror(errno) + "\n").encode())
os._exit(1)
"#,
            path = format!("{:?}", secret_file),
        );

        let config = linux_config();
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("python3 - <<'PY'\n{script}\nPY"),
        ];
        let result = sandbox.execute(&command)?;

        assert_denied(&result);

        Ok(())
    }

    #[test]
    fn test_proc_self_cwd_bypass() -> Result<(), Box<dyn Error>> {
        let unauthorized_dir = TempDir::new_in("/var/tmp")?;
        let secret_dir = unauthorized_dir.path().join("secret_dir");
        fs::create_dir(&secret_dir)?;
        let secret_file = secret_dir.join("secret.txt");
        fs::write(&secret_file, "secret\n")?;

        let config = linux_config();
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "cd {} && /bin/cat /proc/self/cwd/secret.txt",
                shell_quote(&secret_dir)
            ),
        ];
        let result = sandbox.execute(&command)?;

        assert_denied(&result);

        Ok(())
    }

    #[test]
    fn test_hardlink_bypass() -> Result<(), Box<dyn Error>> {
        let unauthorized_dir = TempDir::new_in("/var/tmp")?;
        let secret_file = unauthorized_dir.path().join("secret.txt");
        fs::write(&secret_file, "secret\n")?;

        let tmp_link_dir = TempDir::new_in("/tmp")?;
        let mut readonly_root = PathBuf::from("/tmp");
        let mut hardlink_path = tmp_link_dir.path().join("secret-hardlink.txt");
        let mut fallback_link_dir = None;

        if let Err(error) = fs::hard_link(&secret_file, &hardlink_path) {
            if error.raw_os_error() != Some(18) {
                return Err(Box::new(error));
            }

            // EXDEV 表示 /tmp 与 /var/tmp 不在同一文件系统；硬链接无法跨设备。
            // 此时退化为同文件系统下的只读授权目录，继续验证硬链接写绕过。
            let same_fs_link_dir = TempDir::new_in("/var/tmp")?;
            hardlink_path = same_fs_link_dir.path().join("secret-hardlink.txt");
            fs::hard_link(&secret_file, &hardlink_path)?;
            readonly_root = same_fs_link_dir.path().canonicalize()?;
            fallback_link_dir = Some(same_fs_link_dir);
        }

        let mut config = linux_config();
        config.fs_readonly.push(readonly_root);

        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("echo overwritten > {}", shell_quote(&hardlink_path)),
        ];
        let result = sandbox.execute(&command)?;

        assert_denied(&result);
        assert_eq!(fs::read_to_string(&secret_file)?, "secret\n");
        drop(fallback_link_dir);

        Ok(())
    }
}
