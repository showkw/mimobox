#[cfg(target_os = "linux")]
mod linux_seccomp_enforcement_tests {
    use std::error::Error;
    use std::path::{Path, PathBuf};

    use mimobox_core::{Sandbox, SandboxConfig, SeccompProfile};
    use mimobox_os::LinuxSandbox;
    use tempfile::TempDir;

    fn strict_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.seccomp_profile = SeccompProfile::Essential;
        config.allow_fork = false;
        config
    }

    fn python_command() -> Option<PathBuf> {
        ["/usr/bin/python3", "/bin/python3", "/usr/bin/python"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.exists())
    }

    fn assert_blocked_by_seccomp(exit_code: Option<i32>) {
        assert!(
            matches!(exit_code, None | Some(-31) | Some(159)) || exit_code != Some(0),
            "被禁止的 syscall 应导致非零退出、SIGSYS 退出或无退出码，实际 exit_code: {exit_code:?}"
        );
    }

    fn run_python_syscall(script: String) -> Result<Option<i32>, Box<dyn Error>> {
        let Some(python) = python_command() else {
            eprintln!("跳过测试: 当前系统未找到 python3/python");
            return Ok(Some(0));
        };

        let mut sandbox = LinuxSandbox::new(strict_config())?;
        let command = vec![
            python.to_string_lossy().into_owned(),
            "-c".to_string(),
            script,
        ];
        let result = sandbox.execute(&command)?;

        Ok(result.exit_code)
    }

    fn quoted_path(path: &Path) -> String {
        format!("{path:?}")
    }

    #[test]
    fn test_seccomp_blocks_fork() -> Result<(), Box<dyn Error>> {
        let mut sandbox = LinuxSandbox::new(strict_config())?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 0.1 & wait".to_string(),
        ];
        let result = sandbox.execute(&command)?;

        assert_blocked_by_seccomp(result.exit_code);

        Ok(())
    }

    #[test]
    fn test_seccomp_blocks_clone() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_clone = 56
SIGCHLD = 17
libc = ctypes.CDLL(None, use_errno=True)
pid = libc.syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0)
if pid == 0:
    os._exit(0)
if pid > 0:
    os.waitpid(pid, 0)
    os._exit(0)
os._exit(1)
"#
            .to_string(),
        )?;

        if exit_code == Some(0) && python_command().is_none() {
            return Ok(());
        }

        assert_blocked_by_seccomp(exit_code);

        Ok(())
    }

    #[test]
    fn test_seccomp_blocks_ptrace() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_ptrace = 101
PTRACE_TRACEME = 0
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        if exit_code == Some(0) && python_command().is_none() {
            return Ok(());
        }

        assert_blocked_by_seccomp(exit_code);

        Ok(())
    }

    #[test]
    fn test_seccomp_blocks_chroot() -> Result<(), Box<dyn Error>> {
        let root = TempDir::new()?;
        let script = format!(
            r#"
import ctypes
import os

SYS_chroot = 161
path = {path}.encode()
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_chroot, ctypes.c_char_p(path))
os._exit(0)
"#,
            path = quoted_path(root.path()),
        );
        let exit_code = run_python_syscall(script)?;

        if exit_code == Some(0) && python_command().is_none() {
            return Ok(());
        }

        assert_blocked_by_seccomp(exit_code);

        Ok(())
    }

    #[test]
    #[ignore = "mount 通常需要 root/CAP_SYS_ADMIN；默认跳过，仅在具备权限的 Linux 环境中手动运行"]
    fn test_seccomp_blocks_mount() -> Result<(), Box<dyn Error>> {
        let target = TempDir::new()?;
        let script = format!(
            r#"
import ctypes
import os

SYS_mount = 165
source = b"none"
target = {target}.encode()
fstype = b"tmpfs"
flags = 0
data = b"size=4k"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(
    SYS_mount,
    ctypes.c_char_p(source),
    ctypes.c_char_p(target),
    ctypes.c_char_p(fstype),
    ctypes.c_ulong(flags),
    ctypes.c_char_p(data),
)
os._exit(0)
"#,
            target = quoted_path(target.path()),
        );
        let exit_code = run_python_syscall(script)?;

        if exit_code == Some(0) && python_command().is_none() {
            return Ok(());
        }

        assert_blocked_by_seccomp(exit_code);

        Ok(())
    }
}
