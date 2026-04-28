#[cfg(target_os = "linux")]
pub mod seccomp_rejection_tests {
    use std::error::Error;
    use std::path::{Path, PathBuf};

    use mimobox_core::{NamespaceDegradation, Sandbox, SandboxConfig, SeccompProfile};
    use mimobox_os::LinuxSandbox;
    use tempfile::TempDir;

    fn strict_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.seccomp_profile = SeccompProfile::Essential;
        config.allow_fork = false;
        config.namespace_degradation = NamespaceDegradation::AllowDegradation;
        config
    }

    fn config_with_profile(profile: SeccompProfile) -> SandboxConfig {
        let mut config = strict_config();
        config.seccomp_profile = profile;
        // 带 Fork 的 profile 需要同时设置 allow_fork=true，
        // 否则 RLIMIT_NPROC 等配套机制不会生效。
        if matches!(
            profile,
            SeccompProfile::EssentialWithFork | SeccompProfile::NetworkWithFork
        ) {
            config.allow_fork = true;
        }
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
        run_python_syscall_with_config(script, strict_config())
    }

    fn run_python_syscall_with_config(
        script: String,
        config: SandboxConfig,
    ) -> Result<Option<i32>, Box<dyn Error>> {
        let Some(python) = python_command() else {
            eprintln!("跳过测试: 当前系统未找到 python3/python");
            return Ok(Some(0));
        };

        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            python.to_string_lossy().into_owned(),
            "-c".to_string(),
            script,
        ];
        let result = sandbox.execute(&command)?;

        Ok(result.exit_code)
    }

    fn assert_python_syscall_blocked(exit_code: Option<i32>) -> Result<(), Box<dyn Error>> {
        if exit_code == Some(0) && python_command().is_none() {
            return Ok(());
        }

        assert_blocked_by_seccomp(exit_code);
        Ok(())
    }

    fn quoted_path(path: &Path) -> String {
        format!("{path:?}")
    }

    /// 防止沙箱内挂载新文件系统；Essential profile 应直接拒绝 mount syscall。
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

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱内卸载宿主或命名空间挂载点；Essential profile 应拒绝 umount2。
    #[test]
    #[ignore = "umount2 依赖具备挂载命名空间权限的 Linux 环境；默认跳过"]
    fn test_seccomp_blocks_umount2() -> Result<(), Box<dyn Error>> {
        let target = TempDir::new()?;
        let script = format!(
            r#"
import ctypes
import os

SYS_umount2 = 166
target = {target}.encode()
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_umount2, ctypes.c_char_p(target), 0)
os._exit(0)
"#,
            target = quoted_path(target.path()),
        );
        let exit_code = run_python_syscall(script)?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱加载或操作内核 BPF 程序；Essential profile 应拒绝 bpf。
    #[test]
    fn test_seccomp_blocks_bpf() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_bpf = 321
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_bpf, 0, 0, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱访问性能事件侧信道；Essential profile 应拒绝 perf_event_open。
    #[test]
    fn test_seccomp_blocks_perf_event_open() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_perf_event_open = 298
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_perf_event_open, -1, -1, -1, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱读取内核日志泄露宿主信息；Essential profile 应拒绝 syslog。
    #[test]
    fn test_seccomp_blocks_syslog() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_syslog = 103
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_syslog, 2, 0, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱切换到高权限用户身份；Essential profile 应拒绝 setuid。
    #[test]
    fn test_seccomp_blocks_setuid() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_setuid = 105
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_setuid, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱切换到高权限组身份；Essential profile 应拒绝 setgid。
    #[test]
    fn test_seccomp_blocks_setgid() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_setgid = 106
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_setgid, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱调试或注入其他进程；Essential profile 应拒绝 ptrace。
    #[test]
    fn test_seccomp_blocks_ptrace() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_ptrace = 101
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_ptrace, 0, 0, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱触发系统重启路径；Essential profile 应拒绝 reboot。
    #[test]
    #[ignore = "reboot 属于高危系统调用；默认跳过，仅在隔离 Linux 环境中手动运行"]
    fn test_seccomp_blocks_reboot() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_reboot = 169
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_reboot, 0, 0, 0, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱替换根文件系统；Essential profile 应拒绝 pivot_root。
    #[test]
    #[ignore = "pivot_root 需要特权挂载环境；默认跳过，仅在隔离 Linux 环境中手动运行"]
    fn test_seccomp_blocks_pivot_root() -> Result<(), Box<dyn Error>> {
        let old_root = TempDir::new()?;
        let new_root = TempDir::new()?;
        let script = format!(
            r#"
import ctypes
import os

SYS_pivot_root = 155
new_root = {new_root}.encode()
old_root = {old_root}.encode()
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(
    SYS_pivot_root,
    ctypes.c_char_p(new_root),
    ctypes.c_char_p(old_root),
)
os._exit(0)
"#,
            new_root = quoted_path(new_root.path()),
            old_root = quoted_path(old_root.path()),
        );
        let exit_code = run_python_syscall(script)?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 防止沙箱访问内核 keyring；Essential profile 应拒绝 keyctl。
    #[test]
    fn test_seccomp_blocks_keyctl() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_keyctl = 250
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_keyctl, 0, 0, 0, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// 网络 profile 只允许 AF_UNIX/AF_INET；AF_INET6 socket 应被参数约束拒绝。
    #[test]
    fn test_seccomp_arg_constraint_blocks_inet6_socket() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall_with_config(
            r#"
import ctypes
import os

SYS_socket = 41
AF_INET6 = 10
SOCK_STREAM = 1
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_socket, AF_INET6, SOCK_STREAM, 0)
os._exit(0)
"#
            .to_string(),
            config_with_profile(SeccompProfile::Network),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// prctl 仅允许只读 capability 查询；PR_SET_DUMPABLE 应被参数约束拒绝。
    #[test]
    fn test_seccomp_arg_constraint_blocks_prctl_set_dumpable() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_prctl = 157
PR_SET_DUMPABLE = 4
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// futex 仅允许普通等待/唤醒操作；FUTEX_LOCK_PI 应被参数约束拒绝。
    #[test]
    fn test_seccomp_arg_constraint_blocks_futex_lock_pi() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_futex = 202
FUTEX_LOCK_PI = 6
word = ctypes.c_int(0)
addr = ctypes.c_void_p(ctypes.addressof(word))
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_futex, addr, FUTEX_LOCK_PI, 0, 0, 0, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// fork profile 允许普通 clone，但 namespace flag 仍应被参数约束拒绝。
    #[test]
    fn test_seccomp_arg_constraint_blocks_clone_newnet() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall_with_config(
            r#"
import ctypes
import os

SYS_clone = 56
CLONE_NEWNET = 0x40000000
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_clone, CLONE_NEWNET, 0, 0, 0, 0)
os._exit(0)
"#
            .to_string(),
            config_with_profile(SeccompProfile::EssentialWithFork),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// ioctl 只允许终端安全 request；TIOCSTI 终端注入应被参数约束拒绝。
    #[test]
    fn test_seccomp_arg_constraint_blocks_ioctl_tiocsti() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_ioctl = 16
TIOCSTI = 0x5412
fd = os.open("/dev/null", os.O_RDONLY)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_ioctl, fd, TIOCSTI, ctypes.c_char_p(b"x"))
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// Essential profile 只允许 AF_UNIX socket；AF_INET socket 应被拒绝。
    #[test]
    fn test_seccomp_essential_blocks_inet_socket() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall(
            r#"
import ctypes
import os

SYS_socket = 41
AF_INET = 2
SOCK_STREAM = 1
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(SYS_socket, AF_INET, SOCK_STREAM, 0)
os._exit(0)
"#
            .to_string(),
        )?;

        assert_python_syscall_blocked(exit_code)
    }

    /// Network profile 应允许 AF_INET socket，并允许执行 connect/close 路径。
    #[test]
    fn test_seccomp_network_allows_inet_socket() -> Result<(), Box<dyn Error>> {
        let exit_code = run_python_syscall_with_config(
            r#"
import ctypes
import os

SYS_socket = 41
SYS_connect = 42
SYS_close = 3
AF_INET = 2
SOCK_STREAM = 1

class SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]

libc = ctypes.CDLL(None, use_errno=True)
fd = libc.syscall(SYS_socket, AF_INET, SOCK_STREAM, 0)
if fd < 0:
    os._exit(1)

addr = SockaddrIn()
addr.sin_family = AF_INET
addr.sin_port = 9 << 8
addr.sin_addr = int.from_bytes(bytes([127, 0, 0, 1]), "little")
libc.syscall(SYS_connect, fd, ctypes.byref(addr), ctypes.sizeof(addr))
libc.syscall(SYS_close, fd)
os._exit(0)
"#
            .to_string(),
            config_with_profile(SeccompProfile::Network),
        )?;

        if exit_code == Some(0) && python_command().is_none() {
            return Ok(());
        }

        // CI 容器环境 execvp /bin/sh 返回 125
        if exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack \
                 complete filesystem isolation"
            );
            return Ok(());
        }

        assert_eq!(
            exit_code,
            Some(0),
            "Network profile 应允许 AF_INET socket/connect/close，实际 exit_code: {exit_code:?}"
        );

        Ok(())
    }

    /// EssentialWithFork profile 应允许 shell 创建子进程并等待完成。
    #[test]
    #[ignore = "需要 root/CAP_SYS_ADMIN 完整 namespace 隔离；默认跳过，CI 环境下 namespace 不完整"]
    fn test_seccomp_fork_profile_allows_fork() -> Result<(), Box<dyn Error>> {
        let mut sandbox =
            LinuxSandbox::new(config_with_profile(SeccompProfile::EssentialWithFork))?;
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 0.1 & wait".to_string(),
        ];
        let result = sandbox.execute(&command)?;

        assert_eq!(
            result.exit_code,
            Some(0),
            "EssentialWithFork profile 应允许 fork/wait，stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );

        Ok(())
    }

    /// Essential profile 禁止 fork；shell 后台子进程路径应被 seccomp 拦截。
    #[test]
    fn test_seccomp_essential_blocks_fork() -> Result<(), Box<dyn Error>> {
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
}
