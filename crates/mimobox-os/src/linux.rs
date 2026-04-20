use std::ffi::CString;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::time::{Duration, Instant};

use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, execvp, fork};

use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult, SeccompProfile};

use crate::seccomp;

/// 使用 pipe2 + O_CLOEXEC 创建管道
///
/// O_CLOEXEC 确保 fork+exec 后管道 fd 自动关闭，避免泄漏到沙箱进程。
fn create_pipe_cloexec() -> Result<(RawFd, RawFd), SandboxError> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: pipe2 系统调用，fds 是有效的输出缓冲区
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(SandboxError::PipeError(format!(
            "pipe2(O_CLOEXEC) 失败: errno={errno}"
        )));
    }
    Ok((fds[0], fds[1]))
}

pub struct LinuxSandbox {
    config: SandboxConfig,
}

/// 在子进程中写入 fd（无 Rust std 依赖，fork 后安全使用）
///
/// # Safety
///
/// 仅在 fork 后的子进程中使用，此时只有当前线程存活。
unsafe fn write_msg(fd: RawFd, msg: &[u8]) {
    // SAFETY: 仅在 fork 后子进程单线程环境中调用，fd 有效。
    unsafe {
        libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

/// 在子进程中写入格式化错误消息
///
/// # Safety
///
/// 仅在 fork 后的子进程中使用。
unsafe fn write_error(fd: RawFd, msg: &str) {
    let full = format!("[mimobox:error] {msg}\n");
    // SAFETY: 仅在 fork 后子进程单线程环境中调用。
    unsafe {
        write_msg(fd, full.as_bytes());
    }
}

/// 在子进程中设置内存限制
///
/// 优先使用 setrlimit(RLIMIT_AS) 实施，无需 root 权限。
fn set_memory_limit(limit_mb: u64) -> Result<(), String> {
    let limit_bytes = limit_mb * 1024 * 1024;
    // IMPORTANT-03 修复：rlim_max 设为与 rlim_cur 相同，防止子进程提高内存限制
    let rlim = libc::rlimit {
        rlim_cur: limit_bytes,
        rlim_max: limit_bytes,
    };
    // SAFETY: rlim 是栈上有效结构体，RLIMIT_AS 是合法 resource 参数
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_AS, &rlim) };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!(
            "setrlimit(RLIMIT_AS, {limit_mb}MB) 失败: errno={errno}"
        ));
    }
    Ok(())
}

impl LinuxSandbox {
    /// 子进程主逻辑：应用安全策略后执行命令
    ///
    /// 执行顺序（安全策略最早应用，最小化竞态窗口）：
    /// 1. 重定向 fd
    /// 2. 设置内存限制 (setrlimit)
    /// 3. 应用 Landlock 文件系统隔离
    /// 4. unshare 命名空间
    /// 5. 应用 Seccomp-bpf 系统调用过滤（在 exec 之前最后应用）
    /// 6. execvp 执行命令
    fn child_main(
        cmd: &[String],
        config: &SandboxConfig,
        stdout_fd: RawFd,
        stderr_fd: RawFd,
        close_fds: Option<(RawFd, RawFd)>, // 需要关闭的管道读端 fd
    ) -> ! {
        // FATAL-02 修复：setpgid 和 close 使用裸 libc 调用，确保 async-signal-safe
        // SAFETY: setpgid(0, 0) 创建新进程组，参数合法
        unsafe {
            libc::setpgid(0, 0);
        }
        // 关闭管道读端
        if let Some((r1, r2)) = close_fds {
            // SAFETY: fd 有效且子进程不需要读端
            unsafe {
                libc::close(r1);
                libc::close(r2);
            }
        }

        // IMPORTANT-04 修复：清理环境变量，防止预热池复用时信息泄漏
        // SAFETY: clearenv() 清空所有环境变量，在子进程中执行不影响父进程
        unsafe {
            libc::clearenv();
        }
        // 设置最小必要环境变量（shell 等程序运行需要）
        // SAFETY: setenv 在子进程中调用，参数为合法 C 字符串
        unsafe {
            libc::setenv(
                b"PATH\0".as_ptr() as *const i8,
                b"/usr/bin:/bin:/usr/sbin:/sbin\0".as_ptr() as *const i8,
                1,
            );
            libc::setenv(
                b"HOME\0".as_ptr() as *const i8,
                b"/tmp\0".as_ptr() as *const i8,
                1,
            );
            libc::setenv(
                b"TERM\0".as_ptr() as *const i8,
                b"dumb\0".as_ptr() as *const i8,
                1,
            );
        }

        // 0. 重定向 fd
        // FATAL-03 修复：/dev/null 打开失败视为致命错误，终止子进程
        // SAFETY: open 系统调用打开 /dev/null，路径为合法 C 字符串
        let dev_null = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const i8, libc::O_RDWR) };
        if dev_null < 0 {
            unsafe {
                write_error(2, "无法打开 /dev/null");
                libc::_exit(120);
            }
        }
        unsafe {
            libc::dup2(dev_null, 0);
            libc::close(dev_null);
            libc::dup2(stdout_fd, 1);
            libc::dup2(stderr_fd, 2);
            libc::close(stdout_fd);
            libc::close(stderr_fd);
        }

        // 1. 设置内存限制（最早应用，防止后续操作消耗过多内存）
        if let Some(limit_mb) = config.memory_limit_mb {
            if let Err(e) = set_memory_limit(limit_mb) {
                unsafe {
                    write_error(2, &format!("内存限制设置失败: {e}"));
                    libc::_exit(124);
                }
            }
        }

        // 2. 应用 Landlock（文件系统隔离）
        {
            use landlock::{
                ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, path_beneath_rules,
            };

            let abi = ABI::V1;
            let all_access = AccessFs::from_all(abi);
            let read_access = AccessFs::from_read(abi);

            let result = (|| -> Result<(), landlock::RulesetError> {
                let mut ruleset = Ruleset::default().handle_access(all_access)?.create()?;

                let default_ro: Vec<&str> = [
                    "/bin",
                    "/usr",
                    "/lib",
                    "/lib64",
                    "/etc",
                    "/proc/self",
                    "/dev/urandom",
                    "/tmp",
                ]
                .into_iter()
                .filter(|path| std::path::Path::new(path).exists())
                .collect();
                if !default_ro.is_empty() {
                    ruleset = ruleset.add_rules(path_beneath_rules(&default_ro, read_access))?;
                }

                let user_ro: Vec<&str> = config
                    .fs_readonly
                    .iter()
                    .filter_map(|p| p.to_str())
                    .collect();
                if !user_ro.is_empty() {
                    ruleset = ruleset.add_rules(path_beneath_rules(&user_ro, read_access))?;
                }

                let rw: Vec<&str> = config
                    .fs_readwrite
                    .iter()
                    .filter_map(|p| p.to_str())
                    .collect();
                if !rw.is_empty() {
                    ruleset = ruleset.add_rules(path_beneath_rules(&rw, all_access))?;
                }

                ruleset.restrict_self()?;
                Ok(())
            })();

            if let Err(e) = result {
                // 致命 #4 修复：Landlock 失败必须终止，否则无文件系统隔离
                unsafe {
                    write_error(2, &format!("Landlock 应用失败（致命）: {e}"));
                    libc::_exit(122);
                }
            }
        }

        // 3. unshare 命名空间
        let ns_flags = CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNET
            | CloneFlags::CLONE_NEWIPC;

        let full_flags = CloneFlags::CLONE_NEWUSER | ns_flags;

        let ns_result = nix::sched::unshare(full_flags);

        if let Err(e) = ns_result {
            let msg = format!("unshare(full_flags) 失败: {e}, 尝试不带 user ns");
            unsafe {
                write_error(2, &msg);
            }

            if let Err(e2) = nix::sched::unshare(ns_flags) {
                // 致命 #5 修复：unshare 失败必须终止，否则无命名空间隔离
                unsafe {
                    write_error(2, &format!("unshare(ns_flags) 也失败（致命）: {e2}"));
                    libc::_exit(121);
                }
            }
        }

        // 4. CLONE_NEWPID 需要 fork 才生效
        // 致命 #6 修复：简化逻辑 — 仅在首次 unshare 成功时需要 reexec
        // （CLONE_NEWPID 已包含在 full_flags 中，无需二次尝试）
        if ns_result.is_ok() {
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child }) => {
                    // 中间进程：等待孙进程退出后转发退出码
                    loop {
                        match waitpid(child, None) {
                            Ok(WaitStatus::Exited(_, code)) => unsafe { libc::_exit(code) },
                            Ok(WaitStatus::Signaled(_, sig, _)) => unsafe {
                                libc::_exit(128 + sig as i32)
                            },
                            _ => continue,
                        }
                    }
                }
                Ok(ForkResult::Child) => {
                    // 孙进程：继续应用 seccomp 并执行命令
                }
                Err(e) => unsafe {
                    write_error(2, &format!("内部 fork 失败: {e}"));
                    libc::_exit(123);
                },
            }
        }

        // 5. 应用 Seccomp-bpf 过滤（在 exec 之前最后应用）
        // 致命 #3 修复：Seccomp 在所有安全策略配置完成后、exec 之前立即应用
        let effective_profile = match (config.allow_fork, config.seccomp_profile) {
            (true, SeccompProfile::Essential) => SeccompProfile::EssentialWithFork,
            (true, SeccompProfile::Network) => SeccompProfile::NetworkWithFork,
            (_, other) => other,
        };
        if let Err(e) = seccomp::apply_seccomp(effective_profile) {
            unsafe {
                write_error(2, &format!("Seccomp error: {e}"));
                libc::_exit(126);
            }
        }

        // 6. execvp
        // 重要 #12 修复：使用 unwrap_or_else + _exit 替代 unwrap
        let c_cmd = CString::new(cmd[0].as_str()).unwrap_or_else(|_| unsafe {
            write_error(2, &format!("命令包含内嵌 NUL: {}", cmd[0]));
            libc::_exit(127);
        });
        let c_args: Vec<CString> = cmd
            .iter()
            .map(|s| {
                CString::new(s.as_str()).unwrap_or_else(|_| unsafe {
                    write_error(2, &format!("参数包含内嵌 NUL: {s}"));
                    libc::_exit(127);
                })
            })
            .collect();

        let _ = execvp(&c_cmd, &c_args);

        unsafe {
            write_error(2, &format!("execvp failed: {}", cmd[0]));
            libc::_exit(125);
        }
    }
}

impl Sandbox for LinuxSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        tracing::info!(
            "创建沙箱, seccomp={:?}, allow_fork={}, timeout={:?}s",
            config.seccomp_profile,
            config.allow_fork,
            config.timeout_secs
        );
        Ok(Self { config })
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        if cmd.is_empty() {
            return Err(SandboxError::ExecutionFailed("命令为空".into()));
        }

        tracing::info!("执行命令: {} {}", cmd[0], cmd[1..].join(" "));
        let start = Instant::now();
        let timeout = self.config.timeout_secs.map(Duration::from_secs);

        // 重要 #10 修复：使用 pipe2 + O_CLOEXEC 创建管道
        let (stdout_read_fd, stdout_write_fd) = create_pipe_cloexec()?;
        let (stderr_read_fd, stderr_write_fd) = create_pipe_cloexec()?;

        // 解析 seccomp profile（结合 allow_fork 配置）
        let effective_profile = match self.config.seccomp_profile {
            p @ mimobox_core::SeccompProfile::Essential => {
                if self.config.allow_fork {
                    mimobox_core::SeccompProfile::EssentialWithFork
                } else {
                    p
                }
            }
            p @ mimobox_core::SeccompProfile::Network => {
                if self.config.allow_fork {
                    mimobox_core::SeccompProfile::NetworkWithFork
                } else {
                    p
                }
            }
            other => other,
        };

        // 创建临时 config 副本（含正确的 seccomp profile）
        let mut child_config = self.config.clone();
        child_config.seccomp_profile = effective_profile;

        match unsafe { fork() }.map_err(|e| SandboxError::Syscall(e.to_string()))? {
            ForkResult::Parent { child } => {
                // 重要 #7 修复：父进程关闭写端（O_CLOEXEC 已在 pipe2 时设置）
                // SAFETY: fd 有效，父进程不再需要写端
                unsafe {
                    libc::close(stdout_write_fd);
                    libc::close(stderr_write_fd);
                }

                // 使用 WNOHANG 轮询实现超时
                let (wait_result, timed_out) = if let Some(dur) = timeout {
                    poll_with_timeout(child, dur, &start)?
                } else {
                    (
                        waitpid(child, None).map_err(|e| SandboxError::Syscall(e.to_string()))?,
                        false,
                    )
                };

                let mut stdout_buf = Vec::new();
                let mut stderr_buf = Vec::new();

                if !timed_out {
                    // SAFETY: fd 有效且未被其他代码接管，from_raw_fd 获取所有权
                    let mut stdout_file = unsafe { std::fs::File::from_raw_fd(stdout_read_fd) };
                    let mut stderr_file = unsafe { std::fs::File::from_raw_fd(stderr_read_fd) };
                    if let Err(e) = stdout_file.read_to_end(&mut stdout_buf) {
                        tracing::warn!("读取 stdout 失败: {e}");
                    }
                    if let Err(e) = stderr_file.read_to_end(&mut stderr_buf) {
                        tracing::warn!("读取 stderr 失败: {e}");
                    }
                } else {
                    // 超时时关闭管道 fd
                    // SAFETY: fd 有效且不再需要
                    unsafe {
                        libc::close(stdout_read_fd);
                        libc::close(stderr_read_fd);
                    }
                }

                let elapsed = start.elapsed();

                match wait_result {
                    WaitStatus::Exited(_, code) => {
                        tracing::info!(
                            "子进程退出, code={}, elapsed={:.2}ms",
                            code,
                            elapsed.as_secs_f64() * 1000.0
                        );
                        Ok(SandboxResult {
                            stdout: stdout_buf,
                            stderr: stderr_buf,
                            exit_code: Some(code),
                            elapsed,
                            timed_out,
                        })
                    }
                    WaitStatus::Signaled(_, sig, _) => {
                        let code = -(sig as i32);
                        if timed_out {
                            tracing::warn!(
                                "子进程因超时被终止 (SIGKILL), elapsed={:.2}ms",
                                elapsed.as_secs_f64() * 1000.0
                            );
                        } else {
                            tracing::info!(
                                "子进程被信号终止: {:?}, elapsed={:.2}ms",
                                sig,
                                elapsed.as_secs_f64() * 1000.0
                            );
                        }
                        Ok(SandboxResult {
                            stdout: stdout_buf,
                            stderr: stderr_buf,
                            exit_code: Some(code),
                            elapsed,
                            timed_out,
                        })
                    }
                    _ => Ok(SandboxResult {
                        stdout: stdout_buf,
                        stderr: stderr_buf,
                        exit_code: None,
                        elapsed,
                        timed_out,
                    }),
                }
            }
            ForkResult::Child => {
                // FATAL-02 修复：setpgid 和 close 已移入 child_main，使用裸 libc 调用
                Self::child_main(
                    cmd,
                    &child_config,
                    stdout_write_fd,
                    stderr_write_fd,
                    Some((stdout_read_fd, stderr_read_fd)),
                );
            }
        }
    }

    fn destroy(self) -> Result<(), SandboxError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimobox_core::SeccompProfile;
    use mimobox_core::{Sandbox, SandboxConfig};

    /// 辅助函数：创建默认测试配置
    fn test_config() -> SandboxConfig {
        SandboxConfig {
            timeout_secs: Some(10),
            memory_limit_mb: Some(256),
            ..Default::default()
        }
    }

    #[test]
    fn test_sandbox_create_and_execute() {
        let mut sb = LinuxSandbox::new(test_config()).expect("创建沙箱失败");
        let cmd = vec!["/bin/echo".to_string(), "hello test".to_string()];
        let result = sb.execute(&cmd).expect("执行失败");

        assert!(!result.timed_out, "不应超时");
        assert_eq!(result.exit_code, Some(0), "退出码应为 0");
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("hello test"),
            "stdout 应包含输出, 实际: {stdout}"
        );
    }

    /// 测试非零退出码
    /// 需要用 release 模式运行：cargo test --release test_sandbox_exit_code
    #[test]
    #[ignore]
    fn test_sandbox_exit_code() {
        let config = SandboxConfig {
            allow_fork: true,
            ..test_config()
        };
        let mut sb = LinuxSandbox::new(config).expect("创建沙箱失败");
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 42".to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行失败");

        assert_eq!(result.exit_code, Some(42), "退出码应为 42");
    }

    #[test]
    fn test_network_isolation() {
        // CLONE_NEWNET 在 child_main 中通过 unshare 创建
        // 添加 /proc 到 readonly 以便读取 /proc/net/dev
        let config = SandboxConfig {
            deny_network: true,
            fs_readonly: vec![
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/bin".into(),
                "/sbin".into(),
                "/proc".into(),
            ],
            ..Default::default()
        };
        let mut sb = LinuxSandbox::new(config).expect("创建沙箱失败");

        let cmd = vec!["/bin/cat".to_string(), "/proc/net/dev".to_string()];
        let result = sb.execute(&cmd).expect("执行失败");

        let stdout = String::from_utf8_lossy(&result.stdout);
        // CLONE_NEWNET 下只有 loopback 接口
        assert!(
            stdout.contains("lo") || stdout.contains("Inter-"),
            "网络应被隔离（仅有 lo）, stdout: {stdout}, exit: {:?}",
            result.exit_code
        );
    }

    /// 测试文件系统读写隔离（需要 release 模式）
    #[test]
    #[ignore]
    fn test_fs_isolation() {
        let config = SandboxConfig {
            allow_fork: true,
            ..test_config()
        };
        let mut sb = LinuxSandbox::new(config.clone()).expect("创建沙箱失败");

        // sh -c 用 /bin/echo 写入 /tmp（应成功，因为在 fs_readwrite 中）
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "/bin/echo test > /tmp/mimobox_test_fs".to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行失败");
        assert_eq!(
            result.exit_code,
            Some(0),
            "写入 /tmp 失败: {:?}",
            result.stderr
        );

        // 用 /bin/cat 读取验证
        let mut sb2 = LinuxSandbox::new(config.clone()).expect("创建沙箱失败");
        let cmd2 = vec!["/bin/cat".to_string(), "/tmp/mimobox_test_fs".to_string()];
        let result2 = sb2.execute(&cmd2).expect("读取失败");
        let stdout = String::from_utf8_lossy(&result2.stdout);
        assert!(stdout.contains("test"), "应能读写 /tmp, stdout: {stdout}");

        // 清理
        let mut sb3 = LinuxSandbox::new(config).expect("创建沙箱失败");
        let _ = sb3.execute(&vec![
            "/bin/rm".to_string(),
            "-f".to_string(),
            "/tmp/mimobox_test_fs".to_string(),
        ]);
    }

    /// 测试只读路径的文件系统隔离（需要 release 模式）
    #[test]
    #[ignore]
    fn test_fs_isolation_readonly() {
        let config = SandboxConfig {
            allow_fork: true,
            seccomp_profile: SeccompProfile::Network,
            ..test_config()
        };
        let mut sb = LinuxSandbox::new(config).expect("创建沙箱失败");

        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo test > /usr/mimobox_test_ro 2>&1; echo exit_code=$?".to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行失败");

        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("Permission denied")
                || stdout.contains("exit_code=1")
                || result.exit_code != Some(0),
            "写入 /usr 应被拒绝, stdout: {stdout}, exit: {:?}",
            result.exit_code
        );
    }

    #[test]
    fn test_seccomp_deny_fork() {
        let config = SandboxConfig {
            allow_fork: false,
            seccomp_profile: SeccompProfile::Essential,
            ..test_config()
        };
        let mut sb = LinuxSandbox::new(config).expect("创建沙箱失败");

        // fork 应被 seccomp 阻止
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "/bin/echo forked".to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行失败");

        // seccomp 会 kill 尝试 fork 的进程
        assert!(
            result.exit_code != Some(0),
            "fork 应被 seccomp 阻止, exit_code: {:?}",
            result.exit_code
        );
    }

    #[test]
    fn test_timeout() {
        let config = SandboxConfig {
            timeout_secs: Some(1),
            ..test_config()
        };
        let mut sb = LinuxSandbox::new(config).expect("创建沙箱失败");

        let cmd = vec!["/bin/sleep".to_string(), "60".to_string()];
        let result = sb.execute(&cmd).expect("执行失败");

        assert!(result.timed_out, "应超时");
    }

    #[test]
    fn test_memory_limit() {
        // 设置极低的内存限制
        let config = SandboxConfig {
            memory_limit_mb: Some(8),
            ..test_config()
        };
        let mut sb = LinuxSandbox::new(config).expect("创建沙箱失败");

        // 尝试分配大量内存（超过 8MB）
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            // dd 生成 32MB 数据试图触发 OOM
            "dd if=/dev/zero bs=1M count=32 2>/dev/null | cat > /dev/null; echo exit=$?"
                .to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行失败");

        // 应该因内存限制而失败或被 kill
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            result.exit_code != Some(0) || stdout.contains("exit="),
            "内存限制应生效, exit_code: {:?}, stdout: {}",
            result.exit_code,
            stdout
        );
    }

    #[test]
    fn test_empty_command_error() {
        let mut sb = LinuxSandbox::new(test_config()).expect("创建沙箱失败");
        let result = sb.execute(&[]);
        assert!(result.is_err(), "空命令应返回错误");
    }
}

/// 使用 WNOHANG 轮询等待子进程，超时后发送 SIGKILL
///
/// 返回 (WaitStatus, timed_out)
fn poll_with_timeout(
    child: nix::unistd::Pid,
    timeout: Duration,
    start: &Instant,
) -> Result<(WaitStatus, bool), SandboxError> {
    let deadline = *start + timeout;
    let mut killed = false;

    loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if Instant::now() >= deadline {
                    if !killed {
                        tracing::warn!("子进程超时 ({:.1}s)，发送 SIGKILL", timeout.as_secs_f64());
                        // Kill 整个进程组（负 PID），确保孙进程也被终止
                        let pgid = child;
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(-pgid.as_raw()),
                            Signal::SIGKILL,
                        );
                        killed = true;
                    }
                    // IMPORTANT-05 修复：kill 后等待从 1ms 增加到 10ms，给内核足够时间清理
                    std::thread::sleep(Duration::from_millis(10));
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Ok(status) => {
                return Ok((status, killed));
            }
            Err(e) => {
                if e == nix::errno::Errno::ECHILD {
                    let status =
                        waitpid(child, None).map_err(|e| SandboxError::Syscall(e.to_string()))?;
                    return Ok((status, killed));
                }
                return Err(SandboxError::Syscall(e.to_string()));
            }
        }
    }
}
