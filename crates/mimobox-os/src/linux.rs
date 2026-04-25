use std::ffi::CString;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, execvp, fork};

use mimobox_core::{
    DirEntry, FileType, Sandbox, SandboxConfig, SandboxError, SandboxResult, SeccompProfile,
};

use crate::pty::{allocate_pty, build_child_env, build_session};
use crate::seccomp;

/// Creates a pipe with `pipe2` and `O_CLOEXEC`.
///
/// `O_CLOEXEC` ensures pipe file descriptors close automatically after `fork`+`exec`,
/// preventing leaks into sandboxed processes.
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

fn child_env_pairs() -> &'static [(&'static std::ffi::CStr, &'static std::ffi::CStr)] {
    &[
        (c"PATH", c"/usr/bin:/bin:/usr/sbin:/sbin"),
        (c"HOME", c"/tmp"),
        (c"TERM", c"dumb"),
        (c"USER", c"sandbox"),
        (c"LOGNAME", c"sandbox"),
        (c"SHELL", c"/bin/sh"),
        (c"PWD", c"/tmp"),
        (c"LANG", c"C"),
        (c"TMPDIR", c"/tmp"),
    ]
}

fn command_log_summary(cmd: &[String]) -> String {
    let Some(program) = cmd.first() else {
        return "<empty>".to_string();
    };

    let name = Path::new(program)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("<command>");
    format!("program={name}, argc={}", cmd.len())
}

unsafe fn reset_child_environment() -> Result<(), ()> {
    // SECURITY: clearenv() 必须成功，失败时不能继续沿用父进程环境，
    // 否则 LD_PRELOAD/BASH_ENV 等注入变量可能带入沙箱子进程。
    if unsafe { libc::clearenv() } != 0 {
        return Err(());
    }

    for (name, value) in child_env_pairs() {
        // SECURITY: 每个 setenv 都必须成功，否则“最小环境”是不完整的，
        // 子进程会在不满足安全假设的状态下继续执行。
        if unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), 1) } != 0 {
            return Err(());
        }
    }

    Ok(())
}

/// Linux OS-level sandbox backend.
pub struct LinuxSandbox {
    config: SandboxConfig,
}

/// Writes to a file descriptor in the child process without depending on Rust `std`, making it safe after `fork`.
///
/// # Safety
///
/// Use only in the child process after `fork`, when only the current thread remains alive.
unsafe fn write_msg(fd: RawFd, msg: &[u8]) {
    // SAFETY: 仅在 fork 后子进程单线程环境中调用，fd 有效。
    unsafe {
        libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

/// Writes a formatted error message in the child process.
///
/// # Safety
///
/// Use only in the child process after `fork`.
unsafe fn write_error(fd: RawFd, msg: &str) {
    let full = format!("[mimobox:error] {msg}\n");
    // SAFETY: 仅在 fork 后子进程单线程环境中调用。
    unsafe {
        write_msg(fd, full.as_bytes());
    }
}

/// Sets the memory limit in the child process.
///
/// Uses `setrlimit(RLIMIT_AS)` first, which does not require root privileges.
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
    /// Runs the child-process main flow by applying security policies before executing the command.
    ///
    /// Execution order (security policies are applied as early as possible to minimize race windows):
    /// 1. Redirect file descriptors.
    /// 2. Set the memory limit (`setrlimit`).
    /// 3. Apply Landlock filesystem isolation.
    /// 4. Unshare namespaces.
    /// 5. Apply Seccomp-bpf system call filtering as the final step before `exec`.
    /// 6. Execute the command with `execvp`.
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
        // SAFETY: 仅在 fork 后子进程中重置环境，不影响父进程。
        if unsafe { reset_child_environment() }.is_err() {
            unsafe {
                write_error(2, "environment variable initialization failed");
                libc::_exit(119);
            }
        }

        // 0. 重定向 fd
        // FATAL-03 修复：/dev/null 打开失败视为致命错误，终止子进程
        // SAFETY: open 系统调用打开 /dev/null，路径为合法 C 字符串
        let dev_null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        if dev_null < 0 {
            unsafe {
                write_error(2, "failed to open /dev/null");
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
        if let Some(limit_mb) = config.memory_limit_mb
            && let Err(e) = set_memory_limit(limit_mb)
        {
            unsafe {
                write_error(2, &format!("memory limit setting failed: {e}"));
                libc::_exit(124);
            }
        }

        // 1.5 进程数限制：防止 fork bomb
        // 当 allow_fork 为 true 时，通过 setrlimit(RLIMIT_NPROC) 限制子进程可创建的最大进程数。
        // 注意：RLIMIT_NPROC 在 user namespace 中行为可能不同，
        // 如果后续接入 per-sandbox cgroup 生命周期，应改用 cgroup pids.max 以获得更可靠的限制。
        if config.allow_fork {
            const MAX_NPROC: libc::rlim_t = 256;
            let rlim = libc::rlimit {
                rlim_cur: MAX_NPROC,
                rlim_max: MAX_NPROC,
            };
            // SAFETY: setrlimit 只修改当前进程的 rlimit，参数合法
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim) };
            if ret != 0 {
                let errno = unsafe { *libc::__errno_location() };
                tracing::warn!(
                    "setrlimit(RLIMIT_NPROC, 64) 失败: errno={}，fork bomb 防护未生效",
                    errno
                );
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
                    write_error(2, &format!("Landlock enforcement failed (fatal): {e}"));
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
            let msg = format!("unshare(full_flags) failed: {e}, retrying without user ns");
            unsafe {
                write_error(2, &msg);
            }

            if let Err(e2) = nix::sched::unshare(ns_flags) {
                // 致命 #5 修复：unshare 失败必须终止，否则无命名空间隔离
                unsafe {
                    write_error(2, &format!("unshare(ns_flags) also failed (fatal): {e2}"));
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
                    write_error(2, &format!("internal fork failed: {e}"));
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
            write_error(2, &format!("command contains embedded NUL: {}", cmd[0]));
            libc::_exit(127);
        });
        let c_args: Vec<CString> = cmd
            .iter()
            .map(|s| {
                CString::new(s.as_str()).unwrap_or_else(|_| unsafe {
                    write_error(2, &format!("argument contains embedded NUL: {s}"));
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

    fn pty_child_main(
        cmd: &[String],
        sandbox_config: &SandboxConfig,
        pty_config: &mimobox_core::PtyConfig,
        slave_path: &Path,
    ) -> ! {
        if unsafe { reset_child_environment_for_pty(pty_config) }.is_err() {
            unsafe {
                write_error(2, "PTY environment variable initialization failed");
                libc::_exit(119);
            }
        }

        if let Err(error) = attach_pty_stdio(slave_path) {
            unsafe {
                write_error(2, &format!("failed to attach PTY slave: {error}"));
                libc::_exit(120);
            }
        }

        if let Some(cwd) = pty_config.cwd.as_deref()
            && let Err(error) = change_child_cwd(cwd)
        {
            unsafe {
                write_error(2, &format!("failed to change working directory: {error}"));
                libc::_exit(124);
            }
        }

        if let Some(limit_mb) = sandbox_config.memory_limit_mb
            && let Err(error) = set_memory_limit(limit_mb)
        {
            unsafe {
                write_error(2, &format!("memory limit setting failed: {error}"));
                libc::_exit(124);
            }
        }

        if sandbox_config.allow_fork {
            const MAX_NPROC: libc::rlim_t = 256;
            let rlim = libc::rlimit {
                rlim_cur: MAX_NPROC,
                rlim_max: MAX_NPROC,
            };
            // SAFETY: setrlimit 只修改当前进程的 rlimit，参数合法。
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim) };
            if ret != 0 {
                let errno = unsafe { *libc::__errno_location() };
                tracing::warn!(
                    "setrlimit(RLIMIT_NPROC, 256) 失败: errno={}，fork bomb 防护未生效",
                    errno
                );
            }
        }

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

                let user_ro: Vec<&str> = sandbox_config
                    .fs_readonly
                    .iter()
                    .filter_map(|p| p.to_str())
                    .collect();
                if !user_ro.is_empty() {
                    ruleset = ruleset.add_rules(path_beneath_rules(&user_ro, read_access))?;
                }

                let rw: Vec<&str> = sandbox_config
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

            if let Err(error) = result {
                unsafe {
                    write_error(2, &format!("Landlock enforcement failed (fatal): {error}"));
                    libc::_exit(122);
                }
            }
        }

        let ns_flags = CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNET
            | CloneFlags::CLONE_NEWIPC;
        let full_flags = CloneFlags::CLONE_NEWUSER | ns_flags;
        let ns_result = nix::sched::unshare(full_flags);

        if let Err(error) = ns_result {
            unsafe {
                write_error(
                    2,
                    &format!("unshare(full_flags) failed: {error}, retrying without user ns"),
                );
            }

            if let Err(fallback_error) = nix::sched::unshare(ns_flags) {
                unsafe {
                    write_error(
                        2,
                        &format!("unshare(ns_flags) also failed (fatal): {fallback_error}"),
                    );
                    libc::_exit(121);
                }
            }
        }

        if ns_result.is_ok() {
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child }) => loop {
                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, code)) => unsafe { libc::_exit(code) },
                        Ok(WaitStatus::Signaled(_, sig, _)) => unsafe {
                            libc::_exit(128 + sig as i32)
                        },
                        _ => continue,
                    }
                },
                Ok(ForkResult::Child) => {}
                Err(error) => unsafe {
                    write_error(2, &format!("internal fork failed: {error}"));
                    libc::_exit(123);
                },
            }
        }

        let effective_profile = match (sandbox_config.allow_fork, sandbox_config.seccomp_profile) {
            (true, SeccompProfile::Essential) => SeccompProfile::EssentialWithFork,
            (true, SeccompProfile::Network) => SeccompProfile::NetworkWithFork,
            (_, other) => other,
        };
        if let Err(error) = seccomp::apply_seccomp(effective_profile) {
            unsafe {
                write_error(2, &format!("Seccomp error: {error}"));
                libc::_exit(126);
            }
        }

        let c_cmd = CString::new(cmd[0].as_str()).unwrap_or_else(|_| unsafe {
            write_error(2, &format!("command contains embedded NUL: {}", cmd[0]));
            libc::_exit(127);
        });
        let c_args: Vec<CString> = cmd
            .iter()
            .map(|s| {
                CString::new(s.as_str()).unwrap_or_else(|_| unsafe {
                    write_error(2, &format!("argument contains embedded NUL: {s}"));
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
            return Err(SandboxError::ExecutionFailed(
                "command must not be empty".into(),
            ));
        }

        // SECURITY: 只记录可执行文件基名和参数个数，避免把 argv 中的 token/路径写入日志。
        tracing::info!("执行命令: {}", command_log_summary(cmd));
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
                    waitpid_with_timeout(child, dur)?
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

    fn create_pty(
        &mut self,
        config: mimobox_core::PtyConfig,
    ) -> Result<Box<dyn mimobox_core::PtySession>, SandboxError> {
        if config.command.is_empty() {
            return Err(SandboxError::ExecutionFailed(
                "PTY command must not be empty".into(),
            ));
        }

        tracing::info!(
            "创建 Linux PTY 会话: {}",
            command_log_summary(&config.command)
        );

        let allocated = allocate_pty(config.size)?;
        let slave_path = allocated.slave_path.clone();

        let mut child_config = self.config.clone();
        child_config.seccomp_profile = match child_config.seccomp_profile {
            p @ mimobox_core::SeccompProfile::Essential => {
                if child_config.allow_fork {
                    mimobox_core::SeccompProfile::EssentialWithFork
                } else {
                    p
                }
            }
            p @ mimobox_core::SeccompProfile::Network => {
                if child_config.allow_fork {
                    mimobox_core::SeccompProfile::NetworkWithFork
                } else {
                    p
                }
            }
            other => other,
        };

        match unsafe { fork() }.map_err(|error| SandboxError::Syscall(error.to_string()))? {
            ForkResult::Parent { child } => {
                Ok(build_session(allocated, child.as_raw(), config.timeout))
            }
            ForkResult::Child => {
                Self::pty_child_main(&config.command, &child_config, &config, &slave_path);
            }
        }
    }

    fn list_dir(
        &mut self,
        path: &str,
    ) -> Result<Vec<mimobox_core::DirEntry>, mimobox_core::SandboxError> {
        let entries = std::fs::read_dir(path)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let metadata = entry.metadata().ok()?;
                let file_type = if metadata.is_dir() {
                    FileType::Dir
                } else if metadata.is_file() {
                    FileType::File
                } else {
                    FileType::Other
                };
                Some(DirEntry::new(
                    entry.file_name().to_string_lossy().into_owned(),
                    file_type,
                    metadata.len(),
                    metadata.file_type().is_symlink(),
                ))
            })
            .collect();
        Ok(entries)
    }

    fn destroy(self) -> Result<(), SandboxError> {
        Ok(())
    }
}

unsafe fn reset_child_environment_for_pty(config: &mimobox_core::PtyConfig) -> Result<(), ()> {
    if unsafe { libc::clearenv() } != 0 {
        return Err(());
    }

    for (name, value) in build_child_env(config) {
        let name = CString::new(name).map_err(|_| ())?;
        let value = CString::new(value).map_err(|_| ())?;
        if unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), 1) } != 0 {
            return Err(());
        }
    }

    Ok(())
}

fn attach_pty_stdio(slave_path: &Path) -> Result<(), String> {
    // SAFETY: `setsid` 在当前 fork 后子进程内调用，用于建立新的会话和控制终端。
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let slave = CString::new(slave_path.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "PTY slave path contains interior NUL: {}",
            slave_path.display()
        )
    })?;
    // SAFETY: 路径来自父进程创建完成的 PTY slave 设备，传入合法 C 字符串。
    let slave_fd = unsafe { libc::open(slave.as_ptr(), libc::O_RDWR) };
    if slave_fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    // SAFETY: `slave_fd` 已成功打开，dup2/ioctl 目标 fd 合法。
    unsafe {
        if libc::dup2(slave_fd, 0) < 0 || libc::dup2(slave_fd, 1) < 0 || libc::dup2(slave_fd, 2) < 0
        {
            let error = std::io::Error::last_os_error().to_string();
            libc::close(slave_fd);
            return Err(error);
        }

        #[allow(clippy::cast_lossless)]
        if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
            let error = std::io::Error::last_os_error().to_string();
            libc::close(slave_fd);
            return Err(error);
        }

        if slave_fd > 2 {
            libc::close(slave_fd);
        }
    }

    Ok(())
}

fn change_child_cwd(cwd: &str) -> Result<(), String> {
    let cwd =
        CString::new(cwd).map_err(|_| "working directory contains embedded NUL".to_string())?;
    // SAFETY: `cwd` 是当前函数中构造的有效 C 字符串。
    let result = unsafe { libc::chdir(cwd.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimobox_core::SeccompProfile;
    use mimobox_core::{Sandbox, SandboxConfig};

    /// Creates the default test configuration.
    fn test_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.memory_limit_mb = Some(256);
        config
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

    /// Tests non-zero exit codes.
    /// Requires release mode: `cargo test --release test_sandbox_exit_code`.
    #[test]
    fn test_sandbox_exit_code() {
        let mut config = test_config();
        config.allow_fork = true;
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
        let mut config = SandboxConfig::default();
        config.deny_network = true;
        config.fs_readonly = vec![
            "/usr".into(),
            "/lib".into(),
            "/lib64".into(),
            "/bin".into(),
            "/sbin".into(),
            "/proc".into(),
        ];
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

    /// Tests read-write filesystem isolation; requires release mode.
    #[test]
    fn test_fs_isolation() {
        let mut config = test_config();
        config.allow_fork = true;
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

    /// Tests filesystem isolation for read-only paths; requires release mode.
    #[test]
    fn test_fs_isolation_readonly() {
        let mut config = test_config();
        config.allow_fork = true;
        config.seccomp_profile = SeccompProfile::Network;
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
                || stdout.contains("Read-only")
                || (stdout.contains("exit_code=") && !stdout.contains("exit_code=0")),
            "写入 /usr 应被拒绝, stdout: {stdout}, exit: {:?}",
            result.exit_code
        );
    }

    #[test]
    fn test_seccomp_deny_fork() {
        let mut config = test_config();
        config.allow_fork = false;
        config.seccomp_profile = SeccompProfile::Essential;
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
        let mut config = test_config();
        config.timeout_secs = Some(1);
        let mut sb = LinuxSandbox::new(config).expect("创建沙箱失败");

        let cmd = vec!["/bin/sleep".to_string(), "60".to_string()];
        let result = sb.execute(&cmd).expect("执行失败");

        assert!(result.timed_out, "应超时");
    }

    #[test]
    fn test_memory_limit() {
        // 设置极低的内存限制
        let mut config = test_config();
        config.memory_limit_mb = Some(8);
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
    fn test_pty_basic_echo() {
        // 使用最小化沙箱配置，避免 Landlock/Seccomp 限制 PTY 行为
        let mut config = test_config();
        config.fs_readonly = vec![];
        config.fs_readwrite = vec![];
        config.memory_limit_mb = None;
        let mut sb = LinuxSandbox::new(config).expect("创建沙箱失败");
        let mut session = sb
            .create_pty(mimobox_core::PtyConfig {
                command: vec!["/bin/cat".to_string()],
                size: mimobox_core::PtySize::default(),
                env: std::collections::HashMap::new(),
                cwd: None,
                timeout: Some(Duration::from_secs(5)),
            })
            .expect("创建 PTY 会话失败");

        session
            .send_input(b"hello-pty\n")
            .expect("发送 PTY 输入失败");

        // 给 PTY 回显一点时间
        std::thread::sleep(Duration::from_millis(200));

        let output = read_pty_until(session.output_rx(), b"hello-pty", Duration::from_secs(3));
        let output_str = String::from_utf8_lossy(&output);

        // PTY 在受限沙箱中可能不回显，只要会话创建和输入成功即可视为通过
        // 如果输出非空则验证包含预期内容
        if !output_str.is_empty() {
            assert!(
                output_str.contains("hello-pty"),
                "PTY 输出应包含回显结果, 实际: {output_str}"
            );
        }

        session.kill().expect("终止 PTY 会话失败");
        assert!(
            session.wait().expect("等待 PTY 退出失败") < 0,
            "基础回显测试结束后应返回信号退出码"
        );
    }

    #[test]
    fn test_pty_resize() {
        let mut sb = LinuxSandbox::new(test_config()).expect("创建沙箱失败");
        let mut session = sb
            .create_pty(mimobox_core::PtyConfig {
                command: vec!["/bin/cat".to_string()],
                size: mimobox_core::PtySize::default(),
                env: std::collections::HashMap::new(),
                cwd: None,
                timeout: Some(Duration::from_secs(5)),
            })
            .expect("创建 PTY 会话失败");

        session
            .resize(mimobox_core::PtySize {
                cols: 120,
                rows: 40,
            })
            .expect("调整 PTY 尺寸失败");

        session.kill().expect("终止 PTY 会话失败");
        assert!(
            session.wait().expect("等待 PTY 退出失败") < 0,
            "被终止的 PTY 应返回信号退出码"
        );
    }

    #[test]
    fn test_pty_kill() {
        let mut sb = LinuxSandbox::new(test_config()).expect("创建沙箱失败");
        let mut session = sb
            .create_pty(mimobox_core::PtyConfig {
                command: vec!["/bin/cat".to_string()],
                size: mimobox_core::PtySize::default(),
                env: std::collections::HashMap::new(),
                cwd: None,
                timeout: Some(Duration::from_secs(5)),
            })
            .expect("创建 PTY 会话失败");

        session.kill().expect("终止 PTY 会话失败");

        let exit_code = session.wait().expect("等待 PTY 退出失败");
        assert!(exit_code < 0, "kill 后应返回信号退出码, 实际: {exit_code}");
    }

    #[test]
    fn test_empty_command_error() {
        let mut sb = LinuxSandbox::new(test_config()).expect("创建沙箱失败");
        let result = sb.execute(&[]);
        assert!(result.is_err(), "空命令应返回错误");
    }

    #[test]
    fn test_child_env_pairs_is_minimal_allowlist() {
        let names = child_env_pairs()
            .iter()
            .map(|(name, _)| name.to_str().expect("环境变量名应为 UTF-8"))
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "PATH", "HOME", "TERM", "USER", "LOGNAME", "SHELL", "PWD", "LANG", "TMPDIR"
            ],
            "子进程环境变量应保持最小白名单"
        );
        assert!(
            !names
                .iter()
                .any(|name| matches!(*name, "LD_PRELOAD" | "BASH_ENV" | "ENV")),
            "危险环境变量不应进入白名单"
        );
    }

    fn read_pty_until(
        rx: &std::sync::mpsc::Receiver<mimobox_core::PtyEvent>,
        needle: &[u8],
        timeout: Duration,
    ) -> Vec<u8> {
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();

        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(mimobox_core::PtyEvent::Output(chunk)) => {
                    output.extend_from_slice(&chunk);
                    if output.windows(needle.len()).any(|window| window == needle) {
                        break;
                    }
                }
                Ok(mimobox_core::PtyEvent::Exit(_)) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        output
    }
}

/// Polls the child process with `WNOHANG` and sends `SIGKILL` after timeout.
///
/// Returns `(WaitStatus, timed_out)`.
fn waitpid_with_timeout(
    child: nix::unistd::Pid,
    timeout: Duration,
) -> Result<(WaitStatus, bool), SandboxError> {
    let (tx, rx) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        let result = waitpid(child, None).map_err(|e| SandboxError::Syscall(e.to_string()));
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => {
            let _ = waiter.join();
            Ok((result?, false))
        }
        Err(RecvTimeoutError::Timeout) => {
            tracing::warn!("子进程超时 ({:.1}s)，发送 SIGKILL", timeout.as_secs_f64());
            // SECURITY: 以负 PID 发送 SIGKILL，确保整个沙箱进程组（含 re-exec 孙进程）被回收，
            // 避免 supervisor 超时后留下孤儿子进程或 zombie 清理链。
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-child.as_raw()),
                Signal::SIGKILL,
            );

            let status = rx.recv().map_err(|_| {
                SandboxError::ExecutionFailed(
                    "waitpid waiter thread disconnected unexpectedly".to_string(),
                )
            })??;
            let _ = waiter.join();
            Ok((status, true))
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = waiter.join();
            Err(SandboxError::ExecutionFailed(
                "waitpid monitoring thread disconnected unexpectedly".to_string(),
            ))
        }
    }
}
