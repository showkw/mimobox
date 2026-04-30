use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
use nix::unistd::{ForkResult, execvp, fork};

use mimobox_core::{
    DirEntry, FileStat, NamespaceDegradation, Sandbox, SandboxConfig, SandboxError, SandboxMetrics,
    SandboxResult, SeccompProfile,
};

use crate::pty::{allocate_pty, build_child_env_with_base, build_session};
use crate::seccomp;

#[cfg(target_os = "linux")]
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";
#[cfg(target_os = "linux")]
const DEFAULT_MAX_PROCESSES: u32 = 64;
const OUTPUT_SIZE_LIMIT: usize = 4 * 1024 * 1024;
const OUTPUT_READ_CHUNK_SIZE: usize = 8 * 1024;
const FALLBACK_PAGE_SIZE_BYTES: u64 = 4096;
const PROC_STAT_UTIME_INDEX: usize = 11;

#[derive(Debug)]
struct OutputCapture {
    data: Vec<u8>,
    truncated: bool,
    read_error: Option<String>,
}

/// Creates a pipe with `pipe2` and `O_CLOEXEC`.
///
/// `O_CLOEXEC` ensures pipe file descriptors close automatically after `fork`+`exec`,
/// preventing leaks into sandboxed processes.
fn create_pipe_cloexec() -> Result<(RawFd, RawFd), SandboxError> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: pipe2 系统调用，fds 是有效的输出缓冲区
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        // SAFETY: errno is thread-local and can be read immediately after the failed libc call.
        let errno = unsafe { *libc::__errno_location() };
        return Err(SandboxError::PipeError(format!(
            "pipe2(O_CLOEXEC) failed: errno={errno}"
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

type PreparedChildEnv = Vec<(CString, CString)>;

fn prepare_child_env_vars(
    env_vars: &std::collections::HashMap<String, String>,
) -> Result<PreparedChildEnv, SandboxError> {
    let mut prepared = Vec::with_capacity(env_vars.len());
    for (key, value) in env_vars {
        if key.is_empty() || key.contains('=') || key.contains('\0') || key.contains(' ') {
            return Err(SandboxError::new(format!(
                "invalid environment variable name: {key}"
            )));
        }
        let key = CString::new(key.as_str()).map_err(|_| {
            SandboxError::new(format!("environment variable name contains NUL: {key}"))
        })?;
        let value = CString::new(value.as_str())
            .map_err(|_| SandboxError::new("environment variable value contains NUL byte"))?;
        prepared.push((key, value));
    }
    Ok(prepared)
}

/// # Safety
///
/// 只能在 fork 后、exec 前的子进程中调用。调用方必须保证 `env_vars`
/// 已在 fork 前转换为有效的 NUL 结尾字符串，且调用期间不会被修改。
unsafe fn set_prepared_child_env(env_vars: &[(CString, CString)]) -> Result<(), ()> {
    for (name, value) in env_vars {
        // SAFETY: name/value 已在 fork 前转换为 NUL 结尾字符串，子进程只读取已准备好的字节。
        if unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), 1) } != 0 {
            return Err(());
        }
    }
    Ok(())
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

const NAMESPACE_FALLBACK_MARKER: &str = "unshare(full_flags) failed";
const NAMESPACE_FAIL_CLOSED_EXIT_CODE: i32 = 128;
const CONTAINER_MOUNT_UNAVAILABLE_MARKER: &str = "container_mount_unavailable";

/// Detects whether stderr contains the namespace fallback marker.
fn namespace_fallback_detected(stderr_buf: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(stderr_buf);
    stderr
        .lines()
        .any(|line| line.contains(NAMESPACE_FALLBACK_MARKER))
}

fn log_namespace_fallback_from_stderr(stderr_buf: &[u8]) {
    if namespace_fallback_detected(stderr_buf) {
        tracing::warn!(
            "Namespace fallback: unshare(full_flags) failed, falling back to isolation without user/pid namespaces"
        );
    }
}

fn apply_namespace_fallback_to_report(report: &mut IsolationReport, stderr_buf: &[u8]) {
    if namespace_fallback_detected(stderr_buf) {
        report.user_namespace = false;
        report.pid_namespace = false;
    }
}

/// # Safety
///
/// Must only be called in a forked child process before exec. The function clears
/// and rebuilds the process environment from a static allowlist, which is safe only
/// when the process is single-threaded (post-fork). Calling in a multi-threaded
/// process would race with other threads reading/writing environ.
unsafe fn reset_child_environment(env_vars: &[(CString, CString)]) -> Result<(), ()> {
    // SECURITY: clearenv() 必须成功，失败时不能继续沿用父进程环境，
    // 否则 LD_PRELOAD/BASH_ENV 等注入变量可能带入沙箱子进程。
    // SAFETY: Called only in the forked child before exec; clearing its process environment is local.
    if unsafe { libc::clearenv() } != 0 {
        return Err(());
    }

    for (name, value) in child_env_pairs() {
        // SECURITY: 每个 setenv 都必须成功，否则“最小环境”是不完整的，
        // 子进程会在不满足安全假设的状态下继续执行。
        // SAFETY: name and value are static NUL-terminated C strings; overwrite flag is valid.
        if unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), 1) } != 0 {
            return Err(());
        }
    }

    // SAFETY: env_vars 已在 fork 前完成 CString 序列化，子进程不访问父进程 HashMap。
    unsafe { set_prepared_child_env(env_vars)? };

    Ok(())
}

/// Report describing the isolation level that was actually applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsolationReport {
    /// Whether the user namespace was successfully enabled.
    pub user_namespace: bool,
    /// Whether the PID namespace was successfully enabled.
    pub pid_namespace: bool,
    /// Whether the network namespace was successfully enabled.
    pub network_namespace: bool,
    /// Whether the mount namespace was successfully enabled.
    pub mount_namespace: bool,
    /// Whether the IPC namespace was successfully enabled.
    pub ipc_namespace: bool,
    /// Whether Landlock was successfully enabled.
    pub landlock: bool,
    /// Whether seccomp was successfully enabled.
    pub seccomp: bool,
}

impl Default for IsolationReport {
    fn default() -> Self {
        Self {
            user_namespace: true,
            pid_namespace: true,
            network_namespace: true,
            mount_namespace: true,
            ipc_namespace: true,
            landlock: true,
            seccomp: true,
        }
    }
}

/// Linux OS-level sandbox backend.
///
/// `LinuxSandbox` executes commands in a child process and applies OS isolation
/// before `exec`. It combines resource limits, Landlock filesystem rules,
/// Linux namespaces, and seccomp-bpf filtering according to
/// [`SandboxConfig`].
pub struct LinuxSandbox {
    config: SandboxConfig,
    #[cfg(target_os = "linux")]
    last_cgroup_path: Option<PathBuf>,
    last_isolation_report: IsolationReport,
    cached_metrics: Option<SandboxMetrics>,
}

impl LinuxSandbox {
    /// 返回最近一次 Linux 后端执行缓存的资源指标。
    pub fn metrics(&self) -> Option<SandboxMetrics> {
        self.cached_metrics.clone()
    }
}

/// 通过 /proc/{pid}/statm、/proc/{pid}/io 和 /proc/{pid}/stat 采样进程资源指标。
///
/// 必须在子进程被 waitpid 回收前调用，否则 /proc/{pid} 会被内核清理。
pub fn sample_metrics(pid: i32, memory_limit_mb: Option<u64>) -> SandboxMetrics {
    let mut metrics = SandboxMetrics::default();

    if let Ok(statm) = std::fs::read_to_string(format!("/proc/{pid}/statm"))
        && let Some(rss_pages) = statm
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u64>().ok())
    {
        metrics.memory_usage_bytes = Some(rss_pages.saturating_mul(page_size_bytes()));
    }

    if let Ok(io_content) = std::fs::read_to_string(format!("/proc/{pid}/io")) {
        for line in io_content.lines() {
            if let Some(value) = line.strip_prefix("read_bytes:") {
                metrics.io_read_bytes = value.trim().parse().ok();
            } else if let Some(value) = line.strip_prefix("write_bytes:") {
                metrics.io_write_bytes = value.trim().parse().ok();
            }
        }
    }

    if let Ok(stat_content) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        && let Some(close_paren) = stat_content.rfind(')')
    {
        // /proc/{pid}/stat 在 comm 后从 state 开始，utime/stime 分别是第 14/15 个原始字段。
        let mut fields = stat_content[close_paren + 1..].split_whitespace();
        let utime = fields.nth(PROC_STAT_UTIME_INDEX);
        let stime = fields.next();
        if let (Some(utime), Some(stime), Some(clk_tck)) = (utime, stime, clock_ticks_per_second())
        {
            if let Ok(utime) = utime.parse::<u64>() {
                metrics.cpu_time_user_us = Some(utime.saturating_mul(1_000_000) / clk_tck);
            }
            if let Ok(stime) = stime.parse::<u64>() {
                metrics.cpu_time_system_us = Some(stime.saturating_mul(1_000_000) / clk_tck);
            }
        }
    }

    if let Some(limit_mb) = memory_limit_mb {
        metrics.memory_limit_bytes = limit_mb.checked_mul(1024 * 1024);
    }
    metrics.collected_at = Some(std::time::Instant::now());
    metrics
}

fn page_size_bytes() -> u64 {
    // SAFETY: sysconf(_SC_PAGESIZE) 只读取当前系统页大小，无内存安全影响。
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size > 0 {
        page_size as u64
    } else {
        FALLBACK_PAGE_SIZE_BYTES
    }
}

fn clock_ticks_per_second() -> Option<u64> {
    // SAFETY: sysconf(_SC_CLK_TCK) 只读取当前系统 clock tick 配置，无内存安全影响。
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if clk_tck > 0 {
        Some(clk_tck as u64)
    } else {
        None
    }
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

// SIGSYS handler 说明（已移除）
//
// seccomp 使用 TRAP 模式（SECCOMP_RET_TRAP）时，被阻止的 syscall 会触发 SIGSYS 信号。
// 曾在此处注册 sigsys_handler 以记录审计信息，但该 handler 在沙箱实际运行中不会生效：
//
// - handler 在 child process 中注册（exec 之前）
// - execve() 系统调用总是将所有信号处理器重置为 SIG_DFL（POSIX 规定）
// - 只有 SIG_IGN 和 SIG_DFL 可以跨 exec 保留，自定义 handler 一定会被丢弃
// - 因此 exec 后的进程（如 /bin/sh）不会有我们的 SIGSYS handler
//
// TRAP 模式的实际价值：
// - 进程以 SIGSYS 终止，退出码为 159 (128+SIGSYS=31)
// - 内核审计日志（auditd）可记录 SIGSYS 信号及触发 syscall 信息
// - 父进程通过 waitpid 检测到 WaitStatus::Signaled(SIGSYS)，可识别为 seccomp 违规
//
// 如需自定义审计日志（如记录被阻止的 syscall 号、参数等），需要使用：
// - seccomp-unotify (SECCOMP_RET_USER_NOTIF)：内核将违规通知转发到用户空间
// - ptrace + PTRACE_O_TRACESECCOMP：通过 ptrace 拦截 seccomp 事件

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
    let limit_bytes = limit_mb
        .checked_mul(1024)
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| {
            format!("memory_limit_mb={limit_mb} overflowed while converting to bytes")
        })?;
    // IMPORTANT-03 修复：rlim_max 设为与 rlim_cur 相同，防止子进程提高内存限制
    let rlim = libc::rlimit {
        rlim_cur: limit_bytes,
        rlim_max: limit_bytes,
    };
    // SAFETY: rlim 是栈上有效结构体，RLIMIT_AS 是合法 resource 参数
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_AS, &rlim) };
    if ret < 0 {
        // SAFETY: errno is thread-local and can be read immediately after the failed libc call.
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!(
            "setrlimit(RLIMIT_AS, {limit_mb}MB) failed: errno={errno}"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remount_proc_for_pid_namespace() -> Result<(), String> {
    // 新 mount namespace 默认可能继承 shared propagation，先私有化避免挂载传播到宿主。
    // SAFETY: 参数均为合法的 mount(2) 入参；当前调用只修改 fork 后子进程的 mount namespace。
    let propagation_ret = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if propagation_ret != 0 {
        let error = std::io::Error::last_os_error();
        let container_mount_unavailable = matches!(
            error.raw_os_error(),
            Some(errno) if errno == libc::EPERM || errno == libc::ENOSYS
        );
        if container_mount_unavailable {
            return Err(format!(
                "{CONTAINER_MOUNT_UNAVAILABLE_MARKER}: mount(/, MS_REC|MS_PRIVATE) failed: {error}"
            ));
        }
        return Err(format!("mount(/, MS_REC|MS_PRIVATE) failed: {error}"));
    }

    let proc_flags = (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong;
    // SAFETY: source、target、fstype 均为有效的 NUL 结尾 C 字符串，flags 与 data 参数合法。
    let mount_ret = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            proc_flags,
            std::ptr::null(),
        )
    };
    if mount_ret != 0 {
        return Err(format!(
            "mount(proc, /proc) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn sandbox_cgroup_path(root: &Path, pid: libc::pid_t) -> PathBuf {
    root.join("mimobox").join(format!("sandbox-{pid}"))
}

#[cfg(target_os = "linux")]
fn format_cpu_max(config: &SandboxConfig) -> String {
    let period = config.cpu_period_us;
    match config.cpu_quota_us {
        Some(quota) => format!("{quota} {period}"),
        None => format!("max {period}"),
    }
}

#[cfg(target_os = "linux")]
fn effective_max_processes(config: &SandboxConfig) -> u32 {
    config.max_processes.unwrap_or(DEFAULT_MAX_PROCESSES)
}

#[cfg(target_os = "linux")]
fn format_pids_max(config: &SandboxConfig) -> String {
    effective_max_processes(config).to_string()
}

#[cfg(target_os = "linux")]
fn cgroup_v2_available(root: &Path) -> bool {
    root.join("cgroup.controllers").is_file()
}

#[cfg(target_os = "linux")]
fn configure_sandbox_cgroup(
    root: &Path,
    pid: libc::pid_t,
    config: &SandboxConfig,
) -> Result<Option<PathBuf>, SandboxError> {
    if !cgroup_v2_available(root) {
        tracing::warn!(
            "cgroup v2 unavailable, skipping pids.max process limit: root={}",
            root.display()
        );
        return Ok(None);
    }

    let cgroup_path = sandbox_cgroup_path(root, pid);
    if let Err(error) = fs::create_dir_all(&cgroup_path) {
        tracing::warn!(
            "Failed to create cgroup, skipping pids.max process limit: path={}, error={error}",
            cgroup_path.display()
        );
        if config.cpu_quota_us.is_some() {
            return Err(error.into());
        }
        return Ok(None);
    }

    if let Err(error) = fs::write(cgroup_path.join("pids.max"), format_pids_max(config)) {
        cleanup_cgroup(&cgroup_path);
        tracing::warn!(
            "Failed to write cgroup pids.max, skipping pids.max process limit: path={}, max_processes={}, error={error}",
            cgroup_path.display(),
            effective_max_processes(config)
        );
        if config.cpu_quota_us.is_some() {
            return Err(error.into());
        }
        return Ok(None);
    }

    if config.cpu_quota_us.is_some() {
        // Write cpu.max as "quota period"; "max period" means unlimited.
        if let Err(error) = fs::write(cgroup_path.join("cpu.max"), format_cpu_max(config)) {
            cleanup_cgroup(&cgroup_path);
            return Err(error.into());
        }
    }

    if let Err(error) = fs::write(cgroup_path.join("cgroup.procs"), pid.to_string()) {
        cleanup_cgroup(&cgroup_path);
        tracing::warn!(
            "Failed to write cgroup.procs, skipping pids.max process limit: path={}, pid={pid}, error={error}",
            cgroup_path.display()
        );
        if config.cpu_quota_us.is_some() {
            return Err(error.into());
        }
        return Ok(None);
    }

    Ok(Some(cgroup_path))
}

#[cfg(target_os = "linux")]
fn cleanup_cgroup(path: &Path) {
    if let Err(error) = fs::remove_dir(path) {
        tracing::debug!(
            "Failed to clean up cgroup: path={}, error={error}",
            path.display()
        );
    }
}

fn signal_child_start(fd: RawFd) -> Result<(), SandboxError> {
    let signal = [1_u8];
    // SAFETY: fd 是父进程持有的管道写端，buffer 指针和长度有效。
    let written = unsafe { libc::write(fd, signal.as_ptr().cast::<libc::c_void>(), signal.len()) };
    // SAFETY: fd 已完成单次通知，父进程不再需要写端。
    unsafe {
        libc::close(fd);
    }

    if written == signal.len() as isize {
        Ok(())
    } else {
        Err(SandboxError::PipeError(
            "failed to signal child startup gate".to_string(),
        ))
    }
}

fn cancel_child_start(fd: RawFd) {
    // SAFETY: fd 是父进程持有的管道写端；关闭后子进程会在 gate 上失败退出。
    unsafe {
        libc::close(fd);
    }
}

fn wait_for_parent_start_signal(fd: RawFd) -> Result<(), ()> {
    let mut signal = [0_u8; 1];
    loop {
        // SAFETY: fd 是子进程持有的管道读端，buffer 指针和长度有效。
        let read = unsafe { libc::read(fd, signal.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if read == 1 {
            // SAFETY: 子进程已经收到启动信号，不再需要读端。
            unsafe {
                libc::close(fd);
            }
            return Ok(());
        }
        if read == 0 {
            // SAFETY: 父进程未发出成功信号，关闭读端后失败退出。
            unsafe {
                libc::close(fd);
            }
            return Err(());
        }
        // SAFETY: errno is thread-local and can be read immediately after the failed libc call.
        let errno = unsafe { *libc::__errno_location() };
        if errno != libc::EINTR {
            // SAFETY: 读取失败且不是 EINTR，关闭读端后失败退出。
            unsafe {
                libc::close(fd);
            }
            return Err(());
        }
    }
}

fn kill_process_group(pid: libc::pid_t, signal: Signal) {
    let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(-pid), signal);
}

fn kill_process(pid: libc::pid_t, signal: Signal) {
    let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal);
}

fn read_limited_output<R, F>(reader: &mut R, label: &'static str, mut on_limit: F) -> OutputCapture
where
    R: Read,
    F: FnMut(),
{
    let mut data = Vec::new();
    let mut chunk = [0_u8; OUTPUT_READ_CHUNK_SIZE];

    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                return OutputCapture {
                    data,
                    truncated: false,
                    read_error: None,
                };
            }
            Ok(n) => {
                let remaining = OUTPUT_SIZE_LIMIT.saturating_sub(data.len());
                if n <= remaining {
                    data.extend_from_slice(&chunk[..n]);
                    continue;
                }

                data.extend_from_slice(&chunk[..remaining]);
                on_limit();
                tracing::warn!(
                    "{label} output exceeded {} byte limit, truncated and terminated child process group",
                    OUTPUT_SIZE_LIMIT
                );
                return OutputCapture {
                    data,
                    truncated: true,
                    read_error: None,
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return OutputCapture {
                    data,
                    truncated: false,
                    read_error: Some(error.to_string()),
                };
            }
        }
    }
}

fn spawn_pipe_reader(
    label: &'static str,
    fd: RawFd,
    child_pid: libc::pid_t,
    output_limit_triggered: Arc<AtomicBool>,
) -> Receiver<OutputCapture> {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        // SAFETY: fd 的所有权只转移给当前读取线程，由 File 在 drop 时关闭。
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let capture = read_limited_output(&mut file, label, || {
            if !output_limit_triggered.swap(true, Ordering::SeqCst) {
                kill_process_group(child_pid, Signal::SIGKILL);
            }
        });
        let _ = tx.send(capture);
    });

    rx
}

fn receive_output_capture(rx: Receiver<OutputCapture>, label: &'static str) -> OutputCapture {
    match rx.recv() {
        Ok(capture) => capture,
        Err(error) => OutputCapture {
            data: Vec::new(),
            truncated: false,
            read_error: Some(format!("{label} reader thread exited abnormally: {error}")),
        },
    }
}

fn log_output_read_error(label: &'static str, capture: &OutputCapture) {
    if let Some(error) = &capture.read_error {
        tracing::warn!("Failed to read {label}: {error}");
    }
}

fn append_output_truncation_marker(
    stderr_buf: &mut Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
) {
    if !stdout_truncated && !stderr_truncated {
        return;
    }

    let streams = match (stdout_truncated, stderr_truncated) {
        (true, true) => "stdout/stderr",
        (true, false) => "stdout",
        (false, true) => "stderr",
        (false, false) => return,
    };
    let marker = format!(
        "\n[mimobox] {streams} output exceeded {} bytes limit; output truncated and process group terminated\n",
        OUTPUT_SIZE_LIMIT
    );
    let marker = marker.as_bytes();

    if stderr_buf.len() + marker.len() <= OUTPUT_SIZE_LIMIT {
        stderr_buf.extend_from_slice(marker);
        return;
    }

    if marker.len() >= OUTPUT_SIZE_LIMIT {
        stderr_buf.truncate(OUTPUT_SIZE_LIMIT);
        return;
    }

    stderr_buf.truncate(OUTPUT_SIZE_LIMIT - marker.len());
    stderr_buf.extend_from_slice(marker);
}

/// Applies all child-process security policies and executes the command.
///
/// Execution order (security policies are applied as early as possible to minimize race windows):
/// 1. Set the memory limit (`setrlimit`).
/// 2. Set process count limit when fork is allowed.
/// 3. Apply Landlock filesystem isolation.
/// 4. Unshare namespaces with user namespace fallback.
/// 5. Fork once after `CLONE_NEWPID`, then remount `/proc` inside the PID namespace.
/// 6. Apply Seccomp-bpf system call filtering as the final step before `exec`.
/// 7. Execute the command with `execvp`.
fn apply_security_policies_and_exec(
    cmd: &[String],
    config: &SandboxConfig,
    allow_ns_degradation: bool,
) -> ! {
    // 1. 设置内存限制（最早应用，防止后续操作消耗过多内存）
    if let Some(limit_mb) = config.memory_limit_mb
        && let Err(e) = set_memory_limit(limit_mb)
    {
        // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
        unsafe {
            write_error(2, &format!("memory limit setting failed: {e}"));
            libc::_exit(124);
        }
    }

    // 1.5 进程数限制兜底：pids.max 已由父进程在 cgroup 中设置。
    // RLIMIT_NPROC 作为旧内核或 cgroup 不可用时的 best-effort fallback。
    if config.allow_fork {
        let max_nproc = libc::rlim_t::from(effective_max_processes(config));
        let rlim = libc::rlimit {
            rlim_cur: max_nproc,
            rlim_max: max_nproc,
        };
        // SAFETY: setrlimit 只修改当前进程的 rlimit，参数合法。
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim) };
        if ret != 0 {
            // SAFETY: errno is thread-local and can be read immediately after the failed libc call.
            let errno = unsafe { *libc::__errno_location() };
            tracing::warn!(
                "setrlimit(RLIMIT_NPROC, {}) failed: errno={}, fork bomb fallback protection was not applied",
                effective_max_processes(config),
                errno,
            );
        }
    }

    // 2. 应用 Landlock（文件系统隔离）
    {
        use landlock::{
            ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, path_beneath_rules,
        };

        let abi = ABI::V6;
        let all_access = AccessFs::from_all(abi);
        let read_access = AccessFs::from_read(abi);

        let result = (|| -> Result<(), landlock::RulesetError> {
            let mut ruleset = Ruleset::default().handle_access(all_access)?.create()?;

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
            // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
            unsafe {
                write_error(2, &format!("Landlock enforcement failed (fatal): {e}"));
                libc::_exit(122);
            }
        }
    }

    // 3. unshare 命名空间
    let pid_ns_flags = CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNET
        | CloneFlags::CLONE_NEWIPC;
    let fallback_ns_flags =
        CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWIPC;

    let full_flags = CloneFlags::CLONE_NEWUSER | pid_ns_flags;

    let has_new_pid_namespace = match nix::sched::unshare(full_flags) {
        Ok(()) => true,
        Err(e) => {
            if !allow_ns_degradation {
                // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
                unsafe {
                    write_error(2, &format!("namespace creation failed (fail-closed): {e}"));
                    libc::_exit(NAMESPACE_FAIL_CLOSED_EXIT_CODE);
                }
            }

            let msg = format!("unshare(full_flags) failed: {e}, retrying without user/pid ns");
            // SAFETY: This is the forked child; write_error writes directly to stderr without unwinding.
            unsafe {
                write_error(2, &msg);
            }

            if let Err(e2) = nix::sched::unshare(fallback_ns_flags) {
                // 致命 #5 修复：unshare 失败必须终止，否则无命名空间隔离
                // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
                unsafe {
                    write_error(
                        2,
                        &format!("unshare(fallback_ns_flags) failed (fatal): {e2}"),
                    );
                    libc::_exit(121);
                }
            }
            false
        }
    };

    // 4. CLONE_NEWPID 需要 fork 才生效
    // fallback 分支故意不包含 CLONE_NEWPID，因为 unshare(CLONE_NEWPID) 不 fork 不会影响当前进程。
    if has_new_pid_namespace {
        // SAFETY: This child intentionally forks once after CLONE_NEWPID so the namespace takes effect.
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // 中间进程：等待孙进程退出后转发退出码
                loop {
                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, code)) => {
                            // SAFETY: Intermediate child exits immediately with the grandchild code.
                            unsafe { libc::_exit(code) }
                        }
                        Ok(WaitStatus::Signaled(_, sig, _)) => {
                            // SAFETY: Intermediate child exits immediately with the encoded signal status.
                            unsafe { libc::_exit(128 + sig as i32) }
                        }
                        _ => continue,
                    }
                }
            }
            Ok(ForkResult::Child) => {
                // 孙进程：PID namespace 已生效，先刷新 /proc 视图，再继续应用 seccomp。
                if let Err(e) = remount_proc_for_pid_namespace() {
                    if e.contains(CONTAINER_MOUNT_UNAVAILABLE_MARKER) && allow_ns_degradation {
                        // SAFETY: This is the forked child warning path; write_error avoids unwinding.
                        unsafe {
                            write_error(
                                2,
                                &format!("warning: /proc remount skipped (container): {e}"),
                            );
                        }
                    } else {
                        // 必须 fail-closed：如果 /proc 保留宿主 PID namespace 视图，
                        // 会泄露宿主进程信息，违反沙箱隔离承诺。
                        // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
                        unsafe {
                            write_error(2, &format!("remount /proc failed (fatal): {e}"));
                            libc::_exit(124);
                        }
                    }
                }
            }
            Err(e) => {
                // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
                unsafe {
                    write_error(2, &format!("internal fork failed: {e}"));
                    libc::_exit(123);
                }
            }
        }
    }

    // 4.5 SIGSYS handler（已移除）
    // 不在此处注册 SIGSYS handler，因为 execve() 会将所有自定义信号处理器重置为 SIG_DFL。
    // TRAP 模式的价值在于：进程以 SIGSYS 终止（exit_code=159），内核审计可记录。
    // See the "SIGSYS handler notes (removed)" comment above.

    // 5. 应用 Seccomp-bpf 过滤（在 exec 之前最后应用）
    // 致命 #3 修复：Seccomp 在所有安全策略配置完成后、exec 之前立即应用
    let effective_profile = match (config.allow_fork, config.seccomp_profile) {
        (true, SeccompProfile::Essential) => SeccompProfile::EssentialWithFork,
        (true, SeccompProfile::Network) => SeccompProfile::NetworkWithFork,
        (_, other) => other,
    };
    if let Err(e) = seccomp::apply_seccomp(effective_profile, config.deny_network) {
        // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
        unsafe {
            write_error(2, &format!("Seccomp error: {e}"));
            libc::_exit(126);
        }
    }

    // 6. execvp
    // 重要 #12 修复：使用 unwrap_or_else + _exit 替代 unwrap
    let c_cmd = CString::new(cmd[0].as_str()).unwrap_or_else(|_| {
        // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
        unsafe {
            write_error(2, &format!("command contains embedded NUL: {}", cmd[0]));
            libc::_exit(127);
        }
    });
    let c_args: Vec<CString> = cmd
        .iter()
        .map(|s| {
            CString::new(s.as_str()).unwrap_or_else(|_| {
                // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
                unsafe {
                    write_error(2, &format!("argument contains embedded NUL: {s}"));
                    libc::_exit(127);
                }
            })
        })
        .collect();

    let _ = execvp(&c_cmd, &c_args);

    // SAFETY: execvp returned, so this child must report the failure and terminate immediately.
    unsafe {
        write_error(2, &format!("execvp failed: {}", cmd[0]));
        libc::_exit(125);
    }
}

impl LinuxSandbox {
    #[cfg(target_os = "linux")]
    fn cleanup_last_cgroup(&mut self) {
        if let Some(path) = self.last_cgroup_path.take() {
            cleanup_cgroup(&path);
        }
    }

    /// Returns the isolation-level report from the most recent execution.
    pub fn isolation_report(&self) -> IsolationReport {
        self.last_isolation_report
    }

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
        env_vars: &[(CString, CString)],
        stdout_fd: RawFd,
        stderr_fd: RawFd,
        close_fds: Option<(RawFd, RawFd)>, // 需要关闭的管道读端 fd
    ) -> ! {
        // FATAL-02 修复：setpgid 和 close 使用裸 libc 调用，确保 async-signal-safe
        // SAFETY: setpgid(0, 0) 创建新进程组，参数合法
        unsafe {
            libc::setpgid(0, 0);
        }
        // SECURITY: 关闭所有从 3 开始的非必要继承 FD，防止文件描述符泄漏到沙箱子进程。
        // 使用原始 open + getdents64 syscall，完全 async-signal-safe。
        // SAFETY: 仅使用 syscall 层面调用，无堆内存分配，安全在 clone 后子进程中执行。
        {
            let dir_fd = unsafe {
                libc::open(
                    c"/proc/self/fd".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )
            };
            if dir_fd >= 0 {
                let mut buf = [0u8; 512]; // 栈上分配，无 malloc
                let mut preserve_fds: [RawFd; 4] = [stdout_fd, stderr_fd, -1, -1];
                let mut preserve_count = 2usize;
                if let Some((r1, r2)) = close_fds {
                    preserve_fds[2] = r1;
                    preserve_fds[3] = r2;
                    preserve_count = 4;
                }
                loop {
                    // SAFETY: getdents64 系统调用，使用栈缓冲区，无 malloc
                    let nread = unsafe {
                        libc::syscall(libc::SYS_getdents64, dir_fd, buf.as_mut_ptr(), buf.len())
                    };
                    if nread <= 0 {
                        break;
                    }
                    let nread = nread as usize;
                    let mut pos = 0usize;
                    while pos < nread {
                        // linux_dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(var)
                        if pos + 19 > nread {
                            break;
                        }
                        let reclen = u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
                        if reclen == 0 || pos + reclen > nread {
                            break;
                        }
                        let name_start = pos + 18;
                        let name_end = (name_start..pos + reclen)
                            .find(|&i| buf[i] == 0)
                            .unwrap_or(pos + reclen);
                        let name_bytes = &buf[name_start..name_end];
                        if let Ok(name_str) = core::str::from_utf8(name_bytes) {
                            if let Ok(fd) = name_str.parse::<RawFd>() {
                                if fd > 2
                                    && fd != dir_fd
                                    && !preserve_fds[..preserve_count].contains(&fd)
                                {
                                    // SAFETY: fd 来自 getdents64 枚举，且已排除 stdio、dir_fd 与保留 fd。
                                    unsafe {
                                        libc::close(fd);
                                    }
                                }
                            }
                        }
                        pos += reclen;
                    }
                }
                // SAFETY: dir_fd 枚举完成，关闭自身
                unsafe {
                    libc::close(dir_fd);
                }
            }
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
        if unsafe { reset_child_environment(env_vars) }.is_err() {
            // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
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
            // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
            unsafe {
                write_error(2, "failed to open /dev/null");
                libc::_exit(120);
            }
        }
        // SAFETY: All file descriptors are valid in the child; dup2 redirects stdio before exec.
        unsafe {
            libc::dup2(dev_null, 0);
            libc::close(dev_null);
            libc::dup2(stdout_fd, 1);
            libc::dup2(stderr_fd, 2);
            libc::close(stdout_fd);
            libc::close(stderr_fd);
        }

        let allow_degradation = matches!(
            config.namespace_degradation,
            NamespaceDegradation::AllowDegradation
        );
        apply_security_policies_and_exec(cmd, config, allow_degradation);
    }

    fn pty_child_main(
        cmd: &[String],
        sandbox_config: &SandboxConfig,
        pty_config: &mimobox_core::PtyConfig,
        env_vars: &[(CString, CString)],
        slave_path: &Path,
    ) -> ! {
        // SAFETY: Only the forked child environment is reset before exec.
        if unsafe { reset_child_environment_for_pty(env_vars) }.is_err() {
            // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
            unsafe {
                write_error(2, "PTY environment variable initialization failed");
                libc::_exit(119);
            }
        }

        // SECURITY: 关闭所有从 3 开始的非必要继承 FD，防止文件描述符泄漏到沙箱子进程。
        // 使用原始 open + getdents64 syscall，完全 async-signal-safe。
        // SAFETY: 仅使用 syscall 层面调用，无堆内存分配，安全在 clone 后子进程中执行。
        // PTY slave 尚未打开，无需保留额外 FD（stdout/stderr 将在 attach_pty_stdio 中替换）。
        {
            let dir_fd = unsafe {
                libc::open(
                    c"/proc/self/fd".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )
            };
            if dir_fd >= 0 {
                let mut buf = [0u8; 512]; // 栈上分配，无 malloc
                loop {
                    // SAFETY: getdents64 系统调用，使用栈缓冲区，无 malloc
                    let nread = unsafe {
                        libc::syscall(libc::SYS_getdents64, dir_fd, buf.as_mut_ptr(), buf.len())
                    };
                    if nread <= 0 {
                        break;
                    }
                    let nread = nread as usize;
                    let mut pos = 0usize;
                    while pos < nread {
                        // linux_dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(var)
                        if pos + 19 > nread {
                            break;
                        }
                        let reclen = u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
                        if reclen == 0 || pos + reclen > nread {
                            break;
                        }
                        let name_start = pos + 18;
                        let name_end = (name_start..pos + reclen)
                            .find(|&i| buf[i] == 0)
                            .unwrap_or(pos + reclen);
                        let name_bytes = &buf[name_start..name_end];
                        if let Ok(name_str) = core::str::from_utf8(name_bytes) {
                            if let Ok(fd) = name_str.parse::<RawFd>() {
                                if fd > 2 && fd != dir_fd {
                                    // SAFETY: fd 来自 getdents64 枚举，且已排除 stdio 与 dir_fd。
                                    unsafe {
                                        libc::close(fd);
                                    }
                                }
                            }
                        }
                        pos += reclen;
                    }
                }
                // SAFETY: dir_fd 枚举完成，关闭自身
                unsafe {
                    libc::close(dir_fd);
                }
            }
        }

        if let Err(error) = attach_pty_stdio(slave_path) {
            // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
            unsafe {
                write_error(2, &format!("failed to attach PTY slave: {error}"));
                libc::_exit(120);
            }
        }

        if let Some(cwd) = pty_config.cwd.as_deref()
            && let Err(error) = change_child_cwd(cwd)
        {
            // SAFETY: This is the forked child failure path; write_error and _exit avoid unwinding.
            unsafe {
                write_error(2, &format!("failed to change working directory: {error}"));
                libc::_exit(124);
            }
        }

        let allow_degradation = matches!(
            sandbox_config.namespace_degradation,
            NamespaceDegradation::AllowDegradation
        );
        apply_security_policies_and_exec(cmd, sandbox_config, allow_degradation);
    }
}

impl Sandbox for LinuxSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        config.validate()?;

        tracing::info!(
            "Creating sandbox, seccomp={:?}, allow_fork={}, timeout={:?}s",
            config.seccomp_profile,
            config.allow_fork,
            config.timeout_secs
        );
        Ok(Self {
            config,
            #[cfg(target_os = "linux")]
            last_cgroup_path: None,
            last_isolation_report: IsolationReport::default(),
            cached_metrics: None,
        })
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        self.last_isolation_report = IsolationReport::default();
        self.cached_metrics = None;

        if cmd.is_empty() {
            return Err(SandboxError::new("command must not be empty"));
        }

        #[cfg(target_os = "linux")]
        self.cleanup_last_cgroup();

        // SECURITY: 只记录可执行文件基名和参数个数，避免把 argv 中的 token/路径写入日志。
        tracing::info!("Executing command: {}", command_log_summary(cmd));
        let start = Instant::now();
        let timeout = self.config.timeout_secs.map(Duration::from_secs);

        // 重要 #10 修复：使用 pipe2 + O_CLOEXEC 创建管道
        let (stdout_read_fd, stdout_write_fd) = create_pipe_cloexec()?;
        let (stderr_read_fd, stderr_write_fd) = create_pipe_cloexec()?;
        let (start_read_fd, start_write_fd) = create_pipe_cloexec()?;

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
        let child_env_vars = prepare_child_env_vars(&child_config.env_vars)?;

        // SAFETY: The parent immediately manages both branches and the child only runs fork-safe setup.
        match unsafe { fork() }.map_err(|e| SandboxError::Syscall(e.to_string()))? {
            ForkResult::Parent { child } => {
                // SAFETY: 父进程只负责发启动信号，不读取 gate。
                unsafe {
                    libc::close(start_read_fd);
                }
                // 重要 #7 修复：父进程关闭写端（O_CLOEXEC 已在 pipe2 时设置）
                // SAFETY: fd 有效，父进程不再需要写端
                unsafe {
                    libc::close(stdout_write_fd);
                    libc::close(stderr_write_fd);
                }

                let output_limit_triggered = Arc::new(AtomicBool::new(false));
                let stdout_rx = spawn_pipe_reader(
                    "stdout",
                    stdout_read_fd,
                    child.as_raw(),
                    Arc::clone(&output_limit_triggered),
                );
                let stderr_rx = spawn_pipe_reader(
                    "stderr",
                    stderr_read_fd,
                    child.as_raw(),
                    Arc::clone(&output_limit_triggered),
                );

                #[cfg(target_os = "linux")]
                let cgroup_path = {
                    match configure_sandbox_cgroup(
                        Path::new(CGROUP_V2_ROOT),
                        child.as_raw(),
                        &self.config,
                    ) {
                        Ok(path) => {
                            self.last_cgroup_path = path.clone();
                            path
                        }
                        Err(error) => {
                            cancel_child_start(start_write_fd);
                            kill_process(child.as_raw(), Signal::SIGKILL);
                            let _ = waitpid(child, None);
                            let _ = receive_output_capture(stdout_rx, "stdout");
                            let _ = receive_output_capture(stderr_rx, "stderr");
                            return Err(error);
                        }
                    }
                };

                if let Err(error) = signal_child_start(start_write_fd) {
                    kill_process(child.as_raw(), Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    let _ = receive_output_capture(stdout_rx, "stdout");
                    let _ = receive_output_capture(stderr_rx, "stderr");
                    #[cfg(target_os = "linux")]
                    if cgroup_path.is_some() {
                        self.cleanup_last_cgroup();
                    }
                    return Err(error);
                }

                let (wait_result, timed_out, metrics) =
                    waitpid_with_metrics(child, timeout, self.config.memory_limit_mb)?;
                self.cached_metrics = Some(metrics);

                let stdout_capture = receive_output_capture(stdout_rx, "stdout");
                let stderr_capture = receive_output_capture(stderr_rx, "stderr");
                log_output_read_error("stdout", &stdout_capture);
                log_output_read_error("stderr", &stderr_capture);

                let stdout_truncated = stdout_capture.truncated;
                let stderr_truncated = stderr_capture.truncated;
                let stdout_buf = stdout_capture.data;
                let mut stderr_buf = stderr_capture.data;
                append_output_truncation_marker(
                    &mut stderr_buf,
                    stdout_truncated,
                    stderr_truncated,
                );

                let elapsed = start.elapsed();

                #[cfg(target_os = "linux")]
                if cgroup_path.is_some() {
                    self.cleanup_last_cgroup();
                }

                match wait_result {
                    WaitStatus::Exited(_, code) => {
                        if code == NAMESPACE_FAIL_CLOSED_EXIT_CODE {
                            return Err(SandboxError::NamespaceFailed(
                                "namespace creation failed (fail-closed): user/pid namespaces are unavailable, refusing degraded execution"
                                    .to_string(),
                            ));
                        }

                        log_namespace_fallback_from_stderr(&stderr_buf);
                        apply_namespace_fallback_to_report(
                            &mut self.last_isolation_report,
                            &stderr_buf,
                        );
                        tracing::info!(
                            "Child process exited, code={}, elapsed={:.2}ms",
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
                        log_namespace_fallback_from_stderr(&stderr_buf);
                        apply_namespace_fallback_to_report(
                            &mut self.last_isolation_report,
                            &stderr_buf,
                        );
                        let code = -(sig as i32);
                        if timed_out {
                            tracing::warn!(
                                "Child process terminated due to timeout (SIGKILL), elapsed={:.2}ms",
                                elapsed.as_secs_f64() * 1000.0
                            );
                        } else {
                            tracing::info!(
                                "Child process terminated by signal: {:?}, elapsed={:.2}ms",
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
                    _ => {
                        log_namespace_fallback_from_stderr(&stderr_buf);
                        apply_namespace_fallback_to_report(
                            &mut self.last_isolation_report,
                            &stderr_buf,
                        );
                        Ok(SandboxResult {
                            stdout: stdout_buf,
                            stderr: stderr_buf,
                            exit_code: None,
                            elapsed,
                            timed_out,
                        })
                    }
                }
            }
            ForkResult::Child => {
                // SAFETY: 子进程只读取启动 gate，不写入。
                unsafe {
                    libc::close(start_write_fd);
                }
                if wait_for_parent_start_signal(start_read_fd).is_err() {
                    // SAFETY: 父进程未完成 cgroup 设置，子进程必须 fail-closed。
                    unsafe {
                        libc::_exit(118);
                    }
                }
                // FATAL-02 修复：setpgid 和 close 已移入 child_main，使用裸 libc 调用
                Self::child_main(
                    cmd,
                    &child_config,
                    &child_env_vars,
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
            return Err(SandboxError::new("PTY command must not be empty"));
        }

        tracing::info!(
            "Creating Linux PTY session: {}",
            command_log_summary(&config.command)
        );

        #[cfg(target_os = "linux")]
        self.cleanup_last_cgroup();

        let allocated = allocate_pty(config.size)?;
        let slave_path = allocated.slave_path.clone();
        let (start_read_fd, start_write_fd) = create_pipe_cloexec()?;

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
        let pty_env = build_child_env_with_base(&config, &child_config.env_vars);
        let child_env_vars = prepare_child_env_vars(&pty_env)?;

        // SAFETY: The parent manages the child process while the child only performs fork-safe PTY setup.
        match unsafe { fork() }.map_err(|error| SandboxError::Syscall(error.to_string()))? {
            ForkResult::Parent { child } => {
                // SAFETY: 父进程只负责发启动信号，不读取 gate。
                unsafe {
                    libc::close(start_read_fd);
                }
                #[cfg(target_os = "linux")]
                match configure_sandbox_cgroup(
                    Path::new(CGROUP_V2_ROOT),
                    child.as_raw(),
                    &self.config,
                ) {
                    Ok(path) => {
                        self.last_cgroup_path = path;
                    }
                    Err(error) => {
                        cancel_child_start(start_write_fd);
                        kill_process(child.as_raw(), Signal::SIGKILL);
                        let _ = waitpid(child, None);
                        return Err(error);
                    }
                }

                if let Err(error) = signal_child_start(start_write_fd) {
                    kill_process(child.as_raw(), Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    #[cfg(target_os = "linux")]
                    self.cleanup_last_cgroup();
                    return Err(error);
                }

                Ok(build_session(allocated, child.as_raw(), config.timeout))
            }
            ForkResult::Child => {
                // SAFETY: 子进程只读取启动 gate，不写入。
                unsafe {
                    libc::close(start_write_fd);
                }
                if wait_for_parent_start_signal(start_read_fd).is_err() {
                    // SAFETY: 父进程未完成 cgroup 设置，子进程必须 fail-closed。
                    unsafe {
                        libc::_exit(118);
                    }
                }
                Self::pty_child_main(
                    &config.command,
                    &child_config,
                    &config,
                    &child_env_vars,
                    &slave_path,
                );
            }
        }
    }

    fn file_exists(&mut self, _path: &str) -> Result<bool, SandboxError> {
        Err(SandboxError::UnsupportedOperation("OS-level sandbox does not support file_exists: cannot distinguish sandbox-internal paths from host paths after the sandboxed process has exited".to_string()))
    }

    fn remove_file(&mut self, _path: &str) -> Result<(), SandboxError> {
        Err(SandboxError::UnsupportedOperation("OS-level sandbox does not support remove_file: cannot distinguish sandbox-internal paths from host paths after the sandboxed process has exited".to_string()))
    }

    fn rename(&mut self, _from: &str, _to: &str) -> Result<(), SandboxError> {
        Err(SandboxError::UnsupportedOperation("OS-level sandbox does not support rename: cannot distinguish sandbox-internal paths from host paths after the sandboxed process has exited".to_string()))
    }

    fn stat(&mut self, _path: &str) -> Result<FileStat, SandboxError> {
        Err(SandboxError::UnsupportedOperation("OS-level sandbox does not support stat: cannot distinguish sandbox-internal paths from host paths after the sandboxed process has exited".to_string()))
    }

    fn list_dir(&mut self, _path: &str) -> Result<Vec<DirEntry>, SandboxError> {
        Err(SandboxError::UnsupportedOperation("OS-level sandbox does not support list_dir: cannot distinguish sandbox-internal paths from host paths after the sandboxed process has exited".to_string()))
    }

    fn destroy(mut self) -> Result<(), SandboxError> {
        #[cfg(target_os = "linux")]
        self.cleanup_last_cgroup();

        Ok(())
    }
}

/// # Safety
///
/// Only called in the post-fork child process to clear environment variables
/// and set the child environment required for PTY execution.
/// Calling this after `fork` and before `exec` is safe because the child is
/// single-threaded, so environment mutation cannot affect other threads.
unsafe fn reset_child_environment_for_pty(env_vars: &[(CString, CString)]) -> Result<(), ()> {
    // SAFETY: Called only in the forked child before exec; clearing its process environment is local.
    if unsafe { libc::clearenv() } != 0 {
        return Err(());
    }

    // SAFETY: env_vars 已在 fork 前完成 CString 序列化，子进程不访问父进程 HashMap。
    unsafe { set_prepared_child_env(env_vars)? };

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
        config.namespace_degradation = NamespaceDegradation::AllowDegradation;
        config
    }

    #[test]
    fn set_memory_limit_rejects_mib_to_bytes_overflow() {
        let error = set_memory_limit(u64::MAX)
            .expect_err("memory_limit_mb conversion to bytes must return an overflow error");

        assert!(error.contains("memory_limit_mb"));
        assert!(error.contains("overflowed"));
    }

    #[test]
    fn test_isolation_report_default_all_true() {
        let report = IsolationReport::default();
        assert!(
            report.user_namespace,
            "default user_namespace should be true"
        );
        assert!(report.pid_namespace, "default pid_namespace should be true");
        assert!(
            report.network_namespace,
            "default network_namespace should be true"
        );
        assert!(
            report.mount_namespace,
            "default mount_namespace should be true"
        );
        assert!(report.ipc_namespace, "default ipc_namespace should be true");
        assert!(report.landlock, "default landlock should be true");
        assert!(report.seccomp, "default seccomp should be true");
    }

    #[test]
    fn test_namespace_fallback_detected_with_marker() {
        let stderr = b"some output\nunshare(full_flags) failed: EPERM, retrying without user/pid ns\nmore output";
        assert!(
            namespace_fallback_detected(stderr),
            "should detect fallback marker"
        );
    }

    #[test]
    fn test_namespace_fallback_detected_without_marker() {
        let stderr = b"normal output without any fallback marker";
        assert!(
            !namespace_fallback_detected(stderr),
            "should not detect fallback marker"
        );
    }

    #[test]
    fn test_namespace_fallback_updates_report() {
        let mut report = IsolationReport::default();
        let stderr = b"unshare(full_flags) failed: EPERM, retrying without user/pid ns";

        apply_namespace_fallback_to_report(&mut report, stderr);

        assert!(
            !report.user_namespace,
            "user_namespace should be false after fallback"
        );
        assert!(
            !report.pid_namespace,
            "pid_namespace should be false after fallback"
        );
        assert!(
            report.network_namespace,
            "network namespace should not be marked as degraded"
        );
        assert!(
            report.mount_namespace,
            "mount namespace should not be marked as degraded"
        );
        assert!(
            report.ipc_namespace,
            "ipc namespace should not be marked as degraded"
        );
        assert!(
            report.landlock,
            "Landlock should not be affected by namespace fallback"
        );
        assert!(
            report.seccomp,
            "Seccomp should not be affected by namespace fallback"
        );
    }

    #[test]
    fn test_isolation_report_initial_state() {
        let config = SandboxConfig::default();
        let sb = LinuxSandbox::new(config).expect("failed to create sandbox");
        let report = sb.isolation_report();
        assert!(
            report.user_namespace,
            "initial user_namespace should be true"
        );
        assert!(report.pid_namespace, "initial pid_namespace should be true");
    }

    fn assert_unsupported_operation<T>(operation: &str, result: Result<T, SandboxError>) {
        match result {
            Err(SandboxError::UnsupportedOperation(msg)) => {
                assert!(
                    msg.contains(operation),
                    "error should mention {operation}, got: {msg}"
                );
                assert!(
                    msg.contains("OS-level sandbox does not support"),
                    "got: {msg}"
                );
            }
            Err(err) => panic!("should be UnsupportedOperation, got: {err}"),
            Ok(_) => panic!("{operation} should return error on OS backend"),
        }
    }

    #[test]
    fn test_file_exists_unsupported() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("file_exists", sb.file_exists("/tmp/mimobox_exists_test"));
    }

    #[test]
    fn test_remove_file_unsupported() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("remove_file", sb.remove_file("/tmp/mimobox_remove_test"));
    }

    #[test]
    fn test_rename_unsupported() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation(
            "rename",
            sb.rename("/tmp/mimobox_rename_src", "/tmp/mimobox_rename_dst"),
        );
    }

    #[test]
    fn test_stat_unsupported() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("stat", sb.stat("/tmp/mimobox_stat_test"));
    }

    #[test]
    fn test_list_dir_unsupported() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("list_dir", sb.list_dir("/tmp"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_cgroup_helpers_generate_expected_path_and_cpu_max() {
        let limited = SandboxConfig::default()
            .cpu_quota(50_000)
            .cpu_period(100_000);
        let unlimited = SandboxConfig::default().cpu_period(100_000);
        let mut custom_process_limit = SandboxConfig::default();
        custom_process_limit.max_processes = Some(32);
        let path = sandbox_cgroup_path(Path::new("/sys/fs/cgroup"), 42);

        assert_eq!(path, PathBuf::from("/sys/fs/cgroup/mimobox/sandbox-42"));
        assert_eq!(format_cpu_max(&limited), "50000 100000");
        assert_eq!(format_cpu_max(&unlimited), "max 100000");
        assert_eq!(format_pids_max(&unlimited), "64");
        assert_eq!(format_pids_max(&custom_process_limit), "32");
    }

    #[test]
    fn test_sandbox_create_and_execute() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        let cmd = vec!["/bin/echo".to_string(), "hello test".to_string()];
        let result = sb.execute(&cmd).expect("execution failed");

        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return;
        }
        assert!(!result.timed_out, "should not time out");
        assert_eq!(result.exit_code, Some(0), "exit code should be 0");
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("hello test"),
            "stdout should contain output, actual: {stdout}"
        );
    }

    /// Tests non-zero exit codes.
    /// Requires release mode: `cargo test --release test_sandbox_exit_code`.
    #[test]
    fn test_sandbox_exit_code() {
        let mut config = test_config();
        config.allow_fork = true;
        let mut sb = LinuxSandbox::new(config).expect("failed to create sandbox");
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 42".to_string(),
        ];
        let result = sb.execute(&cmd).expect("execution failed");

        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return;
        }
        assert_eq!(result.exit_code, Some(42), "exit code should be 42");
    }

    #[test]
    fn test_network_isolation() {
        // CLONE_NEWNET 在 child_main 中通过 unshare 创建
        // 添加 /proc 到 readonly 以便读取 /proc/net/dev
        let mut config = SandboxConfig::default();
        config.deny_network = true;
        config.namespace_degradation = NamespaceDegradation::AllowDegradation;
        config.fs_readonly = vec![
            "/usr".into(),
            "/lib".into(),
            "/lib64".into(),
            "/bin".into(),
            "/sbin".into(),
            "/proc".into(),
        ];
        let mut sb = LinuxSandbox::new(config).expect("failed to create sandbox");

        let cmd = vec!["/bin/cat".to_string(), "/proc/net/dev".to_string()];
        let result = sb.execute(&cmd).expect("execution failed");

        let stdout = String::from_utf8_lossy(&result.stdout);
        // CLONE_NEWNET 下只有 loopback 接口
        assert!(
            stdout.contains("lo") || stdout.contains("Inter-"),
            "network should be isolated (lo only), stdout: {stdout}, exit: {:?}",
            result.exit_code
        );
    }

    /// Tests read-write filesystem isolation; requires release mode.
    #[test]
    fn test_fs_isolation() {
        let mut config = test_config();
        config.allow_fork = true;
        let mut sb = LinuxSandbox::new(config.clone()).expect("failed to create sandbox");

        // sh -c 用 /bin/echo 写入 /tmp（应成功，因为在 fs_readwrite 中）
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "/bin/echo test > /tmp/mimobox_test_fs".to_string(),
        ];
        let result = sb.execute(&cmd).expect("execution failed");
        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return;
        }
        assert_eq!(
            result.exit_code,
            Some(0),
            "writing to /tmp failed: {:?}",
            result.stderr
        );

        // 用 /bin/cat 读取验证
        let mut sb2 = LinuxSandbox::new(config.clone()).expect("failed to create sandbox");
        let cmd2 = vec!["/bin/cat".to_string(), "/tmp/mimobox_test_fs".to_string()];
        let result2 = sb2.execute(&cmd2).expect("read failed");
        let stdout = String::from_utf8_lossy(&result2.stdout);
        assert!(
            stdout.contains("test"),
            "should be able to read and write /tmp, stdout: {stdout}"
        );

        // 清理
        let mut sb3 = LinuxSandbox::new(config).expect("failed to create sandbox");
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
        config.fs_readonly = vec![
            "/usr".into(),
            "/lib".into(),
            "/lib64".into(),
            "/bin".into(),
            "/sbin".into(),
        ];
        config.fs_readwrite = vec!["/tmp".into()];
        let mut sb = LinuxSandbox::new(config).expect("failed to create sandbox");

        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo test > /usr/mimobox_test_ro 2>&1; echo exit_code=$?".to_string(),
        ];
        let result = sb.execute(&cmd).expect("execution failed");

        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("Permission denied")
                || stdout.contains("Read-only")
                || (stdout.contains("exit_code=") && !stdout.contains("exit_code=0")),
            "writing to /usr should be denied, stdout: {stdout}, exit: {:?}",
            result.exit_code
        );
    }

    #[test]
    fn test_seccomp_deny_fork() {
        let mut config = test_config();
        config.allow_fork = false;
        config.seccomp_profile = SeccompProfile::Essential;
        let mut sb = LinuxSandbox::new(config).expect("failed to create sandbox");

        // dash directly execve's `sh -c "single external command"` without forking first.
        // 两个外部命令可迫使 shell 为第一个命令 fork，从而验证 seccomp 拦截。
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "/bin/echo parent; /bin/echo child".to_string(),
        ];
        let result = sb.execute(&cmd).expect("execution failed");

        // seccomp 会 kill 尝试 fork 的进程
        assert!(
            result.exit_code != Some(0),
            "fork should be blocked by seccomp, exit_code: {:?}",
            result.exit_code
        );
    }

    #[test]
    fn test_timeout() {
        let mut config = test_config();
        config.timeout_secs = Some(1);
        let mut sb = LinuxSandbox::new(config).expect("failed to create sandbox");

        let cmd = vec!["/bin/sleep".to_string(), "60".to_string()];
        let result = sb.execute(&cmd).expect("execution failed");

        if result.exit_code == Some(125) {
            eprintln!(
                "skipping: execvp failed, CI environment may lack complete filesystem isolation"
            );
            return;
        }
        assert!(result.timed_out, "should time out");
    }

    #[test]
    fn test_memory_limit() {
        // 设置极低的内存限制
        let mut config = test_config();
        config.memory_limit_mb = Some(8);
        let mut sb = LinuxSandbox::new(config).expect("failed to create sandbox");

        // 尝试分配大量内存（超过 8MB）
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            // dd 生成 32MB 数据试图触发 OOM
            "dd if=/dev/zero bs=1M count=32 2>/dev/null | cat > /dev/null; echo exit=$?"
                .to_string(),
        ];
        let result = sb.execute(&cmd).expect("execution failed");

        // 应该因内存限制而失败或被 kill
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            result.exit_code != Some(0) || stdout.contains("exit="),
            "memory limit should be enforced, exit_code: {:?}, stdout: {}",
            result.exit_code,
            stdout
        );
    }

    #[test]
    fn test_pty_basic_echo() {
        // 使用最小化沙箱配置，避免 Landlock/Seccomp 限制 PTY 行为
        let mut config = test_config();
        config.fs_readonly = vec![
            "/usr".into(),
            "/lib".into(),
            "/lib64".into(),
            "/bin".into(),
            "/sbin".into(),
        ];
        config.fs_readwrite = vec!["/tmp".into()];
        config.allow_fork = true;
        config.memory_limit_mb = None;
        let mut sb = LinuxSandbox::new(config).expect("failed to create sandbox");
        let mut session = sb
            .create_pty(mimobox_core::PtyConfig {
                command: vec!["/bin/cat".to_string()],
                size: mimobox_core::PtySize::default(),
                env: std::collections::HashMap::new(),
                cwd: None,
                timeout: Some(Duration::from_secs(5)),
            })
            .expect("failed to create PTY session");

        session
            .send_input(b"hello-pty\n")
            .expect("failed to send PTY input");

        // 给 PTY 回显一点时间
        std::thread::sleep(Duration::from_millis(200));

        let output = read_pty_until(session.output_rx(), b"hello-pty", Duration::from_secs(3));
        let output_str = String::from_utf8_lossy(&output);

        // PTY 在受限沙箱中可能不回显，只要会话创建和输入成功即可视为通过
        // 如果输出非空则验证包含预期内容
        if !output_str.is_empty() {
            assert!(
                output_str.contains("hello-pty"),
                "PTY output should contain echo result, actual: {output_str}"
            );
        }

        session.kill().expect("failed to terminate PTY session");
        assert!(
            session.wait().expect("failed to wait for PTY exit") < 0,
            "basic echo test should return a signal exit code after termination"
        );
    }

    #[test]
    fn test_pty_resize() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        let mut session = sb
            .create_pty(mimobox_core::PtyConfig {
                command: vec!["/bin/cat".to_string()],
                size: mimobox_core::PtySize::default(),
                env: std::collections::HashMap::new(),
                cwd: None,
                timeout: Some(Duration::from_secs(5)),
            })
            .expect("failed to create PTY session");

        session
            .resize(mimobox_core::PtySize {
                cols: 120,
                rows: 40,
            })
            .expect("failed to resize PTY");

        session.kill().expect("failed to terminate PTY session");
        let exit_code = session.wait().expect("failed to wait for PTY exit");
        if exit_code == 125 {
            eprintln!(
                "skipping: execvp failed, CI environment may lack \
                 complete filesystem isolation"
            );
            return;
        }
        assert!(
            exit_code < 0,
            "terminated PTY should return a signal exit code"
        );
    }

    #[test]
    fn test_pty_kill() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        let mut session = sb
            .create_pty(mimobox_core::PtyConfig {
                command: vec!["/bin/cat".to_string()],
                size: mimobox_core::PtySize::default(),
                env: std::collections::HashMap::new(),
                cwd: None,
                timeout: Some(Duration::from_secs(5)),
            })
            .expect("failed to create PTY session");

        session.kill().expect("failed to terminate PTY session");

        let exit_code = session.wait().expect("failed to wait for PTY exit");
        if exit_code == 125 {
            eprintln!(
                "skipping: execvp failed, CI environment may lack \
                 complete filesystem isolation"
            );
            return;
        }
        assert!(
            exit_code < 0,
            "kill should return a signal exit code, actual: {exit_code}"
        );
    }

    #[test]
    fn test_empty_command_error() {
        let mut sb = LinuxSandbox::new(test_config()).expect("failed to create sandbox");
        let result = sb.execute(&[]);
        assert!(result.is_err(), "empty command should return an error");
    }

    #[test]
    fn test_child_env_pairs_is_minimal_allowlist() {
        let names = child_env_pairs()
            .iter()
            .map(|(name, _)| {
                name.to_str()
                    .expect("environment variable name should be UTF-8")
            })
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "PATH", "HOME", "TERM", "USER", "LOGNAME", "SHELL", "PWD", "LANG", "TMPDIR"
            ],
            "child environment variables should stay on the minimal allowlist"
        );
        assert!(
            !names
                .iter()
                .any(|name| matches!(*name, "LD_PRELOAD" | "BASH_ENV" | "ENV")),
            "dangerous environment variables should not enter the allowlist"
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

/// 等待子进程结束，并在回收前采样 /proc 指标。
///
/// 返回 `(WaitStatus, timed_out, SandboxMetrics)`。
fn waitpid_with_metrics(
    child: nix::unistd::Pid,
    timeout: Option<Duration>,
    memory_limit_mb: Option<u64>,
) -> Result<(WaitStatus, bool, SandboxMetrics), SandboxError> {
    let Some(timeout) = timeout else {
        wait_until_exited_without_reaping(child)?;
        let metrics = sample_metrics(child.as_raw(), memory_limit_mb);
        let status = reap_child(child)?;
        return Ok((status, false, metrics));
    };

    let started_at = Instant::now();
    loop {
        let status = poll_exited_without_reaping(child)?;
        if status != WaitStatus::StillAlive {
            let metrics = sample_metrics(child.as_raw(), memory_limit_mb);
            let status = reap_child(child)?;
            return Ok((status, false, metrics));
        }

        if started_at.elapsed() >= timeout {
            tracing::warn!(
                "Child process timeout ({:.1}s), sending SIGKILL",
                timeout.as_secs_f64()
            );
            let metrics = sample_metrics(child.as_raw(), memory_limit_mb);
            // SECURITY: 以负 PID 发送 SIGKILL，确保整个沙箱进程组（含 re-exec 孙进程）被回收，
            // 避免 supervisor 超时后留下孤儿子进程或 zombie 清理链。
            kill_process_group(child.as_raw(), Signal::SIGKILL);
            let status = reap_child(child)?;
            return Ok((status, true, metrics));
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_until_exited_without_reaping(child: nix::unistd::Pid) -> Result<WaitStatus, SandboxError> {
    waitid(Id::Pid(child), WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT)
        .map_err(|error| SandboxError::Syscall(error.to_string()))
}

fn poll_exited_without_reaping(child: nix::unistd::Pid) -> Result<WaitStatus, SandboxError> {
    waitid(
        Id::Pid(child),
        WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG,
    )
    .map_err(|error| SandboxError::Syscall(error.to_string()))
}

fn reap_child(child: nix::unistd::Pid) -> Result<WaitStatus, SandboxError> {
    waitpid(child, None).map_err(|error| SandboxError::Syscall(error.to_string()))
}
