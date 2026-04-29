//! macOS sandbox backend (Seatbelt / sandbox_init).
//!
//! Implements process-level sandbox isolation with the native macOS Seatbelt framework.
//! Applies Seatbelt policy in the child process before `exec` and uses the Seatbelt policy
//! language to restrict filesystem access, networking, process execution, and more.
//!
//! # Security Policy
//!
//! | Dimension | Policy | Description |
//! |------|------|------|
//! | File reads | Deny-default + allowlist | Allows minimal system paths, the sandbox-specific temporary directory, and user-configured `fs_readonly` / `fs_readwrite` paths. |
//! | File writes | Deny-default + allowlist | Allows configured `fs_readwrite` paths, or the sandbox-specific temporary directory when no write path is configured. |
//! | Network access | Deny by default | Allows network operations only when `deny_network = false`. |
//! | Process execution | Path-restricted | Allows system and developer toolchain paths while denying writable execution locations. |
//! | Process fork | Config-controlled | Controlled by `allow_fork` config; denied by default. |
//! | Memory limits | Watchdog (proc_pidrusage RSS sampling) | Samples child process physical footprint and terminates the process group when over limit. |

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use mimobox_core::{
    DirEntry, FileStat, Sandbox, SandboxConfig, SandboxError, SandboxMetrics, SandboxResult,
};
use uuid::Uuid;

use crate::pty::{allocate_pty, build_session};

#[cfg(target_os = "macos")]
// SAFETY: This block declares external C linkage functions from the macOS system library.
// sandbox_init and proc_pid_rusage signatures match the system headers.
// sandbox_init is called only within pre_exec closures with validated CString pointers;
// proc_pid_rusage is called with a valid child pid and caller-owned rusage buffer.
unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;

    #[link_name = "proc_pid_rusage"]
    fn proc_pidrusage(
        pid: libc::pid_t,
        flavor: libc::c_int,
        buffer: *mut libc::rusage_info_t,
    ) -> libc::c_int;
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
#[repr(C)]
struct RUsageInfoV2 {
    ri_uuid: [u8; 16],
    ri_user_time: u64,
    ri_system_time: u64,
    ri_pkg_idle_wkups: u64,
    ri_sched_int: u64,
    ri_pageins: u64,
    ri_wired_size: u64,
    ri_resident_size: u64,
    ri_phys_footprint: u64,
    ri_proc_start_abstime: u64,
    ri_proc_exit_abstime: u64,
    ri_child_user_time: u64,
    ri_child_system_time: u64,
    ri_child_pkg_idle_wkups: u64,
    ri_child_interrupt_wkups: u64,
    ri_child_pageins: u64,
    ri_child_elapsed_abstime: u64,
    ri_diskio_bytesread: u64,
    ri_diskio_byteswritten: u64,
}

#[cfg(target_os = "macos")]
const RUSAGE_INFO_V2: i32 = 2;

const SANDBOX_LITERAL_PROFILE: u64 = 0;
const SANDBOX_INIT_FAILURE_EXIT_CODE: i32 = 71;
const SANDBOX_INIT_FAILURE_MESSAGE: &[u8] =
    b"sandbox-exec: sandbox_apply: Operation not permitted\n";
const OUTPUT_SIZE_LIMIT: usize = 4 * 1024 * 1024;
const OUTPUT_READ_CHUNK_SIZE: usize = 8 * 1024;
const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr/lib/",
    "/System/Library/",
    "/Library/Apple/System/Library/",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/usr/share/",
    "/private/etc/",
    "/private/var/db/timezone",
    // SECURITY: 不放开整棵 /private/var/folders；该目录包含用户 TMPDIR。
    // 仅允许系统缓存模板与 com.apple symbols cache 所需路径。
    "/private/var/folders/zz/",
    "/private/var/folders/zz/zyxvpxvq6csfx2n00",
    "/private/var/select/",
    "/dev/",
    "/etc/",
];
const SYSTEM_EXEC_PATHS: &[&str] = &[
    "/bin/",
    "/usr/bin/",
    "/sbin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/opt/homebrew/bin/",
];
const ALLOWED_MACH_SERVICES: &[&str] = &[
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
    "com.apple.logd",
    "com.apple.bsd.dirhelper",
];

#[derive(Debug)]
struct OutputCapture {
    data: Vec<u8>,
    truncated: bool,
    read_error: Option<String>,
}

fn build_safe_child_env(
    sandbox_tmp_dir: &str,
    pwd: &str,
    env_vars: &std::collections::HashMap<String, String>,
) -> HashMap<String, String> {
    let mut env = HashMap::from([
        (
            "PATH".to_string(),
            "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin".to_string(),
        ),
        ("HOME".to_string(), sandbox_tmp_dir.to_string()),
        ("TERM".to_string(), "dumb".to_string()),
        ("USER".to_string(), "sandbox".to_string()),
        ("LOGNAME".to_string(), "sandbox".to_string()),
        ("SHELL".to_string(), "/bin/sh".to_string()),
        ("LANG".to_string(), "C".to_string()),
        ("TMPDIR".to_string(), sandbox_tmp_dir.to_string()),
        ("PWD".to_string(), pwd.to_string()),
    ]);
    // 注入用户配置的持久环境变量（优先级高于内置最小环境）
    env.extend(env_vars.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

/// macOS Seatbelt sandbox backend.
///
/// Applies generated Seatbelt policies with `sandbox_init` in child processes before
/// executing the requested command.
///
/// # Platform Limitations
///
/// - File access uses deny-default Seatbelt rules with explicit read/write allowlists.
/// - Memory limits are enforced by sampling child process physical footprint with `proc_pidrusage`.
pub struct MacOsSandbox {
    config: SandboxConfig,
    /// Sandbox-private temporary directory to prevent cross-sandbox `/tmp` leakage.
    sandbox_tmp_dir: String,
    cached_metrics: Option<SandboxMetrics>,
}

impl MacOsSandbox {
    /// 返回最近一次 macOS 后端执行缓存的资源指标。
    pub fn metrics(&self) -> Option<SandboxMetrics> {
        self.cached_metrics.clone()
    }
}

/// 通过 proc_pidrusage 采样进程资源指标。
///
/// 在 waitpid 之后调用，获取子进程最终资源使用快照。
#[cfg(target_os = "macos")]
pub fn sample_metrics(pid: i32, memory_limit_mb: Option<u64>) -> SandboxMetrics {
    // SAFETY: RUsageInfoV2 是 repr(C) 且字段均为整数/字节数组，零初始化有效；
    // proc_pidrusage 会按 RUSAGE_INFO_V2 布局写入调用方提供的缓冲区。
    let mut rusage: RUsageInfoV2 = unsafe { std::mem::zeroed() };
    // SAFETY: pid 来自当前沙箱启动的子进程；rusage 指向栈上有效缓冲区，
    // 按 Darwin API 要求转换为 rusage_info_t 指针输出槽。
    let result = unsafe {
        proc_pidrusage(
            pid,
            RUSAGE_INFO_V2,
            &mut rusage as *mut _ as *mut libc::rusage_info_t,
        )
    };

    let mut metrics = SandboxMetrics::default();
    if result == 0 {
        // ri_user_time 和 ri_system_time 单位是纳秒。
        metrics.cpu_time_user_us = Some(rusage.ri_user_time / 1000);
        metrics.cpu_time_system_us = Some(rusage.ri_system_time / 1000);
        metrics.memory_usage_bytes = Some(rusage.ri_resident_size);
        metrics.io_read_bytes = Some(rusage.ri_diskio_bytesread);
        metrics.io_write_bytes = Some(rusage.ri_diskio_byteswritten);
    }
    if let Some(limit_mb) = memory_limit_mb {
        metrics.memory_limit_bytes = limit_mb.checked_mul(1024 * 1024);
    }
    metrics.collected_at = Some(std::time::Instant::now());
    metrics
}

fn detect_seatbelt_backend_failure(exit_code: Option<i32>, stderr: &[u8]) -> Option<String> {
    let stderr_text = String::from_utf8_lossy(stderr);

    if exit_code == Some(71) && stderr_text.contains("sandbox_apply: Operation not permitted") {
        // SECURITY: 不向上层暴露 sandbox-exec 原始 stderr，避免泄露策略文本或敏感路径。
        return Some(
            "Seatbelt policy enforcement failed (underlying path and policy details hidden)"
                .to_string(),
        );
    }

    None
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

fn waitpid_raw(pid: libc::pid_t) -> std::io::Result<i32> {
    let mut status = 0;
    // SAFETY: pid 来自刚刚 spawn 的子进程，status 指向栈上有效内存。
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(status)
    }
}

#[cfg(target_os = "macos")]
fn spawn_memory_watchdog(
    pid: libc::pid_t,
    memory_limit_bytes: u64,
    child_running: Arc<AtomicBool>,
    oom_killed: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(200));

            if !child_running.load(Ordering::SeqCst) {
                break;
            }

            // SAFETY: RUsageInfoV2 是 repr(C) 且字段均为整数/字节数组，零初始化有效；
            // proc_pidrusage 会按 RUSAGE_INFO_V2 布局写入调用方提供的缓冲区。
            let mut rui: RUsageInfoV2 = unsafe { std::mem::zeroed() };
            // SAFETY: pid 来自刚刚 spawn 的子进程；rui 指向当前线程栈上的有效缓冲区，
            // 按 Darwin API 要求转换为 rusage_info_t 指针输出槽。
            let ret = unsafe {
                proc_pidrusage(
                    pid,
                    RUSAGE_INFO_V2,
                    &mut rui as *mut _ as *mut libc::rusage_info_t,
                )
            };
            if ret != 0 {
                continue;
            }

            let footprint = rui.ri_phys_footprint;
            if footprint <= memory_limit_bytes {
                continue;
            }

            tracing::warn!(
                "Child process memory exceeded (resident: {} bytes, limit: {} bytes), sending SIGTERM",
                footprint,
                memory_limit_bytes
            );
            oom_killed.store(true, Ordering::SeqCst);
            // SAFETY: 负 pid 表示 pre_exec 中为子进程创建的进程组。
            let _ = unsafe { libc::kill(-pid, libc::SIGTERM) };

            thread::sleep(Duration::from_secs(1));

            if child_running.load(Ordering::SeqCst) {
                // SAFETY: 负 pid 表示 pre_exec 中为子进程创建的进程组。
                let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
            }

            break;
        }
    });
}

fn policy_to_cstring(policy: String) -> Result<CString, SandboxError> {
    CString::new(policy).map_err(|_| SandboxError::new("Seatbelt policy contains NUL byte"))
}

fn create_child_process_group() -> std::io::Result<()> {
    // SAFETY: pre_exec 运行在 fork 后、exec 前的子进程；setpgid(0, 0) 只影响当前子进程，
    // 用于让超时清理可以杀掉整个派生进程组。
    let ret = unsafe { libc::setpgid(0, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn close_inherited_fds_from(min_fd: libc::c_int) {
    // SECURITY: 当前 macOS SDK 未导出 closefrom 符号，使用 getdtablesize()+close 等价关闭
    // min_fd 及以上 FD，防止继承文件描述符泄漏到沙箱子进程。
    // SAFETY: getdtablesize 无入参，返回当前进程可用 fd 表大小。
    let max_fd = unsafe { libc::getdtablesize() };
    for fd in min_fd..max_fd {
        // SAFETY: close 对无效/已关闭 fd 只会返回错误；这里在 fork 后子进程中尽力关闭非必要 fd。
        unsafe {
            libc::close(fd);
        }
    }
}

fn configure_pty_controlling_terminal() -> std::io::Result<()> {
    // SAFETY: pre_exec 运行在 fork 后、exec 前的子进程；setsid 只影响当前子进程，
    // 使其成为新会话首进程和进程组 leader。
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    #[allow(clippy::cast_lossless)]
    {
        // SAFETY: Command 已将 PTY slave 连接到 STDIN_FILENO；TIOCSCTTY 让该 slave
        // 成为当前新会话的控制终端，不访问 Rust 托管内存。
        if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn apply_seatbelt_policy_or_exit(profile: *const libc::c_char) {
    let mut errorbuf: *mut libc::c_char = std::ptr::null_mut();
    // SAFETY: profile 指向 fork 前构造并由 pre_exec 闭包捕获的 NUL 结尾 CString；
    // errorbuf 指向当前栈上的有效输出槽，sandbox_init 只在当前子进程应用策略。
    let ret = unsafe { sandbox_init(profile, SANDBOX_LITERAL_PROFILE, &mut errorbuf) };
    if ret == 0 {
        return;
    }

    if !errorbuf.is_null() {
        // SAFETY: sandbox_init 失败时返回的 errorbuf 由系统分配；按 API 要求释放一次。
        unsafe { libc::free(errorbuf.cast::<libc::c_void>()) };
    }

    // SAFETY: STDERR_FILENO 已由 Command 完成重定向；写入静态错误文本不访问悬垂内存。
    let _ = unsafe {
        libc::write(
            libc::STDERR_FILENO,
            SANDBOX_INIT_FAILURE_MESSAGE.as_ptr().cast::<libc::c_void>(),
            SANDBOX_INIT_FAILURE_MESSAGE.len(),
        )
    };

    // SAFETY: Seatbelt 策略未应用时必须立即终止子进程，避免未沙箱化执行用户命令。
    unsafe { libc::_exit(SANDBOX_INIT_FAILURE_EXIT_CODE) };
}

fn wait_child_with_timeout(
    pid: libc::pid_t,
    timeout: Duration,
) -> Result<(std::process::ExitStatus, bool), SandboxError> {
    let (tx, rx) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        let _ = tx.send(waitpid_raw(pid));
    });

    match rx.recv_timeout(timeout) {
        Ok(status) => {
            let _ = waiter.join();
            Ok((
                std::process::ExitStatus::from_raw(
                    status.map_err(|e| SandboxError::new(format!("waitpid failed: {e}")))?,
                ),
                false,
            ))
        }
        Err(RecvTimeoutError::Timeout) => {
            tracing::warn!(
                "Child process timeout ({:.1}s), sending SIGKILL",
                timeout.as_secs_f64()
            );
            // SECURITY: 配置允许 process-fork 时，超时必须回收整个进程组，
            // 否则其派生进程会在 supervisor 返回后继续存活。
            // SAFETY: Negative pid targets the child process group created by pre_exec setpgid.
            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
            let status = rx.recv().map_err(|_| {
                SandboxError::new("waitpid waiter thread disconnected unexpectedly")
            })?;
            let _ = waiter.join();
            Ok((
                std::process::ExitStatus::from_raw(
                    status.map_err(|e| SandboxError::new(format!("waitpid failed: {e}")))?,
                ),
                true,
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = waiter.join();
            Err(SandboxError::new(
                "waitpid monitoring thread disconnected unexpectedly",
            ))
        }
    }
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

fn spawn_output_reader<R>(
    label: &'static str,
    mut reader: R,
    child_pid: libc::pid_t,
    output_limit_triggered: Arc<AtomicBool>,
) -> Receiver<OutputCapture>
where
    R: Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let capture = read_limited_output(&mut reader, label, || {
            if !output_limit_triggered.swap(true, Ordering::SeqCst) {
                // SAFETY: Negative pid targets the child process group created by pre_exec setpgid.
                let _ = unsafe { libc::kill(-child_pid, libc::SIGKILL) };
            }
        });
        let _ = tx.send(capture);
    });

    rx
}

fn receive_output_capture(
    rx: Option<Receiver<OutputCapture>>,
    label: &'static str,
) -> OutputCapture {
    match rx {
        Some(rx) => match rx.recv() {
            Ok(capture) => capture,
            Err(error) => OutputCapture {
                data: Vec::new(),
                truncated: false,
                read_error: Some(format!("{label} reader thread exited abnormally: {error}")),
            },
        },
        None => OutputCapture {
            data: Vec::new(),
            truncated: false,
            read_error: Some(format!("{label} pipe not initialized")),
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

fn normalize_sbpl_path(path: &str) -> String {
    let p = path.trim_end_matches('/');
    match p {
        "/tmp" => "/private/tmp".to_string(),
        "/etc" => "/private/etc".to_string(),
        "/var" => "/private/var".to_string(),
        _ => p.to_string(),
    }
}

/// Validates that a path can be safely embedded in an SBPL string literal.
///
/// Uses an allowlist policy: ASCII letters, digits, the path separator `/`,
/// and common path characters `. _ - + @` are allowed. Spaces, quotes,
/// backslashes, parentheses, NUL bytes, newlines, and other control characters
/// are rejected to prevent Seatbelt policy string injection.
fn validate_sbpl_path(path: &str) -> Result<(), SandboxError> {
    if path.is_empty() {
        return Err(SandboxError::new("path must not be empty"));
    }

    for (i, byte) in path.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => {}
            b'/' | b'.' | b'_' | b'-' | b'+' | b'@' => {}
            _ => {
                let ch = path[i..].chars().next().unwrap_or('?');
                return Err(SandboxError::new(format!(
                    "path contains unsafe character for SBPL: {:?} (byte position {i}). Only alphanumeric, /, ., _, -, +, @ are allowed in sandbox paths.",
                    ch
                )));
            }
        }
    }

    Ok(())
}

fn push_sbpl_subpath(paths: &mut Vec<String>, path: &str) {
    if validate_sbpl_path(path).is_ok() {
        let rule = format!("(subpath \"{}\")", path);
        if !paths.iter().any(|existing| existing == &rule) {
            paths.push(rule);
        }
    }
}

fn push_normalized_sbpl_subpath(paths: &mut Vec<String>, path: &str) {
    let raw = path.trim_end_matches('/');
    let normalized = normalize_sbpl_path(path);
    push_sbpl_subpath(paths, &normalized);
    if raw != normalized {
        push_sbpl_subpath(paths, raw);
    }
    if let Some(suffix) = raw.strip_prefix("/tmp/") {
        push_sbpl_subpath(paths, &format!("/private/tmp/{suffix}"));
    }
    if let Some(suffix) = raw.strip_prefix("/var/") {
        push_sbpl_subpath(paths, &format!("/private/var/{suffix}"));
    }
    if let Some(suffix) = raw.strip_prefix("/etc/") {
        push_sbpl_subpath(paths, &format!("/private/etc/{suffix}"));
    }
}

impl MacOsSandbox {
    /// Generates a Seatbelt policy string from `SandboxConfig`.
    ///
    /// Policy structure using Seatbelt Scheme compiled format version 1:
    /// 1. `(deny default)` — denies all operations by default.
    /// 2. `(allow file-read* (subpath ...))` — permits reads only for minimal system paths, temporary-directory traversal, the sandbox-private temporary directory, and `fs_readonly`/`fs_readwrite` paths.
    /// 3. `(allow file-write* (subpath ...))` — permits writes only for `fs_readwrite` paths; when none are configured, the sandbox-private temporary directory is allowed by default.
    /// 4. `(allow process-exec (subpath ...))` — restricts executable paths.
    /// 5. `(deny process-exec (subpath ...))` — denies execution from writable locations.
    /// 6. `(allow process-fork)` — emitted only when `allow_fork = true`.
    /// 7. `(allow network*)` — emitted only when `deny_network = false`.
    /// 8. `(allow mach-lookup (global-name ...))` — permits only required Mach services.
    #[cfg(test)]
    fn generate_policy(&self) -> String {
        Self::build_seatbelt_policy(&self.config, &self.sandbox_tmp_dir)
    }

    fn build_seatbelt_policy(config: &SandboxConfig, sandbox_tmp_dir: &str) -> String {
        let mut rules = Vec::new();

        rules.push("(version 1)".to_string());
        rules.push("(deny default)".to_string());

        // 仅允许根目录和 /var 符号链接本身，避免为路径遍历而放开整棵目录树。
        let mut read_paths: Vec<String> = vec![
            "(literal \"/\")".to_string(),
            "(literal \"/var\")".to_string(),
        ];
        read_paths.extend(
            SYSTEM_READ_PATHS
                .iter()
                .map(|s| format!("(subpath \"{}\")", s.trim_end_matches('/'))),
        );
        // SECURITY: 显式允许当前沙箱实例的专属临时目录；基础临时目录只放入读取规则用于遍历。
        push_sbpl_subpath(&mut read_paths, sandbox_tmp_dir);
        // 保留基础 /private/tmp 读取权限用于目录遍历（不包含写入权限）。
        push_sbpl_subpath(&mut read_paths, "/private/tmp");
        push_sbpl_subpath(&mut read_paths, "/tmp");

        for path in &config.fs_readonly {
            push_normalized_sbpl_subpath(&mut read_paths, path.to_string_lossy().as_ref());
        }

        for path in &config.fs_readwrite {
            push_normalized_sbpl_subpath(&mut read_paths, path.to_string_lossy().as_ref());
        }

        rules.push(format!("(allow file-read* {})", read_paths.join(" ")));

        let mut write_paths: Vec<String> = Vec::new();
        for path in &config.fs_readwrite {
            push_normalized_sbpl_subpath(&mut write_paths, path.to_string_lossy().as_ref());
        }
        // SECURITY: 仅当用户未配置任何自定义写入路径时，使用沙箱专属临时目录作为默认写入目录。
        if write_paths.is_empty() {
            push_sbpl_subpath(&mut write_paths, sandbox_tmp_dir);
        }
        rules.push(format!("(allow file-write* {})", write_paths.join(" ")));

        // 进程执行：限制为系统与 Homebrew 路径
        let mut exec_paths: Vec<String> = SYSTEM_EXEC_PATHS
            .iter()
            .map(|s| format!("(subpath \"{}\")", s.trim_end_matches('/')))
            .collect();
        exec_paths
            .push("(subpath \"/Applications/Xcode.app/Contents/Developer/usr/bin\")".to_string());
        exec_paths.push("(subpath \"/Library/Developer/CommandLineTools/usr/bin\")".to_string());
        rules.push(format!("(allow process-exec {})", exec_paths.join(" ")));

        // 可写目录禁止执行，防止下载/写入后二进制直接落地执行。
        rules.push("(deny process-exec (subpath \"/private/tmp\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/bin/osascript\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/bin/pbcopy\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/bin/pbpaste\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/sbin/screencapture\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/bin/open\"))".to_string());

        if config.allow_fork {
            rules.push("(allow process-fork)".to_string());
        }

        if !config.deny_network {
            rules.push("(allow network*)".to_string());
        }

        let mach_rules: Vec<String> = ALLOWED_MACH_SERVICES
            .iter()
            .map(|s| format!("(global-name \"{}\")", s))
            .collect();
        rules.push(format!("(allow mach-lookup {})", mach_rules.join(" ")));

        rules.push("(allow pseudo-tty)".to_string());
        rules.push("(allow file-read* file-write* (literal \"/dev/ptmx\"))".to_string());

        rules.push("(allow ipc-posix-sem)".to_string());
        rules.push(
            "(allow ipc-posix-shm-read* (ipc-posix-name-prefix \"apple.cfprefs.\"))".to_string(),
        );

        rules.push(
            "(allow file-write-data (require-all (path \"/dev/null\") (vnode-type CHARACTER-DEVICE)))"
                .to_string(),
        );

        rules.join("\n")
    }
}

impl Sandbox for MacOsSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        config.validate()?;

        tracing::info!(
            "Creating macOS Seatbelt sandbox, deny_network={}, timeout={:?}s, memory={:?}MB",
            config.deny_network,
            config.timeout_secs,
            config.memory_limit_mb,
        );

        if config.memory_limit_mb.is_some() {
            tracing::info!("macOS memory limit will be enforced via watchdog sampling");
        }

        // SECURITY: 创建沙箱专属临时目录，避免多个沙箱实例共享 /private/tmp 导致数据泄露。
        let sandbox_id = Uuid::new_v4();
        let sandbox_tmp_dir = format!("/private/tmp/mimobox-{sandbox_id}");
        std::fs::create_dir_all(&sandbox_tmp_dir)
            .map_err(|e| SandboxError::new(format!("failed to create sandbox tmp dir: {e}")))?;
        std::fs::set_permissions(&sandbox_tmp_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| SandboxError::new(format!("failed to set tmp dir permissions: {e}")))?;

        Ok(Self {
            config,
            sandbox_tmp_dir,
            cached_metrics: None,
        })
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        self.cached_metrics = None;

        if cmd.is_empty() {
            return Err(SandboxError::new("command must not be empty"));
        }

        // SECURITY: 日志仅记录程序基名和参数个数，避免 argv 中的 token、URL、路径泄露。
        tracing::info!("Executing command: {}", command_log_summary(cmd));
        let start = Instant::now();
        let timeout = self.config.timeout_secs.map(Duration::from_secs);

        // 生成 Seatbelt 策略，并在 fork 前转换为 CString，避免 pre_exec 中分配内存。
        let policy = Self::build_seatbelt_policy(&self.config, &self.sandbox_tmp_dir);
        tracing::debug!(
            "Seatbelt policy generated (rules: {}, length: {} bytes)",
            policy.matches("\n").count() + 1,
            policy.len()
        );
        let policy = policy_to_cstring(policy)?;

        // SAFETY: pre_exec 在子进程 exec 前建立独立进程组并应用 Seatbelt 策略；
        // 闭包捕获的 CString 在子进程调用 sandbox_init 时仍然有效。
        let mut child = unsafe {
            Command::new(&cmd[0])
                .args(&cmd[1..])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env_clear()
                // 内置默认 HOME/TMPDIR/PWD 指向沙箱专属目录；随后允许 env_vars 按优先级覆盖。
                .envs(build_safe_child_env(
                    &self.sandbox_tmp_dir,
                    &self.sandbox_tmp_dir,
                    &self.config.env_vars,
                ))
                .current_dir(&self.sandbox_tmp_dir)
                .pre_exec(move || {
                    // SECURITY: 关闭所有从 3 开始的非必要继承 FD，防止文件描述符泄漏到沙箱子进程。
                    // stdin(0)/stdout(1)/stderr(2) 已通过 Stdio 配置设置，不需要保留其他 FD。
                    // SAFETY: 从 min_fd=3 开始关闭所有非 stdio FD；无效 fd 的 close 错误可安全忽略。
                    close_inherited_fds_from(3);
                    create_child_process_group()?;
                    apply_seatbelt_policy_or_exit(policy.as_ptr());
                    Ok(())
                })
                .spawn()
        }
        .map_err(|e| SandboxError::new(format!("failed to start sandboxed command: {e}")))?;
        let pid = child.id() as libc::pid_t;

        let child_running = Arc::new(AtomicBool::new(true));
        let oom_killed = Arc::new(AtomicBool::new(false));
        if let Some(memory_limit_mb) = self.config.memory_limit_mb {
            let memory_limit_bytes = memory_limit_mb
                .checked_mul(1024)
                .and_then(|value| value.checked_mul(1024))
                .ok_or_else(|| {
                    SandboxError::new(format!(
                        "memory_limit_mb={memory_limit_mb} overflowed while converting to bytes"
                    ))
                })?;
            spawn_memory_watchdog(
                pid,
                memory_limit_bytes,
                Arc::clone(&child_running),
                Arc::clone(&oom_killed),
            );
        }

        let output_limit_triggered = Arc::new(AtomicBool::new(false));
        let stdout_rx = child.stdout.take().map(|stdout| {
            spawn_output_reader("stdout", stdout, pid, Arc::clone(&output_limit_triggered))
        });
        let stderr_rx = child.stderr.take().map(|stderr| {
            spawn_output_reader("stderr", stderr, pid, Arc::clone(&output_limit_triggered))
        });

        let wait_result = if let Some(dur) = timeout {
            wait_child_with_timeout(pid, dur)
        } else {
            waitpid_raw(pid)
                .map(|status| (std::process::ExitStatus::from_raw(status), false))
                .map_err(|e| SandboxError::new(format!("waitpid failed: {e}")))
        };
        child_running.store(false, Ordering::SeqCst);
        let (exit_status, mut timed_out) = wait_result?;
        self.cached_metrics = Some(sample_metrics(pid, self.config.memory_limit_mb));
        if oom_killed.load(Ordering::SeqCst) {
            timed_out = true;
        }

        let elapsed = start.elapsed();

        let stdout_capture = receive_output_capture(stdout_rx, "stdout");
        let stderr_capture = receive_output_capture(stderr_rx, "stderr");
        log_output_read_error("stdout", &stdout_capture);
        log_output_read_error("stderr", &stderr_capture);

        let stdout_truncated = stdout_capture.truncated;
        let stderr_truncated = stderr_capture.truncated;
        let stdout_buf = stdout_capture.data;
        let mut stderr_buf = stderr_capture.data;
        append_output_truncation_marker(&mut stderr_buf, stdout_truncated, stderr_truncated);

        let exit_code = exit_status.code();

        if let Some(reason) = detect_seatbelt_backend_failure(exit_code, &stderr_buf) {
            return Err(SandboxError::new(reason));
        }

        tracing::info!(
            "Child process exited, code={:?}, elapsed={:.2}ms, timed_out={timed_out}",
            exit_code,
            elapsed.as_secs_f64() * 1000.0,
        );

        Ok(SandboxResult {
            stdout: stdout_buf,
            stderr: stderr_buf,
            exit_code,
            elapsed,
            timed_out,
        })
    }

    fn create_pty(
        &mut self,
        config: mimobox_core::PtyConfig,
    ) -> Result<Box<dyn mimobox_core::PtySession>, SandboxError> {
        if config.command.is_empty() {
            return Err(SandboxError::new("PTY command must not be empty"));
        }

        tracing::info!(
            "Creating macOS PTY session: {}",
            command_log_summary(&config.command)
        );

        let allocated = allocate_pty(config.size)?;
        let policy = Self::build_seatbelt_policy(&self.config, &self.sandbox_tmp_dir);
        tracing::debug!(
            "PTY Seatbelt policy generated (rules: {}, length: {} bytes)",
            policy.matches("\n").count() + 1,
            policy.len()
        );
        let policy = policy_to_cstring(policy)?;

        let slave_file = File::options()
            .read(true)
            .write(true)
            .open(&allocated.slave_path)
            .map_err(|error| SandboxError::new(format!("failed to open PTY slave: {error}")))?;
        let stdin_slave = slave_file
            .try_clone()
            .map_err(|error| SandboxError::new(format!("failed to clone PTY stdin: {error}")))?;
        let stdout_slave = slave_file
            .try_clone()
            .map_err(|error| SandboxError::new(format!("failed to clone PTY stdout: {error}")))?;

        let pwd = config
            .cwd
            .clone()
            .unwrap_or_else(|| self.sandbox_tmp_dir.clone());
        let mut child_env =
            build_safe_child_env(&self.sandbox_tmp_dir, &pwd, &self.config.env_vars);
        child_env.extend(
            config
                .env
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );

        let mut command = Command::new(&config.command[0]);
        command
            .args(&config.command[1..])
            .env_clear()
            .envs(child_env)
            .stdin(Stdio::from(stdin_slave))
            .stdout(Stdio::from(stdout_slave))
            .stderr(Stdio::from(slave_file));

        command.current_dir(config.cwd.as_deref().unwrap_or(&self.sandbox_tmp_dir));

        // SAFETY: pre_exec 在子进程 exec 前接管 PTY 并应用 Seatbelt 策略；
        // 闭包捕获的 CString 在 sandbox_init 调用期间有效。
        let child = unsafe {
            command.pre_exec(move || {
                // SECURITY: 关闭所有从 3 开始的非必要继承 FD，防止文件描述符泄漏到沙箱子进程。
                // PTY slave 已通过 Stdio::from() 传递给 stdin/stdout/stderr，关闭 3+ FD 安全。
                // SAFETY: 从 min_fd=3 开始关闭所有非 stdio FD；无效 fd 的 close 错误可安全忽略。
                close_inherited_fds_from(3);
                configure_pty_controlling_terminal()?;
                apply_seatbelt_policy_or_exit(policy.as_ptr());
                Ok(())
            })
        }
        .spawn()
        .map_err(|error| SandboxError::new(format!("failed to start sandboxed PTY: {error}")))?;

        Ok(build_session(
            allocated,
            child.id() as libc::pid_t,
            config.timeout,
        ))
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

    fn destroy(self) -> Result<(), SandboxError> {
        tracing::debug!("Destroying macOS Seatbelt sandbox");
        Ok(())
    }
}

impl Drop for MacOsSandbox {
    fn drop(&mut self) {
        // SECURITY: 沙箱销毁时清理专属临时目录，防止数据残留。
        if !self.sandbox_tmp_dir.is_empty() {
            if let Err(e) = std::fs::remove_dir_all(&self.sandbox_tmp_dir) {
                tracing::warn!(
                    "Failed to clean sandbox temporary directory: {} - {}",
                    self.sandbox_tmp_dir,
                    e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier, OnceLock};

    use super::*;
    use mimobox_core::{Sandbox, SandboxConfig};
    use tempfile::TempDir;

    /// Creates the default macOS test configuration without memory limits to keep tests focused on Seatbelt behavior.
    fn test_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.memory_limit_mb = None;
        config.allow_fork = true;
        config
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

    fn path_to_string(path: &std::path::Path) -> String {
        path.to_str().expect("test path must be UTF-8").to_string()
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', r#"'\''"#))
    }

    fn system_file_read_rule() -> String {
        let mut read_paths = vec![
            "(literal \"/\")".to_string(),
            "(literal \"/var\")".to_string(),
        ];
        read_paths.extend(
            SYSTEM_READ_PATHS
                .iter()
                .map(|path| format!("(subpath \"{}\")", path.trim_end_matches('/'))),
        );
        let read_paths = read_paths.join(" ");
        format!("(allow file-read* {read_paths})")
    }

    fn write_file_command(path: &std::path::Path, content: &str) -> Vec<String> {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "/usr/bin/printf %s {} > {}",
                shell_quote(content),
                shell_quote(&path_to_string(path))
            ),
        ]
    }

    fn should_skip_runtime_tests() -> bool {
        if let Some(reason) = seatbelt_runtime_skip_reason() {
            eprintln!("skipping macOS Seatbelt runtime tests: {reason}");
            return true;
        }

        false
    }

    fn seatbelt_runtime_skip_reason() -> Option<&'static str> {
        static SKIP_REASON: OnceLock<Option<String>> = OnceLock::new();

        SKIP_REASON
            .get_or_init(|| {
                let output = match Command::new("sandbox-exec")
                    .args(["-p", "(version 1) (allow default)", "/usr/bin/true"])
                    .output()
                {
                    Ok(output) => output,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        return Some("sandbox-exec not found in current environment".to_string());
                    }
                    Err(err) => {
                        panic!("failed to run sandbox-exec minimal probe: {err}");
                    }
                };

                if output.status.success() {
                    return None;
                }

                if let Some(reason) =
                    detect_seatbelt_backend_failure(output.status.code(), &output.stderr)
                {
                    return Some(reason);
                }

                panic!(
                    "sandbox-exec minimal probe failed unexpectedly: status={:?}, stderr={}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                );
            })
            .as_deref()
    }

    fn assert_execute_env_is_sanitized() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        let result = sb
            .execute(&["/usr/bin/env".to_string()])
            .expect("failed to execute env");

        assert_eq!(
            result.exit_code,
            Some(0),
            "env should succeed, stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );

        let stdout = String::from_utf8(result.stdout).expect("env output must be UTF-8");

        for prefix in ["DYLD_", "SSH_", "AWS_", "GPG_"] {
            assert!(
                !stdout.lines().any(|line| line.starts_with(prefix)),
                "child environment should not contain variables with {prefix} prefix, actual output:\n{stdout}"
            );
        }

        for key in ["LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV"] {
            let needle = format!("{key}=");
            assert!(
                !stdout.lines().any(|line| line.starts_with(&needle)),
                "child environment should not contain {key}, actual output:\n{stdout}"
            );
        }

        assert!(
            stdout.lines().any(|line| line == "USER=sandbox"),
            "child environment should set USER=sandbox, actual output:\n{stdout}"
        );
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with("HOME=/private/tmp/mimobox-")),
            "SECURITY: child HOME should be set to the sandbox-private temporary directory, actual output:\n{stdout}"
        );
    }

    #[test]
    fn test_execute_env_is_sanitized() {
        const HELPER_ENV: &str = "MIMOBOX_EXEC_ENV_SANITIZE_HELPER";

        if std::env::var_os(HELPER_ENV).is_some() {
            assert_execute_env_is_sanitized();
            return;
        }

        if should_skip_runtime_tests() {
            return;
        }

        let output =
            Command::new(std::env::current_exe().expect("failed to get current test binary path"))
                .arg("test_execute_env_is_sanitized")
                .arg("--nocapture")
                .env(HELPER_ENV, "1")
                .env("DYLD_MIMOBOX_TEST_SECRET", "1")
                .env("LD_PRELOAD", "/tmp/mimobox-preload-test")
                .env("LD_LIBRARY_PATH", "/tmp/mimobox-library-path-test")
                .env("SSH_AUTH_SOCK", "/tmp/mimobox-ssh-agent-test")
                .env("AWS_SECRET_ACCESS_KEY", "mimobox-test-secret")
                .env("GPG_AGENT_INFO", "mimobox-test-secret")
                .env("BASH_ENV", "/tmp/mimobox-bash-env-test")
                .env("ENV", "/tmp/mimobox-env-test")
                .output()
                .expect("failed to run environment sanitization subtest");

        assert!(
            output.status.success(),
            "environment sanitization subtest failed, status={:?}, stdout: {}, stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_file_exists_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("file_exists", sb.file_exists("/tmp/mimobox_exists_test"));
    }

    #[test]
    fn test_remove_file_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("remove_file", sb.remove_file("/tmp/mimobox_remove_test"));
    }

    #[test]
    fn test_rename_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation(
            "rename",
            sb.rename("/tmp/mimobox_rename_src", "/tmp/mimobox_rename_dst"),
        );
    }

    #[test]
    fn test_stat_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("stat", sb.stat("/tmp/mimobox_stat_test"));
    }

    #[test]
    fn test_detect_seatbelt_backend_failure() {
        let stderr = b"sandbox-exec: sandbox_apply: Operation not permitted\n";
        let reason = detect_seatbelt_backend_failure(Some(71), stderr);

        assert!(
            reason
                .as_deref()
                .is_some_and(|value| value.contains("Seatbelt policy enforcement failed")),
            "should detect Seatbelt backend error, actual: {reason:?}"
        );
    }

    #[test]
    fn test_regular_exit_code_71_is_not_backend_failure() {
        let reason = detect_seatbelt_backend_failure(Some(71), b"child failed\n");
        assert!(
            reason.is_none(),
            "regular exit code 71 should not be misclassified"
        );
    }

    #[test]
    fn test_detect_seatbelt_backend_failure_redacts_sensitive_stderr() {
        let stderr =
            br#"sandbox-exec: sandbox_apply: Operation not permitted for /Users/alice/.ssh/id_rsa
"#;
        let reason = detect_seatbelt_backend_failure(Some(71), stderr)
            .expect("should detect Seatbelt backend error");

        assert!(
            !reason.contains("/Users/alice/.ssh/id_rsa"),
            "error message should not leak sensitive path: {reason}"
        );
        assert!(
            reason.contains("Seatbelt policy enforcement failed"),
            "error message should preserve high-level semantics: {reason}"
        );
    }

    #[test]
    fn test_validate_sbpl_path_accepts_normal_paths() {
        assert!(
            validate_sbpl_path("/tmp/sandbox").is_ok(),
            "normal path should pass validation"
        );
        assert!(
            validate_sbpl_path("/usr/local/bin/my-app_v2.1").is_ok(),
            "path containing . _ - should pass validation"
        );
        assert!(
            validate_sbpl_path("/tmp/test+flag@host").is_ok(),
            "path containing + @ should pass validation"
        );
    }

    #[test]
    fn test_validate_sbpl_path_rejects_double_quote() {
        let result = validate_sbpl_path("/path/with\"quote");
        assert!(
            result.is_err(),
            "path containing double quote should be rejected"
        );
        assert!(
            result
                .expect_err("path containing double quote should be rejected")
                .to_string()
                .contains("unsafe character"),
            "error message should explain the unsafe character"
        );
    }

    #[test]
    fn test_validate_sbpl_path_rejects_backslash() {
        let result = validate_sbpl_path("/path\\with\\backslash");
        assert!(
            result.is_err(),
            "path containing backslash should be rejected"
        );
    }

    #[test]
    fn test_validate_sbpl_path_rejects_injection_attempt() {
        let result = validate_sbpl_path(
            "/path\")(allow process-exec (subpath \"/usr/bin\")(allow file-read* (subpath \"/",
        );
        assert!(result.is_err(), "injection attempt should be rejected");
    }

    #[test]
    fn test_validate_sbpl_path_rejects_newline() {
        let result = validate_sbpl_path("/tmp/path\nwith\nnewline");
        assert!(
            result.is_err(),
            "path containing newline should be rejected"
        );
    }

    #[test]
    fn test_validate_sbpl_path_rejects_null_byte() {
        let result = validate_sbpl_path("/tmp/path\0with\0null");
        assert!(
            result.is_err(),
            "path containing NUL byte should be rejected"
        );
    }

    #[test]
    fn test_validate_sbpl_path_rejects_empty() {
        let result = validate_sbpl_path("");
        assert!(result.is_err(), "empty path should be rejected");
    }

    #[test]
    fn test_validate_sbpl_path_rejects_parentheses() {
        assert!(
            validate_sbpl_path("/tmp/path(with").is_err(),
            "path containing parentheses should be rejected"
        );
        assert!(
            validate_sbpl_path("/tmp/path)with").is_err(),
            "path containing closing parenthesis should be rejected"
        );
    }

    #[test]
    fn test_command_log_summary_edge_cases() {
        assert_eq!(command_log_summary(&[]), "<empty>");
        assert_eq!(
            command_log_summary(&["/bin/echo".to_string(), "secret-token".to_string()]),
            "program=echo, argc=2"
        );
        assert_eq!(
            command_log_summary(&["/".to_string()]),
            "program=<command>, argc=1"
        );
        assert_eq!(
            command_log_summary(&["".to_string(), "arg".to_string()]),
            "program=<command>, argc=2"
        );
    }

    #[test]
    fn test_policy_generation_allows_network_when_deny_network_false() {
        let mut config = SandboxConfig::default();
        config.deny_network = false;
        let sb = MacOsSandbox::new(config).expect("failed to create sandbox");
        let policy = sb.generate_policy();

        assert!(
            policy.contains("(allow network*)"),
            "policy should explicitly allow network when deny_network=false"
        );
        assert!(
            !policy.contains("(deny network*)"),
            "policy should not explicitly deny network when deny_network=false"
        );

        let default_policy = MacOsSandbox::new(SandboxConfig::default())
            .expect("failed to create default sandbox")
            .generate_policy();
        assert!(
            !default_policy.contains("(allow network*)"),
            "default deny_network=true policy should not allow network"
        );
    }

    #[test]
    fn test_list_dir_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("list_dir", sb.list_dir("/tmp"));
    }

    #[test]
    fn test_stat_on_directory_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("stat", sb.stat("/tmp/mimobox-stat-dir"));
    }

    #[test]
    fn test_remove_directory_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        assert_unsupported_operation("remove_file", sb.remove_file("/tmp/mimobox-remove-dir"));
    }

    #[test]
    fn test_double_destroy_safety_for_noop_destroy() {
        let sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        sb.destroy().expect("first destroy should not fail");

        let sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox again");
        sb.destroy()
            .expect("destroying an independent sandbox twice should not fail");
    }

    #[test]
    fn test_pty_empty_command_error() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        let result = sb.create_pty(mimobox_core::PtyConfig {
            command: Vec::new(),
            size: mimobox_core::PtySize::default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: Some(Duration::from_secs(1)),
        });

        let Err(error) = result else {
            panic!("empty PTY command should return an error");
        };
        assert!(
            error.to_string().contains("PTY command must not be empty"),
            "error message should mention empty PTY command, actual: {error}"
        );
    }

    #[test]
    fn test_concurrent_sandboxes_execute_in_parallel() {
        if should_skip_runtime_tests() {
            return;
        }

        let thread_count = 4;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = Vec::new();

        for index in 0..thread_count {
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();

                let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
                let cmd = vec!["/bin/echo".to_string(), format!("sandbox-{index}")];
                let result = sb.execute(&cmd).expect("concurrent execution failed");

                assert_eq!(
                    result.exit_code,
                    Some(0),
                    "concurrent command should succeed"
                );
                String::from_utf8(result.stdout)
                    .expect("stdout should be UTF-8")
                    .trim()
                    .to_string()
            }));
        }

        let mut outputs = handles
            .into_iter()
            .map(|handle| handle.join().expect("concurrent test thread panicked"))
            .collect::<Vec<_>>();
        outputs.sort();

        let expected = (0..thread_count)
            .map(|index| format!("sandbox-{index}"))
            .collect::<Vec<_>>();
        assert_eq!(outputs, expected);
    }

    #[test]
    fn test_large_stdout_seq_10000() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        let cmd = vec![
            "/usr/bin/seq".to_string(),
            "1".to_string(),
            "10000".to_string(),
        ];
        let result = sb.execute(&cmd).expect("failed to execute seq");

        assert_eq!(result.exit_code, Some(0), "seq should succeed");
        let stdout = String::from_utf8(result.stdout).expect("stdout should be UTF-8");
        assert_eq!(
            stdout.lines().count(),
            10000,
            "stdout should contain 10000 lines"
        );
        assert!(stdout.starts_with("1\n"), "stdout should start with 1");
        assert!(
            stdout.trim_end().ends_with("10000"),
            "stdout should end with 10000"
        );
    }

    #[test]
    fn test_special_chars_in_command_arguments() {
        if should_skip_runtime_tests() {
            return;
        }

        let payload = r#"spaces and symbols: !@#$%^&*()[]{};:'",.<>/?\|`~"#;
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        let cmd = vec![
            "/usr/bin/printf".to_string(),
            "%s\n".to_string(),
            payload.to_string(),
        ];
        let result = sb.execute(&cmd).expect("failed to execute printf");

        assert_eq!(result.exit_code, Some(0), "printf should succeed");
        assert_eq!(result.stdout, format!("{payload}\n").into_bytes());
    }

    #[test]
    fn test_write_to_system_path_denied() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut config = test_config();
        config.fs_readwrite = vec!["/tmp".into()];
        let mut sb = MacOsSandbox::new(config).expect("failed to create sandbox");
        let target = format!("/System/mimobox_write_denied_{}", std::process::id());
        let cmd = vec!["/usr/bin/touch".to_string(), target.clone()];
        let result = sb.execute(&cmd).expect("failed to execute touch");

        assert_ne!(
            result.exit_code,
            Some(0),
            "writing to system path should fail, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            !std::path::Path::new(&target).exists(),
            "system path should not be created"
        );
    }

    #[test]
    fn test_sensitive_path_read_denied_via_seatbelt() {
        if should_skip_runtime_tests() {
            return;
        }

        // 在 /Users 下创建测试文件
        let home = std::env::var("HOME").expect("HOME is not set");
        let test_dir = format!("{home}/.mimobox_test_sensitive");
        let secret_file = format!("{test_dir}/secret.txt");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).expect("failed to create test directory");
        fs::write(&secret_file, "super-secret").expect("failed to write sensitive file");

        let policy = vec![
            "(version 1)".to_string(),
            "(deny default)".to_string(),
            system_file_read_rule(),
            "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\"))".to_string(),
            "(allow process-fork)".to_string(),
        ]
        .join("\n");
        let output = Command::new("sandbox-exec")
            .args([
                "-p",
                policy.as_str(),
                "--",
                "/bin/cat",
                secret_file.as_str(),
            ])
            .output()
            .expect("failed to execute sandbox-exec");

        // 清理
        let _ = fs::remove_dir_all(&test_dir);
        assert!(
            !output.status.success(),
            "Seatbelt should deny reading files under /Users, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("super-secret"),
            "sensitive content should not appear in stdout"
        );
    }

    #[test]
    fn test_sensitive_path_stat_denied_via_seatbelt() {
        if should_skip_runtime_tests() {
            return;
        }

        let home = std::env::var("HOME").expect("HOME is not set");
        let test_dir = format!("{home}/.mimobox_test_stat");
        let secret_file = format!("{test_dir}/secret.txt");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).expect("failed to create test directory");
        fs::write(&secret_file, "super-secret").expect("failed to write sensitive file");

        let policy = vec![
            "(version 1)".to_string(),
            "(deny default)".to_string(),
            system_file_read_rule(),
            "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\"))".to_string(),
            "(allow process-fork)".to_string(),
        ]
        .join("\n");
        // deny-default 模式下，未加入 allowlist 的用户路径元数据也应被拒绝。
        let sensitive_path = test_dir.clone();
        let list_output = Command::new("sandbox-exec")
            .args([
                "-p",
                policy.as_str(),
                "--",
                "/bin/ls",
                "-ld",
                sensitive_path.as_str(),
            ])
            .output()
            .expect("failed to execute sandbox-exec ls");

        assert!(
            !list_output.status.success(),
            "Seatbelt should deny reading metadata for non-allowlisted directories, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&list_output.stdout),
            String::from_utf8_lossy(&list_output.stderr)
        );

        // 但读取文件内容应被拒绝
        let cat_output = Command::new("sandbox-exec")
            .args([
                "-p",
                policy.as_str(),
                "--",
                "/bin/cat",
                secret_file.as_str(),
            ])
            .output()
            .expect("failed to execute sandbox-exec cat");

        assert!(
            !cat_output.status.success(),
            "Seatbelt should deny reading file contents, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&cat_output.stdout),
            String::from_utf8_lossy(&cat_output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&cat_output.stdout).contains("super-secret"),
            "sensitive content should not appear in stdout"
        );
        // 清理
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_exec_from_tmp_denied_via_seatbelt() {
        if should_skip_runtime_tests() {
            return;
        }

        let temp_dir = TempDir::new_in("/tmp").expect("failed to create /tmp temp directory");
        let script_path = temp_dir.path().join("test_exec.sh");
        fs::write(&script_path, "#!/bin/sh\necho hello\n").expect("failed to write test script");

        let mut permissions = fs::metadata(&script_path)
            .expect("failed to read test script permissions")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions)
            .expect("failed to set test script executable permissions");

        let policy = vec![
            "(version 1)".to_string(),
            "(deny default)".to_string(),
            system_file_read_rule(),
            "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\"))".to_string(),
            "(deny process-exec (subpath \"/private/tmp\"))".to_string(),
            "(allow process-fork)".to_string(),
        ]
        .join("\n");
        let script = path_to_string(&script_path);
        let output = Command::new("sandbox-exec")
            .args(["-p", policy.as_str(), "--", script.as_str()])
            .output()
            .expect("failed to execute sandbox-exec test script");

        assert!(
            !output.status.success(),
            "Seatbelt should deny executing scripts under /tmp, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("hello"),
            "denied script should not output hello"
        );
    }

    #[test]
    fn test_sandbox_isolation_between_instances() {
        if should_skip_runtime_tests() {
            return;
        }

        let dir_one = TempDir::new_in("/tmp").expect("failed to create first temp directory");
        let dir_two = TempDir::new_in("/tmp").expect("failed to create second temp directory");

        let mut config_one = test_config();
        config_one.fs_readwrite = vec![
            dir_one
                .path()
                .canonicalize()
                .expect("canonicalize failed")
                .into(),
        ];
        let mut config_two = test_config();
        config_two.fs_readwrite = vec![
            dir_two
                .path()
                .canonicalize()
                .expect("canonicalize failed")
                .into(),
        ];

        let mut sb_one = MacOsSandbox::new(config_one).expect("failed to create first sandbox");
        let mut sb_two = MacOsSandbox::new(config_two).expect("failed to create second sandbox");

        let own_one = dir_one.path().join("owned-by-one.txt");
        let own_two = dir_two.path().join("owned-by-two.txt");
        let result_one = sb_one
            .execute(&write_file_command(&own_one, "one"))
            .expect("first sandbox failed to write to its own directory");
        let result_two = sb_two
            .execute(&write_file_command(&own_two, "two"))
            .expect("second sandbox failed to write to its own directory");

        assert_eq!(
            result_one.exit_code,
            Some(0),
            "first sandbox should be able to write to its own directory"
        );
        assert_eq!(
            result_two.exit_code,
            Some(0),
            "second sandbox should be able to write to its own directory"
        );
        assert_eq!(
            fs::read_to_string(&own_one).expect("failed to read own file"),
            "one"
        );
        assert_eq!(
            fs::read_to_string(&own_two).expect("failed to read own file"),
            "two"
        );

        let blocked_by_one = dir_two.path().join("blocked-by-one.txt");
        let blocked_by_two = dir_one.path().join("blocked-by-two.txt");
        let denied_one = sb_one
            .execute(&write_file_command(&blocked_by_one, "blocked"))
            .expect("first sandbox unauthorized write command failed to execute");
        let denied_two = sb_two
            .execute(&write_file_command(&blocked_by_two, "blocked"))
            .expect("second sandbox unauthorized write command failed to execute");

        assert_ne!(
            denied_one.exit_code,
            Some(0),
            "first sandbox should not write to the second sandbox directory"
        );
        assert_ne!(
            denied_two.exit_code,
            Some(0),
            "second sandbox should not write to the first sandbox directory"
        );
        assert!(
            !blocked_by_one.exists(),
            "unauthorized file should not be created"
        );
        assert!(
            !blocked_by_two.exists(),
            "unauthorized file should not be created"
        );
    }

    #[test]
    fn test_sandbox_create_and_execute() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        let cmd = vec!["/bin/echo".to_string(), "hello macos test".to_string()];
        let result = sb.execute(&cmd).expect("execution failed");

        assert!(!result.timed_out, "should not time out");
        assert_eq!(result.exit_code, Some(0), "exit code should be 0");
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("hello macos test"),
            "stdout should contain output, actual: {stdout}"
        );
    }

    #[test]
    fn test_nonzero_exit_code() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 42".to_string(),
        ];
        let result = sb.execute(&cmd).expect("execution failed");

        assert_eq!(result.exit_code, Some(42), "exit code should be 42");
    }

    #[test]
    fn test_timeout() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut config = test_config();
        config.timeout_secs = Some(1);
        let mut sb = MacOsSandbox::new(config).expect("failed to create sandbox");

        let cmd = vec!["/bin/sleep".to_string(), "60".to_string()];
        let result = sb.execute(&cmd).expect("execution failed");

        assert!(result.timed_out, "should time out");
    }

    #[test]
    fn test_empty_command_error() {
        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        let result = sb.execute(&[]);
        assert!(result.is_err(), "empty command should return an error");
    }

    #[test]
    fn test_policy_generation() {
        let sb = MacOsSandbox::new(SandboxConfig::default()).expect("failed to create sandbox");
        let policy = sb.generate_policy();
        let read_line = policy
            .lines()
            .find(|line| line.starts_with("(allow file-read*") && !line.contains("file-write*"))
            .expect("should generate file-read allow rule");
        let write_line = policy
            .lines()
            .find(|line| line.starts_with("(allow file-write*"))
            .expect("should generate file-write allow rule");

        assert!(
            policy.contains("(version 1)"),
            "policy should contain version 1"
        );
        assert!(
            policy.contains("(deny default)"),
            "policy should contain deny default"
        );
        assert!(
            policy.contains("(subpath \"/usr/lib\")"),
            "policy should contain the minimal system read allowlist"
        );
        assert!(
            !policy.contains("(allow file-read*)"),
            "policy should not contain global file-read* allow"
        );
        assert!(
            !policy.contains("(deny file-read-data (subpath \"/Users\"))"),
            "deny-default mode should not need an extra /Users content read denial"
        );
        assert_eq!(
            read_line.matches("(subpath \"/private/tmp\")").count(),
            1,
            "file-read rule should contain exactly one /private/tmp traversal permission"
        );
        assert_eq!(
            read_line.matches("(subpath \"/tmp\")").count(),
            1,
            "file-read rule should contain exactly one /tmp traversal permission"
        );
        assert!(
            !write_line.contains("(subpath \"/private/tmp\")"),
            "default file-write rule should not allow all of /private/tmp"
        );
        assert!(
            !write_line.contains("(subpath \"/tmp\")"),
            "default file-write rule should not allow all of /tmp"
        );
        assert!(
            !policy.contains("(allow network*)"),
            "default deny_network=true should not allow network"
        );
        assert!(
            policy.contains("(global-name \"com.apple.logd\")"),
            "policy should contain the Mach service allowlist"
        );
        assert!(
            policy.contains("(allow process-exec"),
            "policy should contain process execution restrictions"
        );
        assert!(
            !policy.contains("(allow process-fork)"),
            "default allow_fork=false should not allow process fork"
        );
        assert!(
            policy.contains("(deny process-exec (subpath \"/private/tmp\"))"),
            "policy should deny execution from /private/tmp"
        );
        assert!(
            policy.contains("(allow pseudo-tty)"),
            "policy should include PTY support"
        );
        assert!(
            policy.contains("(allow file-read* file-write* (literal \"/dev/ptmx\"))"),
            "policy should allow reading and writing /dev/ptmx"
        );
        assert!(
            policy.contains("(allow ipc-posix-sem)"),
            "policy should include POSIX semaphore IPC support"
        );
        for blocked_tool in [
            "/usr/bin/osascript",
            "/usr/bin/pbcopy",
            "/usr/bin/pbpaste",
            "/usr/sbin/screencapture",
            "/usr/bin/open",
        ] {
            assert!(
                policy.contains(&format!("(deny process-exec (literal \"{blocked_tool}\"))")),
                "policy should deny executing high-risk system tool {blocked_tool}"
            );
        }
        assert!(
            policy.contains("(subpath \"/usr/local/bin\")"),
            "policy should allow execution from the Intel Homebrew bin path"
        );
        assert!(
            policy.contains("(subpath \"/opt/homebrew/bin\")"),
            "policy should allow execution from the Apple Silicon Homebrew bin path"
        );
        assert!(
            policy.contains("(subpath \"/Applications/Xcode.app/Contents/Developer/usr/bin\")"),
            "policy should allow execution from the Xcode Developer toolchain path"
        );
        assert!(
            policy.contains("(subpath \"/Library/Developer/CommandLineTools/usr/bin\")"),
            "policy should allow execution from the CommandLineTools toolchain path"
        );
        assert!(
            policy.contains(&format!("(subpath \"{}\")", sb.sandbox_tmp_dir)),
            "SECURITY: policy should allow writing to the sandbox-private temporary directory"
        );
    }

    #[test]
    fn test_policy_generation_uses_explicit_readwrite_allowlist() {
        let mut config = SandboxConfig::default();
        config.fs_readwrite = vec!["/tmp/mimobox-rw".into()];
        config.memory_limit_mb = None;
        config.timeout_secs = Some(10);
        let sb = MacOsSandbox::new(config).expect("failed to create sandbox");
        let policy = sb.generate_policy();
        let read_line = policy
            .lines()
            .find(|line| line.starts_with("(allow file-read*") && !line.contains("file-write*"))
            .expect("should generate file-read allow rule");
        let write_line = policy
            .lines()
            .find(|line| line.starts_with("(allow file-write*"))
            .expect("should generate file-write allow rule");

        assert!(
            read_line.contains("(subpath \"/tmp/mimobox-rw\")"),
            "read-write allowlist should be written to the file-read allow rule"
        );
        assert!(
            write_line.contains("(subpath \"/tmp/mimobox-rw\")"),
            "read-write allowlist should be written to the file-write allow rule"
        );
    }

    #[test]
    fn test_policy_generation_fs_readonly_in_read_allowlist() {
        let mut config = SandboxConfig::default();
        config.fs_readonly = vec!["/tmp/readonly-data".into()];
        let sb = MacOsSandbox::new(config).expect("failed to create sandbox");
        let policy = sb.generate_policy();
        let read_line = policy
            .lines()
            .find(|line| line.starts_with("(allow file-read*") && !line.contains("file-write*"))
            .expect("should generate file-read allow rule");
        let write_line = policy
            .lines()
            .find(|line| line.starts_with("(allow file-write*"))
            .expect("should generate file-write allow rule");

        assert!(
            policy.contains("(subpath \"/tmp/readonly-data\")"),
            "read-only path should be written to the Seatbelt policy"
        );
        assert!(
            read_line.contains("(subpath \"/tmp/readonly-data\")"),
            "read-only path should appear only in the file-read allow rule"
        );
        assert!(
            !write_line.contains("(subpath \"/tmp/readonly-data\")"),
            "read-only path should not appear in the file-write allow rule"
        );
    }

    #[test]
    fn test_policy_generation_deny_fork_when_config_false() {
        let sb = MacOsSandbox::new(SandboxConfig::default()).expect("failed to create sandbox");
        let policy = sb.generate_policy();

        assert!(
            !policy.contains("(allow process-fork)"),
            "allow_fork=false should not generate a process-fork allow rule"
        );
    }

    #[test]
    fn test_policy_generation_allow_fork_when_config_true() {
        let mut config = SandboxConfig::default();
        config.allow_fork = true;
        let sb = MacOsSandbox::new(config).expect("failed to create sandbox");
        let policy = sb.generate_policy();

        assert!(
            policy.contains("(allow process-fork)"),
            "allow_fork=true should generate a process-fork allow rule"
        );
    }

    #[test]
    fn test_policy_generation_no_global_file_read() {
        let sb = MacOsSandbox::new(SandboxConfig::default()).expect("failed to create sandbox");
        let policy = sb.generate_policy();
        let general_file_read_rules = policy
            .lines()
            .filter(|line| line.starts_with("(allow file-read*") && !line.contains("file-write*"))
            .collect::<Vec<_>>();

        assert!(
            !policy
                .lines()
                .any(|line| line.trim() == "(allow file-read*)"),
            "policy should not contain a bare global file-read* allow"
        );
        assert!(
            !general_file_read_rules.is_empty(),
            "policy should generate precise file-read allow rules"
        );
        assert!(
            general_file_read_rules
                .iter()
                .all(|line| line.contains("(subpath ")),
            "file-read allow rules must contain at least one subpath"
        );
    }

    #[test]
    fn test_network_denied() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut config = test_config();
        config.deny_network = true;
        let mut sb = MacOsSandbox::new(config).expect("failed to create sandbox");

        // curl 在网络被拒绝时应失败
        let cmd = vec![
            "/usr/bin/curl".to_string(),
            "--connect-timeout".to_string(),
            "2".to_string(),
            "http://127.0.0.1:1".to_string(),
        ];
        let result = sb.execute(&cmd).expect("execution failed");

        assert!(
            result.exit_code != Some(0),
            "network request should be denied, exit_code: {:?}",
            result.exit_code
        );
    }

    #[test]
    fn test_fs_write_restricted() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut config = test_config();
        config.fs_readwrite = vec!["/tmp".into()];
        let mut sb = MacOsSandbox::new(config).expect("failed to create sandbox");

        // 尝试写入 /usr/local（不在 fs_readwrite 中）
        // 注意：macOS 上 /var 是 /private/var 的符号链接，但 /usr/local 不是
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "/bin/echo test > /usr/local/mimobox_test_write 2>&1; echo exit=$?".to_string(),
        ];
        let result = sb.execute(&cmd).expect("execution failed");

        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        // 写入受限路径应失败（Seatbelt 拒绝或文件系统权限拒绝均可）
        assert!(
            result.exit_code != Some(0)
                || stdout.contains("Operation not permitted")
                || stdout.contains("Permission denied")
                || stdout.contains("Read-only file system")
                || stderr.contains("Operation not permitted"),
            "writing to a restricted path should be denied, stdout: {stdout}, stderr: {stderr}, exit: {:?}",
            result.exit_code
        );
    }

    #[test]
    fn test_fs_write_allowed() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut config = test_config();
        config.fs_readwrite = vec!["/tmp".into()];
        let mut sb = MacOsSandbox::new(config).expect("failed to create sandbox");

        // 写入 /tmp（在 fs_readwrite 中）应成功
        let test_file = format!("/tmp/mimobox_seatbelt_test_{}", std::process::id());
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("/bin/echo ok > {test_file} && /bin/cat {test_file} && /bin/rm {test_file}"),
        ];
        let result = sb.execute(&cmd).expect("execution failed");

        assert_eq!(
            result.exit_code,
            Some(0),
            "writing to /tmp should succeed, stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("ok"),
            "stdout should contain ok, actual: {stdout}"
        );
    }

    #[test]
    fn test_pty_basic_echo() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
        let mut session = sb
            .create_pty(mimobox_core::PtyConfig {
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "printf 'ready\\n'; IFS= read -r line; printf 'reply:%s\\n' \"$line\""
                        .to_string(),
                ],
                size: mimobox_core::PtySize::default(),
                env: std::collections::HashMap::new(),
                cwd: None,
                timeout: Some(Duration::from_secs(5)),
            })
            .expect("failed to create PTY session");

        // 等待 shell 就绪信号，消除竞态条件
        let _ready = read_pty_until(session.output_rx(), b"ready", Duration::from_secs(5));

        session
            .send_input(b"hello-pty\n")
            .expect("failed to send PTY input");

        let output = read_pty_until(
            session.output_rx(),
            b"reply:hello-pty",
            Duration::from_secs(5),
        );
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("reply:hello-pty"),
            "PTY output should contain echo result, actual: {output}"
        );

        assert_eq!(session.wait().expect("failed to wait for PTY exit"), 0);
    }

    #[test]
    fn test_pty_resize() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
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
                cols: 100,
                rows: 32,
            })
            .expect("failed to resize PTY");

        session.kill().expect("failed to terminate PTY session");
        assert!(
            session.wait().expect("failed to wait for PTY exit") < 0,
            "terminated PTY should return a signal exit code"
        );
    }

    #[test]
    fn test_pty_kill() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("failed to create sandbox");
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
        assert!(
            exit_code < 0,
            "kill should return a signal exit code, actual: {exit_code}"
        );
    }

    #[test]
    fn test_sandbox_create_with_memory_limit_warns() {
        // macOS 不支持内存限制，但创建不应失败（仅记录告警日志）
        let mut config = test_config();
        config.memory_limit_mb = Some(256);
        let sb = MacOsSandbox::new(config);
        assert!(
            sb.is_ok(),
            "macOS sandbox creation should not fail because of memory limits"
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
