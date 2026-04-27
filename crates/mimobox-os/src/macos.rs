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
//! | File reads | Allow system + deny user data | macOS process startup depends on many implicit paths; entire /Users directory content reads are denied to protect all user data (credentials, keys, history, etc.). |
//! | File writes | Allowlist | Allows only paths configured in `fs_readwrite` (defaults to `/tmp`). |
//! | Network access | Deny by default | Denies all network operations with `(deny network*)`. |
//! | Process execution | Path-restricted | Allows system and Homebrew executables while denying writable execution locations. |
//! | Process fork | Allowed | Shells and similar commands need to fork child processes. |
//! | Memory limits | Unsupported | `RLIMIT_AS` cannot be reduced from an unlimited value on macOS; a warning is logged instead. |

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use mimobox_core::{DirEntry, FileStat, Sandbox, SandboxConfig, SandboxError, SandboxResult};

use crate::pty::{allocate_pty, build_child_env, build_session};

#[cfg(target_os = "macos")]
// SAFETY: This block declares external C linkage functions from the macOS system library.
// These are standard macOS sandbox API functions (sandbox_init) whose signatures
// match the system headers. The functions are called only within pre_exec closures
// in forked child processes with validated CString pointers, not in multi-threaded contexts.
unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;
}

const SANDBOX_LITERAL_PROFILE: u64 = 0;
const SANDBOX_INIT_FAILURE_EXIT_CODE: i32 = 71;
const SANDBOX_INIT_FAILURE_MESSAGE: &[u8] =
    b"sandbox-exec: sandbox_apply: Operation not permitted\n";
const OUTPUT_SIZE_LIMIT: usize = 4 * 1024 * 1024;
const OUTPUT_READ_CHUNK_SIZE: usize = 8 * 1024;

#[derive(Debug)]
struct OutputCapture {
    data: Vec<u8>,
    truncated: bool,
    read_error: Option<String>,
}

fn build_safe_child_env() -> HashMap<String, String> {
    HashMap::from([
        (
            "PATH".to_string(),
            "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin".to_string(),
        ),
        ("HOME".to_string(), "/tmp".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
        ("USER".to_string(), "sandbox".to_string()),
        ("LOGNAME".to_string(), "sandbox".to_string()),
        ("SHELL".to_string(), "/bin/sh".to_string()),
        ("LANG".to_string(), "C".to_string()),
        ("TMPDIR".to_string(), "/tmp".to_string()),
        ("PWD".to_string(), "/tmp".to_string()),
    ])
}

/// macOS Seatbelt sandbox backend.
///
/// Applies generated Seatbelt policies with `sandbox_init` in child processes before
/// executing the requested command.
///
/// # Platform Limitations
///
/// - File reads are allowed globally because macOS dyld and frameworks depend on many implicit system paths; all /Users directory content reads are denied to protect user data comprehensively.
/// - Memory limits cannot be enforced with `setrlimit(RLIMIT_AS)` because macOS does not support reducing this limit.
pub struct MacOsSandbox {
    config: SandboxConfig,
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

fn policy_to_cstring(policy: String) -> Result<CString, SandboxError> {
    CString::new(policy)
        .map_err(|_| SandboxError::ExecutionFailed("Seatbelt policy contains NUL byte".to_string()))
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
                    status.map_err(|e| {
                        SandboxError::ExecutionFailed(format!("waitpid failed: {e}"))
                    })?,
                ),
                false,
            ))
        }
        Err(RecvTimeoutError::Timeout) => {
            tracing::warn!("子进程超时 ({:.1}s)，发送 SIGKILL", timeout.as_secs_f64());
            // SECURITY: Seatbelt 允许 process-fork，超时必须回收整个进程组，
            // 否则其派生进程会在 supervisor 返回后继续存活。
            // SAFETY: Negative pid targets the child process group created by pre_exec setpgid.
            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
            let status = rx.recv().map_err(|_| {
                SandboxError::ExecutionFailed(
                    "waitpid waiter thread disconnected unexpectedly".to_string(),
                )
            })?;
            let _ = waiter.join();
            Ok((
                std::process::ExitStatus::from_raw(
                    status.map_err(|e| {
                        SandboxError::ExecutionFailed(format!("waitpid failed: {e}"))
                    })?,
                ),
                true,
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = waiter.join();
            Err(SandboxError::ExecutionFailed(
                "waitpid monitoring thread disconnected unexpectedly".to_string(),
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
                    "{label} 输出超过 {} 字节上限，已截断并终止子进程组",
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
                read_error: Some(format!("{label} 读取线程异常退出: {error}")),
            },
        },
        None => OutputCapture {
            data: Vec::new(),
            truncated: false,
            read_error: Some(format!("{label} pipe 未初始化")),
        },
    }
}

fn log_output_read_error(label: &'static str, capture: &OutputCapture) {
    if let Some(error) = &capture.read_error {
        tracing::warn!("读取 {label} 失败: {error}");
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

/// 验证路径可以安全嵌入 SBPL 字符串字面量。
///
/// 采用白名单策略：只允许 ASCII 字母数字、路径分隔符 `/`
/// 以及常见路径字符 `. _ - + @`。空格、引号、反斜杠、
/// 括号、NULL 字节、换行和其他控制字符均拒绝，避免 Seatbelt
/// 策略字符串注入。
fn validate_sbpl_path(path: &str) -> Result<(), SandboxError> {
    if path.is_empty() {
        return Err(SandboxError::ExecutionFailed(
            "path must not be empty".to_string(),
        ));
    }

    for (i, byte) in path.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => {}
            b'/' | b'.' | b'_' | b'-' | b'+' | b'@' => {}
            _ => {
                let ch = path[i..].chars().next().unwrap_or('?');
                return Err(SandboxError::ExecutionFailed(format!(
                    "path contains unsafe character for SBPL: {:?} (byte position {i}). Only alphanumeric, /, ., _, -, +, @ are allowed in sandbox paths.",
                    ch
                )));
            }
        }
    }

    Ok(())
}

impl MacOsSandbox {
    fn push_subpath_rule<I, P>(rules: &mut Vec<String>, operation: &str, paths: I)
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut seen = HashSet::new();
        let mut subpaths = Vec::new();

        for path in paths {
            Self::push_subpath(&mut subpaths, &mut seen, path.as_ref());
        }

        if !subpaths.is_empty() {
            rules.push(format!("(allow {operation} {})", subpaths.join(" ")));
        }
    }

    fn push_subpath(subpaths: &mut Vec<String>, seen: &mut HashSet<String>, path: &Path) {
        let raw = path.to_string_lossy().to_string();
        if validate_sbpl_path(&raw).is_ok() {
            if seen.insert(raw.clone()) {
                subpaths.push(format!("(subpath \"{raw}\")"));
            }
        } else {
            tracing::warn!(path = ?raw, "SBPL 路径验证失败，跳过");
            return;
        }

        if let Ok(real) = std::fs::canonicalize(path) {
            let resolved = real.to_string_lossy().to_string();
            if validate_sbpl_path(&resolved).is_ok() {
                if seen.insert(resolved.clone()) {
                    subpaths.push(format!("(subpath \"{resolved}\")"));
                }
            } else {
                tracing::warn!(path = ?resolved, "SBPL canonicalize 路径验证失败，跳过");
            }
        }
    }

    /// Generates a Seatbelt policy string from `SandboxConfig`.
    ///
    /// Policy structure using Seatbelt Scheme compiled format version 1:
    /// 1. `(deny default)` — denies all operations by default.
    /// 2. `(allow file-read*)` — 允许所有文件读取（macOS dyld/Frameworks 启动依赖大量隐式路径，无法用 subpath 白名单）。
    /// 3. `(deny file-read-data (subpath "/Users"))` — 拒绝读取 /Users 下所有用户数据内容，统一保护凭据、密钥、历史记录等。
    /// 4. `(allow file-write* (subpath ...))` — 仅允许写入配置路径。
    /// 5. `(allow process-exec (subpath ...))` — restricts executable paths.
    /// 6. `(deny process-exec (subpath ...))` — denies execution from writable locations.
    /// 7. `(allow process-fork)` — allows fork for shell commands.
    /// 8. `(deny network*)` — denies network access.
    fn generate_policy(&self) -> String {
        let mut rules = Vec::new();

        rules.push("(version 1)".to_string());
        rules.push("(deny default)".to_string());

        // 文件读取：全局允许（macOS dyld/Frameworks 启动依赖大量系统路径）
        rules.push("(allow file-read*)".to_string());

        // 用户数据保护：拒绝 /Users 目录下所有文件内容读取
        // 统一保护用户凭据（.ssh/.aws/.gnupg 等）、密钥链、浏览器数据等，
        // 比逐条黑名单更安全——覆盖所有用户数据，包括未知敏感路径。
        rules.push("(deny file-read-data (subpath \"/Users\"))".to_string());

        // 文件写入：仅允许配置的路径（默认 /tmp）
        // macOS 上 /tmp -> /private/tmp，/var -> /private/var 等符号链接
        // Seatbelt 在解析 subpath 规则时使用实际路径，因此需要 canonicalize
        Self::push_subpath_rule(&mut rules, "file-write*", self.config.fs_readwrite.iter());

        // 进程执行：限制为系统与 Homebrew 路径
        rules.push(
            "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\") (subpath \"/sbin\") (subpath \"/usr/sbin\") (subpath \"/usr/local/bin\") (subpath \"/opt/homebrew/bin\"))"
                .to_string(),
        );
        rules.push(
            "(allow process-exec (subpath \"/Applications/Xcode.app/Contents/Developer/usr/bin\"))"
                .to_string(),
        );
        rules.push(
            "(allow process-exec (subpath \"/Library/Developer/CommandLineTools/usr/bin\"))"
                .to_string(),
        );

        // 可写目录禁止执行，防止下载/写入后二进制直接落地执行。
        rules.push("(deny process-exec (subpath \"/private/tmp\"))".to_string());
        rules.push("(deny process-exec (subpath \"~/Library/Caches\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/bin/osascript\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/bin/pbcopy\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/bin/pbpaste\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/sbin/screencapture\"))".to_string());
        rules.push("(deny process-exec (literal \"/usr/bin/open\"))".to_string());

        // 进程 fork：允许（shell 等命令需要）
        rules.push("(allow process-fork)".to_string());

        // 网络访问：默认拒绝
        if self.config.deny_network {
            rules.push("(deny network*)".to_string());
        }

        // Mach IPC：默认拒绝 lookup/register，减少宿主服务访问面。
        rules.push("(deny mach-lookup)".to_string());
        rules.push("(deny mach-register)".to_string());

        rules.join("\n")
    }
}

impl Sandbox for MacOsSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        tracing::info!(
            "创建 macOS Seatbelt 沙箱, deny_network={}, timeout={:?}s, memory={:?}MB",
            config.deny_network,
            config.timeout_secs,
            config.memory_limit_mb,
        );

        // macOS 上 RLIMIT_AS 无法从无限值缩小，记录告警
        if config.memory_limit_mb.is_some() {
            tracing::warn!("macOS 不支持通过 setrlimit(RLIMIT_AS) 缩小内存限制，内存限制将不生效");
        }

        Ok(Self { config })
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        if cmd.is_empty() {
            return Err(SandboxError::ExecutionFailed(
                "command must not be empty".into(),
            ));
        }

        // SECURITY: 日志仅记录程序基名和参数个数，避免 argv 中的 token、URL、路径泄露。
        tracing::info!("执行命令: {}", command_log_summary(cmd));
        let start = Instant::now();
        let timeout = self.config.timeout_secs.map(Duration::from_secs);

        // 生成 Seatbelt 策略，并在 fork 前转换为 CString，避免 pre_exec 中分配内存。
        let policy = self.generate_policy();
        tracing::debug!("Seatbelt 策略已生成 (规则数: {}, 长度: {} bytes)", policy.matches("\n").count() + 1, policy.len());
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
                .envs(build_safe_child_env())
                .pre_exec(move || {
                    create_child_process_group()?;
                    apply_seatbelt_policy_or_exit(policy.as_ptr());
                    Ok(())
                })
                .spawn()
        }
        .map_err(|e| {
            SandboxError::ExecutionFailed(format!("failed to start sandboxed command: {e}"))
        })?;
        let pid = child.id() as libc::pid_t;

        let output_limit_triggered = Arc::new(AtomicBool::new(false));
        let stdout_rx = child.stdout.take().map(|stdout| {
            spawn_output_reader("stdout", stdout, pid, Arc::clone(&output_limit_triggered))
        });
        let stderr_rx = child.stderr.take().map(|stderr| {
            spawn_output_reader("stderr", stderr, pid, Arc::clone(&output_limit_triggered))
        });

        let (exit_status, timed_out) =
            if let Some(dur) = timeout {
                wait_child_with_timeout(pid, dur)?
            } else {
                (
                    std::process::ExitStatus::from_raw(waitpid_raw(pid).map_err(|e| {
                        SandboxError::ExecutionFailed(format!("waitpid failed: {e}"))
                    })?),
                    false,
                )
            };

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
            return Err(SandboxError::ExecutionFailed(reason));
        }

        tracing::info!(
            "子进程退出, code={:?}, elapsed={:.2}ms, timed_out={timed_out}",
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
            return Err(SandboxError::ExecutionFailed(
                "PTY command must not be empty".into(),
            ));
        }

        tracing::info!(
            "创建 macOS PTY 会话: {}",
            command_log_summary(&config.command)
        );

        let allocated = allocate_pty(config.size)?;
        let policy = self.generate_policy();
        tracing::debug!("PTY Seatbelt 策略已生成 (规则数: {}, 长度: {} bytes)", policy.matches("\n").count() + 1, policy.len());
        let policy = policy_to_cstring(policy)?;

        let slave_file = File::options()
            .read(true)
            .write(true)
            .open(&allocated.slave_path)
            .map_err(|error| {
                SandboxError::ExecutionFailed(format!("failed to open PTY slave: {error}"))
            })?;
        let stdin_slave = slave_file.try_clone().map_err(|error| {
            SandboxError::ExecutionFailed(format!("failed to clone PTY stdin: {error}"))
        })?;
        let stdout_slave = slave_file.try_clone().map_err(|error| {
            SandboxError::ExecutionFailed(format!("failed to clone PTY stdout: {error}"))
        })?;

        let mut command = Command::new(&config.command[0]);
        command
            .args(&config.command[1..])
            .env_clear()
            .envs(build_child_env(&config))
            .stdin(Stdio::from(stdin_slave))
            .stdout(Stdio::from(stdout_slave))
            .stderr(Stdio::from(slave_file));

        if let Some(cwd) = config.cwd.as_deref() {
            command.current_dir(cwd);
        }

        // SAFETY: pre_exec 在子进程 exec 前接管 PTY 并应用 Seatbelt 策略；
        // 闭包捕获的 CString 在 sandbox_init 调用期间有效。
        let child = unsafe {
            command.pre_exec(move || {
                configure_pty_controlling_terminal()?;
                apply_seatbelt_policy_or_exit(policy.as_ptr());
                Ok(())
            })
        }
        .spawn()
        .map_err(|error| {
            SandboxError::ExecutionFailed(format!("failed to start sandboxed PTY: {error}"))
        })?;

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
        tracing::debug!("销毁 macOS Seatbelt 沙箱");
        Ok(())
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

    /// Creates the default macOS test configuration without memory limits, which macOS does not support.
    fn test_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.memory_limit_mb = None;
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
        path.to_str().expect("测试路径必须是 UTF-8").to_string()
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', r#"'\''"#))
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
            eprintln!("跳过 macOS Seatbelt 运行时测试: {reason}");
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
                        panic!("执行 sandbox-exec 最小探测失败: {err}");
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
                    "sandbox-exec 最小探测出现未知失败: status={:?}, stderr={}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                );
            })
            .as_deref()
    }

    fn assert_execute_env_is_sanitized() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        let result = sb
            .execute(&["/usr/bin/env".to_string()])
            .expect("执行 env 失败");

        assert_eq!(
            result.exit_code,
            Some(0),
            "env 应成功, stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );

        let stdout = String::from_utf8(result.stdout).expect("env 输出必须是 UTF-8");

        for prefix in ["DYLD_", "SSH_", "AWS_", "GPG_"] {
            assert!(
                !stdout.lines().any(|line| line.starts_with(prefix)),
                "子进程环境不应包含 {prefix} 前缀变量, 实际输出:\n{stdout}"
            );
        }

        for key in ["LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV"] {
            let needle = format!("{key}=");
            assert!(
                !stdout.lines().any(|line| line.starts_with(&needle)),
                "子进程环境不应包含 {key}, 实际输出:\n{stdout}"
            );
        }

        assert!(
            stdout.lines().any(|line| line == "USER=sandbox"),
            "子进程环境应设置 USER=sandbox, 实际输出:\n{stdout}"
        );
        assert!(
            stdout.lines().any(|line| line == "HOME=/tmp"),
            "子进程环境应设置 HOME=/tmp, 实际输出:\n{stdout}"
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

        let output = Command::new(std::env::current_exe().expect("获取当前测试二进制路径失败"))
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
            .expect("执行环境清理子测试失败");

        assert!(
            output.status.success(),
            "环境清理子测试失败, status={:?}, stdout: {}, stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_file_exists_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        assert_unsupported_operation("file_exists", sb.file_exists("/tmp/mimobox_exists_test"));
    }

    #[test]
    fn test_remove_file_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        assert_unsupported_operation("remove_file", sb.remove_file("/tmp/mimobox_remove_test"));
    }

    #[test]
    fn test_rename_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        assert_unsupported_operation(
            "rename",
            sb.rename("/tmp/mimobox_rename_src", "/tmp/mimobox_rename_dst"),
        );
    }

    #[test]
    fn test_stat_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
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
            "应识别为 Seatbelt 后端错误, 实际: {reason:?}"
        );
    }

    #[test]
    fn test_regular_exit_code_71_is_not_backend_failure() {
        let reason = detect_seatbelt_backend_failure(Some(71), b"child failed\n");
        assert!(reason.is_none(), "普通退出码 71 不应被误判");
    }

    #[test]
    fn test_detect_seatbelt_backend_failure_redacts_sensitive_stderr() {
        let stderr =
            br#"sandbox-exec: sandbox_apply: Operation not permitted for /Users/alice/.ssh/id_rsa
"#;
        let reason =
            detect_seatbelt_backend_failure(Some(71), stderr).expect("应识别为 Seatbelt 后端错误");

        assert!(
            !reason.contains("/Users/alice/.ssh/id_rsa"),
            "错误消息不应泄露敏感路径: {reason}"
        );
        assert!(
            reason.contains("Seatbelt policy enforcement failed"),
            "错误消息应保留高层语义: {reason}"
        );
    }

    #[test]
    fn test_validate_sbpl_path_accepts_normal_paths() {
        assert!(
            validate_sbpl_path("/tmp/sandbox").is_ok(),
            "正常路径应通过验证"
        );
        assert!(
            validate_sbpl_path("/usr/local/bin/my-app_v2.1").is_ok(),
            "包含 . _ - 的路径应通过验证"
        );
        assert!(
            validate_sbpl_path("/tmp/test+flag@host").is_ok(),
            "包含 + @ 的路径应通过验证"
        );
    }

    #[test]
    fn test_validate_sbpl_path_rejects_double_quote() {
        let result = validate_sbpl_path("/path/with\"quote");
        assert!(result.is_err(), "包含双引号的路径应被拒绝");
        assert!(
            result.unwrap_err().to_string().contains("unsafe character"),
            "错误消息应说明包含不安全字符"
        );
    }

    #[test]
    fn test_validate_sbpl_path_rejects_backslash() {
        let result = validate_sbpl_path("/path\\with\\backslash");
        assert!(result.is_err(), "包含反斜杠的路径应被拒绝");
    }

    #[test]
    fn test_validate_sbpl_path_rejects_injection_attempt() {
        let result = validate_sbpl_path(
            "/path\")(allow process-exec (subpath \"/usr/bin\")(allow file-read* (subpath \"/",
        );
        assert!(result.is_err(), "注入尝试应被拒绝");
    }

    #[test]
    fn test_validate_sbpl_path_rejects_newline() {
        let result = validate_sbpl_path("/tmp/path\nwith\nnewline");
        assert!(result.is_err(), "包含换行符的路径应被拒绝");
    }

    #[test]
    fn test_validate_sbpl_path_rejects_null_byte() {
        let result = validate_sbpl_path("/tmp/path\0with\0null");
        assert!(result.is_err(), "包含 NULL 字节的路径应被拒绝");
    }

    #[test]
    fn test_validate_sbpl_path_rejects_empty() {
        let result = validate_sbpl_path("");
        assert!(result.is_err(), "空路径应被拒绝");
    }

    #[test]
    fn test_validate_sbpl_path_rejects_parentheses() {
        assert!(
            validate_sbpl_path("/tmp/path(with").is_err(),
            "包含括号的路径应被拒绝"
        );
        assert!(
            validate_sbpl_path("/tmp/path)with").is_err(),
            "包含右括号的路径应被拒绝"
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
        let mut config = test_config();
        config.deny_network = false;
        let sb = MacOsSandbox::new(config).expect("创建沙箱失败");
        let policy = sb.generate_policy();

        assert!(
            !policy.contains("(deny network*)"),
            "deny_network=false 时策略不应显式拒绝网络"
        );
        assert!(
            policy.contains("(allow process-exec"),
            "策略仍应保留进程执行限制"
        );
    }

    #[test]
    fn test_list_dir_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        assert_unsupported_operation("list_dir", sb.list_dir("/tmp"));
    }

    #[test]
    fn test_stat_on_directory_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        assert_unsupported_operation("stat", sb.stat("/tmp/mimobox-stat-dir"));
    }

    #[test]
    fn test_remove_directory_unsupported() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        assert_unsupported_operation("remove_file", sb.remove_file("/tmp/mimobox-remove-dir"));
    }

    #[test]
    fn test_double_destroy_safety_for_noop_destroy() {
        let sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        sb.destroy().expect("首次 destroy 不应失败");

        let sb = MacOsSandbox::new(test_config()).expect("再次创建沙箱失败");
        sb.destroy().expect("重复销毁独立沙箱不应失败");
    }

    #[test]
    fn test_pty_empty_command_error() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        let result = sb.create_pty(mimobox_core::PtyConfig {
            command: Vec::new(),
            size: mimobox_core::PtySize::default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: Some(Duration::from_secs(1)),
        });

        let Err(error) = result else {
            panic!("空 PTY 命令应返回错误");
        };
        assert!(
            error.to_string().contains("PTY command must not be empty"),
            "错误消息应说明 PTY 命令为空, 实际: {error}"
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

                let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
                let cmd = vec!["/bin/echo".to_string(), format!("sandbox-{index}")];
                let result = sb.execute(&cmd).expect("并发执行失败");

                assert_eq!(result.exit_code, Some(0), "并发命令应成功");
                String::from_utf8(result.stdout)
                    .expect("stdout 应为 UTF-8")
                    .trim()
                    .to_string()
            }));
        }

        let mut outputs = handles
            .into_iter()
            .map(|handle| handle.join().expect("并发测试线程 panic"))
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

        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        let cmd = vec![
            "/usr/bin/seq".to_string(),
            "1".to_string(),
            "10000".to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行 seq 失败");

        assert_eq!(result.exit_code, Some(0), "seq 应成功");
        let stdout = String::from_utf8(result.stdout).expect("stdout 应为 UTF-8");
        assert_eq!(stdout.lines().count(), 10000, "stdout 应包含 10000 行");
        assert!(stdout.starts_with("1\n"), "stdout 应从 1 开始");
        assert!(
            stdout.trim_end().ends_with("10000"),
            "stdout 应以 10000 结束"
        );
    }

    #[test]
    fn test_special_chars_in_command_arguments() {
        if should_skip_runtime_tests() {
            return;
        }

        let payload = r#"spaces and symbols: !@#$%^&*()[]{};:'",.<>/?\|`~"#;
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        let cmd = vec![
            "/usr/bin/printf".to_string(),
            "%s\n".to_string(),
            payload.to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行 printf 失败");

        assert_eq!(result.exit_code, Some(0), "printf 应成功");
        assert_eq!(result.stdout, format!("{payload}\n").into_bytes());
    }

    #[test]
    fn test_write_to_system_path_denied() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut config = test_config();
        config.fs_readwrite = vec!["/tmp".into()];
        let mut sb = MacOsSandbox::new(config).expect("创建沙箱失败");
        let target = format!("/System/mimobox_write_denied_{}", std::process::id());
        let cmd = vec!["/usr/bin/touch".to_string(), target.clone()];
        let result = sb.execute(&cmd).expect("执行 touch 失败");

        assert_ne!(
            result.exit_code,
            Some(0),
            "写入系统路径应失败, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            !std::path::Path::new(&target).exists(),
            "系统路径不应被创建"
        );
    }

    #[test]
    fn test_sensitive_path_read_denied_via_seatbelt() {
        if should_skip_runtime_tests() {
            return;
        }

        // 在 /Users 下创建测试文件
        let home = std::env::var("HOME").expect("HOME 未设置");
        let test_dir = format!("{home}/.mimobox_test_sensitive");
        let secret_file = format!("{test_dir}/secret.txt");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).expect("创建测试目录失败");
        fs::write(&secret_file, "super-secret").expect("写入敏感文件失败");

        let policy = [
            "(version 1)",
            "(deny default)",
            "(allow file-read*)",
            "(deny file-read-data (subpath \"/Users\"))",
            "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\"))",
            "(allow process-fork)",
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
            .expect("执行 sandbox-exec 失败");

        // 清理
        let _ = fs::remove_dir_all(&test_dir);
        assert!(
            !output.status.success(),
            "Seatbelt 应拒绝读取 /Users 下的文件, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("super-secret"),
            "敏感内容不应出现在 stdout"
        );
    }

    #[test]
    fn test_sensitive_path_stat_allowed_via_seatbelt() {
        if should_skip_runtime_tests() {
            return;
        }

        let home = std::env::var("HOME").expect("HOME 未设置");
        let test_dir = format!("{home}/.mimobox_test_stat");
        let secret_file = format!("{test_dir}/secret.txt");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).expect("创建测试目录失败");
        fs::write(&secret_file, "super-secret").expect("写入敏感文件失败");

        let policy = [
            "(version 1)",
            "(deny default)",
            "(allow file-read*)",
            "(deny file-read-data (subpath \"/Users\"))",
            "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\"))",
            "(allow process-fork)",
        ]
        .join("\n");
        // file-read-metadata 未被 deny，所以 stat(ls -ld) 应该成功。
        // 普通 ls 会枚举目录内容，在 Seatbelt 中属于 file-read-data。
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
            .expect("执行 sandbox-exec ls 失败");

        assert!(
            list_output.status.success(),
            "Seatbelt 应允许读取目录元数据，stdout: {}, stderr: {}",
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
            .expect("执行 sandbox-exec cat 失败");

        assert!(
            !cat_output.status.success(),
            "Seatbelt 应拒绝读取文件内容, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&cat_output.stdout),
            String::from_utf8_lossy(&cat_output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&cat_output.stdout).contains("super-secret"),
            "敏感内容不应出现在 stdout"
        );
        // 清理
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_exec_from_tmp_denied_via_seatbelt() {
        if should_skip_runtime_tests() {
            return;
        }

        let temp_dir = TempDir::new_in("/tmp").expect("创建 /tmp 临时目录失败");
        let script_path = temp_dir.path().join("test_exec.sh");
        fs::write(&script_path, "#!/bin/sh\necho hello\n").expect("写入测试脚本失败");

        let mut permissions = fs::metadata(&script_path)
            .expect("读取测试脚本权限失败")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("设置测试脚本可执行权限失败");

        let policy = [
            "(version 1)",
            "(deny default)",
            "(allow file-read*)",
            "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\"))",
            "(deny process-exec (subpath \"/private/tmp\"))",
            "(allow process-fork)",
        ]
        .join("\n");
        let script = path_to_string(&script_path);
        let output = Command::new("sandbox-exec")
            .args(["-p", policy.as_str(), "--", script.as_str()])
            .output()
            .expect("执行 sandbox-exec 测试脚本失败");

        assert!(
            !output.status.success(),
            "Seatbelt 应拒绝执行 /tmp 下的脚本, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("hello"),
            "被拒绝执行的脚本不应输出 hello"
        );
    }

    #[test]
    fn test_sandbox_isolation_between_instances() {
        if should_skip_runtime_tests() {
            return;
        }

        let dir_one = TempDir::new().expect("创建第一个临时目录失败");
        let dir_two = TempDir::new().expect("创建第二个临时目录失败");

        let mut config_one = test_config();
        config_one.fs_readwrite = vec![dir_one.path().into()];
        let mut config_two = test_config();
        config_two.fs_readwrite = vec![dir_two.path().into()];

        let mut sb_one = MacOsSandbox::new(config_one).expect("创建第一个沙箱失败");
        let mut sb_two = MacOsSandbox::new(config_two).expect("创建第二个沙箱失败");

        let own_one = dir_one.path().join("owned-by-one.txt");
        let own_two = dir_two.path().join("owned-by-two.txt");
        let result_one = sb_one
            .execute(&write_file_command(&own_one, "one"))
            .expect("第一个沙箱写入自身目录失败");
        let result_two = sb_two
            .execute(&write_file_command(&own_two, "two"))
            .expect("第二个沙箱写入自身目录失败");

        assert_eq!(result_one.exit_code, Some(0), "第一个沙箱应能写自身目录");
        assert_eq!(result_two.exit_code, Some(0), "第二个沙箱应能写自身目录");
        assert_eq!(
            fs::read_to_string(&own_one).expect("读取自身文件失败"),
            "one"
        );
        assert_eq!(
            fs::read_to_string(&own_two).expect("读取自身文件失败"),
            "two"
        );

        let blocked_by_one = dir_two.path().join("blocked-by-one.txt");
        let blocked_by_two = dir_one.path().join("blocked-by-two.txt");
        let denied_one = sb_one
            .execute(&write_file_command(&blocked_by_one, "blocked"))
            .expect("第一个沙箱越权写入命令执行失败");
        let denied_two = sb_two
            .execute(&write_file_command(&blocked_by_two, "blocked"))
            .expect("第二个沙箱越权写入命令执行失败");

        assert_ne!(
            denied_one.exit_code,
            Some(0),
            "第一个沙箱不应写入第二个沙箱目录"
        );
        assert_ne!(
            denied_two.exit_code,
            Some(0),
            "第二个沙箱不应写入第一个沙箱目录"
        );
        assert!(!blocked_by_one.exists(), "越权文件不应被创建");
        assert!(!blocked_by_two.exists(), "越权文件不应被创建");
    }

    #[test]
    fn test_sandbox_create_and_execute() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        let cmd = vec!["/bin/echo".to_string(), "hello macos test".to_string()];
        let result = sb.execute(&cmd).expect("执行失败");

        assert!(!result.timed_out, "不应超时");
        assert_eq!(result.exit_code, Some(0), "退出码应为 0");
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            stdout.contains("hello macos test"),
            "stdout 应包含输出, 实际: {stdout}"
        );
    }

    #[test]
    fn test_nonzero_exit_code() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 42".to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行失败");

        assert_eq!(result.exit_code, Some(42), "退出码应为 42");
    }

    #[test]
    fn test_timeout() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut config = test_config();
        config.timeout_secs = Some(1);
        let mut sb = MacOsSandbox::new(config).expect("创建沙箱失败");

        let cmd = vec!["/bin/sleep".to_string(), "60".to_string()];
        let result = sb.execute(&cmd).expect("执行失败");

        assert!(result.timed_out, "应超时");
    }

    #[test]
    fn test_empty_command_error() {
        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        let result = sb.execute(&[]);
        assert!(result.is_err(), "空命令应返回错误");
    }

    #[test]
    fn test_policy_generation() {
        let sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
        let policy = sb.generate_policy();

        assert!(policy.contains("(version 1)"), "策略应包含 version 1");
        assert!(policy.contains("(deny default)"), "策略应包含 deny default");
        assert!(
            policy.contains("(allow file-read*)"),
            "策略应全局允许文件读取（macOS 进程启动需要）"
        );
        assert!(
            policy.contains("(deny file-read-data (subpath \"/Users\"))"),
            "策略应拒绝读取 /Users 目录内容"
        );
        assert!(
            policy.contains("(deny network*)"),
            "策略应包含 deny network"
        );
        assert!(
            policy.contains("(deny mach-lookup)"),
            "策略应拒绝 mach-lookup"
        );
        assert!(
            policy.contains("(deny mach-register)"),
            "策略应拒绝 mach-register"
        );
        assert!(
            policy.contains("(allow process-exec"),
            "策略应包含进程执行限制"
        );
        assert!(
            policy.contains("(allow process-fork)"),
            "策略应允许进程 fork"
        );
        assert!(
            policy.contains("(deny process-exec (subpath \"/private/tmp\"))"),
            "策略应拒绝从 /private/tmp 执行"
        );
        assert!(
            policy.contains("(deny process-exec (subpath \"~/Library/Caches\"))"),
            "策略应拒绝从 ~/Library/Caches 执行"
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
                "策略应拒绝执行高风险系统工具 {blocked_tool}"
            );
        }
        assert!(
            policy.contains("(subpath \"/usr/local/bin\")"),
            "策略应允许 Intel Homebrew bin 路径执行"
        );
        assert!(
            policy.contains("(subpath \"/opt/homebrew/bin\")"),
            "策略应允许 Apple Silicon Homebrew bin 路径执行"
        );
        assert!(
            policy.contains(
                "(allow process-exec (subpath \"/Applications/Xcode.app/Contents/Developer/usr/bin\"))"
            ),
            "策略应允许 Xcode Developer 工具链路径执行"
        );
        assert!(
            policy.contains(
                "(allow process-exec (subpath \"/Library/Developer/CommandLineTools/usr/bin\"))"
            ),
            "策略应允许 CommandLineTools 工具链路径执行"
        );
        assert!(policy.contains("/tmp"), "策略应允许 /tmp 读写");
    }

    #[test]
    fn test_policy_generation_uses_explicit_readonly_allowlist() {
        let mut config = SandboxConfig::default();
        config.fs_readwrite = vec!["/tmp/mimobox-rw".into()];
        config.memory_limit_mb = None;
        config.timeout_secs = Some(10);
        let sb = MacOsSandbox::new(config).expect("创建沙箱失败");
        let policy = sb.generate_policy();

        assert!(
            policy.contains("(subpath \"/tmp/mimobox-rw\")"),
            "读写白名单应写入 Seatbelt 策略"
        );
    }

    #[test]
    fn test_network_denied() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut config = test_config();
        config.deny_network = true;
        let mut sb = MacOsSandbox::new(config).expect("创建沙箱失败");

        // curl 在网络被拒绝时应失败
        let cmd = vec![
            "/usr/bin/curl".to_string(),
            "--connect-timeout".to_string(),
            "2".to_string(),
            "http://127.0.0.1:1".to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行失败");

        assert!(
            result.exit_code != Some(0),
            "网络请求应被拒绝, exit_code: {:?}",
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
        let mut sb = MacOsSandbox::new(config).expect("创建沙箱失败");

        // 尝试写入 /usr/local（不在 fs_readwrite 中）
        // 注意：macOS 上 /var 是 /private/var 的符号链接，但 /usr/local 不是
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "/bin/echo test > /usr/local/mimobox_test_write 2>&1; echo exit=$?".to_string(),
        ];
        let result = sb.execute(&cmd).expect("执行失败");

        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        // 写入受限路径应失败（Seatbelt 拒绝或文件系统权限拒绝均可）
        assert!(
            result.exit_code != Some(0)
                || stdout.contains("Operation not permitted")
                || stdout.contains("Permission denied")
                || stdout.contains("Read-only file system")
                || stderr.contains("Operation not permitted"),
            "写入受限路径应被拒绝, stdout: {stdout}, stderr: {stderr}, exit: {:?}",
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
        let mut sb = MacOsSandbox::new(config).expect("创建沙箱失败");

        // 写入 /tmp（在 fs_readwrite 中）应成功
        let test_file = format!("/tmp/mimobox_seatbelt_test_{}", std::process::id());
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("/bin/echo ok > {test_file} && /bin/cat {test_file} && /bin/rm {test_file}"),
        ];
        let result = sb.execute(&cmd).expect("执行失败");

        assert_eq!(
            result.exit_code,
            Some(0),
            "写入 /tmp 应成功, stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(stdout.contains("ok"), "stdout 应包含 ok, 实际: {stdout}");
    }

    #[test]
    fn test_pty_basic_echo() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
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
            .expect("创建 PTY 会话失败");

        session
            .send_input(b"hello-pty\n")
            .expect("发送 PTY 输入失败");

        let output = read_pty_until(
            session.output_rx(),
            b"reply:hello-pty",
            Duration::from_secs(5),
        );
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("reply:hello-pty"),
            "PTY 输出应包含回显结果, 实际: {output}"
        );

        assert_eq!(session.wait().expect("等待 PTY 退出失败"), 0);
    }

    #[test]
    fn test_pty_resize() {
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
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
                cols: 100,
                rows: 32,
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
        if should_skip_runtime_tests() {
            return;
        }

        let mut sb = MacOsSandbox::new(test_config()).expect("创建沙箱失败");
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
    fn test_sandbox_create_with_memory_limit_warns() {
        // macOS 不支持内存限制，但创建不应失败（仅记录告警日志）
        let mut config = test_config();
        config.memory_limit_mb = Some(256);
        let sb = MacOsSandbox::new(config);
        assert!(sb.is_ok(), "macOS 沙箱创建不应因内存限制而失败");
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
