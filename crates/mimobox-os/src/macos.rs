//! macOS sandbox backend (Seatbelt / sandbox-exec).
//!
//! Implements process-level sandbox isolation with the native macOS Seatbelt framework.
//! Runs commands through `sandbox-exec -p "<seatbelt_policy>"` and uses the Seatbelt
//! policy language to restrict filesystem access, networking, process execution, and more.
//!
//! # Security Policy
//!
//! | Dimension | Policy | Description |
//! |------|------|------|
//! | File reads | Allow globally + deny sensitive paths | macOS process startup depends on many system paths, making precise allowlisting impractical; sensitive user directories are denied explicitly instead. |
//! | File writes | Allowlist | Allows only paths configured in `fs_readwrite` (defaults to `/tmp`). |
//! | Network access | Deny by default | Denies all network operations with `(deny network*)`. |
//! | Process execution | Path-restricted | Allows only executables under `/bin`, `/usr/bin`, `/sbin`, and `/usr/sbin`. |
//! | Process fork | Allowed | Shells and similar commands need to fork child processes. |
//! | Memory limits | Unsupported | `RLIMIT_AS` cannot be reduced from an unlimited value on macOS; a warning is logged instead. |

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};

use crate::pty::{allocate_pty, build_child_env, build_session};

/// Sensitive user directory suffixes, relative to `$HOME`, whose reads must be denied explicitly.
///
/// macOS process startup depends on many system paths (`dyld`, frameworks, and others),
/// making precise allowlisting impractical. File reads are allowed globally, while known
/// sensitive directories such as SSH keys and cloud credentials are denied explicitly.
const SENSITIVE_HOME_SUBPATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/gh",
];

/// macOS Seatbelt sandbox backend.
///
/// Runs commands through `sandbox-exec -p "<seatbelt_policy>"` and uses the native
/// macOS Seatbelt framework for sandbox isolation.
///
/// # Platform Limitations
///
/// - File reads cannot be precisely allowlisted because macOS `dyld` and frameworks depend on many system paths; sensitive directories are denied instead.
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
            // SECURITY: sandbox-exec 允许 process-fork，超时必须回收整个进程组，
            // 否则其派生进程会在 supervisor 返回后继续存活。
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
        if seen.insert(raw.clone()) {
            subpaths.push(format!("(subpath \"{raw}\")"));
        }

        if let Ok(real) = std::fs::canonicalize(path) {
            let resolved = real.to_string_lossy().to_string();
            if seen.insert(resolved.clone()) {
                subpaths.push(format!("(subpath \"{resolved}\")"));
            }
        }
    }

    /// Generates a Seatbelt policy string from `SandboxConfig`.
    ///
    /// Policy structure using Seatbelt Scheme compiled format version 1:
    /// 1. `(deny default)` — denies all operations by default.
    /// 2. `(allow file-read*)` — allows all file reads required by macOS process startup.
    /// 3. `(deny file-read* (subpath ...))` — explicitly denies sensitive user directories.
    /// 4. `(allow file-write* (subpath ...))` — allows writes only to configured paths.
    /// 5. `(allow process-exec (subpath ...))` — restricts executable paths.
    /// 6. `(allow process-fork)` — allows fork for shell commands.
    /// 7. `(deny network*)` — denies network access.
    fn generate_policy(&self) -> String {
        let mut rules = Vec::new();

        rules.push("(version 1)".to_string());
        rules.push("(deny default)".to_string());

        // 文件读取：全局允许（macOS dyld/Frameworks 启动依赖大量系统路径）
        rules.push("(allow file-read*)".to_string());

        // 显式拒绝敏感用户目录（SSH 密钥、云凭证等）
        // Seatbelt 中后出现的更具体规则覆盖先前的通用规则
        if let Ok(home) = std::env::var("HOME") {
            for sub in SENSITIVE_HOME_SUBPATHS {
                let full_path = format!("{home}/{sub}");
                if let Ok(canonical) = std::fs::canonicalize(&full_path) {
                    // 路径存在，拒绝原始路径和 canonicalize 后的路径
                    rules.push(format!("(deny file-read* (subpath \"{full_path}\"))"));
                    let resolved = canonical.to_string_lossy().to_string();
                    if resolved != full_path {
                        rules.push(format!("(deny file-read* (subpath \"{resolved}\"))"));
                    }
                } else {
                    // 路径不存在也加入拒绝规则，防止运行时创建后读取
                    rules.push(format!("(deny file-read* (subpath \"{full_path}\"))"));
                }
            }
        }

        // 文件写入：仅允许配置的路径（默认 /tmp）
        // macOS 上 /tmp -> /private/tmp，/var -> /private/var 等符号链接
        // Seatbelt 在解析 subpath 规则时使用实际路径，因此需要 canonicalize
        Self::push_subpath_rule(&mut rules, "file-write*", self.config.fs_readwrite.iter());

        // 进程执行：限制为系统路径
        rules.push(
            "(allow process-exec (subpath \"/bin\") (subpath \"/usr/bin\") (subpath \"/sbin\") (subpath \"/usr/sbin\"))"
                .to_string(),
        );

        // 进程 fork：允许（shell 等命令需要）
        rules.push("(allow process-fork)".to_string());

        // 网络访问：默认拒绝
        if self.config.deny_network {
            rules.push("(deny network*)".to_string());
        }

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

        // 生成 Seatbelt 策略
        let policy = self.generate_policy();
        tracing::debug!("Seatbelt 策略:\n{policy}");

        // 构造 sandbox-exec 命令: sandbox-exec -p "<policy>" -- <cmd>...
        let mut args = vec!["-p".to_string(), policy, "--".to_string()];
        args.extend(cmd.iter().cloned());

        let mut child = unsafe {
            Command::new("sandbox-exec")
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .pre_exec(|| {
                    // SAFETY: pre_exec 中只调用 async-signal-safe 的 setpgid(0, 0)，
                    // 为超时路径建立独立进程组，避免只杀掉 sandbox-exec 自身。
                    let ret = libc::setpgid(0, 0);
                    if ret != 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                })
                .spawn()
        }
        .map_err(|e| SandboxError::ExecutionFailed(format!("failed to start sandbox-exec: {e}")))?;
        let pid = child.id() as libc::pid_t;

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

        // 读取 stdout/stderr
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_end(&mut stdout_buf);
        }
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_end(&mut stderr_buf);
        }

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
        tracing::debug!("PTY Seatbelt 策略:\n{policy}");

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

        let mut args = vec!["-p".to_string(), policy, "--".to_string()];
        args.extend(config.command.iter().cloned());

        let mut command = Command::new("sandbox-exec");
        command
            .args(&args)
            .env_clear()
            .envs(build_child_env(&config))
            .stdin(Stdio::from(stdin_slave))
            .stdout(Stdio::from(stdout_slave))
            .stderr(Stdio::from(slave_file));

        if let Some(cwd) = config.cwd.as_deref() {
            command.current_dir(cwd);
        }

        let child = unsafe {
            command.pre_exec(|| {
                // SAFETY: pre_exec 中仅调用 async-signal-safe 的 setsid/ioctl，
                // 让 sandbox-exec 成为新的会话首进程并接管 PTY 作为控制终端。
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                #[allow(clippy::cast_lossless)]
                if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            })
        }
        .spawn()
        .map_err(|error| {
            SandboxError::ExecutionFailed(format!("failed to start sandbox-exec PTY: {error}"))
        })?;

        Ok(build_session(
            allocated,
            child.id() as libc::pid_t,
            config.timeout,
        ))
    }

    fn destroy(self) -> Result<(), SandboxError> {
        tracing::debug!("销毁 macOS Seatbelt 沙箱");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use mimobox_core::{Sandbox, SandboxConfig};

    /// Creates the default macOS test configuration without memory limits, which macOS does not support.
    fn test_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.memory_limit_mb = None;
        config
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
            policy.contains("(deny file-read* (subpath"),
            "策略应显式拒绝敏感路径"
        );
        assert!(policy.contains(".ssh"), "策略应拒绝 ~/.ssh");
        assert!(policy.contains(".aws"), "策略应拒绝 ~/.aws");
        assert!(policy.contains(".gnupg"), "策略应拒绝 ~/.gnupg");
        assert!(
            policy.contains("(deny network*)"),
            "策略应包含 deny network"
        );
        assert!(
            policy.contains("(allow process-exec"),
            "策略应包含进程执行限制"
        );
        assert!(
            policy.contains("(allow process-fork)"),
            "策略应允许进程 fork"
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
