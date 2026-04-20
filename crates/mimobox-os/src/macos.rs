//! macOS 沙箱后端（Seatbelt / sandbox-exec）
//!
//! 使用 macOS 原生 Seatbelt 框架实现进程级沙箱隔离。
//! 通过 `sandbox-exec -p "<seatbelt_policy>"` 命令执行，利用 Seatbelt 策略语言
//! 实现文件系统、网络、进程执行等维度的限制。
//!
//! # 安全策略
//!
//! | 维度 | 策略 | 说明 |
//! |------|------|------|
//! | 文件读取 | 全部允许 | macOS 进程运行需访问大量系统路径（dyld、Frameworks 等），无法精确限制 |
//! | 文件写入 | 白名单 | 仅允许 `fs_readwrite` 中配置的路径（默认 `/tmp`） |
//! | 网络访问 | 默认拒绝 | 通过 `(deny network*)` 禁止所有网络操作 |
//! | 进程执行 | 路径限制 | 仅允许 `/bin`、`/usr/bin`、`/sbin`、`/usr/sbin` 下的可执行文件 |
//! | 进程 fork | 允许 | shell 等命令需要 fork 子进程 |
//! | 内存限制 | 不支持 | macOS 上 `RLIMIT_AS` 无法从无限值缩小，记录告警日志 |

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};

/// macOS Seatbelt 沙箱后端
///
/// 通过 `sandbox-exec -p "<seatbelt_policy>"` 执行命令，
/// 利用 macOS 原生 Seatbelt 框架实现沙箱隔离。
///
/// # 平台限制
///
/// - 文件读取无法限制路径（macOS 进程启动依赖大量系统路径）
/// - 内存限制无法通过 `setrlimit(RLIMIT_AS)` 实现（macOS 不支持缩小）
pub struct MacOsSandbox {
    config: SandboxConfig,
}

fn detect_seatbelt_backend_failure(exit_code: Option<i32>, stderr: &[u8]) -> Option<String> {
    let stderr_text = String::from_utf8_lossy(stderr);

    if exit_code == Some(71) && stderr_text.contains("sandbox_apply: Operation not permitted") {
        return Some(format!("Seatbelt 策略应用失败: {}", stderr_text.trim()));
    }

    None
}

impl MacOsSandbox {
    /// 根据 SandboxConfig 生成 Seatbelt 策略字符串
    ///
    /// 策略结构（Seatbelt Scheme 编译格式 version 1）：
    /// 1. `(deny default)` — 默认拒绝所有操作
    /// 2. `(allow file-read*)` — 允许所有文件读取（macOS 进程运行需要）
    /// 3. `(allow file-write* (subpath ...))` — 仅允许配置的路径写入
    /// 4. `(allow process-exec (subpath ...))` — 限制可执行路径
    /// 5. `(allow process-fork)` — 允许 fork（shell 命令需要）
    /// 6. `(deny network*)` — 拒绝网络访问
    fn generate_policy(&self) -> String {
        let mut rules = Vec::new();

        rules.push("(version 1)".to_string());
        rules.push("(deny default)".to_string());

        // 文件读取：全部允许
        // macOS 进程启动需要访问 dyld、System/Library/Frameworks、
        // /usr/lib/libSystem.B.dylib 等大量系统路径，无法精确白名单
        rules.push("(allow file-read*)".to_string());

        // 文件写入：仅允许配置的路径（默认 /tmp）
        // macOS 上 /tmp -> /private/tmp，/var -> /private/var 等符号链接
        // Seatbelt 在解析 subpath 规则时使用实际路径，因此需要 canonicalize
        let mut seen = std::collections::HashSet::new();
        for path in &self.config.fs_readwrite {
            // 同时添加原始路径和 canonicalize 后的路径
            let p = path.to_string_lossy().to_string();
            if seen.insert(p.clone()) {
                rules.push(format!("(allow file-write* (subpath \"{p}\"))"));
            }
            if let Ok(real) = std::fs::canonicalize(path) {
                let rp = real.to_string_lossy().to_string();
                if seen.insert(rp.clone()) {
                    rules.push(format!("(allow file-write* (subpath \"{rp}\"))"));
                }
            }
        }

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
            return Err(SandboxError::ExecutionFailed("命令为空".into()));
        }

        tracing::info!("执行命令: {} {}", cmd[0], cmd[1..].join(" "));
        let start = Instant::now();
        let timeout = self.config.timeout_secs.map(Duration::from_secs);

        // 生成 Seatbelt 策略
        let policy = self.generate_policy();
        tracing::debug!("Seatbelt 策略:\n{policy}");

        // 构造 sandbox-exec 命令: sandbox-exec -p "<policy>" -- <cmd>...
        let mut args = vec!["-p".to_string(), policy, "--".to_string()];
        args.extend(cmd.iter().cloned());

        let mut child = Command::new("sandbox-exec")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::ExecutionFailed(format!("sandbox-exec 启动失败: {e}")))?;

        // 超时轮询等待
        let timed_out = if let Some(dur) = timeout {
            let deadline = start + dur;
            loop {
                match child.try_wait() {
                    Ok(Some(_status)) => break false,
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            tracing::warn!("子进程超时 ({:.1}s)，发送 SIGKILL", dur.as_secs_f64());
                            let _ = child.kill();
                            let _ = child.wait();
                            break true;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => {
                        return Err(SandboxError::ExecutionFailed(format!(
                            "等待子进程状态失败: {e}"
                        )));
                    }
                }
            }
        } else {
            false
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

        // 获取退出码（非超时时 child 尚未 wait）
        let exit_status = if timed_out {
            None
        } else {
            match child.wait() {
                Ok(status) => status.code(),
                Err(e) => {
                    tracing::warn!("获取退出状态失败: {e}");
                    None
                }
            }
        };

        if let Some(reason) = detect_seatbelt_backend_failure(exit_status, &stderr_buf) {
            return Err(SandboxError::ExecutionFailed(reason));
        }

        tracing::info!(
            "子进程退出, code={:?}, elapsed={:.2}ms, timed_out={timed_out}",
            exit_status,
            elapsed.as_secs_f64() * 1000.0,
        );

        Ok(SandboxResult {
            stdout: stdout_buf,
            stderr: stderr_buf,
            exit_code: exit_status,
            elapsed,
            timed_out,
        })
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

    /// macOS 默认测试配置（不设内存限制，macOS 不支持）
    fn test_config() -> SandboxConfig {
        SandboxConfig {
            timeout_secs: Some(10),
            memory_limit_mb: None,
            ..Default::default()
        }
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
                        return Some("当前环境不存在 sandbox-exec".to_string());
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
                .is_some_and(|value| value.contains("Seatbelt 策略应用失败")),
            "应识别为 Seatbelt 后端错误, 实际: {reason:?}"
        );
    }

    #[test]
    fn test_regular_exit_code_71_is_not_backend_failure() {
        let reason = detect_seatbelt_backend_failure(Some(71), b"child failed\n");
        assert!(reason.is_none(), "普通退出码 71 不应被误判");
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

        let config = SandboxConfig {
            timeout_secs: Some(1),
            ..test_config()
        };
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
            "策略应允许所有文件读取"
        );
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
        assert!(policy.contains("/tmp"), "策略应允许 /tmp 写入");
    }

    #[test]
    fn test_network_denied() {
        if should_skip_runtime_tests() {
            return;
        }

        let config = SandboxConfig {
            deny_network: true,
            ..test_config()
        };
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

        let config = SandboxConfig {
            fs_readwrite: vec!["/tmp".into()],
            ..test_config()
        };
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

        let config = SandboxConfig {
            fs_readwrite: vec!["/tmp".into()],
            ..test_config()
        };
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
    fn test_sandbox_create_with_memory_limit_warns() {
        // macOS 不支持内存限制，但创建不应失败（仅记录告警日志）
        let config = SandboxConfig {
            memory_limit_mb: Some(256),
            ..test_config()
        };
        let sb = MacOsSandbox::new(config);
        assert!(sb.is_ok(), "macOS 沙箱创建不应因内存限制而失败");
    }
}
