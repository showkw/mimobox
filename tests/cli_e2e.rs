#![cfg(unix)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde::Deserialize;

static CLI_BUILD: OnceLock<()> = OnceLock::new();
static WORKSPACE_ROOT: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct RunResponseEnvelope {
    ok: bool,
    command: String,
    backend: String,
    requested_backend: String,
    requested_command: String,
    argv: Vec<String>,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed_ms: f64,
    stdout: String,
    stderr: String,
    memory_mb: Option<u64>,
    timeout_secs: Option<u64>,
    deny_network: bool,
    allow_fork: bool,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    ok: bool,
    code: String,
    message: String,
}

fn workspace_root() -> &'static Path {
    WORKSPACE_ROOT
        .get_or_init(|| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            match manifest_dir.parent().and_then(|path| path.parent()) {
                Some(root) => root.to_path_buf(),
                None => panic!(
                    "无法从 CARGO_MANIFEST_DIR 推导 workspace 根目录: {}",
                    manifest_dir.display()
                ),
            }
        })
        .as_path()
}

fn ensure_cli_built() {
    CLI_BUILD.get_or_init(|| {
        let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
        let status = match Command::new(cargo)
            .args(["build", "-p", "mimobox-cli"])
            .current_dir(workspace_root())
            .status()
        {
            Ok(status) => status,
            Err(error) => panic!("执行 cargo build -p mimobox-cli 失败: {error}"),
        };

        assert!(
            status.success(),
            "cargo build -p mimobox-cli 执行失败，退出状态: {status}"
        );
    });
}

fn cli_binary_path() -> PathBuf {
    ensure_cli_built();

    let path = match env::var_os("CARGO_BIN_EXE_mimobox-cli") {
        Some(path) => PathBuf::from(path),
        None => {
            let target_dir = env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| workspace_root().join("target"));
            target_dir.join("debug").join("mimobox-cli")
        }
    };

    assert!(
        path.exists(),
        "未找到 mimobox-cli 二进制: {}",
        path.display()
    );
    path
}

fn run_cli(args: &[&str]) -> Output {
    let output = match Command::new(cli_binary_path())
        .args(args)
        .current_dir(workspace_root())
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("执行 mimobox-cli 子进程失败: {error}"),
    };

    assert!(
        output.status.success(),
        "CLI 进程返回非零退出码: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    output
}

/// 运行 CLI 并接受任意退出码（用于测试沙箱命令非零退出码传播）。
fn run_cli_allow_nonzero(args: &[&str]) -> Output {
    match Command::new(cli_binary_path())
        .args(args)
        .current_dir(workspace_root())
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("执行 mimobox-cli 子进程失败: {error}"),
    }
}

fn parse_run_response(output: Output) -> RunResponseEnvelope {
    match serde_json::from_slice(&output.stdout) {
        Ok(response) => response,
        Err(error) => panic!(
            "解析 CLI JSON 输出失败: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
    }
}

fn parse_error_response(output: Output) -> ErrorEnvelope {
    match serde_json::from_slice(&output.stdout) {
        Ok(response) => response,
        Err(error) => panic!(
            "解析 CLI 错误 JSON 输出失败: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
    }
}

#[test]
fn auto_backend_runs_os_command() {
    let output = run_cli(&["run", "--backend", "auto", "--command", "/bin/echo hello"]);
    let response = parse_run_response(output);

    assert!(response.ok, "auto 路由执行应返回 ok=true");
    assert_eq!(response.command, "run");
    assert_eq!(response.requested_backend, "auto");
    assert_eq!(response.backend, "os");
    assert_ne!(response.backend, "auto");
    assert_eq!(response.exit_code, Some(0));
    assert!(
        response.stdout.contains("hello"),
        "stdout 应包含 hello，实际 stdout: {}",
        response.stdout
    );
}

#[test]
fn explicit_os_backend() {
    let output = run_cli(&["run", "--backend", "os", "--command", "/bin/echo hello"]);
    let response = parse_run_response(output);

    assert!(response.ok, "显式 OS 后端执行应返回 ok=true");
    assert_eq!(response.command, "run");
    assert_eq!(response.requested_backend, "os");
    assert_eq!(response.requested_command, "/bin/echo hello");
    assert_eq!(response.argv, ["/bin/echo", "hello"]);
    assert_eq!(response.backend, "os");
    assert_eq!(response.exit_code, Some(0));
    assert!(!response.timed_out, "正常命令不应超时");
    assert!(response.elapsed_ms >= 0.0, "elapsed_ms 不应为负数");
    assert_eq!(response.memory_mb, Some(256));
    assert_eq!(response.timeout_secs, Some(30));
    assert!(!response.deny_network, "默认不应设置 deny_network");
    assert!(!response.allow_fork, "默认不应允许 fork");
    assert!(
        response.stdout.contains("hello"),
        "stdout 应包含 hello，实际 stdout: {}",
        response.stdout
    );
}

#[test]
fn invalid_command_returns_error() {
    let output = run_cli_allow_nonzero(&[
        "run",
        "--backend",
        "auto",
        "--command",
        "/bin/sh -c 'echo fail >&2; exit 7'",
        "--allow-fork",
    ]);

    // CLI 进程应传播沙箱命令的退出码
    assert_eq!(
        output.status.code(),
        Some(7),
        "CLI 进程退出码应等于沙箱命令退出码 7"
    );

    let response = parse_run_response(output);

    assert!(response.ok, "非零退出命令仍应返回成功 JSON 包装");
    assert_eq!(response.command, "run");
    assert_eq!(response.requested_backend, "auto");
    assert_eq!(response.backend, "os");

    match response.exit_code {
        Some(exit_code) => assert_ne!(exit_code, 0, "exit_code 应为非零"),
        None => panic!("非零退出命令应携带 exit_code"),
    }

    assert!(
        response.stderr.contains("fail"),
        "stderr 应包含 fail，实际 stderr: {}",
        response.stderr
    );
}

#[test]
fn timeout_kills_long_running_command() {
    let started_at = Instant::now();
    let output = run_cli_allow_nonzero(&[
        "run",
        "--backend",
        "os",
        "--command",
        "sleep 10",
        "--timeout",
        "2",
    ]);
    let elapsed = started_at.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "超时命令应在 5 秒内结束，实际耗时: {elapsed:?}"
    );

    let response = parse_run_response(output);

    assert!(response.ok, "超时仍应返回成功 JSON 包装");
    assert!(response.timed_out, "timed_out 应为 true");
}

#[test]
fn captures_stderr() {
    let output = run_cli(&[
        "run",
        "--backend",
        "os",
        "--command",
        "/bin/sh -c 'echo err >&2'",
        "--allow-fork",
    ]);
    let response = parse_run_response(output);

    assert!(
        response.stderr.contains("err"),
        "stderr 应包含 err，实际 stderr: {}",
        response.stderr
    );
}

#[test]
fn consecutive_executions_work() {
    for expected in ["aaa", "bbb", "ccc"] {
        let command = format!("/bin/echo {expected}");
        let output = run_cli(&["run", "--backend", "os", "--command", &command]);
        let response = parse_run_response(output);

        assert_eq!(response.exit_code, Some(0));
        assert_eq!(response.stdout.trim(), expected);
    }
}

#[test]
fn handles_non_utf8_output() {
    let output = run_cli(&[
        "run",
        "--backend",
        "os",
        "--command",
        "/bin/sh -c 'printf \"\\xff\\xfe\"'",
        "--allow-fork",
    ]);
    let response = parse_run_response(output);

    assert_eq!(response.exit_code, Some(0));
}

#[test]
fn empty_command_returns_error() {
    let output = run_cli_allow_nonzero(&["run", "--backend", "os", "--command", ""]);

    assert!(
        !output.status.success(),
        "空命令应导致 CLI 进程返回非零退出码"
    );

    let response = parse_error_response(output);

    assert!(!response.ok, "错误响应 ok 应为 false");
    assert_eq!(response.code, "empty_command");
    assert!(
        response.message.contains("command must not be empty"),
        "错误消息应说明空命令，实际 message: {}",
        response.message
    );
}

#[test]
fn long_command_handled() {
    let payload = "x".repeat(64 * 1024);
    let command = format!("/usr/bin/printf {payload}");
    let output = run_cli(&["run", "--backend", "os", "--command", &command]);
    let response = parse_run_response(output);

    assert_eq!(response.exit_code, Some(0));
    assert!(
        response.stdout.len() >= 65_536,
        "stdout 长度应至少为 65536，实际长度: {}",
        response.stdout.len()
    );
}

#[test]
fn repeated_create_destroy_no_leak() {
    for index in 0..5 {
        let command = format!("/bin/echo {index}");
        let output = run_cli(&["run", "--backend", "os", "--command", &command]);
        let response = parse_run_response(output);

        assert_eq!(response.exit_code, Some(0));
    }
}

#[test]
fn stdout_exact_match() {
    let output = run_cli(&[
        "run",
        "--backend",
        "os",
        "--command",
        "/bin/echo hello mimobox",
    ]);
    let response = parse_run_response(output);

    assert_eq!(response.stdout.trim(), "hello mimobox");
}
