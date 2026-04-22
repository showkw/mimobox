#![cfg(unix)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde::Deserialize;

static CLI_BUILD: OnceLock<()> = OnceLock::new();
static WORKSPACE_ROOT: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct RunResponseEnvelope {
    ok: bool,
    command: String,
    backend: String,
    requested_backend: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
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
    assert_eq!(response.backend, "os");
    assert_eq!(response.exit_code, Some(0));
    assert!(
        response.stdout.contains("hello"),
        "stdout 应包含 hello，实际 stdout: {}",
        response.stdout
    );
}

#[test]
fn invalid_command_returns_error() {
    let output = run_cli(&[
        "run",
        "--backend",
        "auto",
        "--command",
        // 使用 echo 而非 printf：printf 使用的 syscall 被 seccomp 过滤器拒绝（SIGSYS），
        // 而 /bin/echo 已验证在沙箱白名单中可正常执行
        "/bin/sh -c 'echo fail >&2; exit 7'",
    ]);
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
