#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::collections::HashMap;
use std::path::PathBuf;

use mimobox_core::{ErrorCode, Sandbox, SandboxConfig};
use mimobox_sdk::{Config as SdkConfig, IsolationLevel, Sandbox as SdkSandbox, SdkError};
use mimobox_vm::{
    KvmBackend, KvmExitReason, MicrovmConfig, MicrovmError, MicrovmSandbox, StreamEvent,
    microvm_config_from_vm_assets, resolve_vm_assets_dir,
};

const HTTP_PROXY_ALLOWED_HOST: &str = "api.github.com";
const HTTP_PROXY_ALLOWED_URL: &str = "https://api.github.com/zen";
const HTTP_PROXY_LOCAL_IP_URL: &str = "https://127.0.0.1";

fn e2e_config() -> MicrovmConfig {
    microvm_config_from_vm_assets(256).expect("加载 e2e VM assets 配置必须成功")
}

fn guest_cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

fn sdk_http_config(allowed_http_domains: &[&str]) -> SdkConfig {
    let vm_config = e2e_config();

    SdkConfig::builder()
        .isolation(IsolationLevel::MicroVm)
        .vm_vcpu_count(vm_config.vcpu_count)
        .vm_memory_mb(vm_config.memory_mb)
        .kernel_path(vm_config.kernel_path)
        .rootfs_path(vm_config.rootfs_path)
        .allowed_http_domains(allowed_http_domains.iter().copied())
        .build()
}

fn github_zen_headers() -> HashMap<String, String> {
    HashMap::from([
        ("User-Agent".to_string(), "mimobox-kvm-e2e".to_string()),
        (
            "Accept".to_string(),
            "application/vnd.github+json".to_string(),
        ),
    ])
}

fn assert_http_denied_host(error: SdkError) {
    match error {
        SdkError::Sandbox {
            code: ErrorCode::HttpDeniedHost,
            ..
        } => {}
        other => panic!("预期收到 HttpDeniedHost，实际为: {other}"),
    }
}

#[test]
fn test_vm_assets_dir_prefers_env_override() {
    let override_dir = PathBuf::from("/tmp/mimobox-custom-vm-assets");

    let actual =
        resolve_vm_assets_dir(Some(override_dir.clone()), None).expect("环境变量覆盖必须成功");

    assert_eq!(actual, override_dir);
}

#[test]
fn test_vm_assets_dir_falls_back_to_home_default() {
    let home_dir = PathBuf::from("/tmp/mimobox-home");

    let actual = resolve_vm_assets_dir(None, Some(home_dir.clone())).expect("默认回退必须成功");

    assert_eq!(actual, home_dir.join("mimobox-poc/vm-assets"));
}

#[test]
fn test_kvm_vm_boots() {
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), e2e_config()).expect("创建 VM 必须成功");

    let exit_reason = backend.boot().expect("guest 启动必须成功");
    assert_eq!(
        exit_reason,
        KvmExitReason::Io,
        "guest init 进入命令循环后应保持运行，并等待下一条串口命令"
    );
    let serial = String::from_utf8_lossy(backend.serial_output());
    assert!(
        serial.contains("mimobox-kvm: init OK"),
        "boot 串口输出必须来自 guest /init，而不是 host stub"
    );
    assert!(
        serial.contains("READY"),
        "guest init 准备好接收命令后必须打印 READY"
    );

    backend.shutdown().expect("关闭 VM 必须成功");
}

#[test]
fn test_kvm_vm_executes() {
    let mut sandbox = MicrovmSandbox::new(e2e_config()).expect("创建 microVM 沙箱必须成功");

    let result = sandbox
        .execute(&guest_cmd(&["/bin/echo", "hello"]))
        .expect("guest 命令执行必须成功");

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"hello\n");
    assert!(result.stderr.is_empty(), "echo 不应产生 stderr");
    assert!(!result.timed_out, "echo 不应触发超时");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_execute_with_env_vars() {
    let mut sandbox = MicrovmSandbox::new(e2e_config()).expect("创建 microVM 沙箱必须成功");
    let env = HashMap::from([("MY_VAR".to_string(), "hello".to_string())]);

    let result = sandbox
        .execute_with_env(&guest_cmd(&["/bin/sh", "-lc", "echo \"$MY_VAR\""]), env)
        .expect("带环境变量的命令必须成功执行");

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"hello\n");
    assert!(result.stderr.is_empty(), "echo 不应产生 stderr");
    assert!(!result.timed_out, "环境变量命令不应超时");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_execute_with_timeout() {
    let mut sandbox = MicrovmSandbox::new(e2e_config()).expect("创建 microVM 沙箱必须成功");

    let result = sandbox
        .execute_with_timeout(
            &guest_cmd(&["/bin/sh", "-lc", "sleep 5"]),
            std::time::Duration::from_millis(200),
        )
        .expect("命令级超时也必须返回结果结构");

    assert!(result.timed_out, "短超时必须终止长时间命令");
    assert_eq!(result.exit_code, None, "超时结果不应携带退出码");
    assert!(result.stdout.is_empty(), "超时结果不应包含 stdout");
    assert!(result.stderr.is_empty(), "超时结果不应包含 stderr");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_http_proxy_request() {
    let mut sandbox = SdkSandbox::with_config(sdk_http_config(&[HTTP_PROXY_ALLOWED_HOST]))
        .expect("创建 SDK microVM 沙箱必须成功");

    let response = sandbox
        .http_request("GET", HTTP_PROXY_ALLOWED_URL, github_zen_headers(), None)
        .expect("通过 SDK 发起 HTTP 代理请求必须成功");

    assert_eq!(response.status, 200, "公开 API 请求应返回 200");
    assert!(!response.body.is_empty(), "HTTP 代理响应 body 不应为空");

    sandbox.destroy().expect("销毁 SDK microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_http_proxy_denied_host() {
    let mut sandbox =
        SdkSandbox::with_config(sdk_http_config(&[])).expect("创建 SDK microVM 沙箱必须成功");

    let error =
        match sandbox.http_request("GET", HTTP_PROXY_ALLOWED_URL, github_zen_headers(), None) {
            Ok(_) => panic!("白名单缺失时请求必须被拒绝"),
            Err(error) => error,
        };

    assert_http_denied_host(error);

    sandbox.destroy().expect("销毁 SDK microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_http_proxy_ip_rejected() {
    let mut sandbox = SdkSandbox::with_config(sdk_http_config(&["127.0.0.1"]))
        .expect("创建 SDK microVM 沙箱必须成功");

    let error = match sandbox.http_request("GET", HTTP_PROXY_LOCAL_IP_URL, HashMap::new(), None) {
        Ok(_) => panic!("回环 IP 直连必须被拒绝"),
        Err(error) => error,
    };

    assert_http_denied_host(error);

    sandbox.destroy().expect("销毁 SDK microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_executes_argument_with_newline() {
    let mut sandbox = MicrovmSandbox::new(e2e_config()).expect("创建 microVM 沙箱必须成功");

    let result = sandbox
        .execute(&guest_cmd(&["/bin/printf", "%s", "hello\nworld"]))
        .expect("包含换行参数的命令必须成功执行");

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"hello\nworld");
    assert!(result.stderr.is_empty(), "printf 不应产生 stderr");
    assert!(!result.timed_out, "换行参数不应被误判为协议超时");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_separates_stdout_and_stderr() {
    let mut sandbox = MicrovmSandbox::new(e2e_config()).expect("创建 microVM 沙箱必须成功");

    let result = sandbox
        .execute(&guest_cmd(&[
            "/bin/sh",
            "-lc",
            "printf 'hello-stdout'; printf 'hello-stderr' >&2; exit 3",
        ]))
        .expect("stdout/stderr 混合命令必须成功执行");

    assert_eq!(result.exit_code, Some(3));
    assert_eq!(result.stdout, b"hello-stdout");
    assert_eq!(result.stderr, b"hello-stderr");
    assert!(!result.timed_out, "正常退出的混合输出命令不应超时");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_exit_code_124_is_not_timeout() {
    let base_config = SandboxConfig {
        timeout_secs: Some(1),
        ..SandboxConfig::default()
    };
    let mut sandbox = MicrovmSandbox::new_with_base(base_config, e2e_config())
        .expect("创建带超时的 microVM 沙箱必须成功");

    let result = sandbox
        .execute(&guest_cmd(&["/bin/sh", "-lc", "exit 124"]))
        .expect("退出码 124 的命令必须返回结果结构");

    assert_eq!(result.exit_code, Some(124));
    assert!(!result.timed_out, "用户命令合法返回 124 时不应被误判为超时");
    assert!(result.stdout.is_empty(), "exit 124 不应产生 stdout");
    assert!(result.stderr.is_empty(), "exit 124 不应产生 stderr");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_timeout_marks_result() {
    let base_config = SandboxConfig {
        timeout_secs: Some(1),
        ..SandboxConfig::default()
    };
    let mut sandbox = MicrovmSandbox::new_with_base(base_config, e2e_config())
        .expect("创建带超时的 microVM 沙箱必须成功");

    let result = sandbox
        .execute(&guest_cmd(&["/bin/sh", "-lc", "while :; do :; done"]))
        .expect("超时命令也必须返回结果结构");

    assert!(
        result.timed_out,
        "guest 长时间不返回协议响应时必须标记为超时"
    );
    assert_eq!(result.exit_code, None, "超时结果不应携带正常退出码");
    assert!(result.stdout.is_empty(), "忙等命令不应产生 stdout");
    assert!(result.stderr.is_empty(), "忙等命令不应产生 stderr");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_vm_stream_execute_separates_stdout_and_stderr() {
    let mut sandbox = MicrovmSandbox::new(e2e_config()).expect("创建 microVM 沙箱必须成功");

    let receiver = sandbox
        .stream_execute(&guest_cmd(&[
            "/bin/sh",
            "-lc",
            "printf 'stdout-1\\n'; sleep 0.1; printf 'stderr-1\\n' >&2; sleep 0.1; printf 'stdout-2\\n'; sleep 0.1; printf 'stderr-2\\n' >&2; exit 7",
        ]))
        .expect("流式执行必须成功");

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = None;
    let mut timed_out = false;

    for event in receiver {
        match event {
            StreamEvent::Stdout(data) => stdout.extend(data),
            StreamEvent::Stderr(data) => stderr.extend(data),
            StreamEvent::Exit(code) => exit_code = Some(code),
            StreamEvent::TimedOut => timed_out = true,
        }
    }

    assert_eq!(stdout, b"stdout-1\nstdout-2\n");
    assert_eq!(stderr, b"stderr-1\nstderr-2\n");
    assert_eq!(exit_code, Some(7));
    assert!(!timed_out, "正常退出的流式命令不应超时");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_snapshot_restore() {
    let config = e2e_config();
    let mut backend = KvmBackend::create_vm(SandboxConfig::default(), config.clone())
        .expect("创建源 VM 必须成功");

    backend.boot().expect("源 VM 启动必须成功");
    let (memory, vcpu_state) = backend.snapshot_state().expect("导出快照必须成功");
    let serial_before = backend.serial_output().to_vec();

    let mut restored =
        KvmBackend::create_vm(SandboxConfig::default(), config).expect("创建恢复 VM 必须成功");
    restored
        .restore_state(&memory, &vcpu_state)
        .expect("恢复 VM 状态必须成功");

    assert_eq!(restored.serial_output(), serial_before.as_slice());

    backend.shutdown().expect("关闭源 VM 必须成功");
    restored.shutdown().expect("关闭恢复 VM 必须成功");
}

#[test]
fn test_kvm_snapshot_restore_executes_command() {
    let config = e2e_config();
    let mut backend = KvmBackend::create_vm(SandboxConfig::default(), config.clone())
        .expect("创建源 VM 必须成功");

    backend.boot().expect("源 VM 启动必须成功");
    let (memory, vcpu_state) = backend.snapshot_state().expect("导出快照必须成功");

    let mut restored =
        KvmBackend::create_vm(SandboxConfig::default(), config).expect("创建恢复 VM 必须成功");
    restored
        .restore_state(&memory, &vcpu_state)
        .expect("恢复 VM 状态必须成功");

    let result = restored
        .run_command(&guest_cmd(&["/bin/echo", "hello"]))
        .expect("恢复后的 VM 必须能继续执行命令");

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"hello\n");
    assert!(result.stderr.is_empty(), "恢复后的 echo 不应产生 stderr");
    assert!(!result.timed_out, "恢复后的 echo 不应超时");

    backend.shutdown().expect("关闭源 VM 必须成功");
    restored.shutdown().expect("关闭恢复 VM 必须成功");
}

#[test]
fn test_kvm_vm_write_and_read_file() {
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), e2e_config()).expect("创建 VM 必须成功");
    let file_path = "/sandbox/phase-a-fs.bin";
    let expected = b"hello\nphase-a\x00payload";

    backend
        .write_file(file_path, expected)
        .expect("guest 写文件必须成功");
    let actual = backend.read_file(file_path).expect("guest 读文件必须成功");

    assert_eq!(actual, expected);

    backend.shutdown().expect("关闭 VM 必须成功");
}

#[test]
fn test_kvm_vm_read_nonexistent_file() {
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), e2e_config()).expect("创建 VM 必须成功");

    let error = backend
        .read_file("/sandbox/phase-a-missing.txt")
        .expect_err("读取不存在文件必须失败");

    assert!(
        matches!(error, MicrovmError::Backend(ref message) if message.contains("路径错误")),
        "不存在文件应映射为路径错误: {error}"
    );

    backend.shutdown().expect("关闭 VM 必须成功");
}
