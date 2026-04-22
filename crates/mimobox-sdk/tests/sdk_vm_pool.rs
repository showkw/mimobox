#![cfg(all(target_os = "linux", feature = "vm"))]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use mimobox_sdk::{Config, ExecuteResult, IsolationLevel, Sandbox, TrustLevel};
use mimobox_vm::{VmPoolConfig, microvm_config_from_vm_assets};

fn sdk_config() -> Config {
    let microvm_config =
        microvm_config_from_vm_assets(64).expect("加载 SDK VmPool 集成测试 VM assets 配置必须成功");
    let memory_mb = microvm_config.memory_mb;
    let kernel_path = microvm_config.kernel_path;
    let rootfs_path = microvm_config.rootfs_path;

    Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .trust_level(TrustLevel::Untrusted)
        .vm_memory_mb(memory_mb)
        .kernel_path(kernel_path)
        .rootfs_path(rootfs_path)
        .build()
}

fn pool_config() -> VmPoolConfig {
    VmPoolConfig {
        min_size: 1,
        max_size: 2,
        max_idle_duration: Duration::from_secs(30),
        health_check_interval: None,
    }
}

fn pooled_sandbox() -> Sandbox {
    Sandbox::with_pool(sdk_config(), pool_config()).expect("创建带 VM 池的 SDK 沙箱必须成功")
}

fn assert_command_success(result: ExecuteResult, expected_stdout: &[u8]) {
    assert_eq!(result.stdout, expected_stdout, "stdout 输出不符合预期");
    assert!(
        result.stderr.is_empty(),
        "stderr 应为空，实际 stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.exit_code, Some(0), "退出码应为 0");
    assert!(!result.timed_out, "命令不应超时");
}

#[test]
fn test_sdk_pool_acquire_and_execute() {
    let mut sandbox = pooled_sandbox();

    let result = sandbox
        .execute("/bin/echo hello")
        .expect("通过 SDK 的 VmPool 执行 echo 命令必须成功");

    assert_eq!(
        sandbox.active_isolation(),
        Some(IsolationLevel::MicroVm),
        "SDK 应通过 VmPool 路径使用 MicroVm 隔离层级"
    );
    assert_command_success(result, b"hello\n");
}

#[test]
fn test_sdk_pool_reuses_vm() {
    let mut sandbox = pooled_sandbox();

    let first_started_at = Instant::now();
    let first_result = sandbox
        .execute("/bin/echo first")
        .expect("第一次通过 SDK 的 VmPool 执行命令必须成功");
    let first_elapsed = first_started_at.elapsed();

    let second_started_at = Instant::now();
    let second_result = sandbox
        .execute("/bin/echo second")
        .expect("第二次通过 SDK 的 VmPool 执行命令必须成功");
    let second_elapsed = second_started_at.elapsed();

    assert_command_success(first_result, b"first\n");
    assert_command_success(second_result, b"second\n");
    assert!(
        second_elapsed < first_elapsed,
        "第二次执行应比第一次更快，第一次耗时: {:?}，第二次耗时: {:?}",
        first_elapsed,
        second_elapsed
    );
}

#[test]
fn test_sdk_pool_destroy_recycles() {
    let mut sandbox = pooled_sandbox();

    let result = sandbox
        .execute("/bin/echo recycle")
        .expect("销毁前通过 SDK 的 VmPool 执行命令必须成功");
    assert_command_success(result, b"recycle\n");

    let destroy_result = catch_unwind(AssertUnwindSafe(|| sandbox.destroy()));
    assert!(destroy_result.is_ok(), "销毁带 VM 池的 SDK 沙箱不应 panic");

    match destroy_result.expect("销毁带 VM 池的 SDK 沙箱不应 panic") {
        Ok(()) => {}
        Err(error) => panic!("销毁带 VM 池的 SDK 沙箱必须成功: {error}"),
    }
}
