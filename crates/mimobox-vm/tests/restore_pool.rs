#![cfg(all(target_os = "linux", feature = "kvm"))]

use mimobox_core::SandboxConfig;
use mimobox_vm::{
    GuestCommandResult, KvmBackend, KvmExitReason, MicrovmConfig, RestorePool, RestorePoolConfig,
    RestorePoolError, microvm_config_from_vm_assets,
};

fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err}"),
    }
}

fn e2e_config() -> MicrovmConfig {
    must(
        microvm_config_from_vm_assets(256),
        "加载 RestorePool 测试 VM assets 配置失败",
    )
}

fn guest_cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

fn create_restore_pool(
    base_config: SandboxConfig,
    config: MicrovmConfig,
    pool_config: RestorePoolConfig,
) -> Result<RestorePool, RestorePoolError> {
    RestorePool::new(base_config, config, pool_config)
}

fn build_booted_snapshot(config: &MicrovmConfig) -> (Vec<u8>, Vec<u8>) {
    let mut backend = must(
        KvmBackend::create_vm(SandboxConfig::default(), config.clone()),
        "创建快照源 VM 失败",
    );

    let exit_reason = must(backend.boot(), "启动快照源 VM 失败");
    assert_eq!(
        exit_reason,
        KvmExitReason::Io,
        "guest init 应进入命令循环并等待串口命令"
    );

    let serial = String::from_utf8_lossy(backend.serial_output());
    assert!(
        serial.contains("mimobox-kvm: init OK"),
        "boot 串口输出必须来自 guest /init"
    );
    assert!(serial.contains("READY"), "guest init 必须打印 READY");

    let snapshot = must(backend.snapshot_state(), "导出 booted snapshot 失败");
    must(backend.shutdown(), "关闭快照源 VM 失败");
    snapshot
}

fn assert_success(result: GuestCommandResult, expected_stdout: &[u8]) {
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, expected_stdout);
    assert!(result.stderr.is_empty(), "该命令不应产生 stderr");
    assert!(!result.timed_out, "该命令不应超时");
}

fn restore_pool_config(min_size: usize, max_size: usize) -> RestorePoolConfig {
    RestorePoolConfig { min_size, max_size }
}

#[test]
fn test_restore_pool_creates_and_warms() {
    let config = e2e_config();
    let (memory, vcpu_state) = build_booted_snapshot(&config);
    let pool = must(
        create_restore_pool(SandboxConfig::default(), config, restore_pool_config(2, 4)),
        "创建 RestorePool 失败",
    );

    let mut first = must(
        pool.restore(memory.as_slice(), vcpu_state.as_slice()),
        "获取第一个恢复态 VM 失败",
    );
    let mut second = must(
        pool.restore(memory.as_slice(), vcpu_state.as_slice()),
        "获取第二个恢复态 VM 失败",
    );

    assert_success(
        must(
            first.execute(&guest_cmd(&["/bin/echo", "warm-1"])),
            "首个预热恢复态 VM 执行命令失败",
        ),
        b"warm-1\n",
    );
    assert_success(
        must(
            second.execute(&guest_cmd(&["/bin/echo", "warm-2"])),
            "第二个预热恢复态 VM 执行命令失败",
        ),
        b"warm-2\n",
    );
}

#[test]
fn test_restore_pool_restore_and_execute() {
    let config = e2e_config();
    let (memory, vcpu_state) = build_booted_snapshot(&config);
    let pool = must(
        create_restore_pool(SandboxConfig::default(), config, restore_pool_config(1, 2)),
        "创建 RestorePool 失败",
    );

    let mut restored = must(
        pool.restore(memory.as_slice(), vcpu_state.as_slice()),
        "从池中恢复 VM 失败",
    );
    let result = must(
        restored.execute(&guest_cmd(&["/bin/echo", "hello-from-restore-pool"])),
        "恢复态 VM 执行命令失败",
    );

    assert_success(result, b"hello-from-restore-pool\n");
}

#[test]
fn test_restore_pool_execute_result_correctness() {
    let config = e2e_config();
    let (memory, vcpu_state) = build_booted_snapshot(&config);
    let base_config = SandboxConfig {
        timeout_secs: Some(1),
        ..SandboxConfig::default()
    };
    let pool = must(
        create_restore_pool(base_config, config, restore_pool_config(1, 2)),
        "创建带超时配置的 RestorePool 失败",
    );

    let mut non_zero_exit = must(
        pool.restore(memory.as_slice(), vcpu_state.as_slice()),
        "恢复 non-zero exit 场景 VM 失败",
    );
    let result = must(
        non_zero_exit.execute(&guest_cmd(&[
            "/bin/sh",
            "-lc",
            "printf payload; printf warn >&2; exit 7",
        ])),
        "执行 non-zero exit 场景命令失败",
    );
    assert_eq!(result.exit_code, Some(7));
    assert_eq!(result.stdout, b"payload");
    assert_eq!(result.stderr, b"warn");
    assert!(!result.timed_out, "非零退出码结果不应被误判为超时");
    drop(non_zero_exit);

    let mut timeout_vm = must(
        pool.restore(memory.as_slice(), vcpu_state.as_slice()),
        "恢复 timeout 场景 VM 失败",
    );
    let timeout_result = must(
        timeout_vm.execute(&guest_cmd(&["/bin/sh", "-lc", "while :; do :; done"])),
        "执行超时场景命令失败",
    );
    assert!(timeout_result.timed_out, "忙等命令必须标记为超时");
    assert_eq!(timeout_result.exit_code, None, "超时结果不应带退出码");
    assert!(timeout_result.stdout.is_empty(), "超时结果不应包含 stdout");
    assert!(timeout_result.stderr.is_empty(), "超时结果不应包含 stderr");
}

#[test]
fn test_restore_pool_sequential_restore_cycles() {
    let config = e2e_config();
    let (memory, vcpu_state) = build_booted_snapshot(&config);
    let pool = must(
        create_restore_pool(SandboxConfig::default(), config, restore_pool_config(1, 2)),
        "创建 RestorePool 失败",
    );

    for marker in ["cycle-1", "cycle-2", "cycle-3", "cycle-4"] {
        let mut restored = must(
            pool.restore(memory.as_slice(), vcpu_state.as_slice()),
            "连续恢复循环中获取 VM 失败",
        );
        let result = must(
            restored.execute(&guest_cmd(&["/bin/echo", marker])),
            "连续恢复循环中执行命令失败",
        );
        let expected = format!("{marker}\n");
        assert_success(result, expected.as_bytes());
    }
}

#[test]
fn test_restore_pool_stats_tracking() {
    let config = e2e_config();
    let (memory, vcpu_state) = build_booted_snapshot(&config);
    let pool = must(
        create_restore_pool(SandboxConfig::default(), config, restore_pool_config(1, 1)),
        "创建 RestorePool 失败",
    );

    // 当前 RestorePool 尚未公开 stats()，这里通过可观察行为验证 in-use / release 路径：
    // 持有第一个恢复态 VM 时再次 restore 必须成功；全部 Drop 后池子也必须可继续恢复。
    let mut first = must(
        pool.restore(memory.as_slice(), vcpu_state.as_slice()),
        "获取首个恢复态 VM 失败",
    );
    let mut second = must(
        pool.restore(memory.as_slice(), vcpu_state.as_slice()),
        "持有首个 VM 时再次 restore 失败",
    );

    assert_success(
        must(
            first.execute(&guest_cmd(&["/bin/echo", "first-in-use"])),
            "首个恢复态 VM 执行命令失败",
        ),
        b"first-in-use\n",
    );
    assert_success(
        must(
            second.execute(&guest_cmd(&["/bin/echo", "second-in-use"])),
            "第二个恢复态 VM 执行命令失败",
        ),
        b"second-in-use\n",
    );

    drop(first);
    drop(second);

    let mut restored_after_release = must(
        pool.restore(memory.as_slice(), vcpu_state.as_slice()),
        "释放后再次 restore 失败",
    );
    assert_success(
        must(
            restored_after_release.execute(&guest_cmd(&["/bin/echo", "after-release"])),
            "释放后再次恢复的 VM 执行命令失败",
        ),
        b"after-release\n",
    );
}
