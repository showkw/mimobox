#![cfg(all(target_os = "linux", feature = "vm"))]

use std::time::{Duration, Instant};

use mimobox_sdk::{Config, IsolationLevel, RestorePool, RestorePoolConfig, Sandbox};
use mimobox_vm::microvm_config_from_vm_assets;

fn snapshot_config() -> Config {
    let microvm_config =
        microvm_config_from_vm_assets(256).expect("加载 SDK snapshot 测试 VM assets 配置必须成功");

    Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .vm_memory_mb(microvm_config.memory_mb)
        .kernel_path(microvm_config.kernel_path)
        .rootfs_path(microvm_config.rootfs_path)
        .build()
}

fn assert_stdout(result: mimobox_sdk::ExecuteResult, expected_stdout: &[u8]) {
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
fn test_sdk_fork_returns_independent_sandboxes() {
    let mut sandbox = Sandbox::with_config(snapshot_config()).expect("创建 SDK 沙箱必须成功");

    sandbox
        .execute("/bin/sh -lc 'echo seed > /tmp/fork.txt'")
        .expect("初始化原始沙箱状态必须成功");

    let mut forked = sandbox.fork().expect("fork 沙箱必须成功");

    sandbox
        .execute("/bin/sh -lc 'echo original > /tmp/fork.txt'")
        .expect("写入原始沙箱状态必须成功");
    forked
        .execute("/bin/sh -lc 'echo forked > /tmp/fork.txt'")
        .expect("写入 fork 沙箱状态必须成功");

    let original_result = sandbox
        .execute("/bin/cat /tmp/fork.txt")
        .expect("读取原始沙箱状态必须成功");
    let forked_result = forked
        .execute("/bin/cat /tmp/fork.txt")
        .expect("读取 fork 沙箱状态必须成功");

    assert_stdout(original_result, b"original\n");
    assert_stdout(forked_result, b"forked\n");

    sandbox.destroy().expect("销毁原始沙箱必须成功");
    forked.destroy().expect("销毁 fork 沙箱必须成功");
}

#[test]
fn test_sdk_restore_pool_restores_snapshot_and_executes() {
    let config = snapshot_config();
    let mut sandbox = Sandbox::with_config(config.clone()).expect("创建 SDK 沙箱必须成功");

    sandbox
        .execute("/bin/sh -lc 'echo restored > /tmp/restore.txt'")
        .expect("准备 restore 快照状态必须成功");
    let snapshot = sandbox.snapshot().expect("拍摄快照必须成功");
    assert!(
        snapshot.memory_file_path().is_some(),
        "microVM snapshot 应返回文件模式快照"
    );
    assert!(
        !snapshot
            .to_bytes()
            .expect("文件快照应可重建为自描述字节")
            .is_empty(),
        "文件快照重建后的字节不应为空"
    );
    sandbox.destroy().expect("销毁种子沙箱必须成功");

    let pool = RestorePool::new(RestorePoolConfig {
        pool_size: 1,
        base_config: config,
    })
    .expect("创建 SDK RestorePool 必须成功");
    assert_eq!(pool.idle_count(), 1, "初始恢复池应预热 1 个空闲槽位");

    let restore_started_at = Instant::now();
    let mut restored = pool.restore(&snapshot).expect("从恢复池恢复沙箱必须成功");
    let restore_elapsed = restore_started_at.elapsed();

    let result = restored
        .execute("/bin/cat /tmp/restore.txt")
        .expect("恢复态沙箱执行命令必须成功");
    assert_stdout(result, b"restored\n");
    assert!(
        restore_elapsed < Duration::from_secs(1),
        "恢复路径应明显快于冷启动，当前耗时: {:?}",
        restore_elapsed
    );

    restored.destroy().expect("销毁恢复态沙箱必须成功");
    pool.warm(1).expect("恢复池补温必须成功");
    assert!(pool.idle_count() >= 1, "恢复池补温后至少应保留一个空闲槽位");
}
