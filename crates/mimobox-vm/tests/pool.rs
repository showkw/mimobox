use std::time::Duration;

use mimobox_vm::{
    GuestCommandResult, MicrovmConfig, VmPool, VmPoolConfig, microvm_config_from_vm_assets,
};

fn e2e_config() -> MicrovmConfig {
    microvm_config_from_vm_assets(64).expect("加载 pool 测试 VM assets 配置必须成功")
}

fn guest_cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

fn pool_config(min_size: usize, max_size: usize) -> VmPoolConfig {
    VmPoolConfig {
        min_size,
        max_size,
        max_idle_duration: Duration::from_secs(30),
        health_check_interval: None,
    }
}

fn assert_success(result: GuestCommandResult, expected_stdout: &[u8]) {
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, expected_stdout);
    assert!(result.stderr.is_empty(), "当前协议阶段暂不拆分 stderr");
    assert!(!result.timed_out, "该命令不应超时");
}

fn require_pool(config: VmPoolConfig) -> Option<VmPool> {
    if !cfg!(all(target_os = "linux", feature = "kvm")) {
        return None;
    }

    match VmPool::new(e2e_config(), config) {
        Ok(pool) => Some(pool),
        Err(err) => panic!("当前环境应支持 KVM，创建 VM 池失败: {err}"),
    }
}

#[test]
fn test_vm_pool_prewarms() {
    let Some(pool) = require_pool(pool_config(2, 4)) else {
        return;
    };

    let stats = pool.stats().expect("读取池统计必须成功");
    assert_eq!(stats.idle_count, 2);
    assert_eq!(stats.in_use_count, 0);
    assert_eq!(stats.hit_count, 0);
    assert_eq!(stats.miss_count, 0);
}

#[test]
fn test_vm_pool_acquire_returns_booted_vm() {
    let Some(pool) = require_pool(pool_config(1, 2)) else {
        return;
    };

    let mut vm = pool.acquire().expect("从池中获取 VM 必须成功");
    let result = vm
        .execute(&guest_cmd(&["/bin/echo", "ready"]))
        .expect("预热后的 VM 必须能直接执行命令");

    assert_success(result, b"ready\n");

    let stats = pool.stats().expect("读取池统计必须成功");
    assert_eq!(stats.hit_count, 1);
    assert_eq!(stats.miss_count, 0);
    assert_eq!(stats.idle_count, 0);
    assert_eq!(stats.in_use_count, 1);
}

#[test]
fn test_vm_pool_recycle_reuses_vm() {
    let Some(pool) = require_pool(pool_config(0, 1)) else {
        return;
    };

    {
        let mut vm = pool.acquire().expect("第一次获取 VM 必须成功");
        let result = vm
            .execute(&guest_cmd(&["/bin/echo", "first"]))
            .expect("第一次执行命令必须成功");
        assert_success(result, b"first\n");
    }

    {
        let mut vm = pool.acquire().expect("第二次获取 VM 必须成功");
        let result = vm
            .execute(&guest_cmd(&["/bin/echo", "second"]))
            .expect("回收后的 VM 必须能再次执行命令");
        assert_success(result, b"second\n");
    }

    let stats = pool.stats().expect("读取池统计必须成功");
    assert_eq!(stats.miss_count, 1, "第一次获取应触发按需创建");
    assert_eq!(stats.hit_count, 1, "第二次获取应直接复用 idle VM");
    assert_eq!(stats.idle_count, 1);
    assert_eq!(stats.in_use_count, 0);
}

#[test]
fn test_vm_pool_stats_tracking() {
    let Some(pool) = require_pool(pool_config(1, 1)) else {
        return;
    };

    let first = pool.acquire().expect("获取首个 VM 必须成功");
    let after_first = pool.stats().expect("读取统计必须成功");
    assert_eq!(after_first.hit_count, 1);
    assert_eq!(after_first.miss_count, 0);
    assert_eq!(after_first.idle_count, 0);
    assert_eq!(after_first.in_use_count, 1);

    let second = pool.acquire().expect("获取第二个 VM 必须成功");
    let after_second = pool.stats().expect("读取统计必须成功");
    assert_eq!(after_second.hit_count, 1);
    assert_eq!(after_second.miss_count, 1);
    assert_eq!(after_second.idle_count, 0);
    assert_eq!(after_second.in_use_count, 2);

    drop(first);
    let after_drop_first = pool.stats().expect("读取统计必须成功");
    assert_eq!(after_drop_first.idle_count, 1);
    assert_eq!(after_drop_first.in_use_count, 1);

    drop(second);
    let after_drop_second = pool.stats().expect("读取统计必须成功");
    assert_eq!(after_drop_second.idle_count, 1);
    assert_eq!(after_drop_second.in_use_count, 0);
    assert_eq!(after_drop_second.evict_count, 1);
}
