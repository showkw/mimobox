#[cfg(all(target_os = "linux", feature = "kvm"))]
use std::time::Instant;

#[cfg(all(target_os = "linux", feature = "kvm"))]
use criterion::{Criterion, black_box, criterion_group, criterion_main};
#[cfg(all(target_os = "linux", feature = "kvm"))]
use mimobox_core::SandboxConfig;
#[cfg(all(target_os = "linux", feature = "kvm"))]
use mimobox_vm::{
    KvmBackend, KvmExitReason, MicrovmConfig, RestorePool, RestorePoolConfig, VmPool, VmPoolConfig,
    microvm_config_from_vm_assets,
};

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err}"),
    }
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn benchmark_config() -> MicrovmConfig {
    must(
        microvm_config_from_vm_assets(256),
        "加载 benchmark VM assets 配置失败",
    )
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn guest_cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn create_backend(config: &MicrovmConfig) -> KvmBackend {
    must(
        KvmBackend::create_vm(SandboxConfig::default(), config.clone()),
        "创建 KVM 后端失败",
    )
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn boot_backend(backend: &mut KvmBackend) {
    let exit_reason = must(backend.boot(), "启动 guest 失败");
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
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn build_booted_snapshot(config: &MicrovmConfig) -> (Vec<u8>, Vec<u8>) {
    let mut backend = create_backend(config);
    boot_backend(&mut backend);
    let snapshot = must(backend.snapshot_state(), "保存快照失败");
    must(backend.shutdown(), "关闭预热 VM 失败");
    snapshot
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn bench_cold_start(c: &mut Criterion) {
    let config = benchmark_config();
    let command = guest_cmd(&["/bin/echo", "hello"]);

    c.bench_function("bench_cold_start", |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let mut backend = create_backend(&config);
                boot_backend(&mut backend);

                let result = must(
                    backend.run_command(black_box(command.as_slice())),
                    "冷启动命令执行失败",
                );
                assert_eq!(result.exit_code, Some(0), "echo 命令必须成功");
                black_box(result);

                must(backend.shutdown(), "关闭冷启动 VM 失败");
            }

            total_start.elapsed()
        });
    });
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn bench_snapshot_restore(c: &mut Criterion) {
    let config = benchmark_config();
    let command = guest_cmd(&["/bin/echo", "hello"]);
    let (memory, vcpu_state) = build_booted_snapshot(&config);

    c.bench_function("bench_snapshot_restore", |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let mut backend = must(
                    KvmBackend::create_vm_for_restore(SandboxConfig::default(), config.clone()),
                    "创建 restore 用 KVM 后端失败",
                );
                must(
                    backend.restore_state(memory.as_slice(), vcpu_state.as_slice()),
                    "恢复快照失败",
                );

                let result = must(
                    backend.run_command(black_box(command.as_slice())),
                    "快照恢复后的命令执行失败",
                );
                assert_eq!(result.exit_code, Some(0), "恢复后的 echo 命令必须成功");
                black_box(result);

                must(backend.shutdown(), "关闭恢复 VM 失败");
            }

            total_start.elapsed()
        });
    });
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn bench_restore_pool(c: &mut Criterion) {
    let config = benchmark_config();
    let command = guest_cmd(&["/bin/echo", "hello"]);
    let (memory, vcpu_state) = build_booted_snapshot(&config);
    let pool = must(
        RestorePool::new(
            SandboxConfig::default(),
            config,
            RestorePoolConfig {
                min_size: 1,
                max_size: 4,
            },
        ),
        "创建 restore pool 失败",
    );

    c.bench_function("bench_restore_pool", |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let mut restored = must(
                    pool.restore(memory.as_slice(), vcpu_state.as_slice()),
                    "从 restore pool 恢复 VM 失败",
                );

                let result = must(
                    restored.execute(black_box(command.as_slice())),
                    "restore pool 命令执行失败",
                );
                assert_eq!(result.exit_code, Some(0), "restore pool echo 命令必须成功");
                black_box(result);

                drop(restored);
            }

            total_start.elapsed()
        });
    });
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn bench_command_execution(c: &mut Criterion) {
    let config = benchmark_config();
    let commands = [
        guest_cmd(&["/bin/echo", "alpha"]),
        guest_cmd(&["/bin/echo", "beta"]),
        guest_cmd(&["/bin/true"]),
    ];

    c.bench_function("bench_command_execution", |b| {
        b.iter_custom(|iters| {
            let mut backend = create_backend(&config);
            boot_backend(&mut backend);

            let total_start = Instant::now();

            for index in 0..iters {
                let command = &commands[index as usize % commands.len()];
                let result = must(
                    backend.run_command(black_box(command.as_slice())),
                    "连续命令执行失败",
                );
                assert_eq!(result.exit_code, Some(0), "连续命令必须成功");
                black_box(result);
            }

            let elapsed = total_start.elapsed();
            must(backend.shutdown(), "关闭命令执行 VM 失败");
            elapsed
        });
    });
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn bench_pool_hot_path(c: &mut Criterion) {
    use std::time::Duration;

    let config = benchmark_config();
    let pool_config = VmPoolConfig {
        min_size: 1,
        max_size: 4,
        max_idle_duration: Duration::from_secs(60),
        health_check_interval: None,
    };
    let pool = must(VmPool::new(config, pool_config), "创建预热池失败");
    let command = guest_cmd(&["/bin/echo", "hello"]);

    c.bench_function("bench_pool_hot_path", |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let mut pooled = must(pool.acquire(), "从预热池获取 VM 失败");
                let result = must(
                    pooled.execute(black_box(command.as_slice())),
                    "预热池命令执行失败",
                );
                assert_eq!(result.exit_code, Some(0), "预热池 echo 命令必须成功");
                black_box(result);
                drop(pooled);
            }

            total_start.elapsed()
        });
    });
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
criterion_group!(
    kvm_benches,
    bench_cold_start,
    bench_snapshot_restore,
    bench_restore_pool,
    bench_command_execution,
    bench_pool_hot_path
);
#[cfg(all(target_os = "linux", feature = "kvm"))]
criterion_main!(kvm_benches);

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
fn main() {}
