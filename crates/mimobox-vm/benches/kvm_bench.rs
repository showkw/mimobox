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
        "failed to load benchmark VM assets config",
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
        "failed to create KVM backend",
    )
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn boot_backend(backend: &mut KvmBackend) {
    let exit_reason = must(backend.boot(), "failed to boot guest");
    assert_eq!(
        exit_reason,
        KvmExitReason::Io,
        "guest init must enter the command loop and wait for serial commands"
    );

    let serial = String::from_utf8_lossy(backend.serial_output());
    assert!(
        serial.contains("mimobox-kvm: init OK"),
        "boot serial output must come from guest /init"
    );
    assert!(serial.contains("READY"), "guest init must print READY");
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn build_booted_snapshot(config: &MicrovmConfig) -> (Vec<u8>, Vec<u8>) {
    let mut backend = create_backend(config);
    boot_backend(&mut backend);
    let snapshot = must(backend.snapshot_state(), "failed to save snapshot");
    must(backend.shutdown(), "failed to shut down warm VM");
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
                    "cold-start command execution failed",
                );
                assert_eq!(result.exit_code, Some(0), "echo command must succeed");
                black_box(result);

                must(backend.shutdown(), "failed to shut down cold-start VM");
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
                    "failed to create KVM backend for restore",
                );
                must(
                    backend.restore_state(memory.as_slice(), vcpu_state.as_slice()),
                    "failed to restore snapshot",
                );

                let result = must(
                    backend.run_command(black_box(command.as_slice())),
                    "command execution after snapshot restore failed",
                );
                assert_eq!(result.exit_code, Some(0), "restored echo command must succeed");
                black_box(result);

                must(backend.shutdown(), "failed to shut down restored VM");
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
        "failed to create restore pool",
    );

    c.bench_function("bench_restore_pool", |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let mut restored = must(
                    pool.restore(memory.as_slice(), vcpu_state.as_slice()),
                    "failed to restore VM from restore pool",
                );

                let result = must(
                    restored.execute(black_box(command.as_slice())),
                    "restore pool command execution failed",
                );
                assert_eq!(result.exit_code, Some(0), "restore pool echo command must succeed");
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
                    "sequential command execution failed",
                );
                assert_eq!(result.exit_code, Some(0), "sequential command must succeed");
                black_box(result);
            }

            let elapsed = total_start.elapsed();
            must(backend.shutdown(), "failed to shut down command execution VM");
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
    let pool = must(VmPool::new(config, pool_config), "failed to create warm pool");
    let command = guest_cmd(&["/bin/echo", "hello"]);

    c.bench_function("bench_pool_hot_path", |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let mut pooled = must(pool.acquire(), "failed to acquire VM from warm pool");
                let result = must(
                    pooled.execute(black_box(command.as_slice())),
                    "warm pool command execution failed",
                );
                assert_eq!(result.exit_code, Some(0), "warm pool echo command must succeed");
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
