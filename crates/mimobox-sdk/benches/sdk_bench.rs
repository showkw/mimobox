#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use criterion::{Criterion, black_box, criterion_group, criterion_main};
#[cfg(target_os = "linux")]
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

#[cfg(target_os = "linux")]
fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err}"),
    }
}

#[cfg(target_os = "linux")]
fn os_config() -> Config {
    Config::builder()
        .isolation(IsolationLevel::Os)
        .timeout(Duration::from_secs(10))
        .memory_limit_mb(256)
        .build().expect("valid config")
}

#[cfg(target_os = "linux")]
fn bench_config_resolve(c: &mut Criterion) {
    c.bench_function("bench_config_resolve", |b| {
        b.iter(|| {
            let config = Config::default();
            black_box(config);
        });
    });
}

#[cfg(target_os = "linux")]
fn bench_config_builder_chain(c: &mut Criterion) {
    c.bench_function("bench_config_builder_chain", |b| {
        b.iter(|| {
            let config = Config::builder()
                .isolation(IsolationLevel::Os)
                .timeout(Duration::from_secs(10))
                .memory_limit_mb(256)
                .build().expect("valid config");
            black_box(config);
        });
    });
}

#[cfg(target_os = "linux")]
fn bench_sandbox_create_destroy(c: &mut Criterion) {
    c.bench_function("bench_sandbox_create_destroy", |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let mut sandbox = must(Sandbox::with_config(os_config()), "创建 OS 级沙箱失败");
                let result = must(
                    sandbox.execute(black_box("/bin/echo hello")),
                    "执行 echo 失败",
                );
                assert_eq!(result.exit_code, Some(0), "echo 命令必须成功");
                black_box(result);
                must(sandbox.destroy(), "销毁 OS 级沙箱失败");
            }

            total_start.elapsed()
        });
    });
}

#[cfg(target_os = "linux")]
fn bench_sandbox_execute(c: &mut Criterion) {
    c.bench_function("bench_sandbox_execute", |b| {
        b.iter_custom(|iters| {
            let mut sandbox = must(Sandbox::with_config(os_config()), "创建 OS 级沙箱失败");
            let total_start = Instant::now();

            for _ in 0..iters {
                let result = must(
                    sandbox.execute(black_box("/bin/echo hello")),
                    "执行 echo 失败",
                );
                assert_eq!(result.exit_code, Some(0), "echo 命令必须成功");
                black_box(result);
            }

            let elapsed = total_start.elapsed();
            must(sandbox.destroy(), "销毁 OS 级沙箱失败");
            elapsed
        });
    });
}

#[cfg(target_os = "linux")]
fn bench_auto_routing_decision(c: &mut Criterion) {
    let commands = [
        "/bin/echo hello",
        "/usr/bin/env true",
        "/tmp/app.wasm",
        "python script.py",
    ];

    c.bench_function("bench_auto_routing_decision", |b| {
        b.iter(|| {
            for command in commands {
                let mut sandbox = must(Sandbox::new(), "创建默认 SDK 沙箱失败");
                let result = sandbox.execute(black_box(command));
                black_box(result);
            }
        });
    });
}

#[cfg(target_os = "linux")]
criterion_group!(
    sdk_benches,
    bench_config_resolve,
    bench_config_builder_chain,
    bench_sandbox_create_destroy,
    bench_sandbox_execute,
    bench_auto_routing_decision
);
#[cfg(target_os = "linux")]
criterion_main!(sdk_benches);

#[cfg(not(target_os = "linux"))]
fn main() {}
