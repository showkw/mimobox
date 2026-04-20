#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::{Arc, Barrier};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::thread;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mimobox_core::{Sandbox, SandboxConfig};
#[cfg(target_os = "linux")]
use mimobox_os::LinuxSandbox as PlatformSandbox;
#[cfg(target_os = "macos")]
use mimobox_os::MacOsSandbox as PlatformSandbox;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mimobox_os::{PoolConfig, SandboxPool};

#[cfg(any(target_os = "linux", target_os = "macos"))]
static HOT_P99_REPORTED: AtomicBool = AtomicBool::new(false);

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn percentile_us(samples: &mut [f64], percentile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    samples.sort_by(f64::total_cmp);
    let last_index = samples.len().saturating_sub(1);
    let raw_index = ((last_index as f64) * percentile).round() as usize;
    let index = raw_index.min(last_index);
    samples[index]
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sandbox_config() -> SandboxConfig {
    SandboxConfig {
        memory_limit_mb: Some(256),
        ..Default::default()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn warmed_pool(pool_size: usize) -> SandboxPool {
    must(
        SandboxPool::new(
            sandbox_config(),
            PoolConfig {
                min_size: pool_size,
                max_size: pool_size,
                max_idle_duration: Duration::from_secs(30),
                health_check_interval: None,
            },
        ),
        "创建预热池失败",
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_platform_sandbox(config: &SandboxConfig) -> PlatformSandbox {
    must(
        <PlatformSandbox as Sandbox>::new(config.clone()),
        "创建平台沙箱失败",
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn destroy_platform_sandbox(sandbox: PlatformSandbox) {
    must(
        <PlatformSandbox as Sandbox>::destroy(sandbox),
        "销毁平台沙箱失败",
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn bench_hot_acquire(c: &mut Criterion) {
    let pool = warmed_pool(64);
    let mut group = c.benchmark_group("pool");
    group.sample_size(60);
    group.measurement_time(Duration::from_secs(6));
    group.throughput(Throughput::Elements(1));

    group.bench_function("bench_hot_acquire", |b| {
        b.iter_custom(|iters| {
            let sample_cap = 50_000usize;
            let stride = ((iters as usize) / sample_cap).max(1);
            let mut sampled_us = Vec::with_capacity((iters as usize / stride).max(1));
            let total_start = Instant::now();

            for index in 0..iters {
                let hot_path_start = Instant::now();
                let sandbox = must(pool.acquire(), "热获取失败");
                black_box(&sandbox);
                drop(sandbox);
                let elapsed_us = hot_path_start.elapsed().as_secs_f64() * 1_000_000.0;

                if (index as usize) % stride == 0 {
                    sampled_us.push(elapsed_us);
                }
            }

            if !HOT_P99_REPORTED.swap(true, Ordering::Relaxed) {
                let p99 = percentile_us(&mut sampled_us, 0.99);
                eprintln!(
                    "[criterion] bench_hot_acquire sampled_p99={p99:.2}us (目标: P99 < 100us)"
                );
            }

            total_start.elapsed()
        });
    });

    group.finish();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn bench_cold_create(c: &mut Criterion) {
    let config = sandbox_config();
    let command = if cfg!(target_os = "linux") {
        vec!["/bin/true".to_string()]
    } else {
        vec!["/usr/bin/true".to_string()]
    };
    let mut group = c.benchmark_group("pool");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(4));
    group.throughput(Throughput::Elements(1));

    group.bench_function("bench_cold_create", |b| {
        b.iter_batched(
            || config.clone(),
            |config| {
                let mut sandbox = create_platform_sandbox(black_box(&config));
                let result = must(
                    sandbox.execute(black_box(command.as_slice())),
                    "冷启动 execute 失败",
                );
                black_box(result);
                destroy_platform_sandbox(black_box(sandbox));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn bench_warm_throughput(c: &mut Criterion) {
    let pool = warmed_pool(64);
    let mut group = c.benchmark_group("pool");
    group.sample_size(40);
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    group.bench_function("bench_warm_throughput", |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let sandbox = must(pool.acquire(), "预热吞吐量获取失败");
                black_box(&sandbox);
                drop(sandbox);
            }

            total_start.elapsed()
        });
    });

    group.finish();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn bench_concurrent_acquire(c: &mut Criterion) {
    let thread_count = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(2, 8);
    let pool = warmed_pool(thread_count * 4);
    let mut group = c.benchmark_group("pool");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(1));

    group.bench_function("bench_concurrent_acquire", |b| {
        b.iter_custom(|iters| {
            let ready_barrier = Arc::new(Barrier::new(thread_count + 1));
            let start_barrier = Arc::new(Barrier::new(thread_count + 1));
            let mut handles = Vec::with_capacity(thread_count);
            let base_ops = iters / thread_count as u64;
            let remainder = iters % thread_count as u64;

            for index in 0..thread_count {
                let pool = pool.clone();
                let ready_barrier = Arc::clone(&ready_barrier);
                let start_barrier = Arc::clone(&start_barrier);
                let ops = base_ops + u64::from((index as u64) < remainder);

                handles.push(thread::spawn(move || {
                    ready_barrier.wait();
                    start_barrier.wait();

                    for _ in 0..ops {
                        let sandbox = must(pool.acquire(), "并发获取失败");
                        black_box(&sandbox);
                        drop(sandbox);
                    }
                }));
            }

            ready_barrier.wait();
            let total_start = Instant::now();
            start_barrier.wait();

            for handle in handles {
                match handle.join() {
                    Ok(()) => {}
                    Err(_) => panic!("并发基准线程执行失败"),
                }
            }

            total_start.elapsed()
        });
    });

    group.finish();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
criterion_group!(
    pool_benches,
    bench_hot_acquire,
    bench_cold_create,
    bench_warm_throughput,
    bench_concurrent_acquire
);
#[cfg(any(target_os = "linux", target_os = "macos"))]
criterion_main!(pool_benches);

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {}
