use std::error::Error;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use criterion::{Criterion, black_box};
use mimobox_core::{Sandbox, SandboxConfig, SeccompProfile};
use mimobox_wasm::WasmSandbox;
use tempfile::TempDir;

const SAMPLE_SIZE: usize = 100;

struct BenchModule {
    _temp_dir: TempDir,
    command: Vec<String>,
}

fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err}"),
    }
}

fn benchmark_config() -> SandboxConfig {
    SandboxConfig {
        deny_network: true,
        memory_limit_mb: Some(64),
        timeout_secs: Some(30),
        fs_readonly: vec![],
        fs_readwrite: vec![],
        seccomp_profile: SeccompProfile::Essential,
        allow_fork: false,
    }
}

fn compile_wat_to_tempfile(
    file_name: &str,
    wat_source: &str,
) -> Result<(TempDir, PathBuf), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let wasm_path = temp_dir.path().join(file_name);
    let wasm_bytes = wat::parse_str(wat_source)?;
    std::fs::write(&wasm_path, wasm_bytes)?;
    Ok((temp_dir, wasm_path))
}

fn build_noop_module() -> Result<BenchModule, Box<dyn Error>> {
    let (temp_dir, wasm_path) = compile_wat_to_tempfile(
        "noop.wasm",
        r#"
            (module
              (func (export "_start"))
            )
        "#,
    )?;

    Ok(BenchModule {
        _temp_dir: temp_dir,
        command: vec![wasm_path.to_string_lossy().into_owned()],
    })
}

fn wasm_cache_dir() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    // SAFETY: geteuid() 是无副作用系统调用，返回当前进程有效 uid。
    std::env::temp_dir().join(format!("mimobox-cache-{}", uid))
}

fn clear_wasm_cache() -> Result<(), Box<dyn Error>> {
    let cache_dir = wasm_cache_dir();

    for attempt in 0..5 {
        match std::fs::remove_dir_all(&cache_dir) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty && attempt < 4 => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(Box::new(err)),
        }
    }

    Ok(())
}

fn assert_success(
    result: mimobox_core::SandboxResult,
    context: &str,
) -> mimobox_core::SandboxResult {
    assert_eq!(result.exit_code, Some(0), "{context}: 退出码异常");
    assert!(!result.timed_out, "{context}: 执行超时");
    result
}

fn prime_disk_cache(command: &[String], config: &SandboxConfig) {
    must(clear_wasm_cache(), "清理 Wasm 缓存失败");
    let mut sandbox = must(WasmSandbox::new(config.clone()), "创建 Wasm 沙箱失败");
    let result = must(sandbox.execute(command), "预热磁盘缓存失败");
    black_box(assert_success(result, "预热磁盘缓存失败"));
}

fn measure_true_cold_start_once(command: &[String], config: &SandboxConfig) -> Duration {
    must(clear_wasm_cache(), "清理 Wasm 缓存失败");
    let start = Instant::now();
    let mut sandbox = must(WasmSandbox::new(config.clone()), "创建 Wasm 沙箱失败");
    let result = must(sandbox.execute(command), "true_cold_start 执行失败");
    black_box(assert_success(result, "true_cold_start 执行失败"));
    start.elapsed()
}

fn measure_cached_start_once(command: &[String], config: &SandboxConfig) -> Duration {
    let start = Instant::now();
    let mut sandbox = must(WasmSandbox::new(config.clone()), "创建 Wasm 沙箱失败");
    let result = must(sandbox.execute(command), "cached_start 执行失败");
    black_box(assert_success(result, "cached_start 执行失败"));
    start.elapsed()
}

fn collect_samples<F>(sample_size: usize, mut measure_once: F) -> Vec<Duration>
where
    F: FnMut() -> Duration,
{
    let mut samples = Vec::with_capacity(sample_size);
    for _ in 0..sample_size {
        samples.push(measure_once());
    }
    samples
}

fn percentile_index(len: usize, percentile: f64) -> usize {
    let rank = (len as f64 * percentile).ceil() as usize;
    rank.saturating_sub(1).min(len.saturating_sub(1))
}

fn duration_to_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn print_stats(label: &str, samples: &mut [Duration]) {
    samples.sort_unstable();

    let count = samples.len();
    let min = duration_to_ms(samples[0]);
    let p50 = duration_to_ms(samples[percentile_index(count, 0.50)]);
    let p95 = duration_to_ms(samples[percentile_index(count, 0.95)]);
    let p99 = duration_to_ms(samples[percentile_index(count, 0.99)]);
    let max = duration_to_ms(samples[count - 1]);
    let avg = samples
        .iter()
        .map(|sample| sample.as_secs_f64())
        .sum::<f64>()
        * 1000.0
        / count as f64;

    println!("[wasm_bench][stats] {label}");
    println!("  Samples: {count}");
    println!("  Min:  {min:.3} ms");
    println!("  P50:  {p50:.3} ms");
    println!("  P95:  {p95:.3} ms");
    println!("  P99:  {p99:.3} ms");
    println!("  Avg:  {avg:.3} ms");
    println!("  Max:  {max:.3} ms");
}

fn print_manual_stats(module: &BenchModule, config: &SandboxConfig) {
    let mut true_cold_start = collect_samples(SAMPLE_SIZE, || {
        measure_true_cold_start_once(&module.command, config)
    });

    prime_disk_cache(&module.command, config);
    let mut cached_start = collect_samples(SAMPLE_SIZE, || {
        measure_cached_start_once(&module.command, config)
    });

    prime_disk_cache(&module.command, config);
    let mut hot_sandbox = must(WasmSandbox::new(config.clone()), "创建 Wasm 沙箱失败");
    let warmup_result = must(hot_sandbox.execute(&module.command), "hot_execute 预热失败");
    black_box(assert_success(warmup_result, "hot_execute 预热失败"));
    let mut hot_execute = collect_samples(SAMPLE_SIZE, || {
        let start = Instant::now();
        let result = must(hot_sandbox.execute(&module.command), "hot_execute 执行失败");
        black_box(assert_success(result, "hot_execute 执行失败"));
        start.elapsed()
    });

    print_stats("true_cold_start", &mut true_cold_start);
    print_stats("cached_start", &mut cached_start);
    print_stats("hot_execute", &mut hot_execute);
}

fn bench_true_cold_start(c: &mut Criterion, module: &BenchModule, config: &SandboxConfig) {
    let command = module.command.clone();
    let config = config.clone();

    c.bench_function("true_cold_start", move |b| {
        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                must(clear_wasm_cache(), "清理 Wasm 缓存失败");
                let mut sandbox = must(WasmSandbox::new(config.clone()), "创建 Wasm 沙箱失败");
                let result = must(sandbox.execute(&command), "true_cold_start 执行失败");
                black_box(assert_success(result, "true_cold_start 执行失败"));
            }

            total_start.elapsed()
        });
    });
}

fn bench_cached_start(c: &mut Criterion, module: &BenchModule, config: &SandboxConfig) {
    let command = module.command.clone();
    let config = config.clone();

    c.bench_function("cached_start", move |b| {
        prime_disk_cache(&command, &config);

        b.iter_custom(|iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let mut sandbox = must(WasmSandbox::new(config.clone()), "创建 Wasm 沙箱失败");
                let result = must(sandbox.execute(&command), "cached_start 执行失败");
                black_box(assert_success(result, "cached_start 执行失败"));
            }

            total_start.elapsed()
        });
    });
}

fn bench_hot_execute(c: &mut Criterion, module: &BenchModule, config: &SandboxConfig) {
    let command = module.command.clone();
    let config = config.clone();

    c.bench_function("hot_execute", move |b| {
        prime_disk_cache(&command, &config);
        let mut sandbox = must(WasmSandbox::new(config.clone()), "创建 Wasm 沙箱失败");
        let warmup_result = must(sandbox.execute(&command), "hot_execute 预热失败");
        black_box(assert_success(warmup_result, "hot_execute 预热失败"));
        let command_for_iters = command.clone();

        b.iter_custom(move |iters| {
            let total_start = Instant::now();

            for _ in 0..iters {
                let result = must(sandbox.execute(&command_for_iters), "hot_execute 执行失败");
                black_box(assert_success(result, "hot_execute 执行失败"));
            }

            total_start.elapsed()
        });
    });
}

fn main() {
    // SAFETY: set_var 在单线程启动阶段调用，不存在数据竞争。
    // 仅设置一个自定义环境变量用于抑制 benchmark 期间的日志输出。
    unsafe {
        std::env::set_var("MIMOBOX_WASM_QUIET", "1");
    }

    let module = must(build_noop_module(), "创建 benchmark Wasm 模块失败");
    let config = benchmark_config();

    print_manual_stats(&module, &config);

    let mut criterion = Criterion::default()
        .sample_size(SAMPLE_SIZE)
        .configure_from_args();
    bench_true_cold_start(&mut criterion, &module, &config);
    bench_cached_start(&mut criterion, &module, &config);
    bench_hot_execute(&mut criterion, &module, &config);
    criterion.final_summary();
}
