use std::error::Error;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use criterion::black_box;
use mimobox_core::{Sandbox, SandboxConfig, SandboxResult, SeccompProfile};
use mimobox_wasm::WasmSandbox;
use tempfile::TempDir;

const SAMPLE_SIZE: usize = 100;
const DEFAULT_MEMORY_WORKLOAD_MB: u64 = 60;
const MEMORY_TOUCH_STRIDE_BYTES: u64 = 256;
const MEMORY_PRESSURE_LIMITS_MB: [u64; 4] = [16, 32, 64, 128];

// 与 mimobox-wasm 当前缓存命名空间保持一致，用于真实清理磁盘编译缓存。
const WASMTIME_CACHE_VERSION: &str = "43.0.1";
const ENGINE_CONFIG_CACHE_KEY: &str = "opt-speed-fuel-epoch-stack512k-parallel";

struct BenchModule {
    _temp_dir: TempDir,
    command: Vec<String>,
}

struct WorkloadModules {
    noop: BenchModule,
    compute: BenchModule,
    memory: BenchModule,
    string: BenchModule,
}

fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err}"),
    }
}

fn benchmark_config() -> SandboxConfig {
    let mut config = SandboxConfig::default();
    config.deny_network = true;
    config.memory_limit_mb = Some(64);
    config.timeout_secs = Some(30);
    config.fs_readonly = vec![];
    config.fs_readwrite = vec![];
    config.seccomp_profile = SeccompProfile::Essential;
    config.allow_fork = false;
    config
}

fn compile_wat_to_module(file_name: &str, wat_source: &str) -> Result<BenchModule, Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let wasm_path = temp_dir.path().join(file_name);
    let wasm_bytes = wat::parse_str(wat_source)?;
    std::fs::write(&wasm_path, wasm_bytes)?;

    Ok(BenchModule {
        _temp_dir: temp_dir,
        command: vec![wasm_path.to_string_lossy().into_owned()],
    })
}

fn checked_mul(value: u64, factor: u64, context: &'static str) -> Result<u64, Box<dyn Error>> {
    value
        .checked_mul(factor)
        .ok_or_else(|| Box::new(std::io::Error::other(context)) as Box<dyn Error>)
}

fn build_noop_module() -> Result<BenchModule, Box<dyn Error>> {
    compile_wat_to_module("noop.wasm", r#"(module (func (export "_start")))"#)
}

fn build_compute_module() -> Result<BenchModule, Box<dyn Error>> {
    compile_wat_to_module(
        "compute_fib30.wasm",
        r#"
            (module
              (global $sink (mut i32) (i32.const 0))
              (func $fib (param $n i32) (result i32)
                local.get $n
                i32.const 2
                i32.lt_s
                if (result i32)
                  local.get $n
                else
                  local.get $n
                  i32.const 1
                  i32.sub
                  call $fib
                  local.get $n
                  i32.const 2
                  i32.sub
                  call $fib
                  i32.add
                end)
              (func (export "_start")
                i32.const 30
                call $fib
                global.set $sink))
        "#,
    )
}

fn build_memory_module(file_name: &str, target_mib: u64) -> Result<BenchModule, Box<dyn Error>> {
    let target_pages = checked_mul(target_mib, 16, "memory workload page count overflow")?;
    let target_bytes = checked_mul(
        target_mib,
        1024 * 1024,
        "memory workload byte count overflow",
    )?;
    let grow_pages = target_pages.saturating_sub(1);
    let wat_source = format!(
        r#"
            (module
              (memory (export "memory") 1 {target_pages})
              (func (export "_start")
                (local $addr i32)
                (local $end i32)
                (local $checksum i32)

                i32.const {grow_pages}
                memory.grow
                drop

                i32.const {target_bytes}
                local.set $end

                ;; 以固定步长触达整段线性内存，避免只测试 memory.grow。
                (loop $write
                  local.get $addr
                  local.get $addr
                  i32.const 255
                  i32.and
                  i32.store8

                  local.get $addr
                  i32.const {MEMORY_TOUCH_STRIDE_BYTES}
                  i32.add
                  local.tee $addr
                  local.get $end
                  i32.lt_u
                  br_if $write)

                i32.const 0
                local.set $addr
                (loop $read
                  local.get $checksum
                  local.get $addr
                  i32.load8_u
                  i32.add
                  local.set $checksum

                  local.get $addr
                  i32.const {MEMORY_TOUCH_STRIDE_BYTES}
                  i32.add
                  local.tee $addr
                  local.get $end
                  i32.lt_u
                  br_if $read)

                i32.const 0
                local.get $checksum
                i32.store))
        "#
    );

    compile_wat_to_module(file_name, &wat_source)
}

fn build_string_module() -> Result<BenchModule, Box<dyn Error>> {
    compile_wat_to_module(
        "string_fill_copy.wasm",
        r#"
            (module
              (memory (export "memory") 16 32)
              (func (export "_start")
                (local $i i32)
                (loop $copy_loop
                  i32.const 0
                  i32.const 65
                  i32.const 524288
                  memory.fill

                  i32.const 524288
                  i32.const 0
                  i32.const 524288
                  memory.copy

                  local.get $i
                  i32.const 1
                  i32.add
                  local.tee $i
                  i32.const 32
                  i32.lt_u
                  br_if $copy_loop)))
        "#,
    )
}

fn build_workload_modules() -> Result<WorkloadModules, Box<dyn Error>> {
    Ok(WorkloadModules {
        noop: build_noop_module()?,
        compute: build_compute_module()?,
        memory: build_memory_module("memory_60mib.wasm", DEFAULT_MEMORY_WORKLOAD_MB)?,
        string: build_string_module()?,
    })
}

fn cache_namespace() -> String {
    format!("wasmtime-{WASMTIME_CACHE_VERSION}-{ENGINE_CONFIG_CACHE_KEY}")
}

fn wasm_cache_dir() -> PathBuf {
    // SAFETY: geteuid() 是无副作用系统调用，只读取当前进程有效 uid。
    let uid = unsafe { libc::geteuid() };
    std::env::temp_dir().join(format!("mimobox-cache-{}-{}", uid, cache_namespace()))
}

fn legacy_wasm_cache_dir() -> PathBuf {
    // SAFETY: geteuid() 是无副作用系统调用，只读取当前进程有效 uid。
    let uid = unsafe { libc::geteuid() };
    std::env::temp_dir().join(format!("mimobox-cache-{}", uid))
}

fn remove_cache_dir(cache_dir: PathBuf) -> Result<(), Box<dyn Error>> {
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

fn clear_wasm_cache() -> Result<(), Box<dyn Error>> {
    remove_cache_dir(wasm_cache_dir())?;
    remove_cache_dir(legacy_wasm_cache_dir())?;
    Ok(())
}

fn assert_success(result: SandboxResult, context: &str) -> SandboxResult {
    assert_eq!(result.exit_code, Some(0), "{context}: unexpected exit code");
    assert!(!result.timed_out, "{context}: execution timed out");
    result
}

fn execute_success(sandbox: &mut WasmSandbox, command: &[String], context: &str) {
    let result = must(sandbox.execute(command), context);
    black_box(assert_success(result, context));
}

fn prime_disk_cache(command: &[String], config: &SandboxConfig) {
    must(clear_wasm_cache(), "failed to clear Wasm cache");
    let mut sandbox = must(
        WasmSandbox::new(config.clone()),
        "failed to create Wasm sandbox",
    );
    execute_success(&mut sandbox, command, "failed to prime disk cache");
    must(sandbox.destroy(), "failed to destroy cache priming sandbox");
}

fn measure_start_once(
    command: &[String],
    config: &SandboxConfig,
    should_clear_cache: bool,
    context: &str,
) -> Duration {
    if should_clear_cache {
        must(clear_wasm_cache(), "failed to clear Wasm cache");
    }

    let start = Instant::now();
    let mut sandbox = must(
        WasmSandbox::new(config.clone()),
        "failed to create Wasm sandbox",
    );
    execute_success(&mut sandbox, command, context);
    must(sandbox.destroy(), "failed to destroy Wasm sandbox");
    start.elapsed()
}

fn collect_samples<F>(mut measure_once: F) -> Vec<Duration>
where
    F: FnMut() -> Duration,
{
    let mut samples = Vec::with_capacity(SAMPLE_SIZE);
    for _ in 0..SAMPLE_SIZE {
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

    println!(
        "[realworkload_wasm][{label}] Samples={count} Min={min:.3}ms P50={p50:.3}ms P95={p95:.3}ms P99={p99:.3}ms Max={max:.3}ms Avg={avg:.3}ms"
    );
}

fn print_start_stats(label: &str, command: &[String], config: &SandboxConfig, cold_cache: bool) {
    if !cold_cache {
        prime_disk_cache(command, config);
    }

    let mut samples = collect_samples(|| measure_start_once(command, config, cold_cache, label));
    print_stats(label, &mut samples);
}

fn print_hot_execute_stats(label: &str, command: &[String], config: &SandboxConfig) {
    prime_disk_cache(command, config);
    let mut sandbox = must(
        WasmSandbox::new(config.clone()),
        "failed to create hot execute sandbox",
    );

    let mut samples = collect_samples(|| {
        let start = Instant::now();
        execute_success(&mut sandbox, command, label);
        start.elapsed()
    });

    must(sandbox.destroy(), "failed to destroy hot execute sandbox");
    print_stats(label, &mut samples);
}

fn print_memory_pressure_stats() {
    for limit_mb in MEMORY_PRESSURE_LIMITS_MB {
        let target_mib = limit_mb.saturating_sub(1);
        let module = must(
            build_memory_module(&format!("memory_pressure_{limit_mb}mib.wasm"), target_mib),
            "failed to create memory pressure module",
        );
        let mut config = benchmark_config();
        config.memory_limit_mb = Some(limit_mb);

        print_start_stats(
            &format!("wasm_memory_pressure_{limit_mb}mb_cold_start"),
            &module.command,
            &config,
            true,
        );
        print_hot_execute_stats(
            &format!("wasm_memory_pressure_{limit_mb}mb_hot_execute"),
            &module.command,
            &config,
        );
    }
}

fn print_seccomp_impact_stats(command: &[String]) {
    // SeccompProfile 当前没有 None 变体；Wasm 后端也不直接加载 OS seccomp。
    // 这里用 Network 作为最宽松配置，并保留 none 标签便于对照需求输出。
    let profiles = [
        ("wasm_seccomp_impact_none", SeccompProfile::Network),
        ("wasm_seccomp_impact_essential", SeccompProfile::Essential),
    ];

    for (label, profile) in profiles {
        let mut config = benchmark_config();
        config.seccomp_profile = profile;
        print_start_stats(label, command, &config, false);
    }
}

fn main() {
    // SAFETY: set_var 在 benchmark 单线程初始化阶段调用，不与其他环境读写并发。
    unsafe {
        std::env::set_var("MIMOBOX_WASM_QUIET", "1");
    }

    let modules = must(
        build_workload_modules(),
        "failed to create real workload Wasm modules",
    );
    let config = benchmark_config();

    print_start_stats("wasm_cold_start_noop", &modules.noop.command, &config, true);
    print_start_stats(
        "wasm_cached_start_noop",
        &modules.noop.command,
        &config,
        false,
    );
    print_start_stats(
        "wasm_cold_start_compute",
        &modules.compute.command,
        &config,
        true,
    );

    print_hot_execute_stats("wasm_hot_execute_noop", &modules.noop.command, &config);
    print_hot_execute_stats(
        "wasm_hot_execute_compute",
        &modules.compute.command,
        &config,
    );
    print_hot_execute_stats("wasm_hot_execute_memory", &modules.memory.command, &config);
    print_hot_execute_stats("wasm_hot_execute_string", &modules.string.command, &config);

    print_memory_pressure_stats();
    print_seccomp_impact_stats(&modules.noop.command);
}
