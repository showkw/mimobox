#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
//! mimobox-wasm: Wasm sandbox backend.
//!
//! Implements a Wasm sandbox on top of the Wasmtime runtime with WASI Preview 1 support.
//! Core design:
//! - Globally shared Engine, owned by `WasmSandbox` and reused across multiple `execute` calls.
//! - Module compilation cache based on SHA256 hashes of file content to avoid repeated compilation.
//! - Independent Store per `execute`, with a fresh WASI context and resource limits.
//! - stdout/stderr captured into in-memory buffers through `MemoryOutputPipe` with a built-in capacity limit.
//! - Dual execution-time limits with fuel and epoch interruption.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use wasmtime::{
    Config, Engine, Linker, Module, OptLevel, Store, StoreLimits, StoreLimitsBuilder, Trap,
};
use wasmtime_wasi::I32Exit;
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};

/// Sandbox Store data combining the WASI context and resource limits.
///
/// [FATAL-01 fix] Embeds `StoreLimits` in the Store data type so that the `store.limiter()`
/// callback correctly returns `&mut dyn ResourceLimiter`, allowing `memory_limit_mb` to be
/// applied to the Wasm runtime.
struct StoreData {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

/// Logging macro.
fn wasm_logging_enabled() -> bool {
    std::env::var_os("MIMOBOX_WASM_QUIET").is_none()
}

macro_rules! log_info {
    ($($arg:tt)*) => {
        if wasm_logging_enabled() {
            eprintln!("[mimobox:wasm:info] {}", format!($($arg)*))
        }
    };
}

macro_rules! log_warn {
    ($($arg:tt)*) => {
        if wasm_logging_enabled() {
            eprintln!("[mimobox:wasm:warn] {}", format!($($arg)*))
        }
    };
}

/// Fuel estimation factor: about 15 million Wasm instructions (fuel) per second, including 50% headroom.
const FUEL_PER_SECOND: u64 = 15_000_000;

/// Default fuel limit when no timeout is configured, roughly equivalent to 10 million Wasm instructions.
const DEFAULT_FUEL_LIMIT: u64 = 10_000_000;

/// Maximum stdout/stderr buffer capacity: 1 MB.
/// The `MemoryOutputPipe` capacity parameter also acts as the write limit;
/// writes beyond this capacity return `StreamError::Closed`.
const OUTPUT_MAX_CAPACITY: usize = 1024 * 1024;

/// Maximum returned size for a single output stream: 4 MB; excess data is truncated and logged as a warning.
const MAX_OUTPUT_SIZE: usize = 4 * 1024 * 1024;

/// Maximum Wasm module file size: 100 MB.
const MAX_WASM_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Default memory limit: 64 MB, used when the config does not specify one.
const DEFAULT_MEMORY_LIMIT_MB: u64 = 64;

/// Epoch tick interval: 10 ms.
const EPOCH_TICK_INTERVAL_MS: u64 = 10;

/// Dynamically calculates the fuel limit from `timeout_secs`.
///
/// [IMPORTANT-01 fix] Roughly maps `timeout_secs` to a fuel quota.
/// Fuel is consumed only while executing pure Wasm instructions; wait time during WASI I/O does
/// not count. Therefore, fuel is an approximate timeout mechanism paired with epoch interruption
/// to enforce wall-clock timeout.
fn fuel_from_timeout(timeout_secs: Option<u64>) -> u64 {
    match timeout_secs {
        Some(secs) => secs.saturating_mul(FUEL_PER_SECOND),
        None => DEFAULT_FUEL_LIMIT,
    }
}

/// Reads output and truncates it to the maximum size.
fn truncate_output(data: Vec<u8>, label: &str) -> Vec<u8> {
    if data.len() > MAX_OUTPUT_SIZE {
        log_warn!(
            "{} output exceeded limit ({} > {} bytes), truncated",
            label,
            data.len(),
            MAX_OUTPUT_SIZE
        );
        data[..MAX_OUTPUT_SIZE].to_vec()
    } else {
        data
    }
}

/// Wasm sandbox backend.
///
/// Holds the globally shared Engine and module cache directory path, and creates an independent
/// Store for each `execute` call.
pub struct WasmSandbox {
    engine: Arc<Engine>,
    config: SandboxConfig,
    cache_dir: PathBuf,
    epoch_running: Arc<AtomicBool>,
    epoch_thread: Option<std::thread::JoinHandle<()>>,
}

/// Calculates the SHA256 hash of file content.
///
/// [IMPORTANT-02 fix] Uses SHA256 instead of `DefaultHasher`, generating cache keys from file
/// content rather than path plus modification time to eliminate TOCTOU race conditions.
fn content_hash(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}

/// Gets a lightweight metadata fingerprint for a file: size plus modification time.
///
/// Used to quickly determine whether a file may have changed, avoiding a full file read and
/// SHA256 calculation on every `execute` call.
fn file_fingerprint(path: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as u64;
    Some((size, mtime))
}

fn compile_module_from_bytes(
    engine: &Engine,
    wasm_path: &Path,
    bytes: &[u8],
) -> Result<Module, SandboxError> {
    // SECURITY: 调用方在读取字节后立刻使用同一份不可变切片编译，
    // 避免“先读取算哈希、再按路径重新打开编译”的 TOCTOU 竞态。
    Module::from_binary(engine, bytes).map_err(|e| {
        SandboxError::ExecutionFailed(format!(
            "Failed to load Wasm module ({:?}): {}",
            wasm_path, e
        ))
    })
}

/// Gets or compiles a module with a disk cache.
///
/// Uses a hybrid cache strategy:
/// 1. First looks up the cache mapping file using the lightweight metadata fingerprint (size plus modification time).
/// 2. When the cache mapping hits, loads directly with the corresponding SHA256 cache key.
/// 3. When the cache mapping misses, calculates the file content SHA256 and updates the cache.
///
/// This avoids reading the whole file to calculate a hash on the cache-hit hot path.
fn get_cached_module(
    engine: &Engine,
    wasm_path: &Path,
    cache_dir: &Path,
) -> Result<Module, SandboxError> {
    let _ = std::fs::create_dir_all(cache_dir);

    let fingerprint = match file_fingerprint(wasm_path) {
        Some(fp) => fp,
        None => {
            // 无法获取元数据时也只读取一次文件，避免在读取与编译之间被路径替换。
            let file_data = std::fs::read(wasm_path).map_err(|e| {
                SandboxError::ExecutionFailed(format!("Failed to read Wasm file: {}", e))
            })?;
            return compile_module_from_bytes(engine, wasm_path, &file_data);
        }
    };

    // 缓存映射文件：记录 "fingerprint -> sha256_hash" 的映射
    // 文件名格式: {size}_{mtime_nanos}.map
    let map_file = cache_dir.join(format!("{}_{}.map", fingerprint.0, fingerprint.1));

    // 尝试通过映射文件找到对应的缓存
    if let Ok(hash) = std::fs::read_to_string(&map_file) {
        let cache_path = cache_dir.join(format!("{}.cwasm", hash.trim()));
        match std::fs::read(&cache_path) {
            Ok(cached) => {
                // SAFETY: 缓存文件由本系统生成，Engine 配置未变。
                // Module::deserialize 要求输入数据来自相同 Engine 配置的 serialize() 输出。
                // 我们在缓存写入时确保了这一点，因此反序列化是安全的。
                match unsafe { Module::deserialize(engine, &cached) } {
                    Ok(module) => {
                        log_info!("Loaded module from cache: {:?}", wasm_path);
                        return Ok(module);
                    }
                    Err(e) => {
                        // 反序列化失败：缓存可能损坏或 Engine 配置变更，静默降级重新编译
                        log_warn!("Cache deserialization failed, recompiling: {}", e);
                        let _ = std::fs::remove_file(&cache_path);
                        let _ = std::fs::remove_file(&map_file);
                    }
                }
            }
            Err(_) => {
                // 缓存文件不存在，映射过期，清理并重新编译
                let _ = std::fs::remove_file(&map_file);
            }
        }
    }

    // 缓存未命中：需要计算文件内容的 SHA256
    let file_data = std::fs::read(wasm_path)
        .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to read Wasm file: {}", e)))?;
    let hash = content_hash(&file_data);
    let cache_path = cache_dir.join(format!("{}.cwasm", hash));

    // 检查是否已有相同内容的缓存（文件内容相同但元数据不同）
    if let Ok(cached) = std::fs::read(&cache_path) {
        // SAFETY: 缓存文件由本系统生成，Engine 配置未变。
        // Module::deserialize 要求输入数据来自相同 Engine 配置的 serialize() 输出。
        // 我们在缓存写入时确保了这一点，因此反序列化是安全的。
        match unsafe { Module::deserialize(engine, &cached) } {
            Ok(module) => {
                // 更新映射文件
                let _ = std::fs::write(&map_file, &hash);
                log_info!("Loaded module from cache (content match): {:?}", wasm_path);
                return Ok(module);
            }
            Err(e) => {
                log_warn!("Cache deserialization failed, recompiling: {}", e);
                let _ = std::fs::remove_file(&cache_path);
            }
        }
    }

    // 编译模块
    let module = compile_module_from_bytes(engine, wasm_path, &file_data)?;

    // 序列化到缓存目录（原子写入：先写临时文件再 rename，避免并发读到不完整数据）
    if let Ok(serialized) = module.serialize() {
        let tmp_path = cache_path.with_extension("cwasm.tmp");
        if std::fs::write(&tmp_path, &serialized).is_ok() {
            // rename 在同一文件系统上是原子的
            if let Err(e) = std::fs::rename(&tmp_path, &cache_path) {
                log_warn!("Failed to rename cache file: {}", e);
                let _ = std::fs::remove_file(&tmp_path);
            }
        }
        // 更新映射文件
        let _ = std::fs::write(&map_file, &hash);
    }

    log_info!("Compiled and cached module: {:?}", wasm_path);
    Ok(module)
}

/// Creates the Wasmtime Engine configuration for sandbox execution.
fn create_engine_config() -> Config {
    let mut config = Config::new();
    config.cranelift_opt_level(OptLevel::Speed);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.max_wasm_stack(512 * 1024); // 512KB Wasm 栈
    config.parallel_compilation(true);
    config
}

/// Builds a WASI Preview 1 context.
///
/// Configures filesystem access, environment variables, and related settings from `SandboxConfig`.
/// stdout/stderr are captured into in-memory buffers through `MemoryOutputPipe`.
fn build_wasi_ctx(
    config: &SandboxConfig,
    args: &[String],
    stdout_pipe: MemoryOutputPipe,
    stderr_pipe: MemoryOutputPipe,
) -> WasiP1Ctx {
    let mut builder = WasiCtxBuilder::new();

    // 设置命令行参数
    for arg in args {
        builder.arg(arg);
    }

    // 设置最小必要环境变量
    builder.env("HOME", "/tmp");
    builder.env("PATH", "/usr/bin:/bin");
    builder.env("TERM", "dumb");
    builder.env("SANDBOX", "wasm");

    // 配置 stdout/stderr 捕获
    builder.stdout(Box::new(stdout_pipe));
    builder.stderr(Box::new(stderr_pipe));

    // 文件系统访问：仅允许 config 中配置的路径
    for path in &config.fs_readonly {
        if let Some(path_str) = path.to_str() {
            if path.exists() {
                if let Err(e) =
                    builder.preopened_dir(path, path_str, DirPerms::READ, FilePerms::READ)
                {
                    log_warn!("Failed to preopen read-only dir {:?}: {}", path, e);
                }
            } else {
                log_warn!("Read-only path does not exist: {:?}", path);
            }
        }
    }
    for path in &config.fs_readwrite {
        if let Some(path_str) = path.to_str() {
            if path.exists() {
                if let Err(e) =
                    builder.preopened_dir(path, path_str, DirPerms::all(), FilePerms::all())
                {
                    log_warn!("Failed to preopen read-write dir {:?}: {}", path, e);
                }
            } else {
                log_warn!("Read-write path does not exist: {:?}", path);
            }
        }
    }

    // 网络控制：Wasmtime WASI 默认即禁止所有网络，无需额外操作
    // 即使 deny_network 为 false，当前实现也保持禁止（WASI 网络支持有限）

    builder.build_p1()
}

impl Sandbox for WasmSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let engine_config = create_engine_config();
        let engine = Arc::new(Engine::new(&engine_config).map_err(|e| {
            SandboxError::ExecutionFailed(format!("Failed to create Wasmtime Engine: {}", e))
        })?);

        let epoch_running = Arc::new(AtomicBool::new(true));
        let epoch_thread_engine = engine.clone();
        let epoch_thread_running = epoch_running.clone();
        let epoch_thread = std::thread::Builder::new()
            .name("mimobox-wasm-epoch-ticker".to_string())
            .spawn(move || {
                let tick_interval = std::time::Duration::from_millis(EPOCH_TICK_INTERVAL_MS);
                while epoch_thread_running.load(Ordering::Relaxed) {
                    std::thread::sleep(tick_interval);
                    epoch_thread_engine.increment_epoch();
                }
            })
            .map_err(|e| {
                SandboxError::ExecutionFailed(format!("Failed to start Wasm epoch ticker: {}", e))
            })?;

        // [IMPORTANT-02 修复] 使用用户专属缓存目录，避免不同用户之间的缓存污染
        // SAFETY: geteuid() 是无副作用的系统调用，始终返回有效的 uid。
        let uid = unsafe { libc::geteuid() };
        let cache_dir = std::env::temp_dir().join(format!("mimobox-cache-{}", uid));

        log_info!(
            "Created Wasm sandbox backend, memory_limit={:?}MB, timeout={:?}s, cache_dir={:?}",
            config.memory_limit_mb,
            config.timeout_secs,
            cache_dir,
        );

        Ok(Self {
            engine,
            config,
            cache_dir,
            epoch_running,
            epoch_thread: Some(epoch_thread),
        })
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        let start = Instant::now();

        if cmd.is_empty() {
            return Err(SandboxError::ExecutionFailed("Command is empty".into()));
        }

        let wasm_path = Path::new(&cmd[0]);
        if !wasm_path.exists() {
            return Err(SandboxError::ExecutionFailed(format!(
                "Wasm file does not exist: {:?}",
                wasm_path
            )));
        }

        // [MINOR-07] 预检查文件大小，防止超大文件导致编译时 OOM
        if let Ok(meta) = std::fs::metadata(wasm_path)
            && meta.len() > MAX_WASM_FILE_SIZE
        {
            return Err(SandboxError::ExecutionFailed(format!(
                "Wasm file too large: {} bytes (limit {} bytes)",
                meta.len(),
                MAX_WASM_FILE_SIZE
            )));
        }

        // 1. 获取或编译模块（带缓存）
        let module = get_cached_module(&self.engine, wasm_path, &self.cache_dir)?;

        // 2. [IMPORTANT-03 说明] stdout/stderr 缓冲区容量限制
        // MemoryOutputPipe 的 capacity 参数是写入上限而非初始容量，
        // 超过此容量后 OutputStream::write() 返回 StreamError::Trap，
        // check_write() 返回 StreamError::Closed。
        let stdout_pipe = MemoryOutputPipe::new(OUTPUT_MAX_CAPACITY);
        let stdout_reader = stdout_pipe.clone(); // 保留读取端
        let stderr_pipe = MemoryOutputPipe::new(OUTPUT_MAX_CAPACITY);
        let stderr_reader = stderr_pipe.clone(); // 保留读取端

        // 3. 构建 WASI 上下文
        let wasi_ctx = build_wasi_ctx(&self.config, cmd, stdout_pipe, stderr_pipe);

        // 4. 创建 Linker 并注册 WASI Preview 1
        // 注意：Linker 的类型参数必须与 Store data type 一致
        let mut linker: Linker<StoreData> = Linker::new(&self.engine);
        p1::add_to_linker_sync(&mut linker, |data| &mut data.wasi).map_err(|e| {
            SandboxError::ExecutionFailed(format!("Failed to register WASI Preview 1: {}", e))
        })?;

        // 5. [FATAL-01 修复] 创建带资源限制的 Store
        // 将 memory_limit_mb 通过 StoreLimitsBuilder 实际应用到 Wasm 运行时
        let memory_limit_bytes: usize = self
            .config
            .memory_limit_mb
            .map(|mb| mb * 1024 * 1024)
            .unwrap_or(DEFAULT_MEMORY_LIMIT_MB * 1024 * 1024)
            .try_into()
            .unwrap_or(usize::MAX);

        let limits = StoreLimitsBuilder::new()
            .memory_size(memory_limit_bytes)
            .memories(1) // 单个线性内存
            .tables(4) // 限制间接调用表数量
            .instances(1) // 单实例
            .trap_on_grow_failure(true) // 内存增长失败时 trap 而非返回 -1
            .build();

        let store_data = StoreData {
            wasi: wasi_ctx,
            limits,
        };
        let mut store = Store::new(&self.engine, store_data);
        store.limiter(|data| &mut data.limits);

        // 6. [IMPORTANT-01 修复] 根据 timeout_secs 动态设置 fuel 上限
        let fuel_limit = fuel_from_timeout(self.config.timeout_secs);
        store
            .set_fuel(fuel_limit)
            .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to set fuel: {}", e)))?;

        // 7. [IMPORTANT-01 补充] 设置 epoch deadline 实现墙钟超时
        // epoch_interruption 可中断包括 WASI I/O 阻塞在内的执行，
        // 弥补 fuel 仅在纯 Wasm 指令执行时消耗的不足。
        store.epoch_deadline_trap();
        let epoch_deadline_ticks = self
            .config
            .timeout_secs
            .map(|s| s.saturating_mul(100)) // 每 10ms 一个 epoch tick
            .unwrap_or(3000); // 默认 30s
        store.set_epoch_deadline(epoch_deadline_ticks);

        // 8. 实例化模块
        let instance = linker.instantiate(&mut store, &module).map_err(|e| {
            SandboxError::ExecutionFailed(format!("Failed to instantiate Wasm module: {}", e))
        })?;

        // 9. 调用 _start 函数（WASI Command 模式）
        // WASI Command 通过 _start 进入，正常退出时调用 proc_exit(code)，
        // 这会触发 I32Exit 错误，其中包含退出码。
        let exit_code = match instance.get_typed_func::<(), ()>(&mut store, "_start") {
            Ok(start_func) => {
                match start_func.call(&mut store, ()) {
                    Ok(()) => Some(0),
                    Err(e) => {
                        // 检查是否是 WASI 正常退出（I32Exit）
                        // I32Exit 可能被包装在 error chain 中，需要遍历查找
                        if let Some(exit) = find_exit_code(&e) {
                            Some(exit)
                        } else if is_fuel_exhausted(&store) || is_epoch_interrupt(&e) {
                            log_warn!(
                                "Execution timed out (fuel exhausted or epoch deadline exceeded)"
                            );
                            let elapsed = start.elapsed();
                            let stdout =
                                truncate_output(stdout_reader.contents().to_vec(), "stdout");
                            let stderr =
                                truncate_output(stderr_reader.contents().to_vec(), "stderr");
                            return Ok(SandboxResult {
                                stdout,
                                stderr,
                                exit_code: None,
                                elapsed,
                                timed_out: true,
                            });
                        } else {
                            log_warn!("Wasm execution error: {}", e);
                            None
                        }
                    }
                }
            }
            Err(_) => {
                // 没有 _start 函数，尝试查找 main 函数
                match instance.get_typed_func::<(), i32>(&mut store, "main") {
                    Ok(main_func) => match main_func.call(&mut store, ()) {
                        Ok(code) => Some(code),
                        Err(e) => {
                            if let Some(exit) = find_exit_code(&e) {
                                Some(exit)
                            } else {
                                log_warn!("main function execution failed: {}", e);
                                None
                            }
                        }
                    },
                    Err(_) => {
                        return Err(SandboxError::ExecutionFailed(
                            "Wasm module has no _start or main export function".into(),
                        ));
                    }
                }
            }
        };

        let elapsed = start.elapsed();

        // 10. 从 clone 的 MemoryOutputPipe 中读取捕获的输出（带截断保护）
        let stdout = truncate_output(stdout_reader.contents().to_vec(), "stdout");
        let stderr = truncate_output(stderr_reader.contents().to_vec(), "stderr");

        log_info!(
            "Wasm execution completed, exit_code={:?}, elapsed={:.2}ms",
            exit_code,
            elapsed.as_secs_f64() * 1000.0
        );

        Ok(SandboxResult {
            stdout,
            stderr,
            exit_code,
            elapsed,
            timed_out: false,
        })
    }

    fn destroy(self) -> Result<(), SandboxError> {
        log_info!("Destroying Wasm sandbox backend");
        Ok(())
    }
}

impl Drop for WasmSandbox {
    fn drop(&mut self) {
        self.epoch_running.store(false, Ordering::Relaxed);
        if let Some(epoch_thread) = self.epoch_thread.take()
            && let Err(e) = epoch_thread.join()
        {
            log_warn!("Wasm epoch ticker thread join failed: {:?}", e);
        }
    }
}

/// Checks whether the Store fuel is exhausted.
fn is_fuel_exhausted(store: &Store<StoreData>) -> bool {
    store.get_fuel().is_ok_and(|f| f == 0)
}

/// Checks whether an error is an epoch interruption, indicating wall-clock timeout.
fn is_epoch_interrupt(error: &wasmtime::Error) -> bool {
    if let Some(trap) = error.downcast_ref::<Trap>() {
        matches!(trap, Trap::Interrupt)
    } else {
        false
    }
}

/// Finds a WASI `I32Exit` exit code in the wasmtime error chain.
///
/// WASI `proc_exit` propagates the exit code through an `I32Exit` error, but it may be wrapped
/// by intermediate layers such as `WasmBacktrace`. This function walks the entire error chain.
fn find_exit_code(error: &wasmtime::Error) -> Option<i32> {
    // 直接 downcast
    if let Some(exit) = error.downcast_ref::<I32Exit>() {
        return Some(exit.0);
    }

    // 检查 root cause
    let root = error.root_cause();
    if let Some(exit) = root.downcast_ref::<I32Exit>() {
        return Some(exit.0);
    }

    None
}

/// Runs the Wasm sandbox cold-start benchmark.
pub fn run_wasm_benchmark(
    wasm_path: &str,
    iterations: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== mimobox Wasm Sandbox Benchmark ===\n");

    let mut config = SandboxConfig::default();
    config.deny_network = true;
    config.memory_limit_mb = Some(64);
    config.timeout_secs = Some(30);
    config.fs_readonly = vec![];
    config.fs_readwrite = vec![];
    config.seccomp_profile = mimobox_core::SeccompProfile::Essential;
    config.allow_fork = false;
    config.allowed_http_domains = vec![];

    if !Path::new(wasm_path).exists() {
        return Err(format!("Wasm file does not exist: {}", wasm_path).into());
    }

    let cmd = vec![wasm_path.to_string()];

    // Phase 1: Engine 创建开销（一次性）
    println!("Testing Engine creation overhead...");
    let engine_start = Instant::now();
    let mut sb = WasmSandbox::new(config.clone())?;
    let engine_elapsed = engine_start.elapsed();
    println!(
        "  Engine creation: {:.2}ms",
        engine_elapsed.as_secs_f64() * 1000.0
    );

    // Phase 2: 模块编译开销（首次）
    println!("\nTesting first module compilation...");
    let compile_start = Instant::now();
    let result = sb.execute(&cmd)?;
    let compile_elapsed = compile_start.elapsed();
    println!(
        "  First execution (with compilation): {:.2}ms, exit_code={:?}",
        compile_elapsed.as_secs_f64() * 1000.0,
        result.exit_code
    );

    // Phase 3: 冷启动测试（每次 new + execute）
    println!(
        "\nCold start test ({} iterations, each with new + execute)...",
        iterations
    );
    let mut cold_times = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let start = Instant::now();
        let mut sb = WasmSandbox::new(config.clone())?;
        let result = sb.execute(&cmd)?;
        let elapsed = start.elapsed();
        cold_times.push(elapsed.as_micros() as f64 / 1000.0);

        if result.exit_code != Some(0) {
            eprintln!("Iteration {} failed: exit code {:?}", i, result.exit_code);
        }
    }

    // Phase 4: 热路径测试（复用 Engine，仅 execute）
    println!(
        "\nHot path test ({} iterations, reusing Engine)...",
        iterations
    );
    let mut hot_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let result = sb.execute(&cmd)?;
        let elapsed = start.elapsed();
        hot_times.push(elapsed.as_micros() as f64 / 1000.0);

        if result.exit_code != Some(0) {
            eprintln!("Hot path execution failed: {:?}", result.exit_code);
        }
    }

    // 统计输出
    cold_times.sort_by(f64::total_cmp);
    hot_times.sort_by(f64::total_cmp);

    fn print_stats(label: &str, times: &[f64]) {
        let n = times.len();
        if n == 0 {
            println!("{}  no data", label);
            return;
        }
        let p50 = times[n / 2];
        let p95_idx = ((n as f64 * 0.95) as usize).min(n - 1);
        let p99_idx = ((n as f64 * 0.99) as usize).min(n - 1);
        let avg: f64 = times.iter().sum::<f64>() / n as f64;

        println!("\n{} latency:", label);
        println!("  Min:  {:.2}ms", times[0]);
        println!("  P50:  {:.2}ms", p50);
        println!("  P95:  {:.2}ms", times[p95_idx]);
        println!("  P99:  {:.2}ms", times[p99_idx]);
        println!("  Avg:  {:.2}ms", avg);
        println!("  Max:  {:.2}ms", times[n - 1]);
    }

    print_stats("Cold start ", &cold_times);
    print_stats("Hot path ", &hot_times);

    // 目标检查
    let cold_p50 = cold_times[cold_times.len() / 2];
    let hot_p50 = hot_times[hot_times.len() / 2];
    println!("\nTarget check:");
    println!(
        "  Cold start P50: {:.2}ms {}",
        cold_p50,
        if cold_p50 < 5.0 { "[PASS]" } else { "[FAIL]" }
    );
    println!(
        "  Hot path P50: {:.2}ms {}",
        hot_p50,
        if hot_p50 < 1.0 { "[PASS]" } else { "[FAIL]" }
    );

    println!("\n=== Test completed ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimobox_core::Sandbox;
    use wasmtime::{Instance, Store};

    fn test_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.timeout_secs = Some(10);
        config.memory_limit_mb = Some(64);
        config.fs_readonly = vec![];
        config.fs_readwrite = vec![];
        config.deny_network = true;
        config.seccomp_profile = mimobox_core::SeccompProfile::Essential;
        config.allow_fork = false;
        config.allowed_http_domains = vec![];
        config
    }

    #[test]
    fn test_wasm_sandbox_create() {
        let sb = WasmSandbox::new(test_config());
        assert!(sb.is_ok(), "Failed to create Wasm sandbox: {:?}", sb.err());
    }

    #[test]
    fn test_wasm_sandbox_empty_command() {
        let mut sb = WasmSandbox::new(test_config()).expect("Failed to create");
        let result = sb.execute(&[]);
        assert!(result.is_err(), "Empty command should return error");
    }

    #[test]
    fn test_wasm_sandbox_nonexistent_file() {
        let mut sb = WasmSandbox::new(test_config()).expect("Failed to create");
        let result = sb.execute(&["/nonexistent/file.wasm".to_string()]);
        assert!(result.is_err(), "Nonexistent file should return error");
    }

    #[test]
    fn test_wasm_sandbox_destroy() {
        let sb = WasmSandbox::new(test_config()).expect("Failed to create");
        let result = sb.destroy();
        assert!(
            result.is_ok(),
            "Failed to destroy sandbox: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_compile_module_from_bytes_is_not_affected_by_path_swap() {
        let engine = Engine::default();
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let wasm_path = temp_dir.path().join("swap.wasm");
        let module_a = wat::parse_str(
            r#"
                (module
                  (func (export "main") (result i32)
                    i32.const 1))
            "#,
        )
        .expect("Failed to compile module A WAT");
        let module_b = wat::parse_str(
            r#"
                (module
                  (func (export "main") (result i32)
                    i32.const 2))
            "#,
        )
        .expect("Failed to compile module B WAT");

        std::fs::write(&wasm_path, &module_a).expect("Failed to write initial module");
        let module = compile_module_from_bytes(&engine, &wasm_path, &module_a)
            .expect("Should compile from read bytes");
        std::fs::write(&wasm_path, &module_b).expect("Failed to overwrite module");

        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module, &[])
            .expect("Failed to instantiate module from read bytes");
        let main = instance
            .get_typed_func::<(), i32>(&mut store, "main")
            .expect("Failed to get main export");

        assert_eq!(main.call(&mut store, ()).expect("Failed to call main"), 1);
    }
}
