//! mimobox-wasm: Wasm 沙箱后端
//!
//! 基于 Wasmtime 运行时实现 Wasm 沙箱，支持 WASI Preview 1。
//! 核心设计：
//! - Engine 全局共享（WasmSandbox 持有，跨多次 execute 复用）
//! - Module 编译缓存（基于文件内容 SHA256 哈希，避免重复编译）
//! - Store 独立（每次 execute 创建新 Store + WASI 上下文 + 资源限制）
//! - stdout/stderr 通过 MemoryOutputPipe 捕获到内存缓冲区（内置容量上限）
//! - Fuel 机制 + Epoch Interruption 双重执行时间限制

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

/// 沙箱 Store 数据：组合 WASI 上下文和资源限制
///
/// [FATAL-01 修复] 通过将 StoreLimits 嵌入 Store data type，
/// 使 store.limiter() 回调能正确返回 &mut dyn ResourceLimiter，
/// 从而将 memory_limit_mb 配置实际应用到 Wasm 运行时。
struct StoreData {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

/// 日志宏
macro_rules! log_info {
    ($($arg:tt)*) => {
        eprintln!("[mimobox:wasm:info] {}", format!($($arg)*))
    };
}

macro_rules! log_warn {
    ($($arg:tt)*) => {
        eprintln!("[mimobox:wasm:warn] {}", format!($($arg)*))
    };
}

/// Fuel 估算系数：每秒约 1500 万条 Wasm 指令（fuel），含 50% 余量
const FUEL_PER_SECOND: u64 = 15_000_000;

/// 无 timeout 时的默认 fuel 上限（约等价于 1000 万条 Wasm 指令）
const DEFAULT_FUEL_LIMIT: u64 = 10_000_000;

/// stdout/stderr 缓冲区最大容量：1MB
/// MemoryOutputPipe 的 capacity 参数同时作为写入上限，
/// 超过此容量后 write 会返回 StreamError::Closed。
const OUTPUT_MAX_CAPACITY: usize = 1024 * 1024;

/// 单个输出流的最大返回大小：4MB（超出部分截断并记录警告）
const MAX_OUTPUT_SIZE: usize = 4 * 1024 * 1024;

/// Wasm 模块文件大小上限：100MB
const MAX_WASM_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// 默认内存限制：64MB（当 config 未指定时使用）
const DEFAULT_MEMORY_LIMIT_MB: u64 = 64;

/// Epoch tick 间隔：10ms
const EPOCH_TICK_INTERVAL_MS: u64 = 10;

/// 根据 timeout_secs 动态计算 fuel 上限
///
/// [IMPORTANT-01 修复] 粗略映射 timeout_secs 到 fuel 配额。
/// Fuel 仅在 Wasm 纯指令执行时消耗，WASI I/O 操作期间的等待时间不计入。
/// 因此 fuel 是超时的近似机制，配合 epoch_interruption 实现墙钟超时。
fn fuel_from_timeout(timeout_secs: Option<u64>) -> u64 {
    match timeout_secs {
        Some(secs) => secs.saturating_mul(FUEL_PER_SECOND),
        None => DEFAULT_FUEL_LIMIT,
    }
}

/// 读取并截断输出到最大大小
fn truncate_output(data: Vec<u8>, label: &str) -> Vec<u8> {
    if data.len() > MAX_OUTPUT_SIZE {
        log_warn!(
            "{} 输出超出限制 ({} > {} bytes)，已截断",
            label,
            data.len(),
            MAX_OUTPUT_SIZE
        );
        data[..MAX_OUTPUT_SIZE].to_vec()
    } else {
        data
    }
}

/// Wasm 沙箱后端
///
/// 持有全局共享的 Engine 和模块缓存目录路径，每次 execute 创建独立的 Store。
pub struct WasmSandbox {
    engine: Arc<Engine>,
    config: SandboxConfig,
    cache_dir: PathBuf,
}

/// 计算文件内容的 SHA256 哈希
///
/// [IMPORTANT-02 修复] 使用 SHA256 替代 DefaultHasher，
/// 基于文件内容而非路径+修改时间生成缓存键，消除 TOCTOU 竞态条件。
fn content_hash(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}

/// 获取文件的轻量级元数据指纹（大小 + 修改时间）
///
/// 用于快速判断文件是否可能变更，避免每次 execute 都读取文件内容计算 SHA256。
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
        SandboxError::ExecutionFailed(format!("加载 Wasm 模块失败 ({:?}): {}", wasm_path, e))
    })
}

/// 获取或编译模块（带磁盘缓存）
///
/// 使用混合缓存策略：
/// 1. 先用轻量级元数据指纹（大小+修改时间）查找缓存映射文件
/// 2. 缓存映射命中时，直接使用对应的 SHA256 缓存键加载
/// 3. 缓存映射未命中时，计算文件内容 SHA256 并更新缓存
///
/// 这样在缓存命中的热路径上无需读取整个文件计算哈希。
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
            let file_data = std::fs::read(wasm_path)
                .map_err(|e| SandboxError::ExecutionFailed(format!("读取 Wasm 文件失败: {}", e)))?;
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
                        log_info!("从缓存加载模块: {:?}", wasm_path);
                        return Ok(module);
                    }
                    Err(e) => {
                        // 反序列化失败：缓存可能损坏或 Engine 配置变更，静默降级重新编译
                        log_warn!("缓存反序列化失败，将重新编译: {}", e);
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
        .map_err(|e| SandboxError::ExecutionFailed(format!("读取 Wasm 文件失败: {}", e)))?;
    let hash = content_hash(&file_data);
    let cache_path = cache_dir.join(format!("{}.cwasm", hash));

    // 检查是否已有相同内容的缓存（文件内容相同但元数据不同）
    if let Ok(cached) = std::fs::read(&cache_path) {
        match unsafe { Module::deserialize(engine, &cached) } {
            Ok(module) => {
                // 更新映射文件
                let _ = std::fs::write(&map_file, &hash);
                log_info!("从缓存加载模块（内容匹配）: {:?}", wasm_path);
                return Ok(module);
            }
            Err(e) => {
                log_warn!("缓存反序列化失败，将重新编译: {}", e);
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
                log_warn!("重命名缓存文件失败: {}", e);
                let _ = std::fs::remove_file(&tmp_path);
            }
        }
        // 更新映射文件
        let _ = std::fs::write(&map_file, &hash);
    }

    log_info!("编译并缓存模块: {:?}", wasm_path);
    Ok(module)
}

/// 创建沙箱专用的 Wasmtime Engine 配置
fn create_engine_config() -> Config {
    let mut config = Config::new();
    config.cranelift_opt_level(OptLevel::Speed);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.max_wasm_stack(512 * 1024); // 512KB Wasm 栈
    config.parallel_compilation(true);
    config
}

/// 构建 WASI Preview 1 上下文
///
/// 根据 SandboxConfig 配置文件系统访问、环境变量等。
/// stdout/stderr 通过 MemoryOutputPipe 捕获到内存缓冲区。
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
                    log_warn!("开放只读目录失败 {:?}: {}", path, e);
                }
            } else {
                log_warn!("只读路径不存在: {:?}", path);
            }
        }
    }
    for path in &config.fs_readwrite {
        if let Some(path_str) = path.to_str() {
            if path.exists() {
                if let Err(e) =
                    builder.preopened_dir(path, path_str, DirPerms::all(), FilePerms::all())
                {
                    log_warn!("开放读写目录失败 {:?}: {}", path, e);
                }
            } else {
                log_warn!("读写路径不存在: {:?}", path);
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
        let engine = Engine::new(&engine_config).map_err(|e| {
            SandboxError::ExecutionFailed(format!("Wasmtime Engine 创建失败: {}", e))
        })?;

        // [IMPORTANT-02 修复] 使用用户专属缓存目录，避免不同用户之间的缓存污染
        let uid = unsafe { libc::geteuid() };
        // SAFETY: geteuid() 是无副作用的系统调用，始终返回有效的 uid。
        let cache_dir = std::env::temp_dir().join(format!("mimobox-cache-{}", uid));

        log_info!(
            "创建 Wasm 沙箱后端, memory_limit={:?}MB, timeout={:?}s, cache_dir={:?}",
            config.memory_limit_mb,
            config.timeout_secs,
            cache_dir,
        );

        Ok(Self {
            engine: Arc::new(engine),
            config,
            cache_dir,
        })
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        let start = Instant::now();

        if cmd.is_empty() {
            return Err(SandboxError::ExecutionFailed("命令为空".into()));
        }

        let wasm_path = Path::new(&cmd[0]);
        if !wasm_path.exists() {
            return Err(SandboxError::ExecutionFailed(format!(
                "Wasm 文件不存在: {:?}",
                wasm_path
            )));
        }

        // [MINOR-07] 预检查文件大小，防止超大文件导致编译时 OOM
        if let Ok(meta) = std::fs::metadata(wasm_path)
            && meta.len() > MAX_WASM_FILE_SIZE
        {
            return Err(SandboxError::ExecutionFailed(format!(
                "Wasm 文件过大: {} bytes (上限 {} bytes)",
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
            SandboxError::ExecutionFailed(format!("注册 WASI Preview 1 失败: {}", e))
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
            .map_err(|e| SandboxError::ExecutionFailed(format!("设置 Fuel 失败: {}", e)))?;

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

        // 启动 epoch ticker 后台线程
        // 使用 Arc<AtomicBool> 控制线程退出。
        // 注意：不使用 join() 等待线程退出，因为线程循环中每 10ms 检查一次 flag，
        // join() 会导致 execute 额外等待最多 10ms，严重影响热路径性能。
        // 线程会在 running=false 后自然退出（下次循环检查时）。
        let engine_ref = self.engine.clone();
        let max_epoch_duration = std::time::Duration::from_millis(
            epoch_deadline_ticks.saturating_mul(EPOCH_TICK_INTERVAL_MS),
        );
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let _epoch_thread = std::thread::spawn(move || {
            let tick_interval = std::time::Duration::from_millis(EPOCH_TICK_INTERVAL_MS);
            let epoch_start = std::time::Instant::now();
            while running_clone.load(Ordering::Relaxed) {
                std::thread::sleep(tick_interval);
                if epoch_start.elapsed() > max_epoch_duration {
                    break;
                }
                engine_ref.increment_epoch();
            }
        });

        // 8. 实例化模块
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::ExecutionFailed(format!("Wasm 模块实例化失败: {}", e)))?;

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
                            log_warn!("执行超时（fuel 耗尽或 epoch deadline 超出）");
                            // 通知 epoch ticker 线程退出
                            running.store(false, Ordering::Relaxed);
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
                            log_warn!("Wasm 执行错误: {}", e);
                            Some(1)
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
                                log_warn!("main 函数执行失败: {}", e);
                                Some(1)
                            }
                        }
                    },
                    Err(_) => {
                        return Err(SandboxError::ExecutionFailed(
                            "Wasm 模块没有 _start 或 main 导出函数".into(),
                        ));
                    }
                }
            }
        };

        let elapsed = start.elapsed();

        // 10. 通知 epoch ticker 线程退出（不 join，避免阻塞）
        running.store(false, Ordering::Relaxed);

        // 11. 从 clone 的 MemoryOutputPipe 中读取捕获的输出（带截断保护）
        let stdout = truncate_output(stdout_reader.contents().to_vec(), "stdout");
        let stderr = truncate_output(stderr_reader.contents().to_vec(), "stderr");

        log_info!(
            "Wasm 执行完成, exit_code={:?}, elapsed={:.2}ms",
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
        log_info!("销毁 Wasm 沙箱后端");
        Ok(())
    }
}

/// 检查 Store 中的 fuel 是否已耗尽
fn is_fuel_exhausted(store: &Store<StoreData>) -> bool {
    store.get_fuel().is_ok_and(|f| f == 0)
}

/// 检查错误是否为 epoch 中断（墙钟超时）
fn is_epoch_interrupt(error: &wasmtime::Error) -> bool {
    if let Some(trap) = error.downcast_ref::<Trap>() {
        matches!(trap, Trap::Interrupt)
    } else {
        false
    }
}

/// 从 wasmtime Error chain 中查找 WASI I32Exit 退出码
///
/// WASI proc_exit 通过 I32Exit 错误传播退出码，但可能被
/// WasmBacktrace 等中间层包装。此函数遍历整个错误链查找。
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

    // 遍历 error chain（通过 format 字符串匹配作为最后手段）
    let err_str = format!("{}", error);
    if err_str.contains("Exited with i32 exit status") {
        // 格式："Exited with i32 exit status N"
        let parts: Vec<&str> = err_str.split_whitespace().collect();
        for i in 0..parts.len() {
            if parts[i] == "status"
                && i + 1 < parts.len()
                && let Ok(code) = parts[i + 1].parse::<i32>()
            {
                return Some(code);
            }
        }
    }

    None
}

/// 运行 Wasm 沙箱冷启动基准测试
pub fn run_wasm_benchmark(
    wasm_path: &str,
    iterations: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== mimobox Wasm 沙箱性能基准测试 ===\n");

    let config = SandboxConfig {
        deny_network: true,
        memory_limit_mb: Some(64),
        timeout_secs: Some(30),
        fs_readonly: vec![],
        fs_readwrite: vec![],
        seccomp_profile: mimobox_core::SeccompProfile::Essential,
        allow_fork: false,
    };

    if !Path::new(wasm_path).exists() {
        return Err(format!("Wasm 文件不存在: {}", wasm_path).into());
    }

    let cmd = vec![wasm_path.to_string()];

    // Phase 1: Engine 创建开销（一次性）
    println!("测试 Engine 创建开销...");
    let engine_start = Instant::now();
    let mut sb = WasmSandbox::new(config.clone())?;
    let engine_elapsed = engine_start.elapsed();
    println!(
        "  Engine 创建: {:.2}ms",
        engine_elapsed.as_secs_f64() * 1000.0
    );

    // Phase 2: 模块编译开销（首次）
    println!("\n测试模块首次编译...");
    let compile_start = Instant::now();
    let result = sb.execute(&cmd)?;
    let compile_elapsed = compile_start.elapsed();
    println!(
        "  首次执行（含编译）: {:.2}ms, exit_code={:?}",
        compile_elapsed.as_secs_f64() * 1000.0,
        result.exit_code
    );

    // Phase 3: 冷启动测试（每次 new + execute）
    println!(
        "\n冷启动测试 ({} 次迭代, 每次含 new + execute)...",
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
            eprintln!("迭代 {} 失败: 退出码 {:?}", i, result.exit_code);
        }
    }

    // Phase 4: 热路径测试（复用 Engine，仅 execute）
    println!("\n热路径测试 ({} 次迭代, 复用 Engine)...", iterations);
    let mut hot_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let result = sb.execute(&cmd)?;
        let elapsed = start.elapsed();
        hot_times.push(elapsed.as_micros() as f64 / 1000.0);

        if result.exit_code != Some(0) {
            eprintln!("热路径执行失败: {:?}", result.exit_code);
        }
    }

    // 统计输出
    cold_times.sort_by(f64::total_cmp);
    hot_times.sort_by(f64::total_cmp);

    fn print_stats(label: &str, times: &[f64]) {
        let n = times.len();
        if n == 0 {
            println!("{}  无数据", label);
            return;
        }
        let p50 = times[n / 2];
        let p95_idx = ((n as f64 * 0.95) as usize).min(n - 1);
        let p99_idx = ((n as f64 * 0.99) as usize).min(n - 1);
        let avg: f64 = times.iter().sum::<f64>() / n as f64;

        println!("\n{}延迟:", label);
        println!("  Min:  {:.2}ms", times[0]);
        println!("  P50:  {:.2}ms", p50);
        println!("  P95:  {:.2}ms", times[p95_idx]);
        println!("  P99:  {:.2}ms", times[p99_idx]);
        println!("  Avg:  {:.2}ms", avg);
        println!("  Max:  {:.2}ms", times[n - 1]);
    }

    print_stats("冷启动", &cold_times);
    print_stats("热路径", &hot_times);

    // 目标检查
    let cold_p50 = cold_times[cold_times.len() / 2];
    let hot_p50 = hot_times[hot_times.len() / 2];
    println!("\n目标检查:");
    println!(
        "  冷启动 P50: {:.2}ms {}",
        cold_p50,
        if cold_p50 < 5.0 { "[PASS]" } else { "[FAIL]" }
    );
    println!(
        "  热路径 P50: {:.2}ms {}",
        hot_p50,
        if hot_p50 < 1.0 { "[PASS]" } else { "[FAIL]" }
    );

    println!("\n=== 测试完成 ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimobox_core::Sandbox;
    use wasmtime::{Instance, Store};

    fn test_config() -> SandboxConfig {
        SandboxConfig {
            timeout_secs: Some(10),
            memory_limit_mb: Some(64),
            fs_readonly: vec![],
            fs_readwrite: vec![],
            deny_network: true,
            seccomp_profile: mimobox_core::SeccompProfile::Essential,
            allow_fork: false,
        }
    }

    #[test]
    fn test_wasm_sandbox_create() {
        let sb = WasmSandbox::new(test_config());
        assert!(sb.is_ok(), "创建 Wasm 沙箱失败: {:?}", sb.err());
    }

    #[test]
    fn test_wasm_sandbox_empty_command() {
        let mut sb = WasmSandbox::new(test_config()).expect("创建失败");
        let result = sb.execute(&[]);
        assert!(result.is_err(), "空命令应返回错误");
    }

    #[test]
    fn test_wasm_sandbox_nonexistent_file() {
        let mut sb = WasmSandbox::new(test_config()).expect("创建失败");
        let result = sb.execute(&["/nonexistent/file.wasm".to_string()]);
        assert!(result.is_err(), "不存在的文件应返回错误");
    }

    #[test]
    fn test_wasm_sandbox_destroy() {
        let sb = WasmSandbox::new(test_config()).expect("创建失败");
        let result = sb.destroy();
        assert!(result.is_ok(), "销毁沙箱失败: {:?}", result.err());
    }

    #[test]
    fn test_compile_module_from_bytes_is_not_affected_by_path_swap() {
        let engine = Engine::default();
        let temp_dir = tempfile::tempdir().expect("创建临时目录失败");
        let wasm_path = temp_dir.path().join("swap.wasm");
        let module_a = wat::parse_str(
            r#"
                (module
                  (func (export "main") (result i32)
                    i32.const 1))
            "#,
        )
        .expect("编译 module A WAT 失败");
        let module_b = wat::parse_str(
            r#"
                (module
                  (func (export "main") (result i32)
                    i32.const 2))
            "#,
        )
        .expect("编译 module B WAT 失败");

        std::fs::write(&wasm_path, &module_a).expect("写入初始模块失败");
        let module = compile_module_from_bytes(&engine, &wasm_path, &module_a)
            .expect("应使用已读取字节编译");
        std::fs::write(&wasm_path, &module_b).expect("覆盖模块失败");

        let mut store = Store::new(&engine, ());
        let instance = Instance::new(&mut store, &module, &[]).expect("实例化已读取字节的模块失败");
        let main = instance
            .get_typed_func::<(), i32>(&mut store, "main")
            .expect("获取 main 导出失败");

        assert_eq!(main.call(&mut store, ()).expect("调用 main 失败"), 1);
    }
}
