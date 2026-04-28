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

use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tracing::{info, warn};
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

/// Wasmtime serialized module cache namespace.
///
/// Wasmtime 43.0.1 is the currently resolved workspace dependency version. Keeping it in the
/// cache directory isolates serialized modules from incompatible runtime upgrades.
const WASMTIME_CACHE_VERSION: &str = "43.0.1";

/// Engine configuration namespace for serialized module cache entries.
const ENGINE_CONFIG_CACHE_KEY: &str = "opt-speed-fuel-epoch-stack512k-parallel";

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
        warn!(
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
    cache_dir: Option<PathBuf>,
}

/// Calculates the SHA256 hash of file content.
///
/// [IMPORTANT-02 fix] Uses SHA256 instead of `DefaultHasher`, generating cache keys from file
/// content rather than path plus modification time to eliminate TOCTOU race conditions.
fn content_hash(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}

fn get_wasmtime_version() -> &'static str {
    WASMTIME_CACHE_VERSION
}

fn cache_namespace() -> String {
    format!(
        "wasmtime-{}-{}",
        get_wasmtime_version(),
        ENGINE_CONFIG_CACHE_KEY
    )
}

fn current_euid() -> u32 {
    // SAFETY: geteuid() 是无副作用的系统调用，始终返回当前进程有效 uid。
    unsafe { libc::geteuid() as u32 }
}

fn metadata_mtime_nanos(meta: &std::fs::Metadata) -> Option<u64> {
    let nanos = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    u64::try_from(nanos).ok()
}

/// Gets a lightweight metadata fingerprint for a file: size plus modification time.
///
/// Used to quickly determine whether a file may have changed, avoiding a full file read and
/// SHA256 calculation on every `execute` call.
fn file_fingerprint(path: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let size = meta.len();
    let mtime = metadata_mtime_nanos(&meta)?;
    Some((size, mtime))
}

fn validate_cache_dir_security(path: &Path) -> bool {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            warn!("Failed to stat cache directory {:?}: {}", path, e);
            return false;
        }
    };

    if !meta.file_type().is_dir() {
        warn!("Cache path is not a real directory: {:?}", path);
        return false;
    }

    let uid = current_euid();
    if meta.uid() != uid {
        warn!(
            "Cache directory owner mismatch: path={:?}, owner={}, expected={}",
            path,
            meta.uid(),
            uid
        );
        return false;
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        warn!(
            "Cache directory has insecure permissions: path={:?}, mode={:o}",
            path, mode
        );
        return false;
    }

    true
}

fn ensure_cache_dir_security(path: &Path) -> bool {
    if let Err(e) = std::fs::create_dir_all(path) {
        warn!("Failed to create cache directory {:?}: {}", path, e);
        return false;
    }

    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            warn!("Failed to stat cache directory {:?}: {}", path, e);
            return false;
        }
    };

    if !meta.file_type().is_dir() {
        warn!("Cache path is not a real directory: {:?}", path);
        return false;
    }

    let uid = current_euid();
    if meta.uid() != uid {
        warn!(
            "Refusing to use cache directory with unexpected owner: path={:?}, owner={}, expected={}",
            path,
            meta.uid(),
            uid
        );
        return false;
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700
        && let Err(e) = std::fs::set_permissions(path, Permissions::from_mode(0o700))
    {
        warn!(
            "Failed to tighten cache directory permissions for {:?}: {}",
            path, e
        );
        return false;
    }

    validate_cache_dir_security(path)
}

fn validate_cache_file_security(path: &Path) -> bool {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("Failed to stat cache file {:?}: {}", path, e);
            }
            return false;
        }
    };

    if !meta.file_type().is_file() {
        warn!("Cache path is not a regular file: {:?}", path);
        return false;
    }

    let uid = current_euid();
    if meta.uid() != uid {
        warn!(
            "Cache file owner mismatch: path={:?}, owner={}, expected={}",
            path,
            meta.uid(),
            uid
        );
        return false;
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        warn!(
            "Cache file has insecure permissions: path={:?}, mode={:o}",
            path, mode
        );
        return false;
    }

    true
}

fn remove_file_if_exists(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("Failed to remove cache file {:?}: {}", path, e),
    }
}

fn cache_file_mtime(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    metadata_mtime_nanos(&meta)
}

#[derive(Debug)]
struct CacheRecord {
    hash: String,
    mtime_nanos: u64,
}

fn parse_cache_record(contents: &str) -> Option<CacheRecord> {
    let (hash, mtime_nanos) = contents.trim().split_once(':')?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    Some(CacheRecord {
        hash: hash.to_string(),
        mtime_nanos: mtime_nanos.parse().ok()?,
    })
}

fn read_cache_record(path: &Path) -> Option<CacheRecord> {
    if !validate_cache_file_security(path) {
        remove_file_if_exists(path);
        return None;
    }

    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) => {
            warn!("Failed to read cache record {:?}: {}", path, e);
            remove_file_if_exists(path);
            return None;
        }
    };

    match parse_cache_record(&contents) {
        Some(record) => Some(record),
        None => {
            warn!("Invalid cache record format: {:?}", path);
            remove_file_if_exists(path);
            None
        }
    }
}

fn cache_metadata_path(cache_path: &Path) -> PathBuf {
    cache_path.with_extension("cwasm.meta")
}

fn private_tmp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "cache".into());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    path.with_file_name(format!(
        "{}.{}.{}.tmp",
        file_name,
        std::process::id(),
        nonce
    ))
}

fn write_private_file_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp_path = private_tmp_path(path);
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(&tmp_path, path)?;
        std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
        Ok(())
    })();

    if result.is_err() {
        remove_file_if_exists(&tmp_path);
    }

    result
}

fn write_cache_record(path: &Path, hash: &str, cache_mtime_nanos: u64) {
    let record = format!("{}:{}", hash, cache_mtime_nanos);
    if let Err(e) = write_private_file_atomic(path, record.as_bytes()) {
        warn!("Failed to write cache record {:?}: {}", path, e);
    }
}

fn read_secure_cache_file(path: &Path, expected_mtime_nanos: u64) -> Option<Vec<u8>> {
    if !validate_cache_file_security(path) {
        remove_file_if_exists(path);
        return None;
    }

    let before_mtime = match cache_file_mtime(path) {
        Some(mtime) => mtime,
        None => {
            warn!("Failed to read cache file mtime before read: {:?}", path);
            remove_file_if_exists(path);
            return None;
        }
    };
    if before_mtime != expected_mtime_nanos {
        warn!(
            "Cache file mtime mismatch before read: path={:?}, expected={}, actual={}",
            path, expected_mtime_nanos, before_mtime
        );
        remove_file_if_exists(path);
        return None;
    }

    let cached = match std::fs::read(path) {
        Ok(cached) => cached,
        Err(e) => {
            warn!("Failed to read cache file {:?}: {}", path, e);
            remove_file_if_exists(path);
            return None;
        }
    };

    if !validate_cache_file_security(path) {
        remove_file_if_exists(path);
        return None;
    }

    let after_mtime = match cache_file_mtime(path) {
        Some(mtime) => mtime,
        None => {
            warn!("Failed to read cache file mtime after read: {:?}", path);
            remove_file_if_exists(path);
            return None;
        }
    };
    if after_mtime != before_mtime || after_mtime != expected_mtime_nanos {
        warn!(
            "Cache file changed during read: path={:?}, expected={}, before={}, after={}",
            path, expected_mtime_nanos, before_mtime, after_mtime
        );
        remove_file_if_exists(path);
        return None;
    }

    Some(cached)
}

fn load_cached_module(
    engine: &Engine,
    wasm_path: &Path,
    cache_path: &Path,
    expected_mtime_nanos: u64,
    record_path: Option<&Path>,
    label: &str,
) -> Option<Module> {
    let cached = match read_secure_cache_file(cache_path, expected_mtime_nanos) {
        Some(cached) => cached,
        None => {
            if let Some(record_path) = record_path {
                remove_file_if_exists(record_path);
            }
            return None;
        }
    };

    // SAFETY: 只在私有缓存目录通过 owner=当前 euid、mode=0700 校验后进入此路径；
    // 缓存文件和记录文件也必须为 owner=当前 euid、mode=0600。
    // 读取前后均校验缓存文件 mtime 与记录值一致，若文件被替换或修改会删除并重新编译。
    // 因此传入 bytes 只来自本程序在同一缓存命名空间中此前 Module::serialize() 写入的受控缓存。
    match unsafe { Module::deserialize(engine, &cached) } {
        Ok(module) => {
            info!("Loaded module from cache ({}): {:?}", label, wasm_path);
            Some(module)
        }
        Err(e) => {
            warn!("Cache deserialization failed, recompiling: {}", e);
            remove_file_if_exists(cache_path);
            remove_file_if_exists(&cache_metadata_path(cache_path));
            if let Some(record_path) = record_path {
                remove_file_if_exists(record_path);
            }
            None
        }
    }
}

fn compile_uncached_module(engine: &Engine, wasm_path: &Path) -> Result<Module, SandboxError> {
    let file_data = std::fs::read(wasm_path)
        .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to read Wasm file: {}", e)))?;
    compile_module_from_bytes(engine, wasm_path, &file_data)
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
    cache_dir: Option<&Path>,
) -> Result<Module, SandboxError> {
    let cache_dir = match cache_dir {
        Some(cache_dir) if ensure_cache_dir_security(cache_dir) => cache_dir,
        Some(cache_dir) => {
            warn!(
                "Wasm cache directory is insecure; compiling without disk cache: {:?}",
                cache_dir
            );
            return compile_uncached_module(engine, wasm_path);
        }
        None => return compile_uncached_module(engine, wasm_path),
    };

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

    // 缓存映射文件：记录 "fingerprint -> sha256_hash:cache_mtime_nanos" 的映射
    // 文件名格式: {size}_{mtime_nanos}.map
    let map_file = cache_dir.join(format!("{}_{}.map", fingerprint.0, fingerprint.1));

    // 尝试通过映射文件找到对应的缓存
    if let Some(record) = read_cache_record(&map_file) {
        let cache_path = cache_dir.join(format!("{}.cwasm", record.hash));
        if let Some(module) = load_cached_module(
            engine,
            wasm_path,
            &cache_path,
            record.mtime_nanos,
            Some(&map_file),
            "fingerprint match",
        ) {
            return Ok(module);
        }
    }

    // 缓存未命中：需要计算文件内容的 SHA256
    let file_data = std::fs::read(wasm_path)
        .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to read Wasm file: {}", e)))?;
    let hash = content_hash(&file_data);
    let cache_path = cache_dir.join(format!("{}.cwasm", hash));
    let cache_metadata_file = cache_metadata_path(&cache_path);

    // 检查是否已有相同内容的缓存（文件内容相同但元数据不同）
    if let Some(record) = read_cache_record(&cache_metadata_file) {
        if record.hash == hash {
            if let Some(module) = load_cached_module(
                engine,
                wasm_path,
                &cache_path,
                record.mtime_nanos,
                Some(&cache_metadata_file),
                "content match",
            ) {
                write_cache_record(&map_file, &hash, record.mtime_nanos);
                return Ok(module);
            }
        } else {
            warn!(
                "Cache metadata hash mismatch: path={:?}, expected={}, actual={}",
                cache_metadata_file, hash, record.hash
            );
            remove_file_if_exists(&cache_metadata_file);
        }
    }

    // 编译模块
    let module = compile_module_from_bytes(engine, wasm_path, &file_data)?;

    // 序列化到缓存目录（原子写入：先写临时文件再 rename，避免并发读到不完整数据）
    if let Ok(serialized) = module.serialize() {
        match write_private_file_atomic(&cache_path, &serialized) {
            Ok(()) => {
                if let Some(cache_mtime_nanos) = cache_file_mtime(&cache_path) {
                    write_cache_record(&map_file, &hash, cache_mtime_nanos);
                    write_cache_record(&cache_metadata_file, &hash, cache_mtime_nanos);
                } else {
                    warn!("Failed to record cache file mtime: {:?}", cache_path);
                    remove_file_if_exists(&cache_path);
                    remove_file_if_exists(&cache_metadata_file);
                    remove_file_if_exists(&map_file);
                }
            }
            Err(e) => warn!("Failed to write cache file {:?}: {}", cache_path, e),
        }
    }

    info!("Compiled and cached module: {:?}", wasm_path);
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

static GLOBAL_ENGINE: LazyLock<Result<Arc<Engine>, String>> = LazyLock::new(|| {
    let engine_config = create_engine_config();
    let engine = Arc::new(
        Engine::new(&engine_config)
            .map_err(|e| format!("Failed to create Wasmtime Engine: {}", e))?,
    );
    start_global_epoch_ticker(&engine)?;
    Ok(engine)
});

static EPOCH_TICKER_STARTED: OnceLock<()> = OnceLock::new();

fn start_global_epoch_ticker(engine: &Arc<Engine>) -> Result<(), String> {
    if EPOCH_TICKER_STARTED.get().is_some() {
        return Ok(());
    }

    let epoch_thread_engine = Arc::clone(engine);
    std::thread::Builder::new()
        .name("mimobox-wasm-epoch-ticker".to_string())
        .spawn(move || {
            let tick_interval = std::time::Duration::from_millis(EPOCH_TICK_INTERVAL_MS);
            loop {
                std::thread::sleep(tick_interval);
                epoch_thread_engine.increment_epoch();
            }
        })
        .map_err(|e| format!("Failed to start Wasm epoch ticker: {}", e))?;

    let _ = EPOCH_TICKER_STARTED.set(());
    Ok(())
}

fn global_engine() -> Result<Arc<Engine>, SandboxError> {
    GLOBAL_ENGINE
        .as_ref()
        .map(Arc::clone)
        .map_err(|e| SandboxError::ExecutionFailed(e.clone()))
}

/// 检查路径是否是缓存目录的祖先或后代（基于 canonicalize 的双向检查）。
///
/// 使用 canonicalize() 解析符号链接和 .. 路径组件，防止攻击者通过符号链接
/// 将 preopen 路径指向缓存目录的祖先，从而绕过保护。
///
/// 安全模型：guest 不得获得任何覆盖缓存目录的 preopen（无论是只读还是读写），
/// 因为 Module::deserialize 是 unsafe 的，要求缓存文件可信。
fn is_path_cache_ancestor(path: &Path, cache_dir: &Path) -> bool {
    let Ok(canonical_path) = path.canonicalize() else {
        // 路径不存在时无法 canonicalize，安全起见保守处理：回退到词法检查。
        return is_lexical_ancestor(path, cache_dir);
    };
    let Ok(canonical_cache) = cache_dir.canonicalize() else {
        return false;
    };

    canonical_path == canonical_cache
        || canonical_path.starts_with(&canonical_cache)
        || canonical_cache.starts_with(&canonical_path)
}

/// 不存在路径的保守回退：词法前缀检查。
///
/// 当路径不存在无法 canonicalize 时，退而求其次检查词法前缀关系。
/// 这种保守策略确保即使路径尚未创建，也不会意外暴露缓存目录。
fn is_lexical_ancestor(path: &Path, cache_dir: &Path) -> bool {
    let normalize = |path: &Path| -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if !normalized.pop()
                        && !matches!(
                            normalized.components().next_back(),
                            Some(Component::RootDir)
                        )
                    {
                        normalized.push(component.as_os_str());
                    }
                }
                Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {
                    normalized.push(component.as_os_str());
                }
            }
        }
        normalized
    };

    let normalized_path = normalize(path);
    let normalized_cache = normalize(cache_dir);

    normalized_path == normalized_cache
        || normalized_path.starts_with(&normalized_cache)
        || normalized_cache.starts_with(&normalized_path)
}

/// Builds a WASI Preview 1 context.
///
/// Security design:
/// - WASI preopen paths must not expose ancestors of the private module cache directory. Otherwise
///   guest code could traverse into the cache namespace when a broad path such as `/tmp` is
///   preopened.
/// - `HOME` is set to a virtual sandbox path instead of a host temporary directory so guest code
///   does not infer or depend on host cache/temp locations.
/// - `TMPDIR` is intentionally not set. Any temporary directory access must be granted explicitly
///   through `SandboxConfig` preopens instead of an ambient environment hint.
///
/// Configures filesystem access, environment variables, and related settings from `SandboxConfig`.
/// stdout/stderr are captured into in-memory buffers through `MemoryOutputPipe`.
fn build_wasi_ctx(
    config: &SandboxConfig,
    args: &[String],
    cache_dir: Option<&Path>,
    stdout_pipe: MemoryOutputPipe,
    stderr_pipe: MemoryOutputPipe,
) -> WasiP1Ctx {
    let mut builder = WasiCtxBuilder::new();

    // 设置命令行参数
    for arg in args {
        builder.arg(arg);
    }

    // 设置最小必要环境变量
    builder.env("HOME", "/home/sandbox");
    builder.env("PATH", "/usr/bin:/bin");
    builder.env("TERM", "dumb");
    builder.env("SANDBOX", "wasm");

    // 配置 stdout/stderr 捕获
    builder.stdout(Box::new(stdout_pipe));
    builder.stderr(Box::new(stderr_pipe));

    // 文件系统访问：仅允许 config 中配置的路径
    for path in &config.fs_readonly {
        if cache_dir.is_some_and(|cache_dir| is_path_cache_ancestor(path, cache_dir)) {
            warn!(
                "Skipping read-only WASI preopen because it exposes cache ancestor: path={:?}, cache={:?}",
                path, cache_dir
            );
            continue;
        }

        if let Some(path_str) = path.to_str() {
            if path.exists() {
                // 只授予 READ 权限，WASI 的目录创建/删除等写操作会被拒绝。
                if let Err(e) =
                    builder.preopened_dir(path, path_str, DirPerms::READ, FilePerms::READ)
                {
                    warn!("Failed to preopen read-only dir {:?}: {}", path, e);
                }
            } else {
                warn!("Read-only path does not exist: {:?}", path);
            }
        }
    }
    for path in &config.fs_readwrite {
        if cache_dir.is_some_and(|cache_dir| is_path_cache_ancestor(path, cache_dir)) {
            warn!(
                "Skipping read-write WASI preopen because it exposes cache ancestor: path={:?}, cache={:?}",
                path, cache_dir
            );
            continue;
        }

        if let Some(path_str) = path.to_str() {
            if path.exists() {
                if let Err(e) =
                    builder.preopened_dir(path, path_str, DirPerms::all(), FilePerms::all())
                {
                    warn!("Failed to preopen read-write dir {:?}: {}", path, e);
                }
            } else {
                warn!("Read-write path does not exist: {:?}", path);
            }
        }
    }

    if config.deny_network {
        info!("WASI network denied by SandboxConfig; no sockets are preopened");
    } else {
        warn!(
            "SandboxConfig allows network, but WASI backend cannot enable network access; keeping network denied"
        );
    }

    // 时钟能力：WasiCtxBuilder 仅暴露 wall_clock/monotonic_clock 替换点，
    // 没有 WASI Preview 1 clocks 的禁用/白名单 API；执行时限由 fuel、epoch 和 timeout 控制。

    builder.build_p1()
}

impl Sandbox for WasmSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let engine = global_engine()?;

        // [IMPORTANT-02 修复] 使用用户和 Wasmtime 版本专属缓存目录，避免跨用户和跨版本缓存污染。
        let uid = current_euid();
        let cache_dir =
            std::env::temp_dir().join(format!("mimobox-cache-{}-{}", uid, cache_namespace()));
        let cache_dir = if ensure_cache_dir_security(&cache_dir) {
            Some(cache_dir)
        } else {
            warn!("Wasm disk cache disabled because cache directory is insecure");
            None
        };

        info!(
            "Created Wasm sandbox backend, memory_limit={:?}MB, timeout={:?}s, cache_dir={:?}",
            config.memory_limit_mb, config.timeout_secs, cache_dir,
        );

        Ok(Self {
            engine,
            config,
            cache_dir,
        })
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        let start = Instant::now();

        if cmd.is_empty() {
            return Err(SandboxError::ExecutionFailed("Command is empty".into()));
        }

        let wasm_path = Path::new(&cmd[0]);
        let wasm_meta = std::fs::symlink_metadata(wasm_path)
            .map_err(|_| SandboxError::ExecutionFailed("Wasm file does not exist".into()))?;
        if wasm_meta.file_type().is_symlink() {
            return Err(SandboxError::ExecutionFailed(
                "Wasm file path must not be a symlink".into(),
            ));
        }
        if wasm_meta.nlink() > 1 {
            return Err(SandboxError::ExecutionFailed(
                "Wasm file must not be a hard link (nlink > 1)".into(),
            ));
        }
        if !wasm_meta.file_type().is_file() {
            return Err(SandboxError::ExecutionFailed(
                "Wasm path is not a regular file".into(),
            ));
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
        let module = get_cached_module(&self.engine, wasm_path, self.cache_dir.as_deref())?;

        // 2. [IMPORTANT-03 说明] stdout/stderr 缓冲区容量限制
        // MemoryOutputPipe 的 capacity 参数是写入上限而非初始容量，
        // 超过此容量后 OutputStream::write() 返回 StreamError::Trap，
        // check_write() 返回 StreamError::Closed。
        let stdout_pipe = MemoryOutputPipe::new(OUTPUT_MAX_CAPACITY);
        let stdout_reader = stdout_pipe.clone(); // 保留读取端
        let stderr_pipe = MemoryOutputPipe::new(OUTPUT_MAX_CAPACITY);
        let stderr_reader = stderr_pipe.clone(); // 保留读取端

        // 3. 构建 WASI 上下文
        let wasi_ctx = build_wasi_ctx(
            &self.config,
            cmd,
            self.cache_dir.as_deref(),
            stdout_pipe,
            stderr_pipe,
        );

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
                            warn!(
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
                        } else if is_memory_trap(&e) {
                            info!("Wasm memory limit exceeded, mapping to exit code 1");
                            Some(1)
                        } else {
                            warn!("Wasm execution error: {}", e);
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
                            } else if is_memory_trap(&e) {
                                info!("Wasm memory limit exceeded, mapping to exit code 1");
                                Some(1)
                            } else {
                                warn!("main function execution failed: {}", e);
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

        info!(
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
        info!("Destroying Wasm sandbox backend");
        Ok(())
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

/// Checks whether an error is caused by Wasm memory access or growth limits.
fn is_memory_trap(error: &wasmtime::Error) -> bool {
    if let Some(trap) = error.downcast_ref::<Trap>()
        && matches!(trap, Trap::MemoryOutOfBounds)
    {
        return true;
    }

    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("memory")
        && (message.contains("out of bounds")
            || message.contains("grow")
            || message.contains("growth"))
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
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
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

    #[cfg(unix)]
    #[test]
    fn test_cache_preopen_symlink_to_cache_ancestor_is_rejected() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let root = temp_dir.path();
        let cache_dir = root.join("cache");
        let link_path = root.join("preopen-link");

        std::fs::create_dir(&cache_dir).expect("Failed to create cache dir");
        symlink(root, &link_path).expect("Failed to create symlink");

        assert!(
            is_path_cache_ancestor(&link_path, &cache_dir),
            "symlink 指向缓存目录祖先时必须拒绝 preopen"
        );
    }

    #[test]
    fn test_cache_preopen_parent_dir_component_is_rejected() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let root = temp_dir.path();
        let cache_dir = root.join("cache");
        let nested_cache_dir = cache_dir.join("nested");
        let work_dir = root.join("work");
        let preopen_path = work_dir.join("..").join("cache").join("nested");

        std::fs::create_dir_all(&nested_cache_dir).expect("Failed to create nested cache dir");
        std::fs::create_dir(&work_dir).expect("Failed to create work dir");

        assert!(
            is_path_cache_ancestor(&preopen_path, &cache_dir),
            ".. 组件解析后指向缓存目录后代时必须拒绝 preopen"
        );
    }

    #[test]
    fn test_cache_preopen_non_ancestor_path_is_allowed() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let root = temp_dir.path();
        let cache_dir = root.join("cache");
        let sibling_dir = root.join("cache-sibling");

        std::fs::create_dir(&cache_dir).expect("Failed to create cache dir");
        std::fs::create_dir(&sibling_dir).expect("Failed to create sibling dir");

        assert!(
            !is_path_cache_ancestor(&sibling_dir, &cache_dir),
            "普通兄弟路径不能因字符串前缀相同被误判为缓存目录祖先或后代"
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
