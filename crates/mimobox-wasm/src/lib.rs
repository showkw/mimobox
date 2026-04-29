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

use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tracing::{info, warn};
use wasmtime::{
    Config, Engine, Linker, Module, OptLevel, Store, StoreLimits, StoreLimitsBuilder, Trap,
};
use wasmtime_wasi::I32Exit;
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

use mimobox_core::{
    ExecutionFailureKind, Sandbox, SandboxConfig, SandboxError, SandboxMetrics, SandboxResult,
};

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

/// Maximum Wasm module file size: 50 MB.
const MAX_WASM_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Maximum wall-clock time allowed for Wasm module cache load or compilation.
const COMPILE_TIMEOUT_SECS: u64 = 30;

/// Number of bytes in one MiB.
const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Default memory limit: 64 MB, used when the config does not specify one.
const DEFAULT_MEMORY_LIMIT_MB: u64 = 64;

/// Epoch tick interval: 10 ms.
const EPOCH_TICK_INTERVAL_MS: u64 = 10;

/// Epoch ticks per second.
const EPOCH_TICKS_PER_SECOND: u64 = 1000 / EPOCH_TICK_INTERVAL_MS;

/// Default epoch deadline when no timeout is configured, equivalent to 30 seconds.
const DEFAULT_EPOCH_DEADLINE_TICKS: u64 = 30 * EPOCH_TICKS_PER_SECOND;

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
fn fuel_from_timeout(timeout_secs: Option<u64>) -> Result<u64, SandboxError> {
    match timeout_secs {
        Some(secs) => {
            secs.checked_mul(FUEL_PER_SECOND)
                .ok_or_else(|| SandboxError::ExecutionFailed {
                    kind: ExecutionFailureKind::CpuLimit,
                    message: format!(
                        "timeout_secs={secs} is too large; converting to fuel would overflow"
                    ),
                })
        }
        None => Ok(DEFAULT_FUEL_LIMIT),
    }
}

/// Converts `memory_limit_mb` into bytes for Wasmtime's resource limiter.
fn memory_limit_bytes(memory_limit_mb: Option<u64>) -> Result<usize, SandboxError> {
    let mb = memory_limit_mb.unwrap_or(DEFAULT_MEMORY_LIMIT_MB);
    let bytes = mb
        .checked_mul(BYTES_PER_MIB)
        .ok_or_else(|| SandboxError::ExecutionFailed {
            kind: ExecutionFailureKind::Oom,
            message: format!(
                "memory_limit_mb={mb} is too large; converting to bytes would overflow"
            ),
        })?;

    usize::try_from(bytes).map_err(|_| SandboxError::ExecutionFailed {
        kind: ExecutionFailureKind::Oom,
        message: format!("memory_limit_mb={mb} is too large for this platform"),
    })
}

/// Converts timeout seconds into Wasmtime epoch deadline ticks.
fn epoch_deadline_ticks_from_timeout(timeout_secs: Option<u64>) -> Result<u64, SandboxError> {
    match timeout_secs {
        Some(secs) => secs.checked_mul(EPOCH_TICKS_PER_SECOND).ok_or_else(|| {
            SandboxError::new(format!(
                "timeout_secs={secs} is too large; converting to epoch ticks would overflow"
            ))
        }),
        None => Ok(DEFAULT_EPOCH_DEADLINE_TICKS),
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
    cached_metrics: Option<SandboxMetrics>,
}

impl WasmSandbox {
    /// 返回最近一次 Wasm 后端执行缓存的资源指标。
    pub fn metrics(&self) -> Option<SandboxMetrics> {
        self.cached_metrics.clone()
    }

    fn cache_wasm_metrics(
        &mut self,
        instance: &wasmtime::Instance,
        store: &mut Store<StoreData>,
        initial_fuel: u64,
    ) {
        let memory_usage_bytes = wasm_memory_usage_bytes(instance, store);
        self.cached_metrics = Some(sample_wasm_metrics(
            store,
            memory_usage_bytes,
            initial_fuel,
            self.config.memory_limit_mb,
        ));
    }
}

fn wasm_memory_usage_bytes(
    instance: &wasmtime::Instance,
    store: &mut Store<StoreData>,
) -> Option<u64> {
    let memory = instance.get_memory(&mut *store, "memory")?;
    u64::try_from(memory.data_size(&*store)).ok()
}

/// 采样 Wasm 执行后的资源指标。
fn sample_wasm_metrics(
    store: &Store<StoreData>,
    memory_usage_bytes: Option<u64>,
    initial_fuel: u64,
    memory_limit_mb: Option<u64>,
) -> SandboxMetrics {
    let mut metrics = SandboxMetrics::default();

    if let Ok(remaining_fuel) = store.get_fuel() {
        metrics.wasm_fuel_consumed = Some(initial_fuel.saturating_sub(remaining_fuel));
    }
    metrics.memory_usage_bytes = memory_usage_bytes;
    if let Some(limit_mb) = memory_limit_mb {
        metrics.memory_limit_bytes = limit_mb.checked_mul(BYTES_PER_MIB);
    }
    metrics.collected_at = Some(std::time::Instant::now());
    metrics
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
/// Used only as an index into the cache map. The content hash is still verified before loading
/// a cached module so same-size/same-mtime collisions cannot select the wrong cache entry.
fn file_fingerprint(meta: &Metadata) -> Option<(u64, u64)> {
    let size = meta.len();
    let mtime = metadata_mtime_nanos(meta)?;
    Some((size, mtime))
}

fn open_and_validate_wasm_file(wasm_path: &Path) -> Result<(Metadata, Vec<u8>), SandboxError> {
    let mut file = std::fs::File::open(wasm_path)
        .map_err(|_| SandboxError::new("Wasm file does not exist"))?;
    let wasm_meta = file
        .metadata()
        .map_err(|e| SandboxError::new(format!("Failed to stat Wasm file: {}", e)))?;

    if !wasm_meta.file_type().is_file() {
        return Err(SandboxError::new("Wasm path is not a regular file"));
    }
    if wasm_meta.nlink() > 1 {
        return Err(SandboxError::new(
            "Wasm file must not be a hard link (nlink > 1)",
        ));
    }
    if wasm_meta.len() > MAX_WASM_FILE_SIZE {
        return Err(SandboxError::new(format!(
            "Wasm file too large: {} bytes (limit {} bytes)",
            wasm_meta.len(),
            MAX_WASM_FILE_SIZE
        )));
    }

    let mut file_data = Vec::with_capacity(wasm_meta.len() as usize);
    let mut bounded_reader = (&mut file).take(MAX_WASM_FILE_SIZE + 1);
    bounded_reader
        .read_to_end(&mut file_data)
        .map_err(|e| SandboxError::new(format!("Failed to read Wasm file: {}", e)))?;
    if file_data.len() as u64 > MAX_WASM_FILE_SIZE {
        return Err(SandboxError::new(format!(
            "Wasm file too large: {} bytes (limit {} bytes)",
            file_data.len(),
            MAX_WASM_FILE_SIZE
        )));
    }

    Ok((wasm_meta, file_data))
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

    validate_cache_file_metadata(path, &meta)
}

/// Validates cache file metadata security properties (owner, mode, and file type).
///
/// Extracted from `validate_cache_file_security` so callers that already hold a file handle can reuse it,
/// avoiding an extra path-based stat inside the flock-protected section.
fn validate_cache_file_metadata(path: &Path, meta: &Metadata) -> bool {
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

/// Validates security properties for an already-opened cache file handle (owner, mode, and file type).
///
/// Uses the file handle's own metadata() instead of a path-based stat to ensure the validated object
/// is the same inode protected by flock, eliminating TOCTOU.
fn validate_open_cache_file_security(path: &Path, file: &File) -> bool {
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(e) => {
            warn!("Failed to stat opened cache file {:?}: {}", path, e);
            return false;
        }
    };

    validate_cache_file_metadata(path, &meta)
}

/// Acquires a flock shared lock (LOCK_SH) on an already-opened cache file descriptor.
///
/// The shared lock allows concurrent readers but blocks exclusive locks (LOCK_EX), preventing
/// concurrent writers from replacing file contents during cache validation and deserialization.
///
/// The kernel releases the lock automatically when the file is dropped.
#[cfg(unix)]
fn acquire_shared_lock(file: &File) -> Result<(), SandboxError> {
    loop {
        // SAFETY: flock(LOCK_SH) 仅对有效文件描述符获取共享咨询锁。
        // 这是安全的，因为：
        // - file 由 std::fs::File 成功打开并借用，as_raw_fd() 返回的 fd 在调用期间有效；
        // - LOCK_SH 只申请共享读锁，可与其他共享读锁共存，本函数不持有其他锁，不引入锁顺序死锁；
        // - flock 锁与 fd 生命周期绑定，file 关闭或 drop 时会由内核自动释放；
        // - 锁定期间完成缓存文件校验与读取，避免协作写入方在校验和读取之间修改同一缓存文件。
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
        if ret == 0 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            // EINTR: 被信号中断，重试
            continue;
        }

        return Err(SandboxError::new(format!(
            "Failed to acquire shared lock on cache file: {}",
            err
        )));
    }
}

/// Opens a cache file for secure reads using O_NOFOLLOW to prevent symlink traversal and acquiring a flock shared lock.
///
/// The returned file handle holds the shared lock throughout reading and validation; dropping it releases the lock.
fn open_cache_file_for_secure_read(path: &Path) -> Result<File, SandboxError> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let file = options
        .open(path)
        .map_err(|e| SandboxError::new(format!("Failed to open cache file {:?}: {}", path, e)))?;

    #[cfg(unix)]
    acquire_shared_lock(&file)?;

    Ok(file)
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

/// Gets mtime from an already-opened file handle, avoiding an extra path-based stat.
fn opened_cache_file_mtime(file: &File) -> Option<u64> {
    let meta = file.metadata().ok()?;
    metadata_mtime_nanos(&meta)
}

#[derive(Debug)]
struct CacheRecord {
    source_hash: String,
    cache_hash: String,
    mtime_nanos: u64,
}

fn is_sha256_hex(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_cache_record(contents: &str) -> Option<CacheRecord> {
    let mut parts = contents.trim().split(':');
    let source_hash = parts.next()?;
    let cache_hash = parts.next()?;
    let mtime_nanos = parts.next()?;
    if parts.next().is_some() || !is_sha256_hex(source_hash) || !is_sha256_hex(cache_hash) {
        return None;
    }

    Some(CacheRecord {
        source_hash: source_hash.to_string(),
        cache_hash: cache_hash.to_string(),
        mtime_nanos: mtime_nanos.parse().ok()?,
    })
}

fn read_cache_record(path: &Path) -> Option<CacheRecord> {
    if !validate_cache_file_security(path) {
        remove_file_if_exists(path);
        return None;
    }

    // 打开文件并获取 flock(LOCK_SH)，在读取和校验期间持有共享锁，
    // 防止并发写入方在校验和读取之间替换文件内容（TOCTOU 竞态）。
    let mut file = match open_cache_file_for_secure_read(path) {
        Ok(file) => file,
        Err(e) => {
            warn!(
                "Failed to open cache record for secure read {:?}: {}",
                path, e
            );
            remove_file_if_exists(path);
            return None;
        }
    };

    // 使用 fd-based metadata 校验，确保校验对象与 flock 保护的是同一个 inode
    if !validate_open_cache_file_security(path, &file) {
        remove_file_if_exists(path);
        return None;
    }

    let mut contents = String::new();
    if let Err(e) = file.read_to_string(&mut contents) {
        warn!("Failed to read cache record {:?}: {}", path, e);
        remove_file_if_exists(path);
        return None;
    }

    // file drop 时自动释放 flock 共享锁

    match parse_cache_record(&contents) {
        Some(record) => Some(record),
        None => {
            warn!("Invalid cache record format: {:?}", path);
            remove_file_if_exists(path);
            None
        }
    }
}

fn source_cache_record_path(cache_dir: &Path, source_hash: &str) -> PathBuf {
    cache_dir.join(format!("{}.wasm.meta", source_hash))
}

fn expected_cache_hash_from_path(path: &Path) -> Option<&str> {
    if path.extension()?.to_str()? != "cwasm" {
        return None;
    }

    let hash = path.file_stem()?.to_str()?;
    is_sha256_hex(hash).then_some(hash)
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

fn write_cache_record(path: &Path, source_hash: &str, cache_hash: &str, cache_mtime_nanos: u64) {
    let record = format!("{}:{}:{}", source_hash, cache_hash, cache_mtime_nanos);
    if let Err(e) = write_private_file_atomic(path, record.as_bytes()) {
        warn!("Failed to write cache record {:?}: {}", path, e);
    }
}

fn read_secure_cache_file(path: &Path, expected_mtime_nanos: u64) -> Option<Vec<u8>> {
    let expected_hash = match expected_cache_hash_from_path(path) {
        Some(hash) => hash,
        None => {
            warn!("Invalid cache file name, missing SHA256 hash: {:?}", path);
            remove_file_if_exists(path);
            return None;
        }
    };

    if !validate_cache_file_security(path) {
        remove_file_if_exists(path);
        return None;
    }

    // 打开文件并获取 flock(LOCK_SH)，在校验和读取期间持有共享锁，
    // 防止并发写入方在校验和读取之间替换文件内容（TOCTOU 竞态）。
    // O_NOFOLLOW 防止符号链接跟随，flock 确保文件在校验期间不被替换。
    let mut file = match open_cache_file_for_secure_read(path) {
        Ok(file) => file,
        Err(e) => {
            warn!(
                "Failed to open cache file for secure read {:?}: {}",
                path, e
            );
            remove_file_if_exists(path);
            return None;
        }
    };

    // 使用 fd-based metadata 校验，确保校验对象与 flock 保护的是同一个 inode
    if !validate_open_cache_file_security(path, &file) {
        remove_file_if_exists(path);
        return None;
    }

    let current_mtime = match opened_cache_file_mtime(&file) {
        Some(mtime) => mtime,
        None => {
            warn!("Failed to read cache file mtime: {:?}", path);
            remove_file_if_exists(path);
            return None;
        }
    };
    if current_mtime != expected_mtime_nanos {
        warn!(
            "Cache file mtime mismatch, treating as stale: path={:?}, expected={}, actual={}",
            path, expected_mtime_nanos, current_mtime
        );
        remove_file_if_exists(path);
        return None;
    }

    let mut cached = Vec::new();
    if let Err(e) = file.read_to_end(&mut cached) {
        warn!("Failed to read cache file {:?}: {}", path, e);
        remove_file_if_exists(path);
        return None;
    }

    // file drop 时自动释放 flock 共享锁

    let actual_hash = content_hash(&cached);
    if actual_hash != expected_hash {
        warn!(
            "Cache file content hash mismatch: path={:?}, expected={}, actual={}",
            path, expected_hash, actual_hash
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
    // 读取缓存字节后会校验其 SHA256 必须与缓存文件名中的 hash 一致；
    // mtime 只用于跳过明显过期的记录，不作为安全依据。
    // 因此传入 bytes 只来自本程序在同一缓存命名空间中此前 Module::serialize() 写入的受控缓存。
    match unsafe { Module::deserialize(engine, &cached) } {
        Ok(module) => {
            info!("Loaded module from cache ({}): {:?}", label, wasm_path);
            Some(module)
        }
        Err(e) => {
            warn!("Cache deserialization failed, recompiling: {}", e);
            remove_file_if_exists(cache_path);
            if let Some(record_path) = record_path {
                remove_file_if_exists(record_path);
            }
            None
        }
    }
}

fn compile_module_from_bytes(
    engine: &Engine,
    wasm_path: &Path,
    bytes: &[u8],
) -> Result<Module, SandboxError> {
    // SECURITY: 调用方在读取字节后立刻使用同一份不可变切片编译，
    // 避免“先读取算哈希、再按路径重新打开编译”的 TOCTOU 竞态。
    Module::from_binary(engine, bytes).map_err(|e| {
        let message = format!("Failed to load Wasm module ({:?}): {}", wasm_path, e);
        let kind = if message.to_lowercase().contains("fuel") {
            ExecutionFailureKind::CpuLimit
        } else {
            ExecutionFailureKind::Unknown
        };
        SandboxError::ExecutionFailed { kind, message }
    })
}

fn ensure_compile_timeout_not_exceeded(
    compile_start: Instant,
    wasm_path: &Path,
) -> Result<(), SandboxError> {
    let elapsed = compile_start.elapsed();
    if elapsed <= Duration::from_secs(COMPILE_TIMEOUT_SECS) {
        return Ok(());
    }

    Err(SandboxError::ExecutionFailed {
        kind: ExecutionFailureKind::CpuLimit,
        message: format!(
            "Wasm module compile/load exceeded {COMPILE_TIMEOUT_SECS}s wall-clock timeout: path={wasm_path:?}, elapsed_ms={}",
            elapsed.as_millis()
        ),
    })
}

/// Gets or compiles a module with a disk cache.
///
/// Uses a hybrid cache strategy:
/// 1. First looks up the cache mapping file using the lightweight metadata fingerprint (size plus modification time).
/// 2. When the cache mapping hits, verifies the already-read bytes match the source SHA256 key.
/// 3. Reads cached serialized bytes only after validating their SHA256 against the cache filename.
/// 4. When the cache mapping misses, calculates the file content SHA256 and updates the cache.
///
/// The caller provides bytes read from the same fd used for validation, avoiding path-based TOCTOU.
fn get_cached_module(
    engine: &Engine,
    wasm_path: &Path,
    wasm_meta: &Metadata,
    file_data: &[u8],
    cache_dir: Option<&Path>,
) -> Result<Module, SandboxError> {
    let cache_dir = match cache_dir {
        Some(cache_dir) if ensure_cache_dir_security(cache_dir) => cache_dir,
        Some(cache_dir) => {
            warn!(
                "Wasm cache directory is insecure; compiling without disk cache: {:?}",
                cache_dir
            );
            return compile_module_from_bytes(engine, wasm_path, file_data);
        }
        None => return compile_module_from_bytes(engine, wasm_path, file_data),
    };

    let fingerprint = match file_fingerprint(wasm_meta) {
        Some(fp) => fp,
        None => return compile_module_from_bytes(engine, wasm_path, file_data),
    };

    // 缓存映射文件：记录 "fingerprint -> source_hash:cache_hash:cache_mtime_nanos" 的映射
    // 文件名格式: {size}_{mtime_nanos}.map
    let map_file = cache_dir.join(format!("{}_{}.map", fingerprint.0, fingerprint.1));

    let source_hash = content_hash(file_data);

    // 尝试通过映射文件找到对应的缓存
    if let Some(record) = read_cache_record(&map_file) {
        if record.source_hash == source_hash {
            let cache_path = cache_dir.join(format!("{}.cwasm", record.cache_hash));
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
        } else {
            warn!(
                "Cache fingerprint hash mismatch: path={:?}, expected={}, actual={}",
                map_file, source_hash, record.source_hash
            );
            remove_file_if_exists(&map_file);
        }
    }

    // 缓存未命中：复用已读取内容的 SHA256。
    let source_record_file = source_cache_record_path(cache_dir, &source_hash);

    // 检查是否已有相同内容的缓存（文件内容相同但元数据不同）
    if let Some(record) = read_cache_record(&source_record_file) {
        if record.source_hash == source_hash {
            let cache_path = cache_dir.join(format!("{}.cwasm", record.cache_hash));
            if let Some(module) = load_cached_module(
                engine,
                wasm_path,
                &cache_path,
                record.mtime_nanos,
                Some(&source_record_file),
                "content match",
            ) {
                write_cache_record(
                    &map_file,
                    &source_hash,
                    &record.cache_hash,
                    record.mtime_nanos,
                );
                return Ok(module);
            }
        } else {
            warn!(
                "Cache metadata hash mismatch: path={:?}, expected={}, actual={}",
                source_record_file, source_hash, record.source_hash
            );
            remove_file_if_exists(&source_record_file);
        }
    }

    // 编译模块
    let module = compile_module_from_bytes(engine, wasm_path, file_data)?;

    // 序列化到缓存目录（原子写入：先写临时文件再 rename，避免并发读到不完整数据）
    if let Ok(serialized) = module.serialize() {
        let cache_hash = content_hash(&serialized);
        let cache_path = cache_dir.join(format!("{}.cwasm", cache_hash));

        match write_private_file_atomic(&cache_path, &serialized) {
            Ok(()) => {
                if let Some(cache_mtime_nanos) = cache_file_mtime(&cache_path) {
                    write_cache_record(&map_file, &source_hash, &cache_hash, cache_mtime_nanos);
                    write_cache_record(
                        &source_record_file,
                        &source_hash,
                        &cache_hash,
                        cache_mtime_nanos,
                    );
                } else {
                    warn!("Failed to record cache file mtime: {:?}", cache_path);
                    remove_file_if_exists(&cache_path);
                    remove_file_if_exists(&source_record_file);
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
        .map_err(|e| SandboxError::new(e.clone()))
}

/// Checks whether a path is an ancestor or descendant of the cache directory using canonicalize-based bidirectional checks.
///
/// Uses canonicalize() to resolve symlinks and .. path components, preventing attackers from
/// pointing a preopen path to an ancestor of the cache directory through symlinks.
///
/// Security model: the guest must not receive any preopen covering the cache directory,
/// read-only or read-write, because Module::deserialize is unsafe and requires trusted cache files.
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

/// Conservative fallback for nonexistent paths: lexical prefix checks.
///
/// When a path does not exist and cannot be canonicalized, falls back to checking lexical prefix relationships.
/// This conservative strategy avoids accidentally exposing the cache directory before paths are created.
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
) -> Result<WasiP1Ctx, SandboxError> {
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

    // 注入用户配置的持久环境变量（优先级高于内置最小环境）
    // 防御性校验：跳过无效 key/value（完整校验由 SDK Config::validate 完成）
    for (key, value) in &config.env_vars {
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            warn!(
                "Skipping invalid env var: key={:?}, value={:?} (empty key, contains '=' or NUL)",
                key, value
            );
            continue;
        }
        builder.env(key, value);
    }

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
        return Err(SandboxError::new(
            "Wasm backend does not support network access. Tip: use 'os' or 'microvm' isolation for network support, or set NetworkPolicy::DenyAll",
        ));
    }

    // 时钟能力：WasiCtxBuilder 仅暴露 wall_clock/monotonic_clock 替换点，
    // 没有 WASI Preview 1 clocks 的禁用/白名单 API；执行时限由 fuel、epoch 和 timeout 控制。

    Ok(builder.build_p1())
}

impl Sandbox for WasmSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        config.validate()?;

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
            cached_metrics: None,
        })
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        let start = Instant::now();
        self.cached_metrics = None;

        if cmd.is_empty() {
            return Err(SandboxError::new("Command is empty"));
        }

        let wasm_path = Path::new(&cmd[0]);
        let (wasm_meta, file_data) = open_and_validate_wasm_file(wasm_path)?;

        // 1. 获取或编译模块（带缓存）。编译阶段不受 Wasm fuel/epoch 约束，
        // 因此单独用墙钟时间做 fail-closed 检查。
        let compile_start = Instant::now();
        let module = get_cached_module(
            &self.engine,
            wasm_path,
            &wasm_meta,
            &file_data,
            self.cache_dir.as_deref(),
        )?;
        ensure_compile_timeout_not_exceeded(compile_start, wasm_path)?;

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
        )?;

        // 4. 创建 Linker 并注册 WASI Preview 1
        // 注意：Linker 的类型参数必须与 Store data type 一致
        let mut linker: Linker<StoreData> = Linker::new(&self.engine);
        p1::add_to_linker_sync(&mut linker, |data| &mut data.wasi)
            .map_err(|e| SandboxError::new(format!("Failed to register WASI Preview 1: {}", e)))?;

        // 5. [FATAL-01 修复] 创建带资源限制的 Store
        // 将 memory_limit_mb 通过 StoreLimitsBuilder 实际应用到 Wasm 运行时
        let memory_limit_bytes = memory_limit_bytes(self.config.memory_limit_mb)?;

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
        let fuel_limit = fuel_from_timeout(self.config.timeout_secs)?;
        store
            .set_fuel(fuel_limit)
            .map_err(|e| SandboxError::new(format!("Failed to set fuel: {}", e)))?;

        // 7. [IMPORTANT-01 补充] 设置 epoch deadline 实现墙钟超时
        // epoch_interruption 可中断包括 WASI I/O 阻塞在内的执行，
        // 弥补 fuel 仅在纯 Wasm 指令执行时消耗的不足。
        store.epoch_deadline_trap();
        let epoch_deadline_ticks = epoch_deadline_ticks_from_timeout(self.config.timeout_secs)?;
        store.set_epoch_deadline(epoch_deadline_ticks);

        // 8. 实例化模块
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::new(format!("Failed to instantiate Wasm module: {}", e)))?;

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
                            self.cache_wasm_metrics(&instance, &mut store, fuel_limit);
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
                            warn!("Wasm memory limit exceeded (OOM)");
                            self.cache_wasm_metrics(&instance, &mut store, fuel_limit);
                            return Err(SandboxError::ExecutionFailed {
                                kind: ExecutionFailureKind::Oom,
                                message: "wasm memory limit exceeded".into(),
                            });
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
                            } else if is_fuel_exhausted(&store) || is_epoch_interrupt(&e) {
                                warn!(
                                    "Execution timed out (fuel exhausted or epoch deadline exceeded)"
                                );
                                self.cache_wasm_metrics(&instance, &mut store, fuel_limit);
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
                                warn!("Wasm memory limit exceeded (OOM)");
                                self.cache_wasm_metrics(&instance, &mut store, fuel_limit);
                                return Err(SandboxError::ExecutionFailed {
                                    kind: ExecutionFailureKind::Oom,
                                    message: "wasm memory limit exceeded".into(),
                                });
                            } else {
                                warn!("main function execution failed: {}", e);
                                None
                            }
                        }
                    },
                    Err(_) => {
                        return Err(SandboxError::new(
                            "Wasm module has no _start or main export function",
                        ));
                    }
                }
            }
        };

        self.cache_wasm_metrics(&instance, &mut store, fuel_limit);
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
    use mimobox_core::{MAX_MEMORY_LIMIT_MB, Sandbox};
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
    fn test_build_wasi_ctx_rejects_network_access() {
        let mut config = test_config();
        config.deny_network = false;
        let args = vec!["module.wasm".to_string()];

        let err = match build_wasi_ctx(
            &config,
            &args,
            None,
            MemoryOutputPipe::new(OUTPUT_MAX_CAPACITY),
            MemoryOutputPipe::new(OUTPUT_MAX_CAPACITY),
        ) {
            Ok(_) => panic!("Wasm backend 不支持网络访问时必须返回错误"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("Wasm backend does not support network access"),
            "错误信息必须明确说明 Wasm 后端不支持网络访问: {err}"
        );
    }

    #[test]
    fn test_wasm_sandbox_new_rejects_memory_limit_above_max() {
        let mut config = test_config();
        config.memory_limit_mb = Some(MAX_MEMORY_LIMIT_MB + 1);

        let err = match WasmSandbox::new(config) {
            Ok(_) => panic!("memory_limit_mb 超过最大值时必须拒绝创建 Wasm sandbox"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("memory_limit_mb"),
            "错误信息必须指向 memory_limit_mb: {err}"
        );
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
    fn test_memory_limit_bytes_rejects_overflow() {
        let err =
            memory_limit_bytes(Some(u64::MAX)).expect_err("memory_limit_mb 溢出时必须返回错误");

        assert!(
            err.to_string().contains("memory_limit_mb"),
            "错误信息必须指向 memory_limit_mb: {err}"
        );
    }

    #[test]
    fn test_fuel_from_timeout_rejects_overflow() {
        let err =
            fuel_from_timeout(Some(u64::MAX)).expect_err("timeout_secs 转 fuel 溢出时必须返回错误");

        assert!(
            err.to_string().contains("fuel"),
            "错误信息必须指向 fuel: {err}"
        );
    }

    #[test]
    fn test_epoch_deadline_ticks_from_timeout_rejects_overflow() {
        let err = epoch_deadline_ticks_from_timeout(Some(u64::MAX))
            .expect_err("timeout_secs 转 epoch ticks 溢出时必须返回错误");

        assert!(
            err.to_string().contains("epoch"),
            "错误信息必须指向 epoch ticks: {err}"
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
    fn test_read_secure_cache_file_accepts_matching_content_hash() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let cached = b"serialized module bytes";
        let cache_hash = content_hash(cached);
        let cache_path = temp_dir.path().join(format!("{}.cwasm", cache_hash));

        write_private_file_atomic(&cache_path, cached).expect("Failed to write cache file");
        let cache_mtime = cache_file_mtime(&cache_path).expect("Failed to read cache mtime");

        assert_eq!(
            read_secure_cache_file(&cache_path, cache_mtime),
            Some(cached.to_vec())
        );
    }

    #[test]
    fn test_read_secure_cache_file_rejects_content_hash_mismatch() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let expected_hash = content_hash(b"trusted serialized module bytes");
        let cache_path = temp_dir.path().join(format!("{}.cwasm", expected_hash));

        write_private_file_atomic(&cache_path, b"tampered bytes")
            .expect("Failed to write cache file");
        let cache_mtime = cache_file_mtime(&cache_path).expect("Failed to read cache mtime");

        assert_eq!(read_secure_cache_file(&cache_path, cache_mtime), None);
        assert!(!cache_path.exists(), "hash 不匹配的缓存文件必须被删除");
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
