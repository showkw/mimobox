//! mimobox-sdk: Unified Agent Sandbox API
//!
//! **Smart routing by default, full control for advanced users.**
//!
//! Zero-config sandbox creation with automatic backend selection, plus
//! complete configuration control via [`Config::builder()`].
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use mimobox_sdk::Sandbox;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut sandbox = Sandbox::new()?;
//! let result = sandbox.execute("/bin/echo hello")?;
//! println!("exit: {:?}", result.exit_code);
//! sandbox.destroy()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature Gates
//!
//! | Feature | Backend | Default |
//! |---------|---------|---------|
//! | `os`    | OS-level (Linux/macOS) | Yes |
//! | `vm`    | microVM (Linux + KVM) | No |
//! | `wasm`  | Wasm (Wasmtime) | No |
//!
//! # Key Types
//!
//! - [`Sandbox`] — Primary entry point for all sandbox operations
//! - [`Config`] / [`ConfigBuilder`] — SDK configuration with builder pattern
//! - [`ExecuteResult`] — Command execution result (stdout, stderr, exit code, timing)
//! - [`StreamEvent`] — Streaming output event enum
//! - [`SdkError`] / [`ErrorCode`] — Structured error model
//! - [`SandboxSnapshot`] — Opaque snapshot handle
//! - [`PtySession`] — Interactive terminal session

mod config;
mod error;
mod router;

pub use config::{Config, ConfigBuilder, IsolationLevel, NetworkPolicy, TrustLevel};
pub use error::SdkError;
pub use mimobox_core::{ErrorCode, PtyConfig, PtyEvent, PtySize};

use mimobox_core::{Sandbox as CoreSandbox, SandboxResult};
use router::resolve_isolation;
#[cfg(feature = "vm")]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
#[cfg(feature = "vm")]
use std::sync::Arc;
use std::sync::mpsc;
#[cfg(feature = "vm")]
use std::time::Duration;
use tracing::warn;

/// Result of a sandbox command execution.
///
/// Contains raw stdout/stderr bytes, exit code, timeout flag, and wall-clock elapsed time.
/// Use `String::from_utf8_lossy()` to convert stdout/stderr to text.
///
/// # Examples
///
/// ```rust,no_run
/// use mimobox_sdk::Sandbox;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sandbox = Sandbox::new()?;
/// let result = sandbox.execute("/bin/echo hello")?;
/// println!("exit: {:?}", result.exit_code);
/// println!("stdout: {}", String::from_utf8_lossy(&result.stdout));
/// println!("elapsed: {:?}", result.elapsed);
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
pub struct ExecuteResult {
    /// 标准输出字节流。
    pub stdout: Vec<u8>,
    /// 标准错误字节流。
    pub stderr: Vec<u8>,
    /// 退出码；若进程未正常退出则可能为 `None`。
    pub exit_code: Option<i32>,
    /// 是否因超时被终止。
    pub timed_out: bool,
    /// 本次执行的总耗时。
    pub elapsed: std::time::Duration,
}

impl ExecuteResult {
    /// 构造一个新的执行结果。
    ///
    /// 由于 `ExecuteResult` 标记为 `#[non_exhaustive]`，外部 crate 无法使用结构体字面量构造。
    /// 此方法提供了稳定的构造路径。
    pub fn new(
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_code: Option<i32>,
        timed_out: bool,
        elapsed: std::time::Duration,
    ) -> Self {
        Self {
            stdout,
            stderr,
            exit_code,
            timed_out,
            elapsed,
        }
    }
}

/// HTTP response from the controlled host-side proxy.
///
/// Returned by [`Sandbox::http_request()`]. Only available with the `vm` feature on Linux.
///
/// # Examples
///
/// ```text
/// // Requires `vm` feature + Linux
/// use mimobox_sdk::{Config, IsolationLevel, Sandbox};
/// use std::collections::HashMap;
///
/// let config = Config::builder()
///     .isolation(IsolationLevel::MicroVm)
///     .allowed_http_domains(["example.com"])
///     .build();
/// let mut sandbox = Sandbox::with_config(config)?;
/// let resp = sandbox.http_request("GET", "https://example.com", HashMap::new(), None)?;
/// println!("status: {}", resp.status);
/// ```
#[non_exhaustive]
pub struct HttpResponse {
    /// HTTP 状态码。
    pub status: u16,
    /// 归一化后的响应头集合。
    pub headers: std::collections::HashMap<String, String>,
    /// 响应体字节流。
    pub body: Vec<u8>,
}

/// Opaque handle to a sandbox memory snapshot.
///
/// Supports both in-memory bytes and file-backed storage modes.
/// Create via [`Sandbox::snapshot()`] or restore from bytes/file.
///
/// # Examples
///
/// ```rust,no_run
/// use mimobox_sdk::{Config, IsolationLevel, Sandbox};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::builder()
///     .isolation(IsolationLevel::MicroVm)
///     .build();
/// let mut sandbox = Sandbox::with_config(config)?;
/// let snapshot = sandbox.snapshot()?;
/// println!("snapshot size: {} bytes", snapshot.size());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSnapshot {
    inner: mimobox_core::SandboxSnapshot,
}

impl SandboxSnapshot {
    /// 从原始字节恢复快照。
    pub fn from_bytes(data: &[u8]) -> Result<Self, SdkError> {
        mimobox_core::SandboxSnapshot::from_bytes(data)
            .map(Self::from_core)
            .map_err(map_snapshot_bytes_error)
    }

    /// 从文件化快照的 `memory.bin` 创建快照。
    pub fn from_file(path: PathBuf) -> Result<Self, SdkError> {
        mimobox_core::SandboxSnapshot::from_file(path)
            .map(Self::from_core)
            .map_err(map_snapshot_bytes_error)
    }

    /// 返回文件模式快照对应的 memory 文件路径。
    pub fn memory_file_path(&self) -> Option<&Path> {
        self.inner.memory_file_path()
    }

    /// 返回快照字节切片，避免额外拷贝。
    ///
    /// 仅内存模式支持该操作；文件模式会返回错误。
    pub fn as_bytes(&self) -> Result<&[u8], SdkError> {
        self.inner.as_bytes().map_err(map_snapshot_bytes_error)
    }

    /// 返回快照字节副本。
    ///
    /// 文件模式下会重建完整的自描述快照字节。
    pub fn to_bytes(&self) -> Result<Vec<u8>, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        if let Some(memory_path) = self.inner.memory_file_path() {
            return mimobox_vm::MicrovmSnapshot::from_memory_file(memory_path)
                .and_then(|snapshot| snapshot.snapshot())
                .map_err(map_microvm_error);
        }

        self.inner.to_bytes().map_err(map_snapshot_bytes_error)
    }

    /// 消费快照并返回底层字节，避免额外拷贝。
    ///
    /// 文件模式下会重建完整的自描述快照字节。
    pub fn into_bytes(self) -> Result<Vec<u8>, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        if let Some(memory_path) = self.inner.memory_file_path().map(Path::to_path_buf) {
            return mimobox_vm::MicrovmSnapshot::from_memory_file(&memory_path)
                .and_then(|snapshot| snapshot.snapshot())
                .map_err(map_microvm_error);
        }

        self.inner.into_bytes().map_err(map_snapshot_bytes_error)
    }

    /// 返回快照大小（字节）。
    pub fn size(&self) -> usize {
        self.inner.size()
    }

    fn from_core(inner: mimobox_core::SandboxSnapshot) -> Self {
        Self { inner }
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
#[derive(Debug, Clone)]
/// Configuration for creating a snapshot-based restore pool.
///
/// Requires `vm` feature + Linux.
pub struct RestorePoolConfig {
    /// 恢复池目标大小。
    pub pool_size: usize,
    /// 恢复池使用的基础配置。
    pub base_config: Config,
}

#[cfg(all(feature = "vm", target_os = "linux"))]
#[derive(Clone)]
/// Snapshot-based restore pool for sub-millisecond VM restore-to-ready latency.
///
/// Pre-creates a pool of empty microVM shells. When a sandbox is needed,
/// a snapshot is restored into one of the pre-warmed shells, avoiding
/// the full VM boot sequence.
///
/// Requires `vm` feature + Linux.
pub struct RestorePool {
    inner: Arc<mimobox_vm::RestorePool>,
}

impl From<SandboxResult> for ExecuteResult {
    fn from(r: SandboxResult) -> Self {
        Self {
            stdout: r.stdout,
            stderr: r.stderr,
            exit_code: r.exit_code,
            timed_out: r.timed_out,
            elapsed: r.elapsed,
        }
    }
}

#[cfg(feature = "vm")]
impl From<mimobox_vm::HttpResponse> for HttpResponse {
    fn from(value: mimobox_vm::HttpResponse) -> Self {
        Self {
            status: value.status,
            headers: value.headers,
            body: value.body,
        }
    }
}

/// Streaming output event from [`Sandbox::stream_execute()`].
///
/// Events are delivered via a `std::sync::mpsc::Receiver`. `Exit` or `TimedOut`
/// is always the last event in the stream.
///
/// Requires `vm` feature + Linux.
///
/// # Examples
///
/// ```text
/// // Requires `vm` feature + Linux
/// use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};
///
/// let config = Config::builder()
///     .isolation(IsolationLevel::MicroVm)
///     .build();
/// let mut sandbox = Sandbox::with_config(config)?;
/// let rx = sandbox.stream_execute("/bin/echo hello")?;
/// for event in rx.iter() {
///     match event {
///         StreamEvent::Stdout(data) => print!("{}", String::from_utf8_lossy(&data)),
///         StreamEvent::Stderr(data) => eprint!("{}", String::from_utf8_lossy(&data)),
///         StreamEvent::Exit(code) => println!("exit = {code}"),
///         StreamEvent::TimedOut => println!("timed out"),
///     }
/// }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// 一段标准输出数据。
    Stdout(Vec<u8>),
    /// 一段标准错误数据。
    Stderr(Vec<u8>),
    /// 进程退出并携带退出码。
    Exit(i32),
    /// 执行因超时被终止。
    TimedOut,
}

/// Interactive PTY terminal session.
///
/// Wraps a backend-provided terminal handle with a unified interface for
/// input, resize, output events, and lifecycle control.
///
/// Currently supported on OS-level backends only (not microVM).
///
/// # Examples
///
/// ```rust,no_run
/// use mimobox_sdk::Sandbox;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sandbox = Sandbox::new()?;
/// let mut pty = sandbox.create_pty("/bin/sh")?;
/// pty.send_input(b"echo hello\n")?;
/// let exit_code = pty.wait()?;
/// println!("exited with {exit_code}");
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
pub struct PtySession {
    inner: Box<dyn mimobox_core::PtySession>,
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession").finish_non_exhaustive()
    }
}

impl PtySession {
    /// 向 PTY 会话写入输入数据。
    pub fn send_input(&mut self, data: &[u8]) -> Result<(), SdkError> {
        self.inner.send_input(data).map_err(map_pty_session_error)
    }

    /// 调整 PTY 终端尺寸。
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), SdkError> {
        self.inner
            .resize(PtySize { cols, rows })
            .map_err(map_pty_session_error)
    }

    /// 返回 PTY 输出事件接收端。
    pub fn output(&self) -> &mpsc::Receiver<PtyEvent> {
        self.inner.output_rx()
    }

    /// 强制结束 PTY 会话。
    pub fn kill(&mut self) -> Result<(), SdkError> {
        self.inner.kill().map_err(map_pty_session_error)
    }

    /// 等待 PTY 进程退出并返回退出码。
    pub fn wait(&mut self) -> Result<i32, SdkError> {
        self.inner.wait().map_err(map_pty_session_error)
    }
}

trait ExecuteForSdk {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError>;
}

#[allow(dead_code)]
trait StreamExecuteForSdk {
    fn stream_execute_for_sdk(
        &mut self,
        args: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError>;
}

#[cfg(all(feature = "vm", target_os = "linux"))]
trait HttpRequestForSdk {
    fn http_request_for_sdk(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError>;
}

// ── ExecuteForSdk: OS/Wasm 后端（使用 CoreSandbox trait） ──

#[cfg(all(feature = "os", target_os = "linux"))]
impl ExecuteForSdk for mimobox_os::LinuxSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

#[cfg(all(feature = "os", target_os = "macos"))]
impl ExecuteForSdk for mimobox_os::MacOsSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

#[cfg(feature = "wasm")]
impl ExecuteForSdk for mimobox_wasm::WasmSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

// ── VM 后端 MicrovmSandbox 的 ExecuteForSdk（走 CoreSandbox trait） ──

#[cfg(all(feature = "vm", target_os = "linux"))]
impl ExecuteForSdk for mimobox_vm::MicrovmSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

// ── VM 池化/恢复类型 trait 实现：宏消除三种类型的重复 ──

/// VM 池化/恢复类型共享的 execute 实现（使用 start.elapsed() 而非后端自带计时）
#[cfg(all(feature = "vm", target_os = "linux"))]
macro_rules! impl_execute_for_sdk_pooled {
    ($ty:ty) => {
        impl ExecuteForSdk for $ty {
            fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
                let start = std::time::Instant::now();
                self.execute(args)
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(map_microvm_error)
            }
        }
    };
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl_execute_for_sdk_pooled!(mimobox_vm::PooledVm);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_execute_for_sdk_pooled!(mimobox_vm::PooledRestoreVm);

/// StreamExecuteForSdk 的 VM 类型共享实现
#[cfg(all(feature = "vm", target_os = "linux"))]
macro_rules! impl_stream_execute_for_sdk {
    ($ty:ty) => {
        impl StreamExecuteForSdk for $ty {
            fn stream_execute_for_sdk(
                &mut self,
                args: &[String],
            ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
                self.stream_execute(args)
                    .map(bridge_vm_stream)
                    .map_err(map_microvm_error)
            }
        }
    };
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl_stream_execute_for_sdk!(mimobox_vm::MicrovmSandbox);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_stream_execute_for_sdk!(mimobox_vm::PooledVm);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_stream_execute_for_sdk!(mimobox_vm::PooledRestoreVm);

/// HttpRequestForSdk 的 VM 类型共享实现
#[cfg(all(feature = "vm", target_os = "linux"))]
macro_rules! impl_http_request_for_sdk {
    ($ty:ty) => {
        impl HttpRequestForSdk for $ty {
            fn http_request_for_sdk(
                &mut self,
                method: &str,
                url: &str,
                headers: std::collections::HashMap<String, String>,
                body: Option<&[u8]>,
            ) -> Result<HttpResponse, SdkError> {
                let request = mimobox_vm::HttpRequest::new(
                    method,
                    url,
                    headers,
                    body.map(|item| item.to_vec()),
                    None,
                    None,
                )
                .map_err(map_http_proxy_error)?;
                self.http_request(request)
                    .map(HttpResponse::from)
                    .map_err(map_microvm_error)
            }
        }
    };
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl_http_request_for_sdk!(mimobox_vm::MicrovmSandbox);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_http_request_for_sdk!(mimobox_vm::PooledVm);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_http_request_for_sdk!(mimobox_vm::PooledRestoreVm);

/// Internal backend instance enum.
///
/// Each variant wraps a specific sandbox backend. The SDK dispatches
/// method calls to the active variant.
enum SandboxInner {
    #[cfg(all(feature = "os", target_os = "linux"))]
    Os(mimobox_os::LinuxSandbox),
    #[cfg(all(feature = "os", target_os = "macos"))]
    OsMac(mimobox_os::MacOsSandbox),
    #[cfg(all(feature = "vm", target_os = "linux"))]
    MicroVm(mimobox_vm::MicrovmSandbox),
    #[cfg(all(feature = "vm", target_os = "linux"))]
    PooledMicroVm(mimobox_vm::PooledVm),
    #[cfg(all(feature = "vm", target_os = "linux"))]
    RestoredPooledMicroVm(mimobox_vm::PooledRestoreVm),
    #[cfg(feature = "wasm")]
    Wasm(mimobox_wasm::WasmSandbox),
}

/// Primary entry point for all sandbox operations.
///
/// Supports zero-config creation with smart routing ([`Sandbox::new()`])
/// and full configuration via [`Sandbox::with_config()`].
///
/// The backend is initialized lazily on the first operation, not at construction time.
/// Subsequent operations reuse the same backend until the isolation level changes.
///
/// # Resource Cleanup
///
/// Call [`destroy()`](Sandbox::destroy) explicitly when done, or rely on the `Drop`
/// implementation which logs warnings on failure.
///
/// # Examples
///
/// ```rust,no_run
/// use mimobox_sdk::Sandbox;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sandbox = Sandbox::new()?;
/// let result = sandbox.execute("/bin/echo hello")?;
/// assert_eq!(result.exit_code, Some(0));
/// sandbox.destroy()?;
/// # Ok(())
/// # }
/// ```
pub struct Sandbox {
    config: Config,
    inner: Option<SandboxInner>,
    active_isolation: Option<IsolationLevel>,
    #[cfg(feature = "vm")]
    vm_pool: Option<Arc<mimobox_vm::VmPool>>,
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl RestorePool {
    /// 根据基础配置创建一个固定大小的恢复池。
    pub fn new(config: RestorePoolConfig) -> Result<Self, SdkError> {
        let sandbox_config = config.base_config.to_sandbox_config();
        let microvm_config = config.base_config.to_microvm_config()?;
        let inner = mimobox_vm::RestorePool::new(
            sandbox_config,
            microvm_config,
            mimobox_vm::RestorePoolConfig {
                min_size: config.pool_size,
                max_size: config.pool_size,
            },
        )
        .map_err(map_restore_pool_error)?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// 使用给定快照恢复一个新的沙箱实例。
    pub fn restore(&self, snapshot: &SandboxSnapshot) -> Result<Sandbox, SdkError> {
        let restored = self
            .inner
            .restore_snapshot(&snapshot.inner)
            .map_err(map_restore_pool_error)?;
        Ok(Sandbox::from_initialized_inner(
            SandboxInner::RestoredPooledMicroVm(restored),
            Config::builder().isolation(IsolationLevel::MicroVm).build(),
        ))
    }

    /// 返回当前恢复池中的空闲实例数量。
    pub fn idle_count(&self) -> usize {
        self.inner.idle_count()
    }

    /// 将恢复池预热到至少 `target` 个空闲实例。
    pub fn warm(&self, target: usize) -> Result<(), SdkError> {
        self.inner.warm(target).map_err(map_restore_pool_error)
    }
}

macro_rules! dispatch_execute {
    ($inner:expr, $binding:ident, $expr:expr) => {
        match $inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os($binding) => $expr,
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm($binding) => $expr,
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm($binding) => $expr,
        }
    };
}

/// VM-only 三变体分派宏（MicroVm / PooledMicroVm / RestoredPooledMicroVm）。
/// 用于 read_file、write_file、http_request、stream_execute、execute_with_vm_options 等
/// 仅 VM 后端支持的方法。非 VM 变体统一走 fallback 表达式。
macro_rules! dispatch_vm {
    ($inner:expr, $binding:ident, $expr:expr, $fallback:expr) => {
        match $inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm($binding) => $expr,
            _ => $fallback,
        }
    };
}

impl Sandbox {
    /// Creates a sandbox with default configuration.
    ///
    /// Smart routing automatically selects the optimal isolation level based on
    /// each command and the default `TrustLevel::SemiTrusted`.
    ///
    /// # Errors
    ///
    /// Returns `SdkError::BackendUnavailable` if no backend feature is enabled.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::Sandbox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let result = sandbox.execute("/bin/echo hello")?;
    /// assert_eq!(result.exit_code, Some(0));
    /// sandbox.destroy()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self, SdkError> {
        Self::with_config(Config::default())
    }

    /// Creates a sandbox with explicit configuration.
    ///
    /// Use [`Config::builder()`] to construct a `Config` with the builder pattern.
    ///
    /// # Errors
    ///
    /// Returns `SdkError::BackendUnavailable` if the configured isolation level
    /// requires a backend feature that is not enabled.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{Config, IsolationLevel, Sandbox};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::builder()
    ///     .isolation(IsolationLevel::Os)
    ///     .timeout(std::time::Duration::from_secs(10))
    ///     .build();
    /// let mut sandbox = Sandbox::with_config(config)?;
    /// # Ok(())
    /// # }
    /// ```
    #[allow(unused_mut)]
    pub fn with_config(config: Config) -> Result<Self, SdkError> {
        let sandbox = Self::new_uninitialized(config);

        #[cfg(feature = "vm")]
        let mut sandbox = sandbox;

        #[cfg(feature = "vm")]
        {
            sandbox.vm_pool = initialize_default_vm_pool(&sandbox.config)?;
        }

        Ok(sandbox)
    }

    /// Creates a sandbox with an explicit microVM warm pool configuration.
    ///
    /// The pool pre-creates VM instances for sub-millisecond acquisition.
    /// Requires `vm` feature.
    ///
    /// # Errors
    ///
    /// Returns `SdkError::Sandbox` if the pool cannot be initialized.
    #[cfg(feature = "vm")]
    pub fn with_pool(
        config: Config,
        pool_config: mimobox_vm::VmPoolConfig,
    ) -> Result<Self, SdkError> {
        let mut sandbox = Self::new_uninitialized(config);
        let sandbox_config = sandbox.config.to_sandbox_config();
        let microvm_config = sandbox.config.to_microvm_config()?;
        let pool = mimobox_vm::VmPool::new_with_base(sandbox_config, microvm_config, pool_config)
            .map_err(map_pool_error)?;
        sandbox.vm_pool = Some(Arc::new(pool));
        Ok(sandbox)
    }

    /// 拍摄当前沙箱快照。
    ///
    /// 该能力当前仅在 `Linux + vm feature + MicroVm` 后端上可用。
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{Config, IsolationLevel, Sandbox};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::builder()
    ///     .isolation(IsolationLevel::MicroVm)
    ///     .build();
    /// let mut sandbox = Sandbox::with_config(config)?;
    /// let snapshot = sandbox.snapshot()?;
    /// assert!(snapshot.size() > 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn snapshot(&mut self) -> Result<SandboxSnapshot, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        {
            self.ensure_backend_for_snapshot()?;
            let inner = self.require_inner()?;

            let snapshot = match inner {
                SandboxInner::MicroVm(sandbox) => sandbox.snapshot().map_err(map_microvm_error)?,
                SandboxInner::PooledMicroVm(sandbox) => {
                    sandbox.snapshot().map_err(map_microvm_error)?
                }
                SandboxInner::RestoredPooledMicroVm(sandbox) => {
                    sandbox.snapshot().map_err(map_microvm_error)?
                }
                _ => {
                    return Err(SdkError::sandbox(
                        ErrorCode::UnsupportedPlatform,
                        "current backend does not support snapshot",
                        Some(
                            "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                                .to_string(),
                        ),
                    ));
                }
            };

            return Ok(SandboxSnapshot::from_core(snapshot));
        }

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        {
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "snapshot not supported in current build",
                Some("use snapshot on Linux with vm feature enabled".to_string()),
            ))
        }
    }

    /// 从快照恢复新沙箱。
    pub fn from_snapshot(snapshot: &SandboxSnapshot) -> Result<Self, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        {
            let sandbox =
                mimobox_vm::MicrovmSandbox::restore(&snapshot.inner).map_err(map_microvm_error)?;
            return Ok(Self::from_initialized_inner(
                SandboxInner::MicroVm(sandbox),
                Config::builder().isolation(IsolationLevel::MicroVm).build(),
            ));
        }

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        {
            let _ = snapshot;
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "snapshot restore not supported in current build",
                Some("use snapshot restore on Linux with vm feature enabled".to_string()),
            ))
        }
    }

    /// 从当前沙箱 fork 一个独立的副本。
    ///
    /// 仅 microVM 后端支持。fork 出的沙箱与原沙箱共享未修改的内存页（CoW），
    /// 写入时各自持有私有副本。
    #[cfg(all(feature = "vm", target_os = "linux"))]
    pub fn fork(&mut self) -> Result<Self, SdkError> {
        self.ensure_backend_for_snapshot()?;
        let inner = self.require_inner()?;

        match inner {
            SandboxInner::MicroVm(sandbox) => {
                let forked = sandbox.fork().map_err(map_microvm_error)?;
                Ok(Self::from_initialized_inner(
                    SandboxInner::MicroVm(forked),
                    self.config.clone(),
                ))
            }
            _ => Err(SdkError::unsupported_backend("fork")),
        }
    }

    /// Fork stub for platforms without microVM support. Always returns `BackendUnavailable`.
    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    pub fn fork(&mut self) -> Result<Self, SdkError> {
        Err(SdkError::unsupported_backend("fork"))
    }

    /// 在沙箱中执行命令。
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::Sandbox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let result = sandbox.execute("/bin/echo hello")?;
    /// assert_eq!(result.exit_code, Some(0));
    /// # Ok(())
    /// # }
    /// ```
    pub fn execute(&mut self, command: &str) -> Result<ExecuteResult, SdkError> {
        let args = parse_command(command)?;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;
        dispatch_execute!(inner, s, s.execute_for_sdk(&args))
    }

    /// 创建交互式终端会话。
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::Sandbox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let mut pty = sandbox.create_pty("/bin/sh")?;
    /// pty.send_input(b"echo hello\n")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_pty(&mut self, command: &str) -> Result<PtySession, SdkError> {
        let args = parse_command(command)?;
        if args.is_empty() {
            return Err(SdkError::Config(
                "PTY command must not be empty".to_string(),
            ));
        }

        self.create_pty_with_config(PtyConfig {
            command: args,
            size: PtySize::default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: self.config.timeout,
        })
    }

    /// 使用完整 `PtyConfig` 创建交互式终端会话。
    pub fn create_pty_with_config(&mut self, config: PtyConfig) -> Result<PtySession, SdkError> {
        if config.command.is_empty() {
            return Err(SdkError::Config(
                "PTY command must not be empty".to_string(),
            ));
        }

        self.ensure_backend_for_pty()?;
        let inner = self.require_inner()?;

        let session = match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(sandbox) => {
                CoreSandbox::create_pty(sandbox, config.clone()).map_err(map_pty_create_error)?
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(sandbox) => {
                CoreSandbox::create_pty(sandbox, config.clone()).map_err(map_pty_create_error)?
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
                CoreSandbox::create_pty(sandbox, config.clone()).map_err(map_pty_create_error)?
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(_) => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "PTY sessions currently only support OS-level backend, microVM pool not supported yet",
                    Some("set isolation to `Os` or use default Auto".to_string()),
                ));
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(_) => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "PTY sessions currently only support OS-level backend, restored microVM pool not supported yet",
                    Some("set isolation to `Os` or use default Auto".to_string()),
                ));
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(sandbox) => {
                CoreSandbox::create_pty(sandbox, config).map_err(map_pty_create_error)?
            }
        };

        Ok(PtySession { inner: session })
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并为本次调用附加环境变量。
    pub fn execute_with_env(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(command, env, None)
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并覆写本次调用的超时时间。
    pub fn execute_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(command, HashMap::new(), Some(timeout))
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并同时覆写环境变量与超时时间。
    pub fn execute_with_env_and_timeout(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(command, env, Some(timeout))
    }

    /// 以流式事件形式执行命令。
    pub fn stream_execute(
        &mut self,
        command: &str,
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        let args = parse_command(command)?;
        let _ = &args;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.stream_execute_for_sdk(&args),
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "streaming execution only supports microVM backend",
                Some(
                    "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                        .to_string()
                ),
            ))
        )
    }

    #[cfg(feature = "vm")]
    /// 从 microVM 沙箱中读取文件内容。
    pub fn read_file(&mut self, _path: &str) -> Result<Vec<u8>, SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.read_file(_path).map_err(map_microvm_error),
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "file transfer only supports microVM backend",
                Some(
                    "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                        .to_string()
                ),
            ))
        )
    }

    #[cfg(feature = "vm")]
    /// 向 microVM 沙箱中写入文件内容。
    pub fn write_file(&mut self, _path: &str, _data: &[u8]) -> Result<(), SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.write_file(_path, _data).map_err(map_microvm_error),
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "file transfer only supports microVM backend",
                Some(
                    "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                        .to_string()
                ),
            ))
        )
    }

    #[cfg(feature = "vm")]
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    /// 通过受控 HTTP 代理发起请求。
    pub fn http_request(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.http_request_for_sdk(method, url, headers, body),
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "HTTP proxy only supports microVM backend",
                Some("set isolation to `MicroVm` and configure allowed_http_domains".to_string()),
            ))
        )
    }

    /// Returns the isolation level of the currently active backend.
    ///
    /// Returns `None` before the first operation triggers backend initialization.
    /// Useful for querying the result of `Auto` routing after the first execute.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{IsolationLevel, Sandbox};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// assert_eq!(sandbox.active_isolation(), None);
    /// sandbox.execute("/bin/echo hello")?;
    /// assert!(sandbox.active_isolation().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn active_isolation(&self) -> Option<IsolationLevel> {
        self.active_isolation
    }

    /// 等待当前沙箱后端进入可用状态。
    ///
    /// microVM 后端会执行 PING/PONG readiness probe；OS/Wasm 后端初始化后直接视为就绪。
    pub fn wait_ready(&mut self, timeout: std::time::Duration) -> Result<(), SdkError> {
        if timeout.is_zero() {
            return Err(SdkError::Config(
                "wait_ready timeout must not be zero".to_string(),
            ));
        }

        let isolation = match self.config.isolation {
            IsolationLevel::Auto => IsolationLevel::Os,
            other => other,
        };
        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            return self.wait_ready_inner(timeout);
        }

        if self.inner.is_some() {
            self.destroy_inner()?;
        }
        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        self.wait_ready_inner(timeout)
    }

    /// 返回当前 SDK 沙箱是否已经初始化为可用后端。
    pub fn is_ready(&self) -> bool {
        let Some(inner) = self.inner.as_ref() else {
            return false;
        };

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => sandbox.is_ready(),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(_) | SandboxInner::RestoredPooledMicroVm(_) => true,
            _ => true,
        }
    }

    /// Destroys the sandbox and releases all resources.
    ///
    /// If not called explicitly, the `Drop` implementation will attempt
    /// cleanup automatically with warnings logged on failure.
    ///
    /// # Errors
    ///
    /// Returns `SdkError` if the backend fails to clean up resources.
    pub fn destroy(mut self) -> Result<(), SdkError> {
        self.destroy_inner()
    }

    // ── 私有辅助方法 ──

    /// 获取已初始化的后端实例引用，若不存在则返回统一错误。
    fn require_inner(&mut self) -> Result<&mut SandboxInner, SdkError> {
        self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "backend instance missing after initialization",
                Some("check if sandbox initialization was interrupted".to_string()),
            )
        })
    }

    fn ensure_backend(&mut self, command: &str) -> Result<(), SdkError> {
        let isolation = resolve_isolation(&self.config, command)?;

        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_inner()?;
        }

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        Ok(())
    }

    fn wait_ready_inner(&mut self, timeout: std::time::Duration) -> Result<(), SdkError> {
        let _ = timeout;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
                sandbox.wait_ready(timeout).map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => {
                sandbox.ping().map(|_| ()).map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => {
                sandbox.ping().map(|_| ()).map_err(map_microvm_error)
            }
            _ => Ok(()),
        }
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn execute_with_vm_options(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
        timeout: Option<Duration>,
    ) -> Result<ExecuteResult, SdkError> {
        let args = parse_command(command)?;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;
        let options = mimobox_vm::GuestExecOptions { env, timeout };

        dispatch_vm!(
            inner,
            sandbox,
            {
                let start = std::time::Instant::now();
                sandbox
                    .execute_with_options(&args, options)
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(map_microvm_error)
            },
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "per-command env/timeout only supports microVM backend",
                Some(
                    "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                        .to_string()
                ),
            ))
        )
    }

    #[cfg(all(feature = "vm", not(target_os = "linux")))]
    fn execute_with_vm_options(
        &mut self,
        _command: &str,
        _env: HashMap<String, String>,
        _timeout: Option<Duration>,
    ) -> Result<ExecuteResult, SdkError> {
        Err(SdkError::unsupported_backend("microvm"))
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
        let isolation = match self.config.isolation {
            IsolationLevel::Auto | IsolationLevel::MicroVm => IsolationLevel::MicroVm,
            IsolationLevel::Os | IsolationLevel::Wasm => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "file transfer only supports microVM backend",
                    Some("set isolation to `MicroVm`".to_string()),
                ));
            }
        };

        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_inner()?;
        }

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        Ok(())
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn ensure_backend_for_snapshot(&mut self) -> Result<(), SdkError> {
        if self.inner.is_some() {
            return match self.active_isolation {
                Some(IsolationLevel::MicroVm) => Ok(()),
                Some(_) => Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "current sandbox backend does not support snapshot",
                    Some("set isolation to `MicroVm` and recreate sandbox".to_string()),
                )),
                None => Err(SdkError::sandbox(
                    ErrorCode::SandboxCreateFailed,
                    "sandbox backend instance exists but isolation level not recorded",
                    Some("check if sandbox initialization was interrupted".to_string()),
                )),
            };
        }

        let isolation = match self.config.isolation {
            IsolationLevel::Auto | IsolationLevel::MicroVm => IsolationLevel::MicroVm,
            IsolationLevel::Os | IsolationLevel::Wasm => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "configured backend does not support snapshot",
                    Some("set isolation to `MicroVm`".to_string()),
                ));
            }
        };

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        Ok(())
    }

    #[cfg(all(feature = "vm", not(target_os = "linux")))]
    fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
        Err(SdkError::unsupported_backend("microvm"))
    }

    fn ensure_backend_for_pty(&mut self) -> Result<(), SdkError> {
        let isolation = match self.config.isolation {
            IsolationLevel::Auto => IsolationLevel::Os,
            other => other,
        };

        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_inner()?;
        }

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        Ok(())
    }

    fn new_uninitialized(config: Config) -> Self {
        Self {
            config,
            inner: None,
            active_isolation: None,
            #[cfg(feature = "vm")]
            vm_pool: None,
        }
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn from_initialized_inner(inner: SandboxInner, config: Config) -> Self {
        Self {
            config,
            inner: Some(inner),
            active_isolation: Some(IsolationLevel::MicroVm),
            #[cfg(feature = "vm")]
            vm_pool: None,
        }
    }

    fn create_inner(&self, isolation: IsolationLevel) -> Result<SandboxInner, SdkError> {
        let sandbox_config = self.config.to_sandbox_config();

        match isolation {
            IsolationLevel::Os => {
                #[cfg(all(feature = "os", target_os = "linux"))]
                {
                    mimobox_os::LinuxSandbox::new(sandbox_config)
                        .map(SandboxInner::Os)
                        .map_err(SdkError::from_sandbox_create_error)
                }
                #[cfg(all(feature = "os", target_os = "macos"))]
                {
                    mimobox_os::MacOsSandbox::new(sandbox_config)
                        .map(SandboxInner::OsMac)
                        .map_err(SdkError::from_sandbox_create_error)
                }
                #[cfg(not(any(
                    all(feature = "os", target_os = "linux"),
                    all(feature = "os", target_os = "macos")
                )))]
                {
                    Err(SdkError::unsupported_backend("os"))
                }
            }
            IsolationLevel::Wasm => {
                #[cfg(feature = "wasm")]
                {
                    mimobox_wasm::WasmSandbox::new(sandbox_config)
                        .map(SandboxInner::Wasm)
                        .map_err(SdkError::from_sandbox_create_error)
                }
                #[cfg(not(feature = "wasm"))]
                {
                    Err(SdkError::unsupported_backend("wasm"))
                }
            }
            IsolationLevel::MicroVm => {
                #[cfg(all(feature = "vm", target_os = "linux"))]
                {
                    if let Some(pool) = &self.vm_pool {
                        let pooled = pool.acquire().map_err(map_pool_error)?;
                        Ok(SandboxInner::PooledMicroVm(pooled))
                    } else {
                        let microvm_config = self.config.to_microvm_config()?;
                        let sandbox = mimobox_vm::MicrovmSandbox::new_with_base(
                            sandbox_config,
                            microvm_config,
                        )
                        .map_err(map_microvm_error)?;
                        Ok(SandboxInner::MicroVm(sandbox))
                    }
                }
                #[cfg(not(all(feature = "vm", target_os = "linux")))]
                {
                    Err(SdkError::unsupported_backend("microvm"))
                }
            }
            IsolationLevel::Auto => Err(SdkError::unsupported_backend("auto")),
        }
    }

    fn destroy_inner(&mut self) -> Result<(), SdkError> {
        let inner = self.inner.take();
        self.active_isolation = None;

        match inner {
            Some(inner) => destroy_backend_inner(inner),
            None => Ok(()),
        }
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Err(error) = self.destroy_inner() {
            warn!(message = %error, "Sandbox drop 自动清理失败");
        }
    }
}

fn destroy_backend_inner(inner: SandboxInner) -> Result<(), SdkError> {
    match inner {
        #[cfg(all(feature = "os", target_os = "linux"))]
        SandboxInner::Os(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "os", target_os = "macos"))]
        SandboxInner::OsMac(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::MicroVm(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::PooledMicroVm(pooled) => {
            drop(pooled);
            Ok(())
        }
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::RestoredPooledMicroVm(pooled) => {
            drop(pooled);
            Ok(())
        }
        #[cfg(feature = "wasm")]
        SandboxInner::Wasm(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
    }
}

fn parse_command(command: &str) -> Result<Vec<String>, SdkError> {
    shlex::split(command).ok_or_else(|| {
        SdkError::Config("command parsing failed: mismatched shell-style quotes".to_string())
    })
}

fn map_pty_create_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::UnsupportedOperation(message) => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            message,
            Some("set isolation to `Os` or use default Auto".to_string()),
        ),
        other => SdkError::sandbox(ErrorCode::SandboxCreateFailed, other.to_string(), None),
    }
}

fn map_pty_session_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::UnsupportedOperation(message) => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            message,
            Some("set isolation to `Os` or use default Auto".to_string()),
        ),
        mimobox_core::SandboxError::Timeout => SdkError::sandbox(
            ErrorCode::CommandTimeout,
            "PTY session execution timed out",
            Some("increase Config.timeout or PtyConfig.timeout".to_string()),
        ),
        other => SdkError::sandbox(ErrorCode::SandboxDestroyed, other.to_string(), None),
    }
}

fn map_snapshot_bytes_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::InvalidSnapshot => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            "invalid sandbox snapshot",
            Some(
                "for file-mode snapshots, prefer from_snapshot()/restore() or to_bytes()"
                    .to_string(),
            ),
        ),
        mimobox_core::SandboxError::ExecutionFailed(message) => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some(
                "ensure snapshot data is non-empty and from a mimobox microVM snapshot".to_string(),
            ),
        ),
        mimobox_core::SandboxError::Io(error) => SdkError::Io(error),
        other => SdkError::sandbox(ErrorCode::InvalidConfig, other.to_string(), None),
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
fn bridge_vm_stream(
    source: mpsc::Receiver<mimobox_vm::StreamEvent>,
) -> mpsc::Receiver<StreamEvent> {
    let (tx, rx) = mpsc::sync_channel(32);
    std::thread::spawn(move || {
        while let Ok(event) = source.recv() {
            let mapped = match event {
                mimobox_vm::StreamEvent::Stdout(data) => StreamEvent::Stdout(data),
                mimobox_vm::StreamEvent::Stderr(data) => StreamEvent::Stderr(data),
                mimobox_vm::StreamEvent::Exit(code) => StreamEvent::Exit(code),
                mimobox_vm::StreamEvent::TimedOut => StreamEvent::TimedOut,
            };
            if tx.send(mapped).is_err() {
                break;
            }
        }
    });
    rx
}

#[cfg(feature = "vm")]
fn should_prepare_vm_pool(config: &Config) -> bool {
    matches!(resolve_isolation(config, ""), Ok(IsolationLevel::MicroVm))
}

#[cfg(feature = "vm")]
fn initialize_default_vm_pool(
    config: &Config,
) -> Result<Option<Arc<mimobox_vm::VmPool>>, SdkError> {
    if !should_prepare_vm_pool(config) {
        return Ok(None);
    }

    let microvm_config = config.to_microvm_config()?;
    let sandbox_config = config.to_sandbox_config();
    let pool_config = mimobox_vm::VmPoolConfig {
        min_size: 1,
        max_size: 4,
        max_idle_duration: std::time::Duration::from_secs(60),
        health_check_interval: None,
    };

    match mimobox_vm::VmPool::new_with_base(sandbox_config, microvm_config, pool_config) {
        Ok(pool) => Ok(Some(Arc::new(pool))),
        Err(error) => {
            tracing::warn!("初始化 microVM 预热池失败，回退到冷启动路径: {error}");
            Ok(None)
        }
    }
}

#[cfg(test)]
fn inner_is_initialized(sandbox: &Sandbox) -> bool {
    sandbox.inner.is_some()
}

#[cfg(test)]
fn active_isolation(sandbox: &Sandbox) -> Option<IsolationLevel> {
    sandbox.active_isolation
}

#[cfg(all(test, feature = "vm"))]
fn vm_pool_is_initialized(sandbox: &Sandbox) -> bool {
    sandbox.vm_pool.is_some()
}

#[cfg(test)]
#[cfg(feature = "wasm")]
fn has_os_backend(sandbox: &Sandbox) -> bool {
    match sandbox.inner.as_ref() {
        #[cfg(all(feature = "os", target_os = "linux"))]
        Some(SandboxInner::Os(_)) => true,
        #[cfg(all(feature = "os", target_os = "macos"))]
        Some(SandboxInner::OsMac(_)) => true,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::MicroVm(_)) => false,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::PooledMicroVm(_)) => false,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::RestoredPooledMicroVm(_)) => false,
        #[cfg(feature = "wasm")]
        Some(SandboxInner::Wasm(_)) => false,
        None => false,
    }
}

#[cfg(test)]
#[cfg(feature = "wasm")]
fn has_wasm_backend(sandbox: &Sandbox) -> bool {
    match sandbox.inner.as_ref() {
        #[cfg(feature = "wasm")]
        Some(SandboxInner::Wasm(_)) => true,
        #[cfg(all(feature = "os", target_os = "linux"))]
        Some(SandboxInner::Os(_)) => false,
        #[cfg(all(feature = "os", target_os = "macos"))]
        Some(SandboxInner::OsMac(_)) => false,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::MicroVm(_)) => false,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::PooledMicroVm(_)) => false,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::RestoredPooledMicroVm(_)) => false,
        None => false,
    }
}

#[cfg(test)]
fn parse_for_test(command: &str) -> Result<Vec<String>, SdkError> {
    parse_command(command)
}

#[cfg(feature = "vm")]
fn map_http_proxy_error(error: mimobox_vm::HttpProxyError) -> SdkError {
    use mimobox_vm::HttpProxyError;

    match error {
        HttpProxyError::DeniedHost(message) => SdkError::sandbox(
            ErrorCode::HttpDeniedHost,
            message,
            Some("ensure target domain is in allowed_http_domains whitelist".to_string()),
        ),
        HttpProxyError::DnsRebind(message) => SdkError::sandbox(
            ErrorCode::HttpDeniedHost,
            message,
            Some("target domain resolved to private/loopback address, access denied".to_string()),
        ),
        HttpProxyError::Timeout => SdkError::sandbox(
            ErrorCode::HttpTimeout,
            "HTTP request timed out",
            Some("check target service reachability or increase timeout config".to_string()),
        ),
        HttpProxyError::BodyTooLarge => SdkError::sandbox(
            ErrorCode::HttpBodyTooLarge,
            "HTTP body exceeds size limit",
            Some("reduce request/response body size or transfer volume".to_string()),
        ),
        HttpProxyError::ConnectFail(message) => SdkError::sandbox(
            ErrorCode::HttpConnectFail,
            message,
            Some("check target service connectivity and port reachability".to_string()),
        ),
        HttpProxyError::TlsFail(message) => SdkError::sandbox(
            ErrorCode::HttpTlsFail,
            message,
            Some("check target certificate chain and TLS configuration".to_string()),
        ),
        HttpProxyError::InvalidUrl(message) => SdkError::sandbox(
            ErrorCode::HttpInvalidUrl,
            message,
            Some("only HTTPS URLs are supported, and direct IP access is not allowed".to_string()),
        ),
        HttpProxyError::Internal(message) => SdkError::Config(message),
    }
}

#[cfg(feature = "vm")]
fn map_microvm_error(error: mimobox_vm::MicrovmError) -> SdkError {
    use mimobox_vm::MicrovmError;

    match error {
        MicrovmError::UnsupportedPlatform => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            "KVM microVM backend not supported on current platform",
            Some("use microVM features only on Linux with vm feature enabled".to_string()),
        ),
        MicrovmError::InvalidConfig(message) => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some("check microVM config, kernel/rootfs paths, and memory settings".to_string()),
        ),
        MicrovmError::Lifecycle(message) => {
            let code = if message.contains("released")
                || message.contains("destroyed")
                || message.contains("Destroyed")
            {
                ErrorCode::SandboxDestroyed
            } else {
                ErrorCode::SandboxNotReady
            };
            SdkError::sandbox(
                code,
                message,
                Some(
                    "ensure sandbox creation has completed and current state allows this operation"
                        .to_string(),
                ),
            )
        }
        MicrovmError::HttpProxy(error) => map_http_proxy_error(error),
        MicrovmError::Backend(message) => {
            if message.contains("file path error") {
                return SdkError::sandbox(
                    ErrorCode::FileNotFound,
                    message,
                    Some(
                        "ensure target file exists and path is within allowed access scope"
                            .to_string(),
                    ),
                );
            }
            if message.contains("file permission error") {
                return SdkError::sandbox(
                    ErrorCode::FilePermissionDenied,
                    message,
                    Some("check file permissions and sandbox mount policy".to_string()),
                );
            }
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                message,
                Some("ensure KVM is available and guest runtime state is healthy".to_string()),
            )
        }
        MicrovmError::SnapshotFormat(message) => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some("ensure snapshot comes from a compatible mimobox microVM version".to_string()),
        ),
        MicrovmError::Io(error) => SdkError::sandbox(
            ErrorCode::SandboxCreateFailed,
            error.to_string(),
            Some(
                "check snapshot file I/O and underlying virtualization resource state".to_string(),
            ),
        ),
    }
}

#[cfg(feature = "vm")]
fn map_pool_error(error: mimobox_vm::PoolError) -> SdkError {
    match error {
        mimobox_vm::PoolError::InvalidConfig { min_size, max_size } => SdkError::Config(format!(
            "invalid warm pool config: min_size={min_size}, max_size={max_size}"
        )),
        mimobox_vm::PoolError::StatePoisoned => {
            SdkError::Config("warm pool internal state lock poisoned".to_string())
        }
        mimobox_vm::PoolError::Microvm(error) => map_microvm_error(error),
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
fn map_restore_pool_error(error: mimobox_vm::RestorePoolError) -> SdkError {
    match error {
        mimobox_vm::RestorePoolError::InvalidConfig { min_size, max_size } => SdkError::Config(
            format!("invalid restore pool config: min_size={min_size}, max_size={max_size}"),
        ),
        mimobox_vm::RestorePoolError::StatePoisoned => SdkError::sandbox(
            ErrorCode::SandboxDestroyed,
            "restore pool internal state lock poisoned",
            Some("destroy current restore pool and recreate".to_string()),
        ),
        mimobox_vm::RestorePoolError::Microvm(error) => map_microvm_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_config_defers_backend_creation_until_first_execute() {
        let sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        assert!(!inner_is_initialized(&sandbox));
        assert_eq!(active_isolation(&sandbox), None);
    }

    #[cfg(feature = "vm")]
    #[test]
    fn default_auto_config_does_not_prepare_vm_pool() {
        let sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        assert!(!vm_pool_is_initialized(&sandbox));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn explicit_microvm_config_marks_pool_as_eligible_on_supported_builds() {
        let config = Config::builder().isolation(IsolationLevel::MicroVm).build();

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert!(should_prepare_vm_pool(&config));

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(!should_prepare_vm_pool(&config));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn auto_untrusted_config_marks_pool_as_eligible_on_supported_builds() {
        let config = Config::builder().trust_level(TrustLevel::Untrusted).build();

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert!(should_prepare_vm_pool(&config));

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(!should_prepare_vm_pool(&config));
    }

    #[test]
    fn invalid_shell_quoting_returns_sdk_error_instead_of_fallback_execution() {
        let result = parse_for_test("'unterminated");

        assert!(matches!(result, Err(SdkError::Config(_))));
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn create_pty_auto_routes_to_os_backend() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");
        let mut session = sandbox
            .create_pty("/bin/echo ready")
            .expect("创建 PTY 会话失败");

        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Os));
        assert_eq!(session.wait().expect("等待 PTY 退出失败"), 0);

        drop(session);
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    #[test]
    fn create_pty_microvm_is_rejected() {
        let mut sandbox =
            Sandbox::with_config(Config::builder().isolation(IsolationLevel::MicroVm).build())
                .expect("创建沙箱失败");

        let result = sandbox.create_pty("/bin/sh");

        match result {
            Err(SdkError::BackendUnavailable("microvm")) => {}
            Err(other) => panic!("期望 microVM 后端不可用，实际为: {other}"),
            Ok(_) => panic!("期望 PTY 在 microVM 配置下被拒绝，实际却创建成功"),
        }
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    #[test]
    fn create_pty_microvm_maps_unsupported_operation_on_supported_vm_build() {
        let Ok(microvm_config) = mimobox_vm::microvm_config_from_vm_assets(256) else {
            return;
        };
        let config = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .vm_memory_mb(microvm_config.memory_mb)
            .kernel_path(microvm_config.kernel_path.clone())
            .rootfs_path(microvm_config.rootfs_path.clone())
            .build();
        let mut microvm = mimobox_vm::MicrovmSandbox::new_with_base(
            mimobox_core::SandboxConfig::default(),
            microvm_config,
        )
        .expect("创建 microVM 沙箱必须成功");
        let pty_config = PtyConfig {
            command: vec!["/bin/sh".to_string()],
            size: PtySize::default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: config.timeout,
        };

        match CoreSandbox::create_pty(&mut microvm, pty_config) {
            Err(mimobox_core::SandboxError::UnsupportedOperation(message)) => {
                assert!(message.contains("microVM"));
            }
            Err(other) => panic!("期望 microVM PTY 返回 UnsupportedOperation，实际为: {other}"),
            Ok(_) => panic!("期望 microVM PTY 被拒绝，实际却创建成功"),
        }

        let mut sandbox = Sandbox::from_initialized_inner(SandboxInner::MicroVm(microvm), config);
        let result = sandbox.create_pty("/bin/sh");

        match result {
            Err(SdkError::Sandbox { code, message, .. }) => {
                assert_eq!(code, ErrorCode::UnsupportedPlatform);
                assert!(message.contains("microVM"));
            }
            Err(other) => panic!(
                "期望 SDK 将 UnsupportedOperation 映射为 UnsupportedPlatform，实际为: {other}"
            ),
            Ok(_) => panic!("期望 SDK PTY 在 microVM 下被拒绝，实际却创建成功"),
        }

        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(
        feature = "os",
        feature = "wasm",
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    fn auto_routing_reinitializes_backend_for_wasm_commands() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");
        sandbox
            .ensure_backend("/bin/echo hello")
            .expect("初始化 OS 后端失败");
        assert!(has_os_backend(&sandbox));
        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Os));

        let script_path = std::path::PathBuf::from(format!(
            "/tmp/mimobox-sdk-auto-route-{}.wasm",
            std::process::id()
        ));
        std::fs::write(&script_path, "#!/bin/sh\necho routed-via-os\n").expect("写入测试脚本失败");
        make_executable(&script_path);

        let command = script_path.to_string_lossy().into_owned();
        sandbox
            .ensure_backend(&command)
            .expect("切换到 Wasm 后端失败");

        let _ = std::fs::remove_file(&script_path);

        assert!(has_wasm_backend(&sandbox));
        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Wasm));
    }

    #[cfg(all(feature = "wasm", unix))]
    fn make_executable(path: &std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).expect("读取测试脚本元数据失败");
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("设置测试脚本权限失败");
    }
}
