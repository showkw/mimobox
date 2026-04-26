#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::config::Config;
use crate::error::SdkError;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::vm_helpers::map_microvm_error;
use crate::vm_helpers::{map_pty_session_error, map_snapshot_bytes_error};
use mimobox_core::{PtyEvent, PtySize, SandboxResult};
use std::path::{Path, PathBuf};
#[cfg(all(feature = "vm", target_os = "linux"))]
use std::sync::Arc;
use std::sync::mpsc;

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
/// ```rust,no_run,ignore
/// // Requires `vm` feature + Linux
/// use mimobox_sdk::{Config, IsolationLevel, Sandbox};
/// use std::collections::HashMap;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::builder()
///     .isolation(IsolationLevel::MicroVm)
///     .allowed_http_domains(["example.com"])
///     .build();
/// let mut sandbox = Sandbox::with_config(config)?;
/// let resp = sandbox.http_request("GET", "https://example.com", HashMap::new(), None)?;
/// println!("status: {}", resp.status);
/// # Ok(())
/// # }
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
    pub(crate) inner: mimobox_core::SandboxSnapshot,
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

    pub(crate) fn from_core(inner: mimobox_core::SandboxSnapshot) -> Self {
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
    pub(crate) inner: Arc<mimobox_vm::RestorePool>,
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
/// ```rust,no_run,ignore
/// // Requires `vm` feature + Linux
/// use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
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
///         _ => {}
///     }
/// }
/// # Ok(())
/// # }
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
    /// 从后端 PTY 会话构造 SDK PTY 包装。
    pub(crate) fn from_inner(inner: Box<dyn mimobox_core::PtySession>) -> Self {
        Self { inner }
    }

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
