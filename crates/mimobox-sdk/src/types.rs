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
    /// Standard output byte stream.
    pub stdout: Vec<u8>,
    /// Standard error byte stream.
    pub stderr: Vec<u8>,
    /// Exit code; may be `None` if the process did not exit normally.
    pub exit_code: Option<i32>,
    /// Whether execution was terminated due to timeout.
    pub timed_out: bool,
    /// Total elapsed time for this execution.
    pub elapsed: std::time::Duration,
}

impl ExecuteResult {
    /// Constructs a new execution result.
    ///
    /// Because `ExecuteResult` is marked `#[non_exhaustive]`, external crates
    /// cannot construct it with a struct literal.
    /// This method provides a stable construction path.
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
///     .build()?;
/// let mut sandbox = Sandbox::with_config(config)?;
/// let resp = sandbox.http_request("GET", "https://example.com", HashMap::new(), None)?;
/// println!("status: {}", resp.status);
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Normalized response headers.
    pub headers: std::collections::HashMap<String, String>,
    /// Response body byte stream.
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
///     .build()?;
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
    /// Restores a snapshot from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SdkError> {
        mimobox_core::SandboxSnapshot::from_bytes(data)
            .map(Self::from_core)
            .map_err(map_snapshot_bytes_error)
    }

    /// Creates a snapshot from a file-backed snapshot's `memory.bin`.
    pub fn from_file(path: PathBuf) -> Result<Self, SdkError> {
        mimobox_core::SandboxSnapshot::from_file(path)
            .map(Self::from_core)
            .map_err(map_snapshot_bytes_error)
    }

    /// Returns the memory file path for a file-backed snapshot.
    pub fn memory_file_path(&self) -> Option<&Path> {
        self.inner.memory_file_path()
    }

    /// Returns a snapshot byte slice without an extra copy.
    ///
    /// Only in-memory snapshots support this operation; file-backed snapshots return an error.
    pub fn as_bytes(&self) -> Result<&[u8], SdkError> {
        self.inner.as_bytes().map_err(map_snapshot_bytes_error)
    }

    /// Returns a copied snapshot byte buffer.
    ///
    /// For file-backed snapshots, rebuilds the complete self-describing snapshot bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        if let Some(memory_path) = self.inner.memory_file_path() {
            return mimobox_vm::MicrovmSnapshot::from_memory_file(memory_path)
                .and_then(|snapshot| snapshot.snapshot())
                .map_err(map_microvm_error);
        }

        self.inner.to_bytes().map_err(map_snapshot_bytes_error)
    }

    /// Consumes the snapshot and returns the underlying bytes without an extra copy.
    ///
    /// For file-backed snapshots, rebuilds the complete self-describing snapshot bytes.
    pub fn into_bytes(self) -> Result<Vec<u8>, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        if let Some(memory_path) = self.inner.memory_file_path().map(Path::to_path_buf) {
            return mimobox_vm::MicrovmSnapshot::from_memory_file(&memory_path)
                .and_then(|snapshot| snapshot.snapshot())
                .map_err(map_microvm_error);
        }

        self.inner.into_bytes().map_err(map_snapshot_bytes_error)
    }

    /// Returns the snapshot size in bytes.
    pub fn size(&self) -> usize {
        self.inner.size()
    }

    /// Provides the from core operation.
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
    /// Target restore pool size.
    pub pool_size: usize,
    /// Base configuration used by the restore pool.
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
///     .build()?;
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
    /// A chunk of standard output data.
    Stdout(Vec<u8>),
    /// A chunk of standard error data.
    Stderr(Vec<u8>),
    /// The process exited with an exit code.
    Exit(i32),
    /// Execution was terminated due to timeout.
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
    /// Constructs an SDK PTY wrapper from a backend PTY session.
    #[cfg(any(
        feature = "wasm",
        all(feature = "os", any(target_os = "linux", target_os = "macos")),
        all(feature = "vm", target_os = "linux")
    ))]
    /// Provides the from inner operation.
    pub(crate) fn from_inner(inner: Box<dyn mimobox_core::PtySession>) -> Self {
        Self { inner }
    }

    /// Writes input data to the PTY session.
    pub fn send_input(&mut self, data: &[u8]) -> Result<(), SdkError> {
        self.inner.send_input(data).map_err(map_pty_session_error)
    }

    /// Resizes the PTY terminal.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), SdkError> {
        self.inner
            .resize(PtySize { cols, rows })
            .map_err(map_pty_session_error)
    }

    /// Returns the PTY output event receiver.
    pub fn output(&self) -> &mpsc::Receiver<PtyEvent> {
        self.inner.output_rx()
    }

    /// Forcefully terminates the PTY session.
    pub fn kill(&mut self) -> Result<(), SdkError> {
        self.inner.kill().map_err(map_pty_session_error)
    }

    /// Waits for the PTY process to exit and returns its exit code.
    pub fn wait(&mut self) -> Result<i32, SdkError> {
        self.inner.wait().map_err(map_pty_session_error)
    }
}
