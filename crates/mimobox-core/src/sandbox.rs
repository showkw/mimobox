use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crate::seccomp::SeccompProfile;

fn default_cpu_period_us() -> u64 {
    100_000
}

fn has_invalid_domain_wildcard(domain: &str) -> bool {
    let wildcard_count = domain.chars().filter(|character| *character == '*').count();
    wildcard_count > 0 && (wildcard_count != 1 || !domain.starts_with("*."))
}

fn is_plain_ip_domain(domain: &str) -> bool {
    let has_digit = domain.chars().any(|character| character.is_ascii_digit());
    let has_dot = domain.contains('.');

    has_digit
        && has_dot
        && domain
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
}

/// Structured error code for programmatic error matching.
///
/// Each variant has a stable string representation via [`ErrorCode::as_str()`],
/// suitable for cross-language transport and log indexing.
///
/// # Examples
///
/// ```
/// use mimobox_core::ErrorCode;
///
/// assert_eq!(ErrorCode::CommandTimeout.as_str(), "command_timeout");
/// assert_eq!(ErrorCode::HttpDeniedHost.as_str(), "http_denied_host");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// The command exceeds its timeout.
    CommandTimeout,
    /// The command exits with a non-zero status code.
    CommandExit(i32),
    /// The command is forcibly terminated by the host.
    CommandKilled,
    /// The target file does not exist.
    FileNotFound,
    /// The target file lacks the required access permission.
    FilePermissionDenied,
    /// The target file or transferred content exceeds the size limit.
    FileTooLarge,
    /// The target path is not a directory.
    NotDirectory,
    /// The HTTP proxy target host is not in the allowlist.
    HttpDeniedHost,
    /// The HTTP proxy request times out.
    HttpTimeout,
    /// The HTTP response body exceeds the allowed size.
    HttpBodyTooLarge,
    /// The HTTP proxy fails to establish a connection.
    HttpConnectFail,
    /// The HTTP proxy TLS handshake fails.
    HttpTlsFail,
    /// The HTTP request URL is invalid.
    HttpInvalidUrl,
    /// The sandbox is not ready to execute commands.
    SandboxNotReady,
    /// The sandbox has been destroyed and cannot be reused.
    SandboxDestroyed,
    /// The sandbox creation flow fails.
    SandboxCreateFailed,
    /// The provided configuration is invalid.
    InvalidConfig,
    /// The current platform or backend does not support this capability.
    UnsupportedPlatform,
    /// 沙箱内存超限被杀（OOM killer 或 cgroups memory.limit）。
    MemoryLimitExceeded,
    /// 沙箱 CPU 配额耗尽（cgroups cpu.stat throttle）。
    CpuLimitExceeded,
}

impl ErrorCode {
    /// Returns the stable string error code for cross-language transport and log indexing.
    pub fn as_str(&self) -> &'static str {
        #[allow(unreachable_patterns)]
        match self {
            Self::CommandTimeout => "command_timeout",
            Self::CommandExit(_) => "command_exit",
            Self::CommandKilled => "command_killed",
            Self::FileNotFound => "file_not_found",
            Self::FilePermissionDenied => "file_permission_denied",
            Self::FileTooLarge => "file_too_large",
            Self::NotDirectory => "not_directory",
            Self::HttpDeniedHost => "http_denied_host",
            Self::HttpTimeout => "http_timeout",
            Self::HttpBodyTooLarge => "http_body_too_large",
            Self::HttpConnectFail => "http_connect_fail",
            Self::HttpTlsFail => "http_tls_fail",
            Self::HttpInvalidUrl => "http_invalid_url",
            Self::SandboxNotReady => "sandbox_not_ready",
            Self::SandboxDestroyed => "sandbox_destroyed",
            Self::SandboxCreateFailed => "sandbox_create_failed",
            Self::InvalidConfig => "invalid_config",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::MemoryLimitExceeded => "memory_limit_exceeded",
            Self::CpuLimitExceeded => "cpu_limit_exceeded",
            _ => "unknown_error",
        }
    }
}

/// 文件类型枚举，用于目录条目的类型区分。
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileType {
    /// 普通文件。
    File,
    /// 目录。
    Dir,
    /// 符号链接。
    Symlink,
    /// 其他类型（设备、管道等）。
    Other,
}

/// 目录条目，表示 list_dir 返回的单个条目。
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirEntry {
    /// 文件名。
    pub name: String,
    /// 文件类型。
    pub file_type: FileType,
    /// 文件大小（字节）。
    pub size: u64,
    /// 是否为符号链接。
    pub is_symlink: bool,
}

impl DirEntry {
    /// 创建目录条目。
    pub fn new(name: String, file_type: FileType, size: u64, is_symlink: bool) -> Self {
        Self {
            name,
            file_type,
            size,
            is_symlink,
        }
    }
}

/// 文件元信息，stat 方法返回的类型。
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileStat {
    /// 文件路径。
    pub path: String,
    /// 是否为目录。
    pub is_dir: bool,
    /// 是否为普通文件。
    pub is_file: bool,
    /// 文件大小（字节）。
    pub size: u64,
    /// 文件权限模式（Unix mode）。
    pub mode: u32,
    /// 最后修改时间（毫秒时间戳），可能不可用。
    pub modified_ms: Option<u64>,
}

impl FileStat {
    /// 创建文件元信息。
    pub fn new(
        path: String,
        is_dir: bool,
        is_file: bool,
        size: u64,
        mode: u32,
        modified_ms: Option<u64>,
    ) -> Self {
        Self {
            path,
            is_dir,
            is_file,
            size,
            mode,
            modified_ms,
        }
    }
}

/// Namespace 降级行为控制策略。
///
/// 当 Linux namespace 创建失败时（如缺少 CAP_SYS_ADMIN），决定如何处理。
/// 默认为 [`NamespaceDegradation::FailClosed`]，确保安全边界不被静默削弱。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum NamespaceDegradation {
    /// 任何 namespace 创建失败都返回错误（默认，生产环境推荐）。
    #[default]
    FailClosed,
    /// 失败时 warn 但继续执行（仅用于开发/CI 环境中 namespace 支持不完整的场景）。
    AllowDegradation,
}

/// Sandbox memory limit upper bound in MiB.
///
/// 32 GiB is intentionally above normal sandbox workloads while keeping
/// MiB-to-bytes conversions and backend resource accounting fail-closed.
pub const MAX_MEMORY_LIMIT_MB: u64 = 32 * 1024;

/// Sandbox configuration shared across all backends.
///
/// This struct describes the minimum capability set used by all sandbox
/// implementations, including filesystem permissions, network policy,
/// resource limits, and controlled HTTP proxy whitelist.
///
/// 默认拒绝所有文件系统访问，由各后端和 SDK Config 按需填充最小权限集。
///
/// # Examples
///
/// ```
/// use mimobox_core::SandboxConfig;
///
/// let config = SandboxConfig::default();
/// assert!(config.deny_network);
/// assert_eq!(config.timeout_secs, Some(30));
/// assert!(config.fs_readonly.is_empty());
/// assert!(config.fs_readwrite.is_empty());
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxConfig {
    /// Read-only path list.
    pub fs_readonly: Vec<PathBuf>,
    /// Read-write path list.
    pub fs_readwrite: Vec<PathBuf>,
    /// Whether direct network access from sandboxed processes is denied.
    pub deny_network: bool,
    /// Memory limit in MB, enforced through cgroups v2 or `setrlimit`.
    pub memory_limit_mb: Option<u64>,
    /// Maximum process count inside one sandbox.
    ///
    /// `None` lets the Linux backend use its secure default.
    #[serde(default)]
    pub max_processes: Option<u32>,
    /// CPU 时间配额（微秒），配合 `cpu_period_us` 使用。
    ///
    /// 例如 quota=50000, period=100000 表示最多使用 50% CPU。
    /// 设为 `None` 表示不限制。
    #[serde(default)]
    pub cpu_quota_us: Option<u64>,
    /// CPU 周期（微秒），默认 100000（100ms）。
    #[serde(default = "default_cpu_period_us")]
    pub cpu_period_us: u64,
    /// Timeout in seconds.
    pub timeout_secs: Option<u64>,
    /// Seccomp filter policy.
    pub seccomp_profile: SeccompProfile,
    /// Whether sandboxed processes may create child processes (`fork`/`clone`).
    /// Defaults to `false`; set to `true` only for shells and other child-process workloads.
    pub allow_fork: bool,
    /// HTTP proxy domain allowlist, including wildcards such as `*.openai.com`.
    /// These domains remain reachable through the controlled proxy even when `deny_network = true`.
    pub allowed_http_domains: Vec<String>,
    /// Namespace 降级行为控制。默认 FailClosed（任何 namespace 创建失败都返回错误）。
    #[serde(default)]
    pub namespace_degradation: NamespaceDegradation,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            fs_readonly: Vec::new(),
            fs_readwrite: Vec::new(),
            deny_network: true,
            memory_limit_mb: Some(512),
            max_processes: None,
            cpu_quota_us: None,
            cpu_period_us: default_cpu_period_us(),
            timeout_secs: Some(30),
            seccomp_profile: SeccompProfile::Essential,
            allow_fork: false,
            allowed_http_domains: Vec::new(),
            namespace_degradation: NamespaceDegradation::FailClosed,
        }
    }
}

impl SandboxConfig {
    /// Set the CPU time quota in microseconds.
    pub fn cpu_quota(mut self, quota_us: u64) -> Self {
        self.cpu_quota_us = Some(quota_us);
        self
    }

    /// Set the CPU period in microseconds.
    pub fn cpu_period(mut self, period_us: u64) -> Self {
        self.cpu_period_us = period_us;
        self
    }

    /// 校验配置合法性，返回不合理项的描述。
    pub fn validate(&self) -> Result<(), SandboxError> {
        // deny_network 只表示禁止沙箱内直连网络；allowed_http_domains 表示
        // host 侧受控 HTTP 代理白名单，两者可以同时存在。

        // memory_limit_mb=Some(0) 无意义。
        if self.memory_limit_mb == Some(0) {
            return Err(
                SandboxError::new("memory_limit_mb=0 无效，请设为正整数或 None")
                    .suggestion("memory_limit_mb 最小值为 1"),
            );
        }
        if let Some(memory_limit_mb) = self.memory_limit_mb
            && memory_limit_mb > MAX_MEMORY_LIMIT_MB
        {
            return Err(SandboxError::new(format!(
                "memory_limit_mb={memory_limit_mb} 超过最大值 {MAX_MEMORY_LIMIT_MB} MB，请设为合理值"
            ))
            .suggestion(format!(
                "memory_limit_mb 最大值为 {MAX_MEMORY_LIMIT_MB}"
            )));
        }

        if self.max_processes == Some(0) {
            return Err(
                SandboxError::new("max_processes=0 无效，请设为正整数或 None")
                    .suggestion("max_processes 最小值为 1，或设置为 None 使用后端默认值"),
            );
        }

        // timeout_secs 允许关闭，但显式设置时不能超过 24 小时。
        if let Some(timeout_secs) = self.timeout_secs {
            const MAX_TIMEOUT_SECS: u64 = 86_400;
            if timeout_secs == 0 {
                return Err(
                    SandboxError::new("timeout_secs=0 无效，请设为正整数或 None")
                        .suggestion("timeout 不能为 0，推荐 30 秒"),
                );
            }
            if timeout_secs > MAX_TIMEOUT_SECS {
                return Err(SandboxError::new(format!(
                    "timeout_secs={timeout_secs} 超过最大值 86400（24小时），请设为合理值"
                ))
                .suggestion("timeout_secs 最大值为 86400（24小时）"));
            }
        }

        for domain in &self.allowed_http_domains {
            if domain.is_empty()
                || domain
                    .chars()
                    .any(|character| matches!(character, ' ' | '\t' | '\n' | '\r'))
                || has_invalid_domain_wildcard(domain)
                || is_plain_ip_domain(domain)
            {
                return Err(SandboxError::new(format!(
                    "allowed_http_domains 包含无效域名: {domain}"
                ))
                .suggestion(
                    "请使用标准域名格式，如 example.com 或 *.example.com，不支持 IP 地址",
                ));
            }
        }

        if self.cpu_period_us == 0 {
            return Err(SandboxError::new("cpu_period_us=0 无效，请设为正整数")
                .suggestion("cpu_period_us 最小值为 1，推荐 100000"));
        }

        Ok(())
    }
}

/// Result of a sandbox command execution.
///
/// Contains raw stdout/stderr bytes, exit code, wall-clock elapsed time,
/// and a timeout flag.
#[derive(Debug)]
pub struct SandboxResult {
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error output.
    pub stderr: Vec<u8>,
    /// Child process exit code; may be `None` when the process does not exit normally.
    pub exit_code: Option<i32>,
    /// Total elapsed time for this execution.
    pub elapsed: Duration,
    /// Whether the execution was terminated because of a timeout.
    pub timed_out: bool,
}

/// Internal storage for sandbox snapshots.
///
/// This enum supports two snapshot storage modes:
/// 1. Stores snapshot content directly as in-memory bytes.
/// 2. Stores only the snapshot file path and size, with the actual data managed externally as a file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SnapshotInner {
    /// In-memory snapshot bytes.
    Bytes(Vec<u8>),
    /// File-backed snapshot reference.
    File {
        /// Snapshot file path.
        path: PathBuf,
        /// Snapshot file size in bytes.
        size: usize,
    },
}

/// Opaque sandbox snapshot handle.
///
/// Carries a backend-generated snapshot without parsing the internal format.
/// Supports two storage modes: in-memory bytes and file-backed references.
///
/// # Examples
///
/// ```
/// use mimobox_core::SandboxSnapshot;
///
/// let snapshot = SandboxSnapshot::from_bytes(b"snapshot-data").unwrap();
/// assert_eq!(snapshot.size(), 13);
/// assert_eq!(snapshot.as_bytes().unwrap(), b"snapshot-data");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSnapshot {
    inner: SnapshotInner,
}

impl SandboxSnapshot {
    /// Creates a snapshot from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SandboxError> {
        if data.is_empty() {
            return Err(SandboxError::new("snapshot data must not be empty"));
        }

        Ok(Self {
            inner: SnapshotInner::Bytes(data.to_vec()),
        })
    }

    /// Creates a snapshot from owned bytes without an extra copy.
    pub fn from_owned_bytes(data: Vec<u8>) -> Result<Self, SandboxError> {
        if data.is_empty() {
            return Err(SandboxError::new("snapshot data must not be empty"));
        }

        Ok(Self {
            inner: SnapshotInner::Bytes(data),
        })
    }

    /// Creates a snapshot reference from a snapshot file.
    ///
    /// This constructor records only the path and file size without reading file content into memory.
    pub fn from_file(path: PathBuf) -> Result<Self, SandboxError> {
        let metadata = std::fs::metadata(&path)?;
        if !metadata.is_file() {
            return Err(SandboxError::InvalidSnapshot);
        }

        let size = usize::try_from(metadata.len()).map_err(|_| SandboxError::InvalidSnapshot)?;
        if size == 0 {
            return Err(SandboxError::InvalidSnapshot);
        }

        Ok(Self {
            inner: SnapshotInner::File { path, size },
        })
    }

    /// Returns the memory file path.
    ///
    /// Returns the corresponding path for file-backed snapshots, or `None` otherwise.
    pub fn memory_file_path(&self) -> Option<&Path> {
        match &self.inner {
            SnapshotInner::Bytes(_) => None,
            SnapshotInner::File { path, .. } => Some(path.as_path()),
        }
    }

    /// Returns the snapshot byte slice without unnecessary copying.
    ///
    /// This operation is supported only for in-memory snapshots; file-backed snapshots return an error.
    pub fn as_bytes(&self) -> Result<&[u8], SandboxError> {
        match &self.inner {
            SnapshotInner::Bytes(data) => Ok(data.as_slice()),
            SnapshotInner::File { .. } => Err(SandboxError::InvalidSnapshot),
        }
    }

    /// Serializes the snapshot into a byte copy.
    ///
    /// File-backed snapshots read file content from disk again.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SandboxError> {
        match &self.inner {
            SnapshotInner::Bytes(data) => Ok(data.clone()),
            SnapshotInner::File { path, .. } => std::fs::read(path).map_err(Into::into),
        }
    }

    /// Consumes the snapshot and returns the underlying bytes without an extra copy.
    ///
    /// File-backed snapshots read file content from disk again.
    pub fn into_bytes(self) -> Result<Vec<u8>, SandboxError> {
        match self.inner {
            SnapshotInner::Bytes(data) => Ok(data),
            SnapshotInner::File { path, .. } => std::fs::read(path).map_err(Into::into),
        }
    }

    /// Returns the snapshot size in bytes.
    pub fn size(&self) -> usize {
        match &self.inner {
            SnapshotInner::Bytes(data) => data.len(),
            SnapshotInner::File { size, .. } => *size,
        }
    }
}

/// PTY terminal dimensions.
///
/// # Examples
///
/// ```
/// use mimobox_core::PtySize;
///
/// let size = PtySize::default();
/// assert_eq!(size.cols, 80);
/// assert_eq!(size.rows, 24);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    /// Terminal column count.
    pub cols: u16,
    /// Terminal row count.
    pub rows: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// PTY session event.
///
/// Events delivered via the PTY output channel.
#[derive(Debug)]
pub enum PtyEvent {
    /// Terminal output data.
    Output(Vec<u8>),
    /// Process exit event.
    Exit(i32),
}

/// PTY session configuration.
///
/// Specifies the command to run, terminal size, environment variables,
/// working directory, and timeout for an interactive PTY session.
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Command and arguments executed when starting the PTY session.
    pub command: Vec<String>,
    /// Initial terminal size.
    pub size: PtySize,
    /// Additional environment variables injected into the session.
    pub env: std::collections::HashMap<String, String>,
    /// Session working directory.
    pub cwd: Option<String>,
    /// Session timeout.
    pub timeout: Option<Duration>,
}

/// PTY session trait for interactive terminal control.
///
/// Backend implementations provide concrete types satisfying this trait.
/// SDK users interact with `mimobox_sdk::PtySession` instead.
pub trait PtySession {
    /// Sends input to the terminal (`stdin`).
    fn send_input(&mut self, data: &[u8]) -> Result<(), SandboxError>;
    /// Resizes the terminal.
    fn resize(&mut self, size: PtySize) -> Result<(), SandboxError>;
    /// Returns the output event receiver.
    fn output_rx(&self) -> &Receiver<PtyEvent>;
    /// Terminates the session.
    fn kill(&mut self) -> Result<(), SandboxError>;
    /// Waits for the process to exit and returns the exit code.
    fn wait(&mut self) -> Result<i32, SandboxError>;
}

/// 执行失败的结构化分类。
///
/// 底层后端直接传递失败类型，避免 SDK 层靠字符串猜测。
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionFailureKind {
    /// 未知/未分类的执行失败。
    Unknown,
    /// 内存超限（OOM killer、cgroups memory.limit、Wasm memory grow 失败）。
    Oom,
    /// CPU 配额耗尽（cgroups cpu throttle、Wasm fuel 耗尽）。
    CpuLimit,
    /// 进程被信号终止（SIGKILL/SIGTERM 等，非超时也非资源限制）。
    Killed,
}

/// Sandbox error type.
///
/// Low-level backend errors. The SDK maps these to `mimobox_sdk::SdkError`
/// with structured [`ErrorCode`] values.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The current platform does not support this sandbox implementation.
    #[error("sandbox backend not supported on current platform")]
    Unsupported,

    /// The current backend does not support the requested operation.
    #[error("operation not supported: {0}")]
    UnsupportedOperation(String),

    /// Namespace initialization fails.
    #[error("namespace creation failed: {0}")]
    NamespaceFailed(String),

    /// The `pivot_root` call fails.
    #[error("pivot_root failed: {0}")]
    PivotRootFailed(String),

    /// Filesystem mounting fails.
    #[error("mount failed: {0}")]
    MountFailed(String),

    /// Landlock rule enforcement fails.
    #[error("Landlock rule enforcement failed: {0}")]
    LandlockFailed(String),

    /// Seccomp rule enforcement fails.
    #[error("Seccomp filter enforcement failed: {0}")]
    SeccompFailed(String),

    /// Command execution or protocol handling fails.
    #[error("command execution failed: {message}")]
    ExecutionFailed {
        /// 结构化失败分类。
        kind: ExecutionFailureKind,
        /// 人类可读的错误描述。
        message: String,
    },

    /// The snapshot content or access mode is invalid.
    #[error("invalid sandbox snapshot")]
    InvalidSnapshot,

    /// The child process execution times out.
    #[error("child process timed out")]
    Timeout,

    /// Pipe I/O fails.
    #[error("pipe I/O error: {0}")]
    PipeError(String),

    /// A system call fails.
    #[error("syscall error: {0}")]
    Syscall(String),

    /// A standard library I/O error occurs.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Adds a remediation suggestion to an existing sandbox error without
    /// changing the original error kind.
    #[error("{error}")]
    WithSuggestion {
        /// Original sandbox error.
        #[source]
        error: Box<SandboxError>,
        /// Suggested action the caller can take to resolve the error.
        suggestion: Option<String>,
    },
}

impl SandboxError {
    /// Constructs a command execution error with no suggestion.
    pub fn new(message: impl Into<String>) -> Self {
        Self::ExecutionFailed {
            kind: ExecutionFailureKind::Unknown,
            message: message.into(),
        }
    }

    /// Attaches a remediation suggestion while preserving the original error kind.
    pub fn suggestion(self, suggestion: impl Into<String>) -> Self {
        Self::WithSuggestion {
            error: Box::new(self),
            suggestion: Some(suggestion.into()),
        }
    }

    /// Returns the remediation suggestion attached to this error, if any.
    pub fn suggestion_text(&self) -> Option<&str> {
        match self {
            Self::WithSuggestion {
                error, suggestion, ..
            } => suggestion.as_deref().or_else(|| error.suggestion_text()),
            _ => None,
        }
    }

    /// Splits a suggested error into its base error and suggestion.
    pub fn into_base_and_suggestion(self) -> (Self, Option<String>) {
        match self {
            Self::WithSuggestion {
                error, suggestion, ..
            } => {
                let (error, nested_suggestion) = error.into_base_and_suggestion();
                (error, suggestion.or(nested_suggestion))
            }
            error => (error, None),
        }
    }
}

/// Sandbox lifecycle trait.
///
/// Each backend implements this trait to provide unified creation, execution,
/// file transfer, snapshot, and destruction capabilities.
///
/// Most users should use `mimobox_sdk::Sandbox` instead of implementing
/// this trait directly.
///
/// # Examples
///
/// ```rust,ignore
/// use mimobox_core::{Sandbox, SandboxConfig};
/// use mimobox_os::LinuxSandbox;
///
/// let mut sandbox = LinuxSandbox::new(SandboxConfig::default())?;
/// let result = sandbox.execute(&["/bin/echo".into(), "hello".into()])?;
/// assert_eq!(result.exit_code, Some(0));
/// sandbox.destroy()?;
/// ```
pub trait Sandbox {
    /// Creates a new sandbox instance with the given configuration.
    fn new(config: SandboxConfig) -> Result<Self, SandboxError>
    where
        Self: Sized;

    /// Executes a command inside the sandbox and waits for completion.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use mimobox_core::Sandbox;
    /// use mimobox_os::LinuxSandbox;
    ///
    /// let mut sandbox = LinuxSandbox::new(Default::default())?;
    /// let result = sandbox.execute(&["/bin/echo".into(), "hello".into()])?;
    /// assert_eq!(result.exit_code, Some(0));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError>;

    /// Creates an interactive PTY session.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use mimobox_core::{PtyConfig, PtySize, Sandbox};
    /// use mimobox_os::LinuxSandbox;
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let mut sandbox = LinuxSandbox::new(Default::default())?;
    /// let mut session = sandbox.create_pty(PtyConfig {
    ///     command: vec!["/bin/sh".into()],
    ///     size: PtySize { cols: 80, rows: 24 },
    ///     env: HashMap::new(),
    ///     cwd: None,
    ///     timeout: Some(Duration::from_secs(10)),
    /// })?;
    /// session.send_input(b"echo hello\n")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn create_pty(&mut self, config: PtyConfig) -> Result<Box<dyn PtySession>, SandboxError> {
        let _ = config;
        Err(SandboxError::UnsupportedOperation(
            "PTY sessions not supported by current backend".to_string(),
        ))
    }

    /// Reads file content from inside the sandbox.
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SandboxError> {
        let _ = path;
        Err(SandboxError::new(
            "file reading not supported by current backend",
        ))
    }

    /// Writes file content inside the sandbox.
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SandboxError> {
        let _ = path;
        let _ = data;
        Err(SandboxError::new(
            "file writing not supported by current backend",
        ))
    }

    /// 列出指定路径下的目录条目。
    fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, SandboxError> {
        let _ = path;
        Err(SandboxError::new(
            "list_dir not supported by current backend",
        ))
    }

    /// 检查指定路径的文件是否存在。
    fn file_exists(&mut self, path: &str) -> Result<bool, SandboxError> {
        let _ = path;
        Err(SandboxError::UnsupportedOperation(
            "file_exists not supported by current backend".to_string(),
        ))
    }

    /// 删除指定路径的文件或空目录。
    ///
    /// 注意：不支持递归删除（安全考虑）。
    fn remove_file(&mut self, path: &str) -> Result<(), SandboxError> {
        let _ = path;
        Err(SandboxError::UnsupportedOperation(
            "remove_file not supported by current backend".to_string(),
        ))
    }

    /// 重命名/移动文件。
    fn rename(&mut self, from: &str, to: &str) -> Result<(), SandboxError> {
        let _ = from;
        let _ = to;
        Err(SandboxError::UnsupportedOperation(
            "rename not supported by current backend".to_string(),
        ))
    }

    /// 返回文件的元信息。
    fn stat(&mut self, path: &str) -> Result<FileStat, SandboxError> {
        let _ = path;
        Err(SandboxError::UnsupportedOperation(
            "stat not supported by current backend".to_string(),
        ))
    }

    /// Exports a snapshot of the current sandbox state.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use mimobox_core::Sandbox;
    /// use mimobox_vm::MicrovmSandbox;
    /// use mimobox_vm::MicrovmConfig;
    ///
    /// let mut sandbox = MicrovmSandbox::new(MicrovmConfig::default())?;
    /// let snapshot = sandbox.snapshot()?;
    /// assert!(!snapshot.to_bytes()?.is_empty());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn snapshot(&mut self) -> Result<SandboxSnapshot, SandboxError> {
        Err(SandboxError::UnsupportedOperation(
            "snapshot not supported by current backend".to_string(),
        ))
    }

    /// Forks an independent copy from the current sandbox.
    ///
    /// Returns `UnsupportedOperation` by default; only the microVM backend supports this operation.
    fn fork(&mut self) -> Result<Self, SandboxError>
    where
        Self: Sized,
    {
        Err(SandboxError::UnsupportedOperation(
            "fork not supported by current backend".to_string(),
        ))
    }

    /// Destroys the sandbox and releases underlying resources.
    fn destroy(self) -> Result<(), SandboxError>;
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{MAX_MEMORY_LIMIT_MB, PtySize, SandboxConfig, SandboxError, SandboxSnapshot};

    #[test]
    fn pty_size_default_is_80x24() {
        assert_eq!(PtySize::default(), PtySize { cols: 80, rows: 24 });
    }

    #[test]
    fn sandbox_config_allows_denied_network_with_http_proxy_whitelist() {
        let mut config = SandboxConfig::default();
        config.deny_network = true;
        config.allowed_http_domains = vec!["api.openai.com".to_string()];

        config
            .validate()
            .expect("受控 HTTP 代理白名单不应打开沙箱直连网络");
    }

    #[test]
    fn sandbox_config_rejects_memory_limit_above_global_max() {
        let mut config = SandboxConfig::default();
        config.memory_limit_mb = Some(MAX_MEMORY_LIMIT_MB + 1);

        let error = config
            .validate()
            .expect_err("超过全局上限的 memory_limit_mb 必须被拒绝");

        assert_eq!(
            error.suggestion_text(),
            Some("memory_limit_mb 最大值为 32768")
        );
        let (error, _) = error.into_base_and_suggestion();
        assert!(
            matches!(error, SandboxError::ExecutionFailed { message, .. } if message.contains("memory_limit_mb"))
        );
    }

    #[test]
    fn sandbox_snapshot_round_trip_preserves_bytes() {
        let original = vec![0x4d, 0x4d, 0x42, 0x58, 0x01, 0x02];

        let snapshot =
            SandboxSnapshot::from_owned_bytes(original.clone()).expect("快照创建必须成功");

        assert_eq!(
            snapshot.as_bytes().expect("内存快照必须可读取字节"),
            original.as_slice()
        );
        assert_eq!(
            snapshot.to_bytes().expect("内存快照必须可复制字节"),
            original
        );
        assert_eq!(snapshot.size(), 6);
    }

    #[test]
    fn sandbox_snapshot_rejects_empty_bytes() {
        let error = SandboxSnapshot::from_bytes(&[]).expect_err("空快照必须被拒绝");

        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn sandbox_snapshot_file_mode_exposes_metadata_only() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系统时间必须晚于 UNIX_EPOCH")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mimobox-sandbox-snapshot-{}-{}.bin",
            std::process::id(),
            unique
        ));

        fs::write(&path, b"file-backed-snapshot").expect("测试快照文件写入必须成功");

        let snapshot = SandboxSnapshot::from_file(path.clone()).expect("文件快照创建必须成功");

        assert_eq!(snapshot.memory_file_path(), Some(path.as_path()));
        assert_eq!(snapshot.size(), b"file-backed-snapshot".len());
        assert!(matches!(
            snapshot.as_bytes().expect_err("文件快照不应暴露内存字节"),
            SandboxError::InvalidSnapshot
        ));
        assert_eq!(
            snapshot.to_bytes().expect("文件快照必须可读回字节"),
            b"file-backed-snapshot"
        );
        assert_eq!(
            snapshot
                .clone()
                .into_bytes()
                .expect("文件快照必须可转移为字节"),
            b"file-backed-snapshot"
        );

        fs::remove_file(path).expect("测试快照文件清理必须成功");
    }
}
