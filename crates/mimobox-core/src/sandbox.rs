use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crate::seccomp::SeccompProfile;

/// 结构化错误码。
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// 命令执行超过超时时间。
    CommandTimeout,
    /// 命令以非零状态码退出。
    CommandExit(i32),
    /// 命令被宿主侧强制终止。
    CommandKilled,
    /// 目标文件不存在。
    FileNotFound,
    /// 目标文件缺少访问权限。
    FilePermissionDenied,
    /// 目标文件或传输内容超出大小限制。
    FileTooLarge,
    /// HTTP 代理访问的域名不在白名单内。
    HttpDeniedHost,
    /// HTTP 代理请求超时。
    HttpTimeout,
    /// HTTP 响应体超过允许大小。
    HttpBodyTooLarge,
    /// HTTP 代理建立连接失败。
    HttpConnectFail,
    /// HTTP 代理 TLS 握手失败。
    HttpTlsFail,
    /// HTTP 请求 URL 非法。
    HttpInvalidUrl,
    /// 沙箱尚未进入可执行状态。
    SandboxNotReady,
    /// 沙箱已销毁，不能再复用。
    SandboxDestroyed,
    /// 沙箱创建流程失败。
    SandboxCreateFailed,
    /// 传入配置不合法。
    InvalidConfig,
    /// 当前平台或后端不支持该能力。
    UnsupportedPlatform,
}

impl ErrorCode {
    /// 返回稳定的字符串错误码，便于跨语言传输和日志检索。
    pub fn as_str(&self) -> &'static str {
        #[allow(unreachable_patterns)]
        match self {
            Self::CommandTimeout => "command_timeout",
            Self::CommandExit(_) => "command_exit",
            Self::CommandKilled => "command_killed",
            Self::FileNotFound => "file_not_found",
            Self::FilePermissionDenied => "file_permission_denied",
            Self::FileTooLarge => "file_too_large",
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
            _ => "unknown_error",
        }
    }
}

/// 沙箱配置。
///
/// 该配置描述所有后端共享的最小能力集合，包括文件系统权限、网络策略、
/// 资源限制和受控 HTTP 代理白名单。
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxConfig {
    /// 只读路径列表
    pub fs_readonly: Vec<PathBuf>,
    /// 读写路径列表
    pub fs_readwrite: Vec<PathBuf>,
    /// 是否拒绝沙箱内进程的直接网络访问
    pub deny_network: bool,
    /// 内存限制 (MB) — 通过 cgroups v2 或 setrlimit 实施
    pub memory_limit_mb: Option<u64>,
    /// 超时时间 (秒)
    pub timeout_secs: Option<u64>,
    /// Seccomp 过滤策略
    pub seccomp_profile: SeccompProfile,
    /// 是否允许沙箱内进程创建子进程（fork/clone）
    /// 默认 false，仅 shell 等需要子进程的场景设为 true
    pub allow_fork: bool,
    /// HTTP 代理允许的域名白名单（支持通配符如 *.openai.com）
    /// 即使 `deny_network = true`，仍可通过受控代理访问这些域名
    pub allowed_http_domains: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            fs_readonly: vec![
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/bin".into(),
                "/sbin".into(),
                "/dev".into(),
                "/proc".into(),
                "/etc".into(),
            ],
            fs_readwrite: vec!["/tmp".into()],
            deny_network: true,
            memory_limit_mb: Some(512),
            timeout_secs: Some(30),
            seccomp_profile: SeccompProfile::Essential,
            allow_fork: false,
            allowed_http_domains: Vec::new(),
        }
    }
}

/// 沙箱执行结果。
#[derive(Debug)]
pub struct SandboxResult {
    /// 标准输出内容。
    pub stdout: Vec<u8>,
    /// 标准错误输出内容。
    pub stderr: Vec<u8>,
    /// 子进程退出码；若进程未正常退出则可能为 `None`。
    pub exit_code: Option<i32>,
    /// 本次执行消耗的总时长。
    pub elapsed: Duration,
    /// 是否因超时被终止
    pub timed_out: bool,
}

/// 沙箱快照内部存储。
///
/// 该枚举支持两种快照承载模式：
/// 1. 直接以内存字节形式保存快照内容；
/// 2. 仅保存快照文件路径与大小，由外部按文件方式管理真实数据。
#[derive(Debug, Clone, PartialEq, Eq)]
enum SnapshotInner {
    /// 内存中的快照字节。
    Bytes(Vec<u8>),
    /// 文件形式保存的快照引用。
    File {
        /// 快照文件路径。
        path: PathBuf,
        /// 快照文件大小（字节）。
        size: usize,
    },
}

/// 沙箱快照。
///
/// 该类型负责承载后端生成的快照句柄，不解析内部格式。
/// 当前支持内存字节和文件引用两种存储模式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSnapshot {
    inner: SnapshotInner,
}

impl SandboxSnapshot {
    /// 从原始字节创建快照。
    pub fn from_bytes(data: &[u8]) -> Result<Self, SandboxError> {
        if data.is_empty() {
            return Err(SandboxError::ExecutionFailed(
                "快照数据不能为空".to_string(),
            ));
        }

        Ok(Self {
            inner: SnapshotInner::Bytes(data.to_vec()),
        })
    }

    /// 从已拥有所有权的字节创建快照，避免额外复制。
    pub fn from_owned_bytes(data: Vec<u8>) -> Result<Self, SandboxError> {
        if data.is_empty() {
            return Err(SandboxError::ExecutionFailed(
                "快照数据不能为空".to_string(),
            ));
        }

        Ok(Self {
            inner: SnapshotInner::Bytes(data),
        })
    }

    /// 从快照文件创建快照引用。
    ///
    /// 该构造函数只记录路径和文件大小，不会把文件内容读入内存。
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

    /// 返回内存文件路径。
    ///
    /// 当快照由文件承载时返回对应路径，否则返回 `None`。
    pub fn memory_file_path(&self) -> Option<&Path> {
        match &self.inner {
            SnapshotInner::Bytes(_) => None,
            SnapshotInner::File { path, .. } => Some(path.as_path()),
        }
    }

    /// 返回快照字节切片，避免不必要拷贝。
    ///
    /// 仅内存模式支持该操作；文件模式会返回错误。
    pub fn as_bytes(&self) -> Result<&[u8], SandboxError> {
        match &self.inner {
            SnapshotInner::Bytes(data) => Ok(data.as_slice()),
            SnapshotInner::File { .. } => Err(SandboxError::InvalidSnapshot),
        }
    }

    /// 序列化为字节副本。
    ///
    /// 文件模式会从磁盘重新读取文件内容。
    pub fn to_bytes(&self) -> Result<Vec<u8>, SandboxError> {
        match &self.inner {
            SnapshotInner::Bytes(data) => Ok(data.clone()),
            SnapshotInner::File { path, .. } => std::fs::read(path).map_err(Into::into),
        }
    }

    /// 消费快照并返回底层字节，避免额外复制。
    ///
    /// 文件模式会从磁盘重新读取文件内容。
    pub fn into_bytes(self) -> Result<Vec<u8>, SandboxError> {
        match self.inner {
            SnapshotInner::Bytes(data) => Ok(data),
            SnapshotInner::File { path, .. } => std::fs::read(path).map_err(Into::into),
        }
    }

    /// 返回快照大小（字节）。
    pub fn size(&self) -> usize {
        match &self.inner {
            SnapshotInner::Bytes(data) => data.len(),
            SnapshotInner::File { size, .. } => *size,
        }
    }
}

/// PTY 终端尺寸
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    /// 终端列数。
    pub cols: u16,
    /// 终端行数。
    pub rows: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// PTY 会话事件
#[derive(Debug)]
pub enum PtyEvent {
    /// 终端输出数据
    Output(Vec<u8>),
    /// 进程退出
    Exit(i32),
}

/// PTY 会话配置
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// 启动 PTY 会话时执行的命令及参数。
    pub command: Vec<String>,
    /// 初始终端尺寸。
    pub size: PtySize,
    /// 额外注入到会话中的环境变量。
    pub env: std::collections::HashMap<String, String>,
    /// 会话工作目录。
    pub cwd: Option<String>,
    /// 会话超时时间。
    pub timeout: Option<Duration>,
}

/// PTY 会话 trait
pub trait PtySession {
    /// 向终端发送输入（stdin）
    fn send_input(&mut self, data: &[u8]) -> Result<(), SandboxError>;
    /// 调整终端尺寸
    fn resize(&mut self, size: PtySize) -> Result<(), SandboxError>;
    /// 获取输出事件接收端
    fn output_rx(&self) -> &Receiver<PtyEvent>;
    /// 终止会话
    fn kill(&mut self) -> Result<(), SandboxError>;
    /// 等待进程退出，返回 exit code
    fn wait(&mut self) -> Result<i32, SandboxError>;
}

/// 沙箱错误类型
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// 当前平台不支持该沙箱实现。
    #[error("当前平台不支持该沙箱后端")]
    Unsupported,

    /// 当前后端不支持指定操作。
    #[error("当前操作不受支持: {0}")]
    UnsupportedOperation(String),

    /// 命名空间初始化失败。
    #[error("命名空间创建失败: {0}")]
    NamespaceFailed(String),

    /// `pivot_root` 调用失败。
    #[error("pivot_root 失败: {0}")]
    PivotRootFailed(String),

    /// 挂载文件系统失败。
    #[error("mount 失败: {0}")]
    MountFailed(String),

    /// Landlock 规则应用失败。
    #[error("Landlock 规则应用失败: {0}")]
    LandlockFailed(String),

    /// Seccomp 规则应用失败。
    #[error("Seccomp 过滤器应用失败: {0}")]
    SeccompFailed(String),

    /// 命令执行或协议处理失败。
    #[error("命令执行失败: {0}")]
    ExecutionFailed(String),

    /// 快照内容或访问模式无效。
    #[error("无效的沙箱快照")]
    InvalidSnapshot,

    /// 子进程执行超时。
    #[error("子进程超时")]
    Timeout,

    /// 管道读写失败。
    #[error("管道 I/O 错误: {0}")]
    PipeError(String),

    /// 系统调用失败。
    #[error("系统调用错误: {0}")]
    Syscall(String),

    /// 标准库 I/O 错误。
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

/// 沙箱生命周期 trait。
///
/// 各后端通过该 trait 提供统一的创建、执行、文件传输、快照和销毁能力。
pub trait Sandbox {
    /// 使用给定配置创建新的沙箱实例。
    fn new(config: SandboxConfig) -> Result<Self, SandboxError>
    where
        Self: Sized;

    /// 在沙箱内执行命令并等待完成。
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

    /// 创建交互式 PTY 会话。
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
            "PTY 会话当前后端不支持".to_string(),
        ))
    }

    /// 读取沙箱内文件内容。
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SandboxError> {
        let _ = path;
        Err(SandboxError::ExecutionFailed(
            "当前后端不支持文件读取".into(),
        ))
    }

    /// 向沙箱内写入文件内容。
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SandboxError> {
        let _ = path;
        let _ = data;
        Err(SandboxError::ExecutionFailed(
            "当前后端不支持文件写入".into(),
        ))
    }

    /// 导出当前沙箱状态快照。
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
            "快照当前后端不支持".to_string(),
        ))
    }

    /// 从当前沙箱 fork 一个独立的副本。
    ///
    /// 默认返回 `UnsupportedOperation`，仅 microVM 后端支持。
    fn fork(&mut self) -> Result<Self, SandboxError>
    where
        Self: Sized,
    {
        Err(SandboxError::UnsupportedOperation(
            "fork 当前后端不支持".to_string(),
        ))
    }

    /// 销毁沙箱并释放底层资源。
    fn destroy(self) -> Result<(), SandboxError>;
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{PtySize, SandboxError, SandboxSnapshot};

    #[test]
    fn pty_size_default_is_80x24() {
        assert_eq!(PtySize::default(), PtySize { cols: 80, rows: 24 });
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

        assert!(error.to_string().contains("不能为空"));
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
