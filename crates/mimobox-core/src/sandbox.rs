use std::path::PathBuf;
use std::time::Duration;

use crate::seccomp::SeccompProfile;

/// 结构化错误码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    // 命令执行
    CommandTimeout,
    CommandExit(i32),
    CommandKilled,
    // 文件操作
    FileNotFound,
    FilePermissionDenied,
    FileTooLarge,
    // HTTP 代理
    HttpDeniedHost,
    HttpTimeout,
    HttpBodyTooLarge,
    HttpConnectFail,
    HttpTlsFail,
    HttpInvalidUrl,
    // 生命周期
    SandboxNotReady,
    SandboxDestroyed,
    SandboxCreateFailed,
    // 配置
    InvalidConfig,
    UnsupportedPlatform,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
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
        }
    }
}

/// 沙箱配置
#[derive(Clone)]
pub struct SandboxConfig {
    /// 只读路径列表
    pub fs_readonly: Vec<PathBuf>,
    /// 读写路径列表
    pub fs_readwrite: Vec<PathBuf>,
    /// 是否拒绝网络访问
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

/// 沙箱执行结果
#[derive(Debug)]
pub struct SandboxResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub elapsed: Duration,
    /// 是否因超时被终止
    pub timed_out: bool,
}

/// 沙箱错误类型
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("当前平台不支持该沙箱后端")]
    Unsupported,

    #[error("命名空间创建失败: {0}")]
    NamespaceFailed(String),

    #[error("pivot_root 失败: {0}")]
    PivotRootFailed(String),

    #[error("mount 失败: {0}")]
    MountFailed(String),

    #[error("Landlock 规则应用失败: {0}")]
    LandlockFailed(String),

    #[error("Seccomp 过滤器应用失败: {0}")]
    SeccompFailed(String),

    #[error("命令执行失败: {0}")]
    ExecutionFailed(String),

    #[error("子进程超时")]
    Timeout,

    #[error("管道 I/O 错误: {0}")]
    PipeError(String),

    #[error("系统调用错误: {0}")]
    Syscall(String),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

/// 沙箱 trait
pub trait Sandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError>
    where
        Self: Sized;
    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError>;
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SandboxError> {
        let _ = path;
        Err(SandboxError::ExecutionFailed(
            "当前后端不支持文件读取".into(),
        ))
    }
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SandboxError> {
        let _ = path;
        let _ = data;
        Err(SandboxError::ExecutionFailed(
            "当前后端不支持文件写入".into(),
        ))
    }
    fn destroy(self) -> Result<(), SandboxError>;
}
