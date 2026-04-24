use mimobox_core::ErrorCode;

/// SDK 错误类型
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    /// 来自底层沙箱后端的结构化错误。
    #[error("[{code_str}] {message}", code_str = code.as_str())]
    Sandbox {
        /// 归一化后的稳定错误码。
        code: ErrorCode,
        /// 面向调用方的主错误信息。
        message: String,
        /// 建议调用方采取的修复动作。
        suggestion: Option<String>,
    },

    /// 当前构建未启用所需后端 feature。
    #[error("后端不可用: {0}（请启用对应 feature）")]
    BackendUnavailable(&'static str),

    /// SDK 配置或内部状态不合法。
    #[error("配置错误: {0}")]
    Config(String),

    /// 来自标准库的 I/O 错误。
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

impl SdkError {
    /// 构造带错误码和建议的沙箱错误。
    pub fn sandbox(
        code: ErrorCode,
        message: impl Into<String>,
        suggestion: Option<String>,
    ) -> Self {
        Self::Sandbox {
            code,
            message: message.into(),
            suggestion,
        }
    }

    /// 将执行阶段的 `SandboxError` 映射为 SDK 错误。
    pub fn from_sandbox_execute_error(err: mimobox_core::SandboxError) -> Self {
        match err {
            mimobox_core::SandboxError::UnsupportedOperation(message) => Self::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                message,
                suggestion: Some("将 isolation 设置为 `Os` 或使用默认 Auto".into()),
            },
            mimobox_core::SandboxError::Timeout => Self::Sandbox {
                code: ErrorCode::CommandTimeout,
                message: "命令执行超时".into(),
                suggestion: Some("增大 Config.timeout 或命令级 timeout 参数".into()),
            },
            mimobox_core::SandboxError::ExecutionFailed(msg) => Self::Sandbox {
                code: ErrorCode::CommandExit(1),
                message: msg,
                suggestion: None,
            },
            other => Self::Sandbox {
                code: ErrorCode::SandboxCreateFailed,
                message: other.to_string(),
                suggestion: None,
            },
        }
    }

    /// 将创建阶段的 `SandboxError` 映射为 SDK 错误。
    pub fn from_sandbox_create_error(err: mimobox_core::SandboxError) -> Self {
        match err {
            mimobox_core::SandboxError::UnsupportedOperation(message) => Self::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                message,
                suggestion: Some("将 isolation 设置为 `Os` 或使用默认 Auto".into()),
            },
            other => Self::Sandbox {
                code: ErrorCode::SandboxCreateFailed,
                message: other.to_string(),
                suggestion: Some("检查 KVM 是否可用（Linux）或选择其他隔离层级".into()),
            },
        }
    }

    /// 将销毁阶段的 `SandboxError` 映射为 SDK 错误。
    pub fn from_sandbox_destroy_error(err: mimobox_core::SandboxError) -> Self {
        Self::Sandbox {
            code: ErrorCode::SandboxDestroyed,
            message: err.to_string(),
            suggestion: None,
        }
    }

    /// 构造“后端不可用”错误。
    pub fn unsupported_backend(msg: &'static str) -> Self {
        Self::BackendUnavailable(msg)
    }

    /// 构造 SDK 内部配置错误。
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

impl From<mimobox_core::SandboxError> for SdkError {
    fn from(err: mimobox_core::SandboxError) -> Self {
        Self::from_sandbox_execute_error(err)
    }
}
