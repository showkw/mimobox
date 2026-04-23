use mimobox_core::ErrorCode;

/// SDK 错误类型
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("[{code_str}] {message}", code_str = code.as_str())]
    Sandbox {
        code: ErrorCode,
        message: String,
        suggestion: Option<String>,
    },

    #[error("后端不可用: {0}（请启用对应 feature）")]
    BackendUnavailable(&'static str),

    #[error("配置错误: {0}")]
    Config(String),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

impl SdkError {
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

    pub fn from_sandbox_destroy_error(err: mimobox_core::SandboxError) -> Self {
        Self::Sandbox {
            code: ErrorCode::SandboxDestroyed,
            message: err.to_string(),
            suggestion: None,
        }
    }

    pub fn unsupported_backend(msg: &'static str) -> Self {
        Self::BackendUnavailable(msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

impl From<mimobox_core::SandboxError> for SdkError {
    fn from(err: mimobox_core::SandboxError) -> Self {
        Self::from_sandbox_execute_error(err)
    }
}
