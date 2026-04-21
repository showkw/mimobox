/// SDK 错误类型
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("后端不可用: {0}（请启用对应 feature）")]
    BackendUnavailable(&'static str),

    #[error("沙箱创建失败: {0}")]
    CreateFailed(String),

    #[error("命令执行失败: {0}")]
    ExecutionFailed(String),

    #[error("沙箱销毁失败: {0}")]
    DestroyFailed(String),

    #[error("配置错误: {0}")]
    Config(String),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

impl From<mimobox_core::SandboxError> for SdkError {
    fn from(err: mimobox_core::SandboxError) -> Self {
        match err {
            mimobox_core::SandboxError::ExecutionFailed(msg) => SdkError::ExecutionFailed(msg),
            other => SdkError::CreateFailed(other.to_string()),
        }
    }
}
