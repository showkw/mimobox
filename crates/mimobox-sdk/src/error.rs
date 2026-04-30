use mimobox_core::ErrorCode;

/// SDK error type.
///
/// All errors produced by the mimobox SDK fall into one of four categories:
///
/// - **`Sandbox`**: Structured errors from validation or the sandbox backend with a stable
///   [`ErrorCode`], human-readable message, and optional suggestion.
/// - **`BackendUnavailable`**: The required backend feature (e.g., `vm`, `wasm`)
///   is not enabled in the current build.
/// - **`Config`**: Invalid SDK configuration or malformed input.
/// - **`Io`**: Standard library I/O errors propagated from the OS.
///
/// # Examples
///
/// ```rust,no_run
/// use mimobox_sdk::Sandbox;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sandbox = Sandbox::new()?;
/// let result = sandbox.execute("/nonexistent/command");
/// match result {
///     Err(e) => println!("error: {e}"),
///     Ok(_) => println!("success"),
/// }
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    /// Structured error from the sandbox backend.
    ///
    /// Contains a stable [`ErrorCode`] for programmatic matching, a human-readable
    /// message describing what went wrong, and an optional suggestion for how to
    /// resolve the error.
    #[error("[{code_str}] {message}", code_str = code.as_str())]
    Sandbox {
        /// Stable, normalized error code for cross-language transport and log indexing.
        code: ErrorCode,
        /// Primary error message for the caller.
        message: String,
        /// Suggested action the caller can take to resolve the error.
        suggestion: Option<String>,
    },

    /// The required backend feature is not enabled in the current build.
    ///
    /// Enable the corresponding Cargo feature (e.g., `vm`, `wasm`, `os`) to resolve.
    #[error("backend unavailable: {0} (enable the corresponding feature)")]
    BackendUnavailable(&'static str),

    /// Invalid SDK configuration or internal state.
    #[error("config error: {0}")]
    Config(String),

    /// Standard library I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl SdkError {
    /// Constructs a structured sandbox error with code, message, and optional suggestion.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::SdkError;
    /// use mimobox_core::ErrorCode;
    ///
    /// let err = SdkError::sandbox(
    ///     ErrorCode::CommandTimeout,
    ///     "command timed out",
    ///     Some("increase Config.timeout".to_string()),
    /// );
    /// ```
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

    /// Constructs a structured invalid configuration error with an optional suggestion.
    pub fn invalid_config(message: impl Into<String>, suggestion: Option<String>) -> Self {
        Self::sandbox(ErrorCode::InvalidConfig, message, suggestion)
    }

    /// Maps a core configuration error to a structured SDK invalid-config error.
    pub fn from_core_config_error(err: mimobox_core::SandboxError) -> Self {
        let (err, suggestion) = err.into_base_and_suggestion();
        match err {
            mimobox_core::SandboxError::Config { message }
            | mimobox_core::SandboxError::Other { message } => {
                Self::sandbox(ErrorCode::InvalidConfig, message, suggestion)
            }
            mimobox_core::SandboxError::SecurityPolicy { message } => {
                Self::sandbox(ErrorCode::SecurityPolicyViolation, message, suggestion)
            }
            mimobox_core::SandboxError::ResourceExhausted { message } => {
                Self::sandbox(ErrorCode::ResourceExhausted, message, suggestion)
            }
            other => Self::sandbox(ErrorCode::InvalidConfig, other.to_string(), suggestion),
        }
    }

    /// Maps an execution-phase `SandboxError` to an SDK error.
    pub fn from_sandbox_execute_error(err: mimobox_core::SandboxError) -> Self {
        let (err, core_suggestion) = err.into_base_and_suggestion();
        match err {
            mimobox_core::SandboxError::Unsupported => Self::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                message: "sandbox backend not supported on current platform".into(),
                suggestion: core_suggestion
                    .or_else(|| Some("set isolation to `Os` or use default Auto".into())),
            },
            mimobox_core::SandboxError::UnsupportedOperation(message) => Self::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                message,
                suggestion: core_suggestion
                    .or_else(|| Some("set isolation to `Os` or use default Auto".into())),
            },
            mimobox_core::SandboxError::Config { message } => Self::Sandbox {
                code: ErrorCode::InvalidConfig,
                message,
                suggestion: core_suggestion,
            },
            mimobox_core::SandboxError::SecurityPolicy { message } => Self::Sandbox {
                code: ErrorCode::SecurityPolicyViolation,
                message,
                suggestion: core_suggestion,
            },
            mimobox_core::SandboxError::ResourceExhausted { message } => Self::Sandbox {
                code: ErrorCode::ResourceExhausted,
                message,
                suggestion: core_suggestion,
            },
            mimobox_core::SandboxError::Timeout => Self::Sandbox {
                code: ErrorCode::CommandTimeout,
                message: "command execution timed out".into(),
                suggestion: core_suggestion
                    .or_else(|| Some("increase Config.timeout or per-command timeout".into())),
            },
            mimobox_core::SandboxError::ExecutionFailed { kind, message } => {
                let code = match kind {
                    mimobox_core::ExecutionFailureKind::Oom => ErrorCode::MemoryLimitExceeded,
                    mimobox_core::ExecutionFailureKind::CpuLimit => ErrorCode::CpuLimitExceeded,
                    _ => {
                        let msg_lower = message.to_lowercase();
                        if msg_lower.contains("oom")
                            || msg_lower.contains("memory")
                            || msg_lower.contains("memory_limit")
                            || msg_lower.contains("out of memory")
                        {
                            ErrorCode::MemoryLimitExceeded
                        } else if msg_lower.contains("cpu")
                            || msg_lower.contains("cpu_quota")
                            || msg_lower.contains("cpu_limit")
                        {
                            ErrorCode::CpuLimitExceeded
                        } else {
                            ErrorCode::CommandKilled
                        }
                    }
                };
                let suggestion = match &code {
                    ErrorCode::MemoryLimitExceeded => "Increase Config.memory_limit_mb or optimize the command's memory usage.".to_string(),
                    ErrorCode::CpuLimitExceeded => "Increase Config.cpu_quota_us or optimize the command's CPU usage.".to_string(),
                    _ => "Command may have been killed due to seccomp policy or invalid input. Check sandbox resource limits.".to_string(),
                };
                Self::Sandbox {
                    code,
                    message,
                    suggestion: core_suggestion.or(Some(suggestion)),
                }
            }
            mimobox_core::SandboxError::Other { message } => {
                let msg_lower = message.to_lowercase();
                let code = if msg_lower.contains("timeout") || msg_lower.contains("timed out") {
                    ErrorCode::CommandTimeout
                } else {
                    ErrorCode::SandboxCreateFailed
                };
                let suggestion = match code {
                    ErrorCode::CommandTimeout => {
                        "Increase Config.timeout or per-command timeout".to_string()
                    }
                    _ => "Check sandbox logs and backend diagnostics for the unclassified failure."
                        .to_string(),
                };
                Self::Sandbox {
                    code,
                    message,
                    suggestion: core_suggestion.or(Some(suggestion)),
                }
            }
            other => Self::Sandbox {
                code: ErrorCode::SandboxCreateFailed,
                message: other.to_string(),
                suggestion: core_suggestion.or_else(|| {
                    Some(
                        "For microVM: verify /dev/kvm exists. Use isolation='os' as fallback."
                            .to_string(),
                    )
                }),
            },
        }
    }

    /// Maps a creation-phase `SandboxError` to an SDK error.
    pub fn from_sandbox_create_error(err: mimobox_core::SandboxError) -> Self {
        let (err, core_suggestion) = err.into_base_and_suggestion();
        match err {
            mimobox_core::SandboxError::Unsupported => Self::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                message: "sandbox backend not supported on current platform".into(),
                suggestion: core_suggestion
                    .or_else(|| Some("set isolation to `Os` or use default Auto".into())),
            },
            mimobox_core::SandboxError::UnsupportedOperation(message) => Self::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                message,
                suggestion: core_suggestion
                    .or_else(|| Some("set isolation to `Os` or use default Auto".into())),
            },
            mimobox_core::SandboxError::Config { message } => Self::Sandbox {
                code: ErrorCode::InvalidConfig,
                message,
                suggestion: core_suggestion,
            },
            mimobox_core::SandboxError::SecurityPolicy { message } => Self::Sandbox {
                code: ErrorCode::SecurityPolicyViolation,
                message,
                suggestion: core_suggestion,
            },
            mimobox_core::SandboxError::ResourceExhausted { message } => Self::Sandbox {
                code: ErrorCode::ResourceExhausted,
                message,
                suggestion: core_suggestion,
            },
            other => Self::Sandbox {
                code: ErrorCode::SandboxCreateFailed,
                message: other.to_string(),
                suggestion: core_suggestion.or_else(|| {
                    Some(
                        "verify KVM is available (Linux) or choose a different isolation level"
                            .into(),
                    )
                }),
            },
        }
    }

    /// Maps a destroy-phase `SandboxError` to an SDK error.
    pub fn from_sandbox_destroy_error(err: mimobox_core::SandboxError) -> Self {
        let (err, core_suggestion) = err.into_base_and_suggestion();
        match err {
            mimobox_core::SandboxError::Config { message } => Self::Sandbox {
                code: ErrorCode::InvalidConfig,
                message,
                suggestion: core_suggestion,
            },
            mimobox_core::SandboxError::SecurityPolicy { message } => Self::Sandbox {
                code: ErrorCode::SecurityPolicyViolation,
                message,
                suggestion: core_suggestion,
            },
            mimobox_core::SandboxError::ResourceExhausted { message } => Self::Sandbox {
                code: ErrorCode::ResourceExhausted,
                message,
                suggestion: core_suggestion,
            },
            mimobox_core::SandboxError::Other { message } => Self::Sandbox {
                code: ErrorCode::SandboxDestroyed,
                message,
                suggestion: core_suggestion.or_else(|| {
                    Some(
                        "Create a new sandbox instance. Sandbox objects cannot be reused after close()."
                            .to_string(),
                    )
                }),
            },
            other => Self::Sandbox {
                code: ErrorCode::SandboxDestroyed,
                message: other.to_string(),
                suggestion: core_suggestion.or_else(|| {
                    Some(
                        "Create a new sandbox instance. Sandbox objects cannot be reused after close()."
                            .to_string(),
                    )
                }),
            },
        }
    }

    /// Constructs a "backend unavailable" error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mimobox_sdk::SdkError;
    ///
    /// let err = SdkError::unsupported_backend("microvm");
    /// assert!(matches!(err, SdkError::BackendUnavailable("microvm")));
    /// ```
    pub fn unsupported_backend(msg: &'static str) -> Self {
        Self::BackendUnavailable(msg)
    }

    /// Constructs an SDK internal configuration error.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

impl From<mimobox_core::SandboxError> for SdkError {
    fn from(err: mimobox_core::SandboxError) -> Self {
        Self::from_sandbox_execute_error(err)
    }
}

#[cfg(test)]
mod tests {
    use super::SdkError;
    use mimobox_core::{ErrorCode, ExecutionFailureKind, SandboxError};

    #[test]
    fn execution_failed_maps_to_command_killed_and_preserves_message() {
        let error = SdkError::from_sandbox_execute_error(SandboxError::ExecutionFailed {
            kind: ExecutionFailureKind::Unknown,
            message: "process killed by seccomp".to_string(),
        });

        match error {
            SdkError::Sandbox {
                code,
                message,
                suggestion,
            } => {
                assert_eq!(code, ErrorCode::CommandKilled);
                assert_eq!(message, "process killed by seccomp");
                assert!(
                    suggestion.is_some(),
                    "suggestion should be populated for CommandKilled"
                );
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }

    #[test]
    fn execution_failed_with_oom_maps_to_memory_limit_exceeded() {
        let error = SdkError::from_sandbox_execute_error(SandboxError::ExecutionFailed {
            kind: ExecutionFailureKind::Unknown,
            message: "process killed by OOM killer".to_string(),
        });
        match error {
            SdkError::Sandbox { code, .. } => {
                assert_eq!(code, ErrorCode::MemoryLimitExceeded);
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }

    #[test]
    fn execution_failed_with_cpu_maps_to_cpu_limit_exceeded() {
        let error = SdkError::from_sandbox_execute_error(SandboxError::ExecutionFailed {
            kind: ExecutionFailureKind::Unknown,
            message: "cpu_quota exceeded".to_string(),
        });
        match error {
            SdkError::Sandbox { code, .. } => {
                assert_eq!(code, ErrorCode::CpuLimitExceeded);
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }

    #[test]
    fn execution_failed_with_structured_oom_maps_to_memory_limit_exceeded() {
        let error = SdkError::from_sandbox_execute_error(SandboxError::ExecutionFailed {
            kind: ExecutionFailureKind::Oom,
            message: "process killed".to_string(),
        });

        match error {
            SdkError::Sandbox { code, .. } => {
                assert_eq!(code, ErrorCode::MemoryLimitExceeded);
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }

    #[test]
    fn execution_failed_with_structured_cpu_maps_to_cpu_limit_exceeded() {
        let error = SdkError::from_sandbox_execute_error(SandboxError::ExecutionFailed {
            kind: ExecutionFailureKind::CpuLimit,
            message: "process stopped".to_string(),
        });

        match error {
            SdkError::Sandbox { code, .. } => {
                assert_eq!(code, ErrorCode::CpuLimitExceeded);
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }

    #[test]
    fn config_maps_to_invalid_config() {
        let error = SdkError::from_sandbox_execute_error(SandboxError::Config {
            message: "bad config".to_string(),
        });

        match error {
            SdkError::Sandbox { code, message, .. } => {
                assert_eq!(code, ErrorCode::InvalidConfig);
                assert_eq!(message, "bad config");
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }

    #[test]
    fn security_policy_maps_to_security_policy_violation() {
        let error = SdkError::from_sandbox_create_error(SandboxError::SecurityPolicy {
            message: "policy denied".to_string(),
        });

        match error {
            SdkError::Sandbox { code, message, .. } => {
                assert_eq!(code, ErrorCode::SecurityPolicyViolation);
                assert_eq!(message, "policy denied");
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }

    #[test]
    fn resource_exhausted_maps_to_resource_exhausted() {
        let error = SdkError::from_core_config_error(SandboxError::ResourceExhausted {
            message: "pool exhausted".to_string(),
        });

        match error {
            SdkError::Sandbox { code, message, .. } => {
                assert_eq!(code, ErrorCode::ResourceExhausted);
                assert_eq!(message, "pool exhausted");
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }

    #[test]
    fn other_maps_to_phase_fallback() {
        let error = SdkError::from_sandbox_destroy_error(SandboxError::new("already gone"));

        match error {
            SdkError::Sandbox { code, message, .. } => {
                assert_eq!(code, ErrorCode::SandboxDestroyed);
                assert_eq!(message, "already gone");
            }
            other => panic!("expected sandbox error, got {other:?}"),
        }
    }
}
