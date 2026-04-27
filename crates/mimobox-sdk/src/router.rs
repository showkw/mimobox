use crate::config::{Config, IsolationLevel, TrustLevel};
use crate::error::SdkError;
#[cfg(not(all(feature = "vm", target_os = "linux")))]
use mimobox_core::ErrorCode;

/// 智能路由器：根据命令内容和信任级别自动选择最优隔离层级
pub(crate) fn resolve_isolation(
    config: &Config,
    command: &str,
) -> Result<IsolationLevel, SdkError> {
    match config.isolation {
        IsolationLevel::Auto => auto_route(config.trust_level, command),
        IsolationLevel::Os => {
            #[cfg(not(feature = "os"))]
            {
                Err(SdkError::BackendUnavailable("os"))
            }
            #[cfg(feature = "os")]
            {
                Ok(IsolationLevel::Os)
            }
        }
        IsolationLevel::Wasm => {
            #[cfg(not(feature = "wasm"))]
            {
                Err(SdkError::BackendUnavailable("wasm"))
            }
            #[cfg(feature = "wasm")]
            {
                Ok(IsolationLevel::Wasm)
            }
        }
        IsolationLevel::MicroVm => {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            {
                Ok(IsolationLevel::MicroVm)
            }
            #[cfg(not(all(feature = "vm", target_os = "linux")))]
            {
                Err(SdkError::BackendUnavailable("microvm"))
            }
        }
    }
}

/// 自动路由逻辑
fn auto_route(trust_level: TrustLevel, command: &str) -> Result<IsolationLevel, SdkError> {
    // TrustLevel::Untrusted 必须先于 Wasm 文件检测处理，避免 .wasm/.wat/.wast
    // 通过轻量 Wasm 路由绕过 microVM 的 fail-closed 边界。
    if trust_level == TrustLevel::Untrusted {
        return require_microvm_for_untrusted();
    }

    // 优先检测 Wasm 文件
    if is_wasm_command(command) {
        #[cfg(feature = "wasm")]
        return Ok(IsolationLevel::Wasm);

        #[cfg(not(feature = "wasm"))]
        {
            // Wasm 不可用，fallback 到 OS 级
            tracing::debug!("Wasm 后端不可用，fallback 到 OS 级");
        }
    }

    // 默认走 OS 级
    #[cfg(feature = "os")]
    return Ok(IsolationLevel::Os);

    #[cfg(not(feature = "os"))]
    return Err(SdkError::BackendUnavailable("os"));
}

fn require_microvm_for_untrusted() -> Result<IsolationLevel, SdkError> {
    #[cfg(all(feature = "vm", target_os = "linux"))]
    {
        Ok(IsolationLevel::MicroVm)
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    {
        Err(SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            "Untrusted isolation level requires microVM backend, which is not supported on current platform",
            Some("Use IsolationLevel::Os as alternative".to_string()),
        ))
    }
}

fn is_wasm_command(command: &str) -> bool {
    command.ends_with(".wasm") || command.ends_with(".wat") || command.ends_with(".wast")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn wasm_file_routes_to_wasm() {
        let result = auto_route(TrustLevel::Trusted, "app.wasm");
        assert!(matches!(
            result,
            Ok(IsolationLevel::Wasm) | Ok(IsolationLevel::Os)
        ));
    }

    #[test]
    fn shell_command_routes_to_os() {
        let result = auto_route(TrustLevel::Trusted, "/bin/echo hello");
        #[cfg(feature = "os")]
        assert_eq!(result.unwrap(), IsolationLevel::Os);
    }

    #[test]
    fn untrusted_requires_microvm_or_fails_closed() {
        let result = auto_route(TrustLevel::Untrusted, "python script.py");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert_eq!(result.unwrap(), IsolationLevel::MicroVm);

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        match result {
            Err(SdkError::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                message,
                suggestion,
            }) => {
                assert_eq!(
                    message,
                    "Untrusted isolation level requires microVM backend, which is not supported on current platform"
                );
                assert_eq!(
                    suggestion.as_deref(),
                    Some("Use IsolationLevel::Os as alternative")
                );
            }
            other => panic!("期望 fail-closed 的结构化错误，实际为: {other:?}"),
        }
    }

    #[test]
    fn untrusted_wasm_file_does_not_route_to_wasm() {
        let result = auto_route(TrustLevel::Untrusted, "module.wasm");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert_eq!(result.unwrap(), IsolationLevel::MicroVm);

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        match result {
            Err(SdkError::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                message,
                suggestion,
            }) => {
                assert_eq!(
                    message,
                    "Untrusted isolation level requires microVM backend, which is not supported on current platform"
                );
                assert_eq!(
                    suggestion.as_deref(),
                    Some("Use IsolationLevel::Os as alternative")
                );
            }
            Ok(IsolationLevel::Wasm) => panic!("Untrusted .wasm 不应路由到 Wasm 后端"),
            other => panic!("期望 Untrusted .wasm fail-closed 或进入 MicroVm，实际为: {other:?}"),
        }
    }

    #[test]
    fn explicit_microvm_selection_reflects_backend_availability() {
        let config = Config::builder().isolation(IsolationLevel::MicroVm).build().expect("valid config");
        let result = resolve_isolation(&config, "python script.py");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert_eq!(result.unwrap(), IsolationLevel::MicroVm);

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(matches!(
            result,
            Err(SdkError::BackendUnavailable("microvm"))
        ));
    }

    #[test]
    fn is_wasm_detection() {
        assert!(is_wasm_command("app.wasm"));
        assert!(is_wasm_command("module.wat"));
        assert!(!is_wasm_command("app.py"));
        assert!(!is_wasm_command("/bin/echo hello"));
    }
}
