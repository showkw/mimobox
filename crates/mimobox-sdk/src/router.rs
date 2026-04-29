use crate::config::{Config, IsolationLevel, TrustLevel};
use crate::error::SdkError;
#[cfg(not(all(feature = "vm", target_os = "linux")))]
use mimobox_core::ErrorCode;

/// Smart router: automatically selects the best isolation layer by command and trust level.
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

/// Automatic routing logic.
fn auto_route(trust_level: TrustLevel, command: &str) -> Result<IsolationLevel, SdkError> {
    // TrustLevel::Untrusted must be handled before Wasm file detection to prevent .wasm/.wat/.wast
    // from bypassing the microVM fail-closed boundary through lightweight routing.
    if trust_level == TrustLevel::Untrusted {
        return require_microvm_for_untrusted();
    }

    // Prefer Wasm file detection.
    if is_wasm_command(command) {
        #[cfg(feature = "wasm")]
        return Ok(IsolationLevel::Wasm);

        #[cfg(not(feature = "wasm"))]
        {
            // Wasm is unavailable; fall back to OS level.
            tracing::debug!("Wasm backend unavailable, falling back to OS level");
        }
    }

    // Default to OS level.
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
    // SECURITY: Only check the command first token (executable path), so a .wasm suffix in an argument
    // does not cause incorrect routing. For example, "run module.wasm --arg" should not route to the Wasm backend.
    let first_token = command.split_whitespace().next().unwrap_or(command);
    first_token.ends_with(".wasm")
        || first_token.ends_with(".wat")
        || first_token.ends_with(".wast")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "wasm")]
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
        assert_eq!(
            result.expect("trusted shell command should route to OS"),
            IsolationLevel::Os
        );
    }

    #[test]
    fn untrusted_requires_microvm_or_fails_closed() {
        let result = auto_route(TrustLevel::Untrusted, "python script.py");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert_eq!(
            result.expect("untrusted command should route to MicroVm"),
            IsolationLevel::MicroVm
        );

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
            other => panic!("expected structured fail-closed error, got: {other:?}"),
        }
    }

    #[test]
    fn untrusted_wasm_file_does_not_route_to_wasm() {
        let result = auto_route(TrustLevel::Untrusted, "module.wasm");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert_eq!(
            result.expect("untrusted Wasm command should route to MicroVm"),
            IsolationLevel::MicroVm
        );

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
            Ok(IsolationLevel::Wasm) => panic!("Untrusted .wasm should not route to Wasm backend"),
            other => {
                panic!("expected Untrusted .wasm to fail closed or use MicroVm, got: {other:?}")
            }
        }
    }

    #[test]
    fn explicit_microvm_selection_reflects_backend_availability() {
        let config = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .build()
            .expect("valid config");
        let result = resolve_isolation(&config, "python script.py");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert_eq!(
            result.expect("explicit MicroVm should resolve when backend is available"),
            IsolationLevel::MicroVm
        );

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(matches!(
            result,
            Err(SdkError::BackendUnavailable("microvm"))
        ));
    }

    #[test]
    fn is_wasm_detection() {
        assert!(is_wasm_command("app.wasm"));
        assert!(is_wasm_command("path/to/app.wasm"));
        assert!(is_wasm_command("module.wat"));
        assert!(!is_wasm_command("run module.wasm --arg"));
        assert!(!is_wasm_command("app.py"));
        assert!(!is_wasm_command("/bin/echo hello"));
    }
}
