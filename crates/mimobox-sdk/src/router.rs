use crate::config::{Config, IsolationLevel, TrustLevel};
use crate::error::SdkError;

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

    // 不可信代码优先走 microVM；若当前构建或平台不支持，则 fallback 到 OS 级。
    if trust_level == TrustLevel::Untrusted {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        return Ok(IsolationLevel::MicroVm);

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        tracing::warn!(
            "Untrusted 代码建议使用 microVM 隔离，当前 fallback 到 OS 级（隔离强度较低）"
        );
    }

    // 默认走 OS 级
    #[cfg(feature = "os")]
    return Ok(IsolationLevel::Os);

    #[cfg(not(feature = "os"))]
    return Err(SdkError::BackendUnavailable("os"));
}

fn is_wasm_command(command: &str) -> bool {
    command.ends_with(".wasm") || command.ends_with(".wat") || command.ends_with(".wast")
}

#[cfg(test)]
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
    fn untrusted_prefers_microvm_when_available() {
        let result = auto_route(TrustLevel::Untrusted, "python script.py");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert_eq!(result.unwrap(), IsolationLevel::MicroVm);

        #[cfg(all(not(all(feature = "vm", target_os = "linux")), feature = "os"))]
        assert_eq!(result.unwrap(), IsolationLevel::Os);

        #[cfg(not(any(all(feature = "vm", target_os = "linux"), feature = "os")))]
        assert!(matches!(result, Err(SdkError::BackendUnavailable("os"))));
    }

    #[test]
    fn explicit_microvm_selection_reflects_backend_availability() {
        let config = Config::builder().isolation(IsolationLevel::MicroVm).build();
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
