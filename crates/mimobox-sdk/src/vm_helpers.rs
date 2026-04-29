#[cfg(feature = "vm")]
use crate::config::{Config, IsolationLevel};
use crate::error::SdkError;
#[cfg(feature = "vm")]
use crate::router::resolve_isolation;
use crate::sandbox::SandboxInner;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::types::StreamEvent;
use mimobox_core::ErrorCode;
#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use mimobox_core::Sandbox as CoreSandbox;
#[cfg(feature = "vm")]
use mimobox_vm::GuestFileErrorKind;
#[cfg(feature = "vm")]
use std::sync::Arc;
#[cfg(all(feature = "vm", target_os = "linux"))]
use std::sync::mpsc;

pub(crate) fn destroy_backend_inner(inner: SandboxInner) -> Result<(), SdkError> {
    match inner {
        #[cfg(all(feature = "os", target_os = "linux"))]
        SandboxInner::Os(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "os", target_os = "macos"))]
        SandboxInner::OsMac(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::MicroVm(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::PooledMicroVm(pooled) => {
            drop(pooled);
            Ok(())
        }
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::RestoredPooledMicroVm(pooled) => {
            drop(pooled);
            Ok(())
        }
        #[cfg(feature = "wasm")]
        SandboxInner::Wasm(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
    }
}

pub(crate) fn parse_command(command: &str) -> Result<Vec<String>, SdkError> {
    shlex::split(command).ok_or_else(|| {
        SdkError::Config("command parsing failed: mismatched shell-style quotes".to_string())
    })
}

pub(crate) fn build_code_command(language: &str, code: &str) -> Result<String, SdkError> {
    let quoted = shlex::try_quote(code).map_err(|_| {
        SdkError::Config("code contains characters that cannot be shell-escaped".to_string())
    })?;

    match language {
        "bash" => Ok(format!("bash -c {quoted}")),
        "sh" | "shell" => Ok(format!("sh -c {quoted}")),
        "python" | "python3" | "py" => Ok(format!("python3 -c {quoted}")),
        "javascript" | "js" | "node" | "nodejs" => Ok(format!("node -e {quoted}")),
        _ => Err(SdkError::sandbox(
            ErrorCode::InvalidConfig,
            format!("unsupported language: {language}"),
            Some(
                "Supported: bash, sh, shell, python, python3, py, javascript, js, node, nodejs"
                    .to_string(),
            ),
        )),
    }
}

#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
pub(crate) fn map_pty_create_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::UnsupportedOperation(message) => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            message,
            Some("set isolation to `Os` or use default Auto".to_string()),
        ),
        other => SdkError::sandbox(
            ErrorCode::SandboxCreateFailed,
            other.to_string(),
            Some("Check sandbox lifecycle state and retry with a fresh instance.".to_string()),
        ),
    }
}

pub(crate) fn map_pty_session_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::UnsupportedOperation(message) => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            message,
            Some("set isolation to `Os` or use default Auto".to_string()),
        ),
        mimobox_core::SandboxError::Timeout => SdkError::sandbox(
            ErrorCode::CommandTimeout,
            "PTY session execution timed out",
            Some("increase Config.timeout or PtyConfig.timeout".to_string()),
        ),
        other => SdkError::sandbox(
            ErrorCode::SandboxDestroyed,
            other.to_string(),
            Some("Ensure sandbox is still alive before PTY operations.".to_string()),
        ),
    }
}

pub(crate) fn map_snapshot_bytes_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::InvalidSnapshot => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            "invalid sandbox snapshot",
            Some(
                "for file-mode snapshots, prefer from_snapshot()/restore() or to_bytes()"
                    .to_string(),
            ),
        ),
        mimobox_core::SandboxError::ExecutionFailed { message, .. } => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some(
                "ensure snapshot data is non-empty and from a mimobox microVM snapshot".to_string(),
            ),
        ),
        mimobox_core::SandboxError::Io(error) => SdkError::Io(error),
        other => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            other.to_string(),
            Some("Verify snapshot format compatibility with current mimobox version.".to_string()),
        ),
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
pub(crate) fn bridge_vm_stream(
    source: mpsc::Receiver<mimobox_vm::StreamEvent>,
) -> mpsc::Receiver<StreamEvent> {
    let (tx, rx) = mpsc::sync_channel(32);
    std::thread::spawn(move || {
        while let Ok(event) = source.recv() {
            let mapped = match event {
                mimobox_vm::StreamEvent::Stdout(data) => StreamEvent::Stdout(data),
                mimobox_vm::StreamEvent::Stderr(data) => StreamEvent::Stderr(data),
                mimobox_vm::StreamEvent::Exit(code) => StreamEvent::Exit(code),
                mimobox_vm::StreamEvent::TimedOut => StreamEvent::TimedOut,
            };
            if tx.send(mapped).is_err() {
                break;
            }
        }
    });
    rx
}

#[cfg(feature = "vm")]
pub(crate) fn should_prepare_vm_pool(config: &Config) -> bool {
    matches!(resolve_isolation(config, ""), Ok(IsolationLevel::MicroVm))
}

#[cfg(feature = "vm")]
pub(crate) fn initialize_default_vm_pool(
    config: &Config,
) -> Result<Option<Arc<mimobox_vm::VmPool>>, SdkError> {
    if !should_prepare_vm_pool(config) {
        return Ok(None);
    }

    let microvm_config = config.to_microvm_config()?;
    let sandbox_config = config.to_sandbox_config();
    let pool_config = mimobox_vm::VmPoolConfig {
        min_size: 1,
        max_size: 4,
        max_idle_duration: std::time::Duration::from_secs(60),
        health_check_interval: None,
    };

    match mimobox_vm::VmPool::new_with_base(sandbox_config, microvm_config, pool_config) {
        Ok(pool) => Ok(Some(Arc::new(pool))),
        Err(error) => {
            tracing::warn!(
                "Failed to initialize microVM warm pool, falling back to cold start: {error}"
            );
            Ok(None)
        }
    }
}

#[cfg(feature = "vm")]
pub(crate) fn map_http_proxy_error(error: mimobox_vm::HttpProxyError) -> SdkError {
    use mimobox_vm::HttpProxyError;

    match error {
        HttpProxyError::DeniedHost(message) => SdkError::sandbox(
            ErrorCode::HttpDeniedHost,
            message,
            Some("ensure target domain is in allowed_http_domains whitelist".to_string()),
        ),
        HttpProxyError::DeniedAcl(message) => SdkError::sandbox(
            ErrorCode::HttpDeniedAcl,
            message,
            Some("HTTP request denied by ACL policy, check http_acl config".to_string()),
        ),
        HttpProxyError::DnsRebind(message) => SdkError::sandbox(
            ErrorCode::HttpDeniedHost,
            message,
            Some("target domain resolved to private/loopback address, access denied".to_string()),
        ),
        HttpProxyError::Timeout => SdkError::sandbox(
            ErrorCode::HttpTimeout,
            "HTTP request timed out",
            Some("check target service reachability or increase timeout config".to_string()),
        ),
        HttpProxyError::BodyTooLarge => SdkError::sandbox(
            ErrorCode::HttpBodyTooLarge,
            "HTTP body exceeds size limit",
            Some("reduce request/response body size or transfer volume".to_string()),
        ),
        HttpProxyError::ConnectFail(message) => SdkError::sandbox(
            ErrorCode::HttpConnectFail,
            message,
            Some("check target service connectivity and port reachability".to_string()),
        ),
        HttpProxyError::TlsFail(message) => SdkError::sandbox(
            ErrorCode::HttpTlsFail,
            message,
            Some("check target certificate chain and TLS configuration".to_string()),
        ),
        HttpProxyError::InvalidUrl(message) => SdkError::sandbox(
            ErrorCode::HttpInvalidUrl,
            message,
            Some("only HTTPS URLs are supported, and direct IP access is not allowed".to_string()),
        ),
        HttpProxyError::Internal(message) => SdkError::Config(message),
    }
}

#[cfg(feature = "vm")]
pub(crate) fn map_microvm_error(error: mimobox_vm::MicrovmError) -> SdkError {
    use mimobox_vm::MicrovmError;

    let error_message = error.to_string();

    match error {
        MicrovmError::UnsupportedPlatform => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            "KVM microVM backend not supported on current platform",
            Some("use microVM features only on Linux with vm feature enabled".to_string()),
        ),
        MicrovmError::InvalidConfig(message) => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some("check microVM config, kernel/rootfs paths, and memory settings".to_string()),
        ),
        MicrovmError::Lifecycle(error) => {
            use mimobox_vm::LifecycleError;

            let code = match error {
                LifecycleError::Destroyed(_) | LifecycleError::Released(_) => {
                    ErrorCode::SandboxDestroyed
                }
                _ => ErrorCode::SandboxNotReady,
            };
            SdkError::sandbox(
                code,
                error.to_string(),
                Some(
                    "ensure sandbox creation has completed and current state allows this operation"
                        .to_string(),
                ),
            )
        }
        MicrovmError::HttpProxy(error) => map_http_proxy_error(error),
        MicrovmError::Backend(message) => SdkError::sandbox(
            ErrorCode::SandboxCreateFailed,
            message,
            Some("ensure KVM is available and guest runtime state is healthy".to_string()),
        ),
        MicrovmError::GuestFile { kind, path } => {
            let code = match kind {
                GuestFileErrorKind::NotFound => ErrorCode::FileNotFound,
                GuestFileErrorKind::PermissionDenied => ErrorCode::FilePermissionDenied,
                _ => mimobox_core::ErrorCode::SandboxCreateFailed,
            };
            SdkError::sandbox(
                code,
                error_message,
                Some(match kind {
                    GuestFileErrorKind::NotFound => format!(
                        "ensure target file exists and path is within allowed access scope: {path}"
                    ),
                    GuestFileErrorKind::PermissionDenied => {
                        format!("check file permissions and sandbox mount policy: {path}")
                    }
                    _ => format!("check guest file system state: {path}"),
                }),
            )
        }
        MicrovmError::SnapshotFormat(message) => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some("ensure snapshot comes from a compatible mimobox microVM version".to_string()),
        ),
        MicrovmError::AssetIntegrity(message) => SdkError::sandbox(
            ErrorCode::SandboxCreateFailed,
            message,
            Some("VM kernel/rootfs asset integrity check failed, possible tampering".to_string()),
        ),
        MicrovmError::Io(error) => SdkError::sandbox(
            ErrorCode::SandboxCreateFailed,
            error.to_string(),
            Some(
                "check snapshot file I/O and underlying virtualization resource state".to_string(),
            ),
        ),
    }
}

#[cfg(feature = "vm")]
pub(crate) fn map_pool_error(error: mimobox_vm::PoolError) -> SdkError {
    match error {
        mimobox_vm::PoolError::InvalidConfig { min_size, max_size } => SdkError::Config(format!(
            "invalid warm pool config: min_size={min_size}, max_size={max_size}"
        )),
        mimobox_vm::PoolError::StatePoisoned => {
            SdkError::Config("warm pool internal state lock poisoned".to_string())
        }
        mimobox_vm::PoolError::Microvm(error) => map_microvm_error(error),
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
pub(crate) fn map_restore_pool_error(error: mimobox_vm::RestorePoolError) -> SdkError {
    match error {
        mimobox_vm::RestorePoolError::InvalidConfig { min_size, max_size } => SdkError::Config(
            format!("invalid restore pool config: min_size={min_size}, max_size={max_size}"),
        ),
        mimobox_vm::RestorePoolError::StatePoisoned => SdkError::sandbox(
            ErrorCode::SandboxDestroyed,
            "restore pool internal state lock poisoned",
            Some("destroy current restore pool and recreate".to_string()),
        ),
        mimobox_vm::RestorePoolError::Microvm(error) => map_microvm_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_for_test(command: &str) -> Result<Vec<String>, SdkError> {
        parse_command(command)
    }

    #[test]
    fn invalid_shell_quoting_returns_sdk_error_instead_of_fallback_execution() {
        let result = parse_for_test("'unterminated");

        assert!(matches!(result, Err(SdkError::Config(_))));
    }

    #[test]
    fn build_code_command_maps_languages_correctly() {
        assert!(
            build_code_command("bash", "echo 1")
                .expect("bash code command should build")
                .starts_with("bash -c ")
        );
        assert!(
            build_code_command("sh", "echo 1")
                .expect("sh code command should build")
                .starts_with("sh -c ")
        );
        assert!(
            build_code_command("shell", "echo 1")
                .expect("shell code command should build")
                .starts_with("sh -c ")
        );
        assert!(
            build_code_command("python", "print(1)")
                .expect("python code command should build")
                .starts_with("python3 -c ")
        );
        assert!(
            build_code_command("python3", "print(1)")
                .expect("python3 code command should build")
                .starts_with("python3 -c ")
        );
        assert!(
            build_code_command("py", "print(1)")
                .expect("py code command should build")
                .starts_with("python3 -c ")
        );
        assert!(
            build_code_command("node", "console.log(1)")
                .expect("node code command should build")
                .starts_with("node -e ")
        );
        assert!(
            build_code_command("js", "console.log(1)")
                .expect("js code command should build")
                .starts_with("node -e ")
        );
        assert!(
            build_code_command("javascript", "console.log(1)")
                .expect("javascript code command should build")
                .starts_with("node -e ")
        );
        assert!(
            build_code_command("nodejs", "console.log(1)")
                .expect("nodejs code command should build")
                .starts_with("node -e ")
        );
    }

    #[test]
    fn build_code_command_rejects_unknown_language() {
        let err = build_code_command("ruby", "puts 1")
            .expect_err("unsupported language must be rejected");
        assert!(matches!(
            err,
            SdkError::Sandbox {
                code: ErrorCode::InvalidConfig,
                ..
            }
        ));
    }
}
