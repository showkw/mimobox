use crate::error::SdkError;
use crate::types::PtySession;
#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use crate::vm_helpers::map_pty_create_error;
use crate::vm_helpers::parse_command;
#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use mimobox_core::Sandbox as CoreSandbox;
use mimobox_core::{PtyConfig, PtySize};

#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use super::SandboxInner;
use super::{Sandbox, merge_env_vars, validate_cwd};

impl Sandbox {
    /// Creates an interactive terminal session.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::Sandbox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let mut pty = sandbox.create_pty("/bin/sh")?;
    /// pty.send_input(b"echo hello\n")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_pty(&mut self, command: &str) -> Result<PtySession, SdkError> {
        let args = parse_command(command)?;
        if args.is_empty() {
            return Err(SdkError::Config(
                "PTY command must not be empty".to_string(),
            ));
        }

        self.create_pty_with_config(PtyConfig {
            command: args,
            size: PtySize::default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: self.config.timeout,
        })
    }

    /// Creates an interactive terminal session with a complete `PtyConfig`.
    pub fn create_pty_with_config(
        &mut self,
        mut config: PtyConfig,
    ) -> Result<PtySession, SdkError> {
        if config.command.is_empty() {
            return Err(SdkError::Config(
                "PTY command must not be empty".to_string(),
            ));
        }

        if let Some(cwd) = config.cwd.as_deref() {
            validate_cwd(cwd)?;
        }

        config.env = merge_env_vars(&self.config.env_vars, &config.env)?;

        self.ensure_backend_for_pty()?;

        #[cfg(not(any(
            feature = "wasm",
            all(feature = "os", any(target_os = "linux", target_os = "macos")),
            all(feature = "vm", target_os = "linux")
        )))]
        {
            return Err(SdkError::unsupported_backend("pty"));
        }

        #[cfg(any(
            feature = "wasm",
            all(feature = "os", any(target_os = "linux", target_os = "macos")),
            all(feature = "vm", target_os = "linux")
        ))]
        {
            let inner = self.require_inner()?;

            let session = match inner {
                #[cfg(all(feature = "os", target_os = "linux"))]
                SandboxInner::Os(sandbox) => CoreSandbox::create_pty(sandbox, config.clone())
                    .map_err(map_pty_create_error)?,
                #[cfg(all(feature = "os", target_os = "macos"))]
                SandboxInner::OsMac(sandbox) => CoreSandbox::create_pty(sandbox, config.clone())
                    .map_err(map_pty_create_error)?,
                #[cfg(all(feature = "vm", target_os = "linux"))]
                SandboxInner::MicroVm(sandbox) => CoreSandbox::create_pty(sandbox, config.clone())
                    .map_err(map_pty_create_error)?,
                #[cfg(all(feature = "vm", target_os = "linux"))]
                SandboxInner::PooledMicroVm(_) => {
                    return Err(SdkError::sandbox(
                        mimobox_core::ErrorCode::UnsupportedPlatform,
                        "PTY sessions currently only support OS-level backend, microVM pool not supported yet",
                        Some("set isolation to `Os` or use default Auto".to_string()),
                    ));
                }
                #[cfg(all(feature = "vm", target_os = "linux"))]
                SandboxInner::RestoredPooledMicroVm(_) => {
                    return Err(SdkError::sandbox(
                        mimobox_core::ErrorCode::UnsupportedPlatform,
                        "PTY sessions currently only support OS-level backend, restored microVM pool not supported yet",
                        Some("set isolation to `Os` or use default Auto".to_string()),
                    ));
                }
                #[cfg(feature = "wasm")]
                SandboxInner::Wasm(sandbox) => {
                    CoreSandbox::create_pty(sandbox, config).map_err(map_pty_create_error)?
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!("no backend variant matched"),
            };

            Ok(PtySession::from_inner(session))
        }
    }
}
