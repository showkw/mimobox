#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use crate::dispatch::{ExecuteForSdk, StreamExecuteForSdk};
use crate::error::SdkError;
use crate::types::{ExecuteResult, StreamEvent};
use crate::vm_helpers::parse_command;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;
use tracing::debug;

#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use super::SandboxInner;
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use super::build_fallback_command_args;
use super::{Sandbox, SdkExecOptions, validate_cwd};

macro_rules! dispatch_execute {
    ($inner:expr, $binding:ident, $expr:expr, $ctx:literal) => {{
        debug!(context = $ctx, "dispatching execute");
        match $inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os($binding) => $expr,
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm($binding) => $expr,
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm($binding) => $expr,
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched for dispatch_execute"),
        }
    }};
}

impl Sandbox {
    /// Executes a command inside the sandbox.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::Sandbox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let result = sandbox.execute("/bin/echo hello")?;
    /// assert_eq!(result.exit_code, Some(0));
    /// # Ok(())
    /// # }
    /// ```
    pub fn execute(&mut self, command: &str) -> Result<ExecuteResult, SdkError> {
        let args = parse_command(command)?;
        let _ = &args;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;
        dispatch_execute!(inner, s, s.execute_for_sdk(&args), "execute")
    }

    /// Execute code in the given language inside the sandbox.
    ///
    /// # Supported languages
    ///
    /// - "bash" -> bash -c <code>
    /// - "sh" / "shell" -> sh -c <code>
    /// - "python" / "python3" / "py" -> python3 -c <code>
    /// - "javascript" / "js" / "node" / "nodejs" -> node -e <code>
    pub fn execute_code(&mut self, language: &str, code: &str) -> Result<ExecuteResult, SdkError> {
        let command = crate::vm_helpers::build_code_command(language, code)?;
        self.execute(&command)
    }

    /// Executes a command as a stream of events.
    pub fn stream_execute(
        &mut self,
        command: &str,
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        let args = parse_command(command)?;
        let _ = &args;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;

        dispatch_execute!(
            inner,
            sandbox,
            sandbox.stream_execute_for_sdk(&args),
            "stream_execute"
        )
    }

    /// Executes a command with additional environment variables for this call.
    pub fn execute_with_env(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_sdk_options(
            command,
            SdkExecOptions {
                env,
                timeout: None,
                cwd: None,
            },
        )
    }

    /// Executes a command with a timeout override where the backend supports it.
    pub fn execute_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_sdk_options(
            command,
            SdkExecOptions {
                env: HashMap::new(),
                timeout: Some(timeout),
                cwd: None,
            },
        )
    }

    /// Executes a command with additional environment variables and a timeout override.
    pub fn execute_with_env_and_timeout(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_sdk_options(
            command,
            SdkExecOptions {
                env,
                timeout: Some(timeout),
                cwd: None,
            },
        )
    }

    /// Executes a command with a working directory override where the backend supports it.
    pub fn execute_with_cwd(
        &mut self,
        command: &str,
        cwd: &str,
    ) -> Result<ExecuteResult, SdkError> {
        validate_cwd(cwd)?;

        self.execute_with_sdk_options(
            command,
            SdkExecOptions {
                cwd: Some(cwd.to_string()),
                ..Default::default()
            },
        )
    }

    #[cfg(feature = "vm")]
    /// Executes a command in the microVM backend with full per-command execution options.
    pub fn execute_with_vm_options_full(
        &mut self,
        command: &str,
        options: mimobox_vm::GuestExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        if let Some(cwd) = options.cwd.as_deref() {
            validate_cwd(cwd)?;
        }

        self.execute_with_sdk_options(command, options.into())
    }

    pub(crate) fn execute_with_sdk_options(
        &mut self,
        command: &str,
        options: SdkExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        if let Some(cwd) = options.cwd.as_deref() {
            validate_cwd(cwd)?;
        }
        let _ = (&options.env, options.timeout);

        self.ensure_backend(command)?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(sandbox) => {
                let args = build_fallback_command_args(command, &options)?;
                sandbox.execute_for_sdk(&args)
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(sandbox) => {
                let args = build_fallback_command_args(command, &options)?;
                sandbox.execute_for_sdk(&args)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
                let args = parse_command(command)?;
                let start = std::time::Instant::now();
                sandbox
                    .execute_with_options(&args, options.to_guest_exec_options())
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(super::map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => {
                let args = parse_command(command)?;
                let start = std::time::Instant::now();
                sandbox
                    .execute_with_options(&args, options.to_guest_exec_options())
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(super::map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => {
                let args = parse_command(command)?;
                let start = std::time::Instant::now();
                sandbox
                    .execute_with_options(&args, options.to_guest_exec_options())
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(super::map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(sandbox) => {
                let args = parse_command(command)?;
                sandbox.execute_for_sdk(&args)
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }
}
