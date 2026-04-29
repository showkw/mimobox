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

#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use super::SandboxInner;
use super::{Sandbox, SdkExecOptions, merge_env_vars, validate_cwd};
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use super::{build_fallback_argv_args, build_fallback_command_args};

impl Sandbox {
    /// Executes a command inside the sandbox.
    ///
    /// Prefer [`exec()`](Sandbox::exec) for user-controlled input to avoid shell injection.
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
        self.execute_with_sdk_options(command, SdkExecOptions::default())
    }

    /// Executes an argv vector inside the sandbox without shell parsing.
    ///
    /// This is the recommended safe execution API. Arguments are passed directly
    /// to the backend `execve`-style execution path and are not interpreted by a
    /// shell, so user-controlled input cannot change command structure through
    /// shell metacharacters.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::Sandbox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let result = sandbox.exec(&["/bin/echo", "hello", "world"])?;
    /// assert_eq!(result.exit_code, Some(0));
    /// # Ok(())
    /// # }
    /// ```
    pub fn exec<A: AsRef<str>>(&mut self, argv: &[A]) -> Result<ExecuteResult, SdkError> {
        self.exec_with_options(argv, SdkExecOptions::default())
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
    ///
    /// Prefer [`stream_exec()`](Sandbox::stream_exec) for user-controlled input to avoid shell injection.
    pub fn stream_execute(
        &mut self,
        command: &str,
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        let args = parse_command(command)?;
        let _ = &args;
        self.ensure_backend(command)?;
        #[cfg(all(feature = "vm", target_os = "linux"))]
        let options = SdkExecOptions {
            env: self.config.env_vars.clone(),
            ..Default::default()
        };
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(sandbox) => sandbox.stream_execute_for_sdk(&args),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(sandbox) => sandbox.stream_execute_for_sdk(&args),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => sandbox
                .stream_execute_with_options(&args, options.to_guest_exec_options())
                .map(crate::vm_helpers::bridge_vm_stream)
                .map_err(super::map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => sandbox
                .stream_execute_with_options(&args, options.to_guest_exec_options())
                .map(crate::vm_helpers::bridge_vm_stream)
                .map_err(super::map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => sandbox
                .stream_execute_with_options(&args, options.to_guest_exec_options())
                .map(crate::vm_helpers::bridge_vm_stream)
                .map_err(super::map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(sandbox) => sandbox.stream_execute_for_sdk(&args),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }

    /// Executes an argv vector as a stream of events without shell parsing.
    ///
    /// This is the recommended safe streaming API for user-controlled input.
    /// Arguments are passed directly to the backend `execve`-style execution path
    /// and are not interpreted by a shell, so shell metacharacters remain ordinary
    /// argument bytes.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{Sandbox, StreamEvent};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let receiver = sandbox.stream_exec(&["/bin/echo", "hello"])?;
    /// assert!(receiver.iter().any(|event| matches!(event, StreamEvent::Exit(0))));
    /// # Ok(())
    /// # }
    /// ```
    pub fn stream_exec<A: AsRef<str>>(
        &mut self,
        argv: &[A],
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        let args = argv_to_strings(argv)?;
        let command = args.join(" ");
        self.ensure_backend(&command)?;
        #[cfg(all(feature = "vm", target_os = "linux"))]
        let options = SdkExecOptions {
            env: self.config.env_vars.clone(),
            ..Default::default()
        };
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(sandbox) => sandbox.stream_execute_for_sdk(&args),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(sandbox) => sandbox.stream_execute_for_sdk(&args),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => sandbox
                .stream_execute_with_options(&args, options.to_guest_exec_options())
                .map(crate::vm_helpers::bridge_vm_stream)
                .map_err(super::map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => sandbox
                .stream_execute_with_options(&args, options.to_guest_exec_options())
                .map(crate::vm_helpers::bridge_vm_stream)
                .map_err(super::map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => sandbox
                .stream_execute_with_options(&args, options.to_guest_exec_options())
                .map(crate::vm_helpers::bridge_vm_stream)
                .map_err(super::map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(sandbox) => sandbox.stream_execute_for_sdk(&args),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
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
        let merged_env = merge_env_vars(&self.config.env_vars, &options.env);
        let options = SdkExecOptions {
            env: merged_env,
            ..options
        };
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

    /// Executes an argv vector with per-call execution options.
    ///
    /// This argv-first variant is safe for user-controlled input because command
    /// arguments are never parsed by a shell. Environment variables, working
    /// directory and timeout are scoped to this single execution where the active
    /// backend supports them.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{Sandbox, SdkExecOptions};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let result = sandbox.exec_with_options(
    ///     &["/bin/echo", "hello"],
    ///     SdkExecOptions::default(),
    /// )?;
    /// assert_eq!(result.exit_code, Some(0));
    /// # Ok(())
    /// # }
    /// ```
    pub fn exec_with_options<A: AsRef<str>>(
        &mut self,
        argv: &[A],
        options: SdkExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        let args = argv_to_strings(argv)?;
        if let Some(cwd) = options.cwd.as_deref() {
            validate_cwd(cwd)?;
        }
        let merged_env = merge_env_vars(&self.config.env_vars, &options.env);
        let options = SdkExecOptions {
            env: merged_env,
            ..options
        };
        let _ = (&options.env, options.timeout);

        let command = args.join(" ");
        self.ensure_backend(&command)?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(sandbox) => {
                let args = build_fallback_argv_args(&args, &options)?;
                sandbox.execute_for_sdk(&args)
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(sandbox) => {
                let args = build_fallback_argv_args(&args, &options)?;
                sandbox.execute_for_sdk(&args)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
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
                #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
                {
                    let args = build_fallback_argv_args(&args, &options)?;
                    sandbox.execute_for_sdk(&args)
                }

                #[cfg(not(all(feature = "os", any(target_os = "linux", target_os = "macos"))))]
                {
                    sandbox.execute_for_sdk(&args)
                }
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }
}

fn argv_to_strings<A: AsRef<str>>(argv: &[A]) -> Result<Vec<String>, SdkError> {
    if argv.is_empty() {
        return Err(SdkError::Config("argv must not be empty".to_string()));
    }

    Ok(argv
        .iter()
        .map(|arg| arg.as_ref().to_string())
        .collect::<Vec<_>>())
}
