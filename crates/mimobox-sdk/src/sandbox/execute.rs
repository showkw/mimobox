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
use super::{Sandbox, SdkExecOptions, merge_env_vars, validate_cwd, validate_env_key};
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
            _ => Err(backend_variant_mismatch()),
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
            _ => Err(backend_variant_mismatch()),
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

    /// Provides the execute with sdk options operation.
    pub(crate) fn execute_with_sdk_options(
        &mut self,
        command: &str,
        options: SdkExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        if let Some(cwd) = options.cwd.as_deref() {
            validate_cwd(cwd)?;
        }
        validate_exec_options(&options)?;
        let merged_env = merge_env_vars(&self.config.env_vars, &options.env)?;
        let options = SdkExecOptions {
            env: merged_env,
            ..options
        };

        self.cached_metrics = None;
        self.ensure_backend(command)?;

        let result = (|| {
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
                _ => Err(backend_variant_mismatch()),
            }
        })();
        self.sync_cached_metrics_from_inner();
        result
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
        validate_exec_options(&options)?;
        let merged_env = merge_env_vars(&self.config.env_vars, &options.env)?;
        let options = SdkExecOptions {
            env: merged_env,
            ..options
        };

        let command = args.join(" ");
        self.cached_metrics = None;
        self.ensure_backend(&command)?;

        let result = (|| {
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

                    #[cfg(not(all(
                        feature = "os",
                        any(target_os = "linux", target_os = "macos")
                    )))]
                    {
                        sandbox.execute_for_sdk(&args)
                    }
                }
                #[allow(unreachable_patterns)]
                _ => Err(backend_variant_mismatch()),
            }
        })();
        self.sync_cached_metrics_from_inner();
        result
    }
}

fn argv_to_strings<A: AsRef<str>>(argv: &[A]) -> Result<Vec<String>, SdkError> {
    if argv.is_empty() {
        return Err(SdkError::Config("argv must not be empty".to_string()));
    }

    let mut args = Vec::with_capacity(argv.len());
    for (index, arg) in argv.iter().enumerate() {
        let arg = arg.as_ref();
        if index == 0 && arg.is_empty() {
            return Err(SdkError::Config("argv[0] must not be empty".to_string()));
        }
        if arg.contains('\0') {
            return Err(SdkError::Config(format!(
                "argv[{index}] must not contain NUL bytes"
            )));
        }
        args.push(arg.to_string());
    }

    Ok(args)
}

fn validate_exec_options(options: &SdkExecOptions) -> Result<(), SdkError> {
    if options.timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(SdkError::Config(
            "per-command timeout must be greater than zero".to_string(),
        ));
    }

    for (key, value) in &options.env {
        validate_env_key(key)?;
        if value.contains('\0') {
            return Err(SdkError::Config(format!(
                "environment variable `{key}` contains NUL byte"
            )));
        }
    }

    Ok(())
}

fn backend_variant_mismatch() -> SdkError {
    SdkError::internal("no backend variant matched the current feature/platform configuration")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimobox_core::BLOCKED_ENV_VARS;

    fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn merge_env_vars_empty_maps_return_empty_map() {
        let merged =
            merge_env_vars(&HashMap::new(), &HashMap::new()).expect("empty env maps should merge");

        assert!(merged.is_empty());
    }

    #[test]
    fn merge_env_vars_config_empty_returns_command_env() {
        let command_env = env_map(&[("REQUEST_ID", "cmd-1")]);

        let merged = merge_env_vars(&HashMap::new(), &command_env)
            .expect("command env should merge when config env is empty");

        assert_eq!(merged, command_env);
    }

    #[test]
    fn merge_env_vars_command_empty_returns_config_env() {
        let config_env = env_map(&[("APP_MODE", "test")]);

        let merged = merge_env_vars(&config_env, &HashMap::new())
            .expect("config env should merge when command env is empty");

        assert_eq!(merged, config_env);
    }

    #[test]
    fn merge_env_vars_command_env_overrides_config_env() {
        let config_env = env_map(&[("APP_MODE", "config"), ("CONFIG_ONLY", "yes")]);
        let command_env = env_map(&[("APP_MODE", "command"), ("COMMAND_ONLY", "yes")]);

        let merged =
            merge_env_vars(&config_env, &command_env).expect("valid env maps should merge");

        assert_eq!(merged.get("APP_MODE"), Some(&"command".to_string()));
        assert_eq!(merged.get("CONFIG_ONLY"), Some(&"yes".to_string()));
        assert_eq!(merged.get("COMMAND_ONLY"), Some(&"yes".to_string()));
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn merge_env_vars_rejects_blocked_command_env_keys() {
        for blocked_key in BLOCKED_ENV_VARS {
            let command_env = env_map(&[(blocked_key, "value")]);

            let error = merge_env_vars(&HashMap::new(), &command_env)
                .expect_err("blocked command env key should be rejected");

            assert!(
                error.to_string().contains("blocked"),
                "blocked key {blocked_key} returned unexpected error: {error}"
            );
        }
    }

    #[test]
    fn merge_env_vars_rejects_blocked_config_env_keys() {
        let config_env = env_map(&[("HOME", "/tmp/override")]);
        let command_env = env_map(&[("APP_MODE", "test")]);

        let error = merge_env_vars(&config_env, &command_env)
            .expect_err("config env must not override baseline HOME");

        assert!(error.to_string().contains("sandbox baseline"));
    }

    #[test]
    fn merge_env_vars_prevents_baseline_path_override() {
        let command_env = env_map(&[("PATH", "/malicious/bin")]);

        let error = merge_env_vars(&HashMap::new(), &command_env)
            .expect_err("PATH must remain owned by sandbox baseline");

        assert!(error.to_string().contains("sandbox baseline"));
    }

    #[test]
    fn validate_exec_options_rejects_nul_env_value() {
        let options = SdkExecOptions {
            env: env_map(&[("SAFE_KEY", "value\0tail")]),
            ..Default::default()
        };

        let error =
            validate_exec_options(&options).expect_err("NUL bytes in env value should be rejected");

        assert!(error.to_string().contains("NUL byte"));
    }

    #[test]
    fn validate_exec_options_rejects_zero_timeout() {
        let options = SdkExecOptions {
            timeout: Some(Duration::ZERO),
            ..Default::default()
        };

        let error = validate_exec_options(&options)
            .expect_err("zero per-command timeout should be rejected");

        assert!(error.to_string().contains("greater than zero"));
    }
}
