use mimobox_core::{Sandbox, SandboxConfig, SandboxResult};
#[cfg(target_os = "linux")]
use mimobox_os::LinuxSandbox;
#[cfg(target_os = "macos")]
use mimobox_os::MacOsSandbox;
use mimobox_sdk::Sandbox as SdkSandbox;
#[cfg(all(target_os = "linux", feature = "kvm"))]
use mimobox_vm::{MicrovmConfig, MicrovmSandbox};
#[cfg(feature = "wasm")]
use mimobox_wasm::WasmSandbox;
#[cfg(all(target_os = "linux", feature = "kvm"))]
use std::path::PathBuf;
use std::time::Duration;

use tracing::{error, info, warn};

use super::*;
use crate::DEFAULT_MEMORY_MB;
use crate::capture::capture_stderr_bytes;

pub(crate) fn handle_run(args: RunArgs) -> Result<RunResponse, CliError> {
    validate_resource_args(args.memory, args.timeout, args.vcpu_count)?;

    let deny_network = resolve_run_deny_network(&args);
    info!(
        backend = ?args.backend,
        memory_mb = args.memory.unwrap_or(DEFAULT_MEMORY_MB),
        timeout_secs = ?normalize_timeout(args.timeout),
        deny_network,
        allow_fork = args.allow_fork,
        kernel = args.kernel.as_deref().unwrap_or("default"),
        rootfs = args.rootfs.as_deref().unwrap_or("default"),
        vcpu_count = args.vcpu_count,
        "preparing to execute run subcommand"
    );

    let argv = parse_command(&args.command)?;
    let memory_mb = Some(args.memory.unwrap_or(DEFAULT_MEMORY_MB));
    let timeout_secs = normalize_timeout(args.timeout);
    let allow_fork = args.allow_fork;

    let requested_backend = args.backend;
    let (execution, fallback_stderr) =
        capture_stderr_bytes(|| match resolve_run_execution_mode(args.backend) {
            RunExecutionMode::Sdk => handle_run_via_sdk(
                &args.command,
                args.memory,
                args.timeout,
                deny_network,
                args.allow_fork,
            ),
            RunExecutionMode::Direct => {
                let config =
                    build_sandbox_config(args.memory, args.timeout, deny_network, args.allow_fork);

                match args.backend {
                    Backend::Auto => unreachable!("Auto backend is handled in SDK path"),
                    Backend::Os => Ok(RunExecution {
                        backend: Backend::Os,
                        result: execute_os_backend(config, &argv)?,
                    }),
                    Backend::Wasm => Ok(RunExecution {
                        backend: Backend::Wasm,
                        result: execute_wasm_backend(config, &argv)?,
                    }),
                    Backend::Kvm => Ok(RunExecution {
                        backend: Backend::Kvm,
                        result: execute_kvm_backend(config, &argv, &args)?,
                    }),
                }
            }
        })?;
    let mut execution = execution?;
    apply_stderr_fallback(&mut execution.result.stderr, fallback_stderr);

    Ok(RunResponse {
        backend: execution.backend,
        requested_backend,
        requested_command: args.command,
        argv,
        exit_code: execution.result.exit_code,
        timed_out: execution.result.timed_out,
        elapsed_ms: execution.result.elapsed.as_secs_f64() * 1000.0,
        stdout: String::from_utf8_lossy(&execution.result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&execution.result.stderr).to_string(),
        memory_mb,
        timeout_secs,
        deny_network,
        allow_fork,
    })
}

pub(crate) fn resolve_run_execution_mode(backend: Backend) -> RunExecutionMode {
    match backend {
        Backend::Auto => RunExecutionMode::Sdk,
        Backend::Os | Backend::Wasm | Backend::Kvm => RunExecutionMode::Direct,
    }
}

pub(crate) fn handle_run_via_sdk(
    command: &str,
    memory: Option<u64>,
    timeout: Option<u64>,
    deny_network: bool,
    allow_fork: bool,
) -> Result<RunExecution, CliError> {
    let config = build_sdk_config(memory, timeout, deny_network, allow_fork);
    info!(
        memory_mb = config.memory_limit_mb,
        timeout_secs = config.timeout.as_ref().map(Duration::as_secs),
        deny_network,
        allow_fork,
        "executing command via SDK smart routing"
    );

    let mut sandbox = SdkSandbox::with_config(config).map_err(|error| {
        let cli_error = map_sdk_error(error);
        error!(code = cli_error.code(), message = %cli_error, "SDK sandbox initialization failed");
        cli_error
    })?;

    let execute_result = sandbox.execute(command);

    match execute_result {
        Ok(result) => {
            let backend = sandbox
                .active_isolation()
                .and_then(backend_from_sdk_isolation)
                .ok_or_else(|| {
                    let error = CliError::Sdk(
                        "SDK execution succeeded but actual backend not recorded".to_string(),
                    );
                    error!(
                        code = error.code(),
                        message = %error,
                        "failed to resolve actual backend after SDK execution succeeded"
                    );
                    error
                })?;

            sandbox.destroy().map_err(|error| {
                let cli_error = map_sdk_error(error);
                error!(
                    code = cli_error.code(),
                    message = %cli_error,
                    backend = ?backend,
                    "failed to destroy sandbox after SDK execution succeeded"
                );
                cli_error
            })?;

            info!(backend = ?backend, "SDK execution succeeded, sandbox destroyed");
            Ok(RunExecution {
                backend,
                result: sdk_result_into_sandbox_result(result),
            })
        }
        Err(error) => {
            let cli_error = map_sdk_error(error);
            error!(
                code = cli_error.code(),
                message = %cli_error,
                "SDK command execution failed"
            );

            if let Err(destroy_error) = sandbox.destroy() {
                let destroy_cli_error = map_sdk_error(destroy_error);
                error!(
                    code = destroy_cli_error.code(),
                    message = %destroy_cli_error,
                    "failed to destroy sandbox after SDK execution failure"
                );
            } else {
                warn!("sandbox destroyed after SDK execution failure");
            }
            Err(cli_error)
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn execute_os_backend(
    config: SandboxConfig,
    argv: &[String],
) -> Result<SandboxResult, CliError> {
    info!("executing command via Linux OS backend");
    execute_with_sandbox::<LinuxSandbox>(config, argv)
}

#[cfg(target_os = "macos")]
pub(crate) fn execute_os_backend(
    config: SandboxConfig,
    argv: &[String],
) -> Result<SandboxResult, CliError> {
    info!("executing command via macOS OS backend");
    execute_with_sandbox::<MacOsSandbox>(config, argv)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn execute_os_backend(
    _config: SandboxConfig,
    _argv: &[String],
) -> Result<SandboxResult, CliError> {
    Err(CliError::UnsupportedOsBackend)
}

#[cfg(feature = "wasm")]
pub(crate) fn execute_wasm_backend(
    config: SandboxConfig,
    argv: &[String],
) -> Result<SandboxResult, CliError> {
    info!("executing command via Wasm backend");
    execute_with_sandbox::<WasmSandbox>(config, argv)
}

#[cfg(not(feature = "wasm"))]
pub(crate) fn execute_wasm_backend(
    _config: SandboxConfig,
    _argv: &[String],
) -> Result<SandboxResult, CliError> {
    Err(CliError::WasmFeatureDisabled)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
pub(crate) fn execute_kvm_backend(
    config: SandboxConfig,
    argv: &[String],
    args: &RunArgs,
) -> Result<SandboxResult, CliError> {
    info!("executing command via KVM microVM backend");

    let memory_limit_mb = config.memory_limit_mb.unwrap_or(DEFAULT_MEMORY_MB);
    let memory_mb = u32::try_from(memory_limit_mb).map_err(|_| {
        CliError::Sandbox(SandboxError::ExecutionFailed(format!(
            "KVM guest memory exceeds u32 range: {memory_limit_mb} MB"
        )))
    })?;

    let mut microvm_config = MicrovmConfig {
        vcpu_count: args.vcpu_count,
        memory_mb,
        ..MicrovmConfig::default()
    };

    if let Some(kernel) = args.kernel.as_ref() {
        microvm_config.kernel_path = PathBuf::from(kernel);
    }

    if let Some(rootfs) = args.rootfs.as_ref() {
        microvm_config.rootfs_path = PathBuf::from(rootfs);
    }

    microvm_config
        .validate()
        .map_err(|error| CliError::Sandbox(error.into()))?;

    execute_with_sandbox_specific(config, argv, move |sandbox_config| {
        MicrovmSandbox::new_with_base(sandbox_config, microvm_config)
            .map_err(|error| CliError::Sandbox(error.into()))
    })
}

#[cfg(not(all(target_os = "linux", feature = "kvm")))]
pub(crate) fn execute_kvm_backend(
    _config: SandboxConfig,
    _argv: &[String],
    _args: &RunArgs,
) -> Result<SandboxResult, CliError> {
    Err(CliError::KvmFeatureDisabled)
}

pub(crate) fn execute_with_sandbox<S>(
    config: SandboxConfig,
    argv: &[String],
) -> Result<SandboxResult, CliError>
where
    S: Sandbox,
{
    execute_with_sandbox_specific(config, argv, |sandbox_config| {
        S::new(sandbox_config).map_err(Into::into)
    })
}

pub(crate) fn execute_with_sandbox_specific<S, F>(
    config: SandboxConfig,
    argv: &[String],
    build_sandbox: F,
) -> Result<SandboxResult, CliError>
where
    S: Sandbox,
    F: FnOnce(SandboxConfig) -> Result<S, CliError>,
{
    let mut sandbox = build_sandbox(config)?;
    let execute_result = sandbox.execute(argv);

    match execute_result {
        Ok(result) => {
            sandbox.destroy()?;
            Ok(result)
        }
        Err(error) => {
            if let Err(destroy_error) = sandbox.destroy() {
                warn!(message = %destroy_error, "failed to destroy sandbox after execution failure");
            }
            Err(error.into())
        }
    }
}
