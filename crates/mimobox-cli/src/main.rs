mod asset_download;
mod doctor;

use std::cell::Cell;
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult, SeccompProfile};
#[cfg(target_os = "linux")]
use mimobox_os::LinuxSandbox;
#[cfg(target_os = "macos")]
use mimobox_os::MacOsSandbox;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mimobox_os::run_pool_benchmark;
#[cfg(all(target_os = "linux", feature = "kvm"))]
use mimobox_sdk::SandboxSnapshot as SdkSnapshot;
use mimobox_sdk::{
    Config as SdkConfig, ExecuteResult as SdkExecuteResult, IsolationLevel as SdkIsolationLevel,
    NetworkPolicy as SdkNetworkPolicy, PtyConfig as SdkPtyConfig, PtyEvent as SdkPtyEvent,
    PtySize as SdkPtySize, Sandbox as SdkSandbox,
};
#[cfg(all(target_os = "linux", feature = "kvm"))]
use mimobox_vm::{MicrovmConfig, MicrovmSandbox};
#[cfg(feature = "wasm")]
use mimobox_wasm::WasmSandbox;
use serde::Serialize;
use thiserror::Error;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt::writer::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_MEMORY_MB: u64 = 256;
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_BENCH_ITERATIONS: usize = 50;
const DEFAULT_POOL_SIZE: usize = 16;

#[derive(Debug, Parser)]
#[command(
    name = "mimobox",
    version,
    about = "Cross-platform Agent Sandbox CLI",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Execute a command in the specified backend sandbox
    Run(RunArgs),
    /// Start an interactive terminal session
    Shell(ShellArgs),
    /// Create a microVM snapshot file
    Snapshot(SnapshotArgs),
    /// Restore from a snapshot file and execute a command
    Restore(RestoreArgs),
    /// Run pool-related benchmarks
    Bench(BenchArgs),
    /// Diagnose the current runtime environment
    Doctor,
    /// Initialize mimobox local assets and directories
    Setup,
    /// Configure mimobox MCP server for a desktop client
    McpInit(McpInitArgs),
    /// Print version information
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum, Default)]
#[serde(rename_all = "kebab-case")]
enum Backend {
    #[default]
    Auto,
    Os,
    Wasm,
    Kvm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum BenchTarget {
    ColdStart,
    HotAcquire,
    WarmThroughput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum McpClient {
    Claude,
    Cursor,
    Windsurf,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Select backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    backend: Backend,

    /// Command to execute (shell-style string, e.g. "/bin/echo hello")
    #[arg(long, value_name = "cmd")]
    command: String,

    /// Memory limit in MB
    #[arg(long)]
    memory: Option<u64>,

    /// Timeout in seconds; pass 0 for no timeout
    #[arg(long)]
    timeout: Option<u64>,

    /// Deny network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "allow_network")]
    deny_network: bool,

    /// Allow network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "deny_network")]
    allow_network: bool,

    /// Allow child process fork/clone
    #[arg(long, default_value_t = false)]
    allow_fork: bool,

    /// Path to the KVM kernel image
    #[arg(long)]
    kernel: Option<String>,

    /// Path to the KVM rootfs
    #[arg(long)]
    rootfs: Option<String>,

    /// Number of KVM vCPUs
    #[arg(long, default_value_t = 1)]
    vcpu_count: u8,
}

#[derive(Debug, Args)]
struct ShellArgs {
    /// Select backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    backend: Backend,

    /// Command to run; defaults to /bin/sh
    #[arg(long, value_name = "cmd", default_value = "/bin/sh")]
    command: String,

    /// Memory limit in MB
    #[arg(long)]
    memory: Option<u64>,

    /// Timeout in seconds; pass 0 for no timeout
    #[arg(long)]
    timeout: Option<u64>,

    /// Deny network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "allow_network")]
    deny_network: bool,

    /// Allow network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "deny_network")]
    allow_network: bool,
}

#[derive(Debug, Args)]
struct SnapshotArgs {
    /// Snapshot output file path
    #[arg(long, value_name = "path")]
    output: String,

    /// Initialization command to run before snapshotting
    #[arg(long, value_name = "cmd")]
    init_command: Option<String>,

    /// Memory limit in MB
    #[arg(long)]
    memory: Option<u64>,

    /// Timeout in seconds; pass 0 for no timeout
    #[arg(long)]
    timeout: Option<u64>,

    /// Deny network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "allow_network")]
    deny_network: bool,

    /// Allow network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "deny_network")]
    allow_network: bool,

    /// Allow child process fork/clone
    #[arg(long, default_value_t = false)]
    allow_fork: bool,

    /// Path to the KVM kernel image
    #[arg(long)]
    kernel: Option<String>,

    /// Path to the KVM rootfs
    #[arg(long)]
    rootfs: Option<String>,

    /// Number of KVM vCPUs
    #[arg(long, default_value_t = 1)]
    vcpu_count: u8,
}

#[derive(Debug, Args)]
struct RestoreArgs {
    /// Snapshot file path
    #[arg(long, value_name = "path")]
    snapshot: String,

    /// Command to execute after restoration
    #[arg(long, value_name = "cmd")]
    command: String,
}

#[derive(Debug, Args)]
struct BenchArgs {
    /// Benchmark target
    #[arg(long, value_enum)]
    target: BenchTarget,
}

#[derive(Debug, Args)]
struct McpInitArgs {
    /// MCP client to configure
    #[arg(value_enum, required_unless_present = "all", conflicts_with = "all")]
    client: Option<McpClient>,

    /// Configure all supported MCP clients
    #[arg(long, action = ArgAction::SetTrue)]
    all: bool,
}

#[derive(Debug, Serialize)]
struct SuccessEnvelope<T>
where
    T: Serialize,
{
    ok: bool,
    #[serde(flatten)]
    payload: T,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    ok: bool,
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
enum CommandResponse {
    Run(RunResponse),
    Snapshot(SnapshotResponse),
    Restore(RestoreResponse),
    Bench(BenchResponse),
    Version(VersionResponse),
}

#[derive(Debug, Serialize)]
struct RunResponse {
    backend: Backend,
    requested_backend: Backend,
    requested_command: String,
    argv: Vec<String>,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed_ms: f64,
    stdout: String,
    stderr: String,
    memory_mb: Option<u64>,
    timeout_secs: Option<u64>,
    deny_network: bool,
    allow_fork: bool,
}

#[derive(Debug, Serialize)]
struct SnapshotResponse {
    output_path: String,
    init_command: Option<String>,
    size_bytes: usize,
    backend: Backend,
}

#[derive(Debug, Serialize)]
struct RestoreResponse {
    snapshot_path: String,
    requested_command: String,
    argv: Vec<String>,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed_ms: f64,
    stdout: String,
    stderr: String,
    snapshot_size: usize,
}

#[derive(Debug, Serialize)]
struct BenchResponse {
    target: BenchTarget,
    pool_size: usize,
    iterations: usize,
    raw_output: String,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct VersionResponse {
    name: &'static str,
    version: &'static str,
    enabled_features: Vec<&'static str>,
    target_os: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunExecutionMode {
    Sdk,
    Direct,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("argument parsing failed: {0}")]
    Args(String),

    #[error("command string parsing failed: {0}")]
    CommandParse(String),

    #[error("command must not be empty")]
    EmptyCommand,

    #[error("logging initialization failed: {0}")]
    Logging(String),

    #[error("JSON output failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("SDK execution failed: {0}")]
    Sdk(String),

    #[error("sandbox execution failed: {0}")]
    Sandbox(#[from] SandboxError),

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[error("OS backend not supported on current platform")]
    UnsupportedOsBackend,

    #[error("Wasm backend not enabled in current build; rebuild with `--features wasm`")]
    #[allow(dead_code)]
    WasmFeatureDisabled,

    #[error(
        "KVM backend not enabled or platform unsupported; rebuild on Linux with `--features kvm`"
    )]
    #[allow(dead_code)]
    KvmFeatureDisabled,

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[error("warm pool benchmark not supported on current platform")]
    BenchUnsupported,

    #[error("benchmark execution failed: {0}")]
    Benchmark(String),

    #[error("MCP initialization failed: {0}")]
    McpInit(String),

    #[error("unexpected runtime panic: {0}")]
    Panic(String),
}

impl CliError {
    fn code(&self) -> &'static str {
        match self {
            Self::Args(_) => "args_error",
            Self::CommandParse(_) => "command_parse_error",
            Self::EmptyCommand => "empty_command",
            Self::Logging(_) => "logging_init_error",
            Self::Json(_) => "json_error",
            Self::Io(_) => "io_error",
            Self::Sdk(_) => "sdk_error",
            Self::Sandbox(_) => "sandbox_error",
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            Self::UnsupportedOsBackend => "unsupported_os_backend",
            Self::WasmFeatureDisabled => "wasm_feature_disabled",
            Self::KvmFeatureDisabled => "kvm_feature_disabled",
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            Self::BenchUnsupported => "bench_unsupported",
            Self::Benchmark(_) => "benchmark_error",
            Self::McpInit(_) => "mcp_init_error",
            Self::Panic(_) => "panic",
        }
    }
}

impl From<mimobox_sdk::SdkError> for CliError {
    fn from(error: mimobox_sdk::SdkError) -> Self {
        match error {
            mimobox_sdk::SdkError::BackendUnavailable("wasm") => Self::WasmFeatureDisabled,
            mimobox_sdk::SdkError::BackendUnavailable("microvm") => Self::KvmFeatureDisabled,
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            mimobox_sdk::SdkError::BackendUnavailable("os") => Self::UnsupportedOsBackend,
            other => Self::Sdk(other.to_string()),
        }
    }
}

#[derive(Clone)]
struct SharedFileWriter {
    file: Arc<Mutex<File>>,
}

#[derive(Debug)]
struct RunExecution {
    backend: Backend,
    result: SandboxResult,
}

thread_local! {
    /// Temporarily disable terminal logging when capturing process-level stderr, to avoid log output polluting fallback output.
    static STDERR_LOGGING_ENABLED: Cell<bool> = const { Cell::new(true) };
}

#[cfg(unix)]
static SHELL_SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
static SHELL_SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    if let Err(error) = init_tracing() {
        if let Err(print_error) = emit_error_json(&error) {
            eprintln!(
                "{{\"ok\":false,\"code\":\"logging_init_error\",\"message\":\"{}\"}}",
                print_error
            );
        }
        return ExitCode::FAILURE;
    }

    match panic::catch_unwind(AssertUnwindSafe(run_with_panic_guard)) {
        Ok(code) => code,
        Err(payload) => {
            let message = panic_payload_to_string(payload.as_ref());
            let error = CliError::Panic(message);
            if let Err(print_error) = emit_error_json(&error) {
                eprintln!(
                    "{{\"ok\":false,\"code\":\"panic\",\"message\":\"{}\"}}",
                    print_error
                );
            }
            ExitCode::FAILURE
        }
    }
}

fn run_with_panic_guard() -> ExitCode {
    match run() {
        Ok(Some(exit_code)) => process::exit(exit_code),
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            error!(code = error.code(), message = %error, "CLI execution failed");
            if let Err(print_error) = emit_error_json(&error) {
                eprintln!(
                    "{{\"ok\":false,\"code\":\"json_error\",\"message\":\"{}\"}}",
                    print_error
                );
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<Option<i32>, CliError> {
    let cli = Cli::try_parse().map_err(|error| CliError::Args(error.to_string()))?;
    let is_human_readable_command = matches!(
        cli.command,
        CliCommand::Doctor | CliCommand::Setup | CliCommand::McpInit(_)
    );

    if !is_human_readable_command {
        info!("mimobox CLI starting");
        info!(command = ?cli.command, "CLI arguments parsed");
    }

    let response = match cli.command {
        CliCommand::Run(args) => CommandResponse::Run(handle_run(args)?),
        CliCommand::Shell(args) => {
            let exit_code = handle_shell(args)?;
            info!(exit_code, "shell subcommand completed");
            return Ok(Some(exit_code));
        }
        CliCommand::Snapshot(args) => CommandResponse::Snapshot(handle_snapshot(args)?),
        CliCommand::Restore(args) => CommandResponse::Restore(handle_restore(args)?),
        CliCommand::Bench(args) => CommandResponse::Bench(handle_bench(args)?),
        CliCommand::Doctor => {
            let exit_code = doctor::run_doctor();
            if !is_human_readable_command {
                info!(exit_code, "doctor subcommand completed");
            }
            return Ok(Some(exit_code));
        }
        CliCommand::Setup => {
            let exit_code = doctor::run_setup();
            if !is_human_readable_command {
                info!(exit_code, "setup subcommand completed");
            }
            return Ok(Some(exit_code));
        }
        CliCommand::McpInit(args) => {
            if let Err(error) = handle_mcp_init(args) {
                eprintln!("{error}");
                return Ok(Some(1));
            }
            return Ok(None);
        }
        CliCommand::Version => CommandResponse::Version(handle_version()),
    };

    let exit_code = success_exit_code(&response);
    emit_success_json(&response)?;
    if !is_human_readable_command {
        info!("CLI execution completed");
    }
    Ok(exit_code)
}

fn init_tracing() -> Result<(), CliError> {
    let log_dir = "logs";
    fs::create_dir_all(log_dir).map_err(|error| CliError::Logging(error.to_string()))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CliError::Logging(error.to_string()))?
        .as_secs();
    let log_path = format!("{log_dir}/mimobox-cli-{timestamp}.log");
    let file = File::options()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| CliError::Logging(error.to_string()))?;
    let file_writer = SharedFileWriter {
        file: Arc::new(Mutex::new(file)),
    };

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(ConditionalStderrWriter)
        .with_target(true);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(file_writer)
        .with_target(true);

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .try_init()
        .map_err(|error| CliError::Logging(error.to_string()))?;

    Ok(())
}

fn handle_run(args: RunArgs) -> Result<RunResponse, CliError> {
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

fn resolve_run_execution_mode(backend: Backend) -> RunExecutionMode {
    match backend {
        Backend::Auto => RunExecutionMode::Sdk,
        Backend::Os | Backend::Wasm | Backend::Kvm => RunExecutionMode::Direct,
    }
}

fn handle_shell(args: ShellArgs) -> Result<i32, CliError> {
    #[cfg(not(unix))]
    {
        let _ = args;
        return Err(CliError::Sdk(
            "shell subcommand only supports Unix terminal environments".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        let deny_network = resolve_shell_deny_network(&args);
        let sdk_config = build_shell_sdk_config(&args, deny_network);
        let pty_config = SdkPtyConfig {
            command: parse_command(&args.command)?,
            size: current_terminal_size().unwrap_or_default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: sdk_config.timeout,
        };

        info!(
            backend = ?args.backend,
            command = %args.command,
            timeout_secs = sdk_config.timeout.as_ref().map(Duration::as_secs),
            deny_network,
            "preparing to execute shell subcommand"
        );

        install_shell_signal_handlers();

        let mut sandbox = SdkSandbox::with_config(sdk_config).map_err(map_sdk_error)?;
        let mut session = match sandbox.create_pty_with_config(pty_config) {
            Ok(session) => session,
            Err(error) => {
                if let Err(destroy_error) = sandbox.destroy() {
                    warn!(message = %destroy_error, "failed to destroy sandbox after shell initialization failure");
                }
                return Err(map_sdk_error(error));
            }
        };

        let shell_result = run_shell_session(&mut session);
        drop(session);

        if let Err(destroy_error) = sandbox.destroy() {
            warn!(message = %destroy_error, "failed to destroy sandbox after shell session");
        }

        shell_result
    }
}

fn handle_snapshot(args: SnapshotArgs) -> Result<SnapshotResponse, CliError> {
    #[cfg(not(all(target_os = "linux", feature = "kvm")))]
    {
        let _ = args;
        Err(CliError::KvmFeatureDisabled)
    }

    #[cfg(all(target_os = "linux", feature = "kvm"))]
    {
        let deny_network = if args.allow_network {
            false
        } else {
            args.deny_network
        };
        let config = build_snapshot_sdk_config(&args, deny_network)?;

        info!(
            output = %args.output,
            init_command = args.init_command.as_deref().unwrap_or("<none>"),
            memory_mb = config.memory_limit_mb,
            timeout_secs = config.timeout.as_ref().map(Duration::as_secs),
            deny_network,
            allow_fork = args.allow_fork,
            kernel = args.kernel.as_deref().unwrap_or("default"),
            rootfs = args.rootfs.as_deref().unwrap_or("default"),
            vcpu_count = args.vcpu_count,
            "preparing to execute snapshot subcommand"
        );

        let mut sandbox = SdkSandbox::with_config(config).map_err(map_sdk_error)?;

        if let Some(init_command) = args.init_command.as_deref() {
            let init_result = sandbox.execute(init_command).map_err(|error| {
                let cli_error = map_sdk_error(error);
                error!(
                    code = cli_error.code(),
                    message = %cli_error,
                    "snapshot init command execution failed"
                );
                cli_error
            })?;

            if init_result.timed_out || init_result.exit_code != Some(0) {
                let stderr = String::from_utf8_lossy(&init_result.stderr);
                let cli_error = CliError::Sdk(format!(
                    "init command failed: exit_code={:?}, timed_out={}, stderr={stderr}",
                    init_result.exit_code, init_result.timed_out,
                ));
                destroy_sdk_sandbox_quietly(
                    sandbox,
                    "cleaning up sandbox after snapshot init failure",
                );
                return Err(cli_error);
            }
        }

        let snapshot = match sandbox.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let cli_error = map_sdk_error(error);
                destroy_sdk_sandbox_quietly(sandbox, "cleaning up sandbox after snapshot failure");
                return Err(cli_error);
            }
        };

        let snapshot_bytes = snapshot.to_bytes().map_err(map_sdk_error)?;
        fs::write(&args.output, &snapshot_bytes)?;
        sandbox.destroy().map_err(map_sdk_error)?;

        Ok(SnapshotResponse {
            output_path: args.output,
            init_command: args.init_command,
            size_bytes: snapshot_bytes.len(),
            backend: Backend::Kvm,
        })
    }
}

fn handle_restore(args: RestoreArgs) -> Result<RestoreResponse, CliError> {
    #[cfg(not(all(target_os = "linux", feature = "kvm")))]
    {
        let _ = args;
        Err(CliError::KvmFeatureDisabled)
    }

    #[cfg(all(target_os = "linux", feature = "kvm"))]
    {
        info!(
            snapshot = %args.snapshot,
            command = %args.command,
            "preparing to execute restore subcommand"
        );

        let snapshot_bytes = fs::read(&args.snapshot)?;
        let snapshot = SdkSnapshot::from_bytes(&snapshot_bytes).map_err(map_sdk_error)?;
        let argv = parse_command(&args.command)?;
        let snapshot_size = snapshot.size();
        let mut sandbox = SdkSandbox::from_snapshot(&snapshot).map_err(map_sdk_error)?;

        let execute_result = match sandbox.execute(&args.command) {
            Ok(result) => result,
            Err(error) => {
                let cli_error = map_sdk_error(error);
                destroy_sdk_sandbox_quietly(
                    sandbox,
                    "cleaning up sandbox after restore execution failure",
                );
                return Err(cli_error);
            }
        };

        sandbox.destroy().map_err(map_sdk_error)?;

        Ok(RestoreResponse {
            snapshot_path: args.snapshot,
            requested_command: args.command,
            argv,
            exit_code: execute_result.exit_code,
            timed_out: execute_result.timed_out,
            elapsed_ms: execute_result.elapsed.as_secs_f64() * 1000.0,
            stdout: String::from_utf8_lossy(&execute_result.stdout).to_string(),
            stderr: String::from_utf8_lossy(&execute_result.stderr).to_string(),
            snapshot_size,
        })
    }
}

fn build_shell_sdk_config(args: &ShellArgs, deny_network: bool) -> SdkConfig {
    let mut config = build_sdk_config(args.memory, args.timeout, deny_network, true);
    config.isolation = backend_to_sdk_isolation(args.backend);
    config
}

fn backend_to_sdk_isolation(backend: Backend) -> SdkIsolationLevel {
    match backend {
        Backend::Auto => SdkIsolationLevel::Auto,
        Backend::Os => SdkIsolationLevel::Os,
        Backend::Wasm => SdkIsolationLevel::Wasm,
        Backend::Kvm => SdkIsolationLevel::MicroVm,
    }
}

fn resolve_shell_deny_network(args: &ShellArgs) -> bool {
    if args.allow_network {
        false
    } else {
        args.deny_network
    }
}

#[cfg(unix)]
fn run_shell_session(session: &mut mimobox_sdk::PtySession) -> Result<i32, CliError> {
    let (input_tx, input_rx) = mpsc::channel();
    spawn_stdin_forwarder(input_tx);

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut exit_code = None;

    loop {
        while let Ok(data) = input_rx.try_recv() {
            session.send_input(&data).map_err(map_sdk_error)?;
        }

        if shell_sigint_received() {
            session.kill().map_err(map_sdk_error)?;
        }

        if shell_sigwinch_received()
            && let Some(size) = current_terminal_size()
        {
            session
                .resize(size.cols, size.rows)
                .map_err(map_sdk_error)?;
        }

        match session.output().recv_timeout(Duration::from_millis(50)) {
            Ok(SdkPtyEvent::Output(data)) => {
                stdout.write_all(&data)?;
                stdout.flush()?;
            }
            Ok(SdkPtyEvent::Exit(code)) => {
                exit_code = Some(code);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    match exit_code {
        Some(code) => session.wait().map_err(map_sdk_error).or(Ok(code)),
        None => session.wait().map_err(map_sdk_error),
    }
}

#[cfg(unix)]
fn spawn_stdin_forwarder(input_tx: mpsc::Sender<Vec<u8>>) {
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let mut buffer = [0_u8; 1024];

        loop {
            match stdin.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if input_tx.send(buffer[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    warn!(message = %error, "failed to read local stdin, stopping input forwarding");
                    break;
                }
            }
        }
    });
}

#[cfg(unix)]
fn current_terminal_size() -> Option<SdkPtySize> {
    // SAFETY: `winsize` is allocated on this stack frame, and `ioctl` only writes to this struct.
    let mut winsize = unsafe { std::mem::zeroed::<libc::winsize>() };
    // SAFETY: `STDOUT_FILENO` is the current process stdout fd; `ioctl` returns an error if it is not a terminal.
    let result = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut winsize) };
    if result != 0 || winsize.ws_col == 0 || winsize.ws_row == 0 {
        return None;
    }

    Some(SdkPtySize {
        cols: winsize.ws_col,
        rows: winsize.ws_row,
    })
}

#[cfg(unix)]
fn install_shell_signal_handlers() {
    SHELL_SIGINT_RECEIVED.store(false, Ordering::SeqCst);
    SHELL_SIGWINCH_RECEIVED.store(false, Ordering::SeqCst);

    // SAFETY: Installs a simple signal handler for the current CLI process; it only writes an atomic flag and performs no async-signal-unsafe operations.
    unsafe {
        libc::signal(
            libc::SIGINT,
            shell_sigint_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGWINCH,
            shell_sigwinch_handler as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(unix)]
fn shell_sigint_received() -> bool {
    SHELL_SIGINT_RECEIVED.swap(false, Ordering::SeqCst)
}

#[cfg(unix)]
fn shell_sigwinch_received() -> bool {
    SHELL_SIGWINCH_RECEIVED.swap(false, Ordering::SeqCst)
}

#[cfg(unix)]
extern "C" fn shell_sigint_handler(_: libc::c_int) {
    SHELL_SIGINT_RECEIVED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
extern "C" fn shell_sigwinch_handler(_: libc::c_int) {
    SHELL_SIGWINCH_RECEIVED.store(true, Ordering::SeqCst);
}

fn handle_bench(args: BenchArgs) -> Result<BenchResponse, CliError> {
    info!(
        target = ?args.target,
        pool_size = DEFAULT_POOL_SIZE,
        iterations = DEFAULT_BENCH_ITERATIONS,
        "preparing to execute bench subcommand"
    );

    let raw_output = capture_benchmark_output(|| {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            run_pool_benchmark(DEFAULT_POOL_SIZE, DEFAULT_BENCH_ITERATIONS)
                .map_err(|error| CliError::Benchmark(error.to_string()))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = args;
            Err(CliError::BenchUnsupported)
        }
    })?;

    let note = match args.target {
        BenchTarget::ColdStart => {
            "The bench subcommand reuses run_pool_benchmark; output includes both cold start and hot acquire summaries."
        }
        BenchTarget::HotAcquire => {
            "The bench subcommand reuses run_pool_benchmark; focus on the hot acquire metrics."
        }
        BenchTarget::WarmThroughput => {
            "The public API only exposes a combined pool benchmark; for finer-grained warm-throughput analysis, use criterion benchmarks directly."
        }
    };

    Ok(BenchResponse {
        target: args.target,
        pool_size: DEFAULT_POOL_SIZE,
        iterations: DEFAULT_BENCH_ITERATIONS,
        raw_output: raw_output.trim().to_string(),
        note,
    })
}

fn handle_mcp_init(args: McpInitArgs) -> Result<(), CliError> {
    let clients = if args.all {
        vec![McpClient::Claude, McpClient::Cursor, McpClient::Windsurf]
    } else {
        vec![
            args.client
                .ok_or_else(|| CliError::McpInit("missing MCP client".to_string()))?,
        ]
    };

    let home_dir = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| CliError::McpInit("HOME environment variable is not set".to_string()))?;
    let binary_path = resolve_mimobox_mcp_binary();

    for client in clients {
        let config_path = mcp_config_path(client, current_mcp_os(), &home_dir);
        configure_mcp_client(client, &config_path, &binary_path)?;
    }

    Ok(())
}

fn configure_mcp_client(
    client: McpClient,
    config_path: &Path,
    binary_path: &str,
) -> Result<(), CliError> {
    let existing_config = read_existing_mcp_config(config_path)?;
    let updated_config = inject_mcp_config(existing_config, binary_path)?;

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            CliError::McpInit(format!(
                "failed to create config directory {}: {error}",
                parent.display()
            ))
        })?;
    }

    let json = serde_json::to_string_pretty(&updated_config)?;
    fs::write(config_path, format!("{json}\n")).map_err(|error| {
        CliError::McpInit(format!(
            "failed to write MCP config {}: {error}",
            config_path.display()
        ))
    })?;

    println!("Configured mimobox-mcp for {}", client.display_name());
    println!("Config: {}", config_path.display());
    println!("Binary: {binary_path}");
    println!("Restart {} to apply changes.", client.display_name());

    Ok(())
}

fn read_existing_mcp_config(config_path: &Path) -> Result<serde_json::Value, CliError> {
    match fs::read_to_string(config_path) {
        Ok(content) => {
            if content.trim().is_empty() {
                Ok(serde_json::json!({}))
            } else {
                serde_json::from_str(&content).map_err(|error| {
                    CliError::McpInit(format!(
                        "failed to parse MCP config {}: {error}",
                        config_path.display()
                    ))
                })
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(serde_json::json!({})),
        Err(error) => Err(CliError::McpInit(format!(
            "failed to read MCP config {}: {error}",
            config_path.display()
        ))),
    }
}

fn inject_mcp_config(
    mut config: serde_json::Value,
    binary_path: &str,
) -> Result<serde_json::Value, CliError> {
    if !config.is_object() {
        config = serde_json::json!({});
    }

    let root = config
        .as_object_mut()
        .ok_or_else(|| CliError::McpInit("MCP config root must be a JSON object".to_string()))?;

    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if !servers.is_object() {
        *servers = serde_json::json!({});
    }

    let servers = servers
        .as_object_mut()
        .ok_or_else(|| CliError::McpInit("mcpServers must be a JSON object".to_string()))?;
    servers.insert(
        "mimobox-mcp".to_string(),
        serde_json::json!({
            "command": binary_path,
            "args": []
        }),
    );

    Ok(config)
}

fn resolve_mimobox_mcp_binary() -> String {
    let binary_name = "mimobox-mcp";

    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|path| path.join(binary_name))
                .find(|candidate| candidate.is_file())
        })
        .and_then(|path| fs::canonicalize(&path).ok().or(Some(path)))
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| binary_name.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpOs {
    Macos,
    Linux,
}

fn current_mcp_os() -> McpOs {
    if cfg!(target_os = "macos") {
        McpOs::Macos
    } else {
        McpOs::Linux
    }
}

fn mcp_config_path(client: McpClient, os: McpOs, home_dir: &Path) -> PathBuf {
    match client {
        McpClient::Claude => match os {
            McpOs::Macos => home_dir
                .join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json"),
            McpOs::Linux => home_dir
                .join(".config")
                .join("Claude")
                .join("claude_desktop_config.json"),
        },
        McpClient::Cursor => home_dir.join(".cursor").join("mcp.json"),
        McpClient::Windsurf => home_dir
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
    }
}

impl McpClient {
    fn display_name(self) -> &'static str {
        match self {
            Self::Claude => "Claude",
            Self::Cursor => "Cursor",
            Self::Windsurf => "Windsurf",
        }
    }
}

fn handle_version() -> VersionResponse {
    info!("preparing to print version info");

    let mut enabled_features = Vec::new();
    if cfg!(feature = "wasm") {
        enabled_features.push("wasm");
    }
    if cfg!(feature = "kvm") {
        enabled_features.push("kvm");
    }

    VersionResponse {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        enabled_features,
        target_os: std::env::consts::OS,
    }
}

fn build_sandbox_config(
    memory: Option<u64>,
    timeout: Option<u64>,
    deny_network: bool,
    allow_fork: bool,
) -> SandboxConfig {
    let mut config = SandboxConfig::default();
    config.memory_limit_mb = Some(memory.unwrap_or(DEFAULT_MEMORY_MB));
    config.timeout_secs = normalize_timeout(timeout);
    config.deny_network = deny_network;
    config.seccomp_profile = resolve_seccomp_profile(deny_network, allow_fork);
    config.allow_fork = allow_fork;
    config
}

fn build_sdk_config(
    memory: Option<u64>,
    timeout: Option<u64>,
    deny_network: bool,
    allow_fork: bool,
) -> SdkConfig {
    SdkConfig {
        memory_limit_mb: Some(memory.unwrap_or(DEFAULT_MEMORY_MB)),
        timeout: normalize_timeout(timeout).map(Duration::from_secs),
        network: build_sdk_network_policy(deny_network),
        allow_fork,
        ..SdkConfig::default()
    }
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn build_snapshot_sdk_config(
    args: &SnapshotArgs,
    deny_network: bool,
) -> Result<SdkConfig, CliError> {
    let mut config = build_sdk_config(args.memory, args.timeout, deny_network, args.allow_fork);
    config.isolation = SdkIsolationLevel::MicroVm;
    config.vm_vcpu_count = args.vcpu_count;

    if let Some(memory) = args.memory {
        config.vm_memory_mb = u32::try_from(memory)
            .map_err(|_| CliError::Args(format!("snapshot memory exceeds u32 range: {memory}")))?;
    }

    if let Some(kernel) = &args.kernel {
        config.kernel_path = Some(std::path::PathBuf::from(kernel));
    }

    if let Some(rootfs) = &args.rootfs {
        config.rootfs_path = Some(std::path::PathBuf::from(rootfs));
    }

    Ok(config)
}

fn build_sdk_network_policy(deny_network: bool) -> SdkNetworkPolicy {
    if deny_network {
        SdkNetworkPolicy::DenyAll
    } else {
        SdkNetworkPolicy::AllowAll
    }
}

fn resolve_run_deny_network(args: &RunArgs) -> bool {
    if args.allow_network {
        false
    } else {
        args.deny_network
    }
}

fn normalize_timeout(timeout: Option<u64>) -> Option<u64> {
    match timeout {
        Some(0) => None,
        Some(value) => Some(value),
        None => Some(DEFAULT_TIMEOUT_SECS),
    }
}

fn resolve_seccomp_profile(deny_network: bool, allow_fork: bool) -> SeccompProfile {
    match (deny_network, allow_fork) {
        (true, true) => SeccompProfile::EssentialWithFork,
        (true, false) => SeccompProfile::Essential,
        (false, true) => SeccompProfile::NetworkWithFork,
        (false, false) => SeccompProfile::Network,
    }
}

fn parse_command(command: &str) -> Result<Vec<String>, CliError> {
    let argv = shlex::split(command).ok_or_else(|| {
        CliError::CommandParse("command string contains unclosed quotes".to_string())
    })?;
    if argv.is_empty() {
        return Err(CliError::EmptyCommand);
    }
    Ok(argv)
}

fn handle_run_via_sdk(
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

fn sdk_result_into_sandbox_result(result: SdkExecuteResult) -> SandboxResult {
    SandboxResult {
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        elapsed: result.elapsed,
        timed_out: result.timed_out,
    }
}

fn map_sdk_error(error: mimobox_sdk::SdkError) -> CliError {
    error.into()
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn destroy_sdk_sandbox_quietly(sandbox: SdkSandbox, context: &str) {
    if let Err(error) = sandbox.destroy() {
        let cli_error = map_sdk_error(error);
        warn!(
            code = cli_error.code(),
            message = %cli_error,
            "{context}"
        );
    }
}

fn apply_stderr_fallback(stderr: &mut Vec<u8>, fallback: Vec<u8>) {
    // Prefer stderr explicitly returned by the backend; use process-level fallback capture only when missing.
    if stderr.is_empty() && !fallback.is_empty() {
        *stderr = fallback;
    }
}

fn backend_from_sdk_isolation(isolation: SdkIsolationLevel) -> Option<Backend> {
    match isolation {
        SdkIsolationLevel::Auto => None,
        SdkIsolationLevel::Os => Some(Backend::Os),
        SdkIsolationLevel::Wasm => Some(Backend::Wasm),
        SdkIsolationLevel::MicroVm => Some(Backend::Kvm),
    }
}

fn success_exit_code(response: &CommandResponse) -> Option<i32> {
    match response {
        CommandResponse::Run(run) => run.exit_code.filter(|code| *code != 0),
        CommandResponse::Restore(restore) => restore.exit_code.filter(|code| *code != 0),
        CommandResponse::Snapshot(_) | CommandResponse::Bench(_) | CommandResponse::Version(_) => {
            None
        }
    }
}

fn emit_success_json(response: &CommandResponse) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(
        &mut handle,
        &SuccessEnvelope {
            ok: true,
            payload: response,
        },
    )?;
    handle.write_all(b"\n")?;
    handle.flush()?;
    Ok(())
}

fn emit_error_json(error: &CliError) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(
        &mut handle,
        &ErrorEnvelope {
            ok: false,
            code: error.code(),
            message: error.to_string(),
        },
    )?;
    handle.write_all(b"\n")?;
    handle.flush()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn execute_os_backend(config: SandboxConfig, argv: &[String]) -> Result<SandboxResult, CliError> {
    info!("executing command via Linux OS backend");
    execute_with_sandbox::<LinuxSandbox>(config, argv)
}

#[cfg(target_os = "macos")]
fn execute_os_backend(config: SandboxConfig, argv: &[String]) -> Result<SandboxResult, CliError> {
    info!("executing command via macOS OS backend");
    execute_with_sandbox::<MacOsSandbox>(config, argv)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn execute_os_backend(_config: SandboxConfig, _argv: &[String]) -> Result<SandboxResult, CliError> {
    Err(CliError::UnsupportedOsBackend)
}

#[cfg(feature = "wasm")]
fn execute_wasm_backend(config: SandboxConfig, argv: &[String]) -> Result<SandboxResult, CliError> {
    info!("executing command via Wasm backend");
    execute_with_sandbox::<WasmSandbox>(config, argv)
}

#[cfg(not(feature = "wasm"))]
fn execute_wasm_backend(
    _config: SandboxConfig,
    _argv: &[String],
) -> Result<SandboxResult, CliError> {
    Err(CliError::WasmFeatureDisabled)
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
fn execute_kvm_backend(
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
fn execute_kvm_backend(
    _config: SandboxConfig,
    _argv: &[String],
    _args: &RunArgs,
) -> Result<SandboxResult, CliError> {
    Err(CliError::KvmFeatureDisabled)
}

fn execute_with_sandbox<S>(
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

fn execute_with_sandbox_specific<S, F>(
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

#[cfg(unix)]
fn capture_benchmark_output<F>(run: F) -> Result<String, CliError>
where
    F: FnOnce() -> Result<(), CliError>,
{
    let (result, output) = capture_fd_output(libc::STDOUT_FILENO, run)?;
    result?;
    String::from_utf8(output).map_err(|error| {
        CliError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("captured stdout is not valid UTF-8: {error}"),
        ))
    })
}

#[cfg(not(unix))]
fn capture_benchmark_output<F>(_run: F) -> Result<String, CliError>
where
    F: FnOnce() -> Result<(), CliError>,
{
    Err(CliError::BenchUnsupported)
}

#[cfg(unix)]
fn capture_stderr_bytes<F, T>(run: F) -> Result<(T, Vec<u8>), CliError>
where
    F: FnOnce() -> T,
{
    capture_fd_output(libc::STDERR_FILENO, run)
}

#[cfg(not(unix))]
fn capture_stderr_bytes<F, T>(run: F) -> Result<(T, Vec<u8>), CliError>
where
    F: FnOnce() -> T,
{
    Ok((run(), Vec::new()))
}

#[cfg(unix)]
fn capture_fd_output<F, T>(target_fd: libc::c_int, run: F) -> Result<(T, Vec<u8>), CliError>
where
    F: FnOnce() -> T,
{
    let _capture_guard = fd_capture_lock()
        .lock()
        .map_err(|_| CliError::Io(io::Error::other("fd capture lock poisoned")))?;
    let mut capture = FdCapture::start(target_fd)?;
    let outcome = if target_fd == libc::STDERR_FILENO {
        let _guard = StderrLoggingGuard::suspend();
        run()
    } else {
        run()
    };
    let output = capture.finish()?;
    Ok((outcome, output))
}

#[cfg(unix)]
fn fd_capture_lock() -> &'static Mutex<()> {
    static FD_CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    FD_CAPTURE_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(unix)]
struct FdCapture {
    target_fd: libc::c_int,
    saved_fd: Option<OwnedFd>,
    read_file: Option<File>,
}

#[cfg(unix)]
impl FdCapture {
    fn start(target_fd: libc::c_int) -> Result<Self, CliError> {
        flush_standard_fd(target_fd)?;

        let mut pipe_fds = [-1; 2];
        // SAFETY: `pipe_fds` points to two valid `c_int` slots; `pipe` writes the read and write ends on success.
        let pipe_result = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        if pipe_result != 0 {
            return Err(CliError::Io(io::Error::last_os_error()));
        }

        // SAFETY: Ownership of fds returned by `pipe` is transferred to `File` / `OwnedFd` exactly once.
        let read_file = unsafe { File::from_raw_fd(pipe_fds[0]) };
        // SAFETY: Ownership of fds returned by `pipe` is transferred to `OwnedFd` exactly once.
        let write_fd = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        // SAFETY: `dup` duplicates the current target fd and returns a new independent fd.
        let saved_fd_raw = unsafe { libc::dup(target_fd) };
        if saved_fd_raw < 0 {
            return Err(CliError::Io(io::Error::last_os_error()));
        }
        // SAFETY: The fd returned by successful `dup` is transferred here to exclusive `OwnedFd` ownership.
        let saved_fd = unsafe { OwnedFd::from_raw_fd(saved_fd_raw) };

        // SAFETY: Redirects the target fd to the pipe write end. Both fds are valid open descriptors in this process.
        let dup_result = unsafe { libc::dup2(write_fd.as_raw_fd(), target_fd) };
        if dup_result < 0 {
            return Err(CliError::Io(io::Error::last_os_error()));
        }

        Ok(Self {
            target_fd,
            saved_fd: Some(saved_fd),
            read_file: Some(read_file),
        })
    }

    fn finish(&mut self) -> Result<Vec<u8>, CliError> {
        self.restore()?;

        let mut output = Vec::new();
        if let Some(read_file) = self.read_file.as_mut() {
            read_file.read_to_end(&mut output)?;
        }
        Ok(output)
    }

    fn restore(&mut self) -> Result<(), CliError> {
        flush_standard_fd(self.target_fd)?;

        if let Some(saved_fd) = self.saved_fd.as_ref() {
            // SAFETY: `saved_fd` is a valid fd duplicated earlier via `dup`, so it can safely restore the original standard stream.
            let restore_result = unsafe { libc::dup2(saved_fd.as_raw_fd(), self.target_fd) };
            if restore_result < 0 {
                return Err(CliError::Io(io::Error::last_os_error()));
            }
        }

        self.saved_fd = None;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for FdCapture {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(unix)]
fn flush_standard_fd(target_fd: libc::c_int) -> Result<(), CliError> {
    match target_fd {
        libc::STDOUT_FILENO => io::stdout().flush()?,
        libc::STDERR_FILENO => io::stderr().flush()?,
        _ => {}
    }
    Ok(())
}

fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

struct SharedFileGuard {
    file: Arc<Mutex<File>>,
}

#[derive(Clone, Copy)]
struct ConditionalStderrWriter;

struct ConditionalStderrGuard {
    muted: bool,
}

struct StderrLoggingGuard {
    previous: bool,
}

impl StderrLoggingGuard {
    fn suspend() -> Self {
        let previous = STDERR_LOGGING_ENABLED.with(|flag| flag.replace(false));
        Self { previous }
    }
}

impl Drop for StderrLoggingGuard {
    fn drop(&mut self) {
        STDERR_LOGGING_ENABLED.with(|flag| flag.set(self.previous));
    }
}

impl<'a> MakeWriter<'a> for SharedFileWriter {
    type Writer = SharedFileGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedFileGuard {
            file: Arc::clone(&self.file),
        }
    }
}

impl<'a> MakeWriter<'a> for ConditionalStderrWriter {
    type Writer = ConditionalStderrGuard;

    fn make_writer(&'a self) -> Self::Writer {
        let muted = STDERR_LOGGING_ENABLED.with(|flag| !flag.get());
        ConditionalStderrGuard { muted }
    }
}

impl Write for SharedFileGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;
        file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;
        file.flush()
    }
}

impl Write for ConditionalStderrGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.muted {
            Ok(buf.len())
        } else {
            io::stderr().write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.muted {
            Ok(())
        } else {
            io::stderr().flush()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimobox_core::SeccompProfile;

    #[test]
    fn run_subcommand_parses_expected_flags() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "run",
            "--backend",
            "wasm",
            "--command",
            "/bin/echo hello",
            "--memory",
            "128",
            "--timeout",
            "5",
            "--deny-network",
            "--allow-fork",
        ])
        .expect("run subcommand should parse successfully");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Wasm);
                assert_eq!(args.command, "/bin/echo hello");
                assert_eq!(args.memory, Some(128));
                assert_eq!(args.timeout, Some(5));
                assert!(args.deny_network);
                assert!(!args.allow_network);
                assert!(args.allow_fork);
            }
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn run_subcommand_uses_requested_defaults() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "run",
            "--backend",
            "os",
            "--command",
            "/bin/echo hello",
        ])
        .expect("minimal run subcommand should parse successfully");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Os);
                assert_eq!(args.memory, None);
                assert_eq!(args.timeout, None);
                assert!(!args.deny_network);
                assert!(!args.allow_network);
                assert!(!args.allow_fork);
            }
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn run_subcommand_defaults_to_auto_backend() {
        let cli = Cli::try_parse_from(["mimobox", "run", "--command", "/bin/echo hello"])
            .expect("should default to auto when backend is not specified");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Auto);
                assert_eq!(args.command, "/bin/echo hello");
            }
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn shell_subcommand_parses_expected_defaults() {
        let cli = Cli::try_parse_from(["mimobox", "shell"])
            .expect("shell subcommand should parse successfully");

        match cli.command {
            CliCommand::Shell(args) => {
                assert_eq!(args.backend, Backend::Auto);
                assert_eq!(args.command, "/bin/sh");
                assert_eq!(args.memory, None);
                assert_eq!(args.timeout, None);
                assert!(!args.deny_network);
                assert!(!args.allow_network);
            }
            _ => panic!("expected shell subcommand"),
        }
    }

    #[test]
    fn snapshot_subcommand_parses_expected_flags() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "snapshot",
            "--output",
            "/tmp/base.snap",
            "--init-command",
            "/bin/echo seed",
            "--memory",
            "256",
            "--timeout",
            "9",
            "--deny-network",
            "--allow-fork",
            "--kernel",
            "/tmp/vmlinux",
            "--rootfs",
            "/tmp/rootfs.cpio.gz",
            "--vcpu-count",
            "2",
        ])
        .expect("snapshot subcommand should parse successfully");

        match cli.command {
            CliCommand::Snapshot(args) => {
                assert_eq!(args.output, "/tmp/base.snap");
                assert_eq!(args.init_command.as_deref(), Some("/bin/echo seed"));
                assert_eq!(args.memory, Some(256));
                assert_eq!(args.timeout, Some(9));
                assert!(args.deny_network);
                assert!(args.allow_fork);
                assert_eq!(args.kernel.as_deref(), Some("/tmp/vmlinux"));
                assert_eq!(args.rootfs.as_deref(), Some("/tmp/rootfs.cpio.gz"));
                assert_eq!(args.vcpu_count, 2);
            }
            _ => panic!("expected snapshot subcommand"),
        }
    }

    #[test]
    fn restore_subcommand_parses_expected_flags() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "restore",
            "--snapshot",
            "/tmp/base.snap",
            "--command",
            "/bin/echo hello",
        ])
        .expect("restore subcommand should parse successfully");

        match cli.command {
            CliCommand::Restore(args) => {
                assert_eq!(args.snapshot, "/tmp/base.snap");
                assert_eq!(args.command, "/bin/echo hello");
            }
            _ => panic!("expected restore subcommand"),
        }
    }

    #[test]
    fn auto_backend_routes_to_sdk_executor() {
        assert_eq!(
            resolve_run_execution_mode(Backend::Auto),
            RunExecutionMode::Sdk
        );
        assert_eq!(
            resolve_run_execution_mode(Backend::Os),
            RunExecutionMode::Direct
        );
        assert_eq!(
            resolve_run_execution_mode(Backend::Wasm),
            RunExecutionMode::Direct
        );
        assert_eq!(
            resolve_run_execution_mode(Backend::Kvm),
            RunExecutionMode::Direct
        );
    }

    #[test]
    fn shell_sdk_config_forces_allow_fork() {
        let args = ShellArgs {
            backend: Backend::Os,
            command: "/bin/sh".to_string(),
            memory: Some(256),
            timeout: Some(10),
            deny_network: true,
            allow_network: false,
        };

        let config = build_shell_sdk_config(&args, true);
        assert!(config.allow_fork);
        assert_eq!(config.isolation, SdkIsolationLevel::Os);
        assert!(matches!(config.network, SdkNetworkPolicy::DenyAll));
    }

    #[test]
    fn sdk_config_maps_cli_flags() {
        let config = build_sdk_config(Some(256), Some(10), true, true);

        assert_eq!(config.memory_limit_mb, Some(256));
        assert_eq!(config.timeout, Some(std::time::Duration::from_secs(10)));
        assert!(matches!(
            config.network,
            mimobox_sdk::NetworkPolicy::DenyAll
        ));
        assert!(config.allow_fork);
    }

    #[test]
    fn sdk_config_maps_allow_network_to_allow_all() {
        let config = build_sdk_config(Some(256), Some(10), false, false);

        assert!(matches!(
            config.network,
            mimobox_sdk::NetworkPolicy::AllowAll
        ));
    }

    #[test]
    fn run_subcommand_parses_allow_network_flag() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "run",
            "--backend",
            "os",
            "--command",
            "/bin/echo hello",
            "--allow-network",
        ])
        .expect("allow-network flag should parse successfully");

        match cli.command {
            CliCommand::Run(args) => {
                assert!(!args.deny_network);
                assert!(args.allow_network);
                assert!(!resolve_run_deny_network(&args));
            }
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn run_subcommand_rejects_conflicting_network_flags() {
        let error = Cli::try_parse_from([
            "mimobox",
            "run",
            "--command",
            "/bin/echo hello",
            "--deny-network",
            "--allow-network",
        ])
        .expect_err("conflicting network flags should not both be present");

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn run_subcommand_parses_kvm_specific_flags() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "run",
            "--backend",
            "kvm",
            "--command",
            "/bin/echo hello",
            "--kernel",
            "/tmp/vmlinux",
            "--rootfs",
            "/tmp/rootfs.cpio.gz",
            "--vcpu-count",
            "2",
        ])
        .expect("kvm run subcommand should parse successfully");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Kvm);
                assert_eq!(args.kernel.as_deref(), Some("/tmp/vmlinux"));
                assert_eq!(args.rootfs.as_deref(), Some("/tmp/rootfs.cpio.gz"));
                assert_eq!(args.vcpu_count, 2);
            }
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn run_subcommand_uses_kvm_defaults() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "run",
            "--backend",
            "kvm",
            "--command",
            "/bin/echo hello",
        ])
        .expect("minimal kvm run subcommand should parse successfully");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Kvm);
                assert_eq!(args.kernel, None);
                assert_eq!(args.rootfs, None);
                assert_eq!(args.vcpu_count, 1);
            }
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn bench_subcommand_parses_target() {
        let cli = Cli::try_parse_from(["mimobox", "bench", "--target", "hot-acquire"])
            .expect("bench subcommand should parse successfully");

        match cli.command {
            CliCommand::Bench(args) => {
                assert_eq!(args.target, BenchTarget::HotAcquire);
            }
            _ => panic!("expected bench subcommand"),
        }
    }

    #[test]
    fn bench_subcommand_rejects_legacy_pool_flags() {
        let error = Cli::try_parse_from([
            "mimobox",
            "bench",
            "--target",
            "cold-start",
            "--pool-size",
            "8",
        ])
        .expect_err("bench subcommand should no longer accept pool flags");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn mcp_init_subcommand_parses_clients() {
        for (raw_client, expected_client) in [
            ("claude", McpClient::Claude),
            ("cursor", McpClient::Cursor),
            ("windsurf", McpClient::Windsurf),
        ] {
            let cli = Cli::try_parse_from(["mimobox", "mcp-init", raw_client])
                .expect("mcp-init client should parse successfully");

            match cli.command {
                CliCommand::McpInit(args) => {
                    assert_eq!(args.client, Some(expected_client));
                    assert!(!args.all);
                }
                _ => panic!("expected mcp-init subcommand"),
            }
        }
    }

    #[test]
    fn mcp_init_subcommand_parses_all_flag() {
        let cli = Cli::try_parse_from(["mimobox", "mcp-init", "--all"])
            .expect("mcp-init --all should parse successfully");

        match cli.command {
            CliCommand::McpInit(args) => {
                assert_eq!(args.client, None);
                assert!(args.all);
            }
            _ => panic!("expected mcp-init subcommand"),
        }
    }

    #[test]
    fn inject_mcp_config_preserves_existing_servers() {
        let input = serde_json::json!({
            "mcpServers": {
                "existing-server": {
                    "command": "/usr/bin/existing",
                    "args": ["--keep"]
                },
                "mimobox-mcp": {
                    "command": "/old/mimobox-mcp"
                }
            },
            "other": true
        });

        let output = inject_mcp_config(input, "/usr/local/bin/mimobox-mcp")
            .expect("JSON config injection should succeed");

        assert_eq!(output["other"], serde_json::json!(true));
        assert_eq!(
            output["mcpServers"]["existing-server"],
            serde_json::json!({
                "command": "/usr/bin/existing",
                "args": ["--keep"]
            })
        );
        assert_eq!(
            output["mcpServers"]["mimobox-mcp"],
            serde_json::json!({
                "command": "/usr/local/bin/mimobox-mcp",
                "args": []
            })
        );
    }

    #[test]
    fn mcp_config_path_calculates_platform_specific_paths() {
        let home = PathBuf::from("/home/alice");

        assert_eq!(
            mcp_config_path(McpClient::Claude, McpOs::Linux, &home),
            PathBuf::from("/home/alice/.config/Claude/claude_desktop_config.json")
        );
        assert_eq!(
            mcp_config_path(McpClient::Claude, McpOs::Macos, &home),
            PathBuf::from(
                "/home/alice/Library/Application Support/Claude/claude_desktop_config.json"
            )
        );
        assert_eq!(
            mcp_config_path(McpClient::Cursor, McpOs::Linux, &home),
            PathBuf::from("/home/alice/.cursor/mcp.json")
        );
        assert_eq!(
            mcp_config_path(McpClient::Windsurf, McpOs::Macos, &home),
            PathBuf::from("/home/alice/.codeium/windsurf/mcp_config.json")
        );
    }

    #[test]
    fn doctor_subcommand_parses() {
        let cli = Cli::try_parse_from(["mimobox", "doctor"])
            .expect("doctor subcommand should parse successfully");

        assert!(matches!(cli.command, CliCommand::Doctor));
    }

    #[test]
    fn setup_subcommand_parses() {
        let cli = Cli::try_parse_from(["mimobox", "setup"])
            .expect("setup subcommand should parse successfully");

        assert!(matches!(cli.command, CliCommand::Setup));
    }

    #[test]
    fn version_subcommand_parses() {
        let cli = Cli::try_parse_from(["mimobox", "version"])
            .expect("version subcommand should parse successfully");

        assert!(matches!(cli.command, CliCommand::Version));
    }

    #[test]
    fn kvm_backend_is_accepted() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "run",
            "--backend",
            "kvm",
            "--command",
            "/bin/echo hello",
        ])
        .expect("run subcommand should accept kvm backend");

        match cli.command {
            CliCommand::Run(args) => assert_eq!(args.backend, Backend::Kvm),
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn sandbox_config_maps_network_and_fork_flags() {
        let config = build_sandbox_config(Some(256), Some(10), false, true);

        assert_eq!(config.memory_limit_mb, Some(256));
        assert_eq!(config.timeout_secs, Some(10));
        assert!(!config.deny_network);
        assert!(config.allow_fork);
        assert!(matches!(
            config.seccomp_profile,
            SeccompProfile::NetworkWithFork
        ));
    }

    #[test]
    fn command_parser_rejects_unbalanced_quotes() {
        let error =
            parse_command("/bin/sh -c 'echo").expect_err("unclosed quotes should return error");

        assert_eq!(error.code(), "command_parse_error");
    }

    #[test]
    fn sdk_config_error_is_preserved_in_cli_error() {
        let error = handle_run_via_sdk("/bin/sh -c 'echo", Some(128), Some(5), true, false)
            .expect_err("SDK config error should map to CLI error");

        assert_eq!(error.code(), "sdk_error");
        assert!(error.to_string().contains("config error"));
        assert!(error.to_string().contains("mismatched shell-style quotes"));
    }

    #[test]
    fn sdk_backend_unavailable_maps_to_feature_specific_cli_error() {
        let error = map_sdk_error(mimobox_sdk::SdkError::BackendUnavailable("wasm"));

        assert_eq!(error.code(), "wasm_feature_disabled");
    }

    #[test]
    fn auto_backend_run_response_reports_resolved_backend() {
        let response = handle_run(RunArgs {
            backend: Backend::Auto,
            command: "/bin/echo hello".to_string(),
            memory: Some(128),
            timeout: Some(5),
            deny_network: true,
            allow_network: false,
            allow_fork: false,
            kernel: None,
            rootfs: None,
            vcpu_count: 1,
        })
        .expect("auto routing execution should succeed");

        assert_eq!(response.backend, Backend::Os);
        assert_eq!(response.requested_backend, Backend::Auto);
    }

    #[test]
    fn sdk_isolation_maps_to_cli_backend() {
        assert_eq!(
            backend_from_sdk_isolation(SdkIsolationLevel::Os),
            Some(Backend::Os)
        );
        assert_eq!(
            backend_from_sdk_isolation(SdkIsolationLevel::Wasm),
            Some(Backend::Wasm)
        );
        assert_eq!(
            backend_from_sdk_isolation(SdkIsolationLevel::MicroVm),
            Some(Backend::Kvm)
        );
        assert_eq!(backend_from_sdk_isolation(SdkIsolationLevel::Auto), None);
    }

    #[test]
    fn stderr_fallback_only_fills_missing_value() {
        let mut stderr = Vec::new();
        apply_stderr_fallback(&mut stderr, b"fail".to_vec());
        assert_eq!(stderr, b"fail");

        apply_stderr_fallback(&mut stderr, b"fallback".to_vec());
        assert_eq!(stderr, b"fail");
    }

    #[test]
    fn success_exit_code_ignores_zero_and_non_run_response() {
        let version_response = CommandResponse::Version(handle_version());
        assert_eq!(success_exit_code(&version_response), None);

        let snapshot_response = CommandResponse::Snapshot(SnapshotResponse {
            output_path: "/tmp/base.snap".to_string(),
            init_command: None,
            size_bytes: 128,
            backend: Backend::Kvm,
        });
        assert_eq!(success_exit_code(&snapshot_response), None);

        let zero_exit_response = CommandResponse::Run(RunResponse {
            backend: Backend::Os,
            requested_backend: Backend::Os,
            requested_command: "/bin/true".to_string(),
            argv: vec!["/bin/true".to_string()],
            exit_code: Some(0),
            timed_out: false,
            elapsed_ms: 1.0,
            stdout: String::new(),
            stderr: String::new(),
            memory_mb: Some(64),
            timeout_secs: Some(30),
            deny_network: false,
            allow_fork: false,
        });
        assert_eq!(success_exit_code(&zero_exit_response), None);
    }

    #[test]
    fn success_exit_code_propagates_non_zero_run_exit_code() {
        let response = CommandResponse::Run(RunResponse {
            backend: Backend::Os,
            requested_backend: Backend::Os,
            requested_command: "/bin/false".to_string(),
            argv: vec!["/bin/false".to_string()],
            exit_code: Some(7),
            timed_out: false,
            elapsed_ms: 1.0,
            stdout: String::new(),
            stderr: String::new(),
            memory_mb: Some(64),
            timeout_secs: Some(30),
            deny_network: false,
            allow_fork: false,
        });

        assert_eq!(success_exit_code(&response), Some(7));
    }

    #[test]
    fn success_exit_code_propagates_non_zero_restore_exit_code() {
        let response = CommandResponse::Restore(RestoreResponse {
            snapshot_path: "/tmp/base.snap".to_string(),
            requested_command: "/bin/false".to_string(),
            argv: vec!["/bin/false".to_string()],
            exit_code: Some(9),
            timed_out: false,
            elapsed_ms: 1.0,
            stdout: String::new(),
            stderr: String::new(),
            snapshot_size: 256,
        });

        assert_eq!(success_exit_code(&response), Some(9));
    }

    #[cfg(unix)]
    #[test]
    fn capture_stderr_bytes_reads_process_stderr() {
        let (value, stderr) = capture_stderr_bytes(|| {
            // Write and flush stderr directly so eprint!'s buffering layer does not bypass fd 2 capture.
            let mut stderr = io::stderr();
            write!(stderr, "fail").expect("writing to stderr should succeed");
            stderr.flush().expect("flushing stderr should succeed");
            7
        })
        .expect("stderr capture should succeed");

        assert_eq!(value, 7);
        assert_eq!(stderr, b"fail");
    }
}
