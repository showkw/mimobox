pub mod bench;
pub mod cat;
pub mod code;
pub mod completions;
pub mod ls;
pub mod mcp_init;
pub mod run;
pub mod shell;
pub mod snapshot;
pub mod version;
pub mod write;

pub(crate) use bench::handle_bench;
pub(crate) use cat::handle_cat;
pub(crate) use code::handle_code;
pub(crate) use completions::{CompletionsArgs, handle_completions};
pub(crate) use ls::handle_ls;
pub(crate) use mcp_init::{handle_mcp_init, inject_mcp_config, resolve_mimobox_mcp_binary};
pub(crate) use run::handle_run;
#[cfg(test)]
pub(crate) use run::handle_run_via_sdk;
pub(crate) use shell::handle_shell;
pub(crate) use snapshot::{handle_restore, handle_snapshot};
pub(crate) use version::handle_version;
pub(crate) use write::handle_write;

use std::io::{self, Write};
use std::time::Duration;

use clap::{ArgAction, Args, ValueEnum};
use mimobox_core::{SandboxConfig, SandboxError, SandboxResult, SeccompProfile};
use mimobox_sdk::{
    Config as SdkConfig, DirEntry, ExecuteResult as SdkExecuteResult,
    IsolationLevel as SdkIsolationLevel, NetworkPolicy as SdkNetworkPolicy, Sandbox as SdkSandbox,
};
use serde::Serialize;
use thiserror::Error;
use tracing::{error, warn};

use crate::{DEFAULT_MEMORY_MB, DEFAULT_TIMEOUT_SECS};

const MAX_DISPLAY_COMMAND_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Backend {
    #[default]
    Auto,
    Os,
    Wasm,
    #[value(name = "kvm", help = "KVM-based microVM backend")]
    Kvm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BenchTarget {
    ColdStart,
    HotAcquire,
    WarmThroughput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum McpClient {
    Claude,
    #[value(name = "claude-code")]
    ClaudeCode,
    Cursor,
    Windsurf,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Select backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    pub(crate) backend: Backend,

    /// Command string to execute (shell-style, for example "/bin/echo hello")
    #[arg(long, value_name = "cmd")]
    pub(crate) command: Option<String>,

    /// argv arguments to execute directly; place them after options and use `--` when needed.
    #[arg(
        value_name = "argv",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 1..,
        required_unless_present = "command",
        conflicts_with = "command"
    )]
    pub(crate) argv: Vec<String>,

    /// Memory limit in MB
    #[arg(long)]
    pub(crate) memory: Option<u64>,

    /// Timeout in seconds; pass 0 to disable timeout (commands may run indefinitely)
    #[arg(long)]
    pub(crate) timeout: Option<u64>,

    /// Deny network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "allow_network")]
    pub(crate) deny_network: bool,

    /// Allow network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "deny_network")]
    pub(crate) allow_network: bool,

    /// Allow child process fork/clone
    #[arg(long, default_value_t = false)]
    pub(crate) allow_fork: bool,

    /// Path to the KVM kernel image
    #[arg(long)]
    pub(crate) kernel: Option<String>,

    /// Path to the KVM rootfs
    #[arg(long)]
    pub(crate) rootfs: Option<String>,

    /// Number of KVM vCPUs
    #[arg(long, default_value_t = 1)]
    pub(crate) vcpu_count: u8,
}

#[derive(Debug, Args)]
pub(crate) struct ShellArgs {
    /// Select backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    pub(crate) backend: Backend,

    /// Command to run; defaults to /bin/sh
    #[arg(long, value_name = "cmd", default_value = "/bin/sh")]
    pub(crate) command: String,

    /// Memory limit in MB
    #[arg(long)]
    pub(crate) memory: Option<u64>,

    /// Timeout in seconds; pass 0 to disable timeout (commands may run indefinitely)
    #[arg(long)]
    pub(crate) timeout: Option<u64>,

    /// Deny network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "allow_network")]
    pub(crate) deny_network: bool,

    /// Allow network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "deny_network")]
    pub(crate) allow_network: bool,
}

#[derive(Debug, Args)]
pub(crate) struct CodeArgs {
    /// Select backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    pub(crate) backend: Backend,

    /// Programming language to execute
    #[arg(short = 'l', long)]
    pub(crate) language: String,

    /// Code snippet to execute
    #[arg(short = 'c', long)]
    pub(crate) code: String,

    /// Timeout in seconds; pass 0 to disable timeout (commands may run indefinitely)
    #[arg(short = 't', long)]
    pub(crate) timeout: Option<u64>,
}

#[derive(Debug, Args)]
pub(crate) struct LsArgs {
    /// Directory path inside the sandbox
    #[arg(value_name = "path")]
    pub(crate) path: String,

    /// Select backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    pub(crate) backend: Backend,
}

#[derive(Debug, Args)]
pub(crate) struct CatArgs {
    /// File path inside the sandbox
    #[arg(value_name = "path")]
    pub(crate) path: String,

    /// Select backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    pub(crate) backend: Backend,
}

#[derive(Debug, Args)]
pub(crate) struct WriteArgs {
    /// File path inside the sandbox
    #[arg(value_name = "path")]
    pub(crate) path: String,

    /// Inline content to write
    #[arg(long, conflicts_with = "file", required_unless_present = "file")]
    pub(crate) content: Option<String>,

    /// Local file path whose bytes should be written
    #[arg(long, value_name = "path", conflicts_with = "content")]
    pub(crate) file: Option<String>,

    /// Select backend
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    pub(crate) backend: Backend,
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotArgs {
    /// Snapshot output file path
    #[arg(long, value_name = "path")]
    pub(crate) output: String,

    /// Initialization command to run before snapshotting
    #[arg(long, value_name = "cmd")]
    pub(crate) init_command: Option<String>,

    /// Memory limit in MB
    #[arg(long)]
    pub(crate) memory: Option<u64>,

    /// Timeout in seconds; pass 0 to disable timeout (commands may run indefinitely)
    #[arg(long)]
    pub(crate) timeout: Option<u64>,

    /// Deny network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "allow_network")]
    pub(crate) deny_network: bool,

    /// Allow network access
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "deny_network")]
    pub(crate) allow_network: bool,

    /// Allow child process fork/clone
    #[arg(long, default_value_t = false)]
    pub(crate) allow_fork: bool,

    /// Path to the KVM kernel image
    #[arg(long)]
    pub(crate) kernel: Option<String>,

    /// Path to the KVM rootfs
    #[arg(long)]
    pub(crate) rootfs: Option<String>,

    /// Number of KVM vCPUs
    #[arg(long, default_value_t = 1)]
    pub(crate) vcpu_count: u8,
}

#[derive(Debug, Args)]
pub(crate) struct RestoreArgs {
    /// Snapshot file path
    #[arg(long, value_name = "path")]
    pub(crate) snapshot: String,

    /// Command to execute after restoration
    #[arg(long, value_name = "cmd")]
    pub(crate) command: String,
}

#[derive(Debug, Args)]
pub(crate) struct BenchArgs {
    /// Benchmark target
    #[arg(long, value_enum)]
    pub(crate) target: BenchTarget,
}

#[derive(Debug, Args)]
pub(crate) struct McpInitArgs {
    /// MCP client to configure
    #[arg(value_enum, required_unless_present = "all", conflicts_with = "all")]
    pub(crate) client: Option<McpClient>,

    /// Configure all supported MCP clients
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) all: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct SuccessEnvelope<T>
where
    T: Serialize,
{
    ok: bool,
    #[serde(flatten)]
    payload: T,
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorEnvelope {
    pub(crate) ok: bool,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub(crate) enum CommandResponse {
    Run(RunResponse),
    Code(CodeResponse),
    Ls(LsResponse),
    Cat(CatResponse),
    Write(WriteResponse),
    Snapshot(SnapshotResponse),
    Restore(RestoreResponse),
    Bench(BenchResponse),
    Version(VersionResponse),
}

#[derive(Debug, Serialize)]
pub(crate) struct RunResponse {
    pub(crate) backend: Backend,
    pub(crate) requested_backend: Backend,
    #[serde(serialize_with = "serialize_requested_command")]
    pub(crate) requested_command: String,
    pub(crate) argv: Vec<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) elapsed_ms: f64,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) memory_mb: Option<u64>,
    pub(crate) timeout_secs: Option<u64>,
    pub(crate) deny_network: bool,
    pub(crate) allow_fork: bool,
}

fn serialize_requested_command<S>(command: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&truncate_for_display(command))
}

fn truncate_for_display(value: &str) -> String {
    let mut truncated = String::new();
    for (index, character) in value.chars().enumerate() {
        if index == MAX_DISPLAY_COMMAND_CHARS {
            truncated.push_str("...");
            return truncated;
        }
        truncated.push(character);
    }
    value.to_string()
}

#[derive(Debug, Serialize)]
pub(crate) struct CodeResponse {
    pub(crate) language: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) elapsed_ms: f64,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct LsResponse {
    pub(crate) path: String,
    pub(crate) entries: Vec<DirEntry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CatResponse {
    pub(crate) path: String,
    pub(crate) size_bytes: usize,
    pub(crate) content_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct WriteResponse {
    pub(crate) path: String,
    pub(crate) bytes_written: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct SnapshotResponse {
    pub(crate) output_path: String,
    pub(crate) init_command: Option<String>,
    pub(crate) size_bytes: usize,
    pub(crate) backend: Backend,
}

#[derive(Debug, Serialize)]
pub(crate) struct RestoreResponse {
    pub(crate) snapshot_path: String,
    pub(crate) requested_command: String,
    pub(crate) argv: Vec<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) elapsed_ms: f64,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) snapshot_size: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct BenchResponse {
    pub(crate) target: BenchTarget,
    pub(crate) pool_size: usize,
    pub(crate) iterations: usize,
    pub(crate) raw_output: String,
    pub(crate) note: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct VersionResponse {
    pub(crate) name: &'static str,
    pub(crate) version: &'static str,
    pub(crate) git_hash: &'static str,
    pub(crate) target_triple: &'static str,
    pub(crate) enabled_features: Vec<&'static str>,
    pub(crate) target_os: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunExecutionMode {
    Sdk,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunCommandInput {
    Command { command: String, argv: Vec<String> },
    Argv(Vec<String>),
}

impl RunCommandInput {
    /// Provides the requested command operation.
    pub(crate) fn requested_command(&self) -> String {
        match self {
            Self::Command { command, .. } => command.clone(),
            Self::Argv(argv) => argv.join(" "),
        }
    }

    /// Provides the argv operation.
    pub(crate) fn argv(&self) -> &[String] {
        match self {
            Self::Command { argv, .. } | Self::Argv(argv) => argv,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum CliError {
    #[error("argument parsing failed: {0}")]
    Args(String),

    #[error("command string parse failed: {0}")]
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
    /// Provides the code operation.
    pub(crate) fn code(&self) -> &'static str {
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

#[derive(Debug)]
pub(crate) struct RunExecution {
    pub(crate) backend: Backend,
    pub(crate) result: SandboxResult,
}

/// Builds the sandbox config value.
pub(crate) fn build_sandbox_config(
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

/// Builds the sdk config value.
pub(crate) fn build_sdk_config(
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

/// Builds the cli sdk config value.
pub(crate) fn build_cli_sdk_config(
    backend: Backend,
    timeout: Option<u64>,
    allow_fork: bool,
) -> SdkConfig {
    let mut config = build_sdk_config(None, timeout, true, allow_fork);
    config.isolation = backend_to_sdk_isolation(backend);
    config
}

/// Provides the backend to sdk isolation operation.
pub(crate) fn backend_to_sdk_isolation(backend: Backend) -> SdkIsolationLevel {
    match backend {
        Backend::Auto => SdkIsolationLevel::Auto,
        Backend::Os => SdkIsolationLevel::Os,
        Backend::Wasm => SdkIsolationLevel::Wasm,
        Backend::Kvm => SdkIsolationLevel::MicroVm,
    }
}

#[cfg(all(target_os = "linux", feature = "kvm"))]
/// Builds the snapshot sdk config value.
pub(crate) fn build_snapshot_sdk_config(
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

/// Builds the sdk network policy value.
pub(crate) fn build_sdk_network_policy(deny_network: bool) -> SdkNetworkPolicy {
    if deny_network {
        SdkNetworkPolicy::DenyAll
    } else {
        SdkNetworkPolicy::AllowAll
    }
}

/// Resolves the run deny network value.
pub(crate) fn resolve_run_deny_network(args: &RunArgs) -> bool {
    !args.allow_network
}

/// Provides the normalize timeout operation.
///
/// 当传入 `--timeout 0` 时返回 `None`（无超时限制），并发出警告。
/// 默认使用 `DEFAULT_TIMEOUT_SECS`。
pub(crate) fn normalize_timeout(timeout: Option<u64>) -> Option<u64> {
    match timeout {
        Some(0) => {
            tracing::warn!("timeout=0 disables execution timeout; commands may run indefinitely");
            None
        }
        Some(value) => Some(value),
        None => Some(DEFAULT_TIMEOUT_SECS),
    }
}

/// Resolves the seccomp profile value.
pub(crate) fn resolve_seccomp_profile(deny_network: bool, allow_fork: bool) -> SeccompProfile {
    match (deny_network, allow_fork) {
        (true, true) => SeccompProfile::EssentialWithFork,
        (true, false) => SeccompProfile::Essential,
        (false, true) => SeccompProfile::NetworkWithFork,
        (false, false) => SeccompProfile::Network,
    }
}

/// Parses the command value.
pub(crate) fn parse_command(command: &str) -> Result<Vec<String>, CliError> {
    let argv = shlex::split(command).ok_or_else(|| {
        CliError::CommandParse("command string contains unclosed quotes".to_string())
    })?;
    if argv.is_empty() {
        return Err(CliError::EmptyCommand);
    }
    Ok(argv)
}

/// Resolves the run command value.
pub(crate) fn resolve_run_command(
    command: Option<String>,
    argv: Vec<String>,
) -> Result<RunCommandInput, CliError> {
    if !argv.is_empty() {
        return Ok(RunCommandInput::Argv(argv));
    }

    if let Some(command) = command {
        let argv = parse_command(&command)?;
        return Ok(RunCommandInput::Command { command, argv });
    }

    Err(CliError::EmptyCommand)
}

/// Provides the sdk result into sandbox result operation.
pub(crate) fn sdk_result_into_sandbox_result(result: SdkExecuteResult) -> SandboxResult {
    SandboxResult {
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        elapsed: result.elapsed,
        timed_out: result.timed_out,
    }
}

/// Maps the sdk error value.
pub(crate) fn map_sdk_error(error: mimobox_sdk::SdkError) -> CliError {
    error.into()
}

/// Validates the resource args value.
pub(crate) fn validate_resource_args(
    memory: Option<u64>,
    timeout: Option<u64>,
    vcpu_count: u8,
) -> Result<(), CliError> {
    if let Some(memory) = memory.filter(|value| !(16..=32768).contains(value)) {
        return Err(CliError::Args(format!(
            "memory must be between 16 and 32768 MB, got: {memory}"
        )));
    }

    if let Some(timeout) = timeout.filter(|value| *value != 0 && !(1..=3600).contains(value)) {
        return Err(CliError::Args(format!(
            "timeout must be 0 (no timeout) or between 1 and 3600 seconds, got: {timeout}"
        )));
    }

    if !(1..=16).contains(&vcpu_count) {
        return Err(CliError::Args(format!(
            "vcpu_count must be between 1 and 16, got: {vcpu_count}"
        )));
    }

    Ok(())
}

/// Provides the finish sdk operation operation.
pub(crate) fn finish_sdk_operation<T>(
    sandbox: SdkSandbox,
    result: Result<T, mimobox_sdk::SdkError>,
    failure_context: &str,
) -> Result<T, CliError> {
    match result {
        Ok(value) => {
            destroy_sdk_sandbox_after_success(sandbox)?;
            Ok(value)
        }
        Err(error) => {
            let cli_error = map_sdk_error(error);
            error!(
                code = cli_error.code(),
                message = %cli_error,
                context = failure_context,
                "SDK operation failed"
            );
            destroy_sdk_sandbox_quietly(sandbox, failure_context);
            Err(cli_error)
        }
    }
}

/// Provides the destroy sdk sandbox after success operation.
pub(crate) fn destroy_sdk_sandbox_after_success(sandbox: SdkSandbox) -> Result<(), CliError> {
    sandbox.destroy().map_err(|error| {
        let cli_error = map_sdk_error(error);
        error!(
            code = cli_error.code(),
            message = %cli_error,
            "failed to destroy sandbox after successful SDK operation"
        );
        cli_error
    })
}

/// Provides the destroy sdk sandbox quietly operation.
pub(crate) fn destroy_sdk_sandbox_quietly(sandbox: SdkSandbox, context: &str) {
    if let Err(error) = sandbox.destroy() {
        let cli_error = map_sdk_error(error);
        warn!(
            code = cli_error.code(),
            message = %cli_error,
            context,
            "failed to destroy sandbox"
        );
    }
}

/// Applies the stderr fallback behavior.
pub(crate) fn apply_stderr_fallback(stderr: &mut Vec<u8>, fallback: Vec<u8>) {
    // Prefer stderr explicitly returned by the backend; use process-level fallback capture only when missing.
    if stderr.is_empty() && !fallback.is_empty() {
        *stderr = fallback;
    }
}

/// Provides the backend from sdk isolation operation.
pub(crate) fn backend_from_sdk_isolation(isolation: SdkIsolationLevel) -> Option<Backend> {
    match isolation {
        SdkIsolationLevel::Auto => None,
        SdkIsolationLevel::Os => Some(Backend::Os),
        SdkIsolationLevel::Wasm => Some(Backend::Wasm),
        SdkIsolationLevel::MicroVm => Some(Backend::Kvm),
    }
}

/// Provides the success exit code operation.
pub(crate) fn success_exit_code(response: &CommandResponse) -> Option<i32> {
    match response {
        CommandResponse::Run(run) => run.exit_code.filter(|code| *code != 0),
        CommandResponse::Code(code) => code.exit_code.filter(|exit_code| *exit_code != 0),
        CommandResponse::Restore(restore) => restore.exit_code.filter(|code| *code != 0),
        CommandResponse::Ls(_)
        | CommandResponse::Cat(_)
        | CommandResponse::Write(_)
        | CommandResponse::Snapshot(_)
        | CommandResponse::Bench(_)
        | CommandResponse::Version(_) => None,
    }
}

/// Emits the success json payload.
pub(crate) fn emit_success_json(response: &CommandResponse) -> Result<(), CliError> {
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

/// Emits the error json payload.
pub(crate) fn emit_error_json(error: &CliError) -> Result<(), CliError> {
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

/// Emits a best-effort fallback error JSON to stderr.
pub(crate) fn emit_fallback_error_json(code: &'static str, message: impl Into<String>) {
    let payload = serde_json::json!({
        "ok": false,
        "code": code,
        "message": message.into(),
    });
    eprintln!("{payload}");
}

/// Provides the panic payload to string operation.
pub(crate) fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_resource_args_accepts_boundaries() {
        assert!(validate_resource_args(Some(16), Some(0), 1).is_ok());
        assert!(validate_resource_args(Some(32768), Some(1), 16).is_ok());
        assert!(validate_resource_args(None, Some(3600), 8).is_ok());
        assert!(validate_resource_args(None, None, 1).is_ok());
    }

    #[test]
    fn validate_resource_args_rejects_memory_out_of_range() {
        let low = validate_resource_args(Some(15), None, 1)
            .expect_err("memory lower than 16 MB should be rejected");
        let high = validate_resource_args(Some(32769), None, 1)
            .expect_err("memory higher than 32 GB should be rejected");

        assert_eq!(low.code(), "args_error");
        assert!(
            low.to_string()
                .contains("memory must be between 16 and 32768 MB")
        );
        assert_eq!(high.code(), "args_error");
        assert!(high.to_string().contains("got: 32769"));
    }

    #[test]
    fn validate_resource_args_rejects_timeout_out_of_range() {
        let error = validate_resource_args(None, Some(3601), 1)
            .expect_err("timeout higher than 3600 seconds should be rejected");

        assert_eq!(error.code(), "args_error");
        assert!(
            error
                .to_string()
                .contains("timeout must be 0 (no timeout) or between 1 and 3600 seconds")
        );
    }

    #[test]
    fn validate_resource_args_rejects_vcpu_count_out_of_range() {
        let zero =
            validate_resource_args(None, None, 0).expect_err("zero vCPU count should be rejected");
        let high = validate_resource_args(None, None, 17)
            .expect_err("more than 16 vCPUs should be rejected");

        assert_eq!(zero.code(), "args_error");
        assert!(zero.to_string().contains("got: 0"));
        assert_eq!(high.code(), "args_error");
        assert!(high.to_string().contains("got: 17"));
    }

    #[test]
    fn resolve_run_command_prefers_argv() {
        let input = resolve_run_command(
            Some("/bin/echo ignored".to_string()),
            vec!["/bin/printf".to_string(), "hello world".to_string()],
        )
        .expect("argv 模式应解析成功");

        assert_eq!(
            input,
            RunCommandInput::Argv(vec!["/bin/printf".to_string(), "hello world".to_string()])
        );
        assert_eq!(input.requested_command(), "/bin/printf hello world");
    }

    #[test]
    fn resolve_run_command_parses_command_string() {
        let input = resolve_run_command(Some("/bin/echo 'hello world'".to_string()), Vec::new())
            .expect("command 模式应解析成功");

        assert_eq!(
            input.argv(),
            &["/bin/echo".to_string(), "hello world".to_string()]
        );
        assert_eq!(input.requested_command(), "/bin/echo 'hello world'");
    }

    #[test]
    fn resolve_run_command_rejects_missing_input() {
        let error = resolve_run_command(None, Vec::new()).expect_err("缺少命令应返回错误");

        assert_eq!(error.code(), "empty_command");
        assert!(error.to_string().contains("command must not be empty"));
    }
}
