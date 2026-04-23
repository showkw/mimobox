use std::cell::Cell;
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::panic::{self, AssertUnwindSafe};
#[cfg(all(target_os = "linux", feature = "kvm"))]
use std::path::PathBuf;
use std::process::{self, ExitCode};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult, SeccompProfile};
#[cfg(target_os = "linux")]
use mimobox_os::LinuxSandbox;
#[cfg(target_os = "macos")]
use mimobox_os::MacOsSandbox;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mimobox_os::run_pool_benchmark;
use mimobox_sdk::{
    Config as SdkConfig, ExecuteResult as SdkExecuteResult, IsolationLevel as SdkIsolationLevel,
    NetworkPolicy as SdkNetworkPolicy, Sandbox as SdkSandbox,
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
    about = "跨平台 Agent Sandbox CLI",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// 在指定后端沙箱中执行命令
    Run(RunArgs),
    /// 运行预热池相关基准
    Bench(BenchArgs),
    /// 输出版本信息
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

#[derive(Debug, Args)]
struct RunArgs {
    /// 选择后端
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    backend: Backend,

    /// 待执行命令，使用 shell 风格字符串，例如："/bin/echo hello"
    #[arg(long, value_name = "cmd")]
    command: String,

    /// 内存上限（MB）
    #[arg(long)]
    memory: Option<u64>,

    /// 超时时间（秒），传 0 表示不设置超时
    #[arg(long)]
    timeout: Option<u64>,

    /// 是否拒绝网络访问
    #[arg(long)]
    deny_network: bool,

    /// 是否允许子进程 fork/clone
    #[arg(long, default_value_t = false)]
    allow_fork: bool,

    /// KVM 内核镜像路径
    #[arg(long)]
    kernel: Option<String>,

    /// KVM rootfs 路径
    #[arg(long)]
    rootfs: Option<String>,

    /// KVM vCPU 数量
    #[arg(long, default_value_t = 1)]
    vcpu_count: u8,
}

#[derive(Debug, Args)]
struct BenchArgs {
    /// 基准目标
    #[arg(long, value_enum)]
    target: BenchTarget,
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
    #[error("参数解析失败: {0}")]
    Args(String),

    #[error("命令字符串解析失败: {0}")]
    CommandParse(String),

    #[error("命令不能为空")]
    EmptyCommand,

    #[error("日志初始化失败: {0}")]
    Logging(String),

    #[error("JSON 输出失败: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO 错误: {0}")]
    Io(#[from] io::Error),

    #[error("SDK 执行失败: {0}")]
    Sdk(String),

    #[error("沙箱执行失败: {0}")]
    Sandbox(#[from] SandboxError),

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[error("当前平台不支持 OS 后端")]
    UnsupportedOsBackend,

    #[error("当前构建未启用 Wasm 后端，请使用 `--features wasm` 重新编译")]
    #[allow(dead_code)]
    WasmFeatureDisabled,

    #[error(
        "当前构建未启用 KVM 后端，或当前平台不支持，请在 Linux 上使用 `--features kvm` 重新编译"
    )]
    #[allow(dead_code)]
    KvmFeatureDisabled,

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[error("当前平台不支持预热池基准")]
    BenchUnsupported,

    #[error("基准执行失败: {0}")]
    Benchmark(String),

    #[error("运行时发生未预期 panic: {0}")]
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
    /// 在需要捕获进程级 stderr 时，临时关闭终端日志，避免日志污染兜底输出。
    static STDERR_LOGGING_ENABLED: Cell<bool> = const { Cell::new(true) };
}

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
            error!(code = error.code(), message = %error, "CLI 执行失败");
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
    info!("mimobox CLI 启动");

    let cli = Cli::try_parse().map_err(|error| CliError::Args(error.to_string()))?;
    info!(command = ?cli.command, "CLI 参数解析完成");

    let response = match cli.command {
        CliCommand::Run(args) => CommandResponse::Run(handle_run(args)?),
        CliCommand::Bench(args) => CommandResponse::Bench(handle_bench(args)?),
        CliCommand::Version => CommandResponse::Version(handle_version()),
    };

    let exit_code = success_exit_code(&response);
    emit_success_json(&response)?;
    info!("CLI 执行完成");
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
    info!(
        backend = ?args.backend,
        memory_mb = args.memory.unwrap_or(DEFAULT_MEMORY_MB),
        timeout_secs = ?normalize_timeout(args.timeout),
        deny_network = args.deny_network,
        allow_fork = args.allow_fork,
        kernel = args.kernel.as_deref().unwrap_or("default"),
        rootfs = args.rootfs.as_deref().unwrap_or("default"),
        vcpu_count = args.vcpu_count,
        "准备执行 run 子命令"
    );

    let argv = parse_command(&args.command)?;
    let memory_mb = Some(args.memory.unwrap_or(DEFAULT_MEMORY_MB));
    let timeout_secs = normalize_timeout(args.timeout);
    let deny_network = args.deny_network;
    let allow_fork = args.allow_fork;

    let requested_backend = args.backend;
    let (execution, fallback_stderr) =
        capture_stderr_bytes(|| match resolve_run_execution_mode(args.backend) {
            RunExecutionMode::Sdk => handle_run_via_sdk(
                &args.command,
                args.memory,
                args.timeout,
                args.deny_network,
                args.allow_fork,
            ),
            RunExecutionMode::Direct => {
                let config = build_sandbox_config(
                    args.memory,
                    args.timeout,
                    args.deny_network,
                    args.allow_fork,
                );

                match args.backend {
                    Backend::Auto => unreachable!("Auto 后端已在 SDK 路径处理"),
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

fn handle_bench(args: BenchArgs) -> Result<BenchResponse, CliError> {
    info!(
        target = ?args.target,
        pool_size = DEFAULT_POOL_SIZE,
        iterations = DEFAULT_BENCH_ITERATIONS,
        "准备执行 bench 子命令"
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
            "当前 bench 子命令复用 run_pool_benchmark，输出同时包含冷启动与热获取摘要。"
        }
        BenchTarget::HotAcquire => {
            "当前 bench 子命令复用 run_pool_benchmark，重点请关注热获取 acquire 指标。"
        }
        BenchTarget::WarmThroughput => {
            "当前公共 API 仅暴露综合预热池基准；warm-throughput 如需更细粒度分析，请结合 criterion bench。"
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

fn handle_version() -> VersionResponse {
    info!("准备输出版本信息");

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
    SandboxConfig {
        memory_limit_mb: Some(memory.unwrap_or(DEFAULT_MEMORY_MB)),
        timeout_secs: normalize_timeout(timeout),
        deny_network,
        seccomp_profile: resolve_seccomp_profile(deny_network, allow_fork),
        allow_fork,
        ..Default::default()
    }
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

fn build_sdk_network_policy(deny_network: bool) -> SdkNetworkPolicy {
    if deny_network {
        SdkNetworkPolicy::DenyAll
    } else {
        SdkNetworkPolicy::DenyDomains(Vec::new())
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
    let argv = shlex::split(command)
        .ok_or_else(|| CliError::CommandParse("命令字符串包含未闭合引号".to_string()))?;
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
        "使用 SDK 智能路由执行命令"
    );

    let mut sandbox = SdkSandbox::with_config(config).map_err(|error| {
        let cli_error = map_sdk_error(error);
        error!(code = cli_error.code(), message = %cli_error, "SDK 沙箱初始化失败");
        cli_error
    })?;

    let execute_result = sandbox.execute(command);

    match execute_result {
        Ok(result) => {
            let backend = sandbox
                .active_isolation()
                .and_then(backend_from_sdk_isolation)
                .ok_or_else(|| {
                    let error = CliError::Sdk("SDK 执行成功但未记录实际后端".to_string());
                    error!(
                        code = error.code(),
                        message = %error,
                        "SDK 执行成功后无法解析实际后端"
                    );
                    error
                })?;

            sandbox.destroy().map_err(|error| {
                let cli_error = map_sdk_error(error);
                error!(
                    code = cli_error.code(),
                    message = %cli_error,
                    backend = ?backend,
                    "SDK 执行成功后销毁沙箱失败"
                );
                cli_error
            })?;

            info!(backend = ?backend, "SDK 执行成功并完成沙箱销毁");
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
                "SDK 执行命令失败"
            );

            if let Err(destroy_error) = sandbox.destroy() {
                let destroy_cli_error = map_sdk_error(destroy_error);
                error!(
                    code = destroy_cli_error.code(),
                    message = %destroy_cli_error,
                    "SDK 执行失败后销毁沙箱也失败"
                );
            } else {
                warn!("SDK 执行失败后已完成沙箱销毁");
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

fn apply_stderr_fallback(stderr: &mut Vec<u8>, fallback: Vec<u8>) {
    // 优先使用后端显式返回的 stderr；只有后端遗漏时才使用进程级兜底捕获。
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
        CommandResponse::Bench(_) | CommandResponse::Version(_) => None,
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
    info!("使用 Linux OS 后端执行命令");
    execute_with_sandbox::<LinuxSandbox>(config, argv)
}

#[cfg(target_os = "macos")]
fn execute_os_backend(config: SandboxConfig, argv: &[String]) -> Result<SandboxResult, CliError> {
    info!("使用 macOS OS 后端执行命令");
    execute_with_sandbox::<MacOsSandbox>(config, argv)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn execute_os_backend(_config: SandboxConfig, _argv: &[String]) -> Result<SandboxResult, CliError> {
    Err(CliError::UnsupportedOsBackend)
}

#[cfg(feature = "wasm")]
fn execute_wasm_backend(config: SandboxConfig, argv: &[String]) -> Result<SandboxResult, CliError> {
    info!("使用 Wasm 后端执行命令");
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
    info!("使用 KVM microVM 后端执行命令");

    let memory_limit_mb = config.memory_limit_mb.unwrap_or(DEFAULT_MEMORY_MB);
    let memory_mb = u32::try_from(memory_limit_mb).map_err(|_| {
        CliError::Sandbox(SandboxError::ExecutionFailed(format!(
            "KVM guest memory 超出 u32 范围: {memory_limit_mb} MB"
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
                warn!(message = %destroy_error, "执行失败后销毁沙箱也失败");
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
            format!("stdout 捕获结果不是有效 UTF-8: {error}"),
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
        // SAFETY: `pipe_fds` 指向两个有效的 `c_int` 槽位，`pipe` 会在成功时写入读写端。
        let pipe_result = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        if pipe_result != 0 {
            return Err(CliError::Io(io::Error::last_os_error()));
        }

        // SAFETY: `pipe` 成功后返回的 fd 所有权转移到 `File` / `OwnedFd`，且只接管一次。
        let read_file = unsafe { File::from_raw_fd(pipe_fds[0]) };
        // SAFETY: `pipe` 成功后返回的 fd 所有权转移到 `OwnedFd`，且只接管一次。
        let write_fd = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        // SAFETY: `dup` 复制当前目标 fd，返回一个新的独立 fd。
        let saved_fd_raw = unsafe { libc::dup(target_fd) };
        if saved_fd_raw < 0 {
            return Err(CliError::Io(io::Error::last_os_error()));
        }
        // SAFETY: `dup` 成功返回的新 fd 在此转交给 `OwnedFd` 独占管理。
        let saved_fd = unsafe { OwnedFd::from_raw_fd(saved_fd_raw) };

        // SAFETY: 将目标 fd 重定向到管道写端。两个 fd 都是当前进程中有效的打开文件描述符。
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
            // SAFETY: `saved_fd` 是前面通过 `dup` 复制出的合法 fd，可安全恢复到原始标准流。
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
        "未知 panic".to_string()
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
            .map_err(|_| io::Error::other("日志文件锁已中毒"))?;
        file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("日志文件锁已中毒"))?;
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
        .expect("run 子命令应解析成功");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Wasm);
                assert_eq!(args.command, "/bin/echo hello");
                assert_eq!(args.memory, Some(128));
                assert_eq!(args.timeout, Some(5));
                assert!(args.deny_network);
                assert!(args.allow_fork);
            }
            _ => panic!("应解析为 run 子命令"),
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
        .expect("最小 run 子命令应解析成功");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Os);
                assert_eq!(args.memory, None);
                assert_eq!(args.timeout, None);
                assert!(!args.deny_network);
                assert!(!args.allow_fork);
            }
            _ => panic!("应解析为 run 子命令"),
        }
    }

    #[test]
    fn run_subcommand_defaults_to_auto_backend() {
        let cli = Cli::try_parse_from(["mimobox", "run", "--command", "/bin/echo hello"])
            .expect("未显式指定 backend 时应默认走 auto");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Auto);
                assert_eq!(args.command, "/bin/echo hello");
            }
            _ => panic!("应解析为 run 子命令"),
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
        .expect("kvm run 子命令应解析成功");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Kvm);
                assert_eq!(args.kernel.as_deref(), Some("/tmp/vmlinux"));
                assert_eq!(args.rootfs.as_deref(), Some("/tmp/rootfs.cpio.gz"));
                assert_eq!(args.vcpu_count, 2);
            }
            _ => panic!("应解析为 run 子命令"),
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
        .expect("最小 kvm run 子命令应解析成功");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Kvm);
                assert_eq!(args.kernel, None);
                assert_eq!(args.rootfs, None);
                assert_eq!(args.vcpu_count, 1);
            }
            _ => panic!("应解析为 run 子命令"),
        }
    }

    #[test]
    fn bench_subcommand_parses_target() {
        let cli = Cli::try_parse_from(["mimobox", "bench", "--target", "hot-acquire"])
            .expect("bench 子命令应解析成功");

        match cli.command {
            CliCommand::Bench(args) => {
                assert_eq!(args.target, BenchTarget::HotAcquire);
            }
            _ => panic!("应解析为 bench 子命令"),
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
        .expect_err("bench 子命令不应再接受 pool 参数");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn version_subcommand_parses() {
        let cli = Cli::try_parse_from(["mimobox", "version"]).expect("version 子命令应解析成功");

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
        .expect("run 子命令应接受 kvm 后端");

        match cli.command {
            CliCommand::Run(args) => assert_eq!(args.backend, Backend::Kvm),
            _ => panic!("应解析为 run 子命令"),
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
        let error = parse_command("/bin/sh -c 'echo").expect_err("未闭合引号应返回错误");

        assert_eq!(error.code(), "command_parse_error");
    }

    #[test]
    fn sdk_config_error_is_preserved_in_cli_error() {
        let error = handle_run_via_sdk("/bin/sh -c 'echo", Some(128), Some(5), true, false)
            .expect_err("SDK 配置错误应映射为 CLI 错误");

        assert_eq!(error.code(), "sdk_error");
        assert!(error.to_string().contains("配置错误"));
        assert!(error.to_string().contains("shell 风格引号不匹配"));
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
            allow_fork: false,
            kernel: None,
            rootfs: None,
            vcpu_count: 1,
        })
        .expect("auto 路由执行应成功");

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

    #[cfg(unix)]
    #[test]
    fn capture_stderr_bytes_reads_process_stderr() {
        let (value, stderr) = capture_stderr_bytes(|| {
            // 直接写入并刷新标准错误，避免 eprint! 的缓冲层绕过底层 fd 2 捕获。
            let mut stderr = io::stderr();
            write!(stderr, "fail").expect("写入 stderr 应成功");
            stderr.flush().expect("刷新 stderr 应成功");
            7
        })
        .expect("stderr 捕获应成功");

        assert_eq!(value, 7);
        assert_eq!(stderr, b"fail");
    }
}
