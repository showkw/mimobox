mod asset_download;
mod capture;
mod commands;
mod doctor;
mod logging;

#[cfg(test)]
use std::io::Write;
use std::panic::{self, AssertUnwindSafe};
use std::process::{self, ExitCode};
#[cfg(test)]
use std::{io, path::PathBuf};

use clap::{Parser, Subcommand};
#[cfg(test)]
use mimobox_sdk::{IsolationLevel as SdkIsolationLevel, NetworkPolicy as SdkNetworkPolicy};
use tracing::{error, info};

#[cfg(test)]
use capture::capture_stderr_bytes;
#[cfg(test)]
use commands::mcp_init::{McpOs, mcp_config_path};
#[cfg(test)]
use commands::run::resolve_run_execution_mode;
#[cfg(test)]
use commands::shell::build_shell_sdk_config;
use commands::*;
use logging::init_tracing;

pub(crate) const DEFAULT_MEMORY_MB: u64 = 256;
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub(crate) const DEFAULT_BENCH_ITERATIONS: usize = 50;
pub(crate) const DEFAULT_POOL_SIZE: usize = 16;

#[derive(Debug, clap::Args)]
struct McpConfigArgs {
    /// MCP client type (affects config format hint)
    #[arg(long, value_name = "CLIENT", default_value = "claude")]
    client: Option<McpClient>,
}

#[derive(Debug, Parser)]
#[command(
    name = "mimobox",
    version,
    about = "MimoBox — Local Sandbox Runtime for AI Agents",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Execute a command in the specified backend sandbox
    Run(RunArgs),
    /// Execute a code snippet in the specified backend sandbox
    Code(CodeArgs),
    /// List directory entries inside a sandbox
    Ls(LsArgs),
    /// Read a file from a microVM-backed sandbox
    Cat(CatArgs),
    /// Write a file into a microVM-backed sandbox
    Write(WriteArgs),
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
    /// Print MCP server JSON config to stdout
    McpConfig(McpConfigArgs),
    /// Generate shell completion script to stdout
    Completions(CompletionsArgs),
    /// Print version information
    Version,
}

/// Returns the command type name without sensitive arguments, paths, or code snippets.
fn command_type_name(cmd: &CliCommand) -> &'static str {
    match cmd {
        CliCommand::Run(_) => "run",
        CliCommand::Code(_) => "code",
        CliCommand::Ls(_) => "ls",
        CliCommand::Cat(_) => "cat",
        CliCommand::Write(_) => "write",
        CliCommand::Shell(_) => "shell",
        CliCommand::Snapshot(_) => "snapshot",
        CliCommand::Restore(_) => "restore",
        CliCommand::Bench(_) => "bench",
        CliCommand::Doctor => "doctor",
        CliCommand::Setup => "setup",
        CliCommand::McpInit(_) => "mcp-init",
        CliCommand::McpConfig(_) => "mcp-config",
        CliCommand::Completions(_) => "completions",
        CliCommand::Version => "version",
    }
}

fn main() -> ExitCode {
    if let Err(error) = init_tracing() {
        if let Err(print_error) = emit_error_json(&error) {
            emit_fallback_error_json("logging_init_error", print_error.to_string());
        }
        return ExitCode::FAILURE;
    }

    match panic::catch_unwind(AssertUnwindSafe(run_with_panic_guard)) {
        Ok(code) => code,
        Err(payload) => {
            let message = panic_payload_to_string(payload.as_ref());
            let error = CliError::Panic(message);
            if let Err(print_error) = emit_error_json(&error) {
                emit_fallback_error_json("panic", print_error.to_string());
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
                emit_fallback_error_json("json_error", print_error.to_string());
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<Option<i32>, CliError> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            return Ok(None);
        }
        Err(error) => return Err(CliError::Args(error.to_string())),
    };
    let is_human_readable_command = matches!(
        cli.command,
        CliCommand::Doctor
            | CliCommand::Setup
            | CliCommand::McpInit(_)
            | CliCommand::McpConfig(_)
            | CliCommand::Completions(_)
    );

    if !is_human_readable_command {
        info!("mimobox CLI starting");
        info!(
            command_type = command_type_name(&cli.command),
            "CLI arguments parsed"
        );
    }

    let response = match cli.command {
        CliCommand::Run(args) => CommandResponse::Run(handle_run(args)?),
        CliCommand::Code(args) => CommandResponse::Code(handle_code(args)?),
        CliCommand::Ls(args) => CommandResponse::Ls(handle_ls(args)?),
        CliCommand::Cat(args) => CommandResponse::Cat(handle_cat(args)?),
        CliCommand::Write(args) => CommandResponse::Write(handle_write(args)?),
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
        CliCommand::McpConfig(args) => {
            let binary_path = resolve_mimobox_mcp_binary();
            let config = inject_mcp_config(serde_json::json!({}), &binary_path)?;
            let json = serde_json::to_string_pretty(&config)?;

            println!("{json}");
            print_mcp_config_hints(args.client.unwrap_or(McpClient::Claude));
            return Ok(None);
        }
        CliCommand::Completions(args) => {
            handle_completions(args);
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

fn print_mcp_config_hints(client: McpClient) {
    let hints = [
        (
            McpClient::Claude,
            "Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json",
        ),
        (
            McpClient::ClaudeCode,
            "Claude Code: ~/.claude/settings.json",
        ),
        (McpClient::Cursor, "Cursor: ~/.cursor/mcp.json"),
        (
            McpClient::Windsurf,
            "Windsurf: ~/.codeium/windsurf/mcp_config.json",
        ),
    ];

    println!("# Add this to your MCP client config file");
    for (_, hint) in hints.iter().filter(|(candidate, _)| *candidate == client) {
        println!("# {hint}");
    }
    for (_, hint) in hints.iter().filter(|(candidate, _)| *candidate != client) {
        println!("# {hint}");
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
                assert_eq!(args.command.as_deref(), Some("/bin/echo hello"));
                assert!(args.argv.is_empty());
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
                assert_eq!(args.command.as_deref(), Some("/bin/echo hello"));
                assert!(args.argv.is_empty());
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
                assert_eq!(args.command.as_deref(), Some("/bin/echo hello"));
                assert!(args.argv.is_empty());
            }
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn run_subcommand_parses_trailing_argv() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "run",
            "--backend",
            "os",
            "--",
            "/bin/echo",
            "-n",
            "hello world",
        ])
        .expect("run 子命令应成功解析 argv");

        match cli.command {
            CliCommand::Run(args) => {
                assert_eq!(args.backend, Backend::Os);
                assert_eq!(args.command, None);
                assert_eq!(args.argv, vec!["/bin/echo", "-n", "hello world"]);
            }
            _ => panic!("expected run subcommand"),
        }
    }

    #[test]
    fn run_subcommand_rejects_missing_command_and_argv() {
        let error = Cli::try_parse_from(["mimobox", "run"])
            .expect_err("run 子命令应要求提供 command 或 argv");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn code_subcommand_parses_expected_flags() {
        let cli = Cli::try_parse_from([
            "mimobox",
            "code",
            "--backend",
            "os",
            "--language",
            "python",
            "--code",
            "print('hello')",
            "--timeout",
            "3",
        ])
        .expect("code subcommand should parse successfully");

        match cli.command {
            CliCommand::Code(args) => {
                assert_eq!(args.backend, Backend::Os);
                assert_eq!(args.language, "python");
                assert_eq!(args.code, "print('hello')");
                assert_eq!(args.timeout, Some(3));
            }
            _ => panic!("expected code subcommand"),
        }
    }

    #[test]
    fn file_operation_subcommands_parse_expected_defaults() {
        let ls = Cli::try_parse_from(["mimobox", "ls", "/tmp"])
            .expect("ls subcommand should parse successfully");
        match ls.command {
            CliCommand::Ls(args) => {
                assert_eq!(args.path, "/tmp");
                assert_eq!(args.backend, Backend::Auto);
            }
            _ => panic!("expected ls subcommand"),
        }

        let cat = Cli::try_parse_from(["mimobox", "cat", "/tmp/a.txt"])
            .expect("cat subcommand should parse successfully");
        match cat.command {
            CliCommand::Cat(args) => {
                assert_eq!(args.path, "/tmp/a.txt");
                assert_eq!(args.backend, Backend::Auto);
            }
            _ => panic!("expected cat subcommand"),
        }

        let write = Cli::try_parse_from([
            "mimobox",
            "write",
            "/tmp/a.txt",
            "--content",
            "hello",
            "--backend",
            "kvm",
        ])
        .expect("write subcommand should parse successfully");
        match write.command {
            CliCommand::Write(args) => {
                assert_eq!(args.path, "/tmp/a.txt");
                assert_eq!(args.content.as_deref(), Some("hello"));
                assert_eq!(args.file, None);
                assert_eq!(args.backend, Backend::Kvm);
            }
            _ => panic!("expected write subcommand"),
        }
    }

    #[test]
    fn write_subcommand_requires_single_input_source() {
        let missing_input = Cli::try_parse_from(["mimobox", "write", "/tmp/a.txt"])
            .expect_err("write subcommand should require --content or --file");
        assert_eq!(
            missing_input.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let conflicting_input = Cli::try_parse_from([
            "mimobox",
            "write",
            "/tmp/a.txt",
            "--content",
            "hello",
            "--file",
            "/tmp/source.txt",
        ])
        .expect_err("write subcommand should reject both input sources");
        assert_eq!(
            conflicting_input.kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
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
    fn mcp_config_subcommand_parses_default_client() {
        let cli = Cli::try_parse_from(["mimobox", "mcp-config"])
            .expect("mcp-config should parse successfully");

        match cli.command {
            CliCommand::McpConfig(args) => {
                assert_eq!(args.client, Some(McpClient::Claude));
            }
            _ => panic!("expected mcp-config subcommand"),
        }
    }

    #[test]
    fn mcp_config_subcommand_parses_with_client_flag() {
        let cli = Cli::try_parse_from(["mimobox", "mcp-config", "--client", "cursor"])
            .expect("mcp-config --client should parse successfully");

        match cli.command {
            CliCommand::McpConfig(args) => {
                assert_eq!(args.client, Some(McpClient::Cursor));
            }
            _ => panic!("expected mcp-config subcommand"),
        }
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
    fn mcp_init_subcommand_parses_claude_code_client() {
        let cli = Cli::try_parse_from(["mimobox", "mcp-init", "claude-code"])
            .expect("mcp-init claude-code should parse successfully");

        match cli.command {
            CliCommand::McpInit(args) => {
                assert_eq!(args.client, Some(McpClient::ClaudeCode));
                assert!(!args.all);
            }
            _ => panic!("expected mcp-init subcommand"),
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
    fn mcp_config_path_includes_claude_code() {
        let home = PathBuf::from("/home/alice");

        assert_eq!(
            mcp_config_path(McpClient::ClaudeCode, McpOs::Linux, &home),
            PathBuf::from("/home/alice/.claude/settings.json")
        );
        assert_eq!(
            mcp_config_path(McpClient::ClaudeCode, McpOs::Macos, &home),
            PathBuf::from("/home/alice/.claude/settings.json")
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
            command: Some("/bin/echo hello".to_string()),
            argv: Vec::new(),
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
    fn success_exit_code_propagates_non_zero_code_exit_code() {
        let response = CommandResponse::Code(CodeResponse {
            language: "python".to_string(),
            exit_code: Some(11),
            timed_out: false,
            elapsed_ms: 1.0,
            stdout: String::new(),
            stderr: String::new(),
        });

        assert_eq!(success_exit_code(&response), Some(11));
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
