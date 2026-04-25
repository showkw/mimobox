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
use commands::mcp_init::{McpOs, inject_mcp_config, mcp_config_path};
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

#[derive(Debug, Parser)]
#[command(
    name = "mimobox",
    version,
    about = "Cross-platform Agent Sandbox CLI",
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
    /// Generate shell completion script to stdout
    Completions(CompletionsArgs),
    /// Print version information
    Version,
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
        CliCommand::Doctor
            | CliCommand::Setup
            | CliCommand::McpInit(_)
            | CliCommand::Completions(_)
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
