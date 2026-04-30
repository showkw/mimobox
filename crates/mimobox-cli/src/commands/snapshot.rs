#[cfg(all(target_os = "linux", feature = "kvm"))]
use std::fs;
#[cfg(all(target_os = "linux", feature = "kvm"))]
use std::time::Duration;

#[cfg(all(target_os = "linux", feature = "kvm"))]
use mimobox_sdk::Sandbox as SdkSandbox;
#[cfg(all(target_os = "linux", feature = "kvm"))]
use mimobox_sdk::SandboxSnapshot as SdkSnapshot;
#[cfg(all(target_os = "linux", feature = "kvm"))]
use tracing::{error, info, warn};

use super::*;

/// 验证文件路径安全性：拒绝虚拟文件系统路径，警告符号链接。
///
/// CLI 是本地工具，不需要过度限制，但基本防护（防止写入 /dev、/proc、/sys）
/// 和 symlink 提醒应该有。
#[cfg(all(target_os = "linux", feature = "kvm"))]
fn validate_file_path(path: &str, purpose: &str) -> Result<(), CliError> {
    let path = std::path::Path::new(path);

    // 解析路径（不要求文件存在，使用 canonicalize 的父目录）
    // 检查路径是否指向虚拟文件系统
    let path_str = path.to_string_lossy();
    if path_str.starts_with("/dev/")
        || path_str.starts_with("/proc/")
        || path_str.starts_with("/sys/")
    {
        return Err(CliError::Sdk(format!(
            "refusing to {purpose} virtual filesystem path: {path_str}"
        )));
    }

    // 如果路径已存在且是符号链接，发出警告
    if path.is_symlink() {
        match std::fs::canonicalize(path) {
            Ok(resolved) => {
                warn!(
                    path = %path_str,
                    resolved = %resolved.display(),
                    "{purpose} path is a symlink; resolved to"
                );
            }
            Err(e) => {
                warn!(
                    path = %path_str,
                    error = %e,
                    "{purpose} path is a dangling symlink"
                );
            }
        }
    }

    Ok(())
}

/// Handles the snapshot request.
pub(crate) fn handle_snapshot(args: SnapshotArgs) -> Result<SnapshotResponse, CliError> {
    validate_resource_args(args.memory, args.timeout, args.vcpu_count)?;

    #[cfg(not(all(target_os = "linux", feature = "kvm")))]
    {
        let _ = args;
        Err(CliError::KvmFeatureDisabled)
    }

    #[cfg(all(target_os = "linux", feature = "kvm"))]
    {
        let deny_network = !args.allow_network;
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
        validate_file_path(&args.output, "write snapshot to")?;
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

/// Handles the restore request.
pub(crate) fn handle_restore(args: RestoreArgs) -> Result<RestoreResponse, CliError> {
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

        validate_file_path(&args.snapshot, "read snapshot from")?;
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
