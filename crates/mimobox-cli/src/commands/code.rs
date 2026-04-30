use mimobox_sdk::Sandbox as SdkSandbox;
use tracing::info;

use super::*;

/// Languages that require an interpreter process: these runtimes use fork/clone internally,
/// so allow_fork must be enabled automatically to avoid being killed by seccomp.
fn language_needs_fork(language: &str) -> bool {
    matches!(
        language,
        "python"
            | "python3"
            | "py"
            | "bash"
            | "sh"
            | "shell"
            | "javascript"
            | "js"
            | "node"
            | "nodejs"
    )
}

/// Handles the code request.
pub(crate) fn handle_code(args: CodeArgs) -> Result<CodeResponse, CliError> {
    validate_resource_args(None, args.timeout, 1)?;
    let allow_fork = language_needs_fork(&args.language);
    info!(
        backend = ?args.backend,
        language = %args.language,
        timeout_secs = ?normalize_timeout(args.timeout),
        allow_fork,
        "preparing to execute code subcommand"
    );

    let config = build_cli_sdk_config(args.backend, args.timeout, allow_fork);
    let mut sandbox = SdkSandbox::with_config(config).map_err(map_sdk_error)?;
    let result = sandbox.execute_code(&args.language, &args.code);
    let result = finish_sdk_operation(sandbox, result, "cleaning up sandbox after code failure")?;

    Ok(CodeResponse {
        language: args.language,
        exit_code: result.exit_code,
        timed_out: result.timed_out,
        elapsed_ms: result.elapsed.as_secs_f64() * 1000.0,
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
    })
}
