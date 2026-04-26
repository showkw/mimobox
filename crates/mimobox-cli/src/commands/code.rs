use mimobox_sdk::Sandbox as SdkSandbox;
use tracing::info;

use super::*;

pub(crate) fn handle_code(args: CodeArgs) -> Result<CodeResponse, CliError> {
    info!(
        backend = ?args.backend,
        language = %args.language,
        timeout_secs = ?normalize_timeout(args.timeout),
        "preparing to execute code subcommand"
    );

    let config = build_cli_sdk_config(args.backend, args.timeout);
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
