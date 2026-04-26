use mimobox_sdk::Sandbox as SdkSandbox;
use tracing::info;

use super::*;

pub(crate) fn handle_ls(args: LsArgs) -> Result<LsResponse, CliError> {
    info!(
        backend = ?args.backend,
        path = %args.path,
        "preparing to execute ls subcommand"
    );

    let config = build_cli_sdk_config(args.backend, None, false);
    let mut sandbox = SdkSandbox::with_config(config).map_err(map_sdk_error)?;
    let result = sandbox.list_dir(&args.path);
    let mut entries =
        finish_sdk_operation(sandbox, result, "cleaning up sandbox after ls failure")?;
    entries.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(LsResponse {
        path: args.path,
        entries,
    })
}
