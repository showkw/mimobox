#[cfg(feature = "kvm")]
use tracing::info;

use super::*;

pub(crate) fn handle_write(args: WriteArgs) -> Result<WriteResponse, CliError> {
    #[cfg(not(feature = "kvm"))]
    {
        let _ = args;
        Err(CliError::KvmFeatureDisabled)
    }

    #[cfg(feature = "kvm")]
    {
        use mimobox_sdk::Sandbox as SdkSandbox;

        let WriteArgs {
            path,
            content,
            file,
            backend,
        } = args;
        let data = resolve_write_data(content, file)?;

        info!(
            backend = ?backend,
            path = %path,
            bytes = data.len(),
            "preparing to execute write subcommand"
        );

        let config = build_cli_sdk_config(backend, None);
        let mut sandbox = SdkSandbox::with_config(config).map_err(map_sdk_error)?;
        let result = sandbox.write_file(&path, &data);
        finish_sdk_operation(sandbox, result, "cleaning up sandbox after write failure")?;

        Ok(WriteResponse {
            path,
            bytes_written: data.len(),
        })
    }
}

#[cfg(feature = "kvm")]
fn resolve_write_data(content: Option<String>, file: Option<String>) -> Result<Vec<u8>, CliError> {
    match (content, file) {
        (Some(content), None) => Ok(content.into_bytes()),
        (None, Some(file)) => std::fs::read(file).map_err(CliError::Io),
        (None, None) => Err(CliError::Args(
            "either --content or --file must be provided".to_string(),
        )),
        (Some(_), Some(_)) => Err(CliError::Args(
            "--content and --file cannot be used together".to_string(),
        )),
    }
}
