#[cfg(feature = "kvm")]
use tracing::info;

use super::*;

pub(crate) fn handle_cat(args: CatArgs) -> Result<CatResponse, CliError> {
    #[cfg(not(feature = "kvm"))]
    {
        let _ = args;
        Err(CliError::KvmFeatureDisabled)
    }

    #[cfg(feature = "kvm")]
    {
        use mimobox_sdk::Sandbox as SdkSandbox;

        info!(
            backend = ?args.backend,
            path = %args.path,
            "preparing to execute cat subcommand"
        );

        let config = build_cli_sdk_config(args.backend, None, false);
        let mut sandbox = SdkSandbox::with_config(config).map_err(map_sdk_error)?;
        let result = sandbox.read_file(&args.path);
        let content =
            finish_sdk_operation(sandbox, result, "cleaning up sandbox after cat failure")?;
        let size_bytes = content.len();

        Ok(CatResponse {
            path: args.path,
            size_bytes,
            content_base64: encode_base64(&content),
        })
    }
}

#[cfg(feature = "kvm")]
fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);

        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0b0000_0011) << 4) | (second >> 4)) as usize] as char);

        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0b0000_1111) << 2) | (third >> 6)) as usize] as char);
        } else {
            output.push('=');
        }

        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0b0011_1111) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}
