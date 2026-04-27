use tracing::info;

use super::VersionResponse;

pub(crate) fn handle_version() -> VersionResponse {
    info!("preparing to print version info");

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
        git_hash: env!("MIMOBOX_GIT_HASH"),
        target_triple: env!("MIMOBOX_TARGET_TRIPLE"),
        enabled_features,
        target_os: std::env::consts::OS,
    }
}
