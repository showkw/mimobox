use std::env;
use std::path::PathBuf;
#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
use std::{fs, path::Path};

#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
use sha2::{Digest, Sha256};
#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
use tracing::{debug, warn};

use crate::vm::{MicrovmConfig, MicrovmError, sanitize_path_display};

const DEFAULT_VM_ASSETS_SUBDIR: &str = ".mimobox/assets";

/// Resolves the microVM assets directory.
///
/// An explicit override takes precedence. If no override is provided, this falls
/// back to `HOME/.mimobox/assets`. The function is parameterized for tests and for
/// callers that have already read environment variables.
pub fn resolve_vm_assets_dir(
    vm_assets_override: Option<PathBuf>,
    home_dir: Option<PathBuf>,
) -> Result<PathBuf, MicrovmError> {
    if let Some(path) = vm_assets_override {
        return Ok(path);
    }

    let home_dir = home_dir.ok_or_else(|| {
        MicrovmError::InvalidConfig(
            "HOME environment variable must exist or VM_ASSETS_DIR must be set".into(),
        )
    })?;
    Ok(home_dir.join(DEFAULT_VM_ASSETS_SUBDIR))
}

/// Resolves the default microVM assets directory from process environment variables.
///
/// `VM_ASSETS_DIR` overrides the default location. Without that override, `HOME`
/// must be present so the default `HOME/.mimobox/assets` path can be derived.
pub fn vm_assets_dir() -> Result<PathBuf, MicrovmError> {
    resolve_vm_assets_dir(
        env::var_os("VM_ASSETS_DIR").map(PathBuf::from),
        env::var_os("HOME").map(PathBuf::from),
    )
}

/// Builds a [`MicrovmConfig`] from an assets directory.
///
/// The directory must contain `vmlinux` and `rootfs.cpio.gz`. The returned config
/// uses one vCPU, the provided memory size, and no CPU quota.
pub fn microvm_config_from_assets_dir(
    assets_dir: PathBuf,
    memory_mb: u32,
) -> Result<MicrovmConfig, MicrovmError> {
    let kernel_path = assets_dir.join("vmlinux");
    let rootfs_path = assets_dir.join("rootfs.cpio.gz");

    if !kernel_path.exists() {
        return Err(MicrovmError::InvalidConfig(format!(
            "missing kernel image: {}",
            sanitize_path_display(&kernel_path)
        )));
    }

    if !rootfs_path.exists() {
        return Err(MicrovmError::InvalidConfig(format!(
            "missing rootfs: {}",
            sanitize_path_display(&rootfs_path)
        )));
    }

    Ok(MicrovmConfig {
        vcpu_count: 1,
        memory_mb,
        cpu_quota_us: None,
        kernel_path,
        rootfs_path,
        security_profile: crate::vm::VmSecurityProfile::default(),
    })
}

/// Builds a [`MicrovmConfig`] from the default assets directory.
///
/// This combines [`vm_assets_dir`] and [`microvm_config_from_assets_dir`].
pub fn microvm_config_from_vm_assets(memory_mb: u32) -> Result<MicrovmConfig, MicrovmError> {
    let assets_dir = vm_assets_dir()?;
    microvm_config_from_assets_dir(assets_dir, memory_mb)
}

/// Verifies an asset byte buffer against its local SHA256 sidecar.
///
/// Missing sidecars are treated as first-use bootstrapping: the current hash is
/// written next to the asset and VM startup continues with a warning.
#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
pub(crate) fn verify_or_initialize_asset_sha256(
    asset_kind: &str,
    asset_path: &Path,
    asset_bytes: &[u8],
) -> Result<String, MicrovmError> {
    let actual_hash = sha256_hex(asset_bytes);
    verify_or_initialize_asset_sha256_hex(asset_kind, asset_path, &actual_hash)?;
    Ok(actual_hash)
}

/// Verifies a precomputed asset SHA256 against its local sidecar.
#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
pub(crate) fn verify_or_initialize_asset_sha256_hex(
    asset_kind: &str,
    asset_path: &Path,
    actual_hash: &str,
) -> Result<(), MicrovmError> {
    if !is_sha256_hex(actual_hash) {
        return Err(MicrovmError::AssetIntegrity(format!(
            "invalid computed SHA256 for {asset_kind}: {actual_hash}"
        )));
    }

    let sidecar_path = asset_sha256_sidecar_path(asset_path)?;
    let expected_hash = match read_sha256_sidecar(asset_kind, &sidecar_path)? {
        Some(hash) => hash,
        None => {
            warn!(
                asset_kind,
                asset = %sanitize_path_display(asset_path),
                sidecar = %sanitize_path_display(&sidecar_path),
                "VM asset SHA256 sidecar missing; creating first-use hash baseline"
            );
            write_sha256_sidecar_best_effort(asset_kind, &sidecar_path, actual_hash);
            return Ok(());
        }
    };

    if !actual_hash.eq_ignore_ascii_case(&expected_hash) {
        return Err(MicrovmError::AssetIntegrity(format!(
            "tampering warning: {asset_kind} SHA256 mismatch; refusing to start VM. expected {expected_hash}, actual {actual_hash}, asset {}",
            sanitize_path_display(asset_path)
        )));
    }

    debug!(
        asset_kind,
        asset = %sanitize_path_display(asset_path),
        "VM asset SHA256 verification succeeded"
    );
    Ok(())
}

#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
fn asset_sha256_sidecar_path(asset_path: &Path) -> Result<PathBuf, MicrovmError> {
    let file_name = asset_path.file_name().ok_or_else(|| {
        MicrovmError::InvalidConfig(format!(
            "VM asset path has no file name: {}",
            sanitize_path_display(asset_path)
        ))
    })?;

    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(".sha256");

    let mut sidecar_path = asset_path.to_path_buf();
    sidecar_path.set_file_name(sidecar_name);
    Ok(sidecar_path)
}

#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
fn read_sha256_sidecar(
    asset_kind: &str,
    sidecar_path: &Path,
) -> Result<Option<String>, MicrovmError> {
    let contents = match fs::read_to_string(sidecar_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(MicrovmError::AssetIntegrity(format!(
                "failed to read {asset_kind} SHA256 sidecar {}: {error}",
                sanitize_path_display(sidecar_path)
            )));
        }
    };

    let hash = contents.split_whitespace().next().ok_or_else(|| {
        MicrovmError::AssetIntegrity(format!(
            "empty {asset_kind} SHA256 sidecar: {}",
            sanitize_path_display(sidecar_path)
        ))
    })?;

    if !is_sha256_hex(hash) {
        return Err(MicrovmError::AssetIntegrity(format!(
            "invalid {asset_kind} SHA256 sidecar {}: expected 64 hex characters",
            sanitize_path_display(sidecar_path)
        )));
    }

    Ok(Some(hash.to_ascii_lowercase()))
}

#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
fn write_sha256_sidecar_best_effort(asset_kind: &str, sidecar_path: &Path, hash: &str) {
    if let Err(error) = fs::write(sidecar_path, format!("{hash}\n")) {
        warn!(
            asset_kind,
            sidecar = %sanitize_path_display(sidecar_path),
            %error,
            "failed to create VM asset SHA256 sidecar; continuing first-use startup"
        );
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "kvm")))]
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{
        DEFAULT_VM_ASSETS_SUBDIR, asset_sha256_sidecar_path, microvm_config_from_assets_dir,
        resolve_vm_assets_dir, verify_or_initialize_asset_sha256,
        verify_or_initialize_asset_sha256_hex,
    };

    #[test]
    fn resolve_vm_assets_dir_prefers_env_override() {
        let override_dir = PathBuf::from("/tmp/mimobox-custom-vm-assets");

        let actual = resolve_vm_assets_dir(Some(override_dir.clone()), None)
            .expect("environment override must resolve successfully");

        assert_eq!(actual, override_dir);
    }

    #[test]
    fn resolve_vm_assets_dir_falls_back_to_home_default() {
        let home_dir = PathBuf::from("/tmp/mimobox-home");

        let actual = resolve_vm_assets_dir(None, Some(home_dir.clone()))
            .expect("default fallback must resolve successfully");

        assert_eq!(actual, home_dir.join(DEFAULT_VM_ASSETS_SUBDIR));
    }

    #[test]
    fn microvm_config_from_assets_dir_uses_expected_filenames() {
        let assets_dir = tempdir().expect("temporary directory must be created");
        let kernel_path = assets_dir.path().join("vmlinux");
        let rootfs_path = assets_dir.path().join("rootfs.cpio.gz");
        fs::write(&kernel_path, b"kernel").expect("kernel placeholder file must be written");
        fs::write(&rootfs_path, b"rootfs").expect("rootfs placeholder file must be written");

        let config = microvm_config_from_assets_dir(assets_dir.path().to_path_buf(), 256)
            .expect("microVM config must be constructed successfully");

        assert_eq!(config.vcpu_count, 1);
        assert_eq!(config.memory_mb, 256);
        assert_eq!(config.kernel_path, kernel_path);
        assert_eq!(config.rootfs_path, rootfs_path);
    }

    #[test]
    fn microvm_config_from_assets_dir_requires_rootfs() {
        let assets_dir = tempdir().expect("temporary directory must be created");
        let kernel_path = assets_dir.path().join("vmlinux");
        fs::write(&kernel_path, b"kernel").expect("kernel placeholder file must be written");

        let err = microvm_config_from_assets_dir(assets_dir.path().to_path_buf(), 256)
            .expect_err("missing rootfs must fail");

        assert!(err.to_string().contains("missing rootfs"));
    }

    #[test]
    fn missing_sha256_sidecar_is_generated_on_first_use() {
        let assets_dir = tempdir().expect("temporary directory must be created");
        let kernel_path = assets_dir.path().join("vmlinux");
        let kernel_bytes = b"kernel";
        fs::write(&kernel_path, kernel_bytes).expect("kernel placeholder file must be written");

        let hash = verify_or_initialize_asset_sha256("kernel", &kernel_path, kernel_bytes)
            .expect("missing sidecar must generate hash automatically");

        let sidecar_path =
            asset_sha256_sidecar_path(&kernel_path).expect("sidecar path must be generated");
        let sidecar =
            fs::read_to_string(sidecar_path).expect("sidecar must be written successfully");
        assert_eq!(sidecar.trim(), hash);
    }

    #[test]
    fn sha256_sidecar_mismatch_is_rejected() {
        let assets_dir = tempdir().expect("temporary directory must be created");
        let rootfs_path = assets_dir.path().join("rootfs.cpio.gz");
        fs::write(&rootfs_path, b"rootfs").expect("rootfs placeholder file must be written");
        let sidecar_path =
            asset_sha256_sidecar_path(&rootfs_path).expect("sidecar path must be generated");
        fs::write(
            &sidecar_path,
            "0000000000000000000000000000000000000000000000000000000000000000\n",
        )
        .expect("sidecar must be written successfully");

        let err = verify_or_initialize_asset_sha256_hex(
            "rootfs",
            &rootfs_path,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect_err("hash mismatch must reject startup");

        assert!(err.to_string().contains("tampering warning"));
    }
}
