use std::env;
use std::path::PathBuf;

use crate::vm::{MicrovmConfig, MicrovmError};

const DEFAULT_VM_ASSETS_SUBDIR: &str = ".mimobox/assets";

/// Resolves the microVM assets directory.
///
/// An explicit override takes precedence. If no override is provided, this falls back to
/// `HOME/.mimobox/assets`.
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

/// Resolves the default microVM assets directory from environment variables.
pub fn vm_assets_dir() -> Result<PathBuf, MicrovmError> {
    resolve_vm_assets_dir(
        env::var_os("VM_ASSETS_DIR").map(PathBuf::from),
        env::var_os("HOME").map(PathBuf::from),
    )
}

/// Builds a `MicrovmConfig` from an assets directory.
pub fn microvm_config_from_assets_dir(
    assets_dir: PathBuf,
    memory_mb: u32,
) -> Result<MicrovmConfig, MicrovmError> {
    let kernel_path = assets_dir.join("vmlinux");
    let rootfs_path = assets_dir.join("rootfs.cpio.gz");

    if !kernel_path.exists() {
        return Err(MicrovmError::InvalidConfig(format!(
            "missing kernel image: {}",
            kernel_path.display()
        )));
    }

    if !rootfs_path.exists() {
        return Err(MicrovmError::InvalidConfig(format!(
            "missing rootfs: {}",
            rootfs_path.display()
        )));
    }

    Ok(MicrovmConfig {
        vcpu_count: 1,
        memory_mb,
        cpu_quota_us: None,
        kernel_path,
        rootfs_path,
    })
}

/// Builds a `MicrovmConfig` from the default assets directory.
pub fn microvm_config_from_vm_assets(memory_mb: u32) -> Result<MicrovmConfig, MicrovmError> {
    let assets_dir = vm_assets_dir()?;
    microvm_config_from_assets_dir(assets_dir, memory_mb)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{DEFAULT_VM_ASSETS_SUBDIR, microvm_config_from_assets_dir, resolve_vm_assets_dir};

    #[test]
    fn resolve_vm_assets_dir_prefers_env_override() {
        let override_dir = PathBuf::from("/tmp/mimobox-custom-vm-assets");

        let actual =
            resolve_vm_assets_dir(Some(override_dir.clone()), None).expect("环境变量覆盖必须成功");

        assert_eq!(actual, override_dir);
    }

    #[test]
    fn resolve_vm_assets_dir_falls_back_to_home_default() {
        let home_dir = PathBuf::from("/tmp/mimobox-home");

        let actual = resolve_vm_assets_dir(None, Some(home_dir.clone())).expect("默认回退必须成功");

        assert_eq!(actual, home_dir.join(DEFAULT_VM_ASSETS_SUBDIR));
    }

    #[test]
    fn microvm_config_from_assets_dir_uses_expected_filenames() {
        let assets_dir = tempdir().expect("临时目录必须创建成功");
        let kernel_path = assets_dir.path().join("vmlinux");
        let rootfs_path = assets_dir.path().join("rootfs.cpio.gz");
        fs::write(&kernel_path, b"kernel").expect("写入内核占位文件必须成功");
        fs::write(&rootfs_path, b"rootfs").expect("写入 rootfs 占位文件必须成功");

        let config = microvm_config_from_assets_dir(assets_dir.path().to_path_buf(), 256)
            .expect("构造 microVM 配置必须成功");

        assert_eq!(config.vcpu_count, 1);
        assert_eq!(config.memory_mb, 256);
        assert_eq!(config.kernel_path, kernel_path);
        assert_eq!(config.rootfs_path, rootfs_path);
    }

    #[test]
    fn microvm_config_from_assets_dir_requires_rootfs() {
        let assets_dir = tempdir().expect("临时目录必须创建成功");
        let kernel_path = assets_dir.path().join("vmlinux");
        fs::write(&kernel_path, b"kernel").expect("写入内核占位文件必须成功");

        let err = microvm_config_from_assets_dir(assets_dir.path().to_path_buf(), 256)
            .expect_err("缺少 rootfs 时必须失败");

        assert!(err.to_string().contains("missing rootfs"));
    }
}
