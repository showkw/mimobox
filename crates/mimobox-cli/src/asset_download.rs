use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

const ASSET_MANIFEST_URL: &str =
    "https://github.com/showkw/mimobox/releases/latest/download/asset-manifest.json";
const ALLOWED_ASSET_URL_PREFIXES: &[&str] = &[
    "https://github.com/showkw/mimobox/",
    "https://github.com/showkw/mimobox",
];

#[derive(Debug, Deserialize)]
struct AssetManifest {
    #[allow(dead_code)]
    version: String,
    assets: Vec<VmAsset>,
}

#[derive(Debug, Deserialize)]
struct VmAsset {
    name: String,
    url: String,
    sha256: String,
    size: u64,
}

pub fn download_vm_assets(assets_dir: &Path, writer: &mut impl Write) -> Result<bool, String> {
    let client = build_client()?;
    let manifest = match fetch_manifest(&client) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return Ok(false),
        Err(error) => {
            warn!(%error, "pre-built VM asset manifest unavailable");
            return Ok(false);
        }
    };

    fs::create_dir_all(assets_dir).map_err(|error| {
        warn!(path = %assets_dir.display(), %error, "failed to create VM asset directory");
        format!("failed to create VM asset directory: {error}")
    })?;

    for asset in manifest.assets {
        if !ensure_asset_ready(&client, assets_dir, &asset, writer)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn build_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .user_agent(format!("mimobox/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| {
            warn!(%error, "failed to create VM asset download client");
            format!("failed to create download client: {error}")
        })
}

fn fetch_manifest(client: &reqwest::blocking::Client) -> Result<Option<AssetManifest>, String> {
    let response = match client.get(ASSET_MANIFEST_URL).send() {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "failed to download VM asset manifest");
            return Ok(None);
        }
    };

    if !response.status().is_success() {
        warn!(status = %response.status(), "VM asset manifest returned non-success status");
        return Ok(None);
    }

    let manifest_text = response.text().map_err(|error| {
        warn!(%error, "failed to read VM asset manifest response");
        format!("failed to read manifest: {error}")
    })?;

    serde_json::from_str::<AssetManifest>(&manifest_text)
        .map(Some)
        .map_err(|error| {
            warn!(%error, "failed to parse VM asset manifest");
            format!("failed to parse manifest: {error}")
        })
}

fn ensure_asset_ready(
    client: &reqwest::blocking::Client,
    assets_dir: &Path,
    asset: &VmAsset,
    writer: &mut impl Write,
) -> Result<bool, String> {
    let target_path = target_asset_path(assets_dir, &asset.name)?;
    if target_path.exists() {
        let actual_hash = sha256_file(&target_path).map_err(|error| {
            warn!(path = %target_path.display(), %error, "failed to compute local VM asset SHA256");
            format!("SHA256 computation failed: {} ({error})", asset.name)
        })?;

        if actual_hash.eq_ignore_ascii_case(&asset.sha256) {
            write_sha256_sidecar_best_effort(&target_path, &actual_hash);
            return Ok(true);
        }
    }

    writeln!(
        writer,
        "  Downloading {}: {}...",
        asset.name,
        human_bytes(asset.size)
    )
    .map_err(|error| {
        warn!(name = %asset.name, %error, "failed to output VM asset download progress");
        error.to_string()
    })?;

    let temporary_path = temporary_asset_path(assets_dir, &asset.name)?;
    if !download_asset(client, asset, &temporary_path)? {
        return Ok(false);
    }

    let actual_hash = sha256_file(&temporary_path).map_err(|error| {
        warn!(path = %temporary_path.display(), %error, "failed to compute SHA256 of downloaded VM asset");
        format!("SHA256 computation failed: {} ({error})", asset.name)
    })?;

    if !actual_hash.eq_ignore_ascii_case(&asset.sha256) {
        let _ = fs::remove_file(&temporary_path);
        warn!(
            name = %asset.name,
            expected = %asset.sha256,
            actual = %actual_hash,
            "VM asset SHA256 verification failed"
        );
        return Err(format!("SHA256 verification failed: {}", asset.name));
    }

    fs::rename(&temporary_path, &target_path).map_err(|error| {
        warn!(from = %temporary_path.display(), to = %target_path.display(), %error, "failed to install VM asset");
        format!("asset installation failed: {} ({error})", asset.name)
    })?;
    write_sha256_sidecar_best_effort(&target_path, &actual_hash);

    Ok(true)
}

fn target_asset_path(assets_dir: &Path, name: &str) -> Result<PathBuf, String> {
    validate_asset_name(name)?;
    Ok(assets_dir.join(name))
}

fn temporary_asset_path(assets_dir: &Path, name: &str) -> Result<PathBuf, String> {
    validate_asset_name(name)?;
    Ok(assets_dir.join(format!(".{name}.tmp")))
}

fn sha256_sidecar_path(asset_path: &Path) -> Result<PathBuf, String> {
    let file_name = asset_path
        .file_name()
        .ok_or_else(|| format!("asset path has no file name: {}", asset_path.display()))?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(".sha256");

    let mut sidecar_path = asset_path.to_path_buf();
    sidecar_path.set_file_name(sidecar_name);
    Ok(sidecar_path)
}

fn validate_asset_name(name: &str) -> Result<(), String> {
    let path = Path::new(name);
    let mut components = path.components();
    let valid = matches!(components.next(), Some(std::path::Component::Normal(component)) if component == std::ffi::OsStr::new(name))
        && components.next().is_none();
    if !valid {
        warn!(%name, "invalid VM asset name");
        return Err(format!("invalid asset name: {name}"));
    }

    Ok(())
}

fn validate_asset_url(url: &str) -> Result<(), String> {
    // SECURITY: 限制资产下载 URL 必须来自官方仓库，防止中间人替换。
    if !ALLOWED_ASSET_URL_PREFIXES
        .iter()
        .any(|prefix| url.starts_with(prefix))
    {
        return Err(format!(
            "asset URL rejected (not from official repository): {url}"
        ));
    }

    Ok(())
}

fn download_asset(
    client: &reqwest::blocking::Client,
    asset: &VmAsset,
    temporary_path: &Path,
) -> Result<bool, String> {
    validate_asset_url(&asset.url)?;

    let mut response = match client.get(&asset.url).send() {
        Ok(response) => response,
        Err(error) => {
            warn!(name = %asset.name, %error, "failed to download VM asset");
            let _ = fs::remove_file(temporary_path);
            return Ok(false);
        }
    };

    if !response.status().is_success() {
        warn!(name = %asset.name, status = %response.status(), "VM asset returned non-success status");
        let _ = fs::remove_file(temporary_path);
        return Ok(false);
    }

    let mut file = File::create(temporary_path).map_err(|error| {
        warn!(path = %temporary_path.display(), %error, "failed to create VM asset temporary file");
        format!("failed to create temporary file: {} ({error})", asset.name)
    })?;

    io::copy(&mut response, &mut file).map_err(|error| {
        warn!(name = %asset.name, %error, "failed to write VM asset temporary file");
        let _ = fs::remove_file(temporary_path);
        format!("asset write failed: {} ({error})", asset.name)
    })?;

    file.sync_all().map_err(|error| {
        warn!(path = %temporary_path.display(), %error, "failed to sync VM asset temporary file");
        format!("asset sync failed: {} ({error})", asset.name)
    })?;

    Ok(true)
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn write_sha256_sidecar_best_effort(asset_path: &Path, hash: &str) {
    let sidecar_path = match sha256_sidecar_path(asset_path) {
        Ok(path) => path,
        Err(error) => {
            warn!(%error, "failed to derive VM asset SHA256 sidecar path");
            return;
        }
    };

    if let Err(error) = fs::write(&sidecar_path, format!("{hash}\n")) {
        warn!(
            asset = %asset_path.display(),
            sidecar = %sidecar_path.display(),
            %error,
            "failed to write VM asset SHA256 sidecar"
        );
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0usize;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{bytes} {}", UNITS[unit_index])
    } else {
        format!("{value:.1}{}", UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{sha256_sidecar_path, validate_asset_url, write_sha256_sidecar_best_effort};

    #[test]
    fn accepts_official_asset_urls() {
        assert!(
            validate_asset_url(
                "https://github.com/showkw/mimobox/releases/latest/download/rootfs.ext4"
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_non_official_asset_urls() {
        let result = validate_asset_url("https://example.com/rootfs.ext4");

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("asset URL rejected (not from official repository)")
        );
    }

    #[test]
    fn writes_sha256_sidecar_next_to_asset() {
        let assets_dir = tempdir().expect("临时目录必须创建成功");
        let asset_path = assets_dir.path().join("vmlinux");

        write_sha256_sidecar_best_effort(
            &asset_path,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );

        let sidecar_path = sha256_sidecar_path(&asset_path).expect("sidecar 路径必须可生成");
        let sidecar = fs::read_to_string(sidecar_path).expect("sidecar 必须写入成功");
        assert_eq!(
            sidecar.trim(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }
}
