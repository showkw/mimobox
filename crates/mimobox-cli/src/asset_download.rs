use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

const ASSET_MANIFEST_URL: &str =
    "https://github.com/showkw/mimobox/releases/latest/download/asset-manifest.json";

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
            warn!(%error, "预构建 VM 资产 manifest 不可用");
            return Ok(false);
        }
    };

    fs::create_dir_all(assets_dir).map_err(|error| {
        warn!(path = %assets_dir.display(), %error, "创建 VM 资产目录失败");
        format!("创建 VM 资产目录失败: {error}")
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
            warn!(%error, "创建 VM 资产下载客户端失败");
            format!("创建下载客户端失败: {error}")
        })
}

fn fetch_manifest(client: &reqwest::blocking::Client) -> Result<Option<AssetManifest>, String> {
    let response = match client.get(ASSET_MANIFEST_URL).send() {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "下载 VM 资产 manifest 失败");
            return Ok(None);
        }
    };

    if !response.status().is_success() {
        warn!(status = %response.status(), "VM 资产 manifest 返回非成功状态");
        return Ok(None);
    }

    let manifest_text = response.text().map_err(|error| {
        warn!(%error, "读取 VM 资产 manifest 响应失败");
        format!("读取 manifest 失败: {error}")
    })?;

    serde_json::from_str::<AssetManifest>(&manifest_text)
        .map(Some)
        .map_err(|error| {
            warn!(%error, "解析 VM 资产 manifest 失败");
            format!("解析 manifest 失败: {error}")
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
            warn!(path = %target_path.display(), %error, "计算本地 VM 资产 SHA256 失败");
            format!("计算 SHA256 失败: {} ({error})", asset.name)
        })?;

        if actual_hash.eq_ignore_ascii_case(&asset.sha256) {
            return Ok(true);
        }
    }

    writeln!(
        writer,
        "  下载 {}: {}...",
        asset.name,
        human_bytes(asset.size)
    )
    .map_err(|error| {
        warn!(name = %asset.name, %error, "输出 VM 资产下载进度失败");
        error.to_string()
    })?;

    let temporary_path = temporary_asset_path(assets_dir, &asset.name)?;
    if !download_asset(client, asset, &temporary_path)? {
        return Ok(false);
    }

    let actual_hash = sha256_file(&temporary_path).map_err(|error| {
        warn!(path = %temporary_path.display(), %error, "计算已下载 VM 资产 SHA256 失败");
        format!("计算 SHA256 失败: {} ({error})", asset.name)
    })?;

    if !actual_hash.eq_ignore_ascii_case(&asset.sha256) {
        let _ = fs::remove_file(&temporary_path);
        warn!(
            name = %asset.name,
            expected = %asset.sha256,
            actual = %actual_hash,
            "VM 资产 SHA256 校验失败"
        );
        return Err(format!("SHA256 校验失败: {}", asset.name));
    }

    fs::rename(&temporary_path, &target_path).map_err(|error| {
        warn!(from = %temporary_path.display(), to = %target_path.display(), %error, "安装 VM 资产失败");
        format!("安装资产失败: {} ({error})", asset.name)
    })?;

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

fn validate_asset_name(name: &str) -> Result<(), String> {
    let path = Path::new(name);
    let mut components = path.components();
    let valid = matches!(components.next(), Some(std::path::Component::Normal(component)) if component == std::ffi::OsStr::new(name))
        && components.next().is_none();
    if !valid {
        warn!(%name, "VM 资产名称非法");
        return Err(format!("资产名称非法: {name}"));
    }

    Ok(())
}

fn download_asset(
    client: &reqwest::blocking::Client,
    asset: &VmAsset,
    temporary_path: &Path,
) -> Result<bool, String> {
    let mut response = match client.get(&asset.url).send() {
        Ok(response) => response,
        Err(error) => {
            warn!(name = %asset.name, %error, "下载 VM 资产失败");
            let _ = fs::remove_file(temporary_path);
            return Ok(false);
        }
    };

    if !response.status().is_success() {
        warn!(name = %asset.name, status = %response.status(), "VM 资产返回非成功状态");
        let _ = fs::remove_file(temporary_path);
        return Ok(false);
    }

    let mut file = File::create(temporary_path).map_err(|error| {
        warn!(path = %temporary_path.display(), %error, "创建 VM 资产临时文件失败");
        format!("创建临时文件失败: {} ({error})", asset.name)
    })?;

    io::copy(&mut response, &mut file).map_err(|error| {
        warn!(name = %asset.name, %error, "写入 VM 资产临时文件失败");
        let _ = fs::remove_file(temporary_path);
        format!("写入资产失败: {} ({error})", asset.name)
    })?;

    file.sync_all().map_err(|error| {
        warn!(path = %temporary_path.display(), %error, "同步 VM 资产临时文件失败");
        format!("同步资产失败: {} ({error})", asset.name)
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
