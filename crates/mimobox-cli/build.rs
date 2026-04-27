use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    configure_git_rerun();

    let git_hash = git_short_hash().unwrap_or_else(|| "unknown".to_string());
    let target_triple = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=MIMOBOX_GIT_HASH={git_hash}");
    println!("cargo:rustc-env=MIMOBOX_TARGET_TRIPLE={target_triple}");
}

fn configure_git_rerun() {
    let git_head = Path::new("../../.git/HEAD");
    if !git_head.exists() {
        return;
    }

    println!("cargo:rerun-if-changed={}", git_head.display());
    let Ok(head) = fs::read_to_string(git_head) else {
        return;
    };

    let Some(ref_path) = head.strip_prefix("ref:").map(str::trim) else {
        return;
    };

    let git_ref = Path::new("../../.git").join(ref_path);
    if git_ref.exists() {
        println!("cargo:rerun-if-changed={}", git_ref.display());
    }
}

fn git_short_hash() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let hash = String::from_utf8(output.stdout).ok()?;
    let hash = hash.trim();
    if hash.is_empty() {
        None
    } else {
        Some(hash.to_string())
    }
}
