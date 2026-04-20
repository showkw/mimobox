#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() {
    printf '[check] %s\n' "$*"
}

cd "${ROOT_DIR}"

log "运行 cargo check"
cargo check

log "运行 cargo clippy -- -D warnings"
cargo clippy -- -D warnings

log "运行 cargo fmt --check"
cargo fmt --check

log "检查完成"
