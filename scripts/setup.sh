#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() {
    printf '[setup] %s\n' "$*"
}

fail() {
    printf '[setup][error] %s\n' "$*" >&2
    exit 1
}

install_rustup() {
    if command -v rustup >/dev/null 2>&1; then
        return
    fi

    if ! command -v curl >/dev/null 2>&1; then
        fail "未找到 rustup，且当前环境没有 curl，无法自动安装"
    fi

    log "安装 rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal
}

install_cargo_tool() {
    local check_cmd="$1"
    local package_name="$2"

    if eval "${check_cmd}" >/dev/null 2>&1; then
        log "${package_name} 已安装，跳过"
        return
    fi

    log "安装 ${package_name}"
    cargo install --locked "${package_name}"
}

install_rustup

if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "${HOME}/.cargo/env"
fi

command -v cargo >/dev/null 2>&1 || fail "cargo 不可用，请检查 Rust 安装"

cd "${ROOT_DIR}"
mkdir -p "${ROOT_DIR}/logs"

log "同步 stable 工具链"
rustup toolchain install stable --profile minimal
rustup default stable
rustup component add rustfmt clippy

install_cargo_tool "cargo nextest --version" "cargo-nextest"
install_cargo_tool "cargo audit --version" "cargo-audit"

log "环境准备完成"
