#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="default"

if [[ $# -gt 0 ]]; then
    case "$1" in
        default | linux | macos | wasm | all)
            TARGET="$1"
            shift
            ;;
    esac
fi

EXTRA_ARGS=("$@")

log() {
    printf '[test] %s\n' "$*"
}

fail() {
    printf '[test][error] %s\n' "$*" >&2
    exit 1
}

case "${TARGET}" in
    default)
        CMD=(cargo test)
        ;;
    linux | macos)
        CMD=(cargo test -p mimobox-core -p mimobox-os -p mimobox-cli)
        ;;
    wasm)
        CMD=(cargo test -p mimobox-wasm -p mimobox-cli --features mimobox-cli/wasm)
        ;;
    all)
        CMD=(cargo test --workspace --features mimobox-cli/wasm)
        ;;
    *)
        fail "未知测试目标: ${TARGET}。可选值: default、linux、macos、wasm、all"
        ;;
esac

if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    CMD+=("${EXTRA_ARGS[@]}")
fi

cd "${ROOT_DIR}"

log "项目根目录: ${ROOT_DIR}"
log "测试目标: ${TARGET}"
log "执行命令: ${CMD[*]}"
"${CMD[@]}"

log "测试完成"
