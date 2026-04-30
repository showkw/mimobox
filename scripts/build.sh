#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() {
    printf '[build] %s\n' "$*"
}

cd "${ROOT_DIR}"

if [[ $# -eq 0 ]]; then
    CMD=(cargo build --workspace)
else
    CMD=(cargo build "$@")
fi

log "项目根目录: ${ROOT_DIR}"
log "执行命令: ${CMD[*]}"
"${CMD[@]}"

log "构建完成"
