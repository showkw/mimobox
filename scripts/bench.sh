#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_NAME="${1:-mimobox-os}"
BENCH_NAME="${2:-all}"
CRITERION_DIR="${ROOT_DIR}/target/criterion"

log() {
    printf '[bench] %s\n' "$*"
}

fail() {
    printf '[bench][error] %s\n' "$*" >&2
    exit 1
}

if [[ $# -gt 2 ]]; then
    fail "用法: scripts/bench.sh [crate-name] [bench-name|all]"
fi

if ! command -v cargo >/dev/null 2>&1; then
    fail "未找到 cargo，请先安装 Rust 工具链"
fi

mkdir -p "${CRITERION_DIR}"

cd "${ROOT_DIR}"

CMD=(cargo bench -p "${CRATE_NAME}")
if [[ "${BENCH_NAME}" != "all" ]]; then
    CMD+=(--bench "${BENCH_NAME}")
fi

log "项目根目录: ${ROOT_DIR}"
log "目标 crate: ${CRATE_NAME}"
log "目标 bench: ${BENCH_NAME}"
log "结果目录: ${CRITERION_DIR}"
log "执行命令: ${CMD[*]}"

"${CMD[@]}"

log "基准完成，结果已输出到 ${CRITERION_DIR}"
