#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${ROOT_DIR}/logs"

mkdir -p "${LOG_DIR}"

cd "${ROOT_DIR}"

cargo bench -p mimobox-wasm --features wasm --bench bench_realworkload_wasm 2>&1 \
    | tee "${LOG_DIR}/bench-realworkload-wasm-$(date +%Y%m%d-%H%M%S).log"
