#!/usr/bin/env bash
# CI benchmark regression check
# Runs OS and Wasm benchmarks with a criterion baseline for regression detection.
set -euo pipefail

echo "=== OS Benchmark ==="
cargo bench -p mimobox-os --bench pool_bench -- --save-baseline ci

echo "=== Wasm Benchmark ==="
cargo bench -p mimobox-wasm --features wasm --bench wasm_bench -- --save-baseline ci

echo "=== Benchmarks complete ==="
