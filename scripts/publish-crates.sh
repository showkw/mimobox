#!/usr/bin/env bash
# mimobox crate 发布脚本
# 按依赖拓扑排序发布到 crates.io
set -euo pipefail

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    echo "=== DRY RUN 模式 ==="
fi

CRATES=(
    "mimobox-core"
    "mimobox-os"
    "mimobox-wasm"
    "mimobox-vm"
    "mimobox-sdk"
    "mimobox-mcp"
)

echo "=== 发布前检查（编译验证） ==="
cargo check --workspace --exclude mimobox-python --all-features || {
    echo "[错误] 编译检查失败，中止发布"
    exit 1
}

echo ""
echo "=== 开始发布 ==="
PUBLISHED=()
FAILED=()

for crate in "${CRATES[@]}"; do
    echo ""
    echo "--- 发布 ${crate} ---"
    if cargo publish -p "${crate}" ${DRY_RUN}; then
        echo "[成功] ${crate} 发布完成"
        PUBLISHED+=("${crate}")
        # 等待 crates.io 索引更新
        if [[ -z "${DRY_RUN}" ]]; then
            echo "等待 30 秒让 crates.io 索引更新..."
            sleep 30
        fi
    else
        echo "[失败] ${crate} 发布失败"
        FAILED+=("${crate}")
    fi
done

echo ""
echo "=== 发布总结 ==="
echo "成功: ${#PUBLISHED[@]} / ${#CRATES[@]}"
if [[ ${#PUBLISHED[@]} -gt 0 ]]; then
    printf '  - %s\n' "${PUBLISHED[@]}"
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "失败: ${#FAILED[@]}"
    printf '  - %s\n' "${FAILED[@]}"
    exit 1
fi
