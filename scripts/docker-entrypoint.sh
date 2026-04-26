#!/usr/bin/env bash
set -euo pipefail

export VM_ASSETS_DIR="${VM_ASSETS_DIR:-/opt/mimobox-assets}"

printf 'mimobox Docker 一键试用环境\n'
printf 'VM assets: %s\n' "${VM_ASSETS_DIR}"

if [[ ! -e /dev/kvm ]]; then
    printf '[mimobox][warn] /dev/kvm 不存在，microVM 后端不可用；auto 会回退到可用后端。\n' >&2
elif [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    printf '[mimobox][warn] /dev/kvm 权限不足，建议使用 --device /dev/kvm 或调整宿主权限。\n' >&2
fi

if [[ $# -eq 0 ]]; then
    set -- shell --backend auto
fi

case "$1" in
    mimobox)
        shift
        exec mimobox "$@"
        ;;
    run|shell|snapshot|restore|bench|doctor|setup|mcp-init|completions|version)
        exec mimobox "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
