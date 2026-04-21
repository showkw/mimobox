#!/usr/bin/env bash
set -euo pipefail

# 基于脚本所在目录定位项目根目录，避免从任意工作目录执行时找不到仓库路径。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT="crates/mimobox-vm/rootfs.cpio.gz"
BUILD_DIR="$(mktemp -d)"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
BUSYBOX_PATH="${ROOTFS_DIR}/bin/busybox"
PRIMARY_BUSYBOX_URL="https://busybox.net/downloads/binaries/1.36.1-x86_64-linux-musl/busybox"
FALLBACK_BUSYBOX_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"

log() {
    printf '[build-rootfs] %s\n' "$*"
}

cleanup() {
    rm -rf -- "${BUILD_DIR}"
}

trap cleanup EXIT

cd "${ROOT_DIR}"

mkdir -p "${BUILD_DIR}"
mkdir -p \
    "${ROOTFS_DIR}/bin" \
    "${ROOTFS_DIR}/sbin" \
    "${ROOTFS_DIR}/etc" \
    "${ROOTFS_DIR}/proc" \
    "${ROOTFS_DIR}/sys" \
    "${ROOTFS_DIR}/dev" \
    "${ROOTFS_DIR}/tmp"

if [[ ! -f "${BUSYBOX_PATH}" ]]; then
    log "下载静态 BusyBox"
    if ! curl -fSL -o "${BUSYBOX_PATH}" "${PRIMARY_BUSYBOX_URL}"; then
        log "主 BusyBox URL 不可用，尝试备用 URL"
        if ! curl -fSL -o "${BUSYBOX_PATH}" "${FALLBACK_BUSYBOX_URL}"; then
            printf '[build-rootfs][error] BusyBox 下载失败，请手动放置静态 busybox 到 %s\n' "${BUSYBOX_PATH}" >&2
            exit 1
        fi
    fi
fi

chmod +x "${BUSYBOX_PATH}"

for applet in sh echo cat ls mkdir rm cp mv sleep true false exit test pwd; do
    ln -sf busybox "${ROOTFS_DIR}/bin/${applet}"
done

cat > "${ROOTFS_DIR}/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
EOF

cat > "${ROOTFS_DIR}/etc/group" <<'EOF'
root:x:0:
EOF

cat > "${ROOTFS_DIR}/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo "mimobox-kvm: init OK"
exec sh
EOF

chmod +x "${ROOTFS_DIR}/init"

mkdir -p "$(dirname "${OUTPUT}")"

# mimobox-vm 的 KVM backend 会把 rootfs 整体作为 initrd 读入内存，
# 当前至少要求它是 gzip 压缩数据；这里使用 Linux 常见的 cpio newc + gzip，
# 既满足现有校验，也和 rdinit=/init 的启动方式保持兼容。
(
    cd "${ROOTFS_DIR}"
    find . | cpio -o -H newc | gzip > "${ROOT_DIR}/${OUTPUT}"
)

SIZE_BYTES="$(wc -c < "${ROOT_DIR}/${OUTPUT}" | tr -d '[:space:]')"

log "rootfs 已生成: ${ROOT_DIR}/${OUTPUT}"
log "文件大小: ${SIZE_BYTES} bytes"
