#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_VM_ASSETS_SUBDIR=".mimobox/assets"
OUTPUT="${OUTPUT:-}"
CC_BIN="${CC:-gcc}"
ENABLE_BOOT_PROFILE="${ENABLE_BOOT_PROFILE:-}"
ENABLE_VSOCK="${ENABLE_VSOCK:-}"
# BusyBox 官方 binaries 目录当前可用的最新 x86_64-linux-musl 版本是 1.35.0；
# 1.36.1 对应链接已失效，因此主下载地址先回退到官方仍可访问的最新版本。
PRIMARY_BUSYBOX_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
FALLBACK_BUSYBOX_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
DOCKER_IMAGE="${DOCKER_IMAGE:-alpine:3.20}"
TARGET_ALPINE_ARCH="x86_64"
BUSYBOX_APPLETS=(
    sh
    echo
    cat
    ls
    mkdir
    rm
    cp
    mv
    sleep
    true
    false
    test
    pwd
    printf
    timeout
)

log() {
    printf '[build-rootfs] %s\n' "$*"
}

fail() {
    printf '[build-rootfs][error] %s\n' "$*" >&2
    exit 1
}

should_enable_boot_profile() {
    case "${ENABLE_BOOT_PROFILE}" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
    esac

    return 1
}

should_enable_vsock() {
    case "${ENABLE_VSOCK}" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
    esac

    return 1
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "缺少依赖命令: $1"
    fi
}

install_python_runtime_with_apk() {
    local rootfs_dir="$1"

    log "向 Alpine rootfs 安装 Python 3 运行时"
    apk add \
        --root "${rootfs_dir}" \
        --initdb \
        --no-cache \
        --arch "${TARGET_ALPINE_ARCH}" \
        --repositories-file /etc/apk/repositories \
        --keys-dir /etc/apk/keys \
        python3 \
        py3-pip >/dev/null
    rm -rf -- "${rootfs_dir}/var/cache/apk"

    [[ -x "${rootfs_dir}/usr/bin/python3" ]] || fail "rootfs 中未找到 /usr/bin/python3"
}

install_python_runtime_in_rootfs() {
    local rootfs_dir="$1"

    if command -v apk >/dev/null 2>&1; then
        install_python_runtime_with_apk "${rootfs_dir}"
        return
    fi

    require_command docker
    log "宿主机未安装 apk，使用 Docker 为 rootfs 安装 Python 3 运行时"

    # 通过 Alpine 容器对目标 rootfs 执行 apk add，保持本地与 Docker 构建结果一致。
    docker run --rm \
        -e TARGET_ALPINE_ARCH="${TARGET_ALPINE_ARCH}" \
        -v "${rootfs_dir}:/rootfs" \
        "${DOCKER_IMAGE}" \
        sh -eu -c '
            apk add \
                --root /rootfs \
                --initdb \
                --no-cache \
                --arch "${TARGET_ALPINE_ARCH}" \
                --repositories-file /etc/apk/repositories \
                --keys-dir /etc/apk/keys \
                python3 \
                py3-pip >/dev/null
            rm -rf /rootfs/var/cache/apk
            [ -x /rootfs/usr/bin/python3 ]
        '
}

resolve_output_path() {
    local output_path="${OUTPUT}"

    if [[ -z "${output_path}" ]]; then
        if [[ -n "${VM_ASSETS_DIR:-}" ]]; then
            output_path="${VM_ASSETS_DIR}/rootfs.cpio.gz"
        else
            [[ -n "${HOME:-}" ]] || fail "未设置 OUTPUT 时，必须存在 HOME 环境变量或设置 VM_ASSETS_DIR"
            output_path="${HOME}/${DEFAULT_VM_ASSETS_SUBDIR}/rootfs.cpio.gz"
        fi
    fi

    if [[ "${output_path}" = /* ]]; then
        printf '%s\n' "${output_path}"
        return
    fi
    printf '%s/%s\n' "${ROOT_DIR}" "${output_path}"
}

can_create_device_nodes() {
    local probe_dir
    probe_dir="$(mktemp -d)"
    if mknod "${probe_dir}/console" c 5 1 >/dev/null 2>&1; then
        rm -rf -- "${probe_dir}"
        return 0
    fi
    rm -rf -- "${probe_dir}"
    return 1
}

build_rootfs_locally() {
    local output_path="$1"
    local build_dir rootfs_dir guest_init_bin busybox_path

    build_dir="$(mktemp -d)"
    rootfs_dir="${build_dir}/rootfs"
    guest_init_bin="${build_dir}/init"
    busybox_path="${rootfs_dir}/bin/busybox"

    cleanup_local() {
        rm -rf -- "${build_dir}"
    }
    trap cleanup_local RETURN

    mkdir -p \
        "${rootfs_dir}/bin" \
        "${rootfs_dir}/sbin" \
        "${rootfs_dir}/etc" \
        "${rootfs_dir}/proc" \
        "${rootfs_dir}/sys" \
        "${rootfs_dir}/dev" \
        "${rootfs_dir}/tmp" \
        "${rootfs_dir}/root"

    log "编译静态 guest init"
    "${CC_BIN}" \
        -O2 \
        -Wall \
        -Wextra \
        -Werror \
        -static \
        -s \
        "${GUEST_INIT_CFLAGS[@]}" \
        -o "${guest_init_bin}" \
        "${ROOT_DIR}/crates/mimobox-vm/guest/guest-init.c"

    log "下载静态 BusyBox"
    if ! curl -fSL -o "${busybox_path}" "${PRIMARY_BUSYBOX_URL}"; then
        log "主 BusyBox URL 不可用，尝试备用 URL"
        curl -fSL -o "${busybox_path}" "${FALLBACK_BUSYBOX_URL}"
    fi
    chmod 0755 "${busybox_path}"

    for applet in "${BUSYBOX_APPLETS[@]}"; do
        ln -sf busybox "${rootfs_dir}/bin/${applet}"
    done

    install -m 0755 "${guest_init_bin}" "${rootfs_dir}/init"

    cat > "${rootfs_dir}/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
EOF

    cat > "${rootfs_dir}/etc/group" <<'EOF'
root:x:0:
EOF

    mknod -m 600 "${rootfs_dir}/dev/console" c 5 1
    mknod -m 666 "${rootfs_dir}/dev/null" c 1 3
    install_python_runtime_in_rootfs "${rootfs_dir}"

    mkdir -p "$(dirname "${output_path}")"
    (
        cd "${rootfs_dir}"
        find . -print0 | cpio --null -o -H newc --quiet | gzip -n > "${output_path}"
    )
}

build_rootfs_in_docker() {
    local output_path="$1"
    local output_dir output_name

    require_command docker
    output_dir="$(dirname "${output_path}")"
    output_name="$(basename "${output_path}")"
    mkdir -p "${output_dir}"

    log "使用 Docker fallback 构建 rootfs"
    docker run --rm \
        -e HOST_UID="$(id -u)" \
        -e HOST_GID="$(id -g)" \
        -e OUTPUT_NAME="${output_name}" \
        -e GUEST_INIT_CFLAGS="${GUEST_INIT_CFLAGS[*]}" \
        -e TARGET_ALPINE_ARCH="${TARGET_ALPINE_ARCH}" \
        -e PRIMARY_BUSYBOX_URL="${PRIMARY_BUSYBOX_URL}" \
        -e FALLBACK_BUSYBOX_URL="${FALLBACK_BUSYBOX_URL}" \
        -e BUSYBOX_APPLETS="${BUSYBOX_APPLETS[*]}" \
        -v "${ROOT_DIR}:/workspace" \
        -v "${output_dir}:/out" \
        "${DOCKER_IMAGE}" \
        sh -eu -c '
            apk add --no-cache build-base curl cpio gzip >/dev/null
            build_dir="$(mktemp -d)"
            rootfs_dir="${build_dir}/rootfs"
            guest_init_bin="${build_dir}/init"
            busybox_path="${rootfs_dir}/bin/busybox"
            trap "rm -rf -- ${build_dir}" EXIT

            mkdir -p \
                "${rootfs_dir}/bin" \
                "${rootfs_dir}/sbin" \
                "${rootfs_dir}/etc" \
                "${rootfs_dir}/proc" \
                "${rootfs_dir}/sys" \
                "${rootfs_dir}/dev" \
                "${rootfs_dir}/tmp" \
                "${rootfs_dir}/root"

            if [ -n "${GUEST_INIT_CFLAGS}" ]; then
                echo "[build-rootfs] 额外 guest init 编译参数: ${GUEST_INIT_CFLAGS}"
            fi

            gcc -O2 -Wall -Wextra -Werror -static -s ${GUEST_INIT_CFLAGS} \
                -o "${guest_init_bin}" \
                /workspace/crates/mimobox-vm/guest/guest-init.c

            if ! curl -fSL -o "${busybox_path}" "${PRIMARY_BUSYBOX_URL}"; then
                curl -fSL -o "${busybox_path}" "${FALLBACK_BUSYBOX_URL}"
            fi
            chmod 0755 "${busybox_path}"

            for applet in ${BUSYBOX_APPLETS}; do
                ln -sf busybox "${rootfs_dir}/bin/${applet}"
            done

            install -m 0755 "${guest_init_bin}" "${rootfs_dir}/init"
            cat > "${rootfs_dir}/etc/passwd" <<'"'"'EOF'"'"'
root:x:0:0:root:/root:/bin/sh
EOF
            cat > "${rootfs_dir}/etc/group" <<'"'"'EOF'"'"'
root:x:0:
EOF
            mknod -m 600 "${rootfs_dir}/dev/console" c 5 1
            mknod -m 666 "${rootfs_dir}/dev/null" c 1 3
            apk add \
                --root "${rootfs_dir}" \
                --initdb \
                --no-cache \
                --arch "${TARGET_ALPINE_ARCH}" \
                --repositories-file /etc/apk/repositories \
                --keys-dir /etc/apk/keys \
                python3 \
                py3-pip >/dev/null
            rm -rf -- "${rootfs_dir}/var/cache/apk"
            [ -x "${rootfs_dir}/usr/bin/python3" ]

            (
                cd "${rootfs_dir}"
                find . -print0 | cpio --null -o -H newc --quiet | gzip -n > "/out/${OUTPUT_NAME}"
            )
            chown "${HOST_UID}:${HOST_GID}" "/out/${OUTPUT_NAME}"
        '
}

if [[ "$(uname -s)" != "Linux" ]]; then
    fail "scripts/build-rootfs.sh 仅支持在 Linux 上执行"
fi

require_command "${CC_BIN}"
require_command curl
require_command cpio
require_command gzip

OUTPUT_PATH="$(resolve_output_path)"
GUEST_INIT_CFLAGS=()

if should_enable_boot_profile; then
    GUEST_INIT_CFLAGS+=("-DBOOT_PROFILE")
    log "启用 guest boot profile 串口时间戳输出"
fi

if should_enable_vsock; then
    GUEST_INIT_CFLAGS+=("-DUSE_VSOCK")
    log "启用 guest vsock 命令通道"
fi

cd "${ROOT_DIR}"

if can_create_device_nodes && build_rootfs_locally "${OUTPUT_PATH}"; then
    :
else
    log "本机构建不可用，回退到 Docker"
    build_rootfs_in_docker "${OUTPUT_PATH}"
fi

SIZE_BYTES="$(wc -c < "${OUTPUT_PATH}" | tr -d '[:space:]')"
log "rootfs 已生成: ${OUTPUT_PATH}"
log "文件大小: ${SIZE_BYTES} bytes"
