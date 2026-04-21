#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

log() {
    printf '[extract-vmlinux] %s\n' "$*" >&2
}

fail() {
    printf '[extract-vmlinux][error] %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
用法: scripts/extract-vmlinux.sh <输出路径> [输入内核镜像]

说明:
  - 默认自动选择最新的 /boot/vmlinuz-* 作为输入镜像
  - 支持 gzip / zstd / xz / lzma / lz4 多种压缩格式
  - 输出路径支持相对仓库根目录或绝对路径
  - 需要 sudo 权限读取 /boot 下的内核镜像
EOF
}

resolve_output_path() {
    local output_path="$1"

    if [[ "${output_path}" = /* ]]; then
        printf '%s\n' "${output_path}"
        return 0
    fi

    printf '%s/%s\n' "${ROOT_DIR}" "${output_path}"
}

find_kernel_image() {
    local latest

    # 列出所有 vmlinuz 文件，优先选择非 rescue 的最新版本
    latest="$(ls -1t /boot/vmlinuz-* 2>/dev/null | grep -v rescue | head -n1 || true)"
    [[ -n "${latest}" ]] || fail "未找到 /boot/vmlinuz-* 内核镜像"
    printf '%s\n' "${latest}"
}

# 使用 sudo cat 将内核镜像复制到临时文件（CI 环境中 /boot 文件可能无读权限）
copy_kernel_to_tmp() {
    local image_path="$1"
    local tmp_file

    tmp_file="$(mktemp)"
    # 尝试直接读取，失败则使用 sudo
    if ! cat "${image_path}" > "${tmp_file}" 2>/dev/null; then
        log "直接读取失败，尝试 sudo: ${image_path}"
        sudo cat "${image_path}" > "${tmp_file}" || {
            rm -f "${tmp_file}"
            fail "无法读取内核镜像: ${image_path}"
        }
    fi
    printf '%s\n' "${tmp_file}"
}

check_elf() {
    local file="$1"
    local elf_magic

    elf_magic="$(od -An -tx1 -N4 "${file}" | tr -d '[:space:]')"
    [[ "${elf_magic}" = "7f454c46" ]]
}

main() {
    local output_arg="${1:-}"
    local kernel_image="${2:-}"
    local output_path
    local tmp_kernel=""

    [[ -n "${output_arg}" ]] || {
        usage >&2
        fail "缺少输出路径参数"
    }

    if [[ $# -gt 2 ]]; then
        usage >&2
        fail "参数过多"
    fi

    output_path="$(resolve_output_path "${output_arg}")"

    if [[ -z "${kernel_image}" ]]; then
        kernel_image="$(find_kernel_image)"
    fi

    [[ -f "${kernel_image}" ]] || fail "输入内核镜像不存在: ${kernel_image}"

    mkdir -p "$(dirname "${output_path}")"

    # 复制到临时文件以确保可读
    tmp_kernel="$(copy_kernel_to_tmp "${kernel_image}")"
    trap "rm -f '${tmp_kernel}'" EXIT

    log "输入镜像: ${kernel_image}"
    log "输出路径: ${output_path}"

    log "调用 Python 提取器: ${SCRIPT_DIR}/extract-vmlinux.py"

    if ! python3 "${SCRIPT_DIR}/extract-vmlinux.py" "${tmp_kernel}" "${output_path}"; then
        rm -f "${output_path}"
        fail "无法从 ${kernel_image} 提取 vmlinux：所有压缩格式均失败"
    fi

    if ! check_elf "${output_path}"; then
        rm -f "${output_path}"
        fail "提取结果不是有效的 ELF 文件: ${output_path}"
    fi

    log "vmlinux 提取完成"
}

main "$@"
