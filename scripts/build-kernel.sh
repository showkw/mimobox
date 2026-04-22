#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CALL_DIR="$(pwd)"

OUTPUT="${OUTPUT:-crates/mimobox-vm/vmlinux}"
KERNEL_SOURCE=""
KERNEL_CACHE_DIR="${KERNEL_CACHE_DIR:-${HOME}/.cache/mimobox/kernel-src}"
KERNEL_BUILD_DIR="${KERNEL_BUILD_DIR:-}"
TARGET_ARCH="x86_64"
FALLBACK_KERNEL_VERSION="6.1.169"
LOG_FILE=""

log() {
    printf '[build-kernel] %s\n' "$*"
}

log_stderr() {
    printf '[build-kernel] %s\n' "$*" >&2
}

fail() {
    printf '[build-kernel][error] %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
用法:
  scripts/build-kernel.sh [--kernel-source /path/to/linux] [--output /path/to/vmlinux]

说明:
  - 默认构建 x86_64 guest 的未压缩 ELF `vmlinux`
  - 未提供 --kernel-source 时，优先从 kernel.org 下载最新 6.1.y LTS
  - 若 6.1 LTS 无法解析，则回退到 kernel.org 当前 latest stable
  - 输出路径支持相对仓库根目录或绝对路径
  - 额外构建目录可通过环境变量 KERNEL_BUILD_DIR 覆盖
  - 非 x86_64 Linux 主机需要自行提供 x86_64 交叉编译链，并设置 CROSS_COMPILE
EOF
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "缺少依赖命令: $1"
    fi
}

resolve_repo_path() {
    local path="$1"

    if [[ "${path}" = /* ]]; then
        printf '%s\n' "${path}"
        return 0
    fi

    printf '%s/%s\n' "${ROOT_DIR}" "${path}"
}

resolve_user_path() {
    local path="$1"

    if [[ "${path}" = /* ]]; then
        printf '%s\n' "${path}"
        return 0
    fi

    printf '%s/%s\n' "${CALL_DIR}" "${path}"
}

detect_jobs() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
        return 0
    fi

    if command -v getconf >/dev/null 2>&1; then
        getconf _NPROCESSORS_ONLN
        return 0
    fi

    printf '1\n'
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --kernel-source)
                [[ $# -ge 2 ]] || fail "--kernel-source 缺少路径参数"
                KERNEL_SOURCE="$(resolve_user_path "$2")"
                shift 2
                ;;
            --output)
                [[ $# -ge 2 ]] || fail "--output 缺少路径参数"
                OUTPUT="$2"
                shift 2
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                fail "未知参数: $1"
                ;;
        esac
    done
}

init_logging() {
    mkdir -p "${ROOT_DIR}/logs"
    LOG_FILE="${ROOT_DIR}/logs/build-kernel-$(date '+%Y%m%d-%H%M%S').log"
    exec > >(tee -a "${LOG_FILE}") 2>&1
    log "日志文件: ${LOG_FILE}"
}

ensure_linux_host() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        fail "scripts/build-kernel.sh 仅支持在 Linux 上执行"
    fi

    if [[ "$(uname -m)" != "${TARGET_ARCH}" && -z "${CROSS_COMPILE:-}" ]]; then
        fail "当前宿主架构不是 ${TARGET_ARCH}，请设置 CROSS_COMPILE=x86_64-linux-gnu- 后重试"
    fi
}

resolve_cc_bin() {
    if [[ -n "${CC:-}" ]]; then
        printf '%s\n' "${CC}"
        return 0
    fi

    printf '%s\n' "${CROSS_COMPILE:-}gcc"
}

resolve_release_version() {
    FALLBACK_KERNEL_VERSION_ENV="${FALLBACK_KERNEL_VERSION}" python3 - <<'PY'
import json
import os
import sys
import urllib.request

fallback = os.environ.get("FALLBACK_KERNEL_VERSION_ENV", "6.1.169")
url = "https://www.kernel.org/releases.json"

try:
    with urllib.request.urlopen(url, timeout=10) as response:
        data = json.load(response)
except Exception:
    print(fallback)
    sys.exit(0)

releases = data.get("releases", [])
latest_61 = None
for item in releases:
    if not isinstance(item, dict):
        continue
    version = str(item.get("version", ""))
    if version.startswith("6.1.") and not item.get("iseol", False):
        latest_61 = version
        break

if latest_61:
    print(latest_61)
    sys.exit(0)

latest_stable = data.get("latest_stable", {})
if isinstance(latest_stable, dict):
    version = str(latest_stable.get("version", "")).strip()
    if version:
        print(version)
        sys.exit(0)

print(fallback)
PY
}

kernel_tarball_url() {
    local version="$1"
    local major="${version%%.*}"

    printf 'https://cdn.kernel.org/pub/linux/kernel/v%s.x/linux-%s.tar.xz\n' "${major}" "${version}"
}

download_kernel_source() {
    local version="$1"
    local source_dir="${KERNEL_CACHE_DIR}/linux-${version}"
    local tarball_url tarball_path extract_dir

    if [[ -f "${source_dir}/Makefile" ]]; then
        log_stderr "复用缓存内核源码: ${source_dir}"
        printf '%s\n' "${source_dir}"
        return 0
    fi

    mkdir -p "${KERNEL_CACHE_DIR}"
    tarball_url="$(kernel_tarball_url "${version}")"
    tarball_path="${KERNEL_CACHE_DIR}/linux-${version}.tar.xz"

    if [[ ! -f "${tarball_path}" ]]; then
        log_stderr "下载 Linux 源码: ${tarball_url}"
        curl --fail --location --retry 3 --retry-delay 1 \
            -o "${tarball_path}" \
            "${tarball_url}"
    else
        log_stderr "复用缓存源码包: ${tarball_path}"
    fi

    extract_dir="$(mktemp -d "${KERNEL_CACHE_DIR}/extract.${version}.XXXXXX")"
    tar -xf "${tarball_path}" -C "${extract_dir}"

    if ! mv "${extract_dir}/linux-${version}" "${source_dir}" 2>/dev/null; then
        rm -rf -- "${extract_dir}"
        [[ -f "${source_dir}/Makefile" ]] || fail "解压 Linux 源码失败: ${tarball_path}"
    else
        rm -rf -- "${extract_dir}"
    fi

    log_stderr "Linux 源码已准备: ${source_dir}"
    printf '%s\n' "${source_dir}"
}

resolve_kernel_source_dir() {
    if [[ -n "${KERNEL_SOURCE}" ]]; then
        [[ -f "${KERNEL_SOURCE}/Makefile" ]] || fail "无效的 Linux 源码目录: ${KERNEL_SOURCE}"
        printf '%s\n' "${KERNEL_SOURCE}"
        return 0
    fi

    download_kernel_source "$(resolve_release_version)"
}

resolve_build_dir() {
    local source_dir="$1"

    if [[ -n "${KERNEL_BUILD_DIR}" ]]; then
        resolve_user_path "${KERNEL_BUILD_DIR}"
        return 0
    fi

    printf '%s/.mimobox-build-%s\n' "${source_dir}" "${TARGET_ARCH}"
}

generate_miniconfig() {
    local config_path="$1"

    cat > "${config_path}" <<'EOF'
# 基于 Firecracker 6.1 guest config 的思路，但直接从 allnoconfig 出发，
# 只保留当前 mimobox guest boot 与串口控制面所需能力。

CONFIG_EXPERT=y
CONFIG_EMBEDDED=y
CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y
CONFIG_LOCALVERSION=""
# CONFIG_LOCALVERSION_AUTO is not set

# x86_64 guest /init 依赖的基本执行环境
CONFIG_64BIT=y
CONFIG_MMU=y
CONFIG_X86_IOPL_IOPERM=y

# 启动路径与时钟
CONFIG_HYPERVISOR_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_KVM_GUEST=y
CONFIG_NO_HZ_IDLE=y
CONFIG_HIGH_RES_TIMERS=y
CONFIG_HZ_100=y

# 单核 guest，减少 bring-up 工作量
# CONFIG_SMP is not set

# 只保留 initramfs 路径，不启用块设备与磁盘文件系统
# CONFIG_BLOCK is not set
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE=""
CONFIG_RD_GZIP=y
# CONFIG_RD_BZIP2 is not set
# CONFIG_RD_LZMA is not set
# CONFIG_RD_XZ is not set
# CONFIG_RD_LZO is not set
# CONFIG_RD_LZ4 is not set
# CONFIG_RD_ZSTD is not set

# 当前 guest init 只需要 /proc /sys /dev /tmp
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_PROC_FS=y
# CONFIG_PROC_KCORE is not set
CONFIG_SYSFS=y
# CONFIG_SYSFS_SYSCALL is not set
CONFIG_TMPFS=y
# CONFIG_TMPFS_POSIX_ACL is not set
# CONFIG_TMPFS_XATTR is not set
# CONFIG_CONFIGFS_FS is not set
# CONFIG_SECURITYFS is not set
# CONFIG_DEBUG_FS is not set

# 仅保留 guest /init 执行 /bin/sh 所需格式支持
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
# CONFIG_COREDUMP is not set
# CONFIG_ELF_CORE is not set

# fork/clone/wait 不是独立 Kconfig 符号，这里保留 guest /init 命令循环
# 需要的进程、信号、定时器与事件通知基础设施。
# CONFIG_SYSVIPC is not set
# CONFIG_POSIX_MQUEUE is not set
# CONFIG_AUDIT is not set
# CONFIG_BPF is not set
# CONFIG_CGROUPS is not set
# CONFIG_NAMESPACES is not set
# CONFIG_KCMP is not set
# CONFIG_CHECKPOINT_RESTORE is not set
# CONFIG_FHANDLE is not set
# CONFIG_AIO is not set
# CONFIG_IO_URING is not set
CONFIG_POSIX_TIMERS=y
CONFIG_FUTEX=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y

# vsock 数据面需要基础网络子系统（AF_VSOCK 依赖）
CONFIG_NET=y
CONFIG_UNIX=y
CONFIG_INET=y
# 避免 driver/net 等不需要的子模块
# CONFIG_NETDEVICES is not set
# CONFIG_WIRELESS is not set
# CONFIG_NETFILTER is not set

# 只保留 ttyS0
CONFIG_PRINTK=y
CONFIG_TTY=y
# CONFIG_VT is not set
# CONFIG_UNIX98_PTYS is not set
# CONFIG_LEGACY_PTYS is not set
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
# CONFIG_SERIAL_8250_PNP is not set
# CONFIG_SERIAL_8250_DMA is not set
# CONFIG_SERIAL_8250_EXTENDED is not set
CONFIG_SERIAL_8250_NR_UARTS=1
CONFIG_SERIAL_8250_RUNTIME_UARTS=1

# 保留 virtio-mmio，方便后续继续挂极简 mmio 设备
CONFIG_VIRTIO=y
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
# CONFIG_VIRTIO_PCI is not set
# CONFIG_VIRTIO_BLK is not set
# CONFIG_VIRTIO_NET is not set
# CONFIG_VIRTIO_CONSOLE is not set
# CONFIG_VIRTIO_BALLOON is not set
# CONFIG_VIRTIO_INPUT is not set
# CONFIG_VIRTIO_PMEM is not set
# CONFIG_VIRTIO_MEM is not set
# CONFIG_VIRTIO_FS is not set
# CONFIG_VIRTIO_VSOCKETS is not set
CONFIG_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_VHOST_VSOCK=y
# CONFIG_HW_RANDOM_VIRTIO is not set

# 切掉 PCI / ACPI 与各类总线外设
# CONFIG_PCI is not set
# CONFIG_ACPI is not set
# CONFIG_EFI is not set
# CONFIG_FW_LOADER is not set
# CONFIG_PNP is not set
# CONFIG_INPUT is not set
# CONFIG_SERIO is not set
# CONFIG_HID is not set
# CONFIG_USB is not set
# CONFIG_SOUND is not set
# CONFIG_DRM is not set
# CONFIG_WLAN is not set
# CONFIG_BT is not set

# 不需要 ext4 / xfs / btrfs / fat / ntfs 等磁盘文件系统
# CONFIG_EXT4_FS is not set
# CONFIG_BTRFS_FS is not set
# CONFIG_XFS_FS is not set
# CONFIG_F2FS_FS is not set
# CONFIG_OVERLAY_FS is not set
# CONFIG_SQUASHFS is not set
# CONFIG_EROFS_FS is not set
# CONFIG_FUSE_FS is not set
# CONFIG_9P_FS is not set
# CONFIG_VFAT_FS is not set
# CONFIG_MSDOS_FS is not set
# CONFIG_NTFS_FS is not set
# CONFIG_NTFS3_FS is not set
# CONFIG_ISO9660_FS is not set
# CONFIG_UDF_FS is not set

# 关闭调试与编译期/运行期强化，优先缩小镜像与减少启动路径
# CONFIG_KALLSYMS is not set
# CONFIG_STACKPROTECTOR is not set
# CONFIG_STACKPROTECTOR_STRONG is not set
# CONFIG_FORTIFY_SOURCE is not set
CONFIG_INIT_STACK_NONE=y
# CONFIG_DEBUG_KERNEL is not set
CONFIG_DEBUG_INFO_NONE=y
# CONFIG_KASAN is not set
# CONFIG_UBSAN is not set
# CONFIG_KCSAN is not set
# CONFIG_KFENCE is not set
# CONFIG_GDB_SCRIPTS is not set
# CONFIG_MAGIC_SYSRQ is not set

# 避免无意义的固件/电源管理初始化
# CONFIG_PM is not set
# CONFIG_HIBERNATION is not set
# CONFIG_CPU_FREQ is not set
# CONFIG_CPU_IDLE is not set
# CONFIG_MICROCODE is not set
# CONFIG_X86_MCE is not set
# CONFIG_RELOCATABLE is not set
# CONFIG_RANDOMIZE_BASE is not set
EOF
}

generate_kernel_config() {
    local source_dir="$1"
    local build_dir="$2"
    local miniconfig_path="$3"
    local make_jobs="$4"

    mkdir -p "${build_dir}"
    generate_miniconfig "${miniconfig_path}"

    log "生成最小化 guest 内核配置"
    make -C "${source_dir}" \
        O="${build_dir}" \
        ARCH="${TARGET_ARCH}" \
        KCONFIG_ALLCONFIG="${miniconfig_path}" \
        allnoconfig

    # 针对比 6.1 更新的稳定版，补一次 olddefconfig，确保新符号走默认值。
    make -C "${source_dir}" \
        O="${build_dir}" \
        ARCH="${TARGET_ARCH}" \
        olddefconfig

    log "最小化配置已生成: ${build_dir}/.config"
    log "构建并发度: ${make_jobs}"
}

build_kernel() {
    local source_dir="$1"
    local build_dir="$2"
    local output_path="$3"
    local make_jobs="$4"
    local cc_bin="$5"

    mkdir -p "$(dirname "${output_path}")"

    log "开始编译未压缩 vmlinux"
    make -C "${source_dir}" \
        O="${build_dir}" \
        ARCH="${TARGET_ARCH}" \
        CC="${cc_bin}" \
        HOSTCC="${HOSTCC:-gcc}" \
        -j"${make_jobs}" \
        vmlinux

    install -m 0644 "${build_dir}/vmlinux" "${output_path}"
    log "vmlinux 已输出: ${output_path}"
    log "最终配置文件: ${build_dir}/.config"
}

main() {
    local output_path source_dir build_dir miniconfig_path make_jobs cc_bin

    parse_args "$@"
    init_logging
    ensure_linux_host

    cc_bin="$(resolve_cc_bin)"
    make_jobs="$(detect_jobs)"
    output_path="$(resolve_repo_path "${OUTPUT}")"

    require_command curl
    require_command tar
    require_command make
    require_command python3
    require_command "${cc_bin}"
    require_command "${HOSTCC:-gcc}"
    require_command bc
    require_command bison
    require_command flex
    require_command perl
    require_command install
    require_command tee

    source_dir="$(resolve_kernel_source_dir)"
    build_dir="$(resolve_build_dir "${source_dir}")"
    miniconfig_path="${build_dir}/mimobox-miniconfig"

    log "目标架构: ${TARGET_ARCH}"
    log "Linux 源码目录: ${source_dir}"
    log "构建目录: ${build_dir}"
    log "输出路径: ${output_path}"
    log "编译器: ${cc_bin}"

    generate_kernel_config "${source_dir}" "${build_dir}" "${miniconfig_path}" "${make_jobs}"
    build_kernel "${source_dir}" "${build_dir}" "${output_path}" "${make_jobs}" "${cc_bin}"
}

main "$@"
