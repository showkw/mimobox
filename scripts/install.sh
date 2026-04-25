#!/usr/bin/env bash
set -euo pipefail

# mimobox CLI 安装脚本：从 GitHub Release 下载当前平台对应的二进制。

REPO="showkw/mimobox"
VERSION="latest"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="mimobox"
TMP_FILE="${TMPDIR:-/tmp}/mimobox-install.$$"

COLOR_GREEN=""
COLOR_RED=""
COLOR_YELLOW=""
COLOR_RESET=""

setup_colors() {
  if [ -t 1 ] && [ "${TERM:-}" != "dumb" ]; then
    COLOR_GREEN='\033[0;32m'
    COLOR_RED='\033[0;31m'
    COLOR_YELLOW='\033[0;33m'
    COLOR_RESET='\033[0m'
  fi
}

info() {
  printf '%s\n' "$*"
}

success() {
  printf '%b%s%b\n' "$COLOR_GREEN" "$*" "$COLOR_RESET"
}

warn() {
  printf '%b%s%b\n' "$COLOR_YELLOW" "$*" "$COLOR_RESET" >&2
}

error() {
  printf '%b错误：%s%b\n' "$COLOR_RED" "$*" "$COLOR_RESET" >&2
}

die() {
  error "$*"
  exit 1
}

cleanup() {
  rm -f "$TMP_FILE"
}

usage() {
  cat <<'EOF'
用法：bash scripts/install.sh [选项]

从 GitHub Release 下载并安装 mimobox CLI。

选项：
  --help              显示帮助信息
  --version VERSION   安装指定版本，而不是 latest

环境变量：
  INSTALL_DIR         安装目录，默认 /usr/local/bin

示例：
  bash scripts/install.sh
  INSTALL_DIR=/opt/bin bash scripts/install.sh
  bash scripts/install.sh --version v0.1.0
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help)
        usage
        exit 0
        ;;
      --version)
        [ "$#" -ge 2 ] || die "--version 需要提供版本号"
        VERSION="$2"
        shift 2
        ;;
      *)
        die "未知参数：$1。使用 --help 查看用法"
        ;;
    esac
  done
}

detect_platform() {
  os_name="$(uname -s)"
  arch_name="$(uname -m)"

  case "$os_name" in
    Darwin)
      os="macOS"
      ;;
    Linux)
      os="Linux"
      ;;
    *)
      die "不支持的操作系统：$os_name"
      ;;
  esac

  case "$arch_name" in
    x86_64)
      arch="x86_64"
      ;;
    aarch64|arm64)
      arch="aarch64"
      ;;
    *)
      die "不支持的 CPU 架构：$arch_name"
      ;;
  esac

  case "$os:$arch" in
    Linux:x86_64)
      TARGET="x86_64-unknown-linux-musl"
      ;;
    macOS:x86_64)
      TARGET="x86_64-apple-darwin"
      ;;
    macOS:aarch64)
      TARGET="aarch64-apple-darwin"
      ;;
    *)
      die "不支持的平台组合：$os / $arch"
      ;;
  esac
}

build_url() {
  if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/mimobox-cli-$TARGET"
  else
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/mimobox-cli-$TARGET"
  fi
}

download() {
  info "下载 mimobox CLI：$DOWNLOAD_URL"

  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$DOWNLOAD_URL" -o "$TMP_FILE" || die "下载失败：$DOWNLOAD_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$TMP_FILE" "$DOWNLOAD_URL" || die "下载失败：$DOWNLOAD_URL"
  else
    die "需要 curl 或 wget 才能下载 mimobox CLI"
  fi

  chmod +x "$TMP_FILE"
}

ensure_install_dir() {
  if [ -d "$INSTALL_DIR" ]; then
    return 0
  fi

  if mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    return 0
  fi

  warn "安装目录不存在且当前用户无法创建：$INSTALL_DIR，将尝试使用 sudo"
  command -v sudo >/dev/null 2>&1 || die "需要 sudo 创建安装目录：$INSTALL_DIR"
  sudo mkdir -p "$INSTALL_DIR"
}

install_binary() {
  DEST="$INSTALL_DIR/$BIN_NAME"
  ensure_install_dir

  if [ -e "$DEST" ]; then
    warn "检测到已有安装，将覆盖：$DEST"
  fi

  if [ -w "$INSTALL_DIR" ]; then
    cp "$TMP_FILE" "$DEST"
    chmod +x "$DEST"
  else
    warn "目标目录不可写，需要 sudo 安装到：$DEST"
    command -v sudo >/dev/null 2>&1 || die "目标目录不可写且未找到 sudo：$INSTALL_DIR"
    sudo cp "$TMP_FILE" "$DEST"
    sudo chmod +x "$DEST"
  fi
}

verify() {
  if version_output="$($DEST --version 2>&1)"; then
    success "安装成功：$DEST"
    success "版本信息：$version_output"
    return 0
  fi

  if version_output="$($DEST version 2>&1)"; then
    success "安装成功：$DEST"
    success "版本信息：$version_output"
    return 0
  fi

  die "安装后验证失败：无法执行 '$DEST --version' 或 '$DEST version'"
}

main() {
  setup_colors
  trap cleanup EXIT INT TERM
  parse_args "$@"
  detect_platform
  build_url

  info "目标平台：$TARGET"
  info "安装目录：$INSTALL_DIR"

  download
  install_binary
  verify
}

main "$@"
