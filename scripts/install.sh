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
  printf '%bError: %s%b\n' "$COLOR_RED" "$*" "$COLOR_RESET" >&2
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
Usage: bash scripts/install.sh [options]

Download and install mimobox CLI from GitHub Releases.

Options:
  --help              Show this help message
  --version VERSION   Install a specific version instead of latest

Environment variables:
  INSTALL_DIR         Installation directory (default: /usr/local/bin)

Examples:
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
        [ "$#" -ge 2 ] || die "--version requires a version argument"
        VERSION="$2"
        shift 2
        ;;
      *)
        die "Unknown argument: $1. Use --help for usage"
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
      die "Unsupported OS: $os_name"
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
      die "Unsupported CPU architecture: $arch_name"
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
      die "Unsupported platform combination: $os / $arch"
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
  info "Downloading mimobox CLI: $DOWNLOAD_URL"

  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$DOWNLOAD_URL" -o "$TMP_FILE" || die "Download failed: $DOWNLOAD_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$TMP_FILE" "$DOWNLOAD_URL" || die "Download failed: $DOWNLOAD_URL"
  else
    die "curl or wget is required to download mimobox CLI"
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

  warn "Install directory does not exist and cannot be created: $INSTALL_DIR. Trying with sudo"
  command -v sudo >/dev/null 2>&1 || die "sudo is required to create install directory: $INSTALL_DIR"
  sudo mkdir -p "$INSTALL_DIR"
}

install_binary() {
  DEST="$INSTALL_DIR/$BIN_NAME"
  ensure_install_dir

  if [ -e "$DEST" ]; then
    warn "Existing installation detected, will overwrite: $DEST"
  fi

  if [ -w "$INSTALL_DIR" ]; then
    cp "$TMP_FILE" "$DEST"
    chmod +x "$DEST"
  else
    warn "Target directory is not writable. Trying with sudo: $DEST"
    command -v sudo >/dev/null 2>&1 || die "Target directory is not writable and sudo not found: $INSTALL_DIR"
    sudo cp "$TMP_FILE" "$DEST"
    sudo chmod +x "$DEST"
  fi
}

verify() {
  if version_output="$($DEST --version 2>&1)"; then
    success "Installed: $DEST"
    success "Version: $version_output"
    info ''
    info 'Next steps:'
    info "  Run 'mimobox doctor' to check supported backends"
    info "  Run 'mimobox run --backend auto --command \"/bin/echo hello\"' to get started"
    return 0
  fi

  if version_output="$($DEST version 2>&1)"; then
    success "Installed: $DEST"
    success "Version: $version_output"
    info ''
    info 'Next steps:'
    info "  Run 'mimobox doctor' to check supported backends"
    info "  Run 'mimobox run --backend auto --command \"/bin/echo hello\"' to get started"
    return 0
  fi

  die "Post-install verification failed: could not run '$DEST --version' or '$DEST version'"
}

main() {
  setup_colors
  trap cleanup EXIT INT TERM
  parse_args "$@"
  detect_platform
  build_url

  info "Target platform: $TARGET"
  info "Install directory: $INSTALL_DIR"

  download
  install_binary
  verify
}

main "$@"
