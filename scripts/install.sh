#!/usr/bin/env bash
set -euo pipefail

# MimoBox CLI installer: downloads the platform-appropriate binary from GitHub Releases.

REPO="showkw/mimobox"
VERSION="latest"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="mimobox"
WITH_MCP=""
TMP_FILE="${TMPDIR:-/tmp}/mimobox-install.$$"
TMP_CHECKSUM="${TMPDIR:-/tmp}/mimobox-install.$$.sha256"

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
  rm -f "$TMP_FILE" "$TMP_CHECKSUM" "${TMPDIR:-/tmp}/mimobox-mcp-install.$$"
}

usage() {
  cat <<'EOF'
Usage: bash scripts/install.sh [options]

Download and install mimobox CLI from GitHub Releases.

Options:
  --help              Show this help message
  --version VERSION   Install a specific version instead of latest
  --with-mcp          Also install mimobox-mcp binary

Environment variables:
  INSTALL_DIR         Installation directory (default: /usr/local/bin)

Examples:
  bash scripts/install.sh
  INSTALL_DIR=/opt/bin bash scripts/install.sh
  bash scripts/install.sh --version v0.1.0
  bash scripts/install.sh --with-mcp
  bash scripts/install.sh --version v0.1.0 --with-mcp
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
      --with-mcp)
        WITH_MCP=1
        shift
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
    Linux:aarch64)
      TARGET="aarch64-unknown-linux-musl"
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
  checksum_url="$DOWNLOAD_URL.sha256"

  if command -v curl >/dev/null 2>&1; then
    http_code=$(curl -fSL -w '%{http_code}' -o "$TMP_FILE" "$DOWNLOAD_URL" 2>/dev/null) || true
    if [ "$http_code" = "404" ] || [ "$http_code" = "000" ]; then
      die "No binary available for $TARGET. Pre-built binaries may not be available for this platform. See: https://github.com/$REPO/releases"
    fi
    curl -fSL "$checksum_url" -o "$TMP_CHECKSUM" || die "Download failed: $checksum_url"
  elif command -v wget >/dev/null 2>&1; then
    if ! wget -O "$TMP_FILE" "$DOWNLOAD_URL" 2>/dev/null; then
      die "No binary available for $TARGET. Pre-built binaries may not be available for this platform. See: https://github.com/$REPO/releases"
    fi
    wget -O "$TMP_CHECKSUM" "$checksum_url" || die "Download failed: $checksum_url"
  else
    die "curl or wget is required to download mimobox CLI"
  fi

  chmod +x "$TMP_FILE"
}

verify_checksum() {
  [ -s "$TMP_CHECKSUM" ] || die "Checksum file is empty: $TMP_CHECKSUM"
  expected_hash=""
  read -r expected_hash _ < "$TMP_CHECKSUM" || true
  [ -n "${expected_hash:-}" ] || die "Checksum file does not contain a hash: $TMP_CHECKSUM"

  if command -v sha256sum >/dev/null 2>&1; then
    actual_hash="$(sha256sum "$TMP_FILE")" || die "Failed to calculate checksum with sha256sum"
    actual_hash="${actual_hash%% *}"
  elif command -v shasum >/dev/null 2>&1; then
    actual_hash="$(shasum -a 256 "$TMP_FILE")" || die "Failed to calculate checksum with shasum"
    actual_hash="${actual_hash%% *}"
  elif command -v openssl >/dev/null 2>&1; then
    actual_hash="$(openssl dgst -sha256 "$TMP_FILE")" || die "Failed to calculate checksum with openssl"
    actual_hash="${actual_hash##* }"
  else
    die "sha256sum, shasum, or openssl is required to verify checksum"
  fi

  if [ "$expected_hash" != "$actual_hash" ]; then
    error "Expected checksum: $expected_hash"
    error "Actual checksum:   $actual_hash"
    die "Checksum verification failed"
  fi

  success "Checksum verified"
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

install_mcp() {
  MCP_BIN_NAME="mimobox-mcp"
  MCP_TMP_FILE="${TMPDIR:-/tmp}/mimobox-mcp-install.$$"

  if [ "$VERSION" = "latest" ]; then
    MCP_DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/mimobox-mcp-$TARGET"
  else
    MCP_DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/mimobox-mcp-$TARGET"
  fi

  info "Downloading mimobox-mcp: $MCP_DOWNLOAD_URL"

  if command -v curl >/dev/null 2>&1; then
    http_code=$(curl -fSL -w '%{http_code}' -o "$MCP_TMP_FILE" "$MCP_DOWNLOAD_URL" 2>/dev/null) || true
    if [ "$http_code" = "404" ] || [ "$http_code" = "000" ]; then
      warn "mimobox-mcp binary not available for $TARGET. You can download it manually from GitHub Releases."
      return 0
    elif [ "$http_code" != "200" ]; then
      warn "Failed to download mimobox-mcp for $TARGET. You can download it manually from GitHub Releases."
      rm -f "$MCP_TMP_FILE"
      return 0
    fi
  elif command -v wget >/dev/null 2>&1; then
    if ! wget -O "$MCP_TMP_FILE" "$MCP_DOWNLOAD_URL" 2>/dev/null; then
      warn "mimobox-mcp binary not available for $TARGET. You can download it manually from GitHub Releases."
      return 0
    fi
  else
    warn "curl or wget is required to download mimobox-mcp. Skipping MCP installation."
    return 0
  fi

  if [ ! -s "$MCP_TMP_FILE" ]; then
    warn "Downloaded mimobox-mcp file is empty. Skipping MCP installation."
    rm -f "$MCP_TMP_FILE"
    return 0
  fi

  MCP_DEST="$INSTALL_DIR/$MCP_BIN_NAME"
  chmod +x "$MCP_TMP_FILE"

  if [ -w "$INSTALL_DIR" ]; then
    cp "$MCP_TMP_FILE" "$MCP_DEST"
  else
    command -v sudo >/dev/null 2>&1 || { warn "Cannot install mimobox-mcp: target directory not writable and sudo not found"; rm -f "$MCP_TMP_FILE"; return 0; }
    sudo cp "$MCP_TMP_FILE" "$MCP_DEST"
    sudo chmod +x "$MCP_DEST"
  fi

  rm -f "$MCP_TMP_FILE"
  success "mimobox-mcp installed to $MCP_DEST"
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
  verify_checksum
  install_binary
  verify

  # Install mimobox-mcp if requested
  if [ -n "${WITH_MCP:-}" ]; then
    install_mcp
  fi
}

main "$@"
