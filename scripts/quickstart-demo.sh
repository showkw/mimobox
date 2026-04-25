#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

info() {
    printf '%b[quickstart]%b %s\n' "$YELLOW" "$RESET" "$*"
}

success() {
    printf '%b[quickstart]%b %s\n' "$GREEN" "$RESET" "$*"
}

error() {
    printf '%b[quickstart]%b %s\n' "$RED" "$RESET" "$*" >&2
}

require_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        error "Missing required command: $command_name"
        error "Install Rust from https://rustup.rs/ and retry."
        exit 1
    fi
}

main() {
    local total_start=$SECONDS
    local build_start
    local run_start
    local output
    local exit_code=0

    cd "$PROJECT_ROOT"

    info "Project root: $PROJECT_ROOT"
    info "Checking Rust toolchain..."
    require_command rustc
    require_command cargo
    success "Rust toolchain found: $(rustc --version), $(cargo --version)"

    info "Building mimobox CLI release binary with OS backend only..."
    build_start=$SECONDS
    cargo build -p mimobox-cli --release
    success "Build completed in $((SECONDS - build_start))s"

    info "Running sandbox demo command..."
    run_start=$SECONDS
    set +e
    output=$(target/release/mimobox run --command "/bin/echo 'Hello from mimobox sandbox!'" 2>&1)
    exit_code=$?
    set -e

    printf '\n%s\n' "----- stdout/stderr -----"
    printf '%s\n' "$output"
    printf '%s\n\n' "-------------------------"

    info "Exit code: $exit_code"
    info "Command elapsed: $((SECONDS - run_start))s"
    info "Total elapsed: $((SECONDS - total_start))s (target: <=60s)"

    if [[ "$exit_code" -eq 0 ]]; then
        success "Quick start demo completed successfully."
    else
        error "Quick start demo failed."
    fi

    return "$exit_code"
}

main "$@"
