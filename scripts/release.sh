#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

DRY_RUN=false
ASSUME_YES=false
VERSION_INPUT=""
VERSION=""

log() {
    printf '[release] %s\n' "$*"
}

success() {
    printf '%b[release] %s%b\n' "${GREEN}" "$*" "${NC}"
}

warn() {
    printf '%b[release][warn] %s%b\n' "${YELLOW}" "$*" "${NC}" >&2
}

fail() {
    printf '%b[release][error] %s%b\n' "${RED}" "$*" "${NC}" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: scripts/release.sh [--dry-run] [--yes] <version>

Arguments:
  <version>    Release version in v*.*.* or *.*.* format.

Flags:
  --dry-run    Run checks only; skip tag creation, push, workflow monitoring, and verification.
  --yes        Skip the confirmation prompt.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --yes)
                ASSUME_YES=true
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            --*)
                usage >&2
                fail "Unknown flag: $1"
                ;;
            *)
                if [[ -n "${VERSION_INPUT}" ]]; then
                    usage >&2
                    fail "Exactly one version argument is required."
                fi
                VERSION_INPUT="$1"
                shift
                ;;
        esac
    done

    if [[ -z "${VERSION_INPUT}" ]]; then
        usage >&2
        fail "Exactly one version argument is required."
    fi

    if [[ ! "${VERSION_INPUT}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        usage >&2
        fail "Invalid version format: ${VERSION_INPUT}. Expected v*.*.* or *.*.*."
    fi

    if [[ "${VERSION_INPUT}" == v* ]]; then
        VERSION="${VERSION_INPUT}"
    else
        VERSION="v${VERSION_INPUT}"
    fi
}

require_master_branch() {
    local branch
    branch="$(git branch --show-current)"

    if [[ "${branch}" != "master" ]]; then
        fail "Release must be run from master. Current branch: ${branch:-detached HEAD}"
    fi
}

require_clean_worktree() {
    git diff --quiet || fail "Working tree has unstaged changes."
    git diff --cached --quiet || fail "Working tree has staged changes."
}

require_gh() {
    command -v gh >/dev/null 2>&1 || fail "GitHub CLI is not installed or not on PATH."
    gh auth status >/dev/null 2>&1 || fail "GitHub CLI is not authenticated. Run: gh auth login"
}

require_secret() {
    local secret_name="$1"
    local secrets

    secrets="$(gh secret list)"
    grep -q "^${secret_name}[[:space:]]" <<<"${secrets}" || fail "Missing GitHub Secret: ${secret_name}"
}

run_pre_release_checks() {
    log "Checking GitHub CLI authentication"
    require_gh

    log "Checking required GitHub Secrets"
    require_secret "PYPI_API_TOKEN"
    require_secret "CARGO_REGISTRY_TOKEN"

    log "Running workspace tests"
    cargo test --workspace --exclude mimobox-python

    log "Checking Rust formatting"
    cargo fmt --check --all

    log "Running clippy with warnings denied"
    cargo clippy --workspace --exclude mimobox-python -- -D warnings
}

workspace_version() {
    local cargo_toml="${ROOT_DIR}/Cargo.toml"
    local version

    version="$(grep -oE '^version = "[^"]+"' "${cargo_toml}" | head -1 | sed -E 's/^version = "([^"]+)"/\1/')"
    [[ -n "${version}" ]] || fail "Unable to read workspace.package.version from ${cargo_toml}."
    printf '%s\n' "${version}"
}

check_version_consistency() {
    local expected_version="${VERSION#v}"
    local cargo_version
    cargo_version="$(workspace_version)"

    if [[ "${cargo_version}" != "${expected_version}" ]]; then
        fail "Version mismatch. Requested: ${expected_version}; Cargo.toml: ${cargo_version}"
    fi

    success "Version check passed: ${VERSION}"
}

confirm_release() {
    log "Release version: ${VERSION}"
    log "Last 5 commits:"
    git log --oneline -5

    if [[ "${DRY_RUN}" == true ]]; then
        warn "Dry run enabled; confirmation and release actions will be skipped."
        return
    fi

    if [[ "${ASSUME_YES}" == true ]]; then
        warn "Confirmation skipped because --yes was provided."
        return
    fi

    local answer
    read -r -p "Type yes to confirm release: " answer
    if [[ "${answer}" != "yes" ]]; then
        fail "Release cancelled."
    fi
}

create_and_push_tag() {
    log "Creating annotated tag ${VERSION}"
    git tag -a "${VERSION}" -m "Release ${VERSION}"

    log "Pushing tag ${VERSION}"
    git push origin "${VERSION}"
    success "Tag pushed: ${VERSION}"
}

monitor_release_workflow() {
    local run_id

    log "Waiting for release workflow to start"
    sleep 5

    run_id="$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
    [[ -n "${run_id}" && "${run_id}" != "null" ]] || fail "Unable to find a release.yml workflow run."

    log "Watching release workflow run: ${run_id}"
    gh run watch "${run_id}"
    success "Release workflow completed: ${run_id}"
}

verify_crate() {
    local crate="$1"
    local result

    result="$(cargo search "${crate}" 2>/dev/null | head -1 || true)"
    if [[ -z "${result}" ]]; then
        warn "crates.io lookup returned no result for ${crate}."
        return
    fi

    log "crates.io ${crate}: ${result}"
}

verify_release() {
    local crates=(
        mimobox-core
        mimobox-os
        mimobox-wasm
        mimobox-vm
        mimobox-sdk
        mimobox-mcp
    )
    local pypi_result

    log "Checking GitHub Release ${VERSION}"
    gh release view "${VERSION}" >/dev/null
    success "GitHub Release exists: ${VERSION}"

    log "Waiting 60 seconds for crates.io index propagation"
    sleep 60

    for crate in "${crates[@]}"; do
        verify_crate "${crate}"
    done

    pypi_result="$(pip index versions mimobox 2>/dev/null | head -1 || true)"
    if [[ -z "${pypi_result}" ]]; then
        warn "PyPI lookup returned no result for mimobox."
    else
        log "PyPI mimobox: ${pypi_result}"
    fi
}

print_summary() {
    local crates=(
        mimobox-core
        mimobox-os
        mimobox-wasm
        mimobox-vm
        mimobox-sdk
        mimobox-mcp
    )

    if [[ "${DRY_RUN}" == true ]]; then
        success "Dry run completed successfully for ${VERSION}. No release was created."
        return
    fi

    success "Release completed: ${VERSION}"
    log "GitHub Release: https://github.com/showkw/mimobox/releases/tag/${VERSION}"

    for crate in "${crates[@]}"; do
        log "crates.io ${crate}: https://crates.io/crates/${crate}"
    done

    log "PyPI mimobox: https://pypi.org/project/mimobox/"
}

main() {
    parse_args "$@"

    cd "${ROOT_DIR}"
    log "Repository root: ${ROOT_DIR}"
    log "Release mode: $([[ "${DRY_RUN}" == true ]] && printf 'dry-run' || printf 'live')"

    require_master_branch
    require_clean_worktree
    run_pre_release_checks
    check_version_consistency
    confirm_release

    if [[ "${DRY_RUN}" == false ]]; then
        create_and_push_tag
        monitor_release_workflow
        verify_release
    fi

    print_summary
}

main "$@"
