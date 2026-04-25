#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CLI_BIN=""
TMP_DIR="$(mktemp -d)"
WASM_FIXTURE_PATH="${TMP_DIR}/noop.wasm"
PLATFORM=""
MACOS_OS_SKIP_REASON=""

PASSED_COUNT=0
SKIPPED_COUNT=0
FAILED_COUNT=0

LAST_STATUS=0
LAST_STDOUT=""
LAST_STDERR=""
LAST_COMMAND_DESC=""

log() {
    printf '[quickstart] %s\n' "$*"
}

error() {
    printf '[quickstart][error] %s\n' "$*" >&2
}

fail() {
    error "$*"
    exit 1
}

cleanup() {
    rm -rf -- "${TMP_DIR}"
}

trap cleanup EXIT

record_pass() {
    PASSED_COUNT=$((PASSED_COUNT + 1))
    log "PASS: $1"
}

record_skip() {
    SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    log "SKIP: $1"

    if [[ $# -ge 2 && -n "$2" ]]; then
        log "DETAIL: $2"
    fi
}

record_fail() {
    FAILED_COUNT=$((FAILED_COUNT + 1))
    log "FAIL: $1"

    if [[ $# -ge 2 && -n "$2" ]]; then
        printf '[quickstart][detail] %s\n' "$2" >&2
    fi
}

command_available() {
    command -v "$1" >/dev/null 2>&1
}

detect_platform() {
    case "$(uname -s)" in
        Linux)
            PLATFORM="linux"
            ;;
        Darwin)
            PLATFORM="macos"
            ;;
        *)
            fail "This demo only supports Linux and macOS."
            ;;
    esac
}

resolve_cli_bin() {
    if [[ -x "${PROJECT_ROOT}/target/release/mimobox-cli" ]]; then
        CLI_BIN="${PROJECT_ROOT}/target/release/mimobox-cli"
        return 0
    fi

    if [[ -x "${PROJECT_ROOT}/target/release/mimobox" ]]; then
        CLI_BIN="${PROJECT_ROOT}/target/release/mimobox"
        return 0
    fi

    return 1
}

prepare_wasm_fixture() {
    # Equivalent WAT: (module (func (export "_start")))
    # Keep the fixture embedded so the demo has no extra Wasm toolchain dependency.
    printf '\x00\x61\x73\x6d\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x07\x0a\x01\x06\x5f\x73\x74\x61\x72\x74\x00\x00\x0a\x04\x01\x02\x00\x0b' > "${WASM_FIXTURE_PATH}"
}

build_cli_if_needed() {
    if resolve_cli_bin; then
        log "Using existing CLI binary: ${CLI_BIN}"
        return 0
    fi

    command_available cargo || fail "Missing required command: cargo"

    log "Building mimobox CLI with wasm feature..."
    (
        cd "${PROJECT_ROOT}"
        cargo build -p mimobox-cli --release --features mimobox-cli/wasm
    )

    resolve_cli_bin || fail "Release CLI binary was not found after build."
    log "Built CLI binary: ${CLI_BIN}"
}

capture_command() {
    local stdout_file="${TMP_DIR}/command.stdout"
    local stderr_file="${TMP_DIR}/command.stderr"

    LAST_COMMAND_DESC="$(printf '%q ' "$@")"
    LAST_COMMAND_DESC="${LAST_COMMAND_DESC% }"

    set +e
    "$@" >"${stdout_file}" 2>"${stderr_file}"
    LAST_STATUS=$?
    set -e

    LAST_STDOUT="$(<"${stdout_file}")"
    LAST_STDERR="$(<"${stderr_file}")"

    return 0
}

validate_json_text() {
    JSON_INPUT="$1" python3 - <<'PY'
import json
import os

json.loads(os.environ["JSON_INPUT"])
PY
}

run_cli_json() {
    capture_command "${CLI_BIN}" "$@"

    if ! validate_json_text "${LAST_STDOUT}"; then
        return 1
    fi

    return 0
}

json_get() {
    local key="$1"

    JSON_INPUT="${LAST_STDOUT}" python3 - "$key" <<'PY'
import json
import os
import sys

value = json.loads(os.environ["JSON_INPUT"]).get(sys.argv[1])

if value is None:
    print("null")
elif isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, list):
    print("\n".join(str(item) for item in value))
else:
    print(value)
PY
}

json_list_contains() {
    local key="$1"
    local expected="$2"

    JSON_INPUT="${LAST_STDOUT}" python3 - "$key" "$expected" <<'PY'
import json
import os
import sys

values = json.loads(os.environ["JSON_INPUT"]).get(sys.argv[1], [])

if not isinstance(values, list):
    raise SystemExit(1)

raise SystemExit(0 if sys.argv[2] in values else 1)
PY
}

assert_json_equals() {
    local demo_name="$1"
    local key="$2"
    local expected="$3"
    local actual=""

    if ! actual="$(json_get "${key}")"; then
        record_fail "${demo_name}" "Failed to read JSON field: ${key}"
        return 1
    fi

    if [[ "${actual}" != "${expected}" ]]; then
        record_fail \
            "${demo_name}" \
            "JSON assertion failed for '${key}'.\nExpected: ${expected}\nActual: ${actual}\nCommand: ${LAST_COMMAND_DESC}\nstdout: ${LAST_STDOUT}\nstderr: ${LAST_STDERR}"
        return 1
    fi

    return 0
}

assert_json_list_contains() {
    local demo_name="$1"
    local key="$2"
    local expected="$3"

    if ! json_list_contains "${key}" "${expected}"; then
        record_fail \
            "${demo_name}" \
            "JSON list '${key}' did not contain '${expected}'.\nstdout: ${LAST_STDOUT}\nstderr: ${LAST_STDERR}"
        return 1
    fi

    return 0
}

command_failure_detail() {
    printf 'Command: %s\nCLI status: %s\nstdout: %s\nstderr: %s' \
        "${LAST_COMMAND_DESC}" \
        "${LAST_STATUS}" \
        "${LAST_STDOUT}" \
        "${LAST_STDERR}"
}

macos_os_backend_skip_reason() {
    if [[ "${PLATFORM}" != "macos" ]]; then
        return 1
    fi

    if [[ -n "${MACOS_OS_SKIP_REASON}" ]]; then
        return 0
    fi

    run_cli_json run --backend os --command "/usr/bin/true" || true

    if [[ "${LAST_STDOUT}" == *"Seatbelt"* ]] \
        || [[ "${LAST_STDOUT}" == *"sandbox-exec"* ]] \
        || [[ "${LAST_STDERR}" == *"sandbox-exec"* ]]; then
        MACOS_OS_SKIP_REASON="macOS Seatbelt runtime is unavailable."
        return 0
    fi

    return 1
}

demo_os_auto_routing() {
    local demo_name="1) OS auto-routing"

    if macos_os_backend_skip_reason; then
        record_skip "${demo_name}" "${MACOS_OS_SKIP_REASON}"
        return 0
    fi

    if ! run_cli_json run --backend auto --command "/bin/echo mimobox-auto"; then
        record_fail "${demo_name}" "$(command_failure_detail)"
        return 0
    fi

    assert_json_equals "${demo_name}" "ok" "true" || return 0
    assert_json_equals "${demo_name}" "command" "run" || return 0
    assert_json_equals "${demo_name}" "requested_backend" "auto" || return 0
    assert_json_equals "${demo_name}" "backend" "os" || return 0
    assert_json_equals "${demo_name}" "exit_code" "0" || return 0

    record_pass "${demo_name}"
}

demo_wasm_sandbox() {
    local demo_name="2) Wasm sandbox"

    if ! run_cli_json version; then
        record_fail "${demo_name}" "$(command_failure_detail)"
        return 0
    fi

    if ! json_list_contains "enabled_features" "wasm"; then
        record_skip "${demo_name}" "The CLI version output does not list the wasm feature."
        return 0
    fi

    if ! run_cli_json run --backend wasm --command "${WASM_FIXTURE_PATH}"; then
        record_fail "${demo_name}" "$(command_failure_detail)"
        return 0
    fi

    assert_json_equals "${demo_name}" "ok" "true" || return 0
    assert_json_equals "${demo_name}" "backend" "wasm" || return 0
    assert_json_equals "${demo_name}" "exit_code" "0" || return 0
    assert_json_equals "${demo_name}" "timed_out" "false" || return 0

    record_pass "${demo_name}"
}

demo_security_block() {
    local demo_name="3) Security block"

    if macos_os_backend_skip_reason; then
        record_skip "${demo_name}" "${MACOS_OS_SKIP_REASON}"
        return 0
    fi

    if ! run_cli_json \
        run \
        --backend os \
        --allow-fork \
        --command "/bin/sh -c 'echo blocked > /usr/local/mimobox_quickstart_blocked'"; then
        record_fail "${demo_name}" "$(command_failure_detail)"
        return 0
    fi

    assert_json_equals "${demo_name}" "ok" "true" || return 0
    assert_json_equals "${demo_name}" "backend" "os" || return 0

    local exit_code=""
    if ! exit_code="$(json_get "exit_code")"; then
        record_fail "${demo_name}" "Failed to read JSON field: exit_code"
        return 0
    fi

    if [[ "${exit_code}" == "0" || "${exit_code}" == "null" ]]; then
        record_fail \
            "${demo_name}" \
            "Expected a non-zero exit_code when writing to /usr/local/.\nstdout: ${LAST_STDOUT}\nstderr: ${LAST_STDERR}"
        return 0
    fi

    record_pass "${demo_name}"
}

demo_summary() {
    local demo_name="4) Summary"

    log "Summary: ${PASSED_COUNT} passed, ${SKIPPED_COUNT} skipped, ${FAILED_COUNT} failed"
    record_pass "${demo_name}"
}

main() {
    command_available python3 || fail "Missing required command: python3"
    detect_platform
    prepare_wasm_fixture

    log "Project root: ${PROJECT_ROOT}"
    log "Platform: ${PLATFORM}"
    build_cli_if_needed

    demo_os_auto_routing
    demo_wasm_sandbox
    demo_security_block
    demo_summary

    log "Final result: ${PASSED_COUNT} passed, ${SKIPPED_COUNT} skipped, ${FAILED_COUNT} failed"

    if [[ ${FAILED_COUNT} -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
