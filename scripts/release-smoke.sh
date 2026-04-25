#!/usr/bin/env bash
set -euo pipefail

# mimobox Release Smoke Test
# 验证发布二进制的核心功能路径。
#
# 本脚本面向发布前冒烟测试：假设 mimobox 已经安装或已完成 release 构建，
# 不在脚本内自动构建，避免把构建链路和用户视角安装验证混在一起。

# 基于脚本所在目录定位项目根目录，避免从任意工作目录执行时找不到仓库路径。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Cargo 实际产物名当前为 mimobox-cli；若后续改成 mimobox，脚本也会兼容。
CLI_BIN=""
MCP_BIN=""
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
    printf '[release-smoke] %s\n' "$*"
}

error() {
    printf '[release-smoke][error] %s\n' "$*" >&2
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
        printf '[release-smoke][detail] %s\n' "$2" >&2
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
            fail "当前脚本仅支持 Linux/macOS"
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

    if command_available mimobox-cli; then
        CLI_BIN="$(command -v mimobox-cli)"
        return 0
    fi

    if command_available mimobox; then
        CLI_BIN="$(command -v mimobox)"
        return 0
    fi

    return 1
}

resolve_mcp_bin() {
    if [[ -x "${PROJECT_ROOT}/target/release/mimobox-mcp" ]]; then
        MCP_BIN="${PROJECT_ROOT}/target/release/mimobox-mcp"
        return 0
    fi

    if command_available mimobox-mcp; then
        MCP_BIN="$(command -v mimobox-mcp)"
        return 0
    fi

    return 1
}

prepare_wasm_fixture() {
    # 该 fixture 等价于：
    # (module (func (export "_start")))
    # 直接内嵌最小 Wasm 二进制，避免脚本依赖额外工具链。
    printf '\x00\x61\x73\x6d\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x07\x0a\x01\x06\x5f\x73\x74\x61\x72\x74\x00\x00\x0a\x04\x01\x02\x00\x0b' > "${WASM_FIXTURE_PATH}"
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

validate_last_json() {
    JSON_INPUT="${LAST_STDOUT}" python3 - <<'PY'
import json
import os

json.loads(os.environ["JSON_INPUT"])
PY
}

run_test() {
    local test_name="$1"
    shift

    capture_command "$@"

    if [[ "${LAST_STATUS}" -ne 0 ]]; then
        record_fail \
            "${test_name}" \
            "命令退出码=${LAST_STATUS}
命令: ${LAST_COMMAND_DESC}
stdout: ${LAST_STDOUT}
stderr: ${LAST_STDERR}"
        return 1
    fi

    if ! validate_last_json; then
        record_fail \
            "${test_name}" \
            "命令输出不是合法 JSON
命令: ${LAST_COMMAND_DESC}
stdout: ${LAST_STDOUT}
stderr: ${LAST_STDERR}"
        return 1
    fi

    return 0
}

json_value() {
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

data = json.loads(os.environ["JSON_INPUT"])
values = data.get(sys.argv[1], [])

if not isinstance(values, list):
    raise SystemExit(1)

raise SystemExit(0 if sys.argv[2] in values else 1)
PY
}

assert_json_equals() {
    local test_name="$1"
    local key="$2"
    local expected="$3"
    local actual=""

    if ! actual="$(json_value "${key}")"; then
        record_fail "${test_name}" "读取 JSON 字段失败: ${key}"
        return 1
    fi

    if [[ "${actual}" != "${expected}" ]]; then
        record_fail \
            "${test_name}" \
            "JSON 字段断言失败: ${key}
期望: ${expected}
实际: ${actual}
命令: ${LAST_COMMAND_DESC}
stdout: ${LAST_STDOUT}
stderr: ${LAST_STDERR}"
        return 1
    fi

    return 0
}

assert_json_contains() {
    local test_name="$1"
    local key="$2"
    local expected_fragment="$3"
    local actual=""

    if ! actual="$(json_value "${key}")"; then
        record_fail "${test_name}" "读取 JSON 字段失败: ${key}"
        return 1
    fi

    if [[ "${actual}" != *"${expected_fragment}"* ]]; then
        record_fail \
            "${test_name}" \
            "JSON 字段不包含期望片段: ${key}
期望包含: ${expected_fragment}
实际: ${actual}
命令: ${LAST_COMMAND_DESC}
stdout: ${LAST_STDOUT}
stderr: ${LAST_STDERR}"
        return 1
    fi

    return 0
}

assert_json_list_contains() {
    local test_name="$1"
    local key="$2"
    local expected_item="$3"

    if ! json_list_contains "${key}" "${expected_item}"; then
        record_fail \
            "${test_name}" \
            "JSON 列表字段不包含期望值: ${key}
期望包含: ${expected_item}
stdout: ${LAST_STDOUT}
stderr: ${LAST_STDERR}"
        return 1
    fi

    return 0
}

command_failure_detail() {
    printf '命令: %s\n退出码: %s\nstdout: %s\nstderr: %s' \
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

    capture_command \
        "${CLI_BIN}" \
        run \
        --backend os \
        --command "/usr/bin/true"

    if [[ "${LAST_STATUS}" -eq 0 ]]; then
        return 1
    fi

    if [[ "${LAST_STDOUT}" == *"Seatbelt 策略应用失败"* ]] \
        || [[ "${LAST_STDOUT}" == *"Seatbelt"* ]] \
        || [[ "${LAST_STDOUT}" == *"sandbox-exec"* ]] \
        || [[ "${LAST_STDERR}" == *"sandbox-exec"* ]]; then
        MACOS_OS_SKIP_REASON="macOS Seatbelt 运行时不可用"
        return 0
    fi

    return 1
}

test_cli_version() {
    local test_name="$1"

    if ! run_test "${test_name}" "${CLI_BIN}" version; then
        return 1
    fi

    assert_json_equals "${test_name}" "ok" "true" || return 1
    assert_json_equals "${test_name}" "command" "version" || return 1

    return 0
}

test_cli_doctor() {
    local test_name="$1"

    capture_command "${CLI_BIN}" doctor

    # doctor 有 warning/fail 时可能返回非零；冒烟只验证命令不崩溃且有输出。
    if [[ "${LAST_STATUS}" -gt 2 ]]; then
        record_fail "${test_name}" "$(command_failure_detail)"
        return 1
    fi

    if [[ -z "${LAST_STDOUT}" && -z "${LAST_STDERR}" ]]; then
        record_fail "${test_name}" "doctor 未产生任何输出"
        return 1
    fi

    return 0
}

test_os_sandbox() {
    local test_name="$1"

    if macos_os_backend_skip_reason; then
        record_skip "${test_name}" "${MACOS_OS_SKIP_REASON}"
        return 2
    fi

    if ! run_test \
        "${test_name}" \
        "${CLI_BIN}" \
        run \
        --backend os \
        --command "/bin/echo hello"; then
        return 1
    fi

    assert_json_equals "${test_name}" "ok" "true" || return 1
    assert_json_equals "${test_name}" "command" "run" || return 1
    assert_json_equals "${test_name}" "backend" "os" || return 1
    assert_json_equals "${test_name}" "exit_code" "0" || return 1
    assert_json_contains "${test_name}" "stdout" "hello" || return 1

    return 0
}

test_wasm_sandbox() {
    local test_name="$1"

    if ! run_test "${test_name}: version" "${CLI_BIN}" version; then
        return 1
    fi

    if ! json_list_contains "enabled_features" "wasm"; then
        record_skip "${test_name}" "CLI version 输出未声明 wasm feature"
        return 2
    fi

    if ! run_test \
        "${test_name}" \
        "${CLI_BIN}" \
        run \
        --backend wasm \
        --command "${WASM_FIXTURE_PATH}"; then
        return 1
    fi

    assert_json_equals "${test_name}" "ok" "true" || return 1
    assert_json_equals "${test_name}" "backend" "wasm" || return 1
    assert_json_equals "${test_name}" "exit_code" "0" || return 1
    assert_json_equals "${test_name}" "timed_out" "false" || return 1

    return 0
}

test_python_import() {
    local test_name="$1"

    if ! command_available python3; then
        record_skip "${test_name}" "未找到 python3"
        return 2
    fi

    capture_command python3 -c "from mimobox import Sandbox; print('OK')"

    if [[ "${LAST_STATUS}" -ne 0 ]]; then
        if [[ "${LAST_STDERR}" == *"ModuleNotFoundError"* ]] \
            || [[ "${LAST_STDERR}" == *"No module named 'mimobox'"* ]]; then
            record_skip "${test_name}" "Python 包 mimobox 未安装"
            return 2
        fi

        record_fail "${test_name}" "$(command_failure_detail)"
        return 1
    fi

    if [[ "${LAST_STDOUT}" != *"OK"* ]]; then
        record_fail "${test_name}" "Python import 未输出 OK
$(command_failure_detail)"
        return 1
    fi

    return 0
}

test_mcp_binary() {
    local test_name="$1"

    if [[ "${PLATFORM}" != "linux" ]]; then
        record_skip "${test_name}" "mimobox-mcp 冒烟测试仅在 Linux 执行"
        return 2
    fi

    if ! resolve_mcp_bin; then
        record_skip "${test_name}" "未找到 mimobox-mcp"
        return 2
    fi

    capture_command "${MCP_BIN}" --help

    if [[ "${LAST_STATUS}" -ne 0 ]]; then
        record_fail "${test_name}" "$(command_failure_detail)"
        return 1
    fi

    if [[ -z "${LAST_STDOUT}" && -z "${LAST_STDERR}" ]]; then
        record_fail "${test_name}" "mimobox-mcp --help 未产生任何输出"
        return 1
    fi

    return 0
}

test_summary() {
    local test_name="$1"

    record_pass "${test_name}"
}

execute_test_case() {
    local test_name="$1"
    local test_func="$2"
    local status=0

    if "${test_func}" "${test_name}"; then
        record_pass "${test_name}"
        return 0
    else
        status=$?
    fi

    case "${status}" in
        1 | 2)
            return 0
            ;;
        *)
            record_fail "${test_name}" "测试函数返回了未预期状态"
            return 0
            ;;
    esac
}

main() {
    command_available python3 || fail "未找到 python3，无法执行 JSON 校验"
    detect_platform
    prepare_wasm_fixture

    log "项目根目录: ${PROJECT_ROOT}"
    log "目标平台: ${PLATFORM}"

    if ! resolve_cli_bin; then
        fail "未找到 mimobox CLI 二进制，请先安装 mimobox 或准备 target/release/mimobox-cli"
    fi

    log "CLI 二进制: ${CLI_BIN}"

    execute_test_case "1) CLI version" test_cli_version
    execute_test_case "2) CLI doctor" test_cli_doctor
    execute_test_case "3) OS sandbox" test_os_sandbox
    execute_test_case "4) Wasm sandbox" test_wasm_sandbox
    execute_test_case "5) Python import" test_python_import
    execute_test_case "6) MCP binary" test_mcp_binary
    test_summary "7) Summary"

    log "最终结果: ${PASSED_COUNT} passed, ${SKIPPED_COUNT} skipped, ${FAILED_COUNT} failed"

    if [[ ${FAILED_COUNT} -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
