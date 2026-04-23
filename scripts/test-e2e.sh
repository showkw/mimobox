#!/usr/bin/env bash
set -euo pipefail

# 基于脚本所在目录定位项目根目录，避免从任意工作目录执行时找不到仓库路径。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Cargo 实际产物名当前为 mimobox-cli；若后续改成 mimobox，脚本也会兼容。
CLI_BIN=""
TMP_DIR="$(mktemp -d)"
WASM_FIXTURE_PATH="${TMP_DIR}/noop.wasm"
DEFAULT_VM_ASSETS_DIR="${HOME}/.mimobox/assets"
VM_ASSETS_DIR="${VM_ASSETS_DIR:-${DEFAULT_VM_ASSETS_DIR}}"
KERNEL_PATH="${VM_ASSETS_DIR}/vmlinux"
ROOTFS_PATH="${VM_ASSETS_DIR}/rootfs.cpio.gz"

PLATFORM=""
BUILD_FEATURES=""
MACOS_OS_SKIP_REASON=""

PASSED_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

LAST_STATUS=0
LAST_STDOUT=""
LAST_STDERR=""
LAST_COMMAND_DESC=""

log() {
    printf '[test-e2e] %s\n' "$*"
}

fail() {
    printf '[test-e2e][error] %s\n' "$*" >&2
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

record_fail() {
    FAILED_COUNT=$((FAILED_COUNT + 1))
    log "FAIL: $1"
    if [[ $# -ge 2 && -n "${2}" ]]; then
        printf '[test-e2e][detail] %s\n' "${2}" >&2
    fi
}

record_skip() {
    SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    log "SKIP: $1"
    if [[ $# -ge 2 && -n "${2}" ]]; then
        printf '[test-e2e][detail] %s\n' "${2}" >&2
    fi
}

command_available() {
    command -v "$1" >/dev/null 2>&1
}

detect_platform() {
    case "$(uname -s)" in
        Linux)
            PLATFORM="linux"
            BUILD_FEATURES="mimobox-cli/wasm,mimobox-cli/kvm"
            ;;
        Darwin)
            PLATFORM="macos"
            BUILD_FEATURES="mimobox-cli/wasm"
            ;;
        *)
            fail "当前脚本仅支持 Linux/macOS"
            ;;
    esac
}

resolve_cli_bin() {
    if [[ -x "${ROOT_DIR}/target/release/mimobox-cli" ]]; then
        CLI_BIN="${ROOT_DIR}/target/release/mimobox-cli"
        return
    fi

    if [[ -x "${ROOT_DIR}/target/release/mimobox" ]]; then
        CLI_BIN="${ROOT_DIR}/target/release/mimobox"
        return
    fi

    fail "未找到 release CLI 二进制，请检查 cargo build 输出"
}

prepare_wasm_fixture() {
    # 该 fixture 等价于：
    # (module (func (export "_start")))
    # 直接内嵌最小 Wasm 二进制，避免脚本依赖额外工具链。
    printf '\x00\x61\x73\x6d\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x07\x0a\x01\x06\x5f\x73\x74\x61\x72\x74\x00\x00\x0a\x04\x01\x02\x00\x0b' > "${WASM_FIXTURE_PATH}"
}

build_release_binary() {
    log "项目根目录: ${ROOT_DIR}"
    log "目标平台: ${PLATFORM}"
    log "启用 feature: ${BUILD_FEATURES}"

    (
        cd "${ROOT_DIR}"
        cargo build --release --features "${BUILD_FEATURES}"
    )

    resolve_cli_bin
    log "CLI 二进制: ${CLI_BIN}"
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

    return "${LAST_STATUS}"
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

    if ! capture_command "$@"; then
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

macos_os_backend_skip_reason() {
    if [[ "${PLATFORM}" != "macos" ]]; then
        return 1
    fi

    if [[ -n "${MACOS_OS_SKIP_REASON}" ]]; then
        return 0
    fi

    if capture_command \
        "${CLI_BIN}" \
        run \
        --backend os \
        --command "/usr/bin/true"; then
        return 1
    fi

    if [[ "${LAST_STDOUT}" == *"Seatbelt 策略应用失败"* ]] \
        || [[ "${LAST_STDOUT}" == *"sandbox-exec"* ]] \
        || [[ "${LAST_STDERR}" == *"sandbox-exec"* ]]; then
        MACOS_OS_SKIP_REASON="macOS Seatbelt 运行时不可用"
        return 0
    fi

    return 1
}

test_version_features() {
    local test_name="$1"

    if ! run_test "${test_name}" "${CLI_BIN}" version; then
        return 1
    fi

    assert_json_equals "${test_name}" "ok" "true" || return 1
    assert_json_equals "${test_name}" "command" "version" || return 1
    assert_json_equals "${test_name}" "target_os" "${PLATFORM}" || return 1
    assert_json_list_contains "${test_name}" "enabled_features" "wasm" || return 1

    if [[ "${PLATFORM}" == "linux" ]]; then
        assert_json_list_contains "${test_name}" "enabled_features" "kvm" || return 1
    fi

    return 0
}

test_os_basic() {
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
    assert_json_equals "${test_name}" "timed_out" "false" || return 1
    assert_json_contains "${test_name}" "stdout" "hello" || return 1

    return 0
}

test_os_exit_code() {
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
        --command "/bin/sh -c 'exit 42'"; then
        return 1
    fi

    # CLI 自身返回 JSON 成功，guest 的退出码在 exit_code 字段中。
    assert_json_equals "${test_name}" "ok" "true" || return 1
    assert_json_equals "${test_name}" "backend" "os" || return 1
    assert_json_equals "${test_name}" "exit_code" "42" || return 1
    assert_json_equals "${test_name}" "timed_out" "false" || return 1

    return 0
}

test_os_timeout() {
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
        --timeout 1 \
        --command "/bin/sleep 5"; then
        return 1
    fi

    assert_json_equals "${test_name}" "ok" "true" || return 1
    assert_json_equals "${test_name}" "backend" "os" || return 1
    assert_json_equals "${test_name}" "timed_out" "true" || return 1
    assert_json_equals "${test_name}" "exit_code" "-9" || return 1

    return 0
}

test_wasm_basic() {
    local test_name="$1"

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

test_kvm_boot() {
    local test_name="$1"

    if [[ "${PLATFORM}" != "linux" ]]; then
        record_skip "${test_name}" "KVM backend 仅在 Linux 上可用"
        return 2
    fi

    if [[ ! -e "/dev/kvm" ]]; then
        record_skip "${test_name}" "缺少 /dev/kvm"
        return 2
    fi

    if [[ ! -f "${KERNEL_PATH}" ]]; then
        record_skip "${test_name}" "缺少内核镜像: ${KERNEL_PATH}"
        return 2
    fi

    if [[ ! -f "${ROOTFS_PATH}" ]]; then
        record_skip "${test_name}" "缺少 rootfs: ${ROOTFS_PATH}"
        return 2
    fi

    if ! run_test \
        "${test_name}" \
        "${CLI_BIN}" \
        run \
        --backend kvm \
        --kernel "${KERNEL_PATH}" \
        --rootfs "${ROOTFS_PATH}" \
        --command "/bin/echo hello"; then
        return 1
    fi

    # 当前 CLI 仅暴露 guest stdout/stderr，不暴露串口 boot banner；
    # 因此这里验证“能启动并执行 echo”这一真实外部行为。
    assert_json_equals "${test_name}" "ok" "true" || return 1
    assert_json_equals "${test_name}" "backend" "kvm" || return 1
    assert_json_equals "${test_name}" "exit_code" "0" || return 1
    assert_json_contains "${test_name}" "stdout" "hello" || return 1

    return 0
}

execute_test_case() {
    local test_name="$1"
    local test_func="$2"
    local status=0

    if "${test_func}" "${test_name}"; then
        status=0
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
    command_available cargo || fail "未找到 cargo"
    command_available python3 || fail "未找到 python3"

    detect_platform
    prepare_wasm_fixture
    build_release_binary

    execute_test_case "test_version_features" test_version_features
    execute_test_case "test_os_basic" test_os_basic
    execute_test_case "test_os_exit_code" test_os_exit_code
    execute_test_case "test_os_timeout" test_os_timeout
    execute_test_case "test_wasm_basic" test_wasm_basic
    execute_test_case "test_kvm_boot" test_kvm_boot

    log "结果: ${PASSED_COUNT} passed, ${FAILED_COUNT} failed, ${SKIPPED_COUNT} skipped"

    if [[ ${FAILED_COUNT} -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
