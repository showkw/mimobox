# error_handling.py — Error handling: demonstrates catching various exception types
#
# mimobox defines an exception hierarchy:
#   SandboxError (base class)
#   ├── SandboxProcessError  — Backend-level process failures, such as killed commands
#   ├── SandboxHttpError     — HTTP proxy request failed or domain not whitelisted
#   └── SandboxLifecycleError — Create/destroy/restore failed

from mimobox import (
    Sandbox,
    SandboxError,
    SandboxHttpError,
    SandboxLifecycleError,
)

# 1. Non-zero process exit is returned as ExecuteResult; check exit_code explicitly.
with Sandbox() as sandbox:
    result = sandbox.execute("false")
    if result.exit_code != 0:
        print(f"[non-zero exit] exit_code={result.exit_code}")

# 2. Catch SandboxHttpError: request to non-whitelisted domain
try:
    with Sandbox(isolation="microvm", allowed_http_domains=[]) as sandbox:
        sandbox.http_request("GET", "https://example.com/")
except SandboxHttpError as exc:
    print(f"[SandboxHttpError] {exc}")

# 3. Catch base class SandboxError: timeout scenario
try:
    with Sandbox() as sandbox:
        sandbox.execute("sleep 999", timeout=0.5)
except SandboxError as exc:
    print(f"[SandboxError/Timeout] {exc}")

# 4. Exception hierarchy: all mimobox-specific exceptions can be caught by SandboxError
try:
    with Sandbox(isolation="microvm", allowed_http_domains=[]) as sandbox:
        sandbox.http_request("GET", "https://example.com/")
except SandboxError as exc:
    print(f"[caught by base class] type={type(exc).__name__}")
