# error_handling.py — Error handling: demonstrates catching various exception types
#
# mimobox defines an exception hierarchy:
#   SandboxError (base class)
#   ├── SandboxProcessError  — Command exits non-zero or is killed
#   ├── SandboxHttpError     — HTTP proxy request failed or domain not whitelisted
#   └── SandboxLifecycleError — Create/destroy/restore failed

from mimobox import (
    Sandbox,
    SandboxError,
    SandboxProcessError,
    SandboxHttpError,
    SandboxLifecycleError,
)

# 1. Catch SandboxProcessError: command exits with non-zero code
try:
    with Sandbox() as sandbox:
        sandbox.execute("exit 42")
except SandboxProcessError as exc:
    print(f"[SandboxProcessError] {exc}")

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

# 4. Exception hierarchy: all specific exceptions can be caught by SandboxError
try:
    with Sandbox() as sandbox:
        sandbox.execute("exit 1")
except SandboxError as exc:
    print(f"[caught by base class] type={type(exc).__name__}")
