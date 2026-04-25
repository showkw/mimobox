# error_handling.py — 错误处理：演示各类异常的捕获
#
# mimobox 定义了异常层级：
#   SandboxError (基类)
#   ├── SandboxProcessError  — 命令非零退出或被 kill
#   ├── SandboxHttpError     — HTTP 代理请求失败或域名未白名单
#   └── SandboxLifecycleError — 创建/销毁/恢复失败

from mimobox import (
    Sandbox,
    SandboxError,
    SandboxProcessError,
    SandboxHttpError,
    SandboxLifecycleError,
)

# 1. 捕获 SandboxProcessError：命令以非零退出码结束
try:
    with Sandbox() as sandbox:
        sandbox.execute("exit 42")
except SandboxProcessError as exc:
    print(f"[SandboxProcessError] {exc}")

# 2. 捕获 SandboxHttpError：请求未白名单的域名
try:
    with Sandbox(isolation="microvm", allowed_http_domains=[]) as sandbox:
        sandbox.http_request("GET", "https://example.com/")
except SandboxHttpError as exc:
    print(f"[SandboxHttpError] {exc}")

# 3. 捕获基类 SandboxError：超时场景
try:
    with Sandbox() as sandbox:
        sandbox.execute("sleep 999", timeout=0.5)
except SandboxError as exc:
    print(f"[SandboxError/Timeout] {exc}")

# 4. 异常层级：所有特定异常都可以被 SandboxError 捕获
try:
    with Sandbox() as sandbox:
        sandbox.execute("exit 1")
except SandboxError as exc:
    print(f"[caught by base class] type={type(exc).__name__}")
