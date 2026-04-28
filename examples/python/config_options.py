# config_options.py — 配置选项：展示各种 Sandbox 初始化参数
#
# Python SDK 通过 Sandbox 构造函数暴露以下配置：
#   - isolation: 隔离级别（auto / os / wasm / microvm）
#   - allowed_http_domains: HTTP 代理域名白名单
#   - memory_limit_mb: 内存限制（MiB），默认 512
#   - timeout_secs: 命令超时（秒），默认 30
#   - max_processes: 最大进程数（仅 Linux cgroup v2）
#   - trust_level: 信任级别（trusted / semi_trusted / untrusted）
#   - network: 网络策略（deny_all / allow_domains / allow_all）

from mimobox import Sandbox

# 1. 默认配置：auto 隔离级别，自动选择最优后端
with Sandbox() as sandbox:
    result = sandbox.execute("echo 'auto isolation'")
    print(f"auto: {result.stdout.strip()}")

# 2. 显式指定 OS 级隔离（Landlock + Seccomp，仅 Linux）
with Sandbox(isolation="os") as sandbox:
    result = sandbox.execute("echo 'OS-level isolation'")
    print(f"os:   {result.stdout.strip()}")

# 3. 显式指定 Wasm 隔离（Wasmtime 沙箱）
with Sandbox(isolation="wasm") as sandbox:
    result = sandbox.execute("echo 'Wasm isolation'")
    print(f"wasm: {result.stdout.strip()}")

# 4. 显式指定 microVM 隔离（KVM，最强隔离）
with Sandbox(isolation="microvm") as sandbox:
    result = sandbox.execute("echo 'microVM isolation'")
    print(f"vm:   {result.stdout.strip()}")

# 5. 带域名白名单：允许沙箱内发起 HTTP 请求
with Sandbox(
    isolation="microvm",
    allowed_http_domains=["api.github.com", "*.openai.com"],
) as sandbox:
    print("http domains configured: ['api.github.com', '*.openai.com']")

# 6. 自定义内存限制和超时
with Sandbox(memory_limit_mb=256, timeout_secs=10) as sandbox:
    result = sandbox.execute("echo 'limited memory and timeout'")
    print(f"custom limits: {result.stdout.strip()}")

# 7. 设置最大进程数和信任级别
with Sandbox(max_processes=32, trust_level="untrusted") as sandbox:
    result = sandbox.execute("echo 'strict limits'")
    print(f"strict: {result.stdout.strip()}")

# 8. execute 时指定超时（秒，浮点数）
with Sandbox() as sandbox:
    result = sandbox.execute("echo 'with timeout'", timeout=5.0)
    print(f"timeout example: {result.stdout.strip()}")

# 7. 检查沙箱就绪状态
with Sandbox(isolation="microvm") as sandbox:
    sandbox.wait_ready(timeout_secs=10.0)
    print(f"ready: {sandbox.is_ready()}")
