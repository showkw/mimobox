# config_options.py — Configuration options: demonstrates various Sandbox initialization parameters
#
# Python SDK exposes the following configuration through the Sandbox constructor:
#   - isolation: Isolation level (auto / os / wasm / microvm)
#   - allowed_http_domains: HTTP proxy domain whitelist
#   - memory_limit_mb: Memory limit (MiB), default 512
#   - timeout_secs: Command timeout (seconds), default 30
#   - max_processes: Max process count (Linux cgroup v2 only)
#   - trust_level: Trust level (trusted / semi_trusted / untrusted)
#   - network: Network policy (deny_all / allow_domains / allow_all)

from mimobox import Sandbox

# 1. Default config: auto isolation level, selects optimal backend automatically
with Sandbox() as sandbox:
    result = sandbox.execute("echo 'auto isolation'")
    print(f"auto: {result.stdout.strip()}")

# 2. Explicit OS-level isolation (Landlock + Seccomp, Linux only)
with Sandbox(isolation="os") as sandbox:
    result = sandbox.execute("echo 'OS-level isolation'")
    print(f"os:   {result.stdout.strip()}")

# 3. Explicit Wasm isolation (Wasmtime sandbox)
with Sandbox(isolation="wasm") as sandbox:
    result = sandbox.execute("echo 'Wasm isolation'")
    print(f"wasm: {result.stdout.strip()}")

# 4. Explicit microVM isolation (KVM, strongest isolation)
with Sandbox(isolation="microvm") as sandbox:
    result = sandbox.execute("echo 'microVM isolation'")
    print(f"vm:   {result.stdout.strip()}")

# 5. With domain whitelist: allows HTTP requests from within the sandbox
with Sandbox(
    isolation="microvm",
    allowed_http_domains=["api.github.com", "*.openai.com"],
) as sandbox:
    print("http domains configured: ['api.github.com', '*.openai.com']")

# 6. Custom memory limit and timeout
with Sandbox(memory_limit_mb=256, timeout_secs=10) as sandbox:
    result = sandbox.execute("echo 'limited memory and timeout'")
    print(f"custom limits: {result.stdout.strip()}")

# 7. Set max process count and trust level
with Sandbox(max_processes=32, trust_level="untrusted") as sandbox:
    result = sandbox.execute("echo 'strict limits'")
    print(f"strict: {result.stdout.strip()}")

# 8. Specify timeout at execute time (seconds, float)
with Sandbox() as sandbox:
    result = sandbox.execute("echo 'with timeout'", timeout=5.0)
    print(f"timeout example: {result.stdout.strip()}")

# 9. Check sandbox ready state
with Sandbox(isolation="microvm") as sandbox:
    sandbox.wait_ready(timeout_secs=10.0)
    print(f"ready: {sandbox.is_ready()}")
