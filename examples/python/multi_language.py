# multi_language.py — 多语言代码执行：execute_code() 在沙箱中运行 Python/Bash/Node.js
#
# 演示 execute_code() 如何在同一个沙箱中使用不同编程语言执行代码。
# 支持的语言: bash, sh, python, python3, py, javascript, js, node, nodejs

from mimobox import Sandbox, SandboxError

with Sandbox() as sb:
    # Python — 沙箱内通常自带 python3
    try:
        r = sb.execute_code('python', "print('Hello from Python!')")
        print(f"[Python] exit={r.exit_code} stdout={r.stdout.strip()}")
    except SandboxError as exc:
        print(f"[Python] skipped — {exc}")

    # Bash — 最基础的语言，几乎总是可用
    try:
        r = sb.execute_code('bash', "echo 'Hello from Bash!'")
        print(f"[Bash]   exit={r.exit_code} stdout={r.stdout.strip()}")
    except SandboxError as exc:
        print(f"[Bash]   skipped — {exc}")

    # Node.js — 取决于沙箱 rootfs 是否安装了 node
    try:
        r = sb.execute_code('node', "console.log('Hello from Node.js!')")
        print(f"[Node]   exit={r.exit_code} stdout={r.stdout.strip()}")
    except SandboxError as exc:
        print(f"[Node]   skipped — {exc}")

print('multi-language execution complete')
