# multi_language.py — Multi-language code execution: execute_code() runs Python/Bash/Node.js in a sandbox
#
# Demonstrates how execute_code() can execute code in different programming languages within the same sandbox.
# Supported languages: bash, sh, python, python3, py, javascript, js, node, nodejs

from mimobox import Sandbox, SandboxError

with Sandbox() as sb:
    # Python — sandbox typically comes with python3
    try:
        r = sb.execute_code('python', "print('Hello from Python!')")
        print(f"[Python] exit={r.exit_code} stdout={r.stdout.strip()}")
    except SandboxError as exc:
        print(f"[Python] skipped — {exc}")

    # Bash — the most fundamental language, almost always available
    try:
        r = sb.execute_code('bash', "echo 'Hello from Bash!'")
        print(f"[Bash]   exit={r.exit_code} stdout={r.stdout.strip()}")
    except SandboxError as exc:
        print(f"[Bash]   skipped — {exc}")

    # Node.js — depends on whether the sandbox rootfs has node installed
    try:
        r = sb.execute_code('node', "console.log('Hello from Node.js!')")
        print(f"[Node]   exit={r.exit_code} stdout={r.stdout.strip()}")
    except SandboxError as exc:
        print(f"[Node]   skipped — {exc}")

print('multi-language execution complete')
