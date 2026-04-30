# basic.py — Minimal example: create sandbox, execute command, print result, close
#
# Demonstrates the most basic Sandbox usage: without context manager, manual lifecycle management.

from mimobox import Sandbox

# Create sandbox (using default auto isolation level)
sandbox = Sandbox()

# Execute command
result = sandbox.execute("echo 'Hello from mimobox!'")

# Print result
print(f"exit_code: {result.exit_code}")
print(f"stdout:    {result.stdout.strip()}")
print(f"stderr:    {result.stderr.strip()}")
print(f"timed_out: {result.timed_out}")
if result.elapsed is not None:
    print(f"elapsed:   {result.elapsed:.3f}s")

# Manual cleanup: close() is the recommended cleanup method when not using a with statement.
sandbox.close()
print("sandbox closed")
