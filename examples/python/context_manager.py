# context_manager.py — Context manager: with Sandbox() as sb: automatic resource management
#
# Demonstrates automatic sandbox lifecycle management with the with statement.
# __enter__ returns the sandbox itself, __exit__ automatically destroys resources, cleanup happens even on exceptions.

from mimobox import Sandbox

# Basic usage: sandbox is automatically destroyed after the with block ends
with Sandbox() as sandbox:
    result = sandbox.execute("echo 'inside context manager'")
    print(result.stdout.strip())

print("sandbox automatically destroyed after with block")

# Exception safety: resources are properly cleaned up even if command execution fails
try:
    with Sandbox() as sandbox:
        sandbox.execute("echo 'before error'")
        raise RuntimeError("simulated error")
except RuntimeError:
    print("exception caught, sandbox was still properly cleaned up")

# Nested usage: multiple sandboxes can exist simultaneously
with Sandbox() as sb1, Sandbox() as sb2:
    r1 = sb1.execute("echo 'from sandbox 1'")
    r2 = sb2.execute("echo 'from sandbox 2'")
    print(r1.stdout.strip())
    print(r2.stdout.strip())
