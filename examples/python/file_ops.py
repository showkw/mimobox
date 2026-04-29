# file_ops.py — File read/write: write_file + read_file
#
# Demonstrates how to write files into a sandbox and read them back.

from mimobox import Sandbox

with Sandbox(isolation="microvm") as sandbox:
    path = "/tmp/mimobox-demo.txt"
    content = b"Hello from mimobox file operations!\nLine 2 here.\n"

    # Write file
    sandbox.write_file(path, content)
    print(f"written {len(content)} bytes to {path}")

    # Read file
    data = sandbox.read_file(path)
    print(f"read {len(data)} bytes from {path}")
    print(f"content:\n{data.decode('utf-8')}")

    # Verify consistency
    assert data == content, "readback mismatch!"
    print("verified: readback matches written content")
