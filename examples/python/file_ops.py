# file_ops.py — 文件读写：write_file + read_file
#
# 演示如何向沙箱内写入文件、再读取回来。

from mimobox import Sandbox

with Sandbox(isolation="microvm") as sandbox:
    path = "/tmp/mimobox-demo.txt"
    content = b"Hello from mimobox file operations!\nLine 2 here.\n"

    # 写入文件
    sandbox.write_file(path, content)
    print(f"written {len(content)} bytes to {path}")

    # 读取文件
    data = sandbox.read_file(path)
    print(f"read {len(data)} bytes from {path}")
    print(f"content:\n{data.decode('utf-8')}")

    # 验证一致性
    assert data == content, "readback mismatch!"
    print("verified: readback matches written content")
