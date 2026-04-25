# streaming.py — stream_execute 使用：遍历 StreamIterator，实时打印输出
#
# 演示如何使用流式执行接口逐块获取 stdout/stderr，
# 而不是等待命令全部完成后再返回。

import sys

from mimobox import Sandbox

with Sandbox() as sandbox:
    # stream_execute 返回 StreamIterator，逐事件遍历
    for event in sandbox.stream_execute(
        "/bin/sh -c 'for i in 1 2 3 4 5; do echo line-$i; sleep 0.1; done'"
    ):
        if event.stdout is not None:
            # stdout 是 bytes 类型
            sys.stdout.buffer.write(event.stdout)
            sys.stdout.buffer.flush()
        if event.stderr is not None:
            sys.stderr.buffer.write(event.stderr)
            sys.stderr.buffer.flush()
        if event.exit_code is not None:
            print(f"\nprocess exited with code: {event.exit_code}")
        if event.timed_out:
            print("\ncommand timed out!")
