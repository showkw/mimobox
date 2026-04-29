# pty_session.py — PTY 交互式会话：通过伪终端执行命令并实时读取输出
#
# 演示 PtySession 的完整使用流程：创建 PTY 会话、发送输入、
# 迭代输出事件、调整终端大小、优雅关闭。
# 注意：PTY 功能需要 Linux + KVM 环境，其他平台可能抛出 NotImplementedError。

import sys

from mimobox import PtyExit, PtyOutput, Sandbox

with Sandbox(isolation="microvm") as sandbox:
    # 创建一个 120x40 的 PTY 会话，运行 /bin/sh
    session = sandbox.pty.create("/bin/sh", cols=120, rows=40)

    try:
        # 发送命令到 PTY
        session.send_input("echo 'Hello from PTY!'\n")

        # 迭代输出事件（PtyOutput 或 PtyExit）
        for event in session:
            if event is None:
                continue
            if isinstance(event, PtyOutput):
                # PtyOutput 事件：输出可能包含 ANSI 转义序列
                sys.stdout.buffer.write(event.data)
                sys.stdout.buffer.flush()
            elif isinstance(event, PtyExit):
                # PtyExit 事件：进程已退出
                print(f"\nprocess exited with code: {event.code}")
                break

        # 发送更多命令
        session.send_input("uname -a\n")
        for event in session:
            if event is None:
                continue
            if isinstance(event, PtyOutput):
                sys.stdout.buffer.write(event.data)
                sys.stdout.buffer.flush()
            elif isinstance(event, PtyExit):
                print(f"\nprocess exited with code: {event.code}")
                break

        # 动态调整终端大小
        session.resize(cols=200, rows=50)
        session.send_input("echo 'resized!'\n")
        for event in session:
            if event is None:
                continue
            if isinstance(event, PtyOutput):
                sys.stdout.buffer.write(event.data)
                sys.stdout.buffer.flush()
            elif isinstance(event, PtyExit):
                print(f"\nprocess exited with code: {event.code}")
                break

    finally:
        # 确保会话被清理
        session.kill()
