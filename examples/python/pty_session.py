# pty_session.py — PTY interactive session: execute commands via pseudo-terminal and read output in real-time
#
# Demonstrates the full PtySession usage flow: create PTY session, send input,
# iterate output events, resize terminal, and graceful shutdown.
# Note: PTY features require Linux + KVM; other platforms may raise NotImplementedError.

import sys

from mimobox import PtyExit, PtyOutput, Sandbox

with Sandbox(isolation="microvm") as sandbox:
    # Create a 120x40 PTY session, running /bin/sh
    session = sandbox.pty.create("/bin/sh", cols=120, rows=40)

    try:
        # Send command to PTY
        session.send_input("echo 'Hello from PTY!'\n")

        # Iterate output events (PtyOutput or PtyExit)
        for event in session:
            if event is None:
                continue
            if isinstance(event, PtyOutput):
                # PtyOutput event: output may contain ANSI escape sequences
                sys.stdout.buffer.write(event.data)
                sys.stdout.buffer.flush()
            elif isinstance(event, PtyExit):
                # PtyExit event: process has exited
                print(f"\nprocess exited with code: {event.code}")
                break

        # Send more commands
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

        # Dynamically resize terminal
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
        # Ensure session is cleaned up
        session.kill()
