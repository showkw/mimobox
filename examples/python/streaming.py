# streaming.py — stream_execute usage: iterate StreamIterator, print output in real-time
#
# Demonstrates how to use the streaming execution interface to get stdout/stderr chunk by chunk,
# instead of waiting for the entire command to complete before returning.

import sys

from mimobox import Sandbox

with Sandbox() as sandbox:
    # stream_execute returns a StreamIterator, iterate over events
    for event in sandbox.stream_execute(
        "/bin/sh -c 'for i in 1 2 3 4 5; do echo line-$i; sleep 0.1; done'"
    ):
        if event.stdout is not None:
            # stdout is bytes type
            sys.stdout.buffer.write(event.stdout)
            sys.stdout.buffer.flush()
        if event.stderr is not None:
            sys.stderr.buffer.write(event.stderr)
            sys.stderr.buffer.flush()
        if event.exit_code is not None:
            print(f"\nprocess exited with code: {event.exit_code}")
        if event.timed_out:
            print("\ncommand timed out!")
