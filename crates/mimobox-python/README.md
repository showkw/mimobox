# mimobox-python

Python bindings for mimobox Agent Sandbox, implemented with PyO3.

`mimobox-python` provides Python access to the same secure sandbox execution model exposed by `mimobox-sdk`, including command execution, streaming output, file transfer, snapshots, forks, and controlled HTTP requests.

Repository: <https://github.com/showkw/mimobox>

## Installation

Install for local development with maturin:

```bash
maturin develop -m crates/mimobox-python/Cargo.toml
```

## Quick Start

Use `Sandbox` as a context manager so resources are released automatically:

```python
from mimobox import Sandbox

with Sandbox(isolation="auto") as sandbox:
    result = sandbox.execute("/bin/echo hello from python")
    print(result.stdout.decode())
```

Streaming output:

```python
from mimobox import Sandbox

with Sandbox(isolation="os") as sandbox:
    for event in sandbox.stream_execute("printf 'hello\\nworld\\n'"):
        if event.stdout is not None:
            print(event.stdout.decode(), end="")
```

## API Overview

The main `Sandbox` APIs are:

- `execute(command, env=None, timeout=None)` executes a command and returns `ExecuteResult`.
- `stream_execute(command)` returns an iterator of `StreamEvent` objects.
- `read_file(path)` reads bytes from the sandbox.
- `write_file(path, data)` writes bytes into the sandbox.
- `snapshot()` captures sandbox state where supported.
- `Sandbox.from_snapshot(snapshot)` restores a sandbox from a snapshot.
- `fork()` creates an independent sandbox copy where supported.
- `http_request(method, url, headers=None, body=None)` uses the controlled HTTP proxy.

## Isolation Parameter

`Sandbox(isolation=...)` accepts:

| Value | Description |
| --- | --- |
| `auto` | Smart routing selected by mimobox. |
| `os` | OS-level sandbox backend. |
| `wasm` | Wasm sandbox backend when available. |
| `microvm` | microVM backend on Linux + KVM. |

## Exception Hierarchy

The bindings expose typed Python exceptions for sandbox failures:

- `SandboxError` is the base exception for mimobox failures.
- `SandboxProcessError` is raised for process execution failures.
- `SandboxTimeoutError` is raised when an operation exceeds its timeout.
- `ValueError` is raised for invalid Python arguments such as an unknown isolation value.

## Feature Flags

This crate is built as a Python extension module and currently enables the `os` and `vm` SDK backends in its crate configuration.

## License

MIT OR Apache-2.0
