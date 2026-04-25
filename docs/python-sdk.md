# mimobox Python SDK

This document describes how to install `mimobox-python`, its public API, exception hierarchy, and complete examples. The prose is in English, while code examples and variable names remain in English as originally written.

## 1. Overview

`mimobox-python` provides Python bindings through PyO3 + maturin, exposing the Rust SDK's `mimobox_sdk::Sandbox` as the Python module `mimobox`.

Core relationship:

```text
Python user code
  |
  v
mimobox.Sandbox
  |
  v
mimobox_sdk::Sandbox
  |
  +-- OS sandbox
  +-- Wasm sandbox
  `-- microVM sandbox
```

The Python SDK supports:

- Basic command execution.
- Command-level environment variable injection and timeouts.
- Streaming output.
- microVM file reads and writes.
- microVM snapshots, restoration, and CoW fork.
- Host-side HTTP proxy.
- Python exception hierarchy and standard exception mapping.

## 2. Installation

Build from source (recommended):

```bash
cd mimobox && maturin develop --features vm
```

OS-level backend only:

```bash
maturin develop
```

Notes:

- `--features vm` requires a Linux + KVM environment to fully use microVM capabilities.
- The OS-level backend is suitable for fast local development, basic command execution, and API debugging.

## 3. Public Classes and Methods

### 3.1 `Sandbox`

`Sandbox` is the main entry point and delegates internally to the Rust SDK's `Sandbox`.

Constructor:

```python
Sandbox(*, isolation=None, allowed_http_domains=None)
```

Parameters:

- `isolation`: Isolation level. The default `None` is equivalent to `"auto"`.
- `allowed_http_domains`: List of domains allowed by the HTTP proxy. Wildcard patterns are supported.

Public methods:

```python
execute(command, env=None, timeout=None) -> ExecuteResult
stream_execute(command) -> StreamIterator
read_file(path) -> bytes
write_file(path, data: bytes)
snapshot() -> Snapshot
fork() -> Sandbox
http_request(method, url, headers=None, body=None) -> HttpResponse
wait_ready(timeout_secs=None)
is_ready() -> bool
```

Class method:

```python
Sandbox.from_snapshot(snapshot) -> Sandbox
```

Context manager:

```python
with Sandbox() as sb:
    result = sb.execute("/bin/echo hello")
```

When the `with` block exits, the underlying sandbox resources are released.

### 3.2 `ExecuteResult`

Command execution result.

Attributes:

- `stdout: str`: Standard output, decoded using UTF-8 lossy decoding.
- `stderr: str`: Standard error, decoded using UTF-8 lossy decoding.
- `exit_code: int`: Exit code; `-1` when the underlying layer has no exit code.
- `timed_out: bool`: Whether the execution timed out.
- `elapsed: float | None`: Execution duration in seconds; `None` when unknown.

### 3.3 `HttpResponse`

HTTP proxy response.

Attributes:

- `status: int`: HTTP status code.
- `headers: dict`: Response headers.
- `body: bytes`: Raw response body bytes.

### 3.4 `Snapshot`

microVM sandbox snapshot.

Methods:

```python
Snapshot.from_bytes(data: bytes) -> Snapshot
to_bytes() -> bytes
size() -> int
```

Notes:

- `from_bytes` is a classmethod.
- `to_bytes()` serializes the snapshot into bytes.
- `size()` returns the snapshot size.

### 3.5 `StreamEvent`

Streaming execution event.

Attributes:

- `stdout: bytes | None`: stdout chunk.
- `stderr: bytes | None`: stderr chunk.
- `exit_code: int | None`: Exit code event.
- `timed_out: bool`: Whether this is a timeout event.

Each event usually carries only one kind of information: stdout, stderr, exit code, or timeout.

### 3.6 `StreamIterator`

`StreamIterator` is the iterator returned by `Sandbox.stream_execute()`.

Behavior:

- Implements the Python iteration protocol.
- Yields one `StreamEvent` on each iteration.
- Stops iteration after the underlying stream ends.

Example:

```python
for event in sb.stream_execute("/bin/sh -c 'echo hello; echo err >&2'"):
    if event.stdout is not None:
        print(event.stdout.decode(), end="")
```

## 4. Exception Hierarchy

The Python SDK defines the following mimobox exceptions:

- `SandboxError`: Base class.
- `SandboxProcessError`: Command execution error, such as a non-zero exit or being killed.
- `SandboxHttpError`: HTTP proxy error, such as a rejected domain, invalid URL, or oversized body.
- `SandboxLifecycleError`: Sandbox lifecycle error, such as not ready, destroyed, or failed to create.

It also maps errors to standard Python exceptions:

- `TimeoutError`: Command or HTTP request timeout.
- `FileNotFoundError`: File does not exist.
- `PermissionError`: File permission denied.
- `ConnectionError`: HTTP connection or TLS failure.
- `ValueError`: Invalid configuration or parameter.
- `NotImplementedError`: Unsupported on the current platform or feature set.

Callers are encouraged to catch specific exceptions first, then use `SandboxError` as a fallback:

```python
from mimobox import Sandbox, SandboxError, SandboxHttpError

try:
    with Sandbox(isolation="microvm") as sb:
        sb.http_request("GET", "https://example.com")
except SandboxHttpError as exc:
    print(f"HTTP proxy failed: {exc}")
except SandboxError as exc:
    print(f"sandbox failed: {exc}")
```

## 5. `isolation` Parameter

`Sandbox(isolation=...)` supports the following values:

- `"auto"`: Default intelligent routing.
- `"os"`: OS-level sandbox.
- `"wasm"`: Wasm sandbox.
- `"microvm"`: microVM sandbox.
- `"micro_vm"`: Alias for `"microvm"`.
- `"micro-vm"`: Alias for `"microvm"`.

Omitting `isolation` is equivalent to `"auto"`.

Intelligent routing semantics:

- `.wasm`, `.wat`, and `.wast` files prefer Wasm.
- Untrusted tasks can use the microVM fail-closed path in the Rust SDK through `TrustLevel::Untrusted`.
- Other normal commands use the OS-level sandbox by default.

## 6. Complete Examples

### 6.1 Basic Execution

```python
from mimobox import Sandbox, Snapshot

with Sandbox(isolation="auto") as sb:
    result = sb.execute("/bin/echo hello")
    print(result.stdout, end="")
    print(f"exit_code={result.exit_code}")
```

### 6.2 Command-Level Environment Variables and Timeout

```python
from mimobox import Sandbox, Snapshot

with Sandbox(isolation="microvm") as sb:
    result = sb.execute(
        "/usr/bin/printenv MIMOBOX_MODE",
        env={"MIMOBOX_MODE": "python-demo"},
        timeout=5.0,
    )
    print(result.stdout, end="")
```

### 6.3 Streaming Output

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    stream = sb.stream_execute("/bin/sh -c 'echo start; echo err >&2; echo done'")
    for event in stream:
        if event.stdout is not None:
            print(event.stdout.decode("utf-8", errors="replace"), end="")
        if event.stderr is not None:
            print(event.stderr.decode("utf-8", errors="replace"), end="")
        if event.exit_code is not None:
            print(f"exit={event.exit_code}")
        if event.timed_out:
            print("timed out")
```

### 6.4 HTTP Request

```python
from mimobox import Sandbox

with Sandbox(
    isolation="microvm",
    allowed_http_domains=["example.com"],
) as sb:
    response = sb.http_request("GET", "https://example.com")
    print(response.status)
    print(response.body[:80])
```

### 6.5 File Operations

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    sb.write_file("/tmp/hello.txt", b"hello from python\n")
    data = sb.read_file("/tmp/hello.txt")
    print(data.decode("utf-8"), end="")
```

### 6.6 Snapshot and Restore

```python
from mimobox import Sandbox, Snapshot

with Sandbox(isolation="microvm") as sb:
    sb.write_file("/tmp/state.txt", b"before snapshot\n")
    snapshot = sb.snapshot()
    snapshot_bytes = snapshot.to_bytes()

restored_snapshot = Snapshot.from_bytes(snapshot_bytes)

with Sandbox.from_snapshot(restored_snapshot) as restored:
    data = restored.read_file("/tmp/state.txt")
    print(data.decode("utf-8"), end="")
```

### 6.7 Fork

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as parent:
    parent.write_file("/tmp/state.txt", b"parent\n")

    child = parent.fork()
    try:
        child.write_file("/tmp/state.txt", b"child\n")

        parent_data = parent.read_file("/tmp/state.txt")
        child_data = child.read_file("/tmp/state.txt")

        print(parent_data.decode("utf-8"), end="")
        print(child_data.decode("utf-8"), end="")
    finally:
        child.__exit__(None, None, None)
```

Note: `fork()` returns an independent sandbox. The example explicitly releases `child` by calling the context manager's exit method; in real code, it is recommended to wrap the forked object in your own resource management logic.
