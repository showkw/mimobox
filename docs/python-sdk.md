# MimoBox Python SDK

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
- Multi-language code execution with `execute_code()`.
- Command-level environment variable injection and timeouts.
- Streaming output.
- Argv-style command execution and streaming with `exec()` and `stream_exec()`.
- Active backend introspection with `active_isolation`.
- microVM file reads and writes.
- Directory listing with `list_dir()`.
- Recursive directory creation, file metadata, existence checks, removal, and rename operations.
- Namespaced helpers through `fs`, `process`, `snapshot`, `network`, and `pty`.
- microVM snapshots, restoration, and CoW fork.
- Host-side HTTP proxy.
- HTTP ACL allow and deny rules for method, host, and path filtering.
- Interactive PTY sessions.
- Python exception hierarchy and standard exception mapping.
- Global sandbox registry: `Sandbox.id`, `Sandbox.list()`, `SandboxInfo`.
- Runtime resource metrics: `Sandbox.metrics()`, `SandboxMetrics`.
- Persistent environment variables at creation: `env_vars` parameter.
- Structured sandbox error attributes, including stable error codes, suggestions, process output, and resource-limit exceptions.

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
Sandbox(*, isolation=None, allowed_http_domains=None, memory_limit_mb=None, timeout_secs=None, max_processes=None, trust_level=None, network=None)
```

Current complete signature including HTTP ACL and env_vars parameters:

```python
Sandbox(*, isolation=None, allowed_http_domains=None, http_acl_allow=None, http_acl_deny=None, memory_limit_mb=None, timeout_secs=None, max_processes=None, trust_level=None, network=None, env_vars=None)
```

Parameters:

- `isolation`: Isolation level. The default `None` is equivalent to `"auto"`.
- `allowed_http_domains`: List of domains allowed by the HTTP proxy. Wildcard patterns are supported.
- `http_acl_allow`: Optional list of HTTP ACL allow rules in `"METHOD host/path"` format. Glob patterns are supported.
- `http_acl_deny`: Optional list of HTTP ACL deny rules in `"METHOD host/path"` format. Deny rules take precedence over allow rules.
- `memory_limit_mb`: Memory limit in MiB. Defaults to 512.
- `timeout_secs`: Sandbox command timeout in seconds. Defaults to 30.
- `max_processes`: Maximum process count. Defaults to backend default (unlimited).
- `trust_level`: Trust level: `"trusted"`, `"semi_trusted"`, or `"untrusted"`. Defaults to `"semi_trusted"`.
- `network`: Network policy: `"deny_all"`, `"allow_domains"`, or `"allow_all"`. Defaults to `"deny_all"`.
- `env_vars`: Optional dict of persistent environment variables set at sandbox creation. These are applied to every subsequent command. Security-critical and baseline names (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `ENV`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `PATH`, `HOME`, `TMPDIR`, `PWD`, `SHELL`, `USER`, `LOGNAME`) are blocked. Keys with `=`, NUL, or spaces, and values with NUL, are rejected. The Python layer also caps this input to 64 variables, 128 bytes per key, 8 KiB per value, and 64 KiB total.

Public methods:

```python
execute(command, env=None, timeout=None, cwd=None) -> ExecuteResult
execute_code(language, code, *, env=None, timeout=None, cwd=None) -> ExecuteResult
stream_execute(command) -> StreamIterator
list_dir(path) -> list[DirEntry]
read_file(path) -> bytes
write_file(path, data: bytes)
snapshot() -> Snapshot
fork() -> Sandbox
http_request(method, url, headers=None, body=None) -> HttpResponse
wait_ready(timeout_secs=None)
is_ready() -> bool
close()
```

Additional public methods and properties:

```python
exec(argv, env=None, timeout=None, cwd=None) -> ExecuteResult
stream_exec(argv) -> StreamIterator
active_isolation -> str | None
id -> str | None
info() -> SandboxInfo
env_vars -> dict[str, str]
metrics() -> SandboxMetrics
make_dir(path)
stat(path) -> FileStat
file_exists(path) -> bool
remove_file(path)
rename(from, to)
fs -> FileSystem
process -> Process
snapshot -> SnapshotOps
network -> Network
pty -> Pty
```

Class method:

```python
Sandbox.from_snapshot(snapshot) -> Sandbox
Sandbox.list() -> list[SandboxInfo]
```

#### execute(command, env=None, timeout=None, cwd=None)

Executes a shell command inside the sandbox.

Parameters:

- `command: str`: Shell command to execute.
- `env: dict | None`: Optional environment variables to set for the command.
- `timeout: float | None`: Optional timeout in seconds. Must be > 0 and finite.
- `cwd: str | None`: Optional working directory for the command. When set, the command runs as `cd <cwd> && <command>`.

Example:

```python
with Sandbox() as sb:
    result = sb.execute("ls -la", cwd="/workspace")
    print(result.stdout)
```

#### execute_code(language, code, *, env=None, timeout=None, cwd=None)

Executes source code in the specified language inside the sandbox. This is a convenience method that wraps the code in the appropriate interpreter invocation.

Supported languages: `"bash"`, `"sh"`, `"shell"`, `"python"`, `"python3"`, `"py"`, `"javascript"`, `"js"`, `"node"`, `"nodejs"`.

Parameters:

- `language: str`: Programming language name.
- `code: str`: Source code to execute.
- `env: dict | None`: Optional environment variables to set for the command.
- `timeout: float | None`: Optional timeout in seconds. Must be > 0 and finite.
- `cwd: str | None`: Optional working directory for the command.

Example:

```python
with Sandbox() as sb:
    result = sb.execute_code("python", "print(42)")
    print(result.stdout, end="")

    result = sb.execute_code("bash", "echo hello", timeout=5.0)
    print(result.stdout, end="")

    result = sb.execute_code("node", "console.log('hi')", cwd="/app")
    print(result.stdout, end="")
```

Raises:

- `ValueError`: If the language is not supported.

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

### 3.3 `DirEntry`

A single directory entry returned by `Sandbox.list_dir()`.

Attributes:

- `name: str`: File or directory name.
- `file_type: str`: Type string: `"file"`, `"dir"`, `"symlink"`, or `"other"`.
- `size: int`: File size in bytes.
- `is_symlink: bool`: Whether this entry is a symbolic link.

### 3.4 `HttpResponse`

HTTP proxy response.

Attributes:

- `status: int`: HTTP status code.
- `headers: dict`: Response headers.
- `body: bytes`: Raw response body bytes.

### 3.5 `Snapshot`

microVM sandbox snapshot.

Methods:

```python
Snapshot.from_bytes(data: bytes) -> Snapshot
Snapshot.from_file(path: str) -> Snapshot
to_bytes() -> bytes
size() -> int
```

Notes:

- `from_bytes` is a classmethod that reconstructs a snapshot from its serialized byte representation.
- `from_file` is a classmethod that loads a snapshot from a file on disk, without reading the entire file into memory. Suitable for large snapshot files previously saved via `to_bytes()`.
- `to_bytes()` serializes the snapshot into bytes.
- `size()` returns the snapshot size.

### 3.6 `StreamEvent`

Streaming execution event.

Attributes:

- `stdout: bytes | None`: stdout chunk.
- `stderr: bytes | None`: stderr chunk.
- `exit_code: int | None`: Exit code event.
- `timed_out: bool`: Whether this is a timeout event.

Each event usually carries only one kind of information: stdout, stderr, exit code, or timeout.

### 3.7 `StreamIterator`

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

### 3.8 `list_dir()`

```python
list_dir(path) -> list[DirEntry]
```

Lists directory entries inside the sandbox.

Parameters:

- `path: str`: Absolute path inside the sandbox filesystem.

Returns a list of `DirEntry` objects.

Example:

```python
with Sandbox(isolation="microvm") as sb:
    entries = sb.list_dir("/tmp")
    for entry in entries:
        print(f"{entry.name} ({entry.file_type}) - {entry.size} bytes")
```

Raises:

- `SandboxError`: If the directory cannot be read.

### 3.9 `close()`

```python
close()
```

Explicitly releases sandbox resources. Safe to call multiple times; subsequent calls are no-ops. Also called automatically by the context manager exit.

### 3.10 `exec()`

```python
exec(argv, env=None, timeout=None, cwd=None) -> ExecuteResult
```

Executes a command with explicit argv. Unlike `execute()`, this method does not
use shell parsing, shell expansion, pipes, redirection, or quoting rules. Each
item in `argv` is passed as one argument.

Parameters:

- `argv: list[str]`: Command and arguments. The list must be non-empty.
- `env: dict | None`: Optional environment variables to set for the command.
- `timeout: float | None`: Optional timeout in seconds. Must be > 0 and finite.
- `cwd: str | None`: Optional working directory for the command.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    result = sb.exec(["ls", "-la", "/tmp"], timeout=5.0)
    print(result.stdout)

    # Shell metacharacters are ordinary argument bytes here.
    result = sb.exec(["printf", "%s\n", "hello; rm -rf /"])
    print(result.stdout, end="")
```

Notes:

- Use `exec()` for user-controlled arguments to avoid shell injection risks.
- Use `execute()` when you explicitly need shell features such as pipes, glob expansion, redirection, or compound commands.
- Passing an empty `argv` raises `ValueError`.

### 3.11 `stream_exec()`

```python
stream_exec(argv) -> StreamIterator
```

Executes an argv-style command and returns a streaming iterator of
`StreamEvent` objects. It is the argv-style counterpart to
`stream_execute()`, which accepts a shell command string.

Parameters:

- `argv: list[str]`: Command and arguments. The list must be non-empty.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    sb.make_dir("/tmp/src")
    sb.write_file("/tmp/src/a.txt", b"pattern\nother\n")
    sb.write_file("/tmp/src/b.txt", b"pattern again\n")

    for event in sb.stream_exec(["grep", "-r", "pattern", "/tmp/src"]):
        if event.stdout is not None:
            print(event.stdout.decode("utf-8", errors="replace"), end="")
        if event.stderr is not None:
            print(event.stderr.decode("utf-8", errors="replace"), end="")
        if event.exit_code is not None:
            print(f"exit={event.exit_code}")
```

Notes:

- `stream_exec()` does not run through a shell, so `|`, `>`, `*`, `$VAR`, and quotes are not interpreted.
- Use `stream_execute()` when the command intentionally depends on shell syntax.
- Passing an empty `argv` raises `ValueError`.

### 3.12 `active_isolation`

```python
active_isolation -> str | None
```

Returns the actual isolation level of the active backend. This is useful when
`isolation="auto"` selects the backend at runtime.

Example:

```python
from mimobox import Sandbox

with Sandbox(isolation="auto") as sb:
    print(sb.active_isolation)  # None before the first operation.

    result = sb.execute("/bin/echo ready")
    print(result.stdout, end="")
    print(sb.active_isolation)
```

Notes:

- The value is `None` before the first operation initializes a backend.
- After auto-routing, the value is the actual backend, such as `"os"`, `"wasm"`, or `"microvm"`.
- The returned value describes the active backend, not just the requested constructor argument.

### 3.13 `Sandbox.id`

```python
id -> str | None
```

Returns the unique UUID string assigned to this sandbox instance. The value is `None` after the sandbox has been closed.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    print(sb.id)  # e.g. "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

Notes:

- The ID is a UUID4 string generated at sandbox creation.
- The ID is registered in the global sandbox registry and can be used for logging, tracing, and debugging.

### 3.14 `Sandbox.list()`

```python
Sandbox.list() -> list[SandboxInfo]
```

Class method that returns all currently registered sandbox instances in the current process.

Example:

```python
from mimobox import Sandbox

sb1 = Sandbox()
sb2 = Sandbox()

active = Sandbox.list()
print(f"{len(active)} sandbox(es) registered")
for info in active:
    print(f"  id={info.id}, isolation={info.active_isolation}, ready={info.is_ready}")

sb1.close()
sb2.close()
```

Notes:

- This is a class method, called on the `Sandbox` type.
- Closed sandboxes are automatically unregistered.
- Useful for orchestration, dashboard displays, and resource auditing.

### 3.15 `Sandbox.metrics()`

```python
metrics() -> SandboxMetrics
```

Returns runtime resource usage metrics from the most recent command execution. If no command has been executed yet, all fields return `None`.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    result = sb.execute("/bin/echo hello")

    m = sb.metrics()
    if m.memory_usage_bytes is not None:
        print(f"memory: {m.memory_usage_bytes} bytes")
    if m.cpu_time_user_us is not None:
        print(f"CPU user: {m.cpu_time_user_us} us")
    if m.cpu_time_system_us is not None:
        print(f"CPU system: {m.cpu_time_system_us} us")
    if m.wasm_fuel_consumed is not None:
        print(f"Wasm fuel: {m.wasm_fuel_consumed}")
    if m.io_read_bytes is not None:
        print(f"IO read: {m.io_read_bytes} bytes")
    if m.io_write_bytes is not None:
        print(f"IO write: {m.io_write_bytes} bytes")
```

Notes:

- Metrics are cached after each `execute()` call.
- Not all backends populate every field.
- `collected_at` is exposed as seconds elapsed since metric collection.

### 3.16 `Sandbox.info()`

```python
info() -> SandboxInfo
```

Returns a registry snapshot for the current sandbox. It is equivalent to
searching `Sandbox.list()` by `sb.id`, but avoids the extra lookup in user code.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    info = sb.info()
    print(info.id)
    print(info.configured_isolation)
    print(info.active_isolation)
    print(info.is_ready)
```

### 3.17 `Sandbox.env_vars`

```python
env_vars -> dict[str, str]
```

Returns a copy of the persistent environment variables configured at sandbox
creation. Backend built-in defaults such as `HOME` and `PATH` are not included.

Example:

```python
from mimobox import Sandbox

with Sandbox(env_vars={"MIMOBOX_MODE": "audit"}) as sb:
    print(sb.env_vars["MIMOBOX_MODE"])
```

### 3.18 `SandboxInfo`

`SandboxInfo` represents a snapshot of a sandbox instance's registration info. Returned by `Sandbox.list()`.

Attributes:

- `id: str`: UUID string of the sandbox instance.
- `is_ready: bool`: Whether the backend is initialized and ready.
- `configured_isolation: str | None`: Configured isolation level string.
- `active_isolation: str | None`: Active isolation level string, such as `"os"`, `"wasm"`, or `"microvm"`. `None` before the first command.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    info = sb.info()
    print(info.id)
    print(info.configured_isolation)
    print(info.is_ready)
    print(info.active_isolation)
```

### 3.19 `SandboxMetrics`

`SandboxMetrics` represents runtime resource usage metrics. Returned by `Sandbox.metrics()`.

Attributes:

- `memory_usage_bytes: int | None`: Current memory usage in bytes.
- `memory_limit_bytes: int | None`: Memory limit in bytes.
- `cpu_time_user_us: int | None`: User-mode CPU time in microseconds.
- `cpu_time_system_us: int | None`: Kernel-mode CPU time in microseconds.
- `wasm_fuel_consumed: int | None`: Wasm fuel consumed (Wasm backend only).
- `io_read_bytes: int | None`: I/O read bytes.
- `io_write_bytes: int | None`: I/O write bytes.
- `collected_at: float | None`: Seconds elapsed since metric collection.

### 3.20 `env_vars` Parameter

The `Sandbox` constructor accepts `env_vars` as an optional dict of persistent environment variables:

```python
from mimobox import Sandbox

with Sandbox(env_vars={"API_KEY": "secret", "DEBUG": "1"}) as sb:
    result = sb.execute("/usr/bin/printenv API_KEY")
    print(result.stdout, end="")  # "secret"

    # env_vars persist across commands
    result = sb.execute("/usr/bin/printenv DEBUG")
    print(result.stdout, end="")  # "1"
```

Notes:

- `env_vars` are set at creation time and apply to every command.
- Per-command `env` parameter takes precedence over `env_vars`.
- Security-critical and baseline names are blocked: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `ENV`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `PATH`, `HOME`, `TMPDIR`, `PWD`, `SHELL`, `USER`, `LOGNAME`.
- Python input quotas: maximum 64 variables, 128 bytes per key, 8 KiB per value, and 64 KiB total.
- Keys containing `=`, NUL, or spaces are rejected. Values containing NUL are rejected.

### 3.21 `make_dir()`

```python
make_dir(path)
```

Creates a directory and any missing parent directories inside the sandbox.

Parameters:

- `path: str`: Directory path inside the sandbox filesystem.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    sb.make_dir("/tmp/a/b/c")
    sb.write_file("/tmp/a/b/c/hello.txt", b"hello\n")
    print(sb.read_file("/tmp/a/b/c/hello.txt").decode("utf-8"), end="")
```

Notes:

- The operation is recursive, similar to `mkdir -p`.
- Invalid paths such as empty strings, NUL bytes, or parent traversal raise `ValueError`.
- A backend failure raises `SandboxError`.

### 3.22 `FileStat`

`FileStat` represents file metadata returned by `Sandbox.stat()` and
`Sandbox.fs.stat()`.

Attributes:

- `path: str`: Path for the file metadata.
- `is_dir: bool`: Whether the path is a directory.
- `is_file: bool`: Whether the path is a regular file.
- `size: int`: File size in bytes.
- `mode: int`: File mode bits as reported by the backend.
- `modified_ms: int | None`: Last modification time in milliseconds, or `None` when unavailable.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    sb.write_file("/tmp/file.txt", b"hello\n")
    info = sb.stat("/tmp/file.txt")

    print(info.path)
    print(info.is_file)
    print(info.is_dir)
    print(info.size)
    print(oct(info.mode))
    print(info.modified_ms)
```

Notes:

- `mode` is backend and platform dependent.
- `modified_ms` can be `None` when the backend cannot provide a timestamp.
- Use `is_file` and `is_dir` instead of deriving file type from `mode`.

### 3.23 `stat()`

```python
stat(path) -> FileStat
```

Returns metadata for a file or directory inside the sandbox.

Parameters:

- `path: str`: Path inside the sandbox filesystem.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    sb.make_dir("/tmp/data")
    sb.write_file("/tmp/data/input.txt", "hello")

    file_stat = sb.stat("/tmp/data/input.txt")
    dir_stat = sb.stat("/tmp/data")

    print(file_stat.is_file, file_stat.size)
    print(dir_stat.is_dir)
```

Notes:

- Use `stat()` when you need metadata, not just existence.
- Missing paths can raise `FileNotFoundError`.
- Permission or backend failures can raise `PermissionError` or `SandboxError`.

### 3.24 `file_exists()`

```python
file_exists(path) -> bool
```

Checks whether a path exists inside the sandbox.

Parameters:

- `path: str`: Path inside the sandbox filesystem.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    print(sb.file_exists("/tmp/created.txt"))

    sb.write_file("/tmp/created.txt", b"created\n")
    print(sb.file_exists("/tmp/created.txt"))
```

Notes:

- This method returns only a boolean.
- Use `stat()` when you need file type, size, mode, or modification time.
- Backend errors can still raise `SandboxError`.

### 3.25 `remove_file()`

```python
remove_file(path)
```

Removes a file or an empty directory inside the sandbox.

Parameters:

- `path: str`: File or empty directory path inside the sandbox filesystem.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    sb.write_file("/tmp/delete-me.txt", b"temporary\n")
    print(sb.file_exists("/tmp/delete-me.txt"))

    sb.remove_file("/tmp/delete-me.txt")
    print(sb.file_exists("/tmp/delete-me.txt"))
```

Notes:

- The method removes files and empty directories.
- It is not a recursive directory delete operation.
- Missing paths, non-empty directories, permission errors, or backend failures can raise an exception.

### 3.26 `rename()`

```python
rename(from, to)
```

Renames or moves a file inside the sandbox filesystem.

Parameters:

- `from: str`: Source path inside the sandbox filesystem.
- `to: str`: Destination path inside the sandbox filesystem.

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    sb.write_file("/tmp/old.txt", b"renamed\n")
    sb.rename("/tmp/old.txt", "/tmp/new.txt")

    print(sb.file_exists("/tmp/old.txt"))
    print(sb.read_file("/tmp/new.txt").decode("utf-8"), end="")
```

Notes:

- Both paths are interpreted inside the sandbox.
- Parent directories for the destination must already exist.
- Permission errors or backend failures can raise an exception.

### 3.27 `FileSystem`

`Sandbox.fs` provides a file system namespace for common file operations.

Methods:

```python
read(path) -> bytes
read_text(path, encoding="utf-8") -> str
write(path, data: str | bytes)
list(path) -> list[DirEntry]
exists(path) -> bool
remove(path)
mkdir(path)
copy(src, to)
rename(from, to)
stat(path) -> FileStat
```

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    fs = sb.fs

    fs.mkdir("/tmp/fs-demo")
    fs.write("/tmp/fs-demo/input.txt", "hello from fs\n")
    fs.copy("/tmp/fs-demo/input.txt", "/tmp/fs-demo/copy.txt")
    fs.rename("/tmp/fs-demo/copy.txt", "/tmp/fs-demo/final.txt")

    print(fs.read_text("/tmp/fs-demo/input.txt"), end="")
    print(fs.read("/tmp/fs-demo/final.txt").decode("utf-8"), end="")
    print(fs.exists("/tmp/fs-demo/final.txt"))
    print(fs.stat("/tmp/fs-demo/final.txt").size)

    for entry in fs.list("/tmp/fs-demo"):
        print(entry.name)

    fs.remove("/tmp/fs-demo/final.txt")
```

Notes:

- `read()` returns `bytes`.
- `read_text()` returns `str` and accepts a configurable `encoding` argument, defaulting to `"utf-8"`.
- `write()` accepts `str` or `bytes`.
- `mkdir()` creates missing parent directories.
- `copy()` copies files; use `rename()` when you want move semantics.

### 3.28 `Process`

`Sandbox.process` provides a process namespace for execution operations.

Methods:

```python
run(command, env=None, timeout=None, cwd=None) -> ExecuteResult
run_code(language, code, *, env=None, timeout=None, cwd=None) -> ExecuteResult
stream(command) -> StreamIterator
```

Example:

```python
from mimobox import Sandbox

with Sandbox() as sb:
    shell_result = sb.process.run("echo shell")
    print(shell_result.stdout, end="")

    argv_result = sb.process.run(["printf", "%s\n", "argv"])
    print(argv_result.stdout, end="")

    code_result = sb.process.run_code("python", "print(6 * 7)")
    print(code_result.stdout, end="")

    for event in sb.process.stream("printf 'stream\\n'"):
        if event.stdout is not None:
            print(event.stdout.decode("utf-8"), end="")
```

Notes:

- `run()` accepts either `str` or `list[str]`.
- A `str` command delegates to `execute()` and uses shell-style execution.
- A `list[str]` command delegates to `exec()` and uses argv-style execution.
- `stream()` accepts only a shell command string and delegates to `stream_execute()`.

### 3.29 `SnapshotOps`

`Sandbox.snapshot` provides a snapshot namespace. It is also callable for
backward compatibility, so `sb.snapshot()` still captures a snapshot.

Methods:

```python
sb.snapshot() -> Snapshot
sb.snapshot.capture() -> Snapshot
sb.snapshot.fork() -> Sandbox
```

Example:

```python
from mimobox import Sandbox, Snapshot

with Sandbox(isolation="microvm") as sb:
    sb.write_file("/tmp/state.txt", b"snapshot state\n")

    snap_a = sb.snapshot()
    snap_b = sb.snapshot.capture()
    child = sb.snapshot.fork()

    try:
        print(snap_a.size)
        print(snap_b.size)
        print(child.read_file("/tmp/state.txt").decode("utf-8"), end="")
    finally:
        child.close()
```

Notes:

- `sb.snapshot()` and `sb.snapshot.capture()` are equivalent.
- `snapshot.fork()` delegates to `Sandbox.fork()` and returns an independent `Sandbox`.
- Snapshot support depends on backend capabilities; microVM is the intended backend for full snapshot behavior.

### 3.30 `Network`

`Sandbox.network` provides a network namespace for HTTP proxy requests.

Methods:

```python
request(method, url, headers=None, body=None) -> HttpResponse
```

Example:

```python
from mimobox import Sandbox

with Sandbox(
    network="allow_domains",
    allowed_http_domains=["example.com"],
) as sb:
    response = sb.network.request(
        "GET",
        "https://example.com",
        headers={"accept": "text/html"},
    )

    print(response.status)
    print(response.headers.get("content-type", ""))
    print(response.body[:80])
```

Notes:

- `request()` delegates to `http_request()`.
- `body` is `bytes | None`.
- Requests are subject to `network`, `allowed_http_domains`, and HTTP ACL configuration.

### 3.31 `PtySession`, `Pty`, `PtyOutput`, and `PtyExit`

`Sandbox.pty` provides interactive PTY sessions.

Methods and event objects:

```python
sb.pty.create(command, *, cols=80, rows=24, env=None, cwd=None, timeout=None) -> PtySession

PtySession.send_input(data)
PtySession.resize(cols, rows)
PtySession.kill()
PtySession.wait(*, timeout=None) -> int

PtyOutput.data -> bytes
PtyExit.code -> int
```

Example:

```python
from mimobox import PtyExit, PtyOutput, Sandbox

with Sandbox() as sb:
    with sb.pty.create(["/bin/sh"], cols=80, rows=24, timeout=10.0) as session:
        session.send_input("echo hello from pty\n")
        session.send_input("exit 0\n")

        for event in session:
            if isinstance(event, PtyOutput):
                print(event.data.decode("utf-8", errors="replace"), end="")
            elif isinstance(event, PtyExit):
                print(f"exit={event.code}")
                break
```

Notes:

- `command` can be `str` or `list[str]`.
- `send_input()` accepts `str` or `bytes`.
- Iterating a `PtySession` yields `PtyOutput` and `PtyExit` objects.
- `PtyOutput.data` is `bytes`.
- `PtyExit.code` is `int`.
- The context manager kills the PTY session on exit if it is still active.

### 3.32 HTTP ACL

`Sandbox` accepts HTTP ACL rules through `http_acl_allow` and
`http_acl_deny`. Rules use `"METHOD host/path"` format and support glob
patterns. Deny rules take precedence over allow rules.

Constructor parameters:

```python
Sandbox(
    *,
    http_acl_allow=None,
    http_acl_deny=None,
)
```

Example:

```python
from mimobox import Sandbox, SandboxHttpError

with Sandbox(
    http_acl_allow=[
        "GET example.com/*",
        "POST api.example.com/v1/*",
    ],
    http_acl_deny=[
        "* api.example.com/v1/admin/*",
    ],
) as sb:
    response = sb.http_request("GET", "https://example.com/")
    print(response.status)

    try:
        sb.http_request("POST", "https://api.example.com/v1/admin/delete")
    except SandboxHttpError as exc:
        print(f"denied: {exc.code}")
```

Notes:

- Rule format is `"METHOD host/path"`, for example `"GET api.example.com/v1/*"`.
- `METHOD` can be an HTTP method or `*`.
- The host and path part supports glob patterns.
- Deny rules are evaluated before allow rules.
- `allowed_http_domains` remains supported and can be used for domain-level allow lists.
- `network="allow_all"` is not compatible with HTTP ACL rules; use allow-domain style policy when applying ACLs.

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

Additional exception attributes and subclasses:

- `SandboxError.code: str | None`: Stable backend error code, such as `"command_timeout"`, or `None` when not provided.
- `SandboxError.suggestion: str | None`: Human-readable remediation suggestion, or `None` when not provided.
- `SandboxProcessError.exit_code: int`: Process exit code, or `-1` when the process was killed and no code is available.
- `SandboxProcessError.stdout: bytes`: Captured stdout bytes associated with the process failure.
- `SandboxProcessError.stderr: bytes`: Captured stderr bytes associated with the process failure.
- `SandboxMemoryError`: Raised when the memory limit is exceeded.
- `SandboxCpuLimitError`: Raised when the CPU limit is exceeded.
- `SandboxTimeoutError`: Raised on command or HTTP timeout.

Example:

```python
from mimobox import (
    Sandbox,
    SandboxCpuLimitError,
    SandboxError,
    SandboxMemoryError,
    SandboxProcessError,
    SandboxTimeoutError,
)

try:
    with Sandbox(memory_limit_mb=128, timeout_secs=5.0) as sb:
        sb.exec(["/bin/sh", "-c", "echo out; echo err >&2; exit 7"])
except SandboxProcessError as exc:
    print(exc.exit_code)
    print(exc.stdout.decode("utf-8", errors="replace"))
    print(exc.stderr.decode("utf-8", errors="replace"))
    print(exc.code)
    print(exc.suggestion)
except SandboxMemoryError as exc:
    print(f"memory limit exceeded: {exc.code}")
except SandboxCpuLimitError as exc:
    print(f"cpu limit exceeded: {exc.code}")
except SandboxTimeoutError as exc:
    print(f"operation timed out: {exc.code}")
except SandboxError as exc:
    print(f"sandbox failed: {exc.code} {exc.suggestion}")
```

Notes:

- Catch specific subclasses before `SandboxError`.
- `code` and `suggestion` are optional and may be `None`.
- `stdout` and `stderr` on `SandboxProcessError` are bytes, not strings.

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


### 6.8 Multi-Language Code Execution

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    # Python
    result = sb.execute_code("python", "import sys; print(sys.version)")
    print(result.stdout, end="")

    # Bash
    result = sb.execute_code("bash", "uname -a", timeout=5.0)
    print(result.stdout, end="")

    # JavaScript (requires Node.js in the sandbox)
    result = sb.execute_code("node", "console.log('hello from node')", cwd="/app")
    print(result.stdout, end="")
```

### 6.9 Directory Listing

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    sb.write_file("/tmp/test.txt", b"hello")

    entries = sb.list_dir("/tmp")
    for entry in entries:
        symlink_info = " -> symlink" if entry.is_symlink else ""
        print(f"{entry.name} ({entry.file_type}) - {entry.size} bytes{symlink_info}")
```

### 6.10 Snapshot from File

```python
from mimobox import Sandbox, Snapshot

# Save snapshot to disk
with Sandbox(isolation="microvm") as sb:
    sb.write_file("/tmp/state.txt", b"saved to disk")
    snapshot = sb.snapshot()
    with open("/tmp/snapshot.bin", "wb") as f:
        f.write(snapshot.to_bytes())

# Restore from file
snapshot = Snapshot.from_file("/tmp/snapshot.bin")
with Sandbox.from_snapshot(snapshot) as restored:
    data = restored.read_file("/tmp/state.txt")
    print(data.decode("utf-8"), end="")
```

### 6.11 PTY Session

```python
from mimobox import PtyExit, PtyOutput, Sandbox

with Sandbox(isolation="microvm") as sb:
    with sb.pty.create(["/bin/sh"], cols=100, rows=30, timeout=10.0) as session:
        session.send_input("echo interactive\n")
        session.resize(120, 40)
        session.send_input("exit 0\n")

        for event in session:
            if isinstance(event, PtyOutput):
                print(event.data.decode("utf-8", errors="replace"), end="")
            elif isinstance(event, PtyExit):
                print(f"exit={event.code}")
                break
```

### 6.12 HTTP ACL

```python
from mimobox import Sandbox, SandboxHttpError

with Sandbox(
    isolation="microvm",
    http_acl_allow=[
        "GET example.com/*",
        "POST api.example.com/v1/*",
    ],
    http_acl_deny=[
        "* api.example.com/v1/admin/*",
    ],
) as sb:
    response = sb.network.request("GET", "https://example.com/")
    print(response.status)

    try:
        sb.network.request("POST", "https://api.example.com/v1/admin/delete")
    except SandboxHttpError as exc:
        print(f"denied by ACL: {exc.code}")
```

### 6.13 File System Namespace

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    fs = sb.fs

    fs.mkdir("/tmp/project/data")
    fs.write("/tmp/project/data/input.txt", "hello\n")
    fs.copy("/tmp/project/data/input.txt", "/tmp/project/data/copy.txt")
    fs.rename("/tmp/project/data/copy.txt", "/tmp/project/data/final.txt")

    print(fs.read_text("/tmp/project/data/input.txt"), end="")
    print(fs.read("/tmp/project/data/final.txt").decode("utf-8"), end="")

    info = fs.stat("/tmp/project/data/final.txt")
    print(f"size={info.size}")

    for entry in fs.list("/tmp/project/data"):
        print(f"{entry.name}: {entry.file_type}")

    fs.remove("/tmp/project/data/final.txt")
    print(fs.exists("/tmp/project/data/final.txt"))
```

### 6.14 Argv Execution and Streaming

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    result = sb.exec(["printf", "%s\n", "hello from exec"])
    print(result.stdout, end="")

    sb.make_dir("/tmp/search")
    sb.write_file("/tmp/search/a.txt", b"needle\n")
    sb.write_file("/tmp/search/b.txt", b"haystack\nneedle\n")

    for event in sb.stream_exec(["grep", "-r", "needle", "/tmp/search"]):
        if event.stdout is not None:
            print(event.stdout.decode("utf-8", errors="replace"), end="")
        if event.stderr is not None:
            print(event.stderr.decode("utf-8", errors="replace"), end="")
        if event.exit_code is not None:
            print(f"exit={event.exit_code}")
```

### 6.15 Recursive Directory Creation

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    sb.make_dir("/tmp/a/b/c")
    sb.write_file("/tmp/a/b/c/result.txt", b"created recursively\n")

    stat = sb.stat("/tmp/a/b/c/result.txt")
    print(stat.path)
    print(stat.is_file)
    print(sb.read_file("/tmp/a/b/c/result.txt").decode("utf-8"), end="")
```
