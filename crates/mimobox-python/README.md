# MimoBox Python SDK

PyO3 Python bindings for mimobox sandbox execution with context manager support.

Repository: <https://github.com/showkw/mimobox>

## Architecture

`mimobox-python` is a thin Python wrapper over `mimobox-sdk`; Rust owns backend selection, isolation, lifecycle, streaming, snapshots, files, and HTTP proxying.

```bash
maturin develop -m crates/mimobox-python/Cargo.toml
```

## Quick Example

```python
from mimobox import Sandbox

with Sandbox(isolation="auto") as sandbox:
    result = sandbox.execute("echo hello", timeout=5.0)
    print(result.stdout)
```

Streaming output:

```python
from mimobox import Sandbox

with Sandbox(isolation="os") as sandbox:
    for event in sandbox.stream_execute("printf 'a\\nb\\n'"):
        if event.stdout:
            print(event.stdout.decode(), end="")
```

## API

| API | Purpose |
| --- | --- |
| `execute`, `stream_execute` | Run commands normally or as events. |
| `read_file`, `write_file` | Transfer sandbox files as bytes. |
| `snapshot`, `from_snapshot`, `fork` | Capture, restore, or copy state. |
| `http_request` | Use the whitelisted host HTTP proxy. |
| `wait_ready`, `is_ready`, `close` | Manage lifecycle and readiness. |

| Isolation | Meaning |
| --- | --- |
| `auto` | Let mimobox choose the backend. |
| `os` | Use the OS sandbox backend. |
| `wasm` | Use the Wasm backend. |
| `microvm` | Use the microVM backend. |

## Exceptions

`SandboxError` is the base exception; `SandboxProcessError`, `SandboxHttpError`, and `SandboxLifecycleError` derive from it.

## License

MIT OR Apache-2.0
