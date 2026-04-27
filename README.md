[中文](README.zh-CN.md)

# MimoBox

[![CI](https://github.com/showkw/mimobox/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/showkw/mimobox/actions/workflows/ci.yml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT) [![alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

**Run AI-generated code safely, locally, and instantly.**

No API keys. No Docker. No cloud.

MimoBox is a local sandbox runtime for AI agents. It provides multi-layer isolation — OS (Landlock + Seccomp), WebAssembly (Wasmtime), and microVM (KVM) — through a unified SDK, CLI, MCP server, and Python binding. Download a single binary and start executing code safely.

---

## Why MimoBox?

- **Local-first** — Runs entirely on your machine. No data leaves your network, no API keys required.
- **Multi-layer isolation** — OS-level (Landlock + Seccomp + Namespaces), Wasm (Wasmtime), and microVM (KVM) backends with smart auto-routing.
- **Ultra-low latency** — OS cold start P50 8.24 ms, Wasm cold start P50 1.01 ms, warm pool acquire P50 0.19 µs.
- **Agent-native** — MCP server with 11 tools, Python SDK, LangChain / OpenAI Agents SDK integration out of the box.

## Quick Start

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/showkw/mimobox/master/scripts/install.sh | bash
```

### Python

```bash
pip install mimobox
```

### Rust

```toml
[dependencies]
mimobox-sdk = "0.1.0-alpha"
```

### MCP Server

```bash
mimobox-mcp                              # stdio mode (default)
mimobox-mcp --transport http --port 8080 # Streamable HTTP mode
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "mimobox": {
      "command": "mimobox-mcp"
    }
  }
}
```

## Integration Examples

### LangChain

```python
from mimobox import Sandbox
from langchain_core.tools import tool

@tool
def sandbox_run_command(command: str) -> str:
    """Run a command inside a secure sandbox."""
    with Sandbox() as sb:
        return sb.execute(command).stdout
```

### OpenAI Agents SDK

```python
from mimobox import Sandbox
from agents import function_tool

@function_tool
def sandbox_execute(command: str) -> str:
    """Run a command inside a secure sandbox."""
    with Sandbox() as sb:
        return sb.execute(command).stdout
```

### Python SDK

```python
from mimobox import Sandbox

with Sandbox() as sandbox:
    result = sandbox.execute("/bin/echo hello")
    print(result.stdout, end="")
```

```python
# File API
with Sandbox() as sandbox:
    sandbox.write_file("/tmp/hello.py", "print('hello')")
    result = sandbox.execute("python3 /tmp/hello.py")
    entries = sandbox.list_dir("/tmp")
```

## Platform Support

| Platform | OS Sandbox | Wasm Sandbox | microVM Sandbox |
| --- | --- | --- | --- |
| Linux (x86_64) | Landlock + Seccomp + Namespaces | Wasmtime | KVM (requires `/dev/kvm` + guest assets) |
| macOS (ARM64, Intel) | Seatbelt | Wasmtime | Not available |

## Isolation Layers

| Layer | Backend | Best For |
| --- | --- | --- |
| OS-level | Linux Landlock + Seccomp + Namespaces; macOS Seatbelt | Fast local commands, default smart routing |
| Wasm | Wasmtime + WASI | Deterministic portable workloads |
| microVM | Linux KVM + guest protocol + pools + snapshot/fork | Strong isolation, production workloads |

## Performance

| Metric | P50 |
| --- | ---:|
| OS cold start | 8.24 ms |
| Wasm cold start | 1.01 ms |
| Warm pool acquire | 0.19 µs |
| microVM cold start | 253 ms |
| microVM snapshot restore (pooled) | 28 ms |

> **Status**: MimoBox is in **alpha** (v0.1.x). It has not undergone a formal security audit. See [SECURITY.md](SECURITY.md) for threat model and known limitations.

## Documentation

- [Getting Started](docs/getting-started.md) — Installation, CLI usage, and SDK examples
- [Architecture](docs/architecture.md) — Workspace structure and smart routing
- [API Reference](docs/api.md) — Rust SDK types and methods
- [Python SDK](docs/python-sdk.md) — Python binding installation and usage
- [MCP Server](docs/mcp-server.md) — Tool reference and client integration
- [MCP Configuration](docs/mcp-config.md) — Templates for Claude Desktop, Cursor, VS Code
- [Performance](docs/performance.md) — Benchmark methodology and detailed metrics
- [FAQ & Troubleshooting](docs/faq.md) — Common issues and solutions

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
