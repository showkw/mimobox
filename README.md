[中文](README.zh-CN.md)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="logo.svg">
    <img alt="mimobox logo" src="logo.svg" width="120">
  </picture>
</p>

# mimobox

[![CI](https://github.com/showkw/mimobox/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/showkw/mimobox/actions/workflows/ci.yml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT) [![alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

**mimobox** — Run AI-generated code in secure isolated sandboxes. Locally. No API keys, no Docker, no cloud.

> **No API keys. No Docker. No cloud required.** Download a single binary and start executing code safely. OS-level + Wasm sandboxes work everywhere; microVM isolation available on Linux with KVM.

`mimobox` provides secure, self-hosted code execution for AI Agent workloads through one SDK, CLI, MCP server, and Python binding surface.

## Quick Start

> **Platform notes**: macOS supports OS-level and Wasm sandboxes only. microVM features require Linux with KVM (`/dev/kvm`). The MCP server binary is currently available for Linux only.

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/showkw/mimobox/master/scripts/install.sh | bash
```

### Python
> Python wheels are coming to PyPI. For now, build from source (requires Rust toolchain):

```bash
git clone https://github.com/showkw/mimobox.git && cd mimobox
cargo build --release -p mimobox-python
# wheel will be at target/wheels/
pip install target/wheels/*.whl
```

### Rust

```toml
[dependencies]
mimobox-sdk = { git = "https://github.com/showkw/mimobox.git", branch = "master" }
```

### From Source

```bash
git clone https://github.com/showkw/mimobox.git && cd mimobox
cargo build --release -p mimobox-cli --features mimobox-cli/wasm
```

### Run

```bash
mimobox run --backend auto --command "/bin/echo hello"
```

### Python

```python
from mimobox import Sandbox

with Sandbox() as sandbox:
    result = sandbox.execute("/bin/echo hello")
    print(result.stdout, end="")
```

### Rust

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello")?;
    println!("{}", String::from_utf8_lossy(&result.stdout));
    sandbox.destroy()?;
    Ok(())
}
```

For streaming, file operations, HTTP proxy, snapshot/fork, CLI examples, and advanced SDK usage, see [docs/getting-started.md](docs/getting-started.md).

> **Status**: mimobox is in **alpha** (v0.1.x). It has not undergone a formal security audit. See [SECURITY.md](SECURITY.md) for threat model and known limitations.

## Platform Support

| Platform | OS Sandbox | Wasm Sandbox | microVM Sandbox |
| --- | --- | --- | --- |
| Linux (x86_64) | Landlock + Seccomp + Namespaces | Wasmtime | KVM (requires `/dev/kvm` + guest assets) |
| macOS (ARM64, Intel) | Seatbelt | Wasmtime | Not available |

## Three-Layer Isolation

| Layer | Backend | Best For | Status |
| --- | --- | --- | --- |
| OS-level | Linux Landlock + Seccomp + namespaces; macOS Seatbelt | Fast local commands and default smart routing | Implemented |
| Wasm | Wasmtime + WASI | Deterministic portable workloads | Implemented |
| microVM | Linux KVM + guest protocol + pools + snapshot/fork | Strong isolation and Linux production workloads | Implemented on Linux (requires KVM + guest kernel + rootfs) |

Glossary and architecture details live in [docs/architecture.md](docs/architecture.md).

## Performance P50 Summary

| Scenario | Target | Current P50 | Status |
| --- | --- | --- | --- |
| OS-level cold start | <10ms | 8.24ms | Meets target |
| Wasm cold start | <5ms | 1.01ms | Meets target |
| OS warm pool acquisition | <100us | 0.19us | Meets target |
| microVM cold start | <300ms | 253ms | Meets target |
| microVM snapshot restore | <50ms | 69ms non-pooled / 28ms pooled | Pooled path meets target |
| microVM warm pool hot path | <1ms | 773us | Meets target |

Metric definitions, benchmark scope, and caveats are maintained in [docs/performance.md](docs/performance.md).

## Directory Structure

```text
mimobox/
├── Cargo.toml
├── README.md
├── CHANGELOG.md
├── crates/
│   ├── mimobox-core/       # Sandbox trait, config, result, and error types
│   ├── mimobox-os/         # OS-level sandbox backends
│   ├── mimobox-wasm/       # Wasmtime sandbox backend
│   ├── mimobox-vm/         # KVM microVM backend, pools, snapshot, fork
│   ├── mimobox-sdk/        # Unified Rust SDK and smart routing
│   ├── mimobox-cli/        # CLI entrypoint
│   ├── mimobox-mcp/        # MCP server over stdio
│   └── mimobox-python/     # Python SDK via PyO3
├── docs/                   # User, API, architecture, MCP, and performance docs
├── discuss/                # Design notes, reviews, and market analysis
├── examples/               # Example code
├── scripts/                # Build, test, run, and setup scripts
├── tests/                  # Integration tests
├── wit/                    # WIT interface definitions
└── logs/                   # Runtime logs
```

## Roadmap

| Status | Direction | Notes |
| --- | --- | --- |
| Completed | Unified SDK + smart routing | `Sandbox::new()` and CLI `--backend auto` are implemented |
| Completed | OS + Wasm + microVM isolation | Linux KVM, snapshot, restore, and fork are verifiable |
| Completed | MCP Server | 10 stdio tools for lifecycle, execution, files, snapshots, fork, and HTTP |
| Completed | Python SDK | PyO3 bindings with execution, streaming, files, HTTP, snapshot, and errors |
| Planned | Formal vsock data plane | Serial remains the bring-up/control path; vsock is the future data plane |
| Planned | Windows backend + GPU/SaaS options | Current priority remains Linux and macOS maturity |

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — SDK and CLI examples, including the removed README sections 6.1-6.5 and 8.
- [docs/architecture.md](docs/architecture.md) — architecture, smart routing, and glossary.
- [docs/performance.md](docs/performance.md) — metric definitions, benchmark methodology, and performance notes.
- [docs/api.md](docs/api.md) — Rust SDK API reference.
- [docs/python-sdk.md](docs/python-sdk.md) — Python SDK usage.
- [docs/mcp-server.md](docs/mcp-server.md) — MCP server setup, tools, and client integration.
- [docs/mcp-integration.md](docs/mcp-integration.md) — MCP integration notes.
- [discuss/competitive-analysis.md](discuss/competitive-analysis.md) — competitive comparison and market framing.
- [CHANGELOG.md](CHANGELOG.md) — release notes and moved README version history.

Competitive comparison is intentionally kept out of this README; see [discuss/competitive-analysis.md](discuss/competitive-analysis.md).
