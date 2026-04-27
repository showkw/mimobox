# MimoBox FAQ & Troubleshooting

## Installation

### Q: `install.sh` returns 404 / prebuilt binaries not found. What should I do?

Prebuilt release binaries may not be published yet. Build from source instead, following the setup in [getting-started](getting-started.md).

```bash
git clone https://github.com/showkw/mimobox.git
cd mimobox
cargo build --workspace --release
```

### Q: `pip install mimobox` fails. Is the Python package available on PyPI?

The Python package is published on [PyPI](https://pypi.org/project/mimobox/). Install it directly:

```bash
pip install mimobox
```

If `pip install` fails, ensure your Python version is 3.8 or newer. To build from source instead, use `maturin`:

```bash
git clone https://github.com/showkw/mimobox.git
cd mimobox
maturin build --release -m crates/mimobox-python/Cargo.toml
pip install target/wheels/*.whl
```

### Q: `cargo build` fails with linking errors. What is missing?

Install a C compiler, linker, and required system development libraries for your platform. On Linux, also verify that common system paths such as `/usr`, `/bin`, and `/proc` exist for sandbox tests.

```bash
cargo build --workspace
```

### Q: The Wasm feature is not found, or `mimobox-wasm` is missing. Why?

The default workspace build excludes `mimobox-wasm`. Enable Wasm explicitly for both the CLI and SDK, as described in [getting-started](getting-started.md).

```bash
cargo build --workspace --features mimobox-cli/wasm,mimobox-sdk/wasm
```

### Q: How do I build with both Wasm and microVM support?

Use the CLI feature names and SDK feature names together. The CLI microVM feature is `kvm`; the SDK feature is `vm`.

```bash
cargo build --workspace --features mimobox-cli/kvm,mimobox-cli/wasm,mimobox-sdk/vm,mimobox-sdk/wasm
```

## Platform & Features

### Q: Which platforms are supported?

| Platform | OS Sandbox | Wasm Sandbox | microVM Sandbox |
| --- | --- | --- | --- |
| Linux (x86_64) | Landlock + Seccomp + Namespaces | Wasmtime | KVM (requires `/dev/kvm` + guest assets) |
| macOS (ARM64, Intel) | Seatbelt | Wasmtime | Not available |

See [README](../README.md) and [architecture](architecture.md) for the current support model.

### Q: Does macOS support microVM?

No. microVM requires Linux with KVM. On macOS, mimobox supports OS-level Seatbelt sandboxing and Wasm only; microVM, snapshot, fork, and VM file operations are not available.

### Q: Landlock or Seccomp fails on Linux. What should I check?

Landlock requires Linux kernel 5.13 or newer. Full Linux sandbox validation also expects cgroups v2, standard system paths, and appropriate privileges for sandbox tests; see [SECURITY](../SECURITY.md).

### Q: `stream_execute`, `read_file`, or `write_file` returns `UnsupportedPlatform`. Why?

These operations are microVM-only. They require Linux + KVM and a build with VM support; on macOS they return `UnsupportedPlatform` by design.

### Q: What backend should I use for default local execution?

Use the OS backend or automatic routing first. The OS backend is the default path for fast local commands; use Wasm for portable deterministic workloads and microVM for stronger Linux isolation.

## MCP Server

### Q: Claude Desktop shows the MCP server as not responding. How do I fix it?

Verify that `command` points to an executable `mimobox-mcp` binary. Use an absolute path or place the binary in `$PATH`, then fully restart Claude Desktop; see [mcp-integration](mcp-integration.md).

```json
{
  "mcpServers": {
    "mimobox": {
      "command": "/usr/local/bin/mimobox-mcp",
      "args": [],
      "env": { "RUST_LOG": "info" }
    }
  }
}
```

### Q: VM tools return `backend unavailable`. What does that mean?

You are likely running the default MCP binary without VM support. Use the VM binary variant or build `mimobox-mcp` from source with `--features vm`; see [mcp-server](mcp-server.md).

```bash
cargo build --release -p mimobox-mcp --features vm
```

### Q: How do I configure MCP for Cursor or Windsurf?

Use the CLI helper after installing `mimobox` and `mimobox-mcp`. These commands write the client-specific MCP configuration.

```bash
mimobox mcp init cursor
mimobox mcp init windsurf
```

### Q: Can I run the MCP server on macOS?

Not currently. The `mimobox-mcp` binary is Linux-only at this time; macOS users can use the CLI and SDK, but not the MCP server.

### Q: Which MCP tools require the VM feature?

`read_file`, `write_file`, `snapshot`, `fork`, and `http_request` require the `vm` feature. Default MCP builds expose OS-level lifecycle and execution tools only.

## Security

### Q: Is mimobox production-ready?

mimobox is currently alpha software (`v0.1.x`) and has not undergone a formal third-party security audit. Review [SECURITY](../SECURITY.md) before using it with sensitive or high-risk workloads.

### Q: How does sandbox isolation work?

mimobox uses three layers: OS isolation with Landlock + Seccomp + Namespaces on Linux or Seatbelt on macOS, Wasm isolation with Wasmtime + WASI, and microVM isolation with KVM hardware virtualization on Linux.

### Q: Is network access allowed by default?

No. Network access is denied by default across layers. microVM HTTP egress goes through a controlled host proxy with allowlists, DNS rebinding protection, body size limits, and HTTPS-only enforcement.

## Performance

### Q: microVM cold start is slow, around 253ms. How can I improve it?

Use microVM warm pools for the hot path, which is around 773us P50, or pooled snapshot restore, which is around 28ms P50. Cold start around 253ms is expected for full microVM creation.

### Q: How do I reduce memory usage?

Tune `memory_limit_mb` for the unified sandbox limit and `vm_memory_mb` for guest memory. On the microVM path, the smaller effective limit controls guest memory.

```json
{
  "memory_limit_mb": 256,
  "vm_memory_mb": 256
}
```

### Q: When should I choose OS, Wasm, or microVM for performance?

Use OS isolation for low-latency local execution, Wasm for small deterministic workloads, and microVM when isolation strength matters more than cold-start latency. See [getting-started](getting-started.md) for benchmark context.
