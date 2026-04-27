# Examples

This directory contains minimal runnable examples for the `mimobox-sdk` Rust crate and the `mimobox` Python module.

## Rust Examples

- `basic.rs`: Basic command execution with `Sandbox::new()` and `execute`
- `streaming.rs`: Streaming execution with `stream_execute` and `Stdout` / `Stderr` / `Exit` event handling
- `agent_demo.rs`: Agent integration with preset requests, command generation, sandbox execution, and interactive mode
- `agent_streaming.rs`: Agent streaming execution with real-time `Stdout` / `Stderr` / `Exit` / `TimedOut` event processing
- `http_proxy.rs`: HTTP proxy with `allowed_http_domains` and `http_request`
- `env_vars.rs`: Environment variable injection with `execute_with_env`
- `file_ops.rs`: File read/write with `write_file` and `read_file`

Rust examples are registered in `crates/mimobox-sdk/Cargo.toml`. Verify with:

```bash
cd crates/mimobox-sdk
cargo check --examples
cargo check --examples --features vm
```

Notes:

- `basic.rs` uses the default backend, suitable for verifying the basic SDK execution path first
- `agent_demo.rs` uses the OS backend and supports Linux/macOS; add `--interactive` for interactive mode
- `streaming.rs`, `agent_streaming.rs`, `http_proxy.rs`, `env_vars.rs`, and `file_ops.rs` require Linux + `vm` feature
- In environments without microVM support, these examples print a notice but still pass `cargo check --examples`

## Python Examples

- `python_basic.py`: Single-file demo covering command execution, streaming output, HTTP requests, file read/write, and environment variable injection

Install the Python bindings first, then run:

```bash
cd crates/mimobox-python
pip install -e .
python ../../examples/python_basic.py
```

Notes:

- The Python example demonstrates basic command execution by default
- microVM-dependent features are explicitly requested via `Sandbox(isolation="microvm", allowed_http_domains=[...])`
- If the platform or build does not support microVM, the example prints an appropriate notice
