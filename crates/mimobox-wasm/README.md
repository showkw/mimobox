# MimoBox Wasm Backend

Wasm sandbox backend for mimobox, powered by Wasmtime and the Cranelift JIT.

Repository: <https://github.com/showkw/mimobox>

## Architecture

`mimobox-wasm` implements `mimobox_core::Sandbox` for WebAssembly workloads and is used through `mimobox-sdk` when callers select Wasm or when the SDK auto-routes `.wasm`, `.wat`, and `.wast` inputs.

It uses a shared Wasmtime engine, WASI Preview 1, per-run stores, resource limits, stdout/stderr capture, fuel plus epoch interruption, and a SHA256 module cache.

## Features

- Wasmtime runtime with Cranelift JIT compilation.
- WASI Preview 1 capability surface.
- SHA256 content-addressed module cache.
- Cold start P50: 1.01ms.
- Feature gate: `wasm` for downstream backend selection.

## Quick Example

Direct backend usage:

```rust
use mimobox_core::{Sandbox, SandboxConfig};
use mimobox_wasm::WasmSandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = WasmSandbox::new(SandboxConfig::default())?;
    let result = sandbox.execute("./module.wasm")?;
    println!("exit: {:?}", result.exit_code);
    sandbox.destroy()?;
    Ok(())
}
```

Via `mimobox-sdk`:

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder().isolation(IsolationLevel::Wasm).build();
    let result = Sandbox::with_config(config)?.execute("./module.wasm")?;
    println!("exit: {:?}", result.exit_code);
    Ok(())
}
```

## License

MIT OR Apache-2.0
