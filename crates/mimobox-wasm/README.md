# mimobox-wasm

Wasm sandbox backend for mimobox Agent Sandbox, powered by Wasmtime.

`mimobox-wasm` provides fast startup and strong capability-oriented isolation for WebAssembly workloads. It is suitable for running trusted or untrusted Wasm modules with explicit WASI capabilities.

Repository: <https://github.com/showkw/mimobox>

## Features

- Wasmtime with Cranelift JIT.
- WASI Preview 2 support.
- Component Model support.
- Content-hash-based module cache.
- Cold start P50: 1.01ms.

The SDK auto-routes `.wasm`, `.wat`, and `.wast` files to this backend when the Wasm backend is enabled.

## Quick Start

```rust
use mimobox_core::{Sandbox, SandboxConfig};
use mimobox_wasm::WasmSandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SandboxConfig::default();
    let mut sandbox = WasmSandbox::new(config)?;

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
    let config = Config::builder()
        .isolation(IsolationLevel::Wasm)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let result = sandbox.execute("./module.wasm")?;
    println!("exit: {:?}", result.exit_code);
    Ok(())
}
```

## Feature Flags

| Feature | Default | Description |
| --- | --- | --- |
| `wasm` | No | Enables the public Wasm backend feature gate for downstream selection. |

## License

MIT OR Apache-2.0
