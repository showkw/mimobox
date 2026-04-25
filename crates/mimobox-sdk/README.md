# mimobox-sdk

Unified Rust SDK for mimobox Agent Sandbox with smart routing.

`mimobox-sdk` is the recommended entry point for Rust applications. It exposes a single API over multiple sandbox backends and automatically routes workloads to the appropriate isolation layer unless you explicitly choose one.

Repository: <https://github.com/showkw/mimobox>

## Quick Start

Zero-config auto routing:

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello from mimobox")?;

    println!("exit: {:?}", result.exit_code);
    println!("stdout: {}", String::from_utf8_lossy(&result.stdout));

    sandbox.destroy()?;
    Ok(())
}
```

Advanced configuration:

```rust
use mimobox_sdk::{Config, IsolationLevel, NetworkPolicy, Sandbox, TrustLevel};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::Os)
        .trust_level(TrustLevel::Untrusted)
        .network(NetworkPolicy::DenyAll)
        .timeout(Duration::from_secs(5))
        .memory_limit_mb(256)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let result = sandbox.execute("/usr/bin/env")?;
    println!("{}", String::from_utf8_lossy(&result.stdout));
    Ok(())
}
```

## Smart Routing

Smart routing selects a backend based on configuration, platform support, and workload hints.

- `Auto` chooses the safest available default for common command execution.
- `.wasm`, `.wat`, and `.wast` workloads are routed to the Wasm backend when enabled.
- `MicroVm` can be selected explicitly for high-isolation Linux + KVM workloads.
- `Os` can be selected explicitly for low-latency local process isolation.

## Additional APIs

`Sandbox` also exposes advanced operations:

- `stream_execute` for stdout/stderr streaming.
- `http_request` for controlled host-side HTTP proxying.
- `execute_with_env_and_timeout` for per-command environment and timeout control.
- `snapshot`, `restore`, and `fork` for microVM state workflows.
- `read_file` and `write_file` for backend-supported file transfer.

## Feature Flags

| Feature | Default | Description |
| --- | --- | --- |
| `os` | Yes | OS-level backend for Linux and macOS. |
| `vm` | No | microVM backend for Linux + KVM. |
| `wasm` | No | Wasm backend powered by Wasmtime. |

Example enabling all backends:

```toml
[dependencies]
mimobox-sdk = { version = "0.1", features = ["vm", "wasm"] }
```

## License

MIT OR Apache-2.0
