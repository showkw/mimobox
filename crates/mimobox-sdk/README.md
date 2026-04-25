# mimobox-sdk

Unified Rust SDK for mimobox sandboxing across OS, Wasm, and microVM backends.

`mimobox-sdk` wraps `mimobox-core` traits and routes to `mimobox-os`,
`mimobox-wasm`, or `mimobox-vm` by config, platform, and enabled features.

Repository: <https://github.com/showkw/mimobox>

## Quick Start

Zero-config routing picks the best available backend.

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

## Advanced Configuration

Use `Config::builder()` for explicit isolation, network, timeout, or resources.

```rust
use mimobox_sdk::{Config, IsolationLevel, NetworkPolicy, Sandbox, TrustLevel};

let config = Config::builder()
    .isolation(IsolationLevel::Os)
    .trust_level(TrustLevel::Untrusted)
    .network(NetworkPolicy::DenyAll)
    .memory_limit_mb(256)
    .build();
let mut sandbox = Sandbox::with_config(config)?;
```

## API Surface

Core: `Sandbox`, `Config`, `ConfigBuilder`, `IsolationLevel`, `NetworkPolicy`, and `TrustLevel`.
Results: `ExecuteResult`, `StreamEvent`, `HttpResponse`, `SandboxSnapshot`, and `PtySession`.

Additional APIs: `stream_execute`, `http_request`, `snapshot`, `from_snapshot`,
`fork`, `read_file`, `write_file`, and `create_pty`.

## Feature Flags

| Feature | Default | Backend |
| --- | --- | --- |
| `os` | yes | OS-level isolation on Linux/macOS |
| `vm` | no | microVM isolation on Linux + KVM |
| `wasm` | no | Wasm execution through Wasmtime |
| `full` | no | Enables `os`, `vm`, and `wasm` |

## License
MIT OR Apache-2.0
