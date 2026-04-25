# mimobox-core

Core traits and shared types for the mimobox sandbox system.

`mimobox-core` is the foundation trait crate: backends implement its contracts, while SDK and higher-level crates consume its backend-neutral types. It does not create sandboxes, spawn processes, or select a backend; application code should usually start with `mimobox-sdk`.

Repository: <https://github.com/showkw/mimobox>

## Responsibilities

- Define backend-neutral traits, data structures, and cross-crate config.
- Keep errors consistent across OS, VM, WASM, and MCP layers.
- Avoid platform-specific behavior and runtime dependencies.

## Key Types

- `Sandbox`, `SandboxConfig`, `SandboxResult`: backend contract, config, and execution result.
- `SandboxError` / `ErrorCode`: structured failures and stable error codes.
- `SandboxSnapshot`: opaque snapshot and restore handle.
- `IsolationLevel` / `TrustLevel`: routing and trust policy inputs.

## When To Use It

Use this crate directly when implementing a backend, sharing types across mimobox crates, or testing backend contracts.

Do not use it as the primary application entry point; `mimobox-sdk` owns backend selection and convenience APIs.

## SDK Example

```rust
use mimobox_sdk::{Config, Sandbox, TrustLevel};
let config = Config::builder().trust_level(TrustLevel::Untrusted).build();
let mut sandbox = Sandbox::with_config(config)?;
let result = sandbox.execute("/bin/echo hi")?;
println!("{}", String::from_utf8_lossy(&result.stdout));
```

## Backend Impl Example

```rust
use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};
struct Backend;
impl Sandbox for Backend {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let _ = config;
        Ok(Self)
    }
    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        let _ = cmd;
        Err(SandboxError::Unsupported)
    }
}
```

## License

MIT OR Apache-2.0
