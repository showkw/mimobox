# mimobox-core

Core traits and shared types for mimobox Agent Sandbox.

`mimobox-core` defines the stable interface implemented by all mimobox sandbox backends. It does not provide a concrete sandbox implementation. Most users should start with `mimobox-sdk`, which provides smart routing and backend selection.

Repository: <https://github.com/showkw/mimobox>

## Key Types

- `Sandbox` trait: common backend interface for create, execute, file transfer, snapshot, fork, and destroy operations.
- `SandboxConfig`: backend-neutral sandbox configuration.
- `SandboxResult`: command execution output, exit status, timeout flag, and elapsed time.
- `SandboxError` and `ErrorCode`: structured error model shared by backends.
- `SandboxSnapshot`: opaque snapshot handle for backends that support snapshot and restore workflows.
- `IsolationLevel`: high-level isolation selection used by the SDK.
- `TrustLevel`: trust policy input used by the SDK router and configuration layer.

## Quick Start

Most applications should use `mimobox-sdk`:

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello")?;
    println!("{}", String::from_utf8_lossy(&result.stdout));
    Ok(())
}
```

## Minimal Backend Implementation

Implement `Sandbox` when building a custom backend:

```rust
use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};
use std::time::Duration;

struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn new(_config: SandboxConfig) -> Result<Self, SandboxError> {
        Ok(Self)
    }

    fn execute(&mut self, _command: &str) -> Result<SandboxResult, SandboxError> {
        Ok(SandboxResult {
            stdout: b"noop".to_vec(),
            stderr: Vec::new(),
            exit_code: Some(0),
            elapsed: Duration::from_millis(0),
            timed_out: false,
        })
    }

    fn destroy(self) -> Result<(), SandboxError> {
        Ok(())
    }
}
```

## Feature Flags

This crate does not define feature flags. Backend-specific features live in `mimobox-os`, `mimobox-vm`, `mimobox-wasm`, and `mimobox-sdk`.

## License

MIT OR Apache-2.0
