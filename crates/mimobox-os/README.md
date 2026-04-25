# mimobox-os

OS-level sandbox backend for mimobox Agent Sandbox.

`mimobox-os` provides low-latency process isolation for Linux and macOS. It is typically used through `mimobox-sdk`, but can also be used directly by backend integrators.

Repository: <https://github.com/showkw/mimobox>

## Platform Support

- Linux: Landlock, Seccomp, Namespaces, and `setrlimit`.
- macOS: Seatbelt through `sandbox-exec`.
- PTY support for interactive terminal sessions.
- `SandboxPool` for extremely fast reuse.

## Performance

| Path | P50 |
| --- | ---: |
| Cold start | 8.24ms |
| `SandboxPool` reuse | 0.19us |

## Quick Start

```rust
use mimobox_core::{Sandbox, SandboxConfig};

#[cfg(target_os = "linux")]
use mimobox_os::LinuxSandbox as OsSandbox;

#[cfg(target_os = "macos")]
use mimobox_os::MacOsSandbox as OsSandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SandboxConfig::default();
    let mut sandbox = OsSandbox::new(config)?;

    let result = sandbox.execute("/bin/echo hello from os sandbox")?;
    println!("{}", String::from_utf8_lossy(&result.stdout));

    sandbox.destroy()?;
    Ok(())
}
```

For application code, prefer `mimobox-sdk` and let smart routing select the OS backend automatically.

## Feature Flags

This crate does not define public feature flags. Platform-specific code is selected with Rust target configuration.

## License

MIT OR Apache-2.0
