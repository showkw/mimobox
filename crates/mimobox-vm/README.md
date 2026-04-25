# mimobox-vm

KVM microVM sandbox backend for mimobox Agent Sandbox.

`mimobox-vm` provides high-isolation Linux sandboxing using a lightweight microVM backend. It is designed for workloads that need stronger isolation than an OS-level sandbox while still keeping startup and restore latency low.

Repository: <https://github.com/showkw/mimobox>

## Performance

| Path | P50 |
| --- | ---: |
| Cold start | 253ms |
| Snapshot restore, pooled | 28ms |
| Warm pool acquire | 773us |

## Features

- Linux + KVM microVM lifecycle management.
- Guest command execution through a serial command protocol.
- Snapshot, restore, and fork workflows.
- Warm VM pools and restore pools for lower latency.
- Guest file transfer.
- Streaming execution output.
- Controlled HTTP proxy support.

## Quick Start

```rust
use mimobox_core::Sandbox;
use mimobox_vm::{MicrovmConfig, MicrovmSandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = MicrovmConfig::default();
    let mut sandbox = MicrovmSandbox::new(config)?;

    let result = sandbox.execute("/bin/echo hello from microvm")?;
    println!("{}", String::from_utf8_lossy(&result.stdout));

    sandbox.destroy()?;
    Ok(())
}
```

Most applications should use `mimobox-sdk` and select `IsolationLevel::MicroVm` instead of depending on this backend directly.

## Feature Flags

| Feature | Default | Description |
| --- | --- | --- |
| `kvm` | No | Enables the Linux KVM backend and virtio/vhost dependencies. |
| `zerocopy-fork` | No | Enables experimental zero-copy fork support. |
| `boot-profile` | No | Enables boot profiling instrumentation. |
| `guest-vsock` | No | Enables guest vsock data-plane experiments. |

## License

MIT OR Apache-2.0
