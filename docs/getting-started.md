# mimobox Getting Started

## 1. Introduction

`mimobox` is a cross-platform Agent Sandbox implemented in Rust for secure code execution scenarios used by AI Agent workloads. It provides a unified abstraction over three isolation layers: OS, Wasm, and microVM. It aims for strict, controllable isolation boundaries while preserving high performance: OS cold start P50 8.24ms, Wasm cold start P50 1.01ms, and microVM cold start P50 253ms. It also supports warm pools and snapshot restore paths.

## 2. Installation

### 2.1 Prerequisites

- Rust 1.82+
- KVM support is required when enabling microVM on Linux
- Full sandbox tests on Linux should have `sudo` privileges, cgroups v2, and common system paths (`/usr`, `/bin`, `/proc`, etc.)
- macOS currently supports the OS backend; Windows is still planned

### 2.2 Basic Build

Run this from the repository root:

```bash
cargo build --workspace
```

This builds the default workspace members. By default, it focuses on the OS backend and does not include the Wasm crate or the microVM CLI feature.

### 2.3 Feature Notes

The current repository has two layers of feature names. They are not a single unified global switch, so keep the distinction clear:

- Default build: run `cargo build --workspace` directly
  - `mimobox-sdk` enables `os` by default
  - The default workspace members do not include `mimobox-wasm`
  - Suitable for validating OS capabilities and the basic SDK interfaces first
- `kvm`: the microVM switch at the CLI layer
  - `mimobox-cli` uses `kvm`
  - The corresponding feature in `mimobox-sdk` is `vm`, not `kvm`
  - Common build command:

```bash
cargo build --workspace --features mimobox-cli/kvm,mimobox-sdk/vm
```

- `wasm`: the Wasm backend switch
  - `mimobox-cli` uses `wasm`
  - `mimobox-sdk` also uses `wasm`
  - Because the workspace excludes `mimobox-wasm` by default, enable it explicitly:

```bash
cargo build --workspace --features mimobox-cli/wasm,mimobox-sdk/wasm
```

If you want to enable both Wasm and microVM:

```bash
cargo build --workspace --features mimobox-cli/kvm,mimobox-cli/wasm,mimobox-sdk/vm,mimobox-sdk/wasm
```

## 3. 30-Second Start (Rust SDK)

The example below is adjusted to the current `mimobox-sdk` API and is compilable. Note: `exit_code` is `Option<i32>` in the current SDK, so it cannot be formatted directly as an integer.

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("python3 -c 'print(42)'")?;

    println!(
        "exit: {:?}, stdout: {}",
        result.exit_code,
        String::from_utf8_lossy(&result.stdout)
    );

    sandbox.destroy()?;
    Ok(())
}
```

If you only want to quickly verify command execution and do not care whether Python exists, using `/bin/echo` is more reliable:

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello")?;

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&result.stdout), "hello\n");

    sandbox.destroy()?;
    Ok(())
}
```

## 4. Core Feature Examples

### 4.1 Command Execution (`execute`)

#### Basic Usage

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo mimobox")?;

    println!("stdout = {}", String::from_utf8_lossy(&result.stdout));
    println!("stderr = {}", String::from_utf8_lossy(&result.stderr));
    println!("exit_code = {:?}", result.exit_code);
    println!("timed_out = {}", result.timed_out);
    println!("elapsed = {:?}", result.elapsed);

    sandbox.destroy()?;
    Ok(())
}
```

#### Timeout Settings

`Config.timeout` is the unified SDK-level timeout. It is currently rounded up to seconds before being passed to the underlying sandbox.

```rust
use std::time::Duration;

use mimobox_sdk::{Config, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .timeout(Duration::from_secs(2))
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let result = sandbox.execute("python3 -c 'import time; time.sleep(1); print(42)'")?;

    assert_eq!(result.exit_code, Some(0));
    assert!(!result.timed_out);

    sandbox.destroy()?;
    Ok(())
}
```

### 4.2 Streaming Output (`stream_execute`)

`stream_execute` currently supports only the microVM backend on Linux. Calls against the OS and Wasm backends return `UnsupportedPlatform`.

#### Iterator Mode

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let receiver = sandbox.stream_execute("/bin/sh -c 'echo start; echo err >&2; echo done'")?;

    for event in receiver {
        match event {
            StreamEvent::Stdout(chunk) => {
                print!("{}", String::from_utf8_lossy(&chunk));
            }
            StreamEvent::Stderr(chunk) => {
                eprint!("{}", String::from_utf8_lossy(&chunk));
            }
            StreamEvent::Exit(code) => {
                println!("exit = {code}");
            }
            StreamEvent::TimedOut => {
                println!("command timed out");
            }
        }
    }

    sandbox.destroy()?;
    Ok(())
}
```

#### Suitable for Long-Running Commands

Suitable scenarios:

- `pip install`
- Builds with long logs
- Model download or training scripts
- Agent tasks that need to consume output while the command is still running

Unsuitable scenarios:

- One-off short commands; use `execute` directly
- Non-Linux environments or builds without microVM enabled

### 4.3 File Operations (`read_file` / `write_file`)

File transfer currently supports only the microVM backend on Linux. When these two APIs are called with `IsolationLevel::Auto`, the microVM path is also forced.

#### Read and Write Files Inside the Sandbox

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    sandbox.write_file("/tmp/message.txt", b"hello from host\n")?;

    let result = sandbox.execute("/bin/cat /tmp/message.txt")?;
    assert_eq!(String::from_utf8_lossy(&result.stdout), "hello from host\n");

    let content = sandbox.read_file("/tmp/message.txt")?;
    assert_eq!(content, b"hello from host\n");

    sandbox.destroy()?;
    Ok(())
}
```

### 4.4 HTTP Proxy (`http_request`)

The HTTP proxy currently supports only the microVM backend on Linux and executes requests through a host proxy. The documentation must make two facts clear:

- The default network policy still denies all network access
- `allowed_http_domains` is a domain allowlist at the host proxy layer; it does not mean “arbitrary networking is enabled inside the sandbox”

#### Domain Allowlist Configuration

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .allowed_http_domains(["api.github.com"])
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "mimobox-example".to_string());

    let response = sandbox.http_request(
        "GET",
        "https://api.github.com",
        headers,
        None,
    )?;

    println!("status = {}", response.status);
    println!("body bytes = {}", response.body.len());

    sandbox.destroy()?;
    Ok(())
}
```

#### Calling External APIs

Recommended practice:

- Add only the necessary domains to `allowed_http_domains`
- Handle request body size, timeouts, and error responses explicitly
- Do not describe this API as a general substitute for enabling arbitrary networking

### 4.5 Python SDK

The current Python binding crate is named `mimobox-python`. The exported Python module is named `mimobox`, and it is built with `PyO3 + maturin`.

#### Installation Methods

Method one: install the development version directly from the binding directory

```bash
cd crates/mimobox-python
pip install -e .
```

Method two: use `maturin` explicitly

```bash
cd crates/mimobox-python
maturin develop
```

#### Basic Usage Example

```python
from mimobox import Sandbox


def main() -> None:
    with Sandbox() as sandbox:
        result = sandbox.execute("/bin/echo hello-from-python")
        print(result.stdout, end="")
        print(result.exit_code)


if __name__ == "__main__":
    main()
```

#### Current Python API Status

- `Sandbox()` is currently equivalent to `Sandbox::new()` on the Rust side and does not expose a separate `ConfigBuilder`
- `execute(command: str)` returns `ExecuteResult`
- `stream_execute(command: str)` returns a Python iterator
- `read_file` / `write_file` / `http_request` are exposed
- `stdout` / `stderr` are decoded with UTF-8 lossy decoding on the Python side
- When the exit code is missing, the Python side maps `exit_code` to `-1`

## 5. Configuration Reference

The current fields of `mimobox_sdk::Config` are as follows.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `isolation` | `IsolationLevel` | `Auto` | Isolation layer selection |
| `trust_level` | `TrustLevel` | `SemiTrusted` | Affects `Auto` routing |
| `network` | `NetworkPolicy` | `DenyAll` | Network policy abstraction |
| `timeout` | `Option<Duration>` | `Some(30s)` | Execution timeout |
| `memory_limit_mb` | `Option<u64>` | `Some(512)` | Unified memory limit |
| `fs_readonly` | `Vec<PathBuf>` | `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/dev`, `/proc`, `/etc` | Read-only mount paths inside the sandbox |
| `fs_readwrite` | `Vec<PathBuf>` | `/tmp` | Read-write paths inside the sandbox |
| `allowed_http_domains` | `Vec<String>` | empty | host HTTP proxy allowlist |
| `allow_fork` | `bool` | `false` | Whether fork is allowed |
| `vm_vcpu_count` | `u8` | `1` | Number of microVM vCPUs |
| `vm_memory_mb` | `u32` | `256` | microVM Guest memory |
| `kernel_path` | `Option<PathBuf>` | `None` | Custom microVM kernel path |
| `rootfs_path` | `Option<PathBuf>` | `None` | Custom microVM rootfs path |

### 5.1 Common Field Notes

#### `timeout`

- Applies to command execution timeout
- Currently rounded up to seconds when converted for the underlying backend
- For example, `1500ms` maps to `2s`

#### `memory_limit_mb`

- It is the unified resource limit
- On the microVM path, the smaller value between this and `vm_memory_mb` is used
- For example, when `memory_limit_mb = 256` and `vm_memory_mb = 768`, the final guest memory is `256MB`

#### `vm_memory_mb`

- Applies only to the microVM backend
- Default value is `256MB`
- If the kernel and rootfs paths are not explicitly overridden, the backend default paths are used:
  - `VM_ASSETS_DIR/vmlinux`
  - `VM_ASSETS_DIR/rootfs.cpio.gz`
  - If `VM_ASSETS_DIR` is not set, it falls back to `~/.mimobox/assets/`

#### `allowed_http_domains`

- Used for the host HTTP proxy allowlist
- Not a general networking allow switch
- Should be used together with `IsolationLevel::MicroVm`

#### `network`

- `NetworkPolicy::DenyAll`: denies all network access
- `NetworkPolicy::AllowDomains([...])`: keeps direct networking inside the sandbox disabled and allows access to allowlisted domains only through the host HTTP proxy
- `NetworkPolicy::AllowAll`: allows arbitrary network access
- When `trust_level = TrustLevel::Untrusted` and the current platform does not support microVM, the SDK returns an error directly and does not silently downgrade to OS

### 5.2 Isolation Layer Selection

| Option | Meaning | Current behavior |
| --- | --- | --- |
| `auto` | Smart routing | Selects the backend based on command type and `trust_level` |
| `os` | OS isolation | Linux uses Landlock + Seccomp + Namespaces; macOS uses Seatbelt |
| `vm` | microVM isolation | Currently supports only Linux + KVM |
| `wasm` | Wasm isolation | Suitable for `.wasm/.wat/.wast` workloads |

The current Rust enum names for `IsolationLevel` are:

- `IsolationLevel::Auto`
- `IsolationLevel::Os`
- `IsolationLevel::MicroVm`
- `IsolationLevel::Wasm`

Current semantics of `auto` routing:

- `.wasm` / `.wat` / `.wast` files prefer Wasm
- `TrustLevel::Untrusted` prefers microVM on Linux when the `vm` feature is enabled
- Other regular commands use OS by default

## 6. Performance Data

The following data comes from the baseline maintained in the current repository. Use `CLAUDE.md` and `README.md` as the source of truth for measurement definitions:

| Path | Metric | Measured |
| --- | --- | --- |
| OS | Cold start | P50 8.24ms |
| Wasm | Cold start (cold cache) | P50 1.01ms |
| OS warm pool | Hot acquire | P50 0.19us (acquire only) |
| microVM | Cold start | P50 253ms |
| microVM | Snapshot restore | P50 69ms (non-pooled) |
| microVM | Pooled snapshot restore | P50 28ms (restore-to-ready) |
| microVM warm pool | Hot path | P50 773us |

Key interpretation points:

- `0.19us` is the cost of acquiring an OS warm-pool object; it does not include command execution
- `28ms` is pooled snapshot restore to the ready state; it does not include command execution
- `773us` is the microVM warm-pool hot path, including lightweight command execution

## 7. Next Steps

If you want to go deeper, read these in order:

- Architecture overview: [docs/architecture.md](./architecture.md)
- API details: [docs/api.md](./api.md)
- Comprehensive research: [docs/research/00-executive-summary.md](./research/00-executive-summary.md)
- Wasm design: [docs/research/11-wasmtime-api-research.md](./research/11-wasmtime-api-research.md)
- microVM design: [docs/research/14-microvm-design.md](./research/14-microvm-design.md)
- Product and competitor discussion: [discuss/product-strategy-review.md](../discuss/product-strategy-review.md)
- Competitive analysis: [discuss/competitive-analysis.md](../discuss/competitive-analysis.md)
- Streaming output proposal: [discuss/streaming-output-design.md](../discuss/streaming-output-design.md)
- HTTP proxy proposal: [discuss/http-proxy-design.md](../discuss/http-proxy-design.md)
