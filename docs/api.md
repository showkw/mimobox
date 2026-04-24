# mimobox SDK API Reference

> **Stability note**: This document describes the current public API of `mimobox-sdk` and `mimobox-core`. The API is stabilizing but may still evolve before 1.0.

## Feature Gates

Many APIs are gated behind Cargo features or platform-specific `cfg` attributes. Throughout this document, annotations like *(requires `vm` feature + Linux)* indicate where these restrictions apply.

| Feature | Enables | Default |
|---------|---------|---------|
| `os` | OS-level backend (Linux/macOS) | Yes |
| `vm` | microVM backend (Linux + KVM) | No |
| `wasm` | Wasm backend (Wasmtime) | No |

Add features in `Cargo.toml`:

```toml
[dependencies]
mimobox-sdk = { version = "0.1", features = ["vm", "wasm"] }
```

## Table of Contents

- [Sandbox](#sandbox)
- [Config](#config)
- [ConfigBuilder](#configbuilder)
- [IsolationLevel](#isolationlevel)
- [TrustLevel](#trustlevel)
- [NetworkPolicy](#networkpolicy)
- [ExecuteResult](#executeresult)
- [StreamEvent](#streamevent)
- [SandboxSnapshot](#sandboxsnapshot)
- [RestorePool](#restorepool)
- [PtySession](#ptysession)
- [PtyConfig / PtySize / PtyEvent](#ptyconfig--ptysize--ptyevent)
- [HttpResponse](#httpresponse)
- [SdkError](#sdkerror)
- [ErrorCode](#errorcode)

---

## Sandbox

```rust
use mimobox_sdk::Sandbox;
```

The primary entry point for all sandbox operations. Supports zero-config creation with smart routing, or full configuration via [`Config`](#config).

### Lifecycle

```text
Sandbox::new() or Sandbox::with_config(config)
         |
         v
    [backend initialized lazily on first execute]
         |
    execute() / stream_execute() / ...
         |
    destroy() or Drop
```

Backends are **not** created at construction time. The first call to `execute()`, `create_pty()`, or other operations triggers backend initialization based on the configured isolation level. Subsequent calls reuse the same backend until the isolation level changes.

### `Sandbox::new`

```rust
pub fn new() -> Result<Self, SdkError>
```

Creates a sandbox with default configuration. Smart routing selects the optimal isolation level based on each command.

**Feature requirements**: Any default feature (`os` is enabled by default).

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello")?;
    assert_eq!(result.exit_code, Some(0));
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::with_config`

```rust
pub fn with_config(config: Config) -> Result<Self, SdkError>
```

Creates a sandbox with explicit configuration.

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::Os)
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let mut sandbox = Sandbox::with_config(config)?;
    let result = sandbox.execute("/bin/echo configured")?;
    assert_eq!(result.exit_code, Some(0));
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::with_pool`

*(requires `vm` feature)*

```rust
#[cfg(feature = "vm")]
pub fn with_pool(config: Config, pool_config: mimobox_vm::VmPoolConfig) -> Result<Self, SdkError>
```

Creates a sandbox with an explicit microVM warm pool configuration. The pool pre-creates VM instances for sub-millisecond acquisition.

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();
    // Note: requires `vm` feature + Linux
    let pool_config = mimobox_vm::VmPoolConfig {
        min_size: 1,
        max_size: 4,
        max_idle_duration: std::time::Duration::from_secs(60),
        health_check_interval: None,
    };
    let mut sandbox = Sandbox::with_pool(config, pool_config)?;
    let result = sandbox.execute("/bin/echo pooled")?;
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::execute`

```rust
pub fn execute(&mut self, command: &str) -> Result<ExecuteResult, SdkError>
```

Executes a command inside the sandbox and waits for completion. The command string is parsed using shell-style quoting (via `shlex`).

**Errors**:
- `SdkError::Config` if the command string has mismatched quotes.
- `SdkError::BackendUnavailable` if the required backend feature is not enabled.
- `SdkError::Sandbox` with `CommandTimeout` if the command exceeds the configured timeout.
- `SdkError::Sandbox` with `CommandExit(code)` if the command exits with a non-zero code.

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo 'hello world'")?;
    println!("stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("exit: {:?}", result.exit_code);
    println!("elapsed: {:?}", result.elapsed);
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::execute_with_env`

*(requires `vm` feature)*

```rust
#[cfg(feature = "vm")]
pub fn execute_with_env(
    &mut self,
    command: &str,
    env: HashMap<String, String>,
) -> Result<ExecuteResult, SdkError>
```

Executes a command with additional environment variables injected into the microVM guest. Only available on the microVM backend.

### `Sandbox::execute_with_timeout`

*(requires `vm` feature)*

```rust
#[cfg(feature = "vm")]
pub fn execute_with_timeout(
    &mut self,
    command: &str,
    timeout: Duration,
) -> Result<ExecuteResult, SdkError>
```

Executes a command with a per-call timeout override. This overrides the global `Config.timeout` for this single invocation.

### `Sandbox::execute_with_env_and_timeout`

*(requires `vm` feature)*

```rust
#[cfg(feature = "vm")]
pub fn execute_with_env_and_timeout(
    &mut self,
    command: &str,
    env: HashMap<String, String>,
    timeout: Duration,
) -> Result<ExecuteResult, SdkError>
```

Executes a command with both environment variable injection and per-call timeout override.

```rust
use std::collections::HashMap;
use std::time::Duration;
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();
    let mut sandbox = Sandbox::with_config(config)?;
    let mut env = HashMap::new();
    env.insert("MY_VAR".to_string(), "hello".to_string());
    let result = sandbox.execute_with_env_and_timeout(
        "/usr/bin/printenv MY_VAR",
        env,
        Duration::from_secs(5),
    )?;
    assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "hello");
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::stream_execute`

*(requires `vm` feature + Linux)*

```rust
pub fn stream_execute(
    &mut self,
    command: &str,
) -> Result<std::sync::mpsc::Receiver<StreamEvent>, SdkError>
```

Executes a command and returns a channel receiver for streaming output events. Only available on the microVM backend.

**Use cases**: Long-running commands, real-time log processing, Agent tasks that consume output incrementally.

**Errors**: Returns `UnsupportedPlatform` on non-microVM backends.

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();
    let mut sandbox = Sandbox::with_config(config)?;
    let rx = sandbox.stream_execute("/bin/sh -c 'echo start; sleep 1; echo done'")?;
    for event in rx.iter() {
        match event {
            StreamEvent::Stdout(chunk) => print!("{}", String::from_utf8_lossy(&chunk)),
            StreamEvent::Stderr(chunk) => eprint!("{}", String::from_utf8_lossy(&chunk)),
            StreamEvent::Exit(code) => println!("exit = {code}"),
            StreamEvent::TimedOut => println!("timed out"),
        }
    }
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::read_file`

*(requires `vm` feature + Linux)*

```rust
#[cfg(feature = "vm")]
pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SdkError>
```

Reads a file from inside the sandbox guest filesystem. The file is transferred over the serial control channel.

**Errors**: Returns `FileNotFound` if the path does not exist, `FilePermissionDenied` if access is denied.

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();
    let mut sandbox = Sandbox::with_config(config)?;
    sandbox.write_file("/tmp/test.txt", b"hello")?;
    let content = sandbox.read_file("/tmp/test.txt")?;
    assert_eq!(content, b"hello");
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::write_file`

*(requires `vm` feature + Linux)*

```rust
#[cfg(feature = "vm")]
pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SdkError>
```

Writes a file into the sandbox guest filesystem.

### `Sandbox::http_request`

*(requires `vm` feature + Linux)*

```rust
#[cfg(feature = "vm")]
pub fn http_request(
    &mut self,
    method: &str,
    url: &str,
    headers: std::collections::HashMap<String, String>,
    body: Option<&[u8]>,
) -> Result<HttpResponse, SdkError>
```

Sends an HTTP request through the host-side controlled proxy. The request is executed by the host on behalf of the sandbox guest.

**Important**: 
- Only HTTPS URLs are supported.
- The target domain must be in the `allowed_http_domains` whitelist.
- Direct network access inside the sandbox remains blocked.

**Errors**: Returns `HttpDeniedHost` if the domain is not whitelisted, `HttpTimeout` if the request times out, `HttpInvalidUrl` if the URL is malformed or uses IP directly.

```rust
use std::collections::HashMap;
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .allowed_http_domains(["api.github.com"])
        .build();
    let mut sandbox = Sandbox::with_config(config)?;
    let response = sandbox.http_request(
        "GET",
        "https://api.github.com",
        HashMap::new(),
        None,
    )?;
    println!("status = {}", response.status);
    println!("body = {} bytes", response.body.len());
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::create_pty`

```rust
pub fn create_pty(&mut self, command: &str) -> Result<PtySession, SdkError>
```

Creates an interactive PTY terminal session. Currently supported on OS-level backends only (not microVM).

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let mut pty = sandbox.create_pty("/bin/sh")?;
    pty.send_input(b"echo hello\n")?;
    // Read output events from pty.output()
    let exit_code = pty.wait()?;
    println!("pty exited with code {exit_code}");
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::create_pty_with_config`

```rust
pub fn create_pty_with_config(&mut self, config: PtyConfig) -> Result<PtySession, SdkError>
```

Creates a PTY session with full configuration (custom terminal size, environment variables, working directory, timeout).

### `Sandbox::snapshot`

*(requires `vm` feature + Linux)*

```rust
pub fn snapshot(&mut self) -> Result<SandboxSnapshot, SdkError>
```

Takes a snapshot of the current sandbox state. Only supported on the microVM backend.

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();
    let mut sandbox = Sandbox::with_config(config)?;
    sandbox.execute("/bin/echo setup")?;
    let snapshot = sandbox.snapshot()?;
    println!("snapshot size = {} bytes", snapshot.size());
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::from_snapshot`

*(requires `vm` feature + Linux)*

```rust
pub fn from_snapshot(snapshot: &SandboxSnapshot) -> Result<Self, SdkError>
```

Creates a new sandbox by restoring from a previously captured snapshot.

### `Sandbox::fork`

*(requires `vm` feature + Linux)*

```rust
pub fn fork(&mut self) -> Result<Self, SdkError>
```

Creates an independent copy of the current sandbox using copy-on-write (CoW) memory. Unmodified pages are shared between parent and child.

**Performance**: Fork is significantly faster than snapshot + restore because it uses `mmap(MAP_PRIVATE)` instead of copying the full memory image.

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();
    let mut sandbox = Sandbox::with_config(config)?;
    sandbox.execute("/bin/echo parent")?;
    let mut child = sandbox.fork()?;
    let result = child.execute("/bin/echo child")?;
    assert_eq!(result.exit_code, Some(0));
    child.destroy()?;
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::active_isolation`

```rust
pub fn active_isolation(&self) -> Option<IsolationLevel>
```

Returns the isolation level of the currently active backend. Returns `None` before the first operation triggers backend initialization. Useful for querying the result of `Auto` routing.

```rust
use mimobox_sdk::{IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    assert_eq!(sandbox.active_isolation(), None); // not yet initialized
    sandbox.execute("/bin/echo hello")?;
    assert!(sandbox.active_isolation().is_some());
    println!("backend = {:?}", sandbox.active_isolation());
    sandbox.destroy()?;
    Ok(())
}
```

### `Sandbox::destroy`

```rust
pub fn destroy(self) -> Result<(), SdkError>
```

Explicitly destroys the sandbox and releases all resources. If not called, the `Drop` implementation will attempt cleanup automatically (with warnings logged on failure).

---

## Config

```rust
use mimobox_sdk::Config;
```

SDK-level configuration that controls isolation level, resource limits, filesystem access, network policy, and microVM-specific settings.

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `isolation` | `IsolationLevel` | `Auto` | Isolation level selection strategy |
| `trust_level` | `TrustLevel` | `SemiTrusted` | Trust level affecting auto-routing |
| `network` | `NetworkPolicy` | `DenyAll` | Network access policy |
| `timeout` | `Option<Duration>` | `Some(30s)` | Command execution timeout |
| `memory_limit_mb` | `Option<u64>` | `Some(512)` | Memory limit in MiB |
| `fs_readonly` | `Vec<PathBuf>` | `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/dev`, `/proc`, `/etc` | Read-only mount paths |
| `fs_readwrite` | `Vec<PathBuf>` | `/tmp` | Read-write mount paths |
| `allowed_http_domains` | `Vec<String>` | `[]` | HTTP proxy domain whitelist |
| `allow_fork` | `bool` | `false` | Allow child process creation |
| `vm_vcpu_count` | `u8` | `1` | microVM vCPU count |
| `vm_memory_mb` | `u32` | `256` | microVM guest memory in MiB |
| `kernel_path` | `Option<PathBuf>` | `None` | Custom microVM kernel path |
| `rootfs_path` | `Option<PathBuf>` | `None` | Custom microVM rootfs path |

### Key behaviors

- **`memory_limit_mb` vs `vm_memory_mb`**: For the microVM backend, the effective guest memory is `min(memory_limit_mb, vm_memory_mb)`.
- **`timeout` precision**: Timeout is rounded up to whole seconds internally. For example, `1500ms` becomes `2s`.
- **`allowed_http_domains`**: Supports glob patterns like `*.openai.com`. Combined with `NetworkPolicy::AllowDomains`.

```rust
use mimobox_sdk::Config;

fn main() {
    let config = Config::default();
    assert_eq!(config.isolation, mimobox_sdk::IsolationLevel::Auto);
    assert_eq!(config.memory_limit_mb, Some(512));
}
```

---

## ConfigBuilder

```rust
impl Config {
    pub fn builder() -> ConfigBuilder { ... }
}
```

Fluent builder for constructing `Config` instances.

### All builder methods

| Method | Parameter | Description |
|--------|-----------|-------------|
| `isolation(level)` | `IsolationLevel` | Set isolation level selection strategy |
| `trust_level(level)` | `TrustLevel` | Set trust level for auto-routing |
| `network(policy)` | `NetworkPolicy` | Set network access policy |
| `timeout(duration)` | `Duration` | Set command execution timeout |
| `memory_limit_mb(mb)` | `u64` | Set memory limit in MiB |
| `fs_readonly(paths)` | `impl IntoIterator<Item = impl Into<PathBuf>>` | Set read-only mount paths |
| `fs_readwrite(paths)` | `impl IntoIterator<Item = impl Into<PathBuf>>` | Set read-write mount paths |
| `allow_fork(allow)` | `bool` | Allow child process creation |
| `allowed_http_domains(domains)` | `impl IntoIterator<Item = impl Into<String>>` | Set HTTP proxy domain whitelist |
| `vm_vcpu_count(count)` | `u8` | Set microVM vCPU count |
| `vm_memory_mb(mb)` | `u32` | Set microVM guest memory in MiB |
| `kernel_path(path)` | `impl Into<PathBuf>` | Set microVM kernel image path |
| `rootfs_path(path)` | `impl Into<PathBuf>` | Set microVM rootfs path |
| `no_timeout()` | - | Remove timeout, allow unlimited execution |
| `build()` | - | Produce final `Config` |

```rust
use std::time::Duration;
use mimobox_sdk::{Config, IsolationLevel, NetworkPolicy, TrustLevel};

fn main() {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .trust_level(TrustLevel::Untrusted)
        .network(NetworkPolicy::AllowDomains(vec!["api.openai.com".to_string()]))
        .timeout(Duration::from_secs(60))
        .memory_limit_mb(512)
        .fs_readonly(["/usr", "/lib", "/bin"])
        .fs_readwrite(["/tmp", "/workspace"])
        .allow_fork(false)
        .allowed_http_domains(["api.openai.com", "*.openai.com"])
        .vm_vcpu_count(2)
        .vm_memory_mb(256)
        .kernel_path("/opt/mimobox/vmlinux")
        .rootfs_path("/opt/mimobox/rootfs.cpio.gz")
        .build();

    assert_eq!(config.vm_vcpu_count, 2);
    assert_eq!(config.kernel_path, Some(std::path::PathBuf::from("/opt/mimobox/vmlinux")));
}
```

---

## IsolationLevel

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    #[default]
    Auto,
    Os,
    Wasm,
    MicroVm,
}
```

| Variant | Description |
|---------|-------------|
| `Auto` | Smart routing based on command type and `TrustLevel`. `.wasm/.wat/.wast` files route to Wasm; `Untrusted` trust level routes to microVM (Linux + `vm` feature); otherwise falls back to OS-level. |
| `Os` | OS-level isolation: Landlock + Seccomp + Namespaces (Linux) or Seatbelt (macOS). |
| `Wasm` | Wasm-level isolation via Wasmtime. Commands must target `.wasm/.wat/.wast` files. |
| `MicroVm` | Hardware-level isolation via KVM microVM. Requires Linux + `vm` feature + KVM support. |

---

## TrustLevel

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustLevel {
    Trusted,
    #[default]
    SemiTrusted,
    Untrusted,
}
```

| Variant | Description | Auto-routing impact |
|---------|-------------|-------------------|
| `Trusted` | Self-authored or fully audited code | Routes to OS-level by default |
| `SemiTrusted` | Third-party libraries or partially audited code | Routes to OS-level by default (same as Trusted for routing) |
| `Untrusted` | User-submitted or downloaded code | Routes to microVM on Linux + `vm` feature; **fails closed** if microVM is unavailable |

---

## NetworkPolicy

```rust
#[derive(Debug, Clone, Default)]
pub enum NetworkPolicy {
    #[default]
    DenyAll,
    AllowDomains(Vec<String>),
    AllowAll,
}
```

| Variant | Description |
|---------|-------------|
| `DenyAll` | Block all network access. Default. |
| `AllowDomains(domains)` | Keep direct sandbox network blocked, but allow HTTP requests via the host proxy to the specified domains. |
| `AllowAll` | Allow unrestricted network access. Uses a permissive Seccomp profile. |

---

## ExecuteResult

```rust
#[non_exhaustive]
pub struct ExecuteResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub elapsed: std::time::Duration,
}
```

| Field | Type | Description |
|-------|------|-------------|
| `stdout` | `Vec<u8>` | Raw standard output bytes. Use `String::from_utf8_lossy()` for text. |
| `stderr` | `Vec<u8>` | Raw standard error bytes. |
| `exit_code` | `Option<i32>` | Process exit code. `None` if the process was killed or timed out. |
| `timed_out` | `bool` | `true` if the command was terminated due to timeout. |
| `elapsed` | `Duration` | Total wall-clock time from execution start to result. |

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello")?;
    println!("exit: {:?}", result.exit_code);
    println!("stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("elapsed: {:?}", result.elapsed);
    println!("timed_out: {}", result.timed_out);
    sandbox.destroy()?;
    Ok(())
}
```

---

## StreamEvent

```rust
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    TimedOut,
}
```

| Variant | Description |
|---------|-------------|
| `Stdout(data)` | A chunk of standard output data. |
| `Stderr(data)` | A chunk of standard error data. |
| `Exit(code)` | The process has exited with the given code. This is always the last event. |
| `TimedOut` | The command was terminated due to timeout. This is always the last event. |

See [`Sandbox::stream_execute`](#sandboxstream_execute) for a complete example.

---

## SandboxSnapshot

```rust
pub struct SandboxSnapshot { /* opaque */ }
```

An opaque handle to a sandbox memory snapshot. Supports both in-memory bytes and file-backed storage modes.

### `SandboxSnapshot::from_bytes`

```rust
pub fn from_bytes(data: &[u8]) -> Result<Self, SdkError>
```

Restores a snapshot from raw bytes. Fails if data is empty.

### `SandboxSnapshot::from_file`

```rust
pub fn from_file(path: PathBuf) -> Result<Self, SdkError>
```

Creates a snapshot reference from a file on disk. Does not load the file into memory immediately.

### `SandboxSnapshot::memory_file_path`

```rust
pub fn memory_file_path(&self) -> Option<&Path>
```

Returns the file path for file-backed snapshots. Returns `None` for in-memory snapshots.

### `SandboxSnapshot::as_bytes`

```rust
pub fn as_bytes(&self) -> Result<&[u8], SdkError>
```

Returns a byte slice without copying. Only works for in-memory snapshots; file-backed snapshots return an error.

### `SandboxSnapshot::to_bytes`

```rust
pub fn to_bytes(&self) -> Result<Vec<u8>, SdkError>
```

Returns a byte copy. File-backed snapshots read from disk and reconstruct the full snapshot.

### `SandboxSnapshot::into_bytes`

```rust
pub fn into_bytes(self) -> Result<Vec<u8>, SdkError>
```

Consumes the snapshot and returns bytes, avoiding copies when possible.

### `SandboxSnapshot::size`

```rust
pub fn size(&self) -> usize
```

Returns the snapshot size in bytes.

---

## RestorePool

*(requires `vm` feature + Linux)*

```rust
pub struct RestorePool { /* opaque */ }
```

A pool of pre-restored microVM instances for sub-millisecond snapshot restore-to-ready latency.

### `RestorePoolConfig`

```rust
pub struct RestorePoolConfig {
    pub pool_size: usize,
    pub base_config: Config,
}
```

### `RestorePool::new`

```rust
pub fn new(config: RestorePoolConfig) -> Result<Self, SdkError>
```

Creates a restore pool with the specified size and base configuration.

### `RestorePool::restore`

```rust
pub fn restore(&self, snapshot: &SandboxSnapshot) -> Result<Sandbox, SdkError>
```

Restores a new sandbox from the given snapshot using a pre-warmed VM from the pool.

### `RestorePool::idle_count`

```rust
pub fn idle_count(&self) -> usize
```

Returns the number of idle VM instances currently in the pool.

### `RestorePool::warm`

```rust
pub fn warm(&self, target: usize) -> Result<(), SdkError>
```

Pre-warms the pool to at least `target` idle instances.

```rust
use mimobox_sdk::{
    Config, IsolationLevel, RestorePool, RestorePoolConfig, Sandbox, SandboxSnapshot,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();
    let pool_config = RestorePoolConfig {
        pool_size: 2,
        base_config,
    };
    let pool = RestorePool::new(pool_config)?;

    // Take a snapshot from a running sandbox
    let mut sandbox = Sandbox::with_config(
        Config::builder().isolation(IsolationLevel::MicroVm).build()
    )?;
    sandbox.execute("/bin/echo setup")?;
    let snapshot = sandbox.snapshot()?;
    sandbox.destroy()?;

    // Restore from the pool
    let mut restored = pool.restore(&snapshot)?;
    let result = restored.execute("/bin/echo restored")?;
    assert_eq!(result.exit_code, Some(0));
    restored.destroy()?;
    Ok(())
}
```

---

## PtySession

```rust
pub struct PtySession { /* opaque */ }
```

An interactive terminal session connected to a PTY inside the sandbox.

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `send_input` | `(&mut self, data: &[u8]) -> Result<(), SdkError>` | Write input to the PTY stdin |
| `resize` | `(&mut self, cols: u16, rows: u16) -> Result<(), SdkError>` | Resize the terminal |
| `output` | `(&self) -> &Receiver<PtyEvent>` | Get the output event receiver |
| `kill` | `(&mut self) -> Result<(), SdkError>` | Force-terminate the session |
| `wait` | `(&mut self) -> Result<i32, SdkError>` | Wait for process exit and return exit code |

```rust
use mimobox_sdk::{PtyEvent, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let mut pty = sandbox.create_pty("/bin/sh")?;
    pty.send_input(b"echo hello\n")?;

    // Receive output in a loop
    let rx = pty.output();
    while let Ok(event) = rx.recv() {
        match event {
            PtyEvent::Output(data) => print!("{}", String::from_utf8_lossy(&data)),
            PtyEvent::Exit(code) => {
                println!("exited with code {code}");
                break;
            }
        }
    }
    sandbox.destroy()?;
    Ok(())
}
```

---

## PtyConfig / PtySize / PtyEvent

### PtyConfig

```rust
pub struct PtyConfig {
    pub command: Vec<String>,
    pub size: PtySize,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub timeout: Option<Duration>,
}
```

### PtySize

```rust
pub struct PtySize {
    pub cols: u16,  // default: 80
    pub rows: u16,  // default: 24
}
```

### PtyEvent

```rust
pub enum PtyEvent {
    Output(Vec<u8>),
    Exit(i32),
}
```

---

## HttpResponse

```rust
pub struct HttpResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | `u16` | HTTP status code (e.g., 200, 404) |
| `headers` | `HashMap<String, String>` | Normalized response headers |
| `body` | `Vec<u8>` | Raw response body bytes |

---

## SdkError

```rust
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("[{code_str}] {message}")]
    Sandbox {
        code: ErrorCode,
        message: String,
        suggestion: Option<String>,
    },
    #[error("backend unavailable: {0}")]
    BackendUnavailable(&'static str),
    #[error("config error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
```

| Variant | Description |
|---------|-------------|
| `Sandbox { code, message, suggestion }` | Structured error from the sandbox backend. `code` provides a stable error identifier. `suggestion` offers a hint for resolution. |
| `BackendUnavailable(name)` | The required backend feature is not enabled. Enable the corresponding Cargo feature. |
| `Config(msg)` | Invalid SDK configuration or malformed input. |
| `Io(err)` | Standard I/O error propagated from the OS. |

---

## ErrorCode

```rust
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    CommandTimeout,
    CommandExit(i32),
    CommandKilled,
    FileNotFound,
    FilePermissionDenied,
    FileTooLarge,
    HttpDeniedHost,
    HttpTimeout,
    HttpBodyTooLarge,
    HttpConnectFail,
    HttpTlsFail,
    HttpInvalidUrl,
    SandboxNotReady,
    SandboxDestroyed,
    SandboxCreateFailed,
    InvalidConfig,
    UnsupportedPlatform,
}
```

Each variant has a stable string representation via `as_str()`:

| Variant | `as_str()` | Description |
|---------|-----------|-------------|
| `CommandTimeout` | `"command_timeout"` | Command exceeded the timeout |
| `CommandExit(n)` | `"command_exit"` | Command exited with non-zero code |
| `CommandKilled` | `"command_killed"` | Command was forcefully killed |
| `FileNotFound` | `"file_not_found"` | Target file does not exist |
| `FilePermissionDenied` | `"file_permission_denied"` | Insufficient file permissions |
| `FileTooLarge` | `"file_too_large"` | File or transfer exceeds size limit |
| `HttpDeniedHost` | `"http_denied_host"` | Domain not in whitelist |
| `HttpTimeout` | `"http_timeout"` | HTTP request timed out |
| `HttpBodyTooLarge` | `"http_body_too_large"` | Response body exceeds limit |
| `HttpConnectFail` | `"http_connect_fail"` | Failed to establish connection |
| `HttpTlsFail` | `"http_tls_fail"` | TLS handshake failed |
| `HttpInvalidUrl` | `"http_invalid_url"` | URL is malformed or uses IP |
| `SandboxNotReady` | `"sandbox_not_ready"` | Sandbox not in executable state |
| `SandboxDestroyed` | `"sandbox_destroyed"` | Sandbox already destroyed |
| `SandboxCreateFailed` | `"sandbox_create_failed"` | Sandbox creation failed |
| `InvalidConfig` | `"invalid_config"` | Configuration is invalid |
| `UnsupportedPlatform` | `"unsupported_platform"` | Current platform doesn't support this operation |

---

## Core Types (mimobox-core)

The following types are re-exported from `mimobox-core` and are also available through `mimobox-sdk`:

- `PtyConfig`, `PtySize`, `PtyEvent`, `PtySession` (trait) — PTY session types
- `ErrorCode` — Structured error codes
- `SeccompProfile` — Linux seccomp filter profiles (`Essential`, `Network`, `EssentialWithFork`, `NetworkWithFork`)

### Sandbox Trait (mimobox-core)

```rust
pub trait Sandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> where Self: Sized;
    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError>;
    fn create_pty(&mut self, config: PtyConfig) -> Result<Box<dyn PtySession>, SandboxError>;
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SandboxError>;
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SandboxError>;
    fn snapshot(&mut self) -> Result<SandboxSnapshot, SandboxError>;
    fn fork(&mut self) -> Result<Self, SandboxError> where Self: Sized;
    fn destroy(self) -> Result<(), SandboxError>;
}
```

The core trait is the backend abstraction layer. Most users should use `mimobox_sdk::Sandbox` instead of implementing this trait directly.

### SandboxConfig (mimobox-core)

Internal configuration shared across all backends. Prefer using `mimobox_sdk::Config` and `ConfigBuilder` for SDK-level configuration.

```rust
pub struct SandboxConfig {
    pub fs_readonly: Vec<PathBuf>,
    pub fs_readwrite: Vec<PathBuf>,
    pub deny_network: bool,
    pub memory_limit_mb: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub seccomp_profile: SeccompProfile,
    pub allow_fork: bool,
    pub allowed_http_domains: Vec<String>,
}
```

### SandboxError (mimobox-core)

```rust
pub enum SandboxError {
    Unsupported,
    UnsupportedOperation(String),
    NamespaceFailed(String),
    PivotRootFailed(String),
    MountFailed(String),
    LandlockFailed(String),
    SeccompFailed(String),
    ExecutionFailed(String),
    InvalidSnapshot,
    Timeout,
    PipeError(String),
    Syscall(String),
    Io(std::io::Error),
}
```

Low-level backend errors. The SDK maps these to `SdkError` with structured `ErrorCode` values.
