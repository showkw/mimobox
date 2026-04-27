# MimoBox Architecture

This document describes the architecture layers, backend implementation mechanisms, SDK intelligent routing, MCP Server, Python bindings, and security boundaries of the current repository. It only records capabilities that actually exist in the current source code, and does not present long-term plans from research documents as current status.

## Version History

| Version | Date | Change Summary | Change Type | Owner |
| --- | --- | --- | --- | --- |
| v2.0 | 2026-04-25 | Rewrote the architecture around the 8 crate workspace, adding SDK routing, MCP Server, and Python SDK binding notes | Update | Codex |
| v1.0 | 2026-04-20 | Initial architecture design document | Added | Codex |

## Glossary

| Term | Definition |
| --- | --- |
| Core abstraction layer | traits, configuration, result, and error types defined in `mimobox-core` |
| OS backend | Native Linux/macOS sandbox implementation in `mimobox-os` |
| Wasm backend | Wasmtime-based sandbox implementation in `mimobox-wasm` |
| microVM backend | Hardware-level isolation implementation based on Linux KVM in `mimobox-vm` |
| Intelligent routing | Logic in `mimobox-sdk` that selects an isolation backend based on command type and trust level |
| MCP Server | Tool service exposed to MCP clients by `mimobox-mcp` through rmcp + stdio |
| Python SDK | Python bindings exposed by `mimobox-python` through PyO3 + maturin |

## Article Outline

| Section | Title | Purpose |
| --- | --- | --- |
| 1 | Overall Architecture | Explain the responsibility boundaries of the 8 crate workspace |
| 2 | Core Abstractions | Describe the `Sandbox` trait and common types |
| 3 | Backend Implementations | Detail the OS, Wasm, and microVM backend categories |
| 4 | SDK Intelligent Routing | Explain the routing rules of `resolve_isolation` |
| 5 | MCP Server | Explain the rmcp + stdio tool service architecture |
| 6 | Python SDK | Explain PyO3 bindings, exported types, and error mapping |
| 7 | Pooling and Snapshots | Explain the OS pool, VM pool, RestorePool, and fork |
| 8 | Security Boundaries | Clarify the isolation guarantees currently in place |
| 9 | Recommended Architecture Reading Order | Provide the recommended source reading path |

## 1. Overall Architecture

The current Cargo workspace contains 8 crates:

```text
.
|
|-- crates/mimobox-core
|    |-- Sandbox trait
|    |-- SandboxConfig / SandboxResult
|    |-- SandboxError / ErrorCode
|    `-- SeccompProfile
|
|-- crates/mimobox-os
|    |-- LinuxSandbox
|    |    |-- Landlock
|    |    |-- Seccomp-bpf
|    |    |-- namespaces
|    |    `-- setrlimit
|    |-- MacOsSandbox
|    |    |-- sandbox-exec
|    |    `-- Seatbelt policy
|    `-- SandboxPool
|
|-- crates/mimobox-wasm
|    `-- WasmSandbox
|         |-- Wasmtime Engine
|         |-- Module cache
|         |-- StoreLimits
|         `-- WASI Preview 1 runtime
|
|-- crates/mimobox-vm
|    |-- MicrovmSandbox
|    |-- VmPool
|    |-- RestorePool
|    |-- HTTP proxy
|    |-- snapshot / restore / fork
|    `-- guest serial command protocol
|
|-- crates/mimobox-sdk
|    |-- Sandbox facade
|    |-- ConfigBuilder
|    |-- router::resolve_isolation
|    |-- streaming / HTTP / file operations
|    `-- structured error mapping
|
|-- crates/mimobox-cli
|    |-- run
|    |-- bench
|    |-- setup
|    `-- doctor
|
|-- crates/mimobox-mcp
|    |-- rmcp server
|    |-- stdio transport
|    `-- 10 MCP tools
|
`-- crates/mimobox-python
     |-- PyO3 module
     |-- Python classes
     `-- Python exception hierarchy
```

From the upper-layer caller perspective, the unified entry points are concentrated in the SDK, CLI, MCP Server, and Python SDK:

```text
Caller
  |
  +--> Rust SDK: mimobox_sdk::Sandbox
  +--> CLI: mimobox-cli
  +--> MCP Client: mimobox-mcp over stdio
  `--> Python: mimobox.Sandbox
        |
        v
  mimobox-sdk
        |
        +--> mimobox-os
        +--> mimobox-wasm
        `--> mimobox-vm
              |
              v
        mimobox-core common trait / config / error
```

`mimobox-core` is the low-level common contract, while `mimobox-sdk` is the unified facade for the application layer. The CLI, MCP Server, and Python SDK do not directly duplicate backend decision logic; they delegate to the SDK as much as possible.

## 2. Core Abstractions

### 2.1 `Sandbox` trait

The `Sandbox` trait in `mimobox-core` covers multiple isolation backends with a minimal lifecycle interface:

- `new`: Create the isolation environment and complete security constraint configuration before execution.
- `execute`: Execute a command or module entry point and return a unified `SandboxResult`.
- `destroy`: Release resources so backend lifecycle does not depend entirely on destructor side effects.

This abstraction keeps KISS intact: upper layers do not need to understand Landlock, Wasmtime Store, or KVM vCPU; they only need to program against a unified lifecycle.

### 2.2 Common Configuration and Errors

`SandboxConfig`, `SandboxResult`, `SandboxError`, and `ErrorCode` are defined uniformly by `mimobox-core`. The benefits are:

- Backend implementations can share semantics for resource limits, timeouts, file allowlists, and network policies.
- The SDK can promote backend errors into structured `SdkError` values.
- The Python SDK can map `SdkError` into the Python exception hierarchy.
- The MCP Server can serialize errors uniformly as tool invocation error responses.

## 3. Backend Implementations

### 3.1 OS Backend: `mimobox-os`

Main Linux backend flow:

```text
Parent process
  |
  +-- Create stdout/stderr pipes
  +-- fork
       |
       `-- Child process
            |-- setpgid
            |-- clearenv + inject minimal environment variables
            |-- redirect stdin/stdout/stderr
            |-- setrlimit(RLIMIT_AS)
            |-- Landlock restrict_self
            |-- unshare namespaces
            |-- apply_seccomp(profile)
            `-- execvp(command)
```

The Linux security sequence is a critical constraint: resource limits first, then filesystem restrictions, then namespace, and finally Seccomp. If any critical isolation step fails, execution fails immediately instead of continuing in a "partially isolated" state.

The macOS backend uses the system-native Seatbelt:

```text
SandboxConfig
  |
  v
generate_policy()
  |
  v
sandbox-exec -p "<policy>" -- <command>
```

The current macOS backend can reliably restrict writes and network access, but the readable path set must retain system startup dependency paths and cannot be narrowed as precisely as Linux Landlock.

### 3.2 Wasm Backend: `mimobox-wasm`

The Wasm backend is based on Wasmtime:

```text
WasmSandbox
  |
  |-- Engine (long-lived reuse)
  |-- cache_dir (module cache)
  |-- SandboxConfig
  `-- execute()
       |-- Load/compile Module
       |-- Create WasiP1Ctx
       |-- Configure StoreLimits
       |-- Configure fuel / epoch deadline
       |-- instantiate
       `-- Call _start or main
```

The Wasm backend uses StoreLimits to control linear memory, instance count, and table count, and uses fuel together with epoch deadline to limit execution cost and wall-clock time.

### 3.3 microVM Backend: `mimobox-vm`

The `mimobox-vm` crate exists and already implements the Linux KVM backend. It is not a planning placeholder, nor a fictional module from a research document.

The current implementation includes:

- `MicrovmSandbox`: KVM microVM lifecycle and command execution entry point.
- `VmPool`: Prewarmed microVM pool that reduces acquisition latency on the hot path.
- `RestorePool`: Pre-created shell VMs used for pooled snapshot restore.
- Snapshot / restore / fork: Supports memory snapshots, restore, and CoW fork.
- HTTP proxy: Host-side controlled HTTPS proxy with domain allowlist support.
- File transfer: Reads and writes files inside the microVM through the guest/host serial protocol.
- Streaming output: `EXECS` and `STREAM:*` frames support stdout/stderr demultiplexing.

The microVM control plane currently depends on guest `/init` and the serial command protocol:

```text
host SDK / VM backend
  |
  +-- EXEC / EXECS
  +-- FS:READ / FS:WRITE
  +-- HTTP:REQUEST
  +-- PING
  `-- SNAPSHOT / RESTORE / FORK control path
        |
        v
guest /init
  |
  +-- Execute command
  +-- Return stdout/stderr/exit
  +-- Handle file transfer
  `-- Forward HTTP proxy requests
```

## 4. SDK Intelligent Routing

`mimobox-sdk` is the recommended upper-layer entry point. The core routing logic is located in `resolve_isolation(config, command)` in `router.rs`.

### 4.1 Auto Mode

When `Config.isolation == IsolationLevel::Auto`:

1. Commands ending in `.wasm`, `.wat`, or `.wast` prefer `Wasm`.
2. `TrustLevel::Untrusted` must select `MicroVm`.
3. If the current platform or feature does not support microVM, untrusted code fails closed and returns an error instead of downgrading to OS-level isolation.
4. Other commands default to `Os`.

This keeps the default path low-latency while avoiding silent downgrades of untrusted tasks to a weaker isolation layer.

### 4.2 Explicit Mode

When the user explicitly configures the isolation layer:

- `IsolationLevel::Os`: Selects the OS backend directly, or returns `BackendUnavailable` when the `os` feature is missing.
- `IsolationLevel::Wasm`: Selects the Wasm backend directly, or returns `BackendUnavailable` when the `wasm` feature is missing.
- `IsolationLevel::MicroVm`: Selects the microVM backend directly. It is available only on Linux + `vm` feature; otherwise it returns `BackendUnavailable`.

Explicit mode no longer attempts to reroute automatically based on command content, which matches the positioning of "full control for advanced users."

## 5. MCP Server

`mimobox-mcp` is based on the rmcp framework and communicates with MCP clients through stdio transport. The core server structure is `MimoboxServer`:

```text
MimoboxServer
  |
  |-- sandboxes: Arc<Mutex<HashMap<u64, ManagedSandbox>>>
  |-- next_id: Arc<Mutex<u64>>
  `-- tool_router: ToolRouter<Self>
```

`ManagedSandbox` stores an SDK `Sandbox` instance, creation timestamp, and runtime duration statistics. MCP tool functions deserialize request parameters through `Parameters<T>`, then call the SDK to complete creation, execution, file, snapshot, fork, and HTTP operations.

The server currently exposes 10 tools:

| Tool | Description |
| --- | --- |
| `create_sandbox` | Create a reusable sandbox instance |
| `execute_code` | Execute a code snippet, converting it into a command according to language |
| `execute_command` | Execute a shell command |
| `destroy_sandbox` | Destroy the specified sandbox and release resources |
| `list_sandboxes` | List active sandboxes and metadata |
| `read_file` | Read a file from a microVM sandbox and return base64 |
| `write_file` | Write base64 file content into a microVM sandbox |
| `snapshot` | Create a microVM memory snapshot |
| `fork` | Fork a microVM sandbox based on CoW |
| `http_request` | Send an HTTP request through the controlled proxy |

When `execute_code` and `execute_command` are called without `sandbox_id`, they create a temporary sandbox and automatically destroy it after execution completes.

## 6. Python SDK

`mimobox-python` exposes the Rust SDK as a Python module through PyO3 + maturin. The core relationship is:

```text
Python caller
  |
  v
mimobox.Sandbox (PySandbox)
  |
  v
mimobox_sdk::Sandbox (RustSandbox)
  |
  +-- OS backend
  +-- Wasm backend
  `-- microVM backend
```

### 6.1 Exported Types

The Python module exports the following public types:

- `Sandbox`
- `Snapshot`
- `ExecuteResult`
- `HttpResponse`
- `StreamEvent`
- `StreamIterator`

`PySandbox` internally holds `Option<RustSandbox>`. After `__exit__` or explicit close, it takes the internal instance and calls `destroy()`, avoiding duplicate release.

### 6.2 Error Mapping

Python exception hierarchy:

- `SandboxError`: Base class.
- `SandboxProcessError`: Command exits non-zero or is killed.
- `SandboxHttpError`: HTTP proxy rejection, invalid URL, oversized body, and similar errors.
- `SandboxLifecycleError`: Sandbox is not ready, has been destroyed, or failed to create.

Standard exception mapping:

- `CommandTimeout` / `HttpTimeout` -> `TimeoutError`
- `FileNotFound` -> `FileNotFoundError`
- `FilePermissionDenied` -> `PermissionError`
- `HttpConnectFail` / `HttpTlsFail` -> `ConnectionError`
- `InvalidConfig` -> `ValueError`
- `UnsupportedPlatform` -> `NotImplementedError`

### 6.3 Method Delegation

Python methods remain thin wrappers around the Rust SDK:

- `execute()` delegates to `execute`, `execute_with_env`, `execute_with_timeout`, or `execute_with_env_and_timeout`.
- `stream_execute()` delegates to `stream_execute()` in the Rust SDK and returns `StreamIterator`.
- `read_file()` / `write_file()` delegate to microVM file transfer capabilities.
- `snapshot()` / `from_snapshot()` / `fork()` delegate to SDK snapshot and CoW fork capabilities.
- `http_request()` delegates to the host-side HTTP proxy.

## 7. Pooling and Snapshots

### 7.1 OS-level `SandboxPool`

`SandboxPool` in `mimobox-os` reduces acquisition latency by pre-creating and reusing OS-level sandboxes:

```text
SandboxPool
  |
  `-- Arc<PoolInner>
       |-- sandbox_config
       |-- pool_config
       |-- health_check_command
       `-- Mutex<PoolState>
            |-- idle: VecDeque<IdleSandbox>
            |-- in_use_count
            |-- hit_count
            |-- miss_count
            `-- evict_count
```

Recycling is triggered by `PooledSandbox::drop`, with a health check performed before returning the sandbox to the pool.

### 7.2 microVM `VmPool` and `RestorePool`

There are two pool types on the `mimobox-vm` side:

- `VmPool`: Prewarms complete microVM instances to optimize the acquire + execute hot path.
- `RestorePool`: Pre-creates restorable VM shells to optimize the snapshot restore-to-ready path.

Snapshots and fork depend on the microVM backend. OS and Wasm backends do not provide equivalent memory snapshot capabilities, and the SDK returns structured errors.

## 8. Security Boundaries

### 8.1 Parts with Hard Boundaries Already in Place

Linux OS-level:

- Filesystem writes are strictly restricted by Landlock.
- System calls are filtered by the Seccomp allowlist.
- The network stack is isolated through namespace.
- Memory is tightened through `setrlimit`.

Wasm:

- Linear memory and instance count are limited by `StoreLimits`.
- Execution time is jointly controlled by fuel and epoch deadline.
- stdout/stderr are captured through in-memory pipes and do not directly take over the host standard streams.

microVM:

- Hardware-assisted isolation boundaries are provided through KVM.
- guest file operations, HTTP proxy, and command execution pass through the host control-plane protocol.
- Network remains denied by default, and the HTTP proxy is controlled by a domain allowlist.

### 8.2 Parts That Only Form Soft or Partial Boundaries

macOS:

- Write controls are reliable.
- Network denial is reliable.
- The read scope cannot be narrowed as precisely as on Linux.
- Memory limits are not currently a hard boundary.

### 8.3 Parts That Still Require Careful Interpretation

- The Windows backend is still a planned direction and is not part of the currently implemented security boundary.
- The formal microVM data plane still targets future vsock evolution. The current serial control plane is usable, but is more oriented toward bring-up and control protocol usage.
- The HTTP proxy exposes a host-controlled request path, which is not equivalent to arbitrary network access from inside the sandbox.

## 9. Recommended Architecture Reading Order

If this is your first time working with `mimobox`, read the source in the following order:

1. `crates/mimobox-core/src/sandbox.rs`
2. `crates/mimobox-core/src/error.rs`
3. `crates/mimobox-sdk/src/config.rs`
4. `crates/mimobox-sdk/src/router.rs`
5. `crates/mimobox-sdk/src/lib.rs`
6. `crates/mimobox-os/src/linux.rs`
7. `crates/mimobox-os/src/pool.rs`
8. `crates/mimobox-wasm/src/lib.rs`
9. `crates/mimobox-vm/src/lib.rs`
10. `crates/mimobox-cli/src/main.rs`
11. `crates/mimobox-mcp/src/main.rs`
12. `crates/mimobox-python/src/lib.rs`

This path corresponds to the actual dependency relationship: "common contract -> SDK decisions -> backend implementations -> upper-layer entry points."
