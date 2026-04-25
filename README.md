[中文](README.zh-CN.md)

# mimobox

**mimobox** — A cross-platform Agent Sandbox in Rust with OS-level, Wasm, and microVM isolation, smart routing by default, and full control for advanced users.

A cross-platform Agent Sandbox implemented in Rust, providing a secure isolated code execution environment for AI Agent workloads.

**Smart routing by default, full control for advanced users.** In the default mode, SDK `Sandbox::new()` and CLI `--backend auto` automatically select the appropriate isolation layer. When finer control is needed, users can explicitly specify the isolation layer, resource limits, network policy, and microVM asset paths.

## Version History

| Version | Date | Summary | Type | Author |
| --- | --- | --- | --- | --- |
| v2.2 | 2026-04-25 | Refreshed README: synchronized the 8-crate workspace, MCP Server, Python SDK capabilities, section numbering, and Quick Start version number | Update | Codex |
| v2.1 | 2026-04-23 | Added the `doctor` environment diagnostics command and `setup` asset bootstrap command, and unified the default microVM asset directory to `~/.mimobox/assets` | Update | Codex |
| v2.0 | 2026-04-23 | Synchronized streaming output, HTTP proxy, structured error model, command-level env/timeout, Getting Started docs, and GitHub Actions CI status | Update | Codex |
| v1.6 | 2026-04-23 | Synchronized GitHub Actions CI to the streamlined 5-job version and documented KVM manual trigger plus hosted runner limitations | Update | Codex |
| v1.5 | 2026-04-21 | Final README review: synchronized directory structure, three-layer isolation status, SDK/CLI examples, competitive comparison framing, and roadmap status | Update | Codex |
| v1.4 | 2026-04-21 | Synchronized SDK, smart routing, microVM serial command channel, and Guest protocol status | Update | Codex |
| v1.3 | 2026-04-21 | Updated product positioning, performance data, and documentation index | Update | — |
| v1.2 | 2026-04-21 | Rewrote README according to the current workspace, CLI, scripts, and CI status | Update | Codex |
| v1.1 | 2026-04-21 | Synchronized documentation with the current codebase and added `mimobox-vm`, KVM, performance, and CI information | Update | Codex |
| v1.0 | 2026-04-20 | Rewrote the root README with architecture, API, performance, scripts, and security model details | Added | Codex |

## Glossary

| Term | Definition |
| --- | --- |
| OS-level sandbox | Backend that isolates processes using native Linux/macOS system mechanisms |
| Wasm sandbox | Backend that executes Wasm modules with Wasmtime |
| microVM sandbox | Hardware-level isolation backend based on Linux KVM |
| Warm pool | Pool of pre-created sandbox instances (OS-level / microVM-level) for microsecond-level acquisition and reuse |
| Smart routing | Backend selection that is automatic based on command type, isolation preference, and trust level |

## Quick Start (30 Seconds)

### Rust

```toml
# Cargo.toml
[dependencies]
mimobox-sdk = "0.1"
```

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello")?;
    println!("exit: {:?}, stdout: {}", result.exit_code, String::from_utf8_lossy(&result.stdout));
    sandbox.destroy()?;
    Ok(())
}
```

### Python

```bash
pip install mimobox
# 或从源码构建：cd crates/mimobox-python && pip install -e .
```

```python
from mimobox import Sandbox

with Sandbox() as sandbox:
    result = sandbox.execute("/bin/echo hello")
    print(result.stdout, end="")
```

Current Python SDK capabilities include:

- streaming: `stream_execute()` returns `StreamIterator`, which yields `StreamEvent` values during iteration.
- HTTP proxy: `http_request()` returns `HttpResponse` and sends requests through a controlled host-side proxy.
- file operations: `read_file()` and `write_file()` read and write files inside the microVM sandbox.
- env vars injection: `execute(command, env={...})` supports command-level environment variable injection.
- snapshot/fork: `snapshot()`, `Sandbox.from_snapshot()`, and `fork()` support microVM snapshots and CoW forks.
- error hierarchy: `SandboxError`, `SandboxProcessError`, `SandboxHttpError`, and `SandboxLifecycleError`, with mappings to standard exceptions such as `TimeoutError`, `FileNotFoundError`, `PermissionError`, and `ConnectionError`.

## 1. Project Overview

`mimobox` targets secure code execution for AI Agent workloads. Its goal is to provide **ultra-low latency**, **multi-layer isolation**, and **self-hosted controllability** behind one unified interface.

Its core positioning is not “just another faster backend”; instead, two properties hold at the same time:

- **Smart routing by default**: works with zero configuration. SDK `Sandbox::new()` and CLI `--backend auto` prefer the most suitable isolation layer.
- **Full control for advanced users**: SDK `Config::builder()` and explicit CLI `--backend os|wasm|kvm` let you override the default decision and precisely control the isolation layer, timeout, memory, network, and microVM resources.

The current Cargo workspace is split into 8 crates:

- `mimobox-core`: shared trait, configuration, result, and error types.
- `mimobox-os`: OS-level sandbox covering Linux + macOS, with `SandboxPool`.
- `mimobox-wasm`: Wasm sandbox based on Wasmtime.
- `mimobox-vm`: microVM sandbox currently focused on Linux KVM, including `VmPool`, `RestorePool`, HTTP proxy, snapshot, and fork.
- `mimobox-sdk`: unified SDK API responsible for smart routing by default and advanced configuration.
- `mimobox-cli`: CLI entrypoint, JSON output, diagnostics, and asset bootstrap commands.
- `mimobox-mcp`: MCP Server exposing 10 tools based on rmcp + stdio.
- `mimobox-python`: Python SDK binding the Rust SDK with PyO3 + maturin.

### Current Smart Routing Semantics

- In the SDK, `IsolationLevel::Auto` routes automatically based on **command type** and `TrustLevel`:
  - `.wasm/.wat/.wast` prefers Wasm.
  - `TrustLevel::Untrusted` prefers microVM on Linux with the `vm` feature.
  - `TrustLevel::Untrusted` fails closed when microVM is unavailable, without silently degrading.
  - Everything else defaults to OS-level isolation.
- In the CLI, `--backend auto` is the default and currently uses the SDK default configuration, meaning the default `TrustLevel::SemiTrusted`.
  - Therefore CLI `auto` routes Wasm files to Wasm automatically.
  - Regular commands route to OS-level isolation by default.
  - If you want untrusted commands to prefer microVM, explicitly use `--backend kvm`, or set `TrustLevel::Untrusted` in the SDK.

## 2. Current Implementation Status of the Three Isolation Layers

This README only records what is actually implemented in the current source tree. It does not promote plans from research documents to current capabilities.

| Isolation Layer | Current Status | Actual Implementation Notes |
| --- | --- | --- |
| OS-level | Completed | Linux: Landlock + Seccomp-bpf + Namespaces + `setrlimit`; macOS: Seatbelt / `sandbox-exec`; Windows is still planned |
| Wasm-level | Completed | Based on Wasmtime + WASI, enabled on demand through the `wasm` feature |
| microVM-level | First version completed | Based on Linux KVM, with guest `/init` + serial command protocol + snapshot/restore/fork connected, and guest/host control-plane capabilities such as streaming output, file transfer, and HTTP proxy |

### Current Feature Status

| Capability | Status | Notes |
| --- | --- | --- |
| SDK crate | Completed | `crates/mimobox-sdk/` provides unified API, configuration builder, execution result, and actual backend query |
| Smart routing by default | Completed | `IsolationLevel::Auto` is implemented in the SDK, and CLI `--backend auto` is wired in by default |
| MCP Server | Completed | `crates/mimobox-mcp/` exposes 10 tools based on rmcp + stdio |
| Python SDK | Completed | `crates/mimobox-python/` exposes Python classes, type stubs, and exception hierarchy through PyO3 |
| Command-level environment variable injection and timeout | Completed | `execute_with_env()`, `execute_with_timeout()`, and `execute_with_env_and_timeout()` are implemented; currently mainly serving Linux + microVM backends |
| Streaming output | Completed | `stream_execute()` is implemented and emits `StreamEvent::Stdout` / `Stderr` / `Exit` / `TimedOut` events |
| HTTP proxy + domain allowlist | Completed | `http_request()` is implemented and sends HTTPS requests through the host proxy; `allowed_http_domains` controls the allowlist, while the default network policy remains deny |
| Structured error model | Completed | Rust exposes structured error codes through `ErrorCode` and `SdkError::Sandbox`; Python maps them to an exception hierarchy |

## 3. Directory Structure

```text
mimobox/
├── CLAUDE.md                    # 项目指导文件
├── AGENTS.md                    # Agent 角色定义
├── Cargo.toml                   # Cargo workspace，当前 8 crate
├── README.md
├── CHANGELOG.md
├── crates/
│   ├── mimobox-core/            # Sandbox trait + Config + Result + Error
│   ├── mimobox-os/              # OS 级沙箱（Linux Landlock+Seccomp+NS / macOS Seatbelt）
│   ├── mimobox-wasm/            # Wasm 沙箱（Wasmtime）
│   ├── mimobox-vm/              # KVM microVM 沙箱 + VmPool + RestorePool + snapshot/fork
│   ├── mimobox-sdk/             # 统一 SDK API（默认智能路由 + 高级完全可控）
│   ├── mimobox-cli/             # CLI 入口
│   ├── mimobox-mcp/             # MCP Server（rmcp + stdio，10 工具）
│   └── mimobox-python/          # Python SDK（PyO3 bindings）
├── docs/
│   ├── architecture.md          # 当前仓库架构分层说明
│   ├── mcp-server.md            # MCP Server 使用说明
│   ├── python-sdk.md            # Python SDK 使用说明
│   └── research/                # 技术调研报告
├── discuss/                     # 讨论、评审、方案权衡
├── examples/                    # 示例代码
├── scripts/                     # 构建/测试/运行脚本入口
├── tests/                       # 集成测试
├── wit/                         # WIT 接口定义
└── logs/                        # 日志目录
```

If `vendor/` exists, it only keeps historical shims and is not part of the default workspace path.

## 4. Performance Data

| Scenario | Target | Current README Baseline | Status |
| --- | --- | --- | --- |
| OS-level cold start | <10ms | P50: 8.24ms | Meets target |
| Wasm-level cold start | <5ms | P50: 1.01ms (cold cache) | Meets target |
| OS warm pool hot acquisition | <100us | P50: 0.19us | Meets target |
| microVM cold start | <300ms | P50: 253ms | Meets target |
| microVM snapshot restore | <50ms | P50: 69ms (non-pooled) / 28ms (pooled restore-to-ready) | Pooled path meets target |
| microVM warm pool hot path | <1ms | P50: 773us | Meets target |

*The OS warm pool number measures the object acquisition cost of acquire()+drop(), excluding command execution.*
*Pooled snapshot restore measures restore-to-ready, excluding command execution and pool refill overhead. Non-pooled snapshot restore includes the full lifecycle.*

### Metric Definitions

| Metric | Start | End | Notes |
| --- | --- | --- | --- |
| OS-level cold start | Before `PlatformSandbox::new()` | After `execute(/bin/true)` returns | Includes the full create, execute, and destroy lifecycle |
| Wasm cold start | Before `WasmSandbox::new()` | After `execute(wasm)` returns | May be affected by module cache |
| Warm pool hot acquisition | Before `pool.acquire()` | After `drop()` completes | Measures object acquisition only, excluding command execution |
| microVM cold start | Before `create_vm()` | After `run_command(echo)` returns | Includes the full create, boot, execute, and shutdown lifecycle |
| microVM snapshot restore | Before `create_vm_for_restore()` | After `run_command(echo)` returns | In-memory snapshot, not file restore |
| microVM pooled snapshot restore | `RestorePool::restore()` takes out an empty-shell VM | memory write + vCPU restore complete | Excludes command execution; the empty-shell VM is pre-created by the pool |
| microVM warm pool hot path | Before `pool.acquire()` | After `pooled.execute(echo)` returns | Light load |

These are the performance baselines currently maintained in the README. Whenever benchmark results change, this section should be updated as well.

## 5. Competitive Comparison Framing

External products' latency, deployment form, and default capabilities can change quickly with versions, templates, regions, and warm state. To avoid maintaining third-party millisecond-level numbers that become stale quickly, this README keeps only a **capability-level comparison** and leaves more detailed market analysis to [`discuss/competitive-analysis.md`](discuss/competitive-analysis.md).

| Product | Current Public Positioning | Main Differences from mimobox |
| --- | --- | --- |
| mimobox | Local / self-hosted Agent Sandbox that unifies OS + Wasm + microVM three-layer isolation | The current repository provides all three isolation layers and puts smart routing by default plus explicit advanced control into the same SDK / CLI / MCP / Python entrypoints |
| Anthropic Sandbox Runtime | OS-level sandbox runtime + network proxy based on `sandbox-exec` / `bubblewrap` | More focused on OS-level runtime wrapping, without Wasm / microVM layering |
| E2B | Cloud sandbox / snapshot API for Agent workloads | More like a hosted Linux sandbox service, not local unified three-layer routing |
| Daytona | Sysbox-based sandbox infrastructure and API | Follows a container / sandbox infrastructure route and does not provide both Wasm and microVM choices |

If you need **precise market background, feature matrices, and product positioning discussion**, read [`discuss/competitive-analysis.md`](discuss/competitive-analysis.md). If you need stable README-level guidance, use the table above.

## 6. SDK Usage Examples

### 6.1 Zero Configuration: Smart Routing by Default

```rust
use mimobox_sdk::{IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello")?;

    println!("stdout = {}", String::from_utf8_lossy(&result.stdout));
    println!("resolved backend = {:?}", sandbox.active_isolation());

    assert_eq!(sandbox.active_isolation(), Some(IsolationLevel::Os));
    sandbox.destroy()?;
    Ok(())
}
```

### 6.2 Advanced Control: Explicit Routing, Environment Variable Injection, and Command-Level Timeout

<!-- Note: the microVM backend requires Linux + KVM. Run mimobox setup to download VM assets. -->

```rust
use std::collections::HashMap;
use std::time::Duration;

use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .memory_limit_mb(256)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let mut env = HashMap::new();
    env.insert("MIMOBOX_MODE".to_string(), "vm-demo".to_string());

    let result = sandbox.execute_with_env_and_timeout(
        "/usr/bin/printenv MIMOBOX_MODE",
        env,
        Duration::from_secs(2),
    )?;

    println!("stdout = {}", String::from_utf8_lossy(&result.stdout));
    println!("resolved backend = {:?}", sandbox.active_isolation());
    sandbox.destroy()?;
    Ok(())
}
```

Notes:

- `execute_with_env()`, `execute_with_timeout()`, and `execute_with_env_and_timeout()` currently mainly support the Linux + `vm` feature microVM backend.
- If the current platform or build does not enable the `vm` feature, the SDK returns `UnsupportedPlatform` or `BackendUnavailable`.
- If you want to continue using automatic routing, change `IsolationLevel::MicroVm` back to `IsolationLevel::Auto`; if you want to **force** microVM, keep the explicit `MicroVm` and add `kernel_path()` / `rootfs_path()` as needed.

### 6.3 Streaming Output: `stream_execute`

<!-- Note: the microVM backend requires Linux + KVM. Run mimobox setup to download VM assets. -->

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let receiver = sandbox.stream_execute(
        "/bin/sh -c 'echo start; echo err >&2; echo done'",
    )?;

    for event in receiver {
        match event {
            StreamEvent::Stdout(chunk) => print!("{}", String::from_utf8_lossy(&chunk)),
            StreamEvent::Stderr(chunk) => eprint!("{}", String::from_utf8_lossy(&chunk)),
            StreamEvent::Exit(code) => println!("exit = {code}"),
            StreamEvent::TimedOut => println!("command timed out"),
        }
    }

    sandbox.destroy()?;
    Ok(())
}
```

### 6.4 HTTP Proxy: `http_request`

<!-- Note: the microVM backend requires Linux + KVM. Run mimobox setup to download VM assets. -->

```rust
use std::collections::HashMap;

use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .allowed_http_domains(["example.com"])
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let response = sandbox.http_request(
        "GET",
        "https://example.com",
        HashMap::new(),
        None,
    )?;

    println!("status = {}", response.status);
    println!("body bytes = {}", response.body.len());

    sandbox.destroy()?;
    Ok(())
}
```

### 6.5 Structured Error Model

- On the Rust side, structured error codes are exposed uniformly through `mimobox_core::ErrorCode`; `mimobox_sdk::SdkError::Sandbox` additionally provides `message` and `suggestion`.
- Python bindings preserve error details while mapping them to an easier-to-handle exception hierarchy, including `SandboxProcessError`, `SandboxHttpError`, and `SandboxLifecycleError`, and reuse standard exceptions such as `TimeoutError`, `FileNotFoundError`, and `PermissionError`.

## 7. MCP Server

`mimobox-mcp` is based on the rmcp framework and communicates with MCP clients through stdio. It currently exposes 10 tools.

| Tool | Brief Description |
| --- | --- |
| `create_sandbox` | Creates a reusable sandbox instance and returns `sandbox_id` plus isolation level |
| `execute_code` | Executes a code snippet in the sandbox, supporting `python`, `javascript` / `node`, and `bash` / `sh` |
| `execute_command` | Executes a shell command in the sandbox |
| `destroy_sandbox` | Destroys the specified sandbox and releases resources |
| `list_sandboxes` | Lists active sandboxes and their metadata |
| `read_file` | Reads a file from a microVM sandbox and returns its content as base64 |
| `write_file` | Writes base64 file content into a microVM sandbox |
| `snapshot` | Creates a microVM sandbox memory snapshot |
| `fork` | Forks a microVM sandbox to create a CoW copy |
| `http_request` | Sends a request through the controlled HTTP proxy |

Startup commands:

```bash
# 默认 OS 级后端
cargo run -p mimobox-mcp

# 启用 microVM 后端
cargo run -p mimobox-mcp --features vm
```

For more complete MCP usage instructions, see [`docs/mcp-server.md`](docs/mcp-server.md).

## 8. CLI Usage Examples

The examples below prefer the command form that is currently executable in this repository: `cargo run -p mimobox-cli -- ...`. If you have already built the binary, you can also call `target/release/mimobox-cli` directly.

### 8.1 Smart Routing by Default

```bash
# 显式写法：使用 auto 路由
cargo run -p mimobox-cli -- \
  run \
  --backend auto \
  --command "/bin/echo hello"

# 等价写法：省略 backend，默认就是 auto
cargo run -p mimobox-cli -- \
  run \
  --command "/bin/echo hello"
```

### 8.2 Wasm Backend

```bash
cargo run -p mimobox-cli --features wasm -- \
  run \
  --backend wasm \
  --command "app.wasm"
```

### 8.3 KVM microVM Backend

<!-- Note: the microVM backend requires Linux + KVM. Run mimobox setup to download VM assets. -->

```bash
cargo run -p mimobox-cli --features kvm -- \
  run \
  --backend kvm \
  --kernel "/path/to/vmlinux" \
  --rootfs "/path/to/rootfs.cpio.gz" \
  --command "/bin/echo hello"
```

### 8.4 Environment Diagnostics and Asset Bootstrap

```bash
# 输出当前主机环境诊断报告
cargo run -p mimobox-cli -- doctor

# 首次引导 ~/.mimobox/assets 下的 microVM 资产，并在最后自动复查
cargo run -p mimobox-cli --features kvm -- setup
```

`doctor` checks the operating system, KVM/Seatbelt, memory, Linux security features, feature flags, microVM assets, Rust toolchain, and optional Python SDK, then returns:

- `0`: no warnings and no errors.
- `1`: warnings exist, but there are no blocking errors.
- `2`: errors exist.

### 8.5 CLI Output Contract

By default, the CLI outputs JSON for consumption by upper-level Agent systems or scripts; logs are written to `logs/`. `doctor` and `setup` are exceptions: by default, they output human-readable terminal reports.

The microVM path is currently driven through the guest `/init` serial control plane. The current frame families include:

1. The guest outputs `READY` after booting.
2. The host can send command frames such as `EXEC:<len>:<payload>\n`, `EXECS:<id>:<len>:<payload>\n`, and `HTTP:REQUEST:<id>:<len>:<json>\n`.
3. For regular execution, the guest sends back `OUTPUT:` / `EXIT:`. For streaming execution, it sends back `STREAM:START:` / `STREAM:STDOUT:` / `STREAM:STDERR:` / `STREAM:END:` / `STREAM:TIMEOUT:`. For HTTP proxy responses, it sends back `HTTPRESP:HEADERS:` / `HTTPRESP:BODY:` / `HTTPRESP:END:` / `HTTPRESP:ERROR:`.
4. File transfer continues to use the `FS:READ:` / `FS:WRITE:` frame families.

This path is already real execution inside the guest and no longer depends on a host-side stub.

## 9. Development and Verification

### Common Scripts

```bash
scripts/setup.sh
scripts/check.sh
scripts/test.sh
scripts/test-e2e.sh
scripts/bench.sh
scripts/build-rootfs.sh
scripts/build-kernel.sh
scripts/extract-vmlinux.sh <output_path>
```

### Current Script Responsibilities

- `scripts/check.sh`: `cargo check` / `clippy` / `fmt --check`.
- `scripts/test.sh`: runs workspace tests by target.
- `scripts/test-e2e.sh`: cross-backend e2e verification.
- `scripts/bench.sh [crate-name] [bench-name|all]`: runs criterion benchmarks.
- `scripts/build-rootfs.sh`: builds the KVM rootfs, defaulting to `VM_ASSETS_DIR/rootfs.cpio.gz`, and falling back to `~/.mimobox/assets/rootfs.cpio.gz` when unset.
- `scripts/build-kernel.sh`: builds the minimal KVM guest `vmlinux`, defaulting to `VM_ASSETS_DIR/vmlinux`, and falling back to `~/.mimobox/assets/vmlinux` when unset.
- `scripts/extract-vmlinux.sh`: extracts a `vmlinux` usable for KVM tests.

## 10. Documentation and CI Status

### Documentation Index

- [`docs/getting-started.md`](docs/getting-started.md) — Quick start, SDK capability examples, and platform constraints.
- [`docs/architecture.md`](docs/architecture.md) — Current repository architecture and layer breakdown.
- [`docs/mcp-server.md`](docs/mcp-server.md) — MCP Server tools, parameters, and client integration instructions.
- [`docs/python-sdk.md`](docs/python-sdk.md) — Python SDK installation, public API, exceptions, and examples.
- [`docs/research/00-executive-summary.md`](docs/research/00-executive-summary.md) — Comprehensive research report.
- [`docs/research/10-code-review-round2.md`](docs/research/10-code-review-round2.md) — Phase 1 code review.
- [`docs/research/14-microvm-design.md`](docs/research/14-microvm-design.md) — microVM design and roadmap.
- [`discuss/competitive-analysis.md`](discuss/competitive-analysis.md) — Competitor and market analysis.
- [`discuss/product-strategy-review.md`](discuss/product-strategy-review.md) — Product strategy review notes.

### CI Status

The current `.github/workflows/ci.yml` contains 5 jobs:

- `lint-and-check`
- `test-linux-os`
- `test-linux-vm`
- `test-sdk`
- `docs-check`

Details:

- `test-linux-vm` is enabled only for manual `workflow_dispatch` runs and checks `/dev/kvm` first; on GitHub-hosted `ubuntu-latest` runners, it is skipped because KVM is unavailable.
- `test-sdk` first compiles the `vm` feature test target for `mimobox-sdk`, then runs library tests; full microVM integration tests still require Linux + KVM + VM assets.

## 11. Roadmap Status

| Status | Direction | Notes |
| --- | --- | --- |
| Completed | Unified SDK + smart routing by default | SDK `Sandbox` and CLI `--backend auto` are implemented |
| Completed | Three foundational isolation layers: OS-level, Wasm-level, and microVM-level | Linux KVM and snapshot/restore/fork are now verifiable |
| Completed | MCP Server | rmcp + stdio exposes 10 tools covering lifecycle, execution, files, snapshots, fork, and HTTP |
| Completed | Python SDK | PyO3 bindings, type stubs, streaming output, HTTP, files, snapshots, and error hierarchy are implemented |
| Completed | P0: microVM serial protocol enhancement and proxy foundation | `EXECS` / `STREAM:*` / `HTTP:REQUEST` are implemented, with `stdout` / `stderr` splitting, command-level env/timeout, and domain allowlist proxy connected |
| Planned | Formal vsock data plane + network proxy | The current serial path is better suited as a bring-up control plane; vsock remains the formal future direction |
| Planned | Windows backend + GPU / SaaS options | Current work still prioritizes completing Linux + macOS capabilities |

## 12. Maintenance Conventions

- Update the README whenever crates, CLI parameters, script entrypoints, performance baselines, or CI structure change.
- The README should describe only the **currently real implementation**; do not directly promote long-term designs from research documents into “implemented capabilities”.
- Precise external competitor latency, pricing, and deployment details are highly time-sensitive; the README keeps capability-level comparisons, while detailed analysis lives in `discuss/competitive-analysis.md`.
