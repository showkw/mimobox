[English](README.md)

# mimobox

[![CI](https://github.com/showkw/mimobox/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/showkw/mimobox/actions/workflows/ci.yml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT) [![alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

**mimobox** — 在安全隔离的沙箱中运行 AI 生成的代码。本地运行。无需 API 密钥，无需 Docker，无需云端。

> **无需 API 密钥。无需 Docker。无需云端。** 下载单个二进制文件即可安全执行代码。OS 级和 Wasm 沙箱在所有平台可用；microVM 隔离在支持 KVM 的 Linux 上可用。

mimobox 通过统一的 SDK、CLI、MCP server 和 Python binding，为 AI Agent 工作负载提供安全、自托管的代码执行能力。

## Quick Start

> **平台说明**：macOS 仅支持 OS 级和 Wasm 沙箱。microVM 功能需要支持 KVM 的 Linux（`/dev/kvm`）。MCP server 二进制目前仅支持 Linux。

### 安装

```bash
curl -fsSL https://raw.githubusercontent.com/showkw/mimobox/master/scripts/install.sh | bash
```

### Python
> Python wheel 即将发布到 PyPI。当前请从源码构建（需要 Rust 工具链）：

```bash
git clone https://github.com/showkw/mimobox.git && cd mimobox
cargo build --release -p mimobox-python
# wheel 将生成在 target/wheels/
pip install target/wheels/*.whl
```

### Rust

```toml
[dependencies]
mimobox-sdk = { git = "https://github.com/showkw/mimobox.git", branch = "master" }
```

### 从源码构建

```bash
git clone https://github.com/showkw/mimobox.git && cd mimobox
cargo build --release -p mimobox-cli --features mimobox-cli/wasm
```

### 运行

```bash
mimobox run --backend auto --command "/bin/echo hello"
```

### Python 示例

```python
from mimobox import Sandbox

with Sandbox() as sandbox:
    result = sandbox.execute("/bin/echo hello")
    print(result.stdout, end="")
```

### Rust 示例

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

流式输出、文件操作、HTTP proxy、snapshot/fork、CLI 示例和高级 SDK 用法见 [docs/getting-started.md](docs/getting-started.md)。

> **Status**: mimobox 目前处于 **alpha** 阶段（v0.1.x）。它尚未经过正式安全审计。威胁模型和已知限制见 [SECURITY.md](SECURITY.md)。

## 平台支持

| Platform | OS Sandbox | Wasm Sandbox | microVM Sandbox |
| --- | --- | --- | --- |
| Linux (x86_64) | Landlock + Seccomp + Namespaces | Wasmtime | KVM (requires `/dev/kvm` + guest assets) |
| macOS (ARM64, Intel) | Seatbelt | Wasmtime | Not available |

## 三层隔离

| Layer | Backend | Best For | Status |
| --- | --- | --- | --- |
| OS-level | Linux Landlock + Seccomp + namespaces; macOS Seatbelt | 快速本地命令和默认智能路由 | Implemented |
| Wasm | Wasmtime + WASI | 确定性的可移植工作负载 | Implemented |
| microVM | Linux KVM + guest protocol + pools + snapshot/fork | 强隔离和 Linux 生产工作负载 | Implemented on Linux (requires KVM + guest kernel + rootfs) |

术语表和架构细节见 [docs/architecture.md](docs/architecture.md)。

## 性能概览 P50

| Scenario | Target | Current P50 | Status |
| --- | --- | --- | --- |
| OS-level cold start | <10ms | 8.24ms | Meets target |
| Wasm cold start | <5ms | 1.01ms | Meets target |
| OS warm pool acquisition | <100us | 0.19us | Meets target |
| microVM cold start | <300ms | 253ms | Meets target |
| microVM snapshot restore | <50ms | 69ms non-pooled / 28ms pooled | Pooled path meets target |
| microVM warm pool hot path | <1ms | 773us | Meets target |

指标定义、benchmark 范围和注意事项维护在 [docs/performance.md](docs/performance.md)。

## 目录结构

```text
mimobox/
├── Cargo.toml
├── README.md
├── CHANGELOG.md
├── crates/
│   ├── mimobox-core/       # Sandbox trait, config, result, and error types
│   ├── mimobox-os/         # OS-level sandbox backends
│   ├── mimobox-wasm/       # Wasmtime sandbox backend
│   ├── mimobox-vm/         # KVM microVM backend, pools, snapshot, fork
│   ├── mimobox-sdk/        # Unified Rust SDK and smart routing
│   ├── mimobox-cli/        # CLI entrypoint
│   ├── mimobox-mcp/        # MCP server over stdio
│   └── mimobox-python/     # Python SDK via PyO3
├── docs/                   # User, API, architecture, MCP, and performance docs
├── discuss/                # Design notes, reviews, and market analysis
├── examples/               # Example code
├── scripts/                # Build, test, run, and setup scripts
├── tests/                  # Integration tests
├── wit/                    # WIT interface definitions
└── logs/                   # Runtime logs
```

## 路线图

| Status | Direction | Notes |
| --- | --- | --- |
| Completed | Unified SDK + smart routing | `Sandbox::new()` 和 CLI `--backend auto` 已实现 |
| Completed | OS + Wasm + microVM isolation | Linux KVM、snapshot、restore 和 fork 可验证 |
| Completed | MCP Server | 面向生命周期、执行、文件、snapshot、fork 和 HTTP 的 10 个 stdio tools |
| Completed | Python SDK | 支持执行、streaming、文件、HTTP、snapshot 和错误的 PyO3 bindings |
| Planned | Formal vsock data plane | Serial 仍是 bring-up/control path；vsock 是未来 data plane |
| Planned | Windows backend + GPU/SaaS options | 当前优先级仍是提升 Linux 和 macOS 成熟度 |

## 文档

- [docs/getting-started.md](docs/getting-started.md) — SDK 和 CLI 示例，包括已移出的 README 章节 6.1-6.5 和 8。
- [docs/architecture.md](docs/architecture.md) — 架构、智能路由和术语表。
- [docs/performance.md](docs/performance.md) — 指标定义、benchmark 方法和性能说明。
- [docs/api.md](docs/api.md) — Rust SDK API 参考。
- [docs/python-sdk.md](docs/python-sdk.md) — Python SDK 用法。
- [docs/mcp-server.md](docs/mcp-server.md) — MCP server 设置、tools 和 client 集成。
- [docs/mcp-integration.md](docs/mcp-integration.md) — MCP 集成说明。
- [discuss/competitive-analysis.md](discuss/competitive-analysis.md) — 竞品对比和市场定位。
- [CHANGELOG.md](CHANGELOG.md) — 发布说明和已迁移的 README 版本历史。

竞品对比被有意保留在本 README 之外；见 [discuss/competitive-analysis.md](discuss/competitive-analysis.md)。
