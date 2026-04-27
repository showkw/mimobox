[English](README.md)

# MimoBox

[![CI](https://github.com/showkw/mimobox/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/showkw/mimobox/actions/workflows/ci.yml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT) [![PyPI](https://img.shields.io/pypi/v/mimobox.svg)](https://pypi.org/project/mimobox/) [![alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

**安全、本地、即时地运行 AI 生成的代码。**

无需 API 密钥。无需 Docker。无需云端。

MimoBox 是面向 AI agents 的本地 sandbox runtime。它通过统一的 SDK、CLI、MCP server 和 Python binding，提供多层隔离能力：OS（Landlock + Seccomp）、WebAssembly（Wasmtime）和 microVM（KVM）。下载单个 binary，即可安全地开始执行代码。

---

## 为什么选择 MimoBox？

- **Local-first** — 完全在你的机器上运行。数据不会离开你的网络，也不需要 API keys。
- **多层隔离** — OS-level（Landlock + Seccomp + Namespaces）、Wasm（Wasmtime）和 microVM（KVM）后端，并支持智能自动路由。
- **超低延迟** — OS 冷启动 P50 8.24 ms，Wasm 冷启动 P50 1.01 ms，warm pool acquire P50 0.19 µs。
- **Agent-native** — 内置包含 11 个 tools 的 MCP server、Python SDK，并开箱支持 LangChain / OpenAI Agents SDK 集成。

各隔离层的详细性能数据见[性能](#性能)。

## 快速开始

### 安装

```bash
curl -fsSL https://raw.githubusercontent.com/showkw/mimobox/master/scripts/install.sh | bash
```

### 试一试

```bash
mimobox run --backend auto --command "/bin/echo hello from MimoBox!"
```

就这样——无需 API 密钥、Docker 或云端。`auto` 后端会为你的平台选择最佳隔离层。

### Python

```bash
pip install mimobox
```

### Rust

```toml
[dependencies]
mimobox-sdk = "0.1.0-alpha"
```

### MCP Server

```bash
mimobox-mcp                              # stdio mode (default)
mimobox-mcp --transport http --port 8080 # Streamable HTTP mode
```

添加到你的 MCP client config：

```json
{
  "mcpServers": {
    "mimobox": {
      "command": "mimobox-mcp"
    }
  }
}
```

## 集成示例

### LangChain

```python
from mimobox import Sandbox
from langchain_core.tools import tool

@tool
def sandbox_run_command(command: str) -> str:
    """Run a command inside a secure sandbox."""
    with Sandbox() as sb:
        return sb.execute(command).stdout
```

### OpenAI Agents SDK

```python
from mimobox import Sandbox
from agents import function_tool

@function_tool
def sandbox_execute(command: str) -> str:
    """Run a command inside a secure sandbox."""
    with Sandbox() as sb:
        return sb.execute(command).stdout
```

### Python SDK

```python
from mimobox import Sandbox

with Sandbox() as sandbox:
    result = sandbox.execute("/bin/echo hello")
    print(result.stdout, end="")
```

```python
# File API
with Sandbox() as sandbox:
    sandbox.write_file("/tmp/hello.py", "print('hello')")
    result = sandbox.execute("python3 /tmp/hello.py")
    entries = sandbox.list_dir("/tmp")
```

## 平台支持

| 平台 | OS 沙箱 | Wasm 沙箱 | microVM 沙箱 |
| --- | --- | --- | --- |
| Linux (x86_64) | Landlock + Seccomp + Namespaces | Wasmtime | KVM (requires `/dev/kvm` + guest assets) |
| macOS (ARM64, Intel) | Seatbelt | Wasmtime | Not available |

## 隔离层

| 层级 | 后端 | 最适合 |
| --- | --- | --- |
| OS-level | Linux Landlock + Seccomp + Namespaces; macOS Seatbelt | 快速本地命令，默认智能路由 |
| Wasm | Wasmtime + WASI | 确定性的可移植工作负载 |
| microVM | Linux KVM + guest protocol + pools + snapshot/fork | 强隔离，生产工作负载 |

## 性能

| 指标 | P50 |
| --- | ---:|
| OS cold start | 8.24 ms |
| Wasm cold start | 1.01 ms |
| Warm pool acquire | 0.19 µs |
| microVM cold start | 253 ms |
| microVM snapshot restore (pooled) | 28 ms |

> **状态**：MimoBox 目前处于 **alpha** 阶段（v0.1.x）。它尚未经过正式安全审计。威胁模型和已知限制见 [SECURITY.md](SECURITY.md)。

## 文档

- [快速入门](docs/getting-started.md) — 安装、CLI 使用和 SDK 示例
- [架构](docs/architecture.md) — Workspace 结构和智能路由
- [API 参考](docs/api.md) — Rust SDK 类型和方法
- [Python SDK](docs/python-sdk.md) — Python binding 安装和使用
- [MCP Server](docs/mcp-server.md) — Tool 参考和 client 集成
- [MCP 配置](docs/mcp-config.md) — Claude Desktop、Cursor、VS Code 模板
- [性能](docs/performance.md) — Benchmark 方法和详细指标
- [FAQ 与故障排除](docs/faq.md) — 常见问题和解决方案

## 许可证

可按你的选择，基于 [Apache License, Version 2.0](LICENSE-APACHE) 或 [MIT license](LICENSE-MIT) 授权使用。
