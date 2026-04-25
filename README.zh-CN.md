[English](README.md)

# mimobox

**mimobox** — A cross-platform Agent Sandbox in Rust with OS-level, Wasm, and microVM isolation, smart routing by default, and full control for advanced users.

Rust 实现的跨平台 Agent Sandbox，为 AI Agent 提供安全隔离的代码执行环境。

**默认智能路由，高级用户完全可控。** 默认模式下，SDK `Sandbox::new()` 和 CLI `--backend auto` 会自动选择合适的隔离层；需要精细控制时，又可以显式指定隔离层、资源限制、网络策略和 microVM 资产路径。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
| v2.2 | 2026-04-25 | 刷新 README：同步 8 crate workspace、MCP Server、Python SDK 能力、章节编号和 Quick Start 版本号 | 更新 | Codex |
| v2.1 | 2026-04-23 | 新增 `doctor` 环境诊断与 `setup` 资产引导命令，并统一 microVM 默认资产目录到 `~/.mimobox/assets` | 更新 | Codex |
| v2.0 | 2026-04-23 | 同步流式输出、HTTP 代理、结构化错误模型、命令级 env/timeout、Getting Started 文档与 GitHub Actions CI 现状 | 更新 | Codex |
| v1.6 | 2026-04-23 | 同步 GitHub Actions CI 为 5-job 精简版，并补充 KVM 手动触发与 hosted runner 限制说明 | 更新 | Codex |
| v1.5 | 2026-04-21 | 最终核对 README：同步目录结构、三层隔离现状、SDK/CLI 示例、竞品对比口径与路线图状态 | 更新 | Codex |
| v1.4 | 2026-04-21 | 同步 SDK、智能路由、microVM 串口命令通道与 Guest 协议现状 | 更新 | Codex |
| v1.3 | 2026-04-21 | 更新产品定位、性能数据与文档索引 | 更新 | — |
| v1.2 | 2026-04-21 | 按当前 workspace、CLI、脚本和 CI 状态重写 README | 更新 | Codex |
| v1.1 | 2026-04-21 | 同步文档与代码现状，补充 `mimobox-vm`、KVM、性能与 CI 信息 | 更新 | Codex |
| v1.0 | 2026-04-20 | 重写根目录 README，补齐架构、API、性能、脚本与安全模型说明 | 新增 | Codex |

## 术语表

| 术语 | 定义 |
| --- | --- |
| OS 级沙箱 | 基于 Linux/macOS 原生系统机制隔离进程的后端 |
| Wasm 沙箱 | 基于 Wasmtime 执行 Wasm 模块的后端 |
| microVM 沙箱 | 基于 Linux KVM 的硬件级隔离后端 |
| 预热池 | 预创建沙箱实例池（OS 级 / microVM 级），实现微秒级获取与复用 |
| 智能路由 | 根据命令类型、隔离偏好和信任级别自动选择后端 |

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

Python SDK 当前能力包括：

- streaming：`stream_execute()` 返回 `StreamIterator`，迭代产出 `StreamEvent`。
- HTTP proxy：`http_request()` 返回 `HttpResponse`，通过 host 侧受控代理发起请求。
- file operations：`read_file()` 和 `write_file()` 读写 microVM 沙箱内文件。
- env vars injection：`execute(command, env={...})` 支持命令级环境变量注入。
- snapshot/fork：`snapshot()`、`Sandbox.from_snapshot()` 和 `fork()` 支持 microVM 快照与 CoW fork。
- 错误层级：`SandboxError`、`SandboxProcessError`、`SandboxHttpError`、`SandboxLifecycleError`，并映射 `TimeoutError`、`FileNotFoundError`、`PermissionError`、`ConnectionError` 等标准异常。

## 1. 项目简介

`mimobox` 面向 AI Agent 安全执行代码的场景，目标是把**极低延迟**、**多层隔离**和**自托管可控性**放到同一个统一接口里。

核心定位不是“只做一个更快的后端”，而是两件事同时成立：

- **默认智能路由**：零配置就能跑。SDK `Sandbox::new()` 和 CLI `--backend auto` 会优先走最合适的隔离层。
- **高级用户完全可控**：SDK `Config::builder()` 和 CLI 显式 `--backend os|wasm|kvm` 允许你覆盖默认决策，精确控制隔离层、超时、内存、网络和 microVM 资源。

当前 Cargo workspace 拆分为 8 个 crate：

- `mimobox-core`：统一 trait、配置、结果和错误类型。
- `mimobox-os`：OS 级沙箱，覆盖 Linux + macOS，并提供 `SandboxPool`。
- `mimobox-wasm`：Wasm 沙箱，基于 Wasmtime。
- `mimobox-vm`：microVM 沙箱，当前聚焦 Linux KVM，包含 `VmPool`、`RestorePool`、HTTP 代理、快照和 fork。
- `mimobox-sdk`：统一 SDK API，负责默认智能路由和高级配置。
- `mimobox-cli`：CLI 入口、JSON 输出、诊断和资产引导命令。
- `mimobox-mcp`：MCP Server，基于 rmcp + stdio 暴露 10 个工具。
- `mimobox-python`：Python SDK，基于 PyO3 + maturin 绑定 Rust SDK。

### 智能路由的当前语义

- SDK 中，`IsolationLevel::Auto` 会结合**命令类型**和 `TrustLevel` 自动选路：
  - `.wasm/.wat/.wast` 优先走 Wasm。
  - `TrustLevel::Untrusted` 在 Linux + `vm` feature 下优先走 microVM。
  - `TrustLevel::Untrusted` 在 microVM 不可用时 fail-closed，不静默降级。
  - 其余默认走 OS 级。
- CLI 中，`--backend auto` 是默认值，当前走 SDK 默认配置，也就是默认 `TrustLevel::SemiTrusted`。
  - 因此 CLI 的 `auto` 会把 Wasm 文件自动路由到 Wasm。
  - 普通命令默认路由到 OS 级。
  - 如果你希望不可信命令优先走 microVM，请显式使用 `--backend kvm`，或者在 SDK 中设置 `TrustLevel::Untrusted`。

## 2. 三层隔离的当前实现状态

README 只记录当前源码里真实存在的实现，不把研究文档里的规划写成现状。

| 隔离层 | 当前状态 | 真实实现说明 |
| --- | --- | --- |
| OS 级 | 已完成 | Linux：Landlock + Seccomp-bpf + Namespaces + `setrlimit`；macOS：Seatbelt / `sandbox-exec`；Windows 仍为规划中 |
| Wasm 级 | 已完成 | 基于 Wasmtime + WASI，按需通过 `wasm` feature 启用 |
| microVM 级 | 已完成首版 | 基于 Linux KVM，已打通 guest `/init` + 串口命令协议 + snapshot/restore/fork，并支持流式输出、文件传输和 HTTP 代理等 guest/host 控制面能力 |

### 当前功能状态

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| SDK crate | 已完成 | `crates/mimobox-sdk/` 已提供统一 API、配置构建器、执行结果与实际后端查询 |
| 默认智能路由 | 已完成 | `IsolationLevel::Auto` 已在 SDK 中落地，CLI `--backend auto` 默认接入 |
| MCP Server | 已完成 | `crates/mimobox-mcp/` 基于 rmcp + stdio 暴露 10 个工具 |
| Python SDK | 已完成 | `crates/mimobox-python/` 基于 PyO3 暴露 Python 类、类型桩和异常层级 |
| 命令级环境变量注入与超时 | 已完成 | `execute_with_env()`、`execute_with_timeout()`、`execute_with_env_and_timeout()` 已落地；当前主要服务 Linux + microVM 后端 |
| 流式输出 | 已完成 | `stream_execute()` 已落地，输出 `StreamEvent::Stdout` / `Stderr` / `Exit` / `TimedOut` 事件 |
| HTTP 代理 + 域名白名单 | 已完成 | `http_request()` 已落地，通过 host 代理发起 HTTPS 请求；`allowed_http_domains` 控制白名单，默认网络策略仍是拒绝 |
| 结构化错误模型 | 已完成 | Rust 侧提供 `ErrorCode` 和 `SdkError::Sandbox`，Python 侧映射为异常层级 |

## 3. 目录结构

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

`vendor/` 如存在，仅保留历史 shim，不属于默认 workspace 使用路径。

## 4. 性能数据

| 场景 | 目标 | 当前 README 基线 | 状态 |
| --- | --- | --- | --- |
| OS 级冷启动 | <10ms | P50: 8.24ms | 达标 |
| Wasm 级冷启动 | <5ms | P50: 1.01ms（清缓存） | 达标 |
| OS 预热池热获取 | <100us | P50: 0.19us | 达标 |
| microVM 冷启动 | <300ms | P50: 253ms | 达标 |
| microVM 快照恢复 | <50ms | P50: 69ms（非池化）/ 28ms（池化 restore-to-ready） | 池化达标 |
| microVM 预热池热路径 | <1ms | P50: 773us | 达标 |

*OS 预热池数字为 acquire()+drop() 对象获取成本，不包含命令执行。*
*池化快照恢复为 restore-to-ready，不含命令执行和池补充开销。非池化快照恢复含全生命周期。*

### 指标定义

| 指标 | 起点 | 终点 | 说明 |
| --- | --- | --- | --- |
| OS 级冷启动 | `PlatformSandbox::new()` 前 | `execute(/bin/true)` 返回后 | 含创建、执行、销毁全生命周期 |
| Wasm 冷启动 | `WasmSandbox::new()` 前 | `execute(wasm)` 返回后 | 可能受模块缓存影响 |
| 预热池热获取 | `pool.acquire()` 前 | `drop()` 完成 | 仅测对象获取，不含命令执行 |
| microVM 冷启动 | `create_vm()` 前 | `run_command(echo)` 返回后 | 含创建、启动、执行、关闭全生命周期 |
| microVM 快照恢复 | `create_vm_for_restore()` 前 | `run_command(echo)` 返回后 | 内存中快照，非文件恢复 |
| microVM 池化快照恢复 | `RestorePool::restore()` 取出空壳 VM | memory 写入 + vCPU 恢复完成 | 不含命令执行，空壳 VM 由池预创建 |
| microVM 预热池热路径 | `pool.acquire()` 前 | `pooled.execute(echo)` 返回后 | 轻载 |

这些是 README 当前维护的性能基线。只要基准结果变化，就应该同步更新这里。

## 5. 竞品对比口径

外部产品的延迟、部署形态和默认能力会随着版本、模板、区域和 warm state 快速变化。为了避免 README 维护一组很快过时的第三方毫秒级数字，这里只保留**能力级对比**，把更细的市场分析放到 [`discuss/competitive-analysis.md`](discuss/competitive-analysis.md)。

| 产品 | 当前公开定位 | 与 mimobox 的主要差异 |
| --- | --- | --- |
| mimobox | 本地 / 自托管 Agent Sandbox，统一封装 OS + Wasm + microVM 三层隔离 | 当前仓库同时提供三层隔离，并把默认智能路由和显式高级控制放进同一 SDK / CLI / MCP / Python 入口 |
| Anthropic Sandbox Runtime | 基于 `sandbox-exec` / `bubblewrap` 的 OS 级 sandbox runtime + 网络代理 | 更偏 OS 级 runtime 包装，不提供 Wasm / microVM 分层 |
| E2B | 面向 Agent 的云端 sandbox / snapshot API | 更偏托管式 Linux sandbox 服务，不是本地统一三层路由 |
| Daytona | 基于 Sysbox 的 sandbox 基础设施和 API | 走容器 / sandbox 基础设施路线，不提供 Wasm / microVM 双层选择 |

如果你需要**精确的市场背景、功能矩阵和产品定位讨论**，请阅读 [`discuss/competitive-analysis.md`](discuss/competitive-analysis.md)。如果你需要 README 级别的稳定说明，请以上表为准。

## 6. SDK 使用示例

### 6.1 零配置：默认智能路由

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

### 6.2 高级控制：显式配置路由、环境变量注入和命令级超时

<!-- 注意：microVM 后端需要 Linux + KVM，运行 mimobox setup 下载 VM assets -->

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

说明：

- `execute_with_env()`、`execute_with_timeout()`、`execute_with_env_and_timeout()` 当前主要支持 Linux + `vm` feature 的 microVM 后端。
- 如果当前平台或构建没有启用 `vm` feature，SDK 会返回 `UnsupportedPlatform` 或 `BackendUnavailable`。
- 如果你要继续使用自动路由，可以把 `IsolationLevel::MicroVm` 改回 `IsolationLevel::Auto`；如果要**强制**走 microVM，则保留显式 `MicroVm` 并按需补上 `kernel_path()` / `rootfs_path()`。

### 6.3 流式输出：`stream_execute`

<!-- 注意：microVM 后端需要 Linux + KVM，运行 mimobox setup 下载 VM assets -->

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

### 6.4 HTTP 代理：`http_request`

<!-- 注意：microVM 后端需要 Linux + KVM，运行 mimobox setup 下载 VM assets -->

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

### 6.5 结构化错误模型

- Rust 侧统一通过 `mimobox_core::ErrorCode` 暴露结构化错误码，`mimobox_sdk::SdkError::Sandbox` 额外提供 `message` 和 `suggestion`。
- Python 绑定会在保留错误细节的同时映射为更易处理的异常层级，包括 `SandboxProcessError`、`SandboxHttpError`、`SandboxLifecycleError`，并复用 `TimeoutError`、`FileNotFoundError`、`PermissionError` 等标准异常。

## 7. MCP Server

`mimobox-mcp` 基于 rmcp 框架，通过 stdio 与 MCP 客户端通信，当前暴露 10 个工具。

| 工具 | 简要说明 |
| --- | --- |
| `create_sandbox` | 创建可复用沙箱实例，返回 `sandbox_id` 和隔离层级 |
| `execute_code` | 在沙箱中执行代码片段，支持 `python`、`javascript` / `node`、`bash` / `sh` |
| `execute_command` | 在沙箱中执行 shell 命令 |
| `destroy_sandbox` | 销毁指定沙箱并释放资源 |
| `list_sandboxes` | 列出活动沙箱及其元数据 |
| `read_file` | 从 microVM 沙箱读取文件，内容以 base64 返回 |
| `write_file` | 向 microVM 沙箱写入 base64 文件内容 |
| `snapshot` | 创建 microVM 沙箱内存快照 |
| `fork` | Fork microVM 沙箱，生成 CoW 副本 |
| `http_request` | 通过受控 HTTP 代理发起请求 |

启动方式：

```bash
# 默认 OS 级后端
cargo run -p mimobox-mcp

# 启用 microVM 后端
cargo run -p mimobox-mcp --features vm
```

更完整的 MCP 使用说明见 [`docs/mcp-server.md`](docs/mcp-server.md)。

## 8. CLI 用法示例

下面示例优先用仓库里当前真实可执行的命令形式：`cargo run -p mimobox-cli -- ...`。如果你已经构建好二进制，也可以直接调用 `target/release/mimobox-cli`。

### 8.1 默认智能路由

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

### 8.2 Wasm 后端

```bash
cargo run -p mimobox-cli --features wasm -- \
  run \
  --backend wasm \
  --command "app.wasm"
```

### 8.3 KVM microVM 后端

<!-- 注意：microVM 后端需要 Linux + KVM，运行 mimobox setup 下载 VM assets -->

```bash
cargo run -p mimobox-cli --features kvm -- \
  run \
  --backend kvm \
  --kernel "/path/to/vmlinux" \
  --rootfs "/path/to/rootfs.cpio.gz" \
  --command "/bin/echo hello"
```

### 8.4 环境诊断与资产引导

```bash
# 输出当前主机环境诊断报告
cargo run -p mimobox-cli -- doctor

# 首次引导 ~/.mimobox/assets 下的 microVM 资产，并在最后自动复查
cargo run -p mimobox-cli --features kvm -- setup
```

`doctor` 会检查操作系统、KVM/Seatbelt、内存、Linux 安全特性、feature flags、microVM 资产、Rust 工具链和可选 Python SDK，并返回：

- `0`：无警告、无错误。
- `1`：存在警告，但没有阻断错误。
- `2`：存在错误。

### 8.5 CLI 输出约定

CLI 默认输出 JSON，便于上层 Agent 或脚本消费；日志则写入 `logs/`。`doctor` 与 `setup` 例外，它们默认输出面向终端的人类可读报告。

microVM 路径当前通过 guest `/init` 驱动串口控制面，当前帧族包括：

1. guest 启动后输出 `READY`。
2. host 可发送 `EXEC:<len>:<payload>\n`、`EXECS:<id>:<len>:<payload>\n`、`HTTP:REQUEST:<id>:<len>:<json>\n` 等命令帧。
3. guest 对普通执行回传 `OUTPUT:` / `EXIT:`，对流式执行回传 `STREAM:START:` / `STREAM:STDOUT:` / `STREAM:STDERR:` / `STREAM:END:` / `STREAM:TIMEOUT:`，对 HTTP 代理回传 `HTTPRESP:HEADERS:` / `HTTPRESP:BODY:` / `HTTPRESP:END:` / `HTTPRESP:ERROR:`。
4. 文件传输继续通过 `FS:READ:` / `FS:WRITE:` 帧族完成。

这条链路已经是 guest 内真实执行，不再依赖 host 侧 stub。

## 9. 开发与验证

### 常用脚本

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

### 当前脚本职责

- `scripts/check.sh`：`cargo check` / `clippy` / `fmt --check`。
- `scripts/test.sh`：按目标运行 workspace 测试。
- `scripts/test-e2e.sh`：跨后端 e2e 验证。
- `scripts/bench.sh [crate-name] [bench-name|all]`：运行 criterion 基准。
- `scripts/build-rootfs.sh`：构建 KVM rootfs，默认输出到 `VM_ASSETS_DIR/rootfs.cpio.gz`，未设置时回退到 `~/.mimobox/assets/rootfs.cpio.gz`。
- `scripts/build-kernel.sh`：构建极简 KVM guest `vmlinux`，默认输出到 `VM_ASSETS_DIR/vmlinux`，未设置时回退到 `~/.mimobox/assets/vmlinux`。
- `scripts/extract-vmlinux.sh`：提取可用于 KVM 测试的 `vmlinux`。

## 10. 文档与 CI 状态

### 文档索引

- [`docs/getting-started.md`](docs/getting-started.md) — 快速上手、SDK 能力示例与平台约束。
- [`docs/architecture.md`](docs/architecture.md) — 当前仓库架构分层说明。
- [`docs/mcp-server.md`](docs/mcp-server.md) — MCP Server 工具、参数和客户端集成说明。
- [`docs/python-sdk.md`](docs/python-sdk.md) — Python SDK 安装、公开 API、异常和示例。
- [`docs/research/00-executive-summary.md`](docs/research/00-executive-summary.md) — 综合研究报告。
- [`docs/research/10-code-review-round2.md`](docs/research/10-code-review-round2.md) — Phase 1 代码审查。
- [`docs/research/14-microvm-design.md`](docs/research/14-microvm-design.md) — microVM 设计与路线。
- [`discuss/competitive-analysis.md`](discuss/competitive-analysis.md) — 竞品与市场分析。
- [`discuss/product-strategy-review.md`](discuss/product-strategy-review.md) — 产品战略评审记录。

### CI 状态

当前 `.github/workflows/ci.yml` 包含 5 个 job：

- `lint-and-check`
- `test-linux-os`
- `test-linux-vm`
- `test-sdk`
- `docs-check`

其中：

- `test-linux-vm` 仅在 `workflow_dispatch` 手动触发时启用，并先检查 `/dev/kvm`；在 GitHub-hosted `ubuntu-latest` runner 上会因缺少 KVM 而显示为跳过。
- `test-sdk` 会先编译 `mimobox-sdk` 的 `vm` feature 测试目标，再执行 library tests；完整的 microVM 集成测试仍需 Linux + KVM + VM assets 环境。

## 11. 路线图状态

| 状态 | 方向 | 说明 |
| --- | --- | --- |
| 已完成 | 统一 SDK + 默认智能路由 | SDK `Sandbox` 与 CLI `--backend auto` 已落地 |
| 已完成 | OS 级、Wasm 级、microVM 级三层基础能力 | Linux KVM 与 snapshot/restore/fork 已进入可验证状态 |
| 已完成 | MCP Server | rmcp + stdio 暴露 10 个工具，覆盖生命周期、执行、文件、快照、fork 和 HTTP |
| 已完成 | Python SDK | PyO3 绑定、类型桩、流式输出、HTTP、文件、快照和错误层级已落地 |
| 已完成 | P0：microVM 串口协议增强与代理基础能力 | `EXECS` / `STREAM:*` / `HTTP:REQUEST` 已落地，`stdout` / `stderr` 分流、命令级 env/timeout 与域名白名单代理已接入 |
| 规划中 | vsock 正式数据面 + 网络代理 | 当前串口更适合作为 bring-up 控制面，vsock 仍是后续正式方向 |
| 规划中 | Windows 后端 + GPU / SaaS 选项 | 当前仍以 Linux + macOS 能力完善为先 |

## 12. 维护约定

- 修改 crate、CLI 参数、脚本入口、性能基线或 CI 结构时，同步更新 README。
- README 只写**当前真实实现**，不要把研究文档中的远期设计直接提升为“已实现能力”。
- 外部竞品的精确延迟、定价和部署细节属于高时效信息；README 保持能力级对比，详细分析放到 `discuss/competitive-analysis.md`。
