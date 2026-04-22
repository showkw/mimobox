# mimobox

Rust 实现的跨平台 Agent Sandbox，为 AI Agent 提供安全隔离的代码执行环境。

**默认智能路由，高级用户完全可控。** 默认模式下，SDK `Sandbox::new()` 和 CLI `--backend auto` 会自动选择合适的隔离层；需要精细控制时，又可以显式指定隔离层、资源限制、网络策略和 microVM 资产路径。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
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

## 1. 项目简介

`mimobox` 面向 AI Agent 安全执行代码的场景，目标是把**极低延迟**、**多层隔离**和**自托管可控性**放到同一个统一接口里。

核心定位不是“只做一个更快的后端”，而是两件事同时成立：

- **默认智能路由**：零配置就能跑。SDK `Sandbox::new()` 和 CLI `--backend auto` 会优先走最合适的隔离层。
- **高级用户完全可控**：SDK `Config::builder()` 和 CLI 显式 `--backend os|wasm|kvm` 允许你覆盖默认决策，精确控制隔离层、超时、内存、网络和 microVM 资源。

当前 Cargo workspace 拆分为六个 crate：

- `mimobox-core`：统一 trait、配置、结果和错误类型
- `mimobox-sdk`：统一 SDK API，负责默认智能路由和高级配置
- `mimobox-os`：OS 级沙箱，覆盖 Linux + macOS
- `mimobox-wasm`：Wasm 沙箱，基于 Wasmtime
- `mimobox-vm`：microVM 沙箱，当前聚焦 Linux KVM
- `mimobox-cli`：CLI 入口、JSON 输出和基准命令

### 智能路由的当前语义

- SDK 中，`IsolationLevel::Auto` 会结合**命令类型**和 `TrustLevel` 自动选路：
  - `.wasm/.wat/.wast` 优先走 Wasm
  - `TrustLevel::Untrusted` 在 Linux + `vm` feature 下优先走 microVM
  - 其余默认走 OS 级
- CLI 中，`--backend auto` 是默认值，当前走 SDK 默认配置，也就是默认 `TrustLevel::SemiTrusted`
  - 因此 CLI 的 `auto` 会把 Wasm 文件自动路由到 Wasm
  - 普通命令默认路由到 OS 级
  - 如果你希望不可信命令优先走 microVM，请显式使用 `--backend kvm`，或者在 SDK 中设置 `TrustLevel::Untrusted`

## 2. 三层隔离的当前实现状态

README 只记录当前源码里真实存在的实现，不把研究文档里的规划写成现状。

| 隔离层 | 当前状态 | 真实实现说明 |
| --- | --- | --- |
| OS 级 | 已完成 | Linux：Landlock + Seccomp-bpf + Namespaces + `setrlimit`；macOS：Seatbelt / `sandbox-exec`；Windows 仍为规划中 |
| Wasm 级 | 已完成 | 基于 Wasmtime + WASI，按需通过 `wasm` feature 启用 |
| microVM 级 | 已完成首版 | 基于 Linux KVM，已打通 guest `/init` + 串口命令协议 + snapshot/restore；当前 `stdout`/`stderr` 仍复用单串口流，但**不再依赖 host 侧 stub** |

### 当前功能状态

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| SDK crate | 已完成 | `crates/mimobox-sdk/` 已提供统一 API、配置构建器、执行结果与实际后端查询 |
| 默认智能路由 | 已完成 | `IsolationLevel::Auto` 已在 SDK 中落地，CLI `--backend auto` 默认接入 |
| 预热池 | 已完成 | `mimobox-os` 与 `mimobox-vm` 均提供预热池，OS 级 P99 0.38us，microVM 热路径 P50 788us |
| microVM Guest 执行链路 | 已完成首版 | guest `/init` 会输出 `READY`，host 发送 `EXEC:<len>:<payload>\\n` 帧，guest 回传 `OUTPUT:` / `EXIT:` |
| microVM 快照恢复 | 已完成首版 | `mimobox-vm` 已提供 `MicrovmSnapshot` 与快照恢复验证 |

## 3. 目录结构

```text
mimobox/
├── .github/
│   └── workflows/
│       └── ci.yml
├── crates/
│   ├── mimobox-cli/       # CLI 入口与 JSON 输出
│   ├── mimobox-core/      # Sandbox trait + Config + Result + Error
│   ├── mimobox-os/        # OS 级沙箱（Linux/macOS）
│   ├── mimobox-sdk/       # 统一 SDK API（默认智能路由 + 高级完全可控）
│   ├── mimobox-vm/        # microVM 沙箱（Linux KVM）
│   │   ├── benches/       # microVM 基准
│   │   ├── guest/         # guest /init 与串口命令协议实现
│   │   ├── src/           # host 侧 KVM / 快照实现
│   │   └── tests/         # KVM e2e / 快照恢复验证
│   └── mimobox-wasm/      # Wasm 沙箱（Wasmtime）
├── discuss/               # 讨论、评审、方案权衡
├── docs/                  # 架构与技术文档
├── examples/
│   └── wasm-tools/
│       └── echo-tool/
├── logs/                  # CLI / 脚本日志
├── scripts/
│   ├── bench.sh
│   ├── build-rootfs.sh
│   ├── check.sh
│   ├── extract-vmlinux.py
│   ├── extract-vmlinux.sh
│   ├── setup.sh
│   ├── test-e2e.sh
│   └── test.sh
├── tests/                 # workspace 集成测试
├── vendor/                # 历史 shim / 研究资产，当前 workspace 默认不通过 patch 覆盖 crates.io 依赖
├── wit/
│   └── mimobox.wit
├── AGENTS.md
├── CLAUDE.md
├── Cargo.toml
└── README.md
```

当前工作区里还会看到 `.env`、`.idea/`、`target/` 等本地环境、IDE 或构建产物目录；它们是当前目录的一部分，但不属于仓库核心源码结构，所以不放进主结构树里展开说明。

## 4. 性能数据

以下为 bench 完整生命周期测量（create + boot/restore + execute + shutdown），包含沙箱创建和销毁开销。测试环境：Intel Xeon E5-2686 v4 @ 2.30GHz, 93GB RAM。

| 后端 | 指标 | 目标 | 实测 | 状态 |
| --- | --- | --- | --- | --- |
| OS 级 | 冷启动 P50 | <10ms | `3.51ms` | ✅ |
| Wasm | 冷启动 P50 | <5ms | `0.61ms` | ✅ |
| OS 级预热池 | 热获取 P99 | <100us | `0.38us` | ✅ |
| microVM (KVM) | 冷启动 P50 | <200ms | `252ms` | 🔄 优化中 |
| microVM (KVM) | 快照恢复 P50 | <50ms | `70ms` | 🔄 优化中 |
| microVM (KVM) | 命令执行 P50 | — | `711us` | ✅ |
| microVM (KVM) | 预热池热路径 P50 | <1ms | `788us` | ✅ |

这些是 README 当前维护的性能基线。只要基准结果变化，就应该同步更新这里。

## 5. 竞品对比口径

外部产品的延迟、部署形态和默认能力会随着版本、模板、区域和 warm state 快速变化。为了避免 README 维护一组很快过时的第三方毫秒级数字，这里只保留**能力级对比**，把更细的市场分析放到 [`discuss/competitive-analysis.md`](discuss/competitive-analysis.md)。

| 产品 | 当前公开定位 | 与 mimobox 的主要差异 |
| --- | --- | --- |
| mimobox | 本地 / 自托管 Agent Sandbox，统一封装 OS + Wasm + microVM 三层隔离 | 唯一在当前仓库中同时提供三层隔离，并把默认智能路由和显式高级控制放进同一 SDK / CLI |
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

### 6.2 高级控制：显式配置路由和资源限制

```rust
use std::time::Duration;

use mimobox_sdk::{Config, IsolationLevel, Sandbox, TrustLevel};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::Auto)
        .trust_level(TrustLevel::Untrusted)
        .memory_limit_mb(256)
        .timeout(Duration::from_secs(5))
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let result = sandbox.execute("python script.py")?;

    println!("exit = {:?}", result.exit_code);
    println!("resolved backend = {:?}", sandbox.active_isolation());
    sandbox.destroy()?;
    Ok(())
}
```

说明：

- 上面第二个例子在 Linux + `vm` feature 可用时，会优先把不可信命令路由到 microVM
- 如果当前平台或构建没有启用 `vm` feature，SDK 会回退到可用后端或返回 `BackendUnavailable`
- 如果你要**强制**走 microVM，而不是“按策略优先”，请把 `IsolationLevel::Auto` 改成 `IsolationLevel::MicroVm`，并补上 `kernel_path()` / `rootfs_path()`

## 7. CLI 用法示例

下面示例优先用仓库里当前真实可执行的命令形式：`cargo run -p mimobox-cli -- ...`。如果你已经构建好二进制，也可以直接调用 `target/release/mimobox-cli`。

### 7.1 默认智能路由

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

### 7.2 Wasm 后端

```bash
cargo run -p mimobox-cli --features wasm -- \
  run \
  --backend wasm \
  --command "app.wasm"
```

### 7.3 KVM microVM 后端

```bash
cargo run -p mimobox-cli --features kvm -- \
  run \
  --backend kvm \
  --kernel "/path/to/vmlinux" \
  --rootfs "/path/to/rootfs.cpio.gz" \
  --command "/bin/echo hello"
```

### 7.4 CLI 输出约定

CLI 默认输出 JSON，便于上层 Agent 或脚本消费；日志则写入 `logs/`。

microVM 路径当前通过 guest `/init` 驱动串口控制面：

1. guest 启动后输出 `READY`
2. host 发送 `EXEC:<len>:<payload>\n` 命令帧
3. guest 逐行回传 `OUTPUT:` 帧
4. guest 最终回传 `EXIT:<code>`

这条链路已经是 guest 内真实执行，不再是 host 侧模拟返回。

## 8. 开发与验证

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

- `scripts/check.sh`：`cargo check` / `clippy` / `fmt --check`
- `scripts/test.sh`：按目标运行 workspace 测试
- `scripts/test-e2e.sh`：跨后端 e2e 验证
- `scripts/bench.sh [crate-name] [bench-name|all]`：运行 criterion 基准
- `scripts/build-rootfs.sh`：构建 KVM rootfs，默认输出到 `crates/mimobox-vm/rootfs.cpio.gz`
- `scripts/build-kernel.sh`：构建极简 KVM guest `vmlinux`，默认输出到 `crates/mimobox-vm/vmlinux`
- `scripts/extract-vmlinux.sh`：提取可用于 KVM 测试的 `vmlinux`

## 9. 文档与 CI 状态

### 文档索引

- [`docs/architecture.md`](docs/architecture.md) — 当前仓库架构分层说明
- [`docs/research/00-executive-summary.md`](docs/research/00-executive-summary.md) — 综合研究报告
- [`docs/research/10-code-review-round2.md`](docs/research/10-code-review-round2.md) — Phase 1 代码审查
- [`docs/research/14-microvm-design.md`](docs/research/14-microvm-design.md) — microVM 设计与路线
- [`discuss/competitive-analysis.md`](discuss/competitive-analysis.md) — 竞品与市场分析
- [`discuss/product-strategy-review.md`](discuss/product-strategy-review.md) — 产品战略评审记录

### CI 状态

当前 `.github/workflows/ci.yml` 包含 9 个 job：

- `check`
- `release-check`
- `test-linux`
- `test-linux-kvm`
- `test-e2e`
- `test-wasm`
- `test-macos`
- `clippy`
- `fmt`

其中：

- `test-linux-kvm` 会准备 `vmlinux` 和 `rootfs` 后执行 `cargo test -p mimobox-vm --features kvm`
- `test-e2e` 通过 `scripts/test-e2e.sh` 执行 6 个跨后端验证用例

## 10. 路线图状态

| 状态 | 方向 | 说明 |
| --- | --- | --- |
| 已完成 | 统一 SDK + 默认智能路由 | SDK `Sandbox` 与 CLI `--backend auto` 已落地 |
| 已完成 | OS 级、Wasm 级、microVM 级三层基础能力 | Linux KVM 与 snapshot/restore 已进入可验证状态 |
| 进行中 | microVM 单串口协议增强 | `stdout` / `stderr` 拆分、健壮性补强、协议演进 |
| 规划中 | vsock 正式数据面 + 网络代理 | 当前串口更适合作为 bring-up 控制面，vsock 仍是后续正式方向 |
| 规划中 | MCP 协议集成 + 编排 API | 面向 Agent 框架和批量调度 |
| 规划中 | Windows 后端 + GPU / SaaS 选项 | 当前仍以 Linux + macOS 能力完善为先 |

## 11. 维护约定

- 修改 crate、CLI 参数、脚本入口、性能基线或 CI 结构时，同步更新 README
- README 只写**当前真实实现**，不要把研究文档中的远期设计直接提升为“已实现能力”
- 外部竞品的精确延迟、定价和部署细节属于高时效信息；README 保持能力级对比，详细分析放到 `discuss/competitive-analysis.md`
