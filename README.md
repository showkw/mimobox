# mimobox

Rust 实现的跨平台 Agent Sandbox，为 AI Agent 提供安全隔离的代码执行环境。

**默认智能路由，高级用户完全可控。** 零配置即可安全执行代码，SDK 同时暴露完整三层配置供精细控制。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
| v1.4 | 2026-04-21 | 同步 SDK、智能路由、microVM 串口命令通道与 Guest 协议现状 | 更新 | Codex |
| v1.3 | 2026-04-21 | 更新产品定位 + 性能数据 + 文档索引 | 更新 | — |
| v1.2 | 2026-04-21 | 按当前 workspace、CLI、脚本和 CI 状态重写 README | 更新 | Codex |
| v1.1 | 2026-04-21 | 同步文档与代码现状，补充 `mimobox-vm`/KVM、性能与 CI 信息 | 更新 | Codex |
| v1.0 | 2026-04-20 | 重写根目录 README，补齐架构、API、性能、脚本与安全模型说明 | 新增 | Codex |

## 术语表

| 术语 | 定义 |
| --- | --- |
| OS 级沙箱 | 基于 Linux/macOS 内核原语隔离进程的后端 |
| Wasm 沙箱 | 基于 Wasmtime 执行 Wasm 模块的后端 |
| microVM 沙箱 | 基于 KVM 的硬件级隔离后端 |
| 预热池 | 预创建沙箱实例池，实现微秒级获取 |

## 1. 项目简介

`mimobox` 面向 AI Agent 安全执行代码的场景，追求极致性能和跨平台支持。

核心特性：
- **三层隔离**：OS 级、Wasm、microVM，按需选择安全/性能平衡点
- **智能路由**：根据代码类型和信任级别自动选择最优隔离层级
- **极致性能**：Wasm 冷启动 P50 0.61ms，预热池热获取 P99 0.38us
- **跨平台**：Linux（三层全开）+ macOS（OS + Wasm）+ Windows（规划中）
- **自托管**：单 binary，无外部依赖，离线运行，数据不出域

当前仓库按 Cargo workspace 拆分为六个 crate：

- `mimobox-core`：统一 trait、配置、结果和错误类型
- `mimobox-sdk`：统一 SDK API，支持零配置默认和完整高级配置
- `mimobox-os`：OS 级沙箱，覆盖 Linux + macOS
- `mimobox-wasm`：Wasm 沙箱，基于 Wasmtime
- `mimobox-vm`：microVM 沙箱，当前聚焦 Linux KVM，已打通 Guest 串口命令执行链路
- `mimobox-cli`：CLI 入口与基准命令

### 当前功能状态

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| SDK crate | ✅ | `crates/mimobox-sdk/` 已提供统一 API、配置构建器与执行结果封装 |
| 智能路由 | ✅ | `IsolationLevel::Auto` 会根据命令类型与信任级别在 OS / Wasm / microVM 间自动选路 |
| microVM 串口命令通道 | ✅ | KVM guest `/init` 已通过串口协议执行真实命令，不再依赖 host 侧 stub |

## 2. 目录结构

```text
mimobox/
├── crates/
│   ├── mimobox-core/     # Sandbox trait + Config + Result + Error
│   ├── mimobox-sdk/      # 统一 SDK API（默认智能路由 + 高级完全可控）
│   ├── mimobox-os/       # OS 级沙箱（Linux Landlock+Seccomp+NS / macOS Seatbelt）
│   ├── mimobox-wasm/     # Wasm 沙箱（Wasmtime）
│   ├── mimobox-vm/       # microVM 沙箱（KVM）
│   │   ├── src/          # host 侧 KVM/microVM 实现
│   │   ├── guest/        # guest /init 与串口命令协议实现
│   │   └── tests/        # KVM e2e / 快照恢复验证
│   └── mimobox-cli/      # CLI 入口
├── scripts/              # 构建/测试/运行脚本
│   ├── setup.sh          # 初始化 Rust 工具链
│   ├── build-rootfs.sh   # KVM rootfs 构建
│   ├── extract-vmlinux.sh # 提取 vmlinux
│   ├── extract-vmlinux.py
│   ├── test.sh           # 运行测试
│   ├── test-e2e.sh       # 跨后端 e2e 验证
│   ├── check.sh          # cargo check / clippy / fmt
│   └── bench.sh          # criterion 基准
├── [已移除] vendor/      # 使用 crates.io 真实 rust-vmm crate
├── examples/             # 示例代码
├── tests/                # 集成测试
├── docs/
│   └── research/         # 技术调研报告
├── discuss/              # 讨论、评审、方案权衡
└── wit/                  # WIT 接口定义
```

## 3. 性能数据

测试环境：hermes Rocky Linux 9.7, 72 核, 93GB RAM, release 模式, 20 iterations。

| 后端 | 指标 | P50 | P99 | 目标 |
| --- | --- | --- | --- | --- |
| OS 级 | 冷启动 | 3.51ms | — | <10ms |
| Wasm | 冷启动 | 0.61ms | — | <5ms |
| 预热池 | 热获取 | — | 0.38us | <100us |
| microVM (KVM) | 冷启动 | 65.78ms | 69.52ms | <200ms |
| microVM (KVM) | 快照恢复 | 41.25ms | 42.07ms | <50ms |

> **注**：microVM 性能数据已基于 guest `/init` + 串口命令通道的真实执行链路采集；当前仍处于单串口协议阶段，`stdout`/`stderr` 尚未拆分为独立回传通道。

与 Agent Sandbox 竞品对比：

| 指标 | mimobox | Anthropic SRT | E2B | Daytona |
| --- | --- | --- | --- | --- |
| Wasm 冷启动 | **0.61ms** | — | — | — |
| OS 冷启动 | **3.51ms** | ~0ms | — | — |
| microVM 冷启动 | **65.78ms** | — | ~150ms | — |
| 预热池热获取 | **0.38us** | — | — | — |

详见 `discuss/competitive-analysis.md`。

## 4. 使用方法

下面示例使用逻辑命令名 `mimobox`。源码直接构建时，当前实际二进制通常为 `target/release/mimibox-cli`，也可以用 `cargo run -p mimobox-cli -- ...` 调用。

```bash
# OS 级沙箱
mimobox run --backend os --command "/bin/echo hello"

# Wasm 沙箱（需要以 wasm feature 构建 CLI）
mimobox run --backend wasm --command "app.wasm"

# KVM microVM（仅 Linux，且需要 --kernel 和 --rootfs）
mimobox run --backend kvm --kernel vmlinux --rootfs rootfs.cpio.gz --command "/bin/echo hello"
```

microVM 路径当前会在 guest 内通过 `/init` 驱动串口控制面，等待 `READY` 后发送命令帧，再按协议回收输出和退出码；这条链路已经是 guest 内真实执行，不再是 host 侧模拟返回。

## 5. 开发环境

```bash
scripts/setup.sh                                  # 初始化 Rust 工具链与常用 cargo 工具
cargo build -p mimibox-cli --release --features wasm,kvm
scripts/test.sh                                   # 运行测试
scripts/test-e2e.sh                               # 跨后端 e2e 验证（6 个测试用例）
scripts/build-rootfs.sh                           # KVM rootfs 构建（仅 Linux）
scripts/extract-vmlinux.sh <output_path>          # 提取 vmlinux（仅 Linux）
scripts/check.sh                                  # cargo check / clippy / fmt --check
scripts/bench.sh                                  # 运行 criterion 基准（默认 mimobox-os，可传 mimobox-vm 跑 KVM）
```

## 6. Guest 串口协议

当前 KVM guest 控制面使用基于 COM1 的单行文本协议，host 与 guest 约定如下：

1. 启动同步：
   guest `/init` 启动后会先输出 `mimobox-kvm: init OK`，随后输出 `READY`，表示进入命令循环。
2. 命令下发：
   host 在收到 `READY` 后，通过串口写入以 `EXEC:` 开头的单行命令帧，让 guest 使用 `/bin/sh -lc` 执行真实命令。
3. 输出回传：
   guest 将子进程输出编码为 `OUTPUT:` 帧逐行回传；换行、回车、制表符、反斜杠和非打印字节会转义为 `\\n`、`\\r`、`\\t`、`\\\\`、`\\xNN`。
4. 退出回传：
   guest 命令完成后回传 `EXIT:<code>`，host 以此组装 `exit_code`。
5. 当前限制：
   当前仍是单串口协议阶段，guest 的 stdout/stderr 复用同一输出流，host 侧 `stderr` 暂为空。

## 7. 文档与状态

### 文档索引

- `docs/research/00-executive-summary.md` — 综合研究报告
- `docs/research/10-code-review-round2.md` — Phase 1 性能与代码审查
- `docs/research/14-microvm-design.md` — Phase 4 microVM 设计
- `discuss/competitive-analysis.md` — Agent Sandbox 竞品功能差异分析
- `discuss/product-strategy-review.md` — 三层隔离架构战略评审记录

### CI 状态

9 个 job 全绿：`check`、`release-check`、`test-linux`、`test-linux-kvm`、`test-e2e`、`test-wasm`、`test-macos`、`clippy`、`fmt`。`test-linux-kvm` 运行 `cargo test -p mimobox-vm --features kvm`，`test-e2e` 通过 `scripts/test-e2e.sh` 执行 6 个跨后端验证用例。

### 路线图

| 优先级 | 方向 |
| --- | --- |
| **P0** | microVM 串口协议完善（stdout/stderr 拆分、健壮性补强）+ 持续性能优化 |
| **P1** | vsock 正式数据面 + 网络代理（域名白名单）+ 统一网络抽象 |
| **P2** | MCP 协议集成 + 编排 API |
| **P3** | Windows 后端 + 可选 SaaS + GPU |

## 维护约定

- 修改 crate、CLI 参数、脚本入口或性能基线时，同步更新 README
- 以当前代码和脚本为准，不沿用历史研究文档中的过时目录或指标
