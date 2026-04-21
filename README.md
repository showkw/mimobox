# mimobox

Rust 实现的多后端 Agent Sandbox，提供统一 `Sandbox` trait，并支持三种隔离层级：OS 级、Wasm、microVM（KVM）。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
| v1.2 | 2026-04-21 | 按当前 workspace、CLI、脚本和 CI 状态重写 README | 更新 | Codex |
| v1.1 | 2026-04-21 | 同步文档与代码现状，补充 `mimobox-vm`/KVM、性能与 CI 信息 | 更新 | Codex |
| v1.0 | 2026-04-20 | 重写根目录 README，补齐架构、API、性能、脚本与安全模型说明 | 新增 | Codex |

## 术语表

| 术语 | 定义 |
| --- | --- |
| OS 级沙箱 | 基于 Linux/macOS 内核原语隔离进程的后端 |
| Wasm 沙箱 | 基于 Wasmtime 执行 Wasm 模块的后端 |
| microVM 沙箱 | 基于 KVM 的硬件级隔离后端 |

## 文章内容大纲目录表

| 章节 | 标题 | 目的 |
| --- | --- | --- |
| 1 | 项目简介 | 说明定位、隔离层级和当前实现状态 |
| 2 | 目录结构 | 对齐当前 workspace / crate 布局 |
| 3 | 性能数据 | 汇总当前已知基线 |
| 4 | 使用方法 | 给出三类后端 CLI 示例 |
| 5 | 开发环境 | 列出当前可用脚本与构建入口 |
| 6 | 文档与状态 | 给出文档索引、CI 与维护约定 |

## 1. 项目简介

`mimobox` 面向需要安全执行不可信命令、脚本或 Wasm 工具的场景。当前仓库已经按 Cargo workspace 拆分为五个 crate：

- `mimobox-core`：统一 trait、配置、结果和错误类型
- `mimobox-os`：OS 级沙箱，覆盖 Linux + macOS
- `mimobox-wasm`：Wasm 沙箱，基于 Wasmtime
- `mimobox-vm`：microVM 沙箱，当前聚焦 Linux KVM
- `mimobox-cli`：CLI 入口与基准命令

## 2. 目录结构

```text
mimobox/
├── crates/
│   ├── mimobox-core/     # 核心 trait 定义
│   ├── mimobox-os/       # OS 级沙箱（Linux + macOS）
│   ├── mimobox-wasm/     # Wasm 沙箱（Wasmtime）
│   ├── mimobox-vm/       # microVM 沙箱（KVM）
│   └── mimobox-cli/      # CLI 入口
├── scripts/              # 构建/测试/运行脚本
│   ├── build-rootfs.sh
│   ├── extract-vmlinux.sh
│   ├── extract-vmlinux.py
│   └── test-e2e.sh
├── docs/
│   └── research/         # 技术调研报告
└── wit/                  # WIT 接口定义
```

## 3. 性能数据

| 阶段 | 后端 | 冷启动 P50 | 说明 |
| --- | --- | --- | --- |
| Phase 1 | OS 级 | 3.51ms | 来自 `docs/research/10-code-review-round2.md` |
| Phase 2 | Wasm | 0.61ms | 来自 `docs/research/14-microvm-design.md` |
| Phase 4 | microVM（KVM） | 待基准测试 | 仓库已有后端代码和 e2e 路径，稳定基线待补 |

## 4. 使用方法

下面示例使用逻辑命令名 `mimobox`。源码直接构建时，当前实际二进制通常为 `target/release/mimobox-cli`，也可以用 `cargo run -p mimobox-cli -- ...` 调用。

```bash
# OS 级沙箱
mimobox run --backend os --command "/bin/echo hello"

# Wasm 沙箱（需要以 wasm feature 构建 CLI）
mimobox run --backend wasm --command "app.wasm"

# KVM microVM（仅 Linux，且需要 --kernel 和 --rootfs）
mimobox run --backend kvm --kernel vmlinux --rootfs rootfs.cpio.gz --command "/bin/echo hello"
```

## 5. 开发环境

当前仓库没有 `scripts/build.sh`，实际构建入口如下：

```bash
scripts/setup.sh                                  # 初始化 Rust 工具链与常用 cargo 工具
cargo build -p mimobox-cli --release --features wasm,kvm
scripts/test.sh                                  # 运行测试
scripts/test-e2e.sh                              # 跨后端 e2e 验证
scripts/build-rootfs.sh                          # KVM rootfs 构建（仅 Linux）
scripts/extract-vmlinux.sh <output_path>         # 提取 vmlinux（仅 Linux）
scripts/check.sh                                 # cargo check / clippy / fmt --check
scripts/bench.sh                                 # 运行 criterion 基准
```

## 6. 文档与状态

- `docs/research/10-code-review-round2.md`：Phase 1 性能与代码审查
- `docs/research/14-microvm-design.md`：Phase 4 microVM 设计与当前基线
- `wit/mimobox.wit`：WIT 接口定义
- CI 当前配置 9 个 job：`check`、`release-check`、`test-linux`、`test-linux-kvm`、`test-e2e`、`test-wasm`、`test-macos`、`clippy`、`fmt`，状态为全绿

## 维护约定

- 修改 crate、CLI 参数、脚本入口或性能基线时，同步更新 README
- 以当前代码和脚本为准，不沿用历史研究文档中的过时目录或指标
