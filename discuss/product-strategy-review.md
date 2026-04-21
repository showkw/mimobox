---
title: mimobox 产品战略评审：三层隔离架构决策
date: 2026-04-21
status: final
participants: 总指挥（Claude）、技术方案评审官、产品与业务分析师
---

# mimobox 产品战略评审：三层隔离架构决策

## 1. 评审背景

mimobox 已完成 Phase 1-4（OS 级 + Wasm + microVM + 预热池），所有性能目标达标，CI 9/9 全绿。
在竞品分析中发现所有主要竞品（Anthropic SRT、E2B、OpenAI Codex、Daytona、Fly.io Sprites）均采用单层隔离，
由此引发"三层隔离是否是正确方向"的战略讨论。

### 争议双方

**观点 A（质疑多层）：**
- 大公司有能力做多层但选择不做，说明单层就够了
- 三层维护成本 3x，分散工程资源
- LLM 推理 500ms-5s 是瓶颈，沙箱冷启动差异（0.61ms vs 150ms）无感知
- 真正的护城河在生态（SDK、集成），不在底层隔离机制
- 早期项目做减法比做加法重要

**观点 B（坚持多层）：**
- Claude Code 是有限场景，不代表 Agent 全部需求
- 三层提供按需选择安全/性能平衡点的能力
- Rust 单 binary 让多层分发成本极低
- 保持三层并极致优化，形成技术壁垒

## 2. 评审结论

### 2.1 三层架构保留 — 三方一致

| 维度 | 结论 |
|------|------|
| 维护成本 | 非 3x，实际约 1.5x。7,421 行代码、5 个解耦 crate、共享 Sandbox trait，三层零互相引用 |
| 性能收益 | 单次调用差异可忽略，批量/多租户场景差异显著（200 次调用：Wasm 122ms vs microVM 13s） |
| 安全审计 | 约 1.5-2x，非 3x。共享 config 统一策略审计，各层机制独立但代码量有限（600-800 行/层） |
| 平台覆盖 | 不对称但合理：macOS 开发 + Linux 部署是标准工作流 |
| 市场趋势 | 2026 年出现"Composite Sandboxing"趋势，K8s agent-sandbox SIG 正在标准化多后端抽象 |

### 2.2 大公司选择单层的原因 — 产品定位，非技术限制

| 公司 | 选择 | 原因 |
|------|------|------|
| Anthropic SRT | OS 级 | 服务 Claude Code 单一场景，本地开发不需要 VM |
| E2B | microVM | 云端 SaaS 统一基础设施，Firecracker 已够用 |
| OpenAI Codex | 容器+gVisor | 闭源自用产品，不为第三方开发者设计 |
| Daytona | 容器 | 从开发环境转型，Sysbox 覆盖目标场景 |

**关键洞察**：Google 内部同时用 gVisor + Firecracker，说明大公司确实在用多层技术。
对外暴露统一接口而非单一后端，恰恰证明"统一抽象 + 多后端"是正确方向。

### 2.3 关键发现：microVM 层仍为 PoC

技术评审发现 `emulate_guest_command` 为硬编码模拟（仅实现 `echo` 和 `true`），
microVM 的 65.78ms 冷启动数据真实，但"执行任意命令"能力尚未实现。
需要接入 vsock/串口真实通信通道才能成为可用产品。

## 3. 产品原则

### 核心原则：默认智能路由，高级用户完全可控

```
// 零配置 —— 自动路由，开箱即用
let sandbox = Sandbox::new()?;
sandbox.execute("python analyze.py").await?;

// 完整配置 —— 开发者精确控制每一层参数
let sandbox = Sandbox::with_config(Config::builder()
    .isolation(IsolationLevel::Wasm)
    .memory_limit_mb(512)
    .fs_readwrite(["/workspace"])
    .network(NetworkPolicy::allow_domains(["api.github.com"]))
    .timeout(Duration::from_secs(30))
    .build()
)?;
```

**零配置是起点不是天花板。** 像 PostgreSQL：默认配置跑得很好，但每个参数都可以精确调整。

### 智能路由决策逻辑

| 条件 | 自动选择 | 理由 |
|------|---------|------|
| 代码可编译为 Wasm + 延迟敏感 | Wasm | 冷启动 <1ms |
| 任意 shell 命令 + 单租户 | OS 级 | 最快启动 + 足够安全 |
| 任意代码 + 多租户/零信任 | microVM | 硬件级隔离 |
| 资源受限环境 | Wasm 或 OS 级 | 轻量 |

## 4. 路线图

### P0（0-3 月）：SDK + microVM 真实通信

| 任务 | 理由 |
|------|------|
| **mimibox-sdk crate** | 没有 SDK = 演示品。Agent 框架集成需要编程接口 |
| **Python/TypeScript 绑定** | Agent 开发者主要用 Python/TS，Rust-only 无法覆盖 |
| **microVM vsock/串口通信** | `emulate_guest_command` 硬编码必须替换为真实通信 |
| **智能路由第一版** | 基于文件类型 + 信任级别自动选层 |

验收标准：Agent 框架开发者在 5 分钟内完成 `cargo add mimibox` 到执行第一个沙箱命令。

### P1（3-6 月）：网络代理 + 产品打磨

| 任务 | 理由 |
|------|------|
| **网络代理**（域名白名单/黑名单） | Agent 执行需要调 API，`deny_network` 硬禁是功能缺口 |
| **统一网络抽象** | 三层各有网络模型（OS: Namespace / Wasm: WASI / VM: virtio-net），需统一 API |
| **信任级别 API** | `TrustLevel::Trusted / SemiTrusted / Untrusted`，映射到隔离层级 |
| **错误处理统一** | 三层错误类型对用户透明，统一为 SandboxError |

### P2（6-12 月）：生态集成

| 任务 | 理由 |
|------|------|
| **MCP 协议集成** | Wasm Component Model + MCP 是 2026 年趋势，mimobox 可做底层引擎 |
| **编排 API**（批量创建/调度/回收） | Agent 框架需要批量调度沙箱 |
| **预热池 + 智能路由联动** | 按预期负载预创建对应层级沙箱 |
| **K8s agent-sandbox SIG 对接** | 成为标准 runtime backend |

### P3（12 月+）：平台扩展

| 任务 | 理由 |
|------|------|
| **Windows 后端**（AppContainer） | 全平台覆盖 |
| **可选 SaaS 托管** | 多租户场景 |
| **GPU 直通**（microVM 级） | ML 推理场景 |
| **沙箱模板市场** | 类似 E2B Templates 的预构建环境 |

## 5. 竞品差异化总结（修订版）

mimibox 的差异化不是"三层让你选"，而是：

1. **零配置安全执行** — 默认智能路由，开发者无需理解隔离机制
2. **极致性能** — 预热池 0.38us，Wasm 0.61ms，作为营销弹药和批量场景的真实优势
3. **灵活可控** — 高级用户可以精确指定每一层参数，零配置是起点不是天花板
4. **真自托管** — 单 binary，无外部依赖，数据不出域
5. **市场窗口 12-18 月** — 竞品尚未提供多层 + 智能路由的组合

## 6. 市场窗口风险

| 风险 | 影响 | 应对 |
|------|------|------|
| K8s agent-sandbox 标准化消解技术壁垒 | mimibox 三层变成"又一个 runtime backend" | 主动参与标准制定，成为 reference implementation |
| E2B 扩展到多层级 | 直接竞争 | 加速 SDK 和生态建设，先发优势 |
| Microsoft Wassette + Azure 整合 | Wasm + VM 组合竞品 | mimibox 有 OS 级兜底的纵深防御差异 |
| 社区资源不足以维护三层 | microVM 层 vendor shim 跟进不及时 | 优先保证 OS + Wasm 两层，microVM 按需投入 |
