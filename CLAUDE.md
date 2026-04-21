# mimobox - Rust 跨平台 Agent Sandbox

## 项目简介

mimobox 是一个用 Rust 实现的跨平台 Agent Sandbox，为 AI Agent 提供安全隔离的代码执行环境。

核心定位：**默认智能路由，高级用户完全可控。** 零配置即可安全执行代码，同时 SDK 暴露完整三层配置供精细控制。

## 项目目标

- **极致性能**：持续优化冷启动、热获取、内存开销，追求每个层级都做到业界最优
- **跨平台**：Linux（三层全开）+ macOS（OS+Wasm）+ Windows（规划中），开发者本地开发与生产部署统一体验
- **三层隔离**：OS 级（Landlock+Seccomp+Namespaces）、Wasm（Wasmtime）、microVM（KVM），按需选择安全/性能平衡点
- **默认智能路由 + 高级完全可控**：零配置自动选择最优层级，SDK 暴露完整配置供精细控制
- **自托管 + 离线运行**：单 binary，无外部依赖，数据不出域

## 技术栈

- 语言：Rust (edition 2024)
- Linux 后端：Landlock + Seccomp-bpf + Namespaces + cgroups v2
- macOS 后端：Seatbelt (sandbox-exec)
- Windows 后端：AppContainer + Job Objects
- Wasm 后端：Wasmtime + WASI Preview 2 + Component Model
- microVM 后端：rust-vmm crate (KVM / Hypervisor.framework / WHPX)

## 项目结构

```
mimobox/
├── CLAUDE.md           # 项目指导文件（本文件）
├── AGENTS.md           # Agent 角色定义
├── .env                # 环境变量（敏感信息，已 gitignore）
├── Cargo.toml
├── crates/
│   ├── mimobox-core/   # Sandbox trait + Config + Result + Error
│   ├── mimobox-os/     # OS 级沙箱（Linux Landlock+Seccomp+NS / macOS Seatbelt）
│   ├── mimobox-wasm/   # Wasm 沙箱（Wasmtime，feature "wasm"）
│   ├── mimobox-vm/     # microVM 沙箱（KVM，feature "kvm"）
│   └── mimobox-cli/    # CLI 入口
├── vendor/             # rust-vmm crate 兼容 shim（kvm-ioctls/vm-memory/vmm-sys-util）
├── examples/           # 示例代码（wasm-tools/）
├── tests/              # 集成测试
├── wit/                # WIT 接口定义
│   └── mimobox.wit
├── scripts/            # 构建/测试/运行脚本（必须通过脚本执行）
├── docs/
│   └── research/       # 技术调研报告
├── discuss/            # 讨论、评审、方案权衡
│   ├── competitive-analysis.md     # Agent Sandbox 竞品分析
│   └── product-strategy-review.md  # 产品战略评审记录
└── logs/               # 日志目录
```

## 强制性规则（不可违反）

1. **所有执行通过 scripts/ 目录的脚本入口**：禁止直接使用 `cargo run`、`cargo build` 等裸命令作为正式方式
2. **日志必须配置**：所有关键执行路径必须有日志输出
3. **先读后写**：修改代码前必须先理解现有实现
4. **unsafe 审计**：所有 unsafe 代码必须有 SAFETY 注释说明为何安全
5. **跨平台条件编译**：平台特定代码必须用 `#[cfg(target_os = "...")]` 隔离
6. **错误处理**：使用 thiserror 定义错误类型，禁止 unwrap() 在非测试代码中使用
7. **Seccomp Profile**：Linux 沙箱必须应用 Seccomp 过滤，默认白名单模式
8. **Landlock 规则**：Linux 沙箱必须应用 Landlock，默认拒绝所有文件系统访问
9. **网络默认拒绝**：所有沙箱默认禁止网络访问
10. **内存限制**：所有沙箱必须设置内存上限

## 开发环境

- macOS：当前设备（代码编辑、文档）
- Linux 服务器：hermes（SSH 连接，沙箱开发和测试）
  - 连接：`ssh hermes`
  - 工作目录：~/mimobox-poc
  - sudo 密码见 .env 文件
  - 所有沙箱测试必须在 Linux 服务器上执行

## 性能目标

| 阶段 | 目标 | 实际 | 状态 |
|------|------|------|------|
| Phase 1（OS 级） | 冷启动 <10ms | P50: 3.51ms | ✅ |
| Phase 2（Wasm 级） | 冷启动 <5ms | P50: 0.61ms | ✅ |
| Phase 3（预热池） | 热获取 <100us | P99: 0.38us | ✅ |
| Phase 4（microVM） | 冷启动 <200ms | P50: 65.78ms | ✅ |
| Phase 4（microVM） | 快照恢复 <50ms | P50: 41.25ms | ✅ |

## 参考文档索引

- `docs/research/00-executive-summary.md` — 综合研究报告（经 3 轮增强）
- `docs/research/08-feasibility-review.md` — 可行性评审报告（6.4/10）
- `docs/research/09-code-review.md` — 第一轮代码审查报告
- `docs/research/10-code-review-round2.md` — 第二轮代码审查报告
- `docs/research/11-wasmtime-api-research.md` — Wasmtime API 技术调研
- `docs/research/12-wit-interface-design.md` — WIT 接口设计文档
- `discuss/competitive-analysis.md` — Agent Sandbox 竞品功能差异分析
- `discuss/product-strategy-review.md` — 三层隔离架构战略评审记录

## 路线图

| 优先级 | 方向 | 时间 |
|--------|------|------|
| **P0** | SDK crate + microVM vsock 真实通信 + 智能路由 + 持续性能优化 | 0-3 月 |
| **P1** | 网络代理（域名白名单）+ 统一网络抽象 | 3-6 月 |
| **P2** | MCP 协议集成 + 编排 API | 6-12 月 |
| **P3** | Windows 后端 + 可选 SaaS + GPU | 12 月+ |
