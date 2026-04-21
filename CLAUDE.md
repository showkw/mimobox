# mimobox - Rust 跨平台 Agent Sandbox

## 项目简介

mimobox 是一个用 Rust 实现的跨平台 Agent Sandbox，为 AI Agent 提供安全隔离的代码执行环境。追求极致性能和跨平台支持。

## 项目目标

- 用 Rust 实现跨平台（Linux/macOS/Windows）Agent Sandbox
- 极致性能：冷启动 <10ms，热获取 <1ms
- 安全隔离：Landlock + Seccomp + Namespaces (Linux)，Seatbelt (macOS)，AppContainer (Windows)
- 支持 OS 级进程沙箱、Wasm 沙箱、microVM 沙箱三种隔离层级
- 统一的 Sandbox trait 抽象，按需选择隔离策略
- 预热池机制实现微秒级沙箱获取

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
├── src/
│   ├── main.rs         # CLI 入口
│   ├── sandbox.rs      # Sandbox trait 定义
│   ├── linux_backend.rs # Linux 后端实现
│   ├── wasm_backend.rs  # Wasm 后端实现（feature "wasm"）
│   └── pool.rs          # 预热池
├── wit/                # WIT 接口定义
│   └── mimobox.wit
├── scripts/            # 构建/测试/运行脚本（必须通过脚本执行）
├── docs/
│   └── research/       # 技术调研报告（13 份）
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
- `docs/research/01~07` — 分领域深度研究
