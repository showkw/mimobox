# 任务计划

## 目标

在 `mimobox` workspace 中新增 `crates/mimobox-vm` crate 骨架，提供
`MicrovmSandbox`、`MicrovmConfig`、快照格式和 Linux KVM 后端基础，
并确保 `cargo check -p mimobox-vm --features kvm` 通过。

## 阶段

| 阶段 | 状态 | 说明 |
| --- | --- | --- |
| 1 | 已完成 | 读取 `CLAUDE.md`、核心 trait、设计文档和现有 crate 风格 |
| 2 | 已完成 | 先写 `mimobox-vm` 基础测试并观察首次失败 |
| 3 | 已完成 | 实现 crate 骨架、错误类型、快照格式和 KVM 后端基础 |
| 4 | 已完成 | 更新 workspace 成员并修复编译错误 |
| 5 | 已完成 | 运行 `cargo check -p mimobox-vm --features kvm` 验证并收尾 |

## 关键约束

- 所有对外注释使用简体中文。
- 平台特定代码必须用 `#[cfg(target_os = "linux")]`
  和 `#[cfg(feature = "kvm")]` 隔离。
- `MicrovmError` 使用 `thiserror` 定义。
- 所有 `unsafe` 都必须附带 `SAFETY` 注释。
- 内存抽象使用 `vm-memory`，不直接使用原始 `mmap` 调用。
- 不使用 `TODO`、`unimplemented!()` 或假通过代码。

## 决策记录

- 维持 `mimobox-core::Sandbox` 现有签名不变，通过
  `MicrovmSandbox` 固有构造器承载 VM 专属配置。
- `SandboxError` 增补 `Unsupported` 变体，避免在非 Linux 平台上把
  “不支持” 伪装成一般执行失败。
- `KvmBackend` 先实现生命周期骨架、KVM fd 初始化、guest memory 装载、
  命令通道协议封装和快照材料导出，真实 guest runner 接入留给后续迭代。
- 当前环境无法访问 crates.io，因此通过 `[patch.crates-io]` 指向 workspace
  内 shim crate，保证离线编译验证可落地。

## 错误记录

| 时间 | 问题 | 处理 |
| --- | --- | --- |
| 2026-04-20 | `Sandbox` trait 不包含内核和 rootfs 参数 | 通过 `MicrovmSandbox::new(MicrovmConfig)` 与 trait 构造器并存化解 |
| 2026-04-20 | `SandboxError` 缺少 `Unsupported` 语义 | 计划在 `mimobox-core` 中最小化补充错误变体 |
