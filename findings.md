# 调研发现

## 核心接口

- `mimobox-core::Sandbox` 当前固定为
  `new(SandboxConfig) / execute(&mut self, &[String]) / destroy(self)`。
- `SandboxConfig` 不包含 microVM 所需的 `kernel_path` 与 `rootfs_path`，
  因此需要额外公开 `MicrovmConfig`。
- `SandboxError` 当前没有 `Unsupported` 变体，但任务要求非 Linux 平台显式返回
  `SandboxError::Unsupported`。

## 设计文档结论

- `docs/research/14-microvm-design.md` 明确建议：
  - 不修改 `Sandbox` trait；
  - 使用 `MicrovmSandbox::new(MicrovmConfig)` 作为固有构造器；
  - `snapshot / restore` 作为 `MicrovmSandbox` 固有方法；
  - 平台差异收敛到 `kvm / hvf / whpx` 等私有模块；
  - 首版重点是“可执行骨架”，快照和池化逐步演进。

## 仓库风格

- 现有 crate 都在 `src/lib.rs` 中做模块声明和 `pub use`。
- `mimobox-os` 使用 target-specific dependencies 和 `lints.workspace = true`。
- 注释语言为简体中文，错误类型统一基于 `thiserror`。

## 当前实现策略

- `mimobox-vm` 公开 `MicrovmConfig`、`MicrovmSandbox`、`MicrovmSnapshot`。
- Linux + `kvm` feature 下编译 `kvm.rs`，其它平台直接返回
  `SandboxError::Unsupported`。
- `KvmBackend` 先实现：
  - `/dev/kvm` 打开与 `KVM_CREATE_VM`；
  - guest memory 对象分配；
  - vCPU fd 创建；
  - kernel/rootfs 文件读取与基础装载；
  - 命令通道封包与生命周期状态维护；
  - 快照所需的配置、memory、vCPU 状态导出。
- 当前 sandbox 无法联网访问 crates.io，且本机缓存缺失
  `kvm-ioctls`、`vm-memory`、`vmm-sys-util`，因此新增了本地 shim crate 并通过
  `[patch.crates-io]` 接管解析；这保证了离线编译，但不代表真实 KVM 运行时已完整接通。
