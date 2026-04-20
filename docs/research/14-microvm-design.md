# Phase 4 microVM 沙箱技术调研与设计

> 撰写日期：2026-04-20
>
> 适用范围：`mimobox` Phase 4，面向 `microVM` 第三层隔离后端的技术选型、架构设计与实施路线。
>
> 当前仓库状态：`crates/mimobox-core` 已定义统一 `Sandbox` trait，`mimobox-os` 与 `mimobox-wasm` 已有实现；仓库中尚不存在 `mimobox-vm` crate，也尚未在 `Cargo.toml` 中引入 rust-vmm 相关依赖。

## 1. 技术方案概述

### 1.1 microVM 的定位

microVM 是 mimobox 分层沙箱体系中的**第三层隔离**。它的职责不是替代 OS 级与 Wasm 级后端，而是在以下场景中提供最强边界：

- 需要运行**原生二进制、完整 Linux 用户态工具链**，且不能接受仅靠同内核隔离的风险。
- 需要把不受信任代码与宿主内核彻底分离，避免 Landlock / Seccomp / Namespace 同内核共享带来的逃逸面。
- 需要把“执行环境模板”做成**可快照、可恢复、可池化**的高安全运行单元。

因此，microVM 在 mimobox 中的角色应当明确为：

- **安全等级最高**：硬件虚拟化边界，优于同内核进程沙箱。
- **启动开销最大**：明显高于 OS 级与 Wasm 级，必须依赖快照恢复和模板化启动。
- **使用范围最窄**：只用于高风险、高隔离要求的工作负载，而不是默认后端。

这与项目当前的总体方向一致：OS 级后端负责通用原生命令执行，Wasm 后端负责极快、跨平台的 Agent 工具执行，microVM 只在需要最强边界时升级启用。

### 1.2 与 OS 级、Wasm 级的对比

| 维度 | OS 级沙箱 | Wasm 级沙箱 | microVM 沙箱 |
|------|-----------|-------------|--------------|
| 隔离边界 | 同宿主内核进程隔离 | 运行时 + 导入能力隔离 | 硬件虚拟化边界 |
| 安全性 | 中 | 中高 | 高 |
| 对宿主内核依赖 | 高 | 中 | 低 |
| 冷启动开销 | 低，当前项目已达 3.51ms P50 | 很低，当前项目已达 0.61ms P50 | 高，目标 `<200ms` |
| 热恢复 / 复用 | 依赖预热池 | 依赖 Engine / Module 缓存 | 依赖 VM 快照，目标 `<50ms` |
| 运行对象 | 原生命令 / 进程 | `.wasm` 模块 | Guest Linux + 原生命令 |
| 资源开销 | 最低 | 低 | 最高 |
| 适用场景 | 通用 CLI、构建工具、测试工具 | Agent skill、可移植工具、强能力裁剪场景 | 高风险原生代码、需要硬隔离的第三方工具 |
| 跨平台实现成本 | 中 | 低 | 高 |
| 当前仓库成熟度 | 已实现 | 已实现 | 仅研究与设计阶段 |

### 1.3 Phase 4 目标

本设计采用当前项目约束中的 Phase 4 目标，而**不沿用早期研究文档中更激进的 `<100ms / <10ms` 目标**。原因有两点：

1. 当前 `CLAUDE.md` 与任务说明已经把 Phase 4 目标收敛为 `冷启动 <200ms，快照恢复 <50ms`。
2. `docs/research/08-feasibility-review.md` 已指出 microVM 跨平台抽象与快照工程量被低估，先用可落地目标建立最小可用实现更合理。

Phase 4 的明确目标如下：

- 冷启动：**`<200ms`**
- 快照恢复：**`<50ms`**
- 基础平台优先级：**Linux KVM > macOS Hypervisor.framework > Windows WHPX**
- 接口策略：**兼容现有 `Sandbox` trait，不在 Phase 4a 直接修改 `mimobox-core`**

---

## 2. rust-vmm 生态系统调研

### 2.1 当前仓库依赖基线

当前 `Cargo.toml` 的 `workspace.dependencies` 已锁定以下与现有实现直接相关的版本：

- `thiserror = "2"`
- `nix = "0.30"`
- `landlock = "0.4"`
- `wasmtime = "43"`
- `wasmtime-wasi = "43"`

当前仓库**尚未声明** `vm-memory`、`kvm-ioctls`、`vmm-sys-util`、HVF/WHPX 绑定等 microVM 依赖。因此本文对 rust-vmm 生态的结论分为两层：

- 对**已存在依赖**，直接以当前 `Cargo.toml` 为准。
- 对**尚未引入的 microVM 依赖**，只描述职责、成熟度与集成位置，不在本文中把 semver 写死为项目基线，避免与当前 workspace 事实不一致。

### 2.2 `vm-memory`

`vm-memory` 是 rust-vmm 生态里最核心的基础 crate 之一，它解决的是**客户机物理内存抽象**问题，而不是 hypervisor 控制问题。对 mimobox 的价值主要体现在四个方面：

1. **解耦 VMM 各组件与底层内存提供者**
   - Loader、VirtIO 设备、快照模块都通过统一 trait 访问 guest memory。
   - 这意味着 `mimobox-vm` 不需要把内存布局硬编码进设备层。

2. **适合跨平台 VMM**
   - 公开资料显示该 crate 支持 `x86_64 / ARM64 / RISCV64`，操作系统层面覆盖 `Linux / Unix / Windows`。
   - 这非常适合 mimobox 的长期目标：共享高层 VMM 逻辑，把平台差异收敛到 hypervisor backend。

3. **适合快照与零拷贝场景**
   - `GuestMemoryMmap` 这类模型天然适合做 file-backed guest memory。
   - 后续快照恢复可把“内存文件 + 状态文件”封装进自己的快照层，而不是让业务代码直接接触 `mmap` 细节。

4. **适合集成 minimal device model**
   - microVM 最终需要极少数 VirtIO 设备：console、block、vsock，最多再加 entropy。
   - 这些设备都需要对 guest memory 做安全读写，`vm-memory` 正是共享基础。

对 mimobox 的结论：

- `vm-memory` 应当作为 `mimobox-vm` 的**一等核心依赖**。
- 它属于**平台中立层**，建议在 `vmm.rs / devices.rs / snapshot/` 内复用，而不是把内存逻辑散落到 `kvm/`、`hvf/`、`whpx/` 目录中。

### 2.3 `kvm-ioctls`

`kvm-ioctls` 是 Linux KVM 的 Rust 安全封装，面向 `/dev/kvm` 暴露的 ioctl 接口。它承担的是**hypervisor 后端控制面**职责，主要包括：

- 创建 VM
- 创建 vCPU
- 设置寄存器与特殊寄存器
- 注入中断
- 配置脏页追踪
- 查询/恢复 vCPU 状态

它非常适合作为 Phase 4a 的 Linux 起点，原因如下：

1. **与目标平台强匹配**
   - Phase 4a 明确先做 Linux KVM。
   - KVM 是 Linux 上最成熟、最直接、性能最好的 microVM 入口。

2. **与 Firecracker / Cloud Hypervisor 方向一致**
   - mimobox 的设计目标不是直接嵌入 Firecracker，而是复用 rust-vmm 生态在更小代码面上自行组装。
   - `kvm-ioctls` 正是这种“VMM-as-a-library”路线的必要底座。

3. **支持快照关键能力**
   - KVM 层可导出 vCPU 状态、内存脏页位图等信息。
   - 这为 Phase 4b 的 full snapshot / diff snapshot 奠定基础。

限制也很明确：

- **仅 Linux 可用**，无法直接帮助 macOS / Windows。
- 它只解决 KVM 控制，不负责 loader、设备模型、文件系统共享与命令通道。

对 mimobox 的结论：

- Phase 4a 应以 `kvm-ioctls` 为 hypervisor 后端核心。
- 但必须在 `mimobox-vm/src/hypervisor.rs` 之上封装自有抽象，绝不能让 KVM 类型泄漏到公共 API。

### 2.4 `vmm-sys-util`

`vmm-sys-util` 是 rust-vmm 的系统工具箱，虽然不直接运行虚拟机，但几乎所有 VMM 组件都会依赖它。其价值在 mimobox 中主要体现在：

- `eventfd` / `event`：宿主线程与 VMM 事件协调
- `epoll` / `poll`：设备事件循环
- `ioctl` 宏：底层系统接口调用
- `tempfile` / `tempdir`：模板 rootfs、快照文件、临时 overlay 管理
- `errno` / `syscall`：统一系统错误处理

对 mimobox 的意义不是“单独引入一个小工具库”，而是：

- 让 `mimobox-vm` 的 Linux backend 不必重新发明轮子。
- 让事件循环、文件句柄、临时文件与 ioctl 模式和 rust-vmm 主流实践保持一致。

需要注意的是：

- 该 crate 的跨平台支持是不对称的，Linux 能力最完整，Windows 只有部分模块可用。
- 因此 `mimobox-vm` 不能把它当成“统一跨平台运行时”，而应把它视作 Linux 优先、其他平台按需退化的工具层。

对 mimobox 的结论：

- Linux KVM 路径推荐引入 `vmm-sys-util`。
- macOS / Windows 代码不要硬依赖它的 Linux-only 模块，应通过 feature 和 `cfg` 做边界隔离。

### 2.5 macOS Hypervisor.framework 的 Rust 绑定

macOS 上不存在 KVM，对 microVM 唯一现实路径是 **Hypervisor.framework**。这部分需要区分三类能力：

1. **Apple 官方能力**
   - `Hypervisor.framework` 提供用户态虚拟机与 vCPU 控制接口。
   - Apple 官方说明表明它支持 Apple Silicon 的 Virtualization Extensions，也支持 Intel Mac 上的 VT-x/EPT。
   - 使用该框架的进程需要 `com.apple.security.hypervisor` entitlement。

2. **历史绑定：`hypervisor` crate**
   - 这是较早期的 Rust 绑定，接口模型偏向早期 macOS / Intel VT-x 时代。
   - 其公开文档仍以 “OS X / VT-x / EPT / Unrestricted Mode” 为主要描述，说明它对现代 Apple Silicon 路线并不理想。

3. **较新的安全绑定路线**
   - 当前公开生态中，`applevisor`、`hv` / `hv-sys` 这类项目更贴近 Apple Silicon 和现代 Hypervisor.framework。
   - 它们更适合做原型验证，但从 mimobox 角度看，**最好不要把任何第三方绑定直接暴露到上层 API**。

对 mimobox 的设计结论：

- `mimobox-vm` 的 macOS 路径不应把“使用哪个 Rust 绑定”上升为公共接口问题。
- 最稳妥的做法是：
  - 在 `hvf/` 模块内部维护一层极薄 FFI 封装；
  - 或者在原型阶段选择现成绑定，但对外统一收敛到自有 `HypervisorBackend` trait。

这样做的好处是：

- 避免绑定 crate 更新节奏绑死整体 API。
- 可以同时兼容 Intel Mac 与 Apple Silicon 的差异。
- 便于处理签名 / entitlement / 代码签名流程，这些都不该进入 `mimobox-core`。

### 2.6 Windows WHPX 的可行性

Windows 上的对应能力是 **Windows Hypervisor Platform（WHPX）**。从官方 API 模型看，它已经具备构建 lightweight VMM 的基本能力：

- 创建 partition
- 设置 partition 属性
- 映射 GPA range
- 创建/运行 virtual processor
- 查询/设置寄存器
- 查询 GPA dirty bitmap

这说明从**能力完备性**角度，WHPX 不是“不可能”，而是“工程成本高”。具体问题在于：

1. **Rust 生态不如 KVM 成熟**
   - KVM 有明确的 rust-vmm 主流路线。
   - WHPX 更多依赖原始 Windows API / FFI，现成可复用件少。

2. **设备模型与命令通道需要更多自建**
   - Windows 上没有 KVM 那种社区收敛的实践路径。
   - 需要自己处理 GPA 映射、退出原因分发、设备模拟与时钟问题。

3. **测试与可重复性成本更高**
   - Linux 可以在 CI/服务器统一验证。
   - Windows 虚拟化特性、系统版本、功能开关、驱动状态都更容易造成环境差异。

对 mimobox 的结论：

- WHPX **可行，但不适合作为 Phase 4 的首发目标**。
- 推荐策略：
  - 先把 `whpx/` 目录与 `HypervisorBackend` trait 预留出来；
  - Phase 4a/4b 不实现 Windows；
  - 在 Linux 与 macOS 验证设计稳定后，再进入 Windows 专项实现。

### 2.7 Firecracker 快照实现参考

Firecracker 不是 mimobox 要直接嵌入的运行时，但它是 Phase 4 快照设计最重要的参考对象。其对 mimobox 有三个直接启发：

1. **快照应拆为“内存文件 + VM 状态文件 + 外部磁盘文件”**
   - 这意味着 mimobox 的对外 `Vec<u8>` API 不应等价于“把全部 guest memory 一次性拷到 Rust 堆里”。
   - 更合理的做法是：`Vec<u8>` 承载的是**快照封装格式**，内部可以是 metadata + state + file-backed memory 引用或压缩块。

2. **恢复要优先做“快恢复”，而不是“快保存”**
   - Firecracker 明确把恢复优化为按需加载：恢复时通过 `MAP_PRIVATE` 映射 memory file，缺页时再加载。
   - 这非常符合 mimobox 的需求，因为 Agent 沙箱最在意的是“拿到一个可执行实例的延迟”。

3. **快照不是纯粹的 VMM 事情，还涉及 guest 语义**
   - 网络连接不能默认认为能无损延续。
   - 时钟、随机数、vsock 状态、磁盘一致性都要被视为“恢复边界”问题。
   - 因此 mimobox 需要一个**受控 guest runner**，而不是任由 guest 自行处理复杂状态。

对 mimobox 的设计结论：

- Phase 4b 应优先实现 **full snapshot**。
- diff snapshot 只作为后续优化方向，不作为第一阶段交付承诺。
- 快照点必须选择在“guest kernel 已启动、guest runner 已就绪、尚未接收业务命令”的稳定状态。

---

## 3. 架构设计

### 3.1 设计原则

microVM 后端的设计必须遵守以下原则：

1. **不修改现有 `Sandbox` trait**
   - `mimobox-core` 当前已稳定导出：
     - `fn new(config: SandboxConfig) -> Result<Self, SandboxError>`
     - `fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError>`
     - `fn destroy(self) -> Result<(), SandboxError>`
   - Phase 4 应先在这个契约下实现可用版本。

2. **把平台差异收敛到 hypervisor 层**
   - KVM / HVF / WHPX 的差异只能出现在 `kvm/`、`hvf/`、`whpx/` 模块内。
   - Loader、guest runner、命令协议、快照 envelope、结果回传逻辑必须尽量共享。

3. **先解决“可执行”再解决“高性能”**
   - Phase 4a 允许先做“直接启动 + 执行 + 销毁”。
   - 快照恢复和池化属于后续迭代，而不是首版就追求最优。

4. **guest 必须最小化**
   - guest 镜像不是通用 Linux 发行版，而是一个精简内核 + 只读 rootfs 模板 + `mimobox-init`。
   - `mimobox-init` 负责接收命令、执行命令、收集结果、回传结果、协调 snapshot barrier。

### 3.2 `MicrovmConfig` 配置项

`SandboxConfig` 是当前公共配置契约，但它不包含 VM 特有参数。因此 Phase 4 需要引入私有的 `MicrovmConfig`，并通过转换与 `SandboxConfig` 兼容。

建议配置项如下：

| 字段 | 类型 | 说明 |
|------|------|------|
| `base` | `SandboxConfig` | 复用当前通用限制：网络、内存、超时、Seccomp profile 等 |
| `vcpu_count` | `u8` | vCPU 数量，首版默认 `1` |
| `guest_memory_mib` | `u32` | Guest 内存大小，首版默认 `128` |
| `kernel_image` | `PathBuf` | Guest 内核镜像路径 |
| `rootfs_template` | `PathBuf` | 只读 rootfs 模板路径 |
| `boot_args` | `Vec<String>` | 内核参数与 guest runner 启动参数 |
| `enable_snapshot` | `bool` | 是否允许创建快照 |
| `console_ring_size` | `usize` | 控制 stdout/stderr 缓冲上限 |
| `overlay_dir` | `Option<PathBuf>` | 可选的临时 overlay 根目录 |

其中，题目要求的四个核心项必须稳定存在：

- `vcpu`
- `memory`
- `kernel`
- `rootfs`

其他项用于让配置能落地，但不改变核心定位。

### 3.3 `MicrovmSandbox` 的组件划分

`MicrovmSandbox` 是 Phase 4 对外暴露的 VM 级后端，职责分为五层：

1. **配置层**
   - 持有 `MicrovmConfig`
   - 负责把 `SandboxConfig` 转换成 VM 语义

2. **Hypervisor backend 层**
   - `KvmBackend`
   - `HvfBackend`
   - `WhpxBackend`

3. **VMM 核心层**
   - guest memory
   - loader
   - minimal device model
   - event loop

4. **guest control 层**
   - `mimobox-init`
   - 命令下发通道（建议优先 `virtio-vsock`，备选 `virtio-console`）
   - stdout/stderr / exit_code 回传

5. **snapshot 层**
   - 创建快照
   - 加载快照
   - 快照格式版本控制

### 3.4 ASCII 架构图

```text
┌────────────────────────────────────────────────────────────────┐
│                         Agent / CLI / Pool                     │
└───────────────────────────────┬────────────────────────────────┘
                                │
                                v
┌────────────────────────────────────────────────────────────────┐
│                      MicrovmSandbox (impl Sandbox)             │
│                                                                │
│  config: MicrovmConfig                                         │
│  state : Created / Ready / Running / Snapshotted / Destroyed   │
│                                                                │
│  ┌─────────────────────┐   ┌────────────────────────────────┐  │
│  │ Command Dispatcher  │   │ Snapshot Manager               │  │
│  │ - send cmd          │   │ - save vm state               │  │
│  │ - recv stdout/stderr│   │ - save/load guest memory      │  │
│  │ - collect exit_code │   │ - encode envelope(Vec<u8>)    │  │
│  └─────────┬───────────┘   └──────────────┬─────────────────┘  │
│            │                              │                    │
│            v                              v                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                      VMM Core                            │  │
│  │  - GuestMemory                                            │  │
│  │  - Loader (kernel/rootfs)                                 │  │
│  │  - Minimal devices: console / block / vsock / entropy     │  │
│  │  - Event loop / timer / interrupt routing                 │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │                                  │
└─────────────────────────────┼──────────────────────────────────┘
                              │
          ┌───────────────────┼────────────────────┬────────────────────┐
          │                   │                    │                    │
          v                   v                    v                    v
┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│ Linux: KVM     │  │ macOS: HVF     │  │ Windows: WHPX  │  │ Shared Guest    │
│ kvm-ioctls     │  │ raw API /      │  │ raw WinHv* API │  │ kernel + rootfs │
│ vm-memory      │  │ safe binding   │  │ dirty bitmap   │  │ mimobox-init    │
└────────────────┘  └────────────────┘  └────────────────┘  └────────────────┘
```

### 3.5 `MicrovmSandbox` 如何兼容现有 `Sandbox` trait

当前 `Sandbox` trait 的调用模型是“创建一个沙箱对象，然后对它执行命令”。对 microVM 而言，这意味着宿主侧必须把 `cmd: &[String]` 翻译成 guest 内可执行的动作。

推荐方案如下：

1. `new(...)`
   - 创建 hypervisor VM 对象
   - 分配 guest memory
   - 加载内核与 rootfs 模板
   - 启动 guest
   - 等待 guest 内 `mimobox-init` 进入“ready”状态

2. `execute(&mut self, cmd)`
   - 把 `cmd` 通过 `vsock` 或 `virtio-console` 发送给 `mimobox-init`
   - guest 内部执行：
     - 应用 guest 内 seccomp / rlimit / timeout policy
     - `execve` 目标命令
     - 捕获 stdout / stderr / exit_code
   - 宿主等待结果并组装为 `SandboxResult`

3. `destroy(self)`
   - 关闭 vCPU
   - 卸载 device
   - 释放 guest memory 和临时 overlay

这种模型有两个优点：

- 与现有 `Sandbox` trait 完全兼容。
- `snapshot` 可以在 `mimobox-init` ready 之后执行，形成“预启动模板 VM”。

### 3.6 快照 / 恢复 API

现有 `Sandbox` trait 没有 `snapshot` / `restore` 方法，因此 Phase 4 不应直接修改 core trait，而应把它们定义为 `MicrovmSandbox` 的固有方法：

- `snapshot(&mut self) -> Result<Vec<u8>, SandboxError>`
- `restore(data: &[u8]) -> Result<Self, SandboxError>`

`Vec<u8>` 的语义应当定义为**快照封装格式**，而不是简单内存转储。推荐结构：

```text
MicrovmSnapshotEnvelope
  ├── header
  │   ├── format_version
  │   ├── backend_kind
  │   ├── arch
  │   └── rootfs_digest
  ├── vm_state_blob
  ├── memory_descriptor
  │   ├── inline bytes (Phase 4b 原型可选)
  │   └── file-backed metadata (Phase 4d 优先)
  ├── device_state
  └── guest_runner_state
```

这样做的原因是：

- 首版 API 满足题目要求的 `Vec<u8>` 形式。
- 内部实现仍可演进到 file-backed / mmap / page-cache / diff snapshot，不会被 API 绑死。

### 3.7 生命周期

推荐生命周期如下：

```text
普通路径:
new -> boot guest -> ready -> execute(cmd) -> collect result -> destroy

快照路径:
new -> boot guest -> ready -> snapshot -> destroy
restore(snapshot) -> ready -> execute(cmd) -> collect result -> destroy
```

更细一点的状态机可定义为：

```text
Created
  -> Booting
  -> Ready
  -> Running
  -> Ready
  -> Snapshotted
  -> Ready
  -> Destroyed
```

其中约束如下：

- 只有 `Ready` 状态允许 `execute`
- 只有 `Ready` 状态允许 `snapshot`
- `restore` 的返回值必须直接进入 `Ready`
- `destroy` 一旦执行，实例不可复用

---

## 4. API 设计（Rust 代码示例）

以下示例代码遵守两条约束：

1. 与当前 `crates/mimobox-core/src/sandbox.rs` 中的 `Sandbox` trait 签名兼容。
2. 不假设 `SandboxError` 已增加 microVM 专属 variant，仍然只使用当前存在的错误类型。

### 4.1 `MicrovmConfig` 定义

```rust
use std::path::PathBuf;

use mimobox_core::{SandboxConfig, SandboxError};

#[derive(Clone)]
pub struct MicrovmConfig {
    /// 复用当前公共配置
    pub base: SandboxConfig,
    /// vCPU 数量
    pub vcpu_count: u8,
    /// Guest 内存大小（MiB）
    pub guest_memory_mib: u32,
    /// Guest 内核镜像
    pub kernel_image: PathBuf,
    /// 只读 rootfs 模板
    pub rootfs_template: PathBuf,
    /// 附加启动参数
    pub boot_args: Vec<String>,
    /// 是否允许快照
    pub enable_snapshot: bool,
}

impl MicrovmConfig {
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.vcpu_count == 0 {
            return Err(SandboxError::ExecutionFailed(
                "vcpu_count 不能为 0".into(),
            ));
        }
        if self.guest_memory_mib < 64 {
            return Err(SandboxError::ExecutionFailed(
                "guest_memory_mib 不能小于 64".into(),
            ));
        }
        if self.kernel_image.as_os_str().is_empty() {
            return Err(SandboxError::ExecutionFailed(
                "kernel_image 不能为空".into(),
            ));
        }
        if self.rootfs_template.as_os_str().is_empty() {
            return Err(SandboxError::ExecutionFailed(
                "rootfs_template 不能为空".into(),
            ));
        }
        Ok(())
    }
}

impl From<SandboxConfig> for MicrovmConfig {
    fn from(base: SandboxConfig) -> Self {
        Self {
            base,
            vcpu_count: 1,
            guest_memory_mib: 128,
            kernel_image: PathBuf::from("/var/lib/mimobox/vm/vmlinux"),
            rootfs_template: PathBuf::from("/var/lib/mimobox/vm/rootfs.ext4"),
            boot_args: vec![
                "console=hvc0".into(),
                "panic=-1".into(),
                "quiet".into(),
            ],
            enable_snapshot: false,
        }
    }
}
```

### 4.2 `MicrovmSandbox` 与 `Sandbox` trait 兼容实现

```rust
use std::time::Instant;

use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};

pub struct MicrovmSandbox {
    config: MicrovmConfig,
    state: MicrovmState,
    backend: Box<dyn HypervisorBackend>,
}

enum MicrovmState {
    Created,
    Ready,
    Running,
    Destroyed,
}

trait HypervisorBackend {
    fn boot(&mut self, config: &MicrovmConfig) -> Result<(), SandboxError>;
    fn run_command(&mut self, cmd: &[String]) -> Result<GuestCommandResult, SandboxError>;
    fn save_snapshot(&mut self) -> Result<Vec<u8>, SandboxError>;
    fn load_snapshot(&mut self, data: &[u8]) -> Result<(), SandboxError>;
    fn shutdown(&mut self) -> Result<(), SandboxError>;
}

struct GuestCommandResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    timed_out: bool,
}

impl Sandbox for MicrovmSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        Self::from_microvm_config(MicrovmConfig::from(config))
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        if cmd.is_empty() {
            return Err(SandboxError::ExecutionFailed("命令为空".into()));
        }

        match self.state {
            MicrovmState::Ready => {}
            _ => {
                return Err(SandboxError::ExecutionFailed(
                    "microVM 当前不处于可执行状态".into(),
                ));
            }
        }

        self.state = MicrovmState::Running;
        let start = Instant::now();
        let result = self.backend.run_command(cmd);
        self.state = MicrovmState::Ready;

        let guest = result?;
        Ok(SandboxResult {
            stdout: guest.stdout,
            stderr: guest.stderr,
            exit_code: guest.exit_code,
            elapsed: start.elapsed(),
            timed_out: guest.timed_out,
        })
    }

    fn destroy(mut self) -> Result<(), SandboxError> {
        self.backend.shutdown()?;
        self.state = MicrovmState::Destroyed;
        Ok(())
    }
}
```

### 4.3 `MicrovmSandbox::new(config)`

由于题目要求提供 `MicrovmSandbox::new(config)`，同时现有 trait 又要求 `Sandbox::new(SandboxConfig)`，推荐做法是保留一个**固有构造函数**，供 VM 特有配置使用：

```rust
impl MicrovmSandbox {
    pub fn new(config: MicrovmConfig) -> Result<Self, SandboxError> {
        Self::from_microvm_config(config)
    }

    fn from_microvm_config(config: MicrovmConfig) -> Result<Self, SandboxError> {
        config.validate()?;

        let mut backend = select_backend()?;
        backend.boot(&config).map_err(|e| {
            SandboxError::ExecutionFailed(format!("microVM 启动失败: {e}"))
        })?;

        Ok(Self {
            config,
            state: MicrovmState::Ready,
            backend,
        })
    }
}

fn select_backend() -> Result<Box<dyn HypervisorBackend>, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        return Ok(Box::new(KvmBackend::new()?));
    }

    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(HvfBackend::new()?));
    }

    #[cfg(target_os = "windows")]
    {
        return Ok(Box::new(WhpxBackend::new()?));
    }

    #[allow(unreachable_code)]
    Err(SandboxError::ExecutionFailed(
        "当前平台不支持 microVM".into(),
    ))
}
```

这套设计满足两个目标：

- `MicrovmSandbox::new(config)` 可承载 VM 特有配置。
- `<MicrovmSandbox as Sandbox>::new(base_config)` 仍然存在，满足当前 trait 契约。

### 4.4 `sandbox.execute(cmd)`

现有 `Sandbox` trait 的 `execute` 签名是：

```rust
fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError>;
```

在 microVM 里，`cmd` 会通过宿主到 guest 的命令通道传给 `mimobox-init`。调用方式如下：

```rust
use mimobox_core::Sandbox;

let base = SandboxConfig::default();
let config = MicrovmConfig {
    base,
    vcpu_count: 1,
    guest_memory_mib: 128,
    kernel_image: "/opt/mimobox/vm/vmlinux".into(),
    rootfs_template: "/opt/mimobox/vm/rootfs.ext4".into(),
    boot_args: vec!["console=hvc0".into(), "panic=-1".into()],
    enable_snapshot: true,
};

let mut sandbox = MicrovmSandbox::new(config)?;

let cmd = vec![
    "/bin/sh".to_string(),
    "-lc".to_string(),
    "echo hello-from-guest".to_string(),
];

let result = sandbox.execute(&cmd)?;
assert_eq!(result.exit_code, Some(0));
```

### 4.5 `sandbox.snapshot()`

由于快照涉及暂停 vCPU、冻结设备状态、导出 guest memory，因此建议签名使用 `&mut self`：

```rust
use std::path::PathBuf;

use mimobox_core::{SandboxConfig, SandboxError, SeccompProfile};

struct SnapshotEnvelope {
    config: MicrovmConfig,
    backend_blob: Vec<u8>,
}

impl SnapshotEnvelope {
    const MAGIC: [u8; 4] = *b"MMBX";
    const VERSION: u8 = 1;

    fn encode(&self) -> Result<Vec<u8>, SandboxError> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        out.push(Self::VERSION);

        write_paths(&mut out, &self.config.base.fs_readonly)?;
        write_paths(&mut out, &self.config.base.fs_readwrite)?;
        out.push(self.config.base.deny_network as u8);
        write_opt_u64(&mut out, self.config.base.memory_limit_mb);
        write_opt_u64(&mut out, self.config.base.timeout_secs);
        out.push(seccomp_to_u8(self.config.base.seccomp_profile));
        out.push(self.config.base.allow_fork as u8);

        out.push(self.config.vcpu_count);
        out.extend_from_slice(&self.config.guest_memory_mib.to_le_bytes());
        write_path(&mut out, &self.config.kernel_image)?;
        write_path(&mut out, &self.config.rootfs_template)?;
        write_strings(&mut out, &self.config.boot_args)?;
        out.push(self.config.enable_snapshot as u8);
        write_bytes(&mut out, &self.backend_blob)?;
        Ok(out)
    }

    fn decode(data: &[u8]) -> Result<Self, SandboxError> {
        let mut offset = 0usize;

        let magic = read_exact(data, &mut offset, 4)?;
        if magic != Self::MAGIC {
            return Err(SandboxError::ExecutionFailed(
                "快照 magic 不匹配".into(),
            ));
        }

        let version = read_u8(data, &mut offset)?;
        if version != Self::VERSION {
            return Err(SandboxError::ExecutionFailed(format!(
                "不支持的快照版本: {version}"
            )));
        }

        let fs_readonly = read_paths(data, &mut offset)?;
        let fs_readwrite = read_paths(data, &mut offset)?;
        let deny_network = read_bool(data, &mut offset)?;
        let memory_limit_mb = read_opt_u64(data, &mut offset)?;
        let timeout_secs = read_opt_u64(data, &mut offset)?;
        let seccomp_profile = u8_to_seccomp(read_u8(data, &mut offset)?)?;
        let allow_fork = read_bool(data, &mut offset)?;

        let vcpu_count = read_u8(data, &mut offset)?;
        let guest_memory_mib = u32::from_le_bytes(read_exact(data, &mut offset, 4)?);
        let kernel_image = read_path(data, &mut offset)?;
        let rootfs_template = read_path(data, &mut offset)?;
        let boot_args = read_strings(data, &mut offset)?;
        let enable_snapshot = read_bool(data, &mut offset)?;
        let backend_blob = read_bytes(data, &mut offset)?;

        let config = MicrovmConfig {
            base: SandboxConfig {
                fs_readonly,
                fs_readwrite,
                deny_network,
                memory_limit_mb,
                timeout_secs,
                seccomp_profile,
                allow_fork,
            },
            vcpu_count,
            guest_memory_mib,
            kernel_image,
            rootfs_template,
            boot_args,
            enable_snapshot,
        };

        Ok(Self { config, backend_blob })
    }
}

fn write_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn read_opt_u64(data: &[u8], offset: &mut usize) -> Result<Option<u64>, SandboxError> {
    match read_u8(data, offset)? {
        0 => Ok(None),
        1 => Ok(Some(u64::from_le_bytes(read_exact(data, offset, 8)?))),
        other => Err(SandboxError::ExecutionFailed(format!(
            "非法 Option<u64> 标记: {other}"
        ))),
    }
}

fn seccomp_to_u8(profile: SeccompProfile) -> u8 {
    match profile {
        SeccompProfile::Essential => 0,
        SeccompProfile::Network => 1,
        SeccompProfile::EssentialWithFork => 2,
        SeccompProfile::NetworkWithFork => 3,
    }
}

fn u8_to_seccomp(value: u8) -> Result<SeccompProfile, SandboxError> {
    match value {
        0 => Ok(SeccompProfile::Essential),
        1 => Ok(SeccompProfile::Network),
        2 => Ok(SeccompProfile::EssentialWithFork),
        3 => Ok(SeccompProfile::NetworkWithFork),
        other => Err(SandboxError::ExecutionFailed(format!(
            "非法 seccomp profile 编码: {other}"
        ))),
    }
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SandboxError> {
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| SandboxError::ExecutionFailed("数据块过大".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_bytes(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, SandboxError> {
    let len = u32::from_le_bytes(read_exact(data, offset, 4)?) as usize;
    let bytes = read_slice(data, offset, len)?;
    Ok(bytes.to_vec())
}

fn write_string(out: &mut Vec<u8>, value: &str) -> Result<(), SandboxError> {
    write_bytes(out, value.as_bytes())
}

fn read_string(data: &[u8], offset: &mut usize) -> Result<String, SandboxError> {
    let raw = read_bytes(data, offset)?;
    String::from_utf8(raw).map_err(|e| {
        SandboxError::ExecutionFailed(format!("快照字符串不是有效 UTF-8: {e}"))
    })
}

fn write_path(out: &mut Vec<u8>, value: &PathBuf) -> Result<(), SandboxError> {
    write_string(out, &value.to_string_lossy())
}

fn read_path(data: &[u8], offset: &mut usize) -> Result<PathBuf, SandboxError> {
    Ok(PathBuf::from(read_string(data, offset)?))
}

fn write_strings(out: &mut Vec<u8>, items: &[String]) -> Result<(), SandboxError> {
    let len: u32 = items
        .len()
        .try_into()
        .map_err(|_| SandboxError::ExecutionFailed("字符串数量过多".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    for item in items {
        write_string(out, item)?;
    }
    Ok(())
}

fn read_strings(data: &[u8], offset: &mut usize) -> Result<Vec<String>, SandboxError> {
    let len = u32::from_le_bytes(read_exact(data, offset, 4)?) as usize;
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        items.push(read_string(data, offset)?);
    }
    Ok(items)
}

fn write_paths(out: &mut Vec<u8>, items: &[PathBuf]) -> Result<(), SandboxError> {
    let len: u32 = items
        .len()
        .try_into()
        .map_err(|_| SandboxError::ExecutionFailed("路径数量过多".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    for item in items {
        write_path(out, item)?;
    }
    Ok(())
}

fn read_paths(data: &[u8], offset: &mut usize) -> Result<Vec<PathBuf>, SandboxError> {
    let len = u32::from_le_bytes(read_exact(data, offset, 4)?) as usize;
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        items.push(read_path(data, offset)?);
    }
    Ok(items)
}

fn read_bool(data: &[u8], offset: &mut usize) -> Result<bool, SandboxError> {
    match read_u8(data, offset)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(SandboxError::ExecutionFailed(format!(
            "非法布尔值编码: {other}"
        ))),
    }
}

fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8, SandboxError> {
    let bytes = read_slice(data, offset, 1)?;
    Ok(bytes[0])
}

fn read_exact<const N: usize>(
    data: &[u8],
    offset: &mut usize,
    len: usize,
) -> Result<[u8; N], SandboxError> {
    let bytes = read_slice(data, offset, len)?;
    bytes.try_into().map_err(|_| {
        SandboxError::ExecutionFailed("快照字段长度不匹配".into())
    })
}

fn read_slice<'a>(
    data: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], SandboxError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| SandboxError::ExecutionFailed("快照偏移溢出".into()))?;
    if end > data.len() {
        return Err(SandboxError::ExecutionFailed(
            "快照数据截断".into(),
        ));
    }
    let slice = &data[*offset..end];
    *offset = end;
    Ok(slice)
}

impl MicrovmSandbox {
    pub fn snapshot(&mut self) -> Result<Vec<u8>, SandboxError> {
        if !self.config.enable_snapshot {
            return Err(SandboxError::ExecutionFailed(
                "当前 microVM 未启用快照".into(),
            ));
        }

        match self.state {
            MicrovmState::Ready => {}
            _ => {
                return Err(SandboxError::ExecutionFailed(
                    "只有 Ready 状态才能创建快照".into(),
                ));
            }
        }

        let backend_blob = self.backend.save_snapshot().map_err(|e| {
            SandboxError::ExecutionFailed(format!("创建快照失败: {e}"))
        })?;

        SnapshotEnvelope {
            config: self.config.clone(),
            backend_blob,
        }
        .encode()
    }
}
```

### 4.6 `MicrovmSandbox::restore(data)`

恢复必须返回一个**直接可执行**的实例，而不是返回中间 builder：

```rust
impl MicrovmSandbox {
    pub fn restore(data: &[u8]) -> Result<Self, SandboxError> {
        let envelope = SnapshotEnvelope::decode(data)?;
        let mut backend = select_backend()?;

        backend.load_snapshot(&envelope.backend_blob).map_err(|e| {
            SandboxError::ExecutionFailed(format!("恢复快照失败: {e}"))
        })?;

        Ok(Self {
            config: envelope.config,
            state: MicrovmState::Ready,
            backend,
        })
    }
}
```

### 4.7 完整使用示例

```rust
use mimobox_core::{Sandbox, SandboxConfig};

fn demo() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = MicrovmSandbox::new(MicrovmConfig {
        base: SandboxConfig::default(),
        vcpu_count: 1,
        guest_memory_mib: 128,
        kernel_image: "/opt/mimobox/vm/vmlinux".into(),
        rootfs_template: "/opt/mimobox/vm/rootfs.ext4".into(),
        boot_args: vec!["console=hvc0".into(), "panic=-1".into()],
        enable_snapshot: true,
    })?;

    let snapshot = sandbox.snapshot()?;

    let mut restored = MicrovmSandbox::restore(&snapshot)?;
    let cmd = vec!["/usr/bin/env".into()];
    let result = restored.execute(&cmd)?;

    println!("exit_code={:?}", result.exit_code);
    restored.destroy()?;
    Ok(())
}
```

上面的 `SnapshotEnvelope` 采用最小二进制格式编码。生产实现可以替换成更高效的等价格式，但必须保持 `Vec<u8>` 契约、版本字段、配置恢复能力和完整性校验。

---

## 5. 可行性评估

### 5.1 跨平台支持难度矩阵

| 平台 | Hypervisor 路径 | 复用现成 Rust 生态 | 快照可行性 | 工程难度 | 结论 |
|------|------------------|--------------------|------------|----------|------|
| Linux | KVM | 高，`kvm-ioctls` + `vm-memory` + `vmm-sys-util` | 高 | 中 | Phase 4 首发平台 |
| macOS | Hypervisor.framework | 中，绑定可选但需自持抽象 | 中 | 高 | 适合作为第二平台 |
| Windows | WHPX | 低到中，更多依赖原始 API | 中 | 很高 | 只建议后置 |

进一步拆解如下：

- **Linux**
  - 最适合先做。
  - KVM 与 Firecracker 路线成熟，快照路径清晰。
  - 也是最容易与现有 Linux 服务器验证链路衔接的平台。

- **macOS**
  - 在“能做”层面没有问题。
  - 真正的成本在 entitlement、Apple Silicon/Intel 差异、设备模型调试、CI 可重复性。
  - 如果 Phase 4a/4b 先把高层抽象打磨好，macOS 是合理的第二站。

- **Windows**
  - API 能力足够，但现成实践少，环境差异大。
  - 更适合作为“抽象设计已稳定”后的专项平台工程，而不是第一版通用方案。

### 5.2 冷启动优化路径

想达到 `<200ms` 冷启动，必须把优化拆成可累积的几段，而不是指望单个技巧解决所有问题。

推荐路径如下：

1. **最小设备模型**
   - 首版只保留：
     - `virtio-console`
     - `virtio-block`
     - `virtio-vsock`
     - `virtio-rng`（可选）
   - 不引入复杂网络桥接、图形、USB、完整 PCI 生态。

2. **直接内核启动**
   - Linux KVM 路径优先采用 direct kernel boot。
   - x86_64 可参考 Firecracker 的 PVH/direct boot 思路，绕过传统 BIOS/bootloader 路径。

3. **只读 rootfs 模板 + 临时 overlay**
   - rootfs 不做完整复制。
   - 每个实例只创建极小的可写层，执行结束即销毁。

4. **guest runner 模板化**
   - `mimobox-init` 在 guest 启动后保持 ready。
   - `execute` 只负责下发命令，而不是每次都重新完成 init 流程。

5. **文件后备 guest memory**
   - 为快照恢复阶段铺路。
   - 同时便于利用页缓存减少重复 I/O。

6. **模板池 / 快照池**
   - 冷启动目标靠 direct boot + minimal guest 达成。
   - 热路径目标则必须靠 snapshot pool 达成。

### 5.3 快照 / 恢复的技术挑战

#### 1. API 是 `Vec<u8>`，但内存状态可能很大

这是本设计最大的接口张力：

- 题目要求 `snapshot() -> Vec<u8>`。
- 真实 microVM 的 guest memory 可能几十到几百 MiB。

解决方法不是否定 API，而是把 `Vec<u8>` 解释为**快照封装数据**，并允许其内部：

- 内联小型状态块
- 引用 file-backed memory
- 承载压缩块和元数据

换句话说，`Vec<u8>` 是 transport envelope，不是“把所有 VM 内存永远塞进 Rust heap”。

#### 2. 设备状态一致性

一旦有 `console / block / vsock`，快照就不只是一份 vCPU + memory 状态：

- console 缓冲是否清空
- vsock 连接是否重建
- block 是否已 flush
- timer / clock 是否重放

这决定了首版必须采用**严格受控的最小设备集**，并明确规定：

- 网络连接不保证跨 snapshot 续存
- 打开的 vsock 会话不保证恢复
- snapshot 点只允许在 `Ready` 状态创建

#### 3. 随机数、时钟与唯一性

Firecracker 的经验很重要：同一个快照如果被恢复成多个副本，就会把“原本应唯一”的状态复制出去。

对 mimobox 而言，至少要处理：

- guest 内熵池
- 时间源
- 临时 token / machine id
- 可重复恢复带来的重复执行语义

因此 `restore` 不能只是“把 VM 状态原样搬回来”，还需要在恢复阶段做 guest runner 级的 re-seed / re-init。

#### 4. dirty page tracking 的收益和成本

差异快照听起来理想，但它并不免费：

- KVM dirty page logging 会引入运行时成本
- 页面粒度、huge page、swap 行为都会影响效果
- 合并层级越多，管理复杂度越高

所以 Phase 4b 推荐策略是：

- 先做 full snapshot
- diff snapshot 只作为后续优化，不作为首版目标

### 5.4 与现有 `Sandbox` trait 的兼容性分析

#### 兼容项

| 当前字段 / 方法 | microVM 映射情况 | 说明 |
|----------------|------------------|------|
| `new(SandboxConfig)` | 可兼容 | 转为默认 `MicrovmConfig` |
| `execute(&mut self, &[String])` | 可兼容 | 通过 guest runner 执行命令 |
| `destroy(self)` | 可兼容 | 关闭 VM 并清理资源 |
| `deny_network` | 可兼容 | 控制是否暴露网络设备或外部网络出口 |
| `memory_limit_mb` | 可兼容 | 映射为 guest memory 上限 |
| `timeout_secs` | 可兼容 | 宿主 wall clock 超时 + guest 侧超时 |
| `allow_fork` | 基本可兼容 | 通过 guest runner 内 seccomp / policy 实施 |

#### 需要重新解释的字段

| 当前字段 | 问题 | 设计处理 |
|----------|------|----------|
| `fs_readonly` | 对进程沙箱是宿主路径白名单；对 microVM 不再是一对一含义 | 改为“可选 host share 列表”，首版默认不暴露 |
| `fs_readwrite` | 与 guest rootfs / overlay 语义冲突 | 首版仅支持 guest 内部 scratch，不承诺直通宿主读写 |
| `seccomp_profile` | 对 guest 进程无直接约束 | 解释为宿主 VMM helper 的硬化策略，guest 另走内部策略 |

#### 当前 trait 的缺口

现有 `Sandbox` trait 缺少两类能力：

1. **VM 特有配置**
   - `vcpu_count`
   - `kernel_image`
   - `rootfs_template`

2. **快照生命周期**
   - `snapshot`
   - `restore`

但这个缺口不会阻止 Phase 4 落地，因为：

- 配置缺口可通过 `MicrovmConfig` + 转换层解决。
- 生命周期缺口可通过 `MicrovmSandbox` 固有方法解决。

因此结论是：

- **当前 `Sandbox` trait 足够支撑 Phase 4 首版实现。**
- 不建议在 Phase 4a/4b 修改 `mimobox-core`。
- 等 future 确认多个后端都需要快照后，再考虑引入扩展 trait，例如 `SnapshotableSandbox`。

---

## 6. 实施路线图

### 6.1 Phase 4a：Linux KVM 基础实现

目标：先在 Linux 上把 `mimobox-vm` 的最小链路跑通。

交付范围：

- 新建 `mimobox-vm` crate
- `kvm/` backend
- `vm-memory` guest memory 管理
- 直接内核启动
- 只读 rootfs 模板 + 临时 overlay
- `mimobox-init` guest runner
- `MicrovmSandbox` 实现 `Sandbox` trait

成功标准：

- `MicrovmSandbox::new(...)` 能在 Linux 上成功启动 guest
- `sandbox.execute(cmd)` 能返回 `stdout / stderr / exit_code`
- `sandbox.destroy()` 能稳定回收资源
- 冷启动达到 `<200ms` 的同量级，哪怕还没完全打到目标

不做的事：

- 不做 diff snapshot
- 不做 macOS / Windows
- 不做复杂 host path 共享

### 6.2 Phase 4b：快照 / 恢复

目标：在 Linux KVM 路径上把“模板 VM -> 快照 -> 恢复 -> 执行”闭环打通。

交付范围：

- 快照 envelope 设计与版本字段
- full snapshot
- `snapshot() -> Vec<u8>`
- `restore(data) -> Self`
- 快照前 `Ready` barrier
- 恢复后 guest runner re-seed / re-init

成功标准：

- 恢复后的实例可直接 `execute`
- 多次恢复不会污染原始模板状态
- 快照恢复时间进入 `<50ms` 目标区间

风险控制：

- 首版先禁止恢复后保留外部网络连接
- 只支持与原始快照相同的 kernel/rootfs digest
- 快照版本不兼容时直接拒绝恢复

### 6.3 Phase 4c：macOS Hypervisor.framework

目标：在不破坏 Linux 高层设计的前提下，增加 `hvf/` 后端。

交付范围：

- `HypervisorBackend` 的 HVF 实现
- entitlement / 代码签名开发流程
- Apple Silicon 主路径支持
- 与 Linux 共享的 loader / guest runner / snapshot envelope 逻辑

成功标准：

- `MicrovmSandbox::new(...)` 在 macOS 上可用
- guest runner 命令执行链路与 Linux 语义一致
- 大部分平台差异被限制在 `hvf/` 模块内

注意事项：

- Phase 4c 可以只保证“创建 / 执行 / 销毁”先可用，快照能力允许晚于 Linux 一版。
- 如果现成 Rust 绑定不稳定，直接使用 raw API 也是合理路线。

### 6.4 Phase 4d：性能优化

目标：把“能跑”提升到“可作为高安全生产路径”。

优化重点：

1. **冷启动优化**
   - 内核裁剪
   - rootfs 模板瘦身
   - loader 路径裁剪
   - 设备初始化并行化

2. **恢复优化**
   - file-backed memory
   - page cache 复用
   - 只读模板共享
   - 可选 diff snapshot 评估

3. **池化优化**
   - 预创建 snapshot template
   - 恢复后健康检查
   - 与现有 `SandboxPool` 思路对齐，但先不强行复用 API

4. **可观测性**
   - 冷启动耗时
   - 恢复耗时
   - guest boot 耗时
   - 命令执行耗时
   - 快照大小与恢复命中率

成功标准：

- 冷启动稳定达到 `<200ms`
- 快照恢复稳定达到 `<50ms`
- 批量执行时无明显资源泄漏
- 日志与指标足够支撑后续性能回归分析

---

## 总结

Phase 4 的正确打开方式不是“把 Firecracker 搬进仓库”，而是基于当前 `Sandbox` trait，在不破坏 `mimobox-core` 契约的前提下，新增一个受控的 `mimobox-vm` 后端。其关键设计点有三个：

1. **接口上兼容当前 trait**
   - `new / execute / destroy` 维持不变
   - `snapshot / restore` 作为 `MicrovmSandbox` 固有方法

2. **架构上平台分层**
   - 共享 VMM 核心、guest runner、快照 envelope
   - 把 KVM / HVF / WHPX 差异收敛到 backend 层

3. **实施上先 Linux，后快照，再跨平台**
   - Linux KVM 是最现实的起点
   - 快照恢复是性能目标的关键
   - macOS 可作为第二平台，Windows 后置

按这个路线推进，mimobox 可以在现有 OS 级与 Wasm 级后端之外，补上真正的“高安全原生代码执行层”，并且不需要在 Phase 4 就推翻当前核心抽象。
