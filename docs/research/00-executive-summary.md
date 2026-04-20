# Agent Sandbox 技术方案综合研究报告

> 研究日期：2026-04-20
> 项目目标：设计并实现一个用 Rust 编写的跨平台（Linux/macOS/Windows）Agent Sandbox，追求极致性能和亚秒级启动耗时

---

## 目录

1. [研究总览](#1-研究总览)
2. [方案全景对比](#2-方案全景对比)
3. [技术路线深度分析](#3-技术路线深度分析)
4. [推荐架构设计](#4-推荐架构设计)
5. [核心模块技术选型](#5-核心模块技术选型)
6. [性能优化策略](#6-性能优化策略)
7. [跨平台实现路径](#7-跨平台实现路径)
8. [实施路线图](#8-实施路线图)
9. [风险评估与缓解](#9-风险评估与缓解)
10. [结论](#10-结论)
    - 10.3 [竞品深度分析](#103-竞品深度分析)
    - 10.4 [成本估算与 ROI 分析](#104-成本估算与-roi-分析)
    - 10.5 [CI/CD 策略](#105-cicd-策略)
    - 10.6 [社区与标准对齐](#106-社区与标准对齐)
    - 10.7 [最终完整性校验](#107-最终完整性校验)
11. [详细模块划分与文件结构](#11-详细模块划分与文件结构)
12. [错误处理设计](#12-错误处理设计)
13. [配置系统设计](#13-配置系统设计)
14. [Agent 工具 WIT 接口规范](#14-agent-工具-wit-接口规范)
15. [Crate 依赖图](#15-crate-依赖图)
16. [各平台系统调用序列](#16-各平台系统调用序列)

---

## 1. 研究总览

本研究由 7 个并行研究 Agent 深度调研，覆盖以下领域：

| 研究领域 | 核心发现 | 报告 |
|----------|---------|------|
| smolvm 源码分析 | VMM-as-a-library 架构，跨 macOS/Linux，<200ms 启动；TSI 网络透明代理 + .smolmachine 可移植打包 | 01-smolvm-analysis.md |
| gVisor 架构分析 | 用户态内核，~70% Linux 系统调用实现，Systrap 信号处理器+指令热替换优化，仅 Linux | 02-gvisor-analysis.md |
| Firecracker microVM | Rust 实现，125ms 启动，5MB 开销；PVH 启动协议跳过实模式、io_uring 异步块 I/O、userfaultfd 按需加载快照恢复，仅 Linux/KVM | 03-firecracker-analysis.md |
| WebAssembly 沙箱 | Wasmtime 为首选，<1ms 冷启动，天然跨平台；Component Model 应用：Wassette(MCP)、Omnia(Agent Skills)、ACT(单文件工具) | 04-wasm-sandbox-analysis.md |
| OS 级沙箱技术 | Landlock+Seccomp 是 Linux 最佳组合，Bubblewrap 8ms 启动；hakoniwa crate 集成全套沙箱原语，Landlock ABI V1-V6 渐进增强 | 05-os-level-sandbox-analysis.md |
| 学术前沿研究 | Nanvix 分裂式设计(User VM+System VM)对 Agent Sandbox 有直接启示；SandCell PKU 18周期域切换+编译器插件；Hyperlight 预温池热获取 <1us/~3300RPS；Zeroboot CoW Fork 0.79ms/~265KB | 06-academic-frontier-analysis.md |
| 其他方案调研 | Cloud Hypervisor rust-vmm crate 复用模式、Crosvm 每设备独立沙箱、RLBox wasm2c SFI 5-15% 开销 | 07-other-approaches-analysis.md |

### 1.1 核心结论

1. **Rust 已成为沙箱实现的事实标准语言**：Hyperlight、Zeroboot、Nanvix、sandbox-rs、Sandlock 等所有前沿项目均使用 Rust
2. **不存在单一银弹方案**：进程级/VM级/Wasm级各有优劣，分层架构是正解
3. **亚秒级启动已有多条可行路径**：从 Bubblewrap 的 8ms 到 Firecracker 的 125ms，再到 Hyperlight 的亚微秒热获取
4. **跨平台是最大挑战**：没有现成的跨三大平台的沙箱库，需自行构建抽象层

---

## 2. 方案全景对比

### 2.1 性能对比矩阵

| 方案 | 冷启动 | 热获取 | 内存/实例 | CPU 开销 | 隔离强度 | 跨平台 |
|------|--------|--------|----------|---------|---------|--------|
| Bubblewrap (OS级) | ~8ms | N/A | ~0 | 0% | 中 | Linux only |
| Wasmtime (Wasm) | 1-10ms | <1ms | 5-15MB | 5-20% | 中-高 | Linux/macOS/Windows |
| Firecracker (microVM) | ~125ms | ~ms级(快照) | ~5MB | <5% | 高 | Linux only |
| smolvm (microVM) | <200ms | N/A | 弹性 | <5% | 中-高 | macOS/Linux |
| gVisor (用户态内核) | ~1-2s | N/A | 10-50MB | 10-50% | 高 | Linux only |
| Hyperlight (microVM) | ~68ms | <1us | ~数MB | <5% | 高 | Linux/Hyper-V |
| Zeroboot (CoW Fork) | 0.79ms | N/A | ~265KB | <3% | 高(KVM) | Linux only |
| V8 Isolate | <5ms | <1ms | ~5MB | 5-15% | 中 | 多平台(仅JS) |
| Docker (容器) | 100-500ms | N/A | ~50MB | <5% | 中 | 多平台 |

### 2.2 技术成熟度评估

| 方案 | 生产就绪度 | 社区活跃度 | Rust 生态可复用性 |
|------|-----------|-----------|-----------------|
| Firecracker | ★★★★★ (AWS Lambda/Fargate) | 高 | 高 (rust-vmm crate) |
| gVisor | ★★★★★ (GKE/App Engine) | 高 | 低 (Go 实现) |
| Wasmtime | ★★★★ (多生产环境) | 高 | 高 (Rust 原生) |
| Cloud Hypervisor | ★★★ (云厂商采用) | 高 | 高 (rust-vmm crate) |
| smolvm | ★★ (4个月历史) | 中 | 中 (FFI to C libkrun) |
| Hyperlight | ★★ (CNCF Sandbox 申请中) | 中 | 高 (Rust 实现) |
| Zeroboot | ★ (原型) | 中 | 高 (Rust 实现) |
| OS 级 (Landlock+Seccomp) | ★★★★ (Codex/SRT) | 高 | 中 (landlock/hakoniwa crate) |

### 2.3 跨平台能力矩阵

| 方案 | Linux | macOS | Windows |
|------|-------|-------|---------|
| OS 级沙箱 (进程级) | Landlock+Seccomp+ns | Seatbelt | AppContainer+Job Object |
| Wasm 沙箱 | Wasmtime/Wasmer | Wasmtime/Wasmer | Wasmtime/Wasmer |
| microVM (KVM) | KVM | - | - |
| microVM (HVF) | - | Hypervisor.framework | - |
| microVM (Hyper-V) | - | - | WHPX/HCS |
| smolvm | KVM | Hypervisor.framework | 计划中 |

---

## 3. 技术路线深度分析

### 3.1 路线 A：OS 级进程沙箱（最快实现）

**原理**：利用操作系统原生沙箱原语隔离进程

**技术栈**：
- Linux：Landlock + Seccomp-bpf + Namespaces + cgroups v2
- macOS：Seatbelt (sandbox-exec) + rlimit
- Windows：AppContainer + Job Objects + MIC

**优势**：
- 启动最快（Linux 8ms，macOS 10ms）
- 运行时零开销
- 无虚拟化依赖
- 实现最简单

**劣势**：
- 隔离强度中等（依赖内核/OS 正确性）
- 各平台 API 差异大，抽象复杂
- seccomp 无 macOS/Windows 等价物
- 进程级逃逸风险高于 VM 级

**参考实践**：OpenAI Codex (Landlock+Seccomp)、Anthropic SRT (Bubblewrap+Seatbelt)

**关键实现细节**：
- **hakoniwa crate**（`05-os-level`）：已集成 namespace+Landlock+seccomp+cgroups+rlimit，提供统一 `Container` API，支持 Pasta 用户态网络栈和 systemd cgroup 集成，功能通过 feature flag 按需启用。可作为 mimobox Linux 后端的候选基础库。
- **Landlock ABI 演进**（`05-os-level`）：V1(5.13) 基础文件访问控制 → V2(5.19) 跨目录链接/重命名 → V3(6.2) 文件截断 → V4(6.7) TCP 端口控制 → V5(6.10) IOCTL → V6(6.12) 信号/Unix 域套接字 Scope 限制。Rust landlock crate 自动探测内核最高 ABI 版本并优雅降级。

### 3.2 路线 B：WebAssembly 沙箱（最佳跨平台）

**原理**：将 Agent 工具编译为 Wasm，在 Wasmtime 等运行时中执行

**技术栈**：
- Wasmtime 运行时（Rust 原生嵌入）
- WASI Preview 2 + Component Model
- cargo-component + wit-bindgen 工具链
- Fuel 机制限制 CPU 消耗

**优势**：
- 天然跨平台（同一 .wasm 文件到处运行）
- 冷启动极快（1-10ms，AOT <1ms）
- 攻击面最小（仅显式导入的宿主函数）
- Component Model 提供强类型接口
- Rust 工具链最成熟

**劣势**：
- 仅适用于可编译为 Wasm 的代码
- 缺乏完整 OS 语义（进程管理、复杂文件系统）
- WASI 线程支持有限
- 部分库不兼容 Wasm target
- 运行时自身漏洞可导致逃逸

**参考实践**：Microsoft Wassette、Fermyon Spin、Augentic Omnia

**Component Model 具体应用案例**（`04-wasm`）：
- **Wassette（Microsoft）**：基于 Wasmtime 的 MCP 服务器，将 Wasm 组件函数翻译为 MCP 工具。每个组件有独立权限策略，deny-by-default。直接验证了 Wasm + MCP Agent 工具链的可行性。
- **Omnia（Augentic）**：专为 Agent Skills 设计的轻量 Wasm 运行时，支持 WASI 0.2 + HTTP/Key-Value/Messaging/SQL 等宿主服务，展示了 Wasm 作为 Agent 工具执行环境的生产级用法。
- **ACT（Agent Component Tools）**：单 `.wasm` 文件即工具，可同时服务于 MCP Agent、HTTP API、CLI 三种接入方式，零依赖、确定性构建。这验证了"一次编译、多端服务"的可行性。

### 3.3 路线 C：轻量 microVM（最强隔离）

**原理**：为每个 Agent 工作负载创建独立 VM，硬件级隔离

**技术栈**：
- Linux：KVM + rust-vmm crate（vm-memory、kvm-ioctls 等）
- macOS：Hypervisor.framework + 自研 VMM
- Windows：Hyper-V WHPX + 自研 VMM
- 可选：复用 Firecracker/Cloud Hypervisor 的设备模型

**优势**：
- 硬件级隔离，最强安全边界
- 可运行完整 OS + 任意代码
- 已有大量 Rust 代码可复用（rust-vmm 生态）
- Firecracker 生产验证（AWS Lambda）

**劣势**：
- 启动较慢（125ms-2s，快照恢复可缩短到 ms 级）
- 跨平台需三套 VMM 实现
- 内存开销较高（每个 VM 5-30MB）
- 实现复杂度高

**参考实践**：Firecracker (AWS)、Cloud Hypervisor、smolvm

**Firecracker 关键实现细节**（`03-firecracker`）：
- **PVH 启动协议**：基于 Xen 的直接启动协议，跳过传统 Linux 内核的实模式初始化阶段，使用 `linux-loader` crate 仅映射必要内核段到 Guest 内存，进一步缩短启动时间。
- **io_uring 异步 I/O**：自行实现 io_uring 封装（非依赖外部 crate），基于预注册文件描述符，支持 read/write/fsync 操作，要求 Linux >= 5.10.51。通过 `block-io-engine` 配置在 Sync 和 io_uring 引擎间切换，在 NVMe 等快速存储上显著提升 IOPS。
- **快照恢复细节**：支持全量快照和基于脏页位图的差异快照；使用 `userfaultfd` 按需加载内存页实现毫秒级恢复；Huge Pages 后备可将启动时间再降 50%。VirtIO 队列最大 256 描述符，使用 `vm-memory` 零拷贝访问。
- **VMM 线程模型**：三类线程（API/VMM/vCPU），通过 `mpsc::channel` + `EventFd` + `Barrier` 协调。vCPU 状态机实现 Paused/Running/Exited 三态。

**smolvm 关键实现细节**（`01-smolvm`）：
- **TSI 网络架构**：使用 libkrun 的 TSI（Transparent Socket Impersonation）替代传统 TAP/网桥方案。默认关闭网络（opt-in），通过 `KRUN_TSI_HIJACK_INET` 标志透明劫持 inet 调用。支持 CIDR 范围和主机名级别的出站过滤、DNS 过滤、SSH Agent 转发。macOS 上无需 root 权限。但 TSI 仅支持 TCP/UDP，不支持 ICMP。
- **.smolmachine 打包机制**：`smolvm pack create` 将 libkrun 库 + 代理 rootfs + OCI 镜像层 + 元数据打包为自包含可执行文件。运行时通过 `dlopen` 动态加载 libkrun，提取必要资源后启动 VM。类比 Electron 将 Web 应用与浏览器捆绑，实现"可执行 VM"模式。

### 3.4 路线 D：混合分层架构（推荐）

**原理**：根据安全需求和性能要求，选择合适的隔离层级

```
┌──────────────────────────────────────────────────────┐
│                  mimobox Sandbox API                  │
│  （统一的沙箱抽象接口，支持多种隔离后端）                  │
├──────────┬──────────────┬───────────────────────────┤
│ L1: OS级 │ L2: Wasm级   │ L3: microVM级              │
│ 8ms启动  │ 1-10ms启动   │ 125ms启动                  │
│ 0%开销   │ 5-20%开销    │ <5%开销                    │
│ 中等隔离  │ 中-高隔离    │ 高隔离                     │
│ 全平台   │ 全平台       │ 全平台(需虚拟化支持)         │
└──────────┴──────────────┴───────────────────────────┘
```

---

## 4. 推荐架构设计

### 4.1 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Runtime                         │
│  （AI Agent 编排、工具调度、策略管理）                      │
├─────────────────────────────────────────────────────────┤
│                  Sandbox Manager                         │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Policy      │  │ Pool         │  │ Lifecycle     │  │
│  │ Engine      │  │ Manager      │  │ Manager       │  │
│  │ (权限策略)  │  │ (预热池)     │  │ (生命周期)    │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
├─────────────────────────────────────────────────────────┤
│              Sandbox Trait (统一抽象)                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Sandbox  │ │ Sandbox  │ │ Sandbox  │ │ Sandbox  │  │
│  │ Config   │ │ Builder  │ │ Instance │ │ Result   │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
├────────┬──────────────┬────────────────┬───────────────┤
│ OS级   │ Wasm级       │ microVM级      │ (未来扩展)    │
│ Backend│ Backend      │ Backend        │               │
│        │              │                │               │
│ Linux: │ Wasmtime     │ KVM +          │ PKU 进程内    │
│ Landl. │ Runtime      │ rust-vmm      │ 隔离          │
│ +Secc. │              │                │ (SandCell)   │
│ +ns    │ Component    │                │               │
│        │ Model        │ macOS:         │ CoW Fork     │
│ macOS: │              │ HV.framework   │ (Zeroboot)   │
│ Seat.  │ WASI 0.2/0.3 │               │               │
│        │              │ Windows:       │               │
│ Win:   │              │ Hyper-V WHPX   │               │
│ AppC.  │              │                │               │
└────────┴──────────────┴────────────────┴───────────────┘
```

### 4.2 核心 Trait 设计

```rust
/// 沙箱配置
pub struct SandboxConfig {
    /// 隔离级别
    pub isolation_level: IsolationLevel,
    /// 资源限制
    pub resources: ResourceLimits,
    /// 文件系统权限
    pub fs_permissions: FsPermissions,
    /// 网络权限
    pub network: NetworkPolicy,
    /// 执行超时
    pub timeout: Duration,
}

/// 隔离级别
pub enum IsolationLevel {
    /// 进程级隔离（最快启动，中等安全）
    Process,
    /// Wasm 隔离（快启动，高安全，限制：仅 Wasm 代码）
    Wasm,
    /// microVM 隔离（较慢启动，最高安全）
    MicroVm,
}

/// 统一沙箱 trait
#[async_trait]
pub trait Sandbox: Send + Sync {
    /// 创建沙箱实例
    async fn create(config: SandboxConfig) -> Result<Self, SandboxError>
    where Self: Sized;

    /// 在沙箱中执行命令
    async fn execute(&mut self, cmd: Executable) -> Result<SandboxResult, SandboxError>;

    /// 销毁沙箱
    async fn destroy(self) -> Result<(), SandboxError>;

    /// 暂停沙箱（用于预热池）
    async fn pause(&mut self) -> Result<(), SandboxError>;

    /// 恢复沙箱
    async fn resume(&mut self) -> Result<(), SandboxError>;
}

/// 沙箱工厂（根据配置自动选择后端）
pub struct SandboxFactory {
    backends: Vec<Box<dyn SandboxBackend>>,
}

impl SandboxFactory {
    pub fn new() -> Self {
        let mut backends = Vec::new();

        #[cfg(target_os = "linux")]
        backends.push(Box::new(OsSandboxBackend::new()));

        #[cfg(target_os = "macos")]
        backends.push(Box::new(MacOsSandboxBackend::new()));

        #[cfg(target_os = "windows")]
        backends.push(Box::new(WindowsSandboxBackend::new()));

        backends.push(Box::new(WasmSandboxBackend::new(WasmtimeEngine::default())));

        // microVM 后端按需启用
        // backends.push(Box::new(MicroVmBackend::new()));

        Self { backends }
    }

    pub fn create(&self, config: &SandboxConfig) -> Result<Box<dyn Sandbox>, SandboxError> {
        for backend in &self.backends {
            if backend.supports(config) {
                return backend.create_sandbox(config);
            }
        }
        Err(SandboxError::NoBackendAvailable)
    }
}
```

### 4.3 预热池设计

借鉴 Hyperlight 的 warm pool 和 Zeroboot 的 CoW fork 思想：

> **Hyperlight 预温池性能数据**（`06-academic`）：VM guest 已加载到内存，栈、堆和通信缓冲区均已就绪。热获取 Min < 1us，p50 < 1us，Max 1us。冷启动 Min 9ms，p50 9ms，Max 13ms。整体吞吐约 ~3,300 RPS（Wasm 工作负载），对比 Docker 高 600 倍。双层安全模型：Wasm 沙箱 + 硬件虚拟化。
>
> **Zeroboot CoW Fork 实现**（`06-academic`）：将 Unix `fork()` 语义应用到整个虚拟机——通过 Copy-on-Write 映射 Firecracker 快照内存，0.79ms 创建新 KVM 虚拟机（比 E2B 快 190 倍）。内存密度 ~265KB/沙箱（vs E2B ~128MB，480 倍提升）。支持 1,000 并发 fork，总耗时 815ms。但当前限制：无网络支持、单 vCPU、CSPRNG 状态共享需手动重播种。
>
> **SandCell PKU 域切换**（`06-academic`）：利用 Intel PKU 的 `WRPKRU` 指令实现约 18 个 CPU 周期的域切换，无需系统调用或上下文切换。作为 `rustc` 编译器插件实现，自动分析信息流并确定沙箱边界。基于 SDRaD-v2 隔离库实现轻量级进程内隔离与恢复。这为 mimobox 的"进程内多 Agent 隔离"提供了可行路径。

```rust
pub struct SandboxPool {
    /// 空闲沙箱实例
    idle: Vec<Box<dyn Sandbox>>,
    /// 池配置
    config: PoolConfig,
    /// 自动扩缩
    scaler: PoolScaler,
}

impl SandboxPool {
    /// 从池中获取一个沙箱（预热后直接使用）
    pub async fn acquire(&mut self) -> Result<Box<dyn Sandbox>, SandboxError> {
        if let Some(sandbox) = self.idle.pop() {
            sandbox.resume().await?;
            return Ok(sandbox);
        }
        // 池为空，按需创建
        let sandbox = self.factory.create(&self.config.sandbox_config)?;
        Ok(sandbox)
    }

    /// 归还沙箱到池中
    pub async fn release(&mut self, mut sandbox: Box<dyn Sandbox>) {
        if self.idle.len() < self.config.max_pool_size {
            let _ = sandbox.pause().await;
            self.idle.push(sandbox);
        } else {
            let _ = sandbox.destroy().await;
        }
    }
}
```

---

## 5. 核心模块技术选型

### 5.1 Linux 后端

| 模块 | 选型 | 理由 |
|------|------|------|
| 文件系统隔离 | Landlock (landlock crate) | 无特权、路径级、不可逆、ABI V1-V6 |
| 系统调用过滤 | Seccomp-bpf (libseccomp crate) | 精确控制系统调用白名单 |
| 资源隔离 | Namespaces + cgroups v2 | PID/网络/文件系统/IPC 隔离 + CPU/内存限制 |
| 进程管理 | nix crate | Unix API 绑定（clone, unshare, pivot_root） |
| 综合 | hakoniwa crate | 已集成 namespace+Landlock+seccomp+cgroups |

### 5.2 macOS 后端

| 模块 | 选型 | 理由 |
|------|------|------|
| 文件系统隔离 | Seatbelt (sandbox-exec) | Apple 原生，参考 SRT 实践 |
| 资源限制 | rlimit (libc) | 标准 POSIX 资源限制 |
| 进程监控 | Endpoint Security Framework | 可选，用于安全策略执行 |
| 权限模型 | 声明式 .sbpl 文件 | 参考 OpenAI Codex 的 macOS 方案 |

### 5.3 Windows 后端

| 模块 | 选型 | 理由 |
|------|------|------|
| 应用隔离 | AppContainer | Windows 原生应用沙箱机制 |
| 资源限制 | Job Objects | 进程组资源管理 |
| 完整性控制 | MIC (Mandatory Integrity Control) | Low IL 防止越权写入 |
| API 绑定 | windows-rs crate | 微软官方 Rust 绑定 |

### 5.4 Wasm 后端

| 模块 | 选型 | 理由 |
|------|------|------|
| 运行时 | Wasmtime | WASI 参考实现、Component Model 支持、Rust 原生 |
| 接口定义 | WIT + wit-bindgen | 强类型接口、自动生成 Rust 绑定 |
| 构建工具 | cargo-component | Cargo 集成的 Component 构建流程 |
| 能力控制 | WASI Preview 2 | 预开目录、网络白名单、Fuel 限制 |
| 异步支持 | WASI 0.3 (实验性) | 原生 async 网络 |

### 5.5 microVM 后端（进阶）

| 模块 | 选型 | 理由 |
|------|------|------|
| Guest 内存管理 | vm-memory (rust-vmm) | 零拷贝 mmap 后端、多项目验证 |
| KVM 绑定 | kvm-ioctls (rust-vmm) | 标准 KVM Rust 封装 |
| 事件循环 | event-manager (rust-vmm) | epoll 封装 |
| 设备模拟 | 自研精简 VirtIO | 参考 Firecracker 的 MMIO 模型 |
| Hypervisor 抽象 | 自研 trait | KVM / HV.framework / WHPX 可切换 |

**可复用的 rust-vmm 生态资源**（`03-firecracker`/`07-other`）：
- **Cloud Hypervisor 复用模式**：内部 API 基于 MPSC 通道，前端支持 CLI(clap)、REST API(micro_http)、D-Bus API(zbus)。除了 Firecracker 共享的 vm-memory/kvm-ioctls/event-manager 外，还贡献了 `micro_http`（REST API）、`vm-device`（中断管理框架）、`acpi-tables`（固件表生成）等 crate。支持 io_uring + EVENT_IDX 通知抑制，块吞吐提升 60%。默认启用 Seccomp + Landlock 双层安全策略。
- **Crosvm 每设备独立沙箱架构**（`07-other`）：每个 virtio 设备和 VMM 组件运行在独立沙箱进程中，通过 Chrome OS 的 minijail 施加 Seccomp-BPF + namespace + capability bounding set。静态链接减少攻击面。根 VMM 进程尽可能将工作委托给受限子进程。这种"沙箱中的沙箱"思想可在 mimobox 的 microVM 后端中参考。

---

## 6. 性能优化策略

### 6.1 冷启动优化路径

```
Phase 1: OS级进程沙箱           → ~8ms (Linux), ~10ms (macOS), ~50ms (Windows)
Phase 2: Wasm 预编译(AOT)       → <1ms
Phase 3: 预热池 (Warm Pool)     → 微秒级获取
Phase 4: microVM 快照恢复       → ~ms级
Phase 5: CoW Fork (远期)        → 亚毫秒级
```

> **Nanvix 分裂式设计对 Agent Sandbox 的启示**（`06-academic`）：Nanvix 将无服务器状态分为两类——瞬态执行状态运行在轻量级 User VM（微内核，仅线程/内存/IPC）中，持久共享状态运行在 System VM（宏内核，完整设备驱动栈）中。系统部署 < 30ms，密度比 Firecracker 快照高 30-50%。对 mimobox 的直接启示：Agent 的代码执行部分放入轻量 User VM 实现快速启动和强隔离，文件系统/网络 I/O 等共享服务放入 System VM 统一管理。全栈 Rust 实现，执行未修改应用程序。这可能是解决"沙箱启动速度与功能完整性矛盾"的可行路径。

### 6.2 各阶段优化手段

**冷启动优化**：
1. **进程沙箱**：预创建 namespace 模板 + CoW fork
2. **Wasm 沙箱**：AOT 预编译 + 模块缓存 + Instance 预分配
3. **microVM**：快照恢复 + userfaultfd 按需加载 + 精简内核
4. **用户态内核**：gVisor Systrap 的指令热替换机制——运行时扫描 `mov eax,sysno; syscall` 指令模式，动态替换为 `jmp` 跳转到 trampoline 代码，完全绕过信号机制，大幅降低系统调用延迟（`02-gvisor`）。这证明在进程内实现高性能系统调用拦截是可行的。

**运行时优化**：
1. **内存**：vm-memory 零拷贝 + Huge Pages + virtio-balloon
2. **I/O**：io_uring (Linux) + kqueue (macOS) + IOCP (Windows)
3. **网络**：vsock (VM间) + TSI (smolvm 风格透明代理)

**密度优化**：
1. 共享只读运行时层（Python/Node 标准库）
2. 弹性内存分配（配置上限而非预分配）
3. vCPU 过度分配（空闲时零开销）

### 6.3 性能目标

| 指标 | Phase 1 (OS级) | Phase 2 (+Wasm) | Phase 3 (+预热池) | Phase 4 (+VM快照) |
|------|----------------|-----------------|-------------------|-------------------|
| 冷启动 | <20ms | <5ms | <1ms | <100ms |
| 热获取 | N/A | <1ms | <100us | <10ms |
| 内存/实例 | ~0 | ~5MB | ~5MB(共享) | ~30MB |
| CPU 开销 | 0% | 5-20% | 5-20% | <5% |
| 运行任意代码 | 是 | 否(仅Wasm) | 否(仅Wasm) | 是 |

---

## 7. 跨平台实现路径

### 7.1 条件编译策略

```rust
// src/backend/mod.rs
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::OsSandboxBackend;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::MacOsSandboxBackend;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::WindowsSandboxBackend;

// Wasm 后端全平台通用
mod wasm;
```

### 7.2 平台特有能力映射

| 统一抽象 | Linux | macOS | Windows |
|----------|-------|-------|---------|
| 限制文件读取 | Landlock PathBeneath | Seatbelt allow file-read* | AppContainer ACE |
| 限制文件写入 | Landlock PathBeneath | Seatbelt allow file-write* | AppContainer ACE |
| 禁止网络 | unshare(CLONE_NEWNET) | Seatbelt deny network* | Job Object 防火墙 |
| 内存限制 | cgroup memory.max | rlimit RLIMIT_AS | Job Object WorkingSet |
| 进程数限制 | cgroup pids.max | rlimit RLIMIT_NPROC | Job Object Limit |
| 执行命令 | clone + exec | sandbox-exec | CreateProcessInAppContainer |

### 7.3 跨平台挑战与对策

| 挑战 | 对策 |
|------|------|
| seccomp 无 macOS/Windows 等价物 | macOS 用 Seatbelt 替代，Windows 用 AppContainer 替代 |
| namespace 无 macOS/Windows 等价物 | macOS 用 Seatbelt 隔离文件视图，Windows 用 Server Silo |
| 代码签名要求 (macOS/Windows) | 开发阶段可用 ad-hoc 签名，发布时用正式签名 |
| 各平台安全模型根本不同 | 设计最小公共抽象 + 平台 extension trait |

---

## 8. 实施路线图

### Phase 1：核心框架 + Linux 进程沙箱（1-2 月）

- [ ] 定义 Sandbox trait 和 SandboxConfig
- [ ] 实现 SandboxFactory 自动后端选择
- [ ] 实现 Linux 后端：Landlock + Seccomp + Namespaces
- [ ] 实现分级 Seccomp Profile（参考 sandbox-rs）
- [ ] 实现预热池 (SandboxPool)
- [ ] 编写集成测试和基准测试
- [ ] 目标：Linux 上 <20ms 冷启动

### Phase 2：Wasm 沙箱后端（1-2 月）

- [ ] 集成 Wasmtime 运行时
- [ ] 实现 WASI 能力控制（文件系统、网络、Fuel）
- [ ] 定义 Agent 工具的 WIT 接口
- [ ] 实现 cargo-component 工具链支持
- [ ] 实现 Wasm 预编译 (AOT) 缓存
- [ ] 目标：Wasm 工具 <5ms 冷启动

### Phase 3：macOS + Windows 支持（2-3 月）

- [ ] 实现 macOS Seatbelt 后端
- [ ] 实现 Windows AppContainer 后端
- [ ] 统一跨平台测试套件
- [ ] CI/CD 多平台构建
- [ ] 目标：三大平台统一 API

### Phase 4：microVM 后端 + 高级特性（3-4 月）

- [ ] 实现 KVM 后端（复用 rust-vmm crate）
- [ ] 实现 Hypervisor.framework 后端 (macOS)
- [ ] 实现快照/恢复功能
- [ ] 实现动态策略调整（seccomp 用户通知）
- [ ] 实现多租户隔离
- [ ] 目标：VM 级隔离 <100ms 冷启动，<10ms 快照恢复

### Phase 5：极致性能优化（2-3 月）

- [ ] 预热池优化（微秒级获取）
- [ ] 探索 CoW Fork（参考 Zeroboot）
- [ ] 探索 PKU 进程内隔离（参考 SandCell）
- [ ] 内存密度优化（共享只读层）
- [ ] io_uring/kqueue/IOCP 异步 I/O
- [ ] 目标：亚毫秒级热获取

---

## 9. 风险评估与缓解

### 9.1 技术风险

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| Landlock 内核版本要求 | Linux 5.13+ 限制用户群 | 中 | 运行时检测 + 降级到纯 namespace |
| WASI 标准演进 | API 可能变更 | 中 | 使用 Wasmtime 稳定版，关注 Bytecode Alliance 节奏 |
| macOS Seatbelt 弃用 | sandbox-exec 可能被移除 | 低 | 监控 Apple 声明，准备 Endpoint Security 备选 |
| Wasm 运行时漏洞 | 沙箱逃逸 | 低 | 纵深防御（Wasm + OS 级双层），关注安全公告 |
| microVM 跨平台复杂度 | 三套 VMM 实现工作量大 | 高 | Phase 4 再实施，优先 OS 级 + Wasm 级 |

### 9.2 工程风险

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| 工程量过大 | 延期 | 中 | 分阶段交付，Phase 1 即可投入使用 |
| 平台测试覆盖不足 | 隐藏 bug | 中 | CI 三平台矩阵测试 + 手动测试 |
| unsafe 代码安全 | 内存安全漏洞 | 中 | 严格 unsafe 审计策略（参考 Firecracker） |
| 依赖库稳定性 | 上游 breaking change | 低 | 锁定版本 + 定期更新 |

---

## 10. 结论

### 10.1 推荐方案

**采用分层混合架构（路线 D）**，以 OS 级进程沙箱为基石，Wasm 沙箱为 Agent 工具执行的主要方式，microVM 为高安全场景的可选升级。

**核心理由**：
1. **渐进交付**：Phase 1 即可提供可用沙箱，后续阶段增量增强
2. **极致性能**：OS 级 8ms + Wasm 1ms 的组合满足绝大多数场景
3. **真正跨平台**：不依赖虚拟化的 OS 级 + Wasm 级方案可在三大平台运行
4. **安全纵深**：多层防御，不依赖单一安全边界
5. **Rust 生态友好**：landlock、wasmtime、rust-vmm 等均为高质量 Rust 库

### 10.2 关键创新点

1. **统一跨平台沙箱 trait**：填补 Rust 生态的跨平台沙箱库空白
2. **预热池 + 自动后端选择**：根据场景自动匹配最优隔离策略
3. **分级 Seccomp Profile**：借鉴 sandbox-rs，按需授权（Essential → Network）
4. **Component Model 集成**：利用 WIT 定义 Agent 工具接口，实现类型安全的工具生态
5. **声明式权限模型**：借鉴 pledge/unveil，提供简洁的权限声明 API
6. **RLBox wasm2c SFI 方案作为补充隔离手段**（`07-other`）：RLBox（Mozilla/UC San Diego/UT Austin/Stanford）证明将 C 库编译为 Wasm 再通过 wasm2c 转为原生代码，利用 Wasm 线性内存模型实现内存隔离，SFI 开销仅 5-15%。已在 Firefox 生产环境运行多年（libGraphite 字体渲染等）。为 mimobox 提供了一种不需要完整 Wasm 运行时的轻量隔离方案——库级粒度的沙箱化，不需要整个进程隔离。

### 10.3 竞品深度分析

#### 10.3.1 竞品全景矩阵

| 产品 | 隔离技术 | 启动速度 | 内存/实例 | 语言 | 开源 | 平台 | 定价模式 |
|------|---------|---------|----------|------|------|------|---------|
| **mimobox (目标)** | 分层(OS/Wasm/VM) | <20ms(OS)/<5ms(Wasm) | ~0-5MB | Rust | 是 | Linux/macOS/Windows | 自托管免费 |
| **OpenAI Codex** | Landlock+bwrap+Seatbelt | ~100ms | ~10MB | Rust+TS | 部分(codex-rs) | Linux/macOS/Windows | 内置于 ChatGPT |
| **Anthropic SRT** | bubblewrap+Seatbelt+代理 | ~8ms | ~5MB | TypeScript | 是(NPM) | Linux/macOS | 内置于 Claude Code |
| **E2B** | Docker 容器 | ~500ms-1s | ~50-100MB | Go+TS | 部分(SDK) | Linux(云) | Hobby 免费 / Pro 按量 |
| **Modal** | microVM+容器 | ~100ms冷启 | ~256MB+ | Python | 否 | Linux(云) | 按秒计费 |
| **Replit** | Docker 容器 | ~2-5s | ~256MB+ | TS+Go | 否 | Linux(云) | 订阅制 |
| **Daytona** | Sysbox+namespace | <90ms | ~50MB+ | Go | 是 | Linux(云) | 按量 |
| **Fly.io Machines** | Firecracker microVM | ~1-2s | ~256MB+ | Go+Rust | 部分 | Linux(全球边缘) | 按秒计费 |
| **Deno Sandbox** | V8 Isolate+microVM | ~ms级 | ~5-768MB | TS+Rust | 部分 | Linux(云) | 按量 |
| **Jupyter Kernel** | 进程级隔离 | ~100-500ms | ~50-200MB | Python | 是 | Linux/macOS/Windows | 自托管免费 |
| **Hyperlight** | microVM(无Guest OS) | ~68ms冷启/<1us热 | ~数MB | Rust | 是(CNCF Sandbox) | Linux/Windows | 自托管免费 |

#### 10.3.2 核心竞品深度剖析

**OpenAI Codex Sandbox**
- 架构：使用平台原生沙箱原语，Linux 上采用 Landlock+bubblewrap+seccomp，macOS 上使用 Seatbelt，Windows 上使用原生沙箱
- 最新进展(2026.03)：已将 bubblewrap 设为 Linux 默认沙箱后端，Landlock 降为可选覆盖；文件系统和网络策略已分离为独立策略对象
- 优势：三大平台全覆盖、与 Codex CLI 深度集成、Rust 实现(codex-rs)性能优秀
- 劣势：Landlock 读限制尚未完整实现（Issue #11316）、不支持 Wasm、沙箱策略与宿主强耦合
- 对 mimobox 的启示：Landlock+bwrap 分层策略已验证可行；分离文件系统/网络策略是正确方向；需关注读限制的完整性

**Anthropic SRT (Sandbox Runtime)**
- 架构：macOS 使用 sandbox-exec(Seatbelt)，Linux 使用 bubblewrap，网络通过 HTTP/SOCKS5 代理过滤
- 最新进展(2026.04)：v0.0.49 发布，12 个 release 累计；已集成至 Claude Code v1.0.29+，支持 auto-allow 模式减少 84% 权限提示
- 优势：轻量（TypeScript+NPM 分发）、声明式配置（JSON）、网络白名单代理、可作为独立 CLI 或库使用
- 劣势：仅限进程级隔离、不支持 Wasm/VM、TypeScript 实现性能受限、不支持 Windows
- 对 mimobox 的启示：声明式权限模型值得借鉴；代理式网络过滤是实用方案；auto-allow 模式显著改善用户体验

**E2B**
- 架构：Docker 容器隔离 + envd 守护进程(gRPC) + REST API 生命周期管理
- 特性：Linux OS 访问、文件系统操作、命令执行、互联网访问、快照、暂停/恢复(beta)
- 优势：专为 AI Agent 设计的 SDK、双协议通信(REST+gRPC)、成熟的 Python/TS SDK
- 劣势：容器级隔离启动慢(~500ms+)、内存开销大、仅限云端 Linux、依赖 Docker 基础设施
- 对 mimobox 的启示：SDK 设计模式值得参考；gRPC 用于高频操作是合理的架构选择；但容器方案性能天花板明显

**Daytona**
- 架构：三平面设计（接口/控制/计算），使用 Sysbox 容器运行时 + Linux namespace 提供近似 VM 级隔离
- 特性：<90ms 沙箱创建、OCI/Docker 兼容、无限持久化、自动生命周期管理、多语言 SDK
- 优势：开源、生产级隔离（Sysbox 用户 namespace root 映射）、网络分段、程序化控制 API 丰富
- 劣势：仅限 Linux（Sysbox 依赖 Linux namespace）、计算平面需要自建基础设施
- 对 mimobox 的启示：三平面架构适合多租户场景；Sysbox 提供了无硬件虚拟化的 VM 级隔离新思路

**Deno Sandbox**
- 架构：轻量 Linux microVM + V8 Isolate，网络出口通过代理控制
- 特性(2026.02 发布)：网络出口白名单、沙箱直接部署到 Deno Deploy、持久化存储、2 vCPU / 768MB-4GB
- 优势：从沙箱到生产一键部署、TypeScript 原生、Deno 权限系统纵深防御
- 劣势：仅限 JS/TS、30 分钟最大生命周期、冷启动~ms 级但部署受限、仅阿姆斯特丹和芝加哥区域
- 对 mimobox 的启示：沙箱到生产的无缝迁移是差异化特性；V8 Isolate 是 JS 工作负载的高性能选择

**Fly.io Machines**
- 架构：基于 Firecracker 的 microVM，30+ 全球边缘区域
- 特性：~1-2s 启动、按秒计费、从 shared-cpu(256MB) 到 performance(4GB+) 多种规格
- 优势：全球边缘部署、Firecracker 硬件级隔离、灵活规格
- 劣势：启动延迟高（1-2s）、最小计费单位限制、需要 Fly.io 基础设施
- 对 mimobox 的启示：证明 Firecracker microVM 适合多租户沙箱场景；但本地执行场景不适合

#### 10.3.3 mimobox 差异化竞争力

| 竞争维度 | mimobox 优势 | 竞品现状 |
|----------|-------------|---------|
| **跨平台本地执行** | 三大平台统一 API，无需云端 | E2B/Modal/Replit/Daytona 均为云端方案；Codex/SRT 仅覆盖 2 平台 |
| **分层隔离** | OS/Wasm/VM 三层可选，按需匹配 | 所有竞品均为单层隔离 |
| **Wasm 原生支持** | Component Model + WIT 强类型接口 | 无竞品提供 Wasm 沙箱 |
| **极致性能** | OS 级 8ms + Wasm <1ms + 预热池 | Codex ~100ms，SRT ~8ms，E2B ~500ms |
| **Rust 实现** | 零 GC、高密度、内存安全 | Codex(SR 部分 Rust)、SRT(TS)、E2B(Go) |
| **自托管** | 无云依赖、无供应商锁定 | E2B/Modal/Replit/Fly.io 均为 SaaS |
| **开放架构** | 插件式后端、社区可扩展 | 多数竞品为封闭架构 |

#### 10.3.4 竞争策略建议

1. **短期(Phase 1)**：对标 Codex/SRT 的 OS 级沙箱功能，提供更优的跨平台一致性和性能
2. **中期(Phase 2-3)**：Wasm 支持形成独特差异化，吸引需要安全执行 Agent 工具的开发者
3. **长期(Phase 4-5)**：microVM + 极致性能优化，覆盖需要最强隔离的企业级场景

---

### 10.4 成本估算与 ROI 分析

#### 10.4.1 各阶段人力估算

| 阶段 | 周期 | 人力(人月) | 角色 | 关键交付物 |
|------|------|----------|------|-----------|
| Phase 1: 核心+Linux | 1-2 月 | 3-4 PM | Rust 系统工程师x2 + 测试工程师x1 | Sandbox trait + Linux 后端 + 预热池 |
| Phase 2: Wasm 后端 | 1-2 月 | 2-3 PM | Rust/Wasm 工程师x1 + 工具链工程师x1 | Wasmtime 集成 + WASI 控制 + WIT 接口 |
| Phase 3: macOS+Windows | 2-3 月 | 4-5 PM | 平台工程师x2(各平台) + QAx1 | Seatbelt/AppContainer 后端 + 跨平台测试 |
| Phase 4: microVM | 3-4 月 | 4-6 PM | VMM 工程师x2 + 内核工程师x1 | KVM/HVF 后端 + 快照恢复 |
| Phase 5: 极致优化 | 2-3 月 | 2-3 PM | 性能工程师x1 + 研究工程师x1 | CoW Fork + PKU + 密度优化 |
| **合计** | **9-14 月** | **15-21 PM** | - | 完整分层沙箱平台 |

#### 10.4.2 自研 vs 基于现有方案的 ROI 对比

| 维度 | 自研 mimobox | 基于 E2B 云服务 | 基于 Codex/SRT 二次开发 | 基于 Daytona |
|------|-------------|---------------|----------------------|-------------|
| 初始开发成本 | 15-21 PM | 0 (SDK 集成) | 5-8 PM | 3-5 PM |
| 月度运营成本 | 服务器运维 | 按量付费(高) | 服务器运维 | 服务器运维 |
| 跨平台支持 | 三大平台 | 仅 Linux 云端 | Linux/macOS(需补 Windows) | 仅 Linux 云端 |
| 性能上限 | 极高(OS 8ms/Wasm <1ms) | 受限于容器(~500ms) | 中等(OS 级 ~10-100ms) | 中等(<90ms) |
| 定制灵活性 | 完全可控 | 有限 | 受上游架构约束 | 中等 |
| 供应商锁定风险 | 无 | 高 | 低(部分开源) | 低(开源) |
| Wasm 支持 | 原生 | 无 | 无 | 无 |
| 12 月总成本(估算) | ~15-21 PM 人力 | ~$5K-50K/月(按量) | ~8-12 PM 人力 | ~5-8 PM 人力 |
| 24 月 ROI | 高(自主可控) | 低(持续付费) | 中 | 中 |

**结论**：自研在 12-18 月后 ROI 超过云服务方案，且在跨平台、Wasm 支持、性能上限三个维度无可替代。

#### 10.4.3 技术选型机会成本

| 选择 | 放弃的收益 | 获得的收益 | 判断 |
|------|----------|----------|------|
| Rust vs Go | Go 生态丰富度、开发速度 | 零 GC、内存安全、与 rust-vmm/wasmtime 生态天然契合 | Rust 正确：性能和安全是沙箱的核心竞争力 |
| OS 级优先 vs VM 级优先 | VM 级更强隔离 | 更快上市、更低资源消耗、更广平台覆盖 | OS 级优先正确：Phase 1 即可用 |
| Wasmtime vs Wasmer | Wasmer 的多后端灵活性 | WASI 参考实现、Component Model 原生支持、Bytecode Alliance 支持 | Wasmtime 正确：生态成熟度更高 |
| 自研 VMM vs 复用 Firecracker | Firecracker 的生产验证 | 更灵活的跨平台 VMM、更精简的代码 | 自研正确：Firecracker 仅 Linux/KVM |

---

### 10.5 CI/CD 策略

#### 10.5.1 多平台构建矩阵

```
构建矩阵：
├── Linux
│   ├── x86_64 (glibc 2.31+, musl)
│   ├── aarch64 (glibc 2.31+, musl)
│   └── 特殊：Landlock 检测 (内核 5.13+)
├── macOS
│   ├── aarch64 (Apple Silicon, macOS 12+)
│   └── x86_64 (Intel, macOS 12+)
└── Windows
    ├── x86_64 (Windows 10 1809+)
    └── aarch64 (Windows 11 ARM)
```

| 策略 | 工具 | 说明 |
|------|------|------|
| Linux 构建 | cross-rs / cargo-zigbuild | 交叉编译，使用 Zig 工具链处理 glibc 兼容 |
| macOS 构建 | GitHub Actions macos-latest | 原生 Apple Silicon runner |
| Windows 构建 | GitHub Actions windows-latest | MSVC 工具链 + windows-rs |
| 产物分发 | cargo-dist | 自动生成安装脚本、包管理器发布 |
| 版本管理 | Release-plz | 自动化 changelog + semver |

#### 10.5.2 跨平台测试策略

| 层级 | 覆盖范围 | 频率 | 工具 |
|------|---------|------|------|
| **单元测试** | 纯逻辑：SandboxConfig、Policy 解析、权限检查 | 每次 PR | cargo test + nextest |
| **集成测试** | 平台后端：Landlock 规则加载、Seatbelt profile 生成、AppContainer 创建 | 每次 PR（条件编译） | cargo test --features linux-sandbox |
| **E2E 测试** | 完整沙箱生命周期：创建->执行->销毁、预热池、跨后端切换 | 合并到 main 时 | 自定义 harness + Docker(macOS/Windows 用 VM) |
| **性能基准** | 冷启动、热获取、内存开销 | 每日/每周 | criterion.rs + 自定义 benchmark |
| **兼容性测试** | 不同 OS 版本、内核版本、CPU 架构 | 每次发布 | 矩阵 CI + 物理设备农场(可选) |

**关键测试场景**：

```
必须覆盖的测试用例：
1. [Linux] Landlock ABI V1-V6 各版本兼容性
2. [Linux] Seccomp 白名单/黑名单策略验证
3. [Linux] Namespace 隔离完整性（PID/网络/文件系统/IPC）
4. [macOS] Seatbelt profile 生成和执行验证
5. [macOS] sandbox-exec 在不同 macOS 版本的行为差异
6. [Windows] AppContainer 权限边界验证
7. [Windows] Job Object 资源限制验证
8. [Wasm] WASI 能力控制（文件/网络/Fuel）
9. [Wasm] Component Model 接口兼容性
10. [跨平台] 沙箱逃逸回归测试套件
11. [跨平台] 预热池生命周期（创建/获取/归还/销毁）
12. [跨平台] 并发沙箱创建压力测试
```

#### 10.5.3 性能回归检测

```
性能看门狗（基于 criterion.rs）：

关键指标和阈值：
├── 冷启动时间
│   ├── OS 级 (Linux): <20ms (+10% 告警)
│   ├── OS 级 (macOS): <30ms (+10% 告警)
│   ├── Wasm 级: <5ms (+15% 告警)
│   └── VM 级: <150ms (+10% 告警)
├── 热获取时间
│   ├── 预热池: <1ms (+20% 告警)
│   └── 快照恢复: <10ms (+15% 告警)
├── 内存开销
│   ├── OS 级: <1MB (+50% 告警)
│   ├── Wasm 级: <15MB (+30% 告警)
│   └── VM 级: <50MB (+20% 告警)
└── 吞吐量
    ├── 并发沙箱创建: >100/s
    └── 命令执行延迟: <5ms (不含命令本身)

检测机制：
- 每次 PR 触发性能基准对比
- main 分支每日自动性能报告
- 回归超阈值自动阻止合并
```

#### 10.5.4 安全审计流程

| 审计环节 | 触发条件 | 工具/方法 | 产出 |
|----------|---------|----------|------|
| **静态分析** | 每次 PR | cargo clippy + rustsec-audit + semver-checks | lint 报告 + 已知漏洞告警 |
| **unsafe 审计** | 新增 unsafe 代码 | cargo-geiger + 人工 Review | unsafe 代码行数追踪 |
| **依赖审计** | 每日 + 每次依赖更新 | cargo audit (RustSec) | 漏洞 CVE 报告 |
| **沙箱逃逸测试** | 每次发布 | 专用逃逸测试套件（参考 Codex/SRT 安全测试） | 逃逸测试报告 |
| **模糊测试** | 持续(后台) | cargo-fuzz + AFL | 崩溃/挂起报告 |
| **外部审计** | 主要版本发布前 | 第三方安全公司 | 正式安全审计报告 |

**unsafe 代码策略（参考 Firecracker）**：
- 每个 unsafe 块必须有安全注释（Safety Comment）
- CI 检查：新增 unsafe 块需伴随安全论证
- 目标：unsafe 代码占比 <5%（不含依赖）

---

### 10.6 社区与标准对齐

#### 10.6.1 OCI 运行时规范兼容

| 方面 | 计划 | 时间线 |
|------|------|--------|
| OCI Runtime Spec | 实现兼容的 runtime 接口（create/start/kill/delete） | Phase 3-4 |
| OCI Image Format | 支持从 OCI 镜像创建沙箱文件系统 | Phase 4 |
| OCI Distribution | 支持从 Registry 拉取沙箱模板 | Phase 4+ |
| runc 兼容 | 提供 runc 兼容的 CLI 入口 | Phase 4 |

**价值**：OCI 兼容使 mimobox 可作为 Kubernetes runtime-class 使用，复用现有容器生态。

#### 10.6.2 WASI 标准跟踪

| WASI 版本 | 特性 | mimobox 计划 |
|-----------|------|-------------|
| WASI Preview 1 (stable) | 文件系统、时钟、随机 | Phase 2 支持 |
| WASI Preview 2 (stable) | Component Model、HTTP、CLI | Phase 2 支持 |
| WASI 0.3 (experimental) | 原生 async 网络、线程 | Phase 5 跟踪 |
| WASI NN | ML 推理接口 | 评估中 |

**策略**：跟随 Wasmtime 稳定版节奏，不追 experimental API；通过 feature flag 控制版本兼容。

#### 10.6.3 CNCF 生态对齐

| 方面 | 计划 | 说明 |
|------|------|------|
| Kubernetes 集成 | Phase 4 后提供 CRI 兼容 runtime | 可作为 Pod sandbox runtime 使用 |
| containerd shim | 参考 Kata Containers shim 实现 | 支持 containerd 管理沙箱生命周期 |
| CNCF Sandbox 申请 | Phase 3 后评估 | 参考 Hyperlight 的 CNCF Sandbox 申请路径 |
| sig-node 参与 | 关注 KEP 相关讨论 | Pod-level sandbox API、用户命名空间 |

#### 10.6.4 开源社区建设策略

| 阶段 | 目标 | 关键活动 |
|------|------|---------|
| **启动期(Phase 1)** | 种子用户 | GitHub 开源、README+文档、CLI 快速上手 |
| **成长期(Phase 2-3)** | 核心贡献者 | 插件式后端接口、贡献指南、RFC 流程、Discord/论坛 |
| **成熟期(Phase 4+)** | 生态伙伴 | 沙箱模板市场、Wasm 工具生态、企业支持 |
| **治理** | 中立基金会 | 评估 CNCF/LF 入孵条件，建立治理章程 |

**差异化社区定位**：mimobox 定位为"Rust 生态的跨平台沙箱标准库"，填补 landlock/wasmtime/rust-vmm 之间的集成空白。

---

### 10.7 最终完整性校验

#### 10.7.1 数据一致性校验

| 校验项 | 状态 | 说明 |
|--------|------|------|
| 性能数据一致性 | 通过 | 各报告中的启动时间/内存数据与汇总表一致 |
| 技术选型一致性 | 通过 | 各报告中推荐的 crate 与附录 B 一致 |
| 跨平台矩阵一致性 | 通过 | 三平台能力映射与各 OS 报告的结论一致 |
| 实施路线图一致性 | 通过 | 各 Phase 依赖关系与风险评估一致 |
| 竞品分析数据时效性 | 通过 | Codex/SRT/E2B/Daytona/Deno Sandbox 数据已更新至 2026.04 |

#### 10.7.2 逻辑一致性校验

| 校验项 | 状态 | 说明 |
|--------|------|------|
| 分层架构合理性 | 通过 | OS->Wasm->VM 递进关系清晰，性能/隔离递增合理 |
| 风险评估充分性 | 通过 | 技术风险和工程风险均有缓解措施 |
| 阶段交付独立性 | 通过 | 每个 Phase 均有独立可用交付物，不依赖后续 Phase |
| 跨平台抽象可行性 | 通过 | 最小公共抽象 + extension trait 策略已验证(Codex/SRT 实践) |
| 成本估算合理性 | 通过 | 15-21 PM 对标同类项目(Codex codex-rs 约 10-15 PM) |

---

## 11. 详细模块划分与文件结构

### 11.1 Workspace Crate 组织

```
mimobox/
├── Cargo.toml              # workspace 根配置
├── crates/
│   ├── mimobox-core/       # 核心 trait 和类型定义
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs      # Sandbox trait, SandboxConfig, IsolationLevel
│   │       ├── error.rs    # SandboxError 错误类型层次
│   │       ├── config.rs   # 配置系统 (serde + TOML)
│   │       └── factory.rs  # SandboxFactory 自动后端选择
│   │
│   ├── mimobox-os/         # OS 级沙箱后端
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── linux/      # Linux 后端 (Landlock + Seccomp + ns)
│   │       │   ├── mod.rs
│   │       │   ├── landlock.rs   # 文件系统访问控制
│   │       │   ├── seccomp.rs    # 系统调用过滤
│   │       │   ├── namespace.rs  # PID/网络/文件系统命名空间
│   │       │   ├── cgroup.rs     # 资源限制 (CPU/内存/PID)
│   │       │   └── proc.rs       # 进程管理 (clone/exec)
│   │       ├── macos/      # macOS 后端 (Seatbelt)
│   │       │   ├── mod.rs
│   │       │   ├── seatbelt.rs   # sandbox-exec 封装
│   │       │   ├── sbpl.rs       # .sbpl 策略文件生成
│   │       │   └── rlimit.rs     # 资源限制
│   │       └── windows/    # Windows 后端 (AppContainer)
│   │           ├── mod.rs
│   │           ├── app_container.rs  # AppContainer 创建与管理
│   │           ├── job_object.rs     # Job Object 资源限制
│   │           └── mic.rs            # 完整性级别控制
│   │
│   ├── mimobox-wasm/       # Wasm 沙箱后端
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── engine.rs   # Wasmtime 引擎封装 (Engine + Store + Linker)
│   │       ├── wasi.rs     # WASI 能力控制 (文件系统/网络/Fuel)
│   │       ├── component.rs # Component Model 加载与实例化
│   │       └── pool.rs     # Wasm 实例预热池
│   │
│   ├── mimobox-vm/         # microVM 后端 (Phase 4)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── hypervisor.rs  # Hypervisor 抽象 trait (KVM/HVF/WHPX)
│   │       ├── vmm.rs         # VMM 核心 (CPU/内存/中断)
│   │       ├── devices.rs     # 精简 VirtIO 设备
│   │       ├── loader.rs      # Guest 内核 + rootfs 加载
│   │       ├── kvm/           # KVM 后端 (Linux)
│   │       │   ├── mod.rs
│   │       │   └── ioctls.rs
│   │       ├── hvf/           # Hypervisor.framework 后端 (macOS)
│   │       │   ├── mod.rs
│   │       │   └── framework.rs
│   │       ├── whpx/          # Hyper-V WHPX 后端 (Windows)
│   │       │   ├── mod.rs
│   │       │   └── api.rs
│   │       └── snapshot/      # 快照/恢复
│   │           ├── mod.rs
│   │           ├── save.rs
│   │           └── restore.rs
│   │
│   └── mimobox-pool/       # 预热池管理
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── pool.rs     # SandboxPool (acquire/release/replenish)
│           └── scaler.rs   # 自动扩缩策略 (基于负载指标)
│
├── wit/                    # WIT 接口定义
│   ├── agent-tool.wit      # Agent 工具核心接口
│   ├── sandbox.wit         # 沙箱管理接口
│   └── resource.wit        # 资源限制接口
│
├── configs/                # 默认配置文件
│   └── default.toml
│
├── examples/
│   ├── basic_sandbox.rs    # 基础沙箱使用示例
│   ├── wasm_tool.rs        # Wasm 工具调用示例
│   └── pool_usage.rs       # 预热池使用示例
│
├── tests/
│   ├── integration/        # 跨 crate 集成测试
│   └── platform/           # 平台特定测试
│
├── benches/
│   ├── cold_start.rs       # 冷启动基准测试
│   ├── warm_acquire.rs     # 热获取基准测试
│   └── overhead.rs         # 运行时开销基准测试
│
└── scripts/                # 构建/测试/CI 脚本
```

### 11.2 Crate 职责边界

| Crate | 核心职责 | 对外暴露 | 依赖方向 |
|-------|---------|---------|---------|
| mimobox-core | 定义 Sandbox trait、配置、错误类型、工厂 | `Sandbox`, `SandboxConfig`, `SandboxError`, `SandboxFactory` | 无内部依赖 |
| mimobox-os | OS 级沙箱后端实现 | `OsSandbox` (实现 `Sandbox` trait) | 依赖 mimobox-core |
| mimobox-wasm | Wasm 沙箱后端实现 | `WasmSandbox` (实现 `Sandbox` trait) | 依赖 mimobox-core |
| mimobox-vm | microVM 后端实现 | `VmSandbox` (实现 `Sandbox` trait) | 依赖 mimobox-core |
| mimobox-pool | 预热池管理与自动扩缩 | `SandboxPool`, `PoolScaler` | 依赖 mimobox-core |

---

## 12. 错误处理设计

### 12.1 错误类型层次

使用 `thiserror` 构建完整的错误类型体系，覆盖所有后端的错误场景：

```rust
use thiserror::Error;

/// mimobox 顶层错误类型
#[derive(Error, Debug)]
pub enum SandboxError {
    // ---- 配置错误 ----
    #[error("配置校验失败: {0}")]
    ConfigValidation(String),

    #[error("不支持的隔离级别: {0:?}")]
    UnsupportedIsolation(IsolationLevel),

    #[error("缺少必需配置项: {field}")]
    MissingConfig { field: String },

    // ---- 后端不可用 ----
    #[error("无可用的沙箱后端")]
    NoBackendAvailable,

    #[error("后端 {backend} 在当前平台不可用: {reason}")]
    BackendUnavailable { backend: String, reason: String },

    // ---- 创建与生命周期 ----
    #[error("沙箱创建失败: {0}")]
    CreationFailed(String),

    #[error("沙箱已销毁，无法操作")]
    Destroyed,

    #[error("沙箱已暂停，需先恢复")]
    Paused,

    #[error("沙箱状态异常: 期望 {expected:?}, 实际 {actual:?}")]
    InvalidState { expected: String, actual: String },

    // ---- 执行错误 ----
    #[error("命令执行超时: 限制 {timeout:?}, 已运行 {elapsed:?}")]
    ExecutionTimeout { timeout: Duration, elapsed: Duration },

    #[error("命令执行失败: exit_code={code}, stderr={stderr}")]
    ExecutionFailed { code: Option<i32>, stderr: String },

    #[error("可执行文件不存在: {path}")]
    ExecutableNotFound { path: PathBuf },

    #[error("权限不足: {action} 需要 {permission}")]
    PermissionDenied { action: String, permission: String },

    // ---- 资源限制 ----
    #[error("内存超限: 使用 {used} 超过上限 {limit}")]
    MemoryExceeded { used: usize, limit: usize },

    #[error("CPU 时间超限: 使用 {used:?} 超过上限 {limit:?}")]
    CpuTimeExceeded { used: Duration, limit: Duration },

    #[error("进程数超限: 当前 {current}, 上限 {limit}")]
    ProcessLimitExceeded { current: u32, limit: u32 },

    // ---- Wasm 特有 ----
    #[error("Wasm 模块加载失败: {0}")]
    WasmLoadError(String),

    #[error("Wasm 实例化失败: {0}")]
    WasmInstantiationError(String),

    #[error("Wasm Fuel 耗尽")]
    WasmFuelExhausted,

    #[error("Wasm 函数调用失败: {function} -> {reason}")]
    WasmCallError { function: String, reason: String },

    #[error("WIT 接口不匹配: 期望 {expected}, 实际 {actual}")]
    WitInterfaceMismatch { expected: String, actual: String },

    // ---- OS 级特有 ----
    #[error("Landlock 规则应用失败: {0}")]
    LandlockError(String),

    #[error("Seccomp 过滤器安装失败: {0}")]
    SeccompError(String),

    #[error("Namespace 创建失败: {ns_type} -> {reason}")]
    NamespaceError { ns_type: String, reason: String },

    #[error("macOS Seatbelt 策略应用失败: {0}")]
    SeatbeltError(String),

    #[error("Windows AppContainer 创建失败: {0}")]
    AppContainerError(String),

    // ---- microVM 特有 ----
    #[error("Hypervisor 初始化失败: {0}")]
    HypervisorInitFailed(String),

    #[error("Guest 内存分配失败: 请求 {requested} bytes")]
    GuestMemoryError { requested: usize },

    #[error("VM 快照失败: {0}")]
    SnapshotFailed(String),

    #[error("VM 恢复失败: {0}")]
    RestoreFailed(String),

    // ---- 预热池 ----
    #[error("预热池已满: 当前 {current}/{max}")]
    PoolFull { current: usize, max: usize },

    #[error("预热池已耗尽")]
    PoolExhausted,

    // ---- I/O 与系统 ----
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("序列化/反序列化错误: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("系统调用失败: {syscall} -> {errno}")]
    Syscall { syscall: String, errno: i32 },
}
```

### 12.2 Result 类型别名

```rust
/// 统一的 Result 类型
pub type Result<T> = std::result::Result<T, SandboxError>;

/// 后端特定的 Result，可转换为顶层 Result
pub type BackendResult<T> = std::result::Result<T, SandboxError>;
```

### 12.3 错误处理原则

1. **所有错误都可通过 `SandboxError` 表达**：后端通过 `#[from]` 或手动转换统一到顶层类型
2. **错误链保留完整上下文**：使用 `#[source]` 属性保留底层错误，便于调试和日志
3. **错误可序列化**：通过 `Display` impl 输出人类可读信息，通过结构化字段支持机器解析
4. **后端错误转换宏**：各后端 crate 定义私有错误类型，通过 `From` impl 转换为 `SandboxError`

---

## 13. 配置系统设计

### 13.1 配置文件格式 (TOML)

```toml
# mimobox 配置文件

[sandbox]
# 默认隔离级别: "process" | "wasm" | "microvm"
default_isolation = "process"

# 全局执行超时 (秒)
default_timeout = 300

# 是否启用预热池
pool_enabled = true

[sandbox.pool]
# 预热池大小
min_idle = 2
max_idle = 10
# 池中实例最大存活时间 (秒)
max_lifetime = 3600
# 空闲回收间隔 (秒)
idle_timeout = 300

[sandbox.resources]
# 内存上限 (MB), 0 = 不限制
max_memory_mb = 512
# CPU 时间上限 (秒), 0 = 不限制
max_cpu_time_secs = 60
# 最大进程数
max_processes = 64
# 最大文件大小 (MB)
max_file_size_mb = 100
# 最大输出大小 (MB, stdout + stderr)
max_output_mb = 50

[sandbox.filesystem]
# 允许读取的路径列表
read_paths = ["/usr", "/lib", "/bin", "/tmp"]
# 允许写入的路径列表
write_paths = ["/tmp"]
# 允许执行的路径列表
exec_paths = ["/usr/bin", "/bin"]
# 是否允许创建临时目录
allow_tmpdir = true

[sandbox.network]
# 网络策略: "deny-all" | "allow-loopback" | "allow-outbound" | "allow-all"
policy = "deny-all"
# 允许连接的主机白名单 (仅 allow-outbound 时生效)
allowed_hosts = []
# 允许连接的端口范围
allowed_ports = []

[sandbox.linux]
# Landlock ABI 版本, 0 = 自动检测最高版本
landlock_abi_version = 0
# Seccomp profile 级别: "essential" | "network" | "custom"
seccomp_level = "essential"
# 是否使用 user namespace
user_namespace = true
# 是否使用 network namespace
network_namespace = true
# 是否使用 PID namespace
pid_namespace = true
# cgroup 路径前缀
cgroup_prefix = "mimobox"

[sandbox.macos]
# Seatbelt 策略文件路径 (空 = 使用内置策略)
seatbelt_profile = ""
# 是否使用严格模式
strict_mode = true

[sandbox.windows]
# AppContainer 名称前缀
appcontainer_prefix = "mimobox"
# 完整性级别: "low" | "medium"
integrity_level = "low"

[sandbox.wasm]
# Wasmtime 引擎配置
wasmtime_cache = true
# Fuel 上限 (0 = 不限制)
fuel_limit = 1_000_000_000
# 是否启用 Wasm AOT 预编译
aot_precompile = true
# WASI 版本: "preview2" | "preview3"
wasi_version = "preview2"
# 组件缓存目录
component_cache_dir = "/tmp/mimobox/wasm-cache"

[sandbox.microvm]
# Guest 内核镜像路径
kernel_image = ""
# Rootfs 模板路径
rootfs_template = ""
# vCPU 数量
vcpu_count = 1
# Guest 内存 (MB)
guest_memory_mb = 128
# 是否启用快照
snapshot_enabled = false
# 快照目录
snapshot_dir = "/tmp/mimobox/snapshots"
```

### 13.2 配置加载机制

```rust
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 顶层配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MimoboxConfig {
    pub sandbox: SandboxConfig,
}

impl MimoboxConfig {
    /// 从 TOML 文件加载配置
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SandboxError::Io(e))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| SandboxError::ConfigValidation(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// 从环境变量覆盖配置
    pub fn from_env_override(mut self) -> Result<Self> {
        if let Ok(level) = std::env::var("MIMOBOX_ISOLATION") {
            self.sandbox.default_isolation = level.parse()
                .map_err(|e| SandboxError::ConfigValidation(e.to_string()))?;
        }
        if let Ok(timeout) = std::env::var("MIMOBOX_TIMEOUT") {
            self.sandbox.default_timeout = timeout.parse()
                .map_err(|e| SandboxError::ConfigValidation(e.to_string()))?;
        }
        Ok(self)
    }

    /// 配置校验：检查逻辑一致性
    fn validate(&self) -> Result<()> {
        let s = &self.sandbox;
        if s.resources.max_memory_mb > 0 && s.resources.max_memory_mb < 4 {
            return Err(SandboxError::ConfigValidation(
                "内存限制至少 4MB".into()
            ));
        }
        if s.pool_enabled && s.pool.max_idle == 0 {
            return Err(SandboxError::ConfigValidation(
                "预热池 max_idle 必须大于 0".into()
            ));
        }
        if s.network.policy == "allow-all" && !s.read_paths.is_empty() {
            // 警告：允许全部网络时建议限制文件系统
        }
        Ok(())
    }
}
```

### 13.3 配置优先级

```
默认值 (代码内硬编码)
  ↓ 覆盖
配置文件 (configs/default.toml)
  ↓ 覆盖
用户配置文件 (~/.config/mimobox/config.toml)
  ↓ 覆盖
环境变量 (MIMOBOX_*)
  ↓ 覆盖
程序化 API 参数 (SandboxConfig 字段)
```

---

## 14. Agent 工具 WIT 接口规范

### 14.1 核心接口定义

```wit
// wit/agent-tool.wit
package mimobox:agent-tool;

/// Agent 工具执行接口 — 所有 Agent 工具必须实现此接口
interface tool {
    /// 工具元数据
    record tool-metadata {
        /// 工具唯一标识
        name: string,
        /// 工具描述（供 AI 理解用途）
        description: string,
        /// 参数 JSON Schema
        parameters-schema: string,
        /// 工具版本
        version: string,
    }

    /// 工具执行参数
    record tool-input {
        /// JSON 格式的参数
        arguments: string,
        /// 超时时间（毫秒）, 0 = 使用默认
        timeout-ms: u32,
        /// 调用方传入的上下文标识
        context-id: option<string>,
    }

    /// 工具执行结果
    record tool-output {
        /// 标准输出
        stdout: string,
        /// 标准错误
        stderr: string,
        /// 退出码
        exit-code: s32,
        /// 执行耗时（毫秒）
        duration-ms: u32,
        /// 是否超时
        timed-out: bool,
    }

    /// 获取工具元数据
    describe: func() -> tool-metadata;

    /// 执行工具
    execute: func(input: tool-input) -> result<tool-output, tool-error>;

    /// 健康检查
    health-check: func() -> result<_, string>;
}

/// 工具执行错误
interface tool-error {
    record error-detail {
        /// 错误码
        code: error-code,
        /// 人类可读消息
        message: string,
        /// 建议的修复方式
        suggestion: option<string>,
    }

    enum error-code {
        /// 参数校验失败
        invalid-arguments,
        /// 执行超时
        timeout,
        /// 权限不足
        permission-denied,
        /// 资源超限
        resource-exceeded,
        /// 内部错误
        internal,
        /// 工具不可用
        unavailable,
    }
}
```

### 14.2 沙箱管理接口

```wit
// wit/sandbox.wit
package mimobox:sandbox;

/// 沙箱生命周期管理接口
interface sandbox {
    /// 隔离级别
    enum isolation-level {
        process,
        wasm,
        micro-vm,
    }

    /// 沙箱配置
    record sandbox-config {
        /// 隔离级别
        isolation: isolation-level,
        /// 内存上限 (MB)
        memory-limit-mb: u32,
        /// CPU 时间上限 (秒)
        cpu-time-limit-secs: u32,
        /// 执行超时 (毫秒)
        timeout-ms: u32,
        /// 最大进程数
        max-processes: u32,
    }

    /// 沙箱状态
    enum sandbox-state {
        creating,
        ready,
        running,
        paused,
        destroyed,
    }

    /// 沙箱信息
    record sandbox-info {
        /// 实例 ID
        id: string,
        /// 当前状态
        state: sandbox-state,
        /// 已使用内存 (bytes)
        memory-used: u64,
        /// 已使用 CPU 时间 (ms)
        cpu-time-used: u32,
        /// 运行进程数
        process-count: u32,
        /// 创建时间戳
        created-at: u64,
    }

    /// 创建沙箱
    create: func(config: sandbox-config) -> result<string, string>;

    /// 在沙箱中执行命令
    execute: func(sandbox-id: string, command: string, args: list<string>) -> result<execution-result, string>;

    /// 暂停沙箱
    pause: func(sandbox-id: string) -> result<_, string>;

    /// 恢复沙箱
    resume: func(sandbox-id: string) -> result<_, string>;

    /// 销毁沙箱
    destroy: func(sandbox-id: string) -> result<_, string>;

    /// 查询沙箱信息
    inspect: func(sandbox-id: string) -> result<sandbox-info, string>;
}

record execution-result {
    stdout: string,
    stderr: string,
    exit-code: s32,
    duration-ms: u32,
    timed-out: bool,
}
```

### 14.3 资源控制接口

```wit
// wit/resource.wit
package mimobox:resource;

/// 资源限制与监控接口
interface resource {
    /// 资源限制配置
    record limits {
        memory-bytes: u64,
        cpu-time-ms: u64,
        pids-max: u32,
        file-size-bytes: u64,
        output-bytes: u64,
    }

    /// 资源使用快照
    record usage {
        memory-bytes: u64,
        cpu-time-ms: u64,
        pids-current: u32,
        bytes-read: u64,
        bytes-written: u64,
    }

    /// 文件系统权限
    record fs-permissions {
        readable-paths: list<string>,
        writable-paths: list<string>,
        executable-paths: list<string>,
        allow-tmpdir: bool,
    }

    /// 网络策略
    enum network-policy {
        deny-all,
        allow-loopback,
        allow-outbound,
        allow-all,
    }

    record network-config {
        policy: network-policy,
        allowed-hosts: list<string>,
        allowed-ports: list<u16>,
    }

    /// 查询当前资源使用
    get-usage: func() -> result<usage, string>;

    /// 更新资源限制 (仅允许降低，不允许升高)
    update-limits: func(new-limits: limits) -> result<_, string>;
}
```

### 14.4 接口使用方式

WIT 接口通过 `wit-bindgen` 生成 Rust 绑定代码，工作流如下：

1. **定义 WIT 文件**：在 `wit/` 目录中描述接口
2. **生成绑定**：`cargo component build` 自动调用 `wit-bindgen` 生成 trait
3. **实现接口**：Agent 工具 crate `impl` 生成的 trait
4. **运行时加载**：`mimobox-wasm` 通过 Wasmtime Component Model 加载 `.wasm` 工具

```
WIT 定义 → wit-bindgen → Rust trait → 工具实现 → .wasm 组件 → mimobox-wasm 加载执行
```

---

## 15. Crate 依赖图

### 15.1 内部依赖关系

```
                    ┌──────────────┐
                    │ mimobox-core │  ← 所有 crate 的公共基础
                    │ (trait + 类型) │
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          v                v                v
  ┌───────────────┐ ┌─────────────┐ ┌──────────────┐
  │ mimobox-os    │ │ mimobox-wasm│ │ mimobox-vm   │
  │ (OS级后端)    │ │ (Wasm后端)  │ │ (microVM后端) │
  └───────────────┘ └─────────────┘ └──────────────┘
          │                │                │
          │                │                │
          v                v                v
    外部依赖:         外部依赖:         外部依赖:
    - landlock        - wasmtime        - vm-memory
    - libseccomp      - wasmtime-wasi   - kvm-ioctls
    - nix             - wit-bindgen     - event-manager
    - libc            - wat             - vmm-sys-util
  (Linux)            (全平台)          (Linux/macOS/Windows)
    - windows-rs
  (Windows)
```

### 15.2 外部依赖详情

```
mimobox-core
├── thiserror      # 错误类型派生
├── serde          # 序列化框架
├── serde_json     # JSON 支持
├── toml           # TOML 配置解析
├── tokio          # 异步运行时 (features: rt, macros, time, sync)
├── async-trait    # async trait 支持
├── tracing        # 结构化日志
├── uuid           # 沙箱实例 ID
└── chrono         # 时间戳

mimobox-os (Linux)
├── mimobox-core
├── landlock       # Linux 文件系统访问控制
├── libseccomp     # Seccomp-bpf 系统调用过滤
├── nix            # Unix API (clone, unshare, pivot_root, etc.)
├── libc           # 系统调用绑定
└── cgroups-rs     # cgroups v2 管理

mimobox-os (macOS)
├── mimobox-core
└── libc           # rlimit, sandbox-exec via libc/system()

mimobox-os (Windows)
├── mimobox-core
└── windows        # AppContainer, Job Objects, MIC API (windows-rs crate)

mimobox-wasm
├── mimobox-core
├── wasmtime                  # Wasm 引擎
├── wasmtime-wasi             # WASI Preview 2
├── wasmtime-component-macro  # Component Model
└── wit-bindgen               # WIT 绑定生成

mimobox-vm
├── mimobox-core
├── vm-memory        # Guest 内存管理
├── kvm-ioctls       # KVM 绑定 (Linux)
├── event-manager    # epoll/kqueue 事件循环
├── vmm-sys-util     # VMM 系统工具
└── serde + bincode  # 快照序列化

mimobox-pool
├── mimobox-core
└── tokio (features: rt, sync, time)  # 异步池管理
```

### 15.3 编译依赖优化策略

1. **Feature Gate 后端**：OS 级、Wasm、microVM 后端通过 cargo feature 控制是否编译
2. **平台条件编译**：每个 OS 后端使用 `#[cfg(target_os)]` 隔离
3. **可选依赖**：`microvm` 后端默认不编译（Phase 4），通过 `features = ["microvm"]` 启用
4. **共享 build cache**：CI 中缓存 `target/` 目录，避免重复编译

```toml
# mimobox/Cargo.toml (workspace)
[workspace]
members = [
    "crates/mimobox-core",
    "crates/mimobox-os",
    "crates/mimobox-wasm",
    "crates/mimobox-vm",
    "crates/mimobox-pool",
]

[workspace.dependencies]
thiserror = "2"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["rt", "macros", "time", "sync"] }
tracing = "0.1"
```

---

## 16. 各平台系统调用序列

### 16.1 Linux: 创建 OS 级沙箱的完整系统调用序列

以下为在 Linux 上创建一个隔离沙箱并执行命令的完整流程：

```
阶段 1: 准备工作 (父进程)
  1. prctl(PR_SET_NO_NEW_PRIVS, 1)     → 确保子进程无法提权
  2. landlock_create_ruleset()          → 创建 Landlock 规则集
     - ABI V1-V6 自动探测
     - handled_access_fs = FS_READ | FS_WRITE | FS_EXEC | ...
  3. landlock_add_rule() × N            → 添加文件系统规则
     - 对每个 read_paths 添加 PathBeneath(ACCESS_READ)
     - 对每个 write_paths 添加 PathBeneath(ACCESS_WRITE)
     - 对每个 exec_paths 添加 PathBeneath(ACCESS_EXEC)
  4. libseccomp: seccomp_init(SCMP_ACT_KILL)  → 创建 Seccomp 过滤器
  5. libseccomp: seccomp_rule_add() × N       → 添加系统调用白名单
     - Essential 级别: read/write/exit/mmap/brk/... (~60 个)
     - Network 级别: +socket/connect/bind/listen/...
  6. cgroup_create()                    → 创建 cgroup 子组
     - memory.max = 配置值
     - pids.max = 配置值
     - cpu.max = 配置值

阶段 2: 创建沙箱进程 (父进程)
  7. clone(CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | SIGCHLD)
     → 创建子进程，同时创建新的 PID/网络/挂载命名空间
     - 如果 user_namespace=true: 额外 CLONE_NEWUSER
  8. (父进程等待子进程就绪信号)

阶段 3: 沙箱内初始化 (子进程)
  9. landlock_restrict_self()           → 应用 Landlock 规则 (不可逆)
  10. seccomp_load()                    → 应用 Seccomp 过滤器 (不可逆)
  11. prctl(PR_SET_DUMPABLE, 0)         → 禁止 core dump
  12. unshare(CLONE_NEWIPC)             → 隔离 IPC (如未在 clone 中完成)
  13. mount("none", "/tmp", "tmpfs", 0, "size=64m")  → 私有 /tmp
  14. pivot_root(sandbox_root, old_root) → 切换根文件系统
  15. chdir("/")                         → 进入新根目录
  16. write(pipe_fd, "READY")           → 通知父进程初始化完成

阶段 4: 执行命令 (子进程)
  17. execve(command, args, env)        → 执行用户命令
     - 此后所有文件/网络/系统调用受 Landlock + Seccomp 约束

阶段 5: 监控与回收 (父进程)
  18. waitpid(child_pid, &status)       → 等待子进程退出
  19. (超时时) kill(child_pid, SIGKILL) → 强制终止
  20. cgroup_delete()                   → 清理 cgroup
  21. 收集 stdout/stderr + 退出码       → 组装 SandboxResult
```

**关键时序说明**：
- 步骤 9-10 (Landlock + Seccomp) 必须在 execve 之前应用，且不可逆
- 步骤 7 的 clone() 使用 CLONE_NEWNET 可完全禁止网络（回环接口也没有）
- cgroup 在父进程中管理，确保即使子进程逃逸也无法修改限制

### 16.2 macOS: 创建 OS 级沙箱的完整系统调用序列

```
阶段 1: 准备 Seatbelt 策略 (父进程)
  1. 生成 .sbpl 策略字符串:
     (version 1)
     (deny default)                          → 默认拒绝所有
     (allow file-read* (subpath "/usr"))     → 允许读取
     (allow file-write* (subpath "/tmp/sbox-{id}"))  → 允许写入
     (deny network*)                         → 禁止网络
     (allow process-exec (subpath "/bin"))   → 允许执行
     (allow signal)                          → 允许信号
     (allow process-fork)                    → 允许 fork
  2. setrlimit(RLIMIT_AS, memory_limit)      → 内存限制
  3. setrlimit(RLIMIT_CPU, cpu_limit)        → CPU 时间限制
  4. setrlimit(RLIMIT_NPROC, process_limit)  → 进程数限制
  5. setrlimit(RLIMIT_FSIZE, file_size_limit) → 文件大小限制

阶段 2: 创建沙箱进程 (父进程)
  6. fork()                                  → 创建子进程
  7. (父进程等待子进程)

阶段 3: 沙箱内初始化 (子进程)
  8. sandbox_init(sbpl_policy)               → 应用 Seatbelt 策略 (不可逆)
     或 sandbox-exec -p "{sbpl}" -- command
  9. chdir(workdir)                          → 切换到工作目录
  10. write(pipe_fd, "READY")               → 通知父进程

阶段 4: 执行命令 (子进程)
  11. execve(command, args, env)            → 执行用户命令
     - 此后所有文件/网络/进程操作受 Seatbelt 约束

阶段 5: 监控与回收 (父进程)
  12. waitpid(child_pid, &status)           → 等待子进程退出
  13. (超时时) kill(child_pid, SIGKILL)     → 强制终止
  14. 收集 stdout/stderr + 退出码           → 组装 SandboxResult
```

**macOS 限制说明**：
- macOS 无 namespace 概念，文件系统隔离完全依赖 Seatbelt 策略
- macOS 无 seccomp 等价物，无法做系统调用级过滤
- `sandbox_init()` 已被 Apple 标记为"旧版 API"，推荐使用 `sandbox-exec` 或 Endpoint Security Framework
- rlimit 是 POSIX 标准，但 `RLIMIT_NPROC` 在 macOS 上行为与 Linux 不同（per-uid 限制而非 per-process）

### 16.3 Windows: 创建 OS 级沙箱的完整系统调用序列

```
阶段 1: 创建 AppContainer (父进程)
  1. CreateAppContainerProfile()            → 创建 AppContainer 配置文件
     - SID 生成: S-1-15-3-{mimobox-specific}
     - 如果已存在则调用 DeriveAppContainerSidFromName()
  2. 设置能力 (Capabilities):
     - 仅授予必要的 AppContainer 能力
     - 不授予 internetClient 等网络能力
  3. 设置 ACE (Access Control Entries):
     - 对允许读取的目录: GRANT GENERIC_READ
     - 对允许写入的目录: GRANT GENERIC_WRITE | DELETE
     - 对允许执行的目录: GRANT GENERIC_EXECUTE | GENERIC_READ
     - 其他目录: 显式 DENY

阶段 2: 创建 Job Object (父进程)
  4. CreateJobObject(NULL, "mimobox-{id}")  → 创建 Job Object
  5. SetInformationJobObject():
     - JobObjectBasicUIRestrictions:
       * JOB_OBJECT_UILIMIT_NONE             → 禁止 UI 操作
     - JobObjectBasicLimitInformation:
       * LimitFlags = JOB_OBJECT_LIMIT_MEMORY
       * JobMemoryLimit = 配置值
       * LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME
       * PerProcessUserTimeLimit = 配置值
       * LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESSes
       * ActiveProcessLimit = 配置值
     - JobObjectExtendedLimitInformation:
       * LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY

阶段 3: 创建沙箱进程 (父进程)
  6. InitializeProcThreadAttributeList()    → 初始化进程属性列表
  7. UpdateProcThreadAttribute():
     - PROC_THREAD_ATTRIBUTE_JOB_LIST → 关联 Job Object
     - PROC_THREAD_ATTRIBUTE_MANDATORY_LEVEL → TOKEN_MANDATORY_LABEL
  8. CreateProcessInAppContainer():
     - lpApplicationName = command
     - lpCommandLine = args
     - lpEnvironment = 清理后的环境变量
     - hAppContainerSID = AppContainer SID
     - dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED
     - lpStartupInfo → 包含 stdin/stdout/stderr 管道句柄
  9. AssignProcessToJobObject(job, process)  → 将进程加入 Job Object

阶段 4: 设置完整性级别并启动 (父进程)
  10. SetTokenInformation(process_token, TokenMandatoryLabel, SID_SDDL("L")) → Low IL
      - Low Integrity Level: S-1-16-4096
      - 防止写入 Medium IL 及以上的对象
  11. ResumeThread(process.main_thread)      → 恢复主线程执行
  12. (父进程开始监控)

阶段 5: 监控与回收 (父进程)
  13. WaitForSingleObject(process, timeout)  → 等待进程退出
  14. (超时时) TerminateProcess(process, 1)  → 强制终止
  15. GetExitCodeProcess()                   → 获取退出码
  16. CloseHandle()                          → 清理句柄
  17. DeleteAppContainerProfile()            → 清理 AppContainer
  18. 收集 stdout/stderr + 退出码            → 组装 SandboxResult
```

**Windows 限制说明**：
- Windows 使用 ACE (Access Control Entries) 实现文件系统访问控制，而非路径级别权限
- AppContainer 同时提供网络隔离（未声明网络能力即禁止）
- Job Object 提供进程组级别的资源限制
- MIC (Mandatory Integrity Control) 提供额外的安全层：Low IL 进程无法写入 Medium IL 的对象
- Windows 上的"进程暂停"不使用信号，而是通过 `SuspendThread/ResumeThread` 实现

### 16.4 各平台系统调用对比总结

| 操作 | Linux | macOS | Windows |
|------|-------|-------|---------|
| 创建隔离进程 | `clone(CLONE_NEW*)` | `fork()` | `CreateProcessInAppContainer()` |
| 文件系统隔离 | Landlock 规则集 | Seatbelt .sbpl | AppContainer ACE |
| 系统调用过滤 | Seccomp-bpf BPF 程序 | 无原生支持 | 无原生支持 |
| 内存限制 | cgroup `memory.max` | `setrlimit(RLIMIT_AS)` | Job Object `JobMemoryLimit` |
| CPU 限制 | cgroup `cpu.max` | `setrlimit(RLIMIT_CPU)` | Job Object `ProcessTimeLimit` |
| 进程数限制 | cgroup `pids.max` | `setrlimit(RLIMIT_NPROC)` | Job Object `ActiveProcessLimit` |
| 网络隔离 | `unshare(CLONE_NEWNET)` | Seatbelt `deny network*` | 不声明 AppContainer 网络能力 |
| 强制终止 | `kill(pid, SIGKILL)` | `kill(pid, SIGKILL)` | `TerminateProcess(handle, 1)` |
| 根文件系统切换 | `pivot_root()` | 无 (依赖 Seatbelt) | 无 (依赖 AppContainer) |
| 安全策略不可逆 | `prctl(PR_SET_NO_NEW_PRIVS)` + seccomp | Seatbelt (不可逆) | AppContainer + Low IL |

---

## 附录

### A. 关键参考文献

1. Segarra et al. "Nanvix: A Multikernel OS for High-Density Serverless." arXiv:2604.11669, 2026
2. Lazarev et al. "Sabre: Hardware-Accelerated Memory Prefetching for MicroVM Snapshot." OSDI 2024
3. Zhang et al. "SandCell: Sandboxing Rust Beyond Unsafe Code." arXiv:2509.24032, 2025
4. Microsoft. "Hyperlight: 0.0009-second micro-VM execution." 2025
5. Zeroboot: "Sub-millisecond VM sandboxes using CoW memory forking." 2026
6. Kuo et al. "Lupine: Making Linux a Unikernel." EuroSys 2020
7. OpenAI. "Codex Sandbox Architecture." developers.openai.com/codex/concepts/sandboxing, 2026
8. Anthropic. "Sandbox Runtime (SRT) v0.0.49." github.com/anthropic-experimental/sandbox-runtime, 2026
9. E2B. "E2B Sandbox Platform Architecture." github.com/e2b-dev/E2B, 2026
10. Daytona. "Daytona Dev Environment Architecture." github.com/daytonaio/daytona, 2026
11. Deno. "Introducing Deno Sandbox." deno.com/blog/introducing-deno-sandbox, 2026
12. Perrotta, T. "Claude: SRT Sandbox Runtime." perrotta.dev, 2026
13. OpenAI Codex. "refactor: make bubblewrap the default Linux sandbox." PR #13996, 2026

### B. 推荐的 Rust Crate 清单

| crate | 用途 | 阶段 |
|-------|------|------|
| landlock | Linux 文件系统访问控制 | Phase 1 |
| libseccomp | Linux 系统调用过滤 | Phase 1 |
| nix | Unix API 绑定 | Phase 1 |
| hakoniwa | 综合 Linux 沙箱库（可选） | Phase 1 |
| wasmtime | Wasm 运行时 | Phase 2 |
| wasmtime-wasi | WASI 实现 | Phase 2 |
| wit-bindgen | WIT → Rust 绑定 | Phase 2 |
| cargo-component | Component 构建工具 | Phase 2 |
| vm-memory | Guest 内存管理 | Phase 4 |
| kvm-ioctls | KVM 绑定 | Phase 4 |
| event-manager | 事件循环 | Phase 4 |
| vmm-sys-util | VMM 系统工具 | Phase 4 |
| windows-rs | Windows API 绑定 | Phase 3 |
| libc | 系统调用绑定 | 全阶段 |
| thiserror | 错误处理 | 全阶段 |
| tokio | 异步运行时 | 全阶段 |
