# gVisor/runsc 深度技术分析

## 1. 项目概览

gVisor 是 Google 开源的应用级内核（Application Kernel），以用户态进程的形式实现了约 70% 的 Linux 系统调用接口，为容器化应用提供了一层额外的安全隔离。其核心可执行文件 `runsc`（run sandbox container）兼容 OCI 运行时规范，可直接与 Docker 和 Kubernetes 集成。

**核心设计哲学**：gVisor 不是一个系统调用过滤器（如 seccomp-bpf），也不是对 Linux 隔离原语的封装（如 firejail），而是一个**完整的用户态内核**，在应用与宿主内核之间建立一个独立的内核抽象层。

**关键数据**：
- 语言：Go（核心），C/汇编（平台相关代码）
- 许可证：Apache 2.0
- 支持架构：x86_64 (AMD64)、ARM64
- 仅支持 Linux 宿主操作系统
- 生产使用：Google 内部大规模部署（GKE Sandbox、Google App Engine 等）
- DigitalOcean App Platform 也基于 gVisor 运行用户应用

## 2. 整体架构设计

gVisor 的架构采用**纵深防御（Defense-in-Depth）**策略，核心组件之间遵循**最小权限原则**。

```
┌──────────────────────────────────────────────┐
│              容器化应用程序                      │
│         (应用进程，受限地址空间内运行)             │
└──────────────┬───────────────────────────────┘
               │ 系统调用 (被 Platform 拦截)
               ▼
┌──────────────────────────────────────────────┐
│              Sentry (应用内核)                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ 系统调用  │ │ 内存管理 │ │ 网络栈   │      │
│  │ 实现     │ │ (MM)     │ │(Netstack)│      │
│  └──────────┘ └──────────┘ └──────────┘      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ VFS      │ │ 调度器   │ │ 信号处理  │      │
│  │(虚拟文件  │ │          │ │          │      │
│  │ 系统)    │ │          │ │          │      │
│  └──────────┘ └──────────┘ └──────────┘      │
└──────┬───────────────┬───────────────────────┘
       │               │
       │ 9P 协议       │ 受限的宿主系统调用
       ▼               ▼
┌──────────────┐ ┌─────────────────────────────┐
│   Gofer      │ │      Linux 宿主内核          │
│ (文件系统    │ │                              │
│  代理进程)   │ │                              │
└──────────────┘ └─────────────────────────────┘
```

**安全边界的关键设计**：

1. **Sentry 自身运行在严格的 seccomp 沙箱中**，限制了 Sentry 可以对宿主内核发起的系统调用
2. **应用进程永远无法直接与宿主内核交互**——所有系统调用都被拦截
3. **Gofer 是独立的宿主进程**，负责文件系统 I/O，通过 9P 协议与 Sentry 通信
4. 每个组件仅拥有完成其职责所需的最小权限

## 3. 核心组件分析

### 3.1 Sentry — 应用内核

Sentry 是 gVisor 的心脏，在用户态实现了完整的操作系统内核功能。

**代码位置**：`pkg/sentry/`

**核心职责**：
- 系统调用实现（`pkg/sentry/syscalls/linux/`）
- 虚拟文件系统（`pkg/sentry/vfs/`、`pkg/sentry/fsimpl/`）
- 内存管理（`pkg/sentry/mm/`、`pkg/sentry/pgalloc/`）
- 网络栈（`pkg/tcpip/`）
- 进程/线程管理（`pkg/sentry/kernel/task.go`）
- 信号处理、futex、IPC 等

**系统调用实现架构**：

系统调用通过 `SyscallTable` 进行分发，这是一个固定大小的数组，以系统调用号为索引，实现 O(1) 查找：

```go
// SyscallFn 是系统调用实现的函数签名
type SyscallFn func(t *Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *SyscallControl, error)

// SyscallTable 核心数据结构
type SyscallTable struct {
    OS            abi.OS
    Arch          arch.Arch
    Table         map[uintptr]Syscall
    lookup        [sentry.MaxSyscallNum + 1]SyscallFn  // 快速查找数组
    pointCallbacks [sentry.MaxSyscallNum + 1]SyscallToProto
    Missing       MissingFn
    Stracer       Stracer
    FeatureEnable SyscallFlagsTable
}
```

系统调用处理流程分为四条路径：

| 路径 | 描述 | 性能影响 |
|------|------|----------|
| **vDSO 短路** | 少数系统调用（如 `gettimeofday`）通过 vDSO 直接在用户空间完成 | 接近原生 |
| **Sentry 内部处理** | 大多数系统调用在 Sentry 内部完成（如 `clone`、`mmap`、`futex`） | 中等 |
| **宿主内核参与** | 资源相关操作，Sentry 发起自己的受控宿主系统调用 | 较高 |
| **Gofer 参与** | 文件 I/O 通过 9P 协议与 Gofer 进程通信 | 最高 |

**文件系统实现**（`pkg/sentry/fsimpl/`）支持丰富的文件系统类型：
- `tmpfs`：内存文件系统
- `gofer`：通过 Gofer 代理访问宿主文件系统
- `overlay`：覆盖文件系统
- `proc`：procfs 实现
- `sys`：sysfs 实现
- `devpts`、`devtmpfs`：设备文件系统
- `erofs`：只读文件系统
- `fuse`：FUSE 文件系统支持

### 3.2 Gofer — 文件系统代理

**代码位置**：`runsc/fsgofer/`

Gofer 是一个标准的宿主进程，运行在 Sentry 沙箱外部，负责为容器提供文件系统访问。

**工作机制**：
1. Sentry 被严格的 seccomp 过滤器限制，无法直接打开文件
2. 所有文件系统操作通过 9P 协议（或优化后的 lisafs 协议）经 socket/共享内存通道发送给 Gofer
3. Gofer 独立验证请求后，代表容器执行文件操作
4. 结果通过相同通道返回给 Sentry

**Directfs 优化**（2023 年引入）：

传统模式下所有文件操作都经过 Gofer 转发，引入大量 RPC 开销。Directfs 允许 Sentry 直接利用 Linux 已有的文件系统隔离机制（namespace、mount namespace），在安全的前提下直接操作文件描述符，绕过 Gofer 的 RPC 往返。

实测效果：
- `stat(2)` 系统调用性能提升 2 倍以上
- Ruby 负载时间减少 17%
- 整体工作负载绝对时间减少 12%

### 3.3 Platform — 系统调用拦截平台

Platform 是 gVisor 的底层抽象，负责系统调用拦截、上下文切换和内存映射。

**代码位置**：`pkg/sentry/platform/`

**Platform 接口定义**（核心方法）：

```go
type Platform interface {
    SupportsAddressSpaceIO() bool
    DetectsCPUPreemption() bool
    MapUnit() uint64
    MinUserAddress() hostarch.Addr
    MaxUserAddress() hostarch.Addr
    NewAddressSpace() (AddressSpace, error)
    NewContext(context.Context) Context
    // ...
}

type Context interface {
    Switch(ctx context.Context, mm MemoryManager, ac *arch.Context64, cpu int32) (*linux.SignalInfo, hostarch.AccessType, error)
    Interrupt()
    Release()
    // ...
}
```

**当前支持的平台**：

#### 3.3.1 Systrap（默认平台，2023 年 4 月发布）

**代码位置**：`pkg/sentry/platform/systrap/`

Systrap 是当前 gVisor 的默认平台，专为在虚拟化环境中运行而优化。

**核心机制**：
1. 使用 `seccomp` 的 `SECCOMP_RET_TRAP` 功能拦截系统调用
2. 内核向触发线程发送 `SIGSYS` 信号
3. 自定义信号处理器接管控制权，切换到 Sentry
4. 通过共享内存区域在用户线程和 Sentry 之间传递数据

**x86_64 上的关键优化 — 系统调用指令热替换**：
- 在运行时扫描 `mov sysno, %eax; syscall` 指令模式
- 动态替换为 `jmp` 跳转到 trampoline 代码
- 完全绕过信号机制，大幅降低系统调用延迟
- 该优化需要 7 字节连续空间，因此对 `mov eax; syscall` 的指令顺序有要求

**ARM64 实现**：
- 使用通用寄存器存储系统调用结果
- 在较新的 ARMv8.4+ 处理器（如 AWS c7gd 的 Neoverse V1）上曾有兼容性问题

**性能数据**（getpid 微基准测试）：
- 相比 ptrace 平台，systrap 的 getpid 循环快数倍
- 在 ABSL 编译基准测试中，整体运行时间显著缩短

#### 3.3.2 KVM 平台

**代码位置**：`pkg/sentry/platform/kvm/`

利用 Linux 内核的 KVM 功能，让 Sentry 同时充当客户操作系统和 VMM。

**特点**：
- 最佳的裸金属性能
- 利用硬件虚拟化扩展实现地址空间隔离
- 系统调用拦截方式类似真正的虚拟机
- 在嵌套虚拟化环境中性能不如 systrap

#### 3.3.3 Ptrace 平台（已弃用）

**代码位置**：`pkg/sentry/platform/ptrace/`

使用 `PTRACE_SYSEMU` 拦截系统调用。

- 通用性最好（几乎所有 Linux 都支持）
- 上下文切换开销极高
- 2023 年中起被 systrap 取代为默认平台
- 目前已不再维护，计划移除

### 3.4 Netstack — 用户态网络栈

**代码位置**：`pkg/tcpip/`

gVisor 实现了完整的用户态 TCP/IP 协议栈（Netstack），这是其安全架构的重要组成部分。

**实现范围**：
- 完整的 IPv4/IPv6 支持
- TCP（含 Reno、CUBIC 拥塞控制、SACK、RACK 等）
- UDP、ICMP
- ARP、NDP（邻居发现协议）
- Netfilter/iptables/nftables 防火墙
- 各种链路层端点（veth、tun、xdp、sharedmem 等）
- 套接字 API（Unix domain socket、TCP、UDP、raw socket 等）

**网络 Passthrough 模式**：
对于高性能网络应用，gVisor 允许禁用用户态网络栈，直接使用宿主网络栈。但这会降低隔离性。

## 4. 系统调用拦截机制

系统调用拦截是 gVisor 安全模型的基石。其核心思想是：**被沙箱化的应用进程永远无法直接与宿主 Linux 内核交互**。

### 4.1 完整拦截流程

```
应用进程发出 syscall
        │
        ▼
   Platform 拦截
   (systrap: SECCOMP_RET_TRAP → SIGSYS → 信号处理器)
   (KVM: VM Exit → Sentry 作为 VMM 接管)
        │
        ▼
   Sentry 接收系统调用号和参数
        │
        ├── vDSO 查找 → 直接在用户空间完成
        │
        ├── SyscallTable.lookup[sysno] → Sentry 内部实现
        │   ├── 纯内部操作 (clone, mmap, futex...)
        │   ├── 需要宿主协助 (受控 syscall)
        │   └── 需要 Gofer (文件 I/O → 9P 协议)
        │
        └── 未实现 → 返回 ENOSYS
        │
        ▼
   结果写回应用进程寄存器
   Platform 恢复应用执行
```

### 4.2 Systrap 拦截机制详解

Systrap 的拦截机制是其性能优势的关键：

**阶段 1：初始化**
1. 通过 ptrace 创建 stub 子进程来管理工作线程的地址空间
2. 安装极其严格的 seccomp-bpf 过滤器
3. 分配 Sentry 与 stub 进程之间的共享内存区域
4. 注册自定义信号处理器

**阶段 2：运行时拦截（常规路径）**
1. 应用执行 `syscall` 指令
2. seccomp 规则返回 `SECCOMP_RET_TRAP`
3. 内核向线程发送 `SIGSYS` 信号
4. 自定义信号处理器被触发
5. 信号处理器将系统调用号和参数写入共享内存
6. 切换到 Sentry 执行

**阶段 3：运行时拦截（优化路径，仅 x86_64）**
1. Sentry 扫描应用代码，找到 `mov eax, sysno; syscall` 模式
2. 动态将 `syscall` 替换为 `jmp` 跳转到 trampoline
3. Trampoline 直接将控制权交给 Sentry，无需信号
4. 消除了信号传递的开销

**阶段 4：Sentry 处理完成后**
1. Sentry 将返回值写入共享内存
2. 使用 futex wake 或轮询模式通知 stub 线程
3. Stub 线程恢复应用执行

### 4.3 Seccomp-bpf 多层防护

gVisor 自身也使用 seccomp-bpf 进行自我防护：

1. **Sentry 的 seccomp 过滤器**：限制 Sentry 自身可以发起的宿主系统调用，形成第二道防线
2. **Gofer 的 seccomp 过滤器**：限制 Gofer 进程的权限
3. seccomp 规则采用预编译（precompiled seccomp）优化启动时间
4. 通过 `HottestSyscalls()` 接口优化 BPF 程序的分支顺序，将高频系统调用放在前面

## 5. 性能特征与开销

### 5.1 性能开销来源

gVisor 的性能开销主要来自两方面：

**结构性开销（无法消除）**：
- 系统调用拦截本身的开销（上下文切换、数据拷贝）
- 用户态网络栈 vs 宿主内核网络栈
- 文件 I/O 的 Gofer RPC 往返
- Sentry 自身的内存占用

**实现性开销（持续优化中）**：
- Sentry 内部实现效率
- seccomp-bpf 过滤器开销
- Go 运行时开销（GC、goroutine 调度等）

### 5.2 关键性能数据

**容器启动时间对比**：

| 运行时 | 启动时间 |
|--------|----------|
| runc | ~0.5s |
| gVisor/runsc | ~1-2s |
| Kata Containers | ~2-5s |

**系统调用开销**（来自 Go Performance Dashboard）：

| 基准 | 性能 |
|------|------|
| GVisorSyscall | 4.06μs/op |
| GVisorHTTPStartup | 173ms |
| GVisorHTTP | 792μs/op |

**Systrap vs Ptrace 性能对比**：
- getpid 微基准：systrap 比 ptrace 快数倍
- ABSL 编译工作负载：整体运行时间显著减少
- WordPress 应用：从 systrap + directfs 优化后，吞吐量提升 7 倍以上（DigitalOcean 实测）
- Node.js 应用：吞吐量提升 2 倍以上

**DigitalOcean 生产环境数据**（从 ptrace 迁移到 systrup）：
- 基础 Node.js 应用吞吐量提升 2 倍以上
- WordPress 应用（文件操作密集型）吞吐量提升 7 倍以上

**Seccomp-bpf 优化影响**：
- seccomp-bpf 仅占 gVisor 总开销的一小部分
- 在 ABSL 编译基准中，优化 seccomp 可减少约 3.6% 的总运行时间
- 但相对于 gVisor 相对原生运行的总开销，这只是一小部分

### 5.3 性能优化策略演进

| 时间 | 优化 | 效果 |
|------|------|------|
| 2023.04 | RootFS Overlay | fsstress 从 262s 降至 3.18s |
| 2023.04 | Systrap 平台 | 全面优于 ptrace |
| 2023.06 | Directfs | stat 系统调用 2x+ 提升 |
| 2024.02 | Seccomp 优化 | 高频 syscall 路径优化 |
| 2024+ | 持续改进 | 网络栈、内存管理优化 |

### 5.4 工作负载适应性

| 工作负载类型 | 性能影响 | 建议 |
|-------------|---------|------|
| CPU 密集型（编译、数据管道） | 极小（<5%） | 非常适合 |
| API 服务器、Web 服务器 | 较小（5-15%） | 适合 |
| I/O 密集型（数据库） | 较大（20-50%） | 需评估 |
| 网络密集型（负载均衡） | 较大（20-50%） | 需评估 |
| 文件密集型（PHP 应用） | 历史较大，directfs 后显著改善 | 可行 |

## 6. 跨平台能力评估

### 6.1 当前支持状况

| 维度 | 支持情况 |
|------|---------|
| **宿主 OS** | 仅 Linux |
| **CPU 架构** | x86_64 (AMD64)、ARM64 |
| **虚拟化环境** | 原生支持（systrap 专为 VM 环境优化） |
| **Kubernetes** | 完整支持（通过 GKE Sandbox 或手动配置） |
| **Docker** | 完整支持 |
| **Windows/macOS** | 不支持 |

### 6.2 跨平台限制分析

gVisor 的平台依赖性较强，主要限制来自：

1. **Platform 层**：systrap 依赖 Linux 的 seccomp-bpf 和信号机制；KVM 依赖 Linux KVM 子系统。这些都是 Linux 特有的。
2. **Seccomp 自防护**：gVisor 使用 seccomp-bpf 限制自身行为，这是 Linux 特有功能。
3. **Ptrace 初始化**：即 systrap 也需要 ptrace 来初始化 stub 进程。
4. **Netstack 链路层**：使用 Linux 特有的 tuntap、veth、XDP 等接口。

### 6.3 不可移植的设计决策

以下设计决策严重依赖 Linux 内核特性，是跨平台移植的主要障碍：

- `SECCOMP_RET_TRAP` / `SECCOMP_RET_USER_NOTIF`
- `PTRACE_SYSEMU` / `PTRACE_SEIZE`
- `/dev/kvm` KVM API
- `memfd_create`、`process_vm_readv`
- `signalfd`、`eventfd`、`timerfd`
- `membarrier()` 系统调用

## 7. Rust 重写可行性分析

### 7.1 为什么考虑 Rust

用 Rust 重写 gVisor 核心思路的动机：

1. **内存安全**：gVisor 核心是约 300 万行 Go 代码实现的内核，内存安全漏洞是沙箱逃逸的主要途径。Rust 的所有权模型可以在编译时消除此类风险。
2. **性能**：Rust 无 GC，可以更精确地控制内存布局和分配，减少 Go 运行时带来的开销。
3. **系统编程友好**：Rust 对底层硬件操作（内联汇编、内存映射、寄存器操作）的支持比 Go 更自然。
4. **Youki 的验证**：Youki 项目已证明 Rust 可以作为容器运行时的实现语言，并通过了 containerd 的端到端测试，已成为 CNCF 沙箱项目。

### 7.2 技术路径

#### 阶段 1：系统调用接口层

- 使用 Rust 定义 Linux 系统调用 ABI（参考 `pkg/abi/linux/`）
- 定义系统调用号、参数结构、错误码
- 利用 Rust 的 `repr(C)` 和 `repr(transparent)` 确保 ABI 兼容
- 已有参考：`nix` crate、`linux-raw-sys` crate

#### 阶段 2：Platform 抽象层

- 实现与 systrap 等价的系统调用拦截机制
- seccomp-bpf 过滤器生成（参考 `libseccomp` Rust 绑定或 youki 的独立 seccomp 实现）
- 共享内存通信机制
- 信号处理器注册（需要 `sigaction` 等 FFI）
- Trampoline 代码注入（需要内联汇编或 `std::arch`）

**核心挑战**：
- Rust 的信号安全性（signal safety）：信号处理器中只能调用异步信号安全函数
- 内联汇编对 `syscall` 指令的替换需要精确控制指令编码
- 平台相关的上下文切换代码需要大量 unsafe Rust

#### 阶段 3：Sentry 核心内核

- **内存管理**：Rust 的所有权模型天然适合实现虚拟内存管理
  - `VMA`（虚拟内存区域）用 Rust 生命周期管理
  - 页面分配器可基于 `buddy allocator` 模式
  - 内存映射利用 `mmap` 的 Rust 封装

- **文件系统 VFS**：
  - 使用 Rust trait 实现 VFS 接口抽象
  - tmpfs、gofer、overlay 等文件系统作为 trait 实现
  - 利用 Rust 的 enum + pattern matching 实现 inode 类型分发

- **网络栈**：
  - 参考 `smoltcp` 或 `netstack3`（Fuchsia 的 Rust 网络栈）
  - 使用 Rust 的 `async/await` 实现异步 I/O
  - TCP 状态机用 enum 表达，编译器保证完备性

- **进程/线程管理**：
  - 进程层次结构用 arena 分配（`bumpalo` 或自定义）
  - 文件描述符表用 `slab` 或 `slotmap`
  - 信号处理用通道（channel）模式

#### 阶段 4：Gofer 代理

- 实现简化的 Gofer（文件系统代理）
- 9P 协议或自定义 RPC 协议
- 使用 `tokio` 或 `glommio` 异步运行时

### 7.3 Rust 生态中可复用的组件

| 组件 | Rust 生态选项 |
|------|-------------|
| 容器运行时框架 | youki/libcontainer |
| OCI 规范 | oci-spec-rs |
| seccomp | youki 的独立 Rust seccomp 实现 |
| 网络栈 | smoltcp、netstack3-rs |
| 文件系统 | fuse-rs、vfs crate |
| 异步运行时 | tokio、glommio |
| 序列化 | protobuf (rust-protobuf)、cap'n proto |
| ELF 加载 | object crate、goblin |
| Linux syscall 绑定 | nix、linux-raw-sys |

### 7.4 Rust 重写的风险与挑战

**高风险项**：
1. **工程量巨大**：gVisor 核心代码超过 300 万行，完全重写需要数年
2. **系统调用兼容性**：需实现数百个 Linux 系统调用，兼容性测试至关重要
3. **Platform 层的 inline asm**：systrap 的 trampoline 注入需要大量平台相关的汇编代码
4. **信号安全性**：Rust 标准库不是异步信号安全的，信号处理器需要极小心地编写

**中风险项**：
1. **性能调优**：Go 的 goroutine 调度模型与 Rust 的 async/await 有本质区别，需要重新设计并发模型
2. **Netstack 复杂度**：完整 TCP/IP 栈实现量巨大
3. **社区和生态**：Go 在系统编程领域的工具链和库比 Rust 更成熟

**低风险项**：
1. VFS 抽象：Rust 的 trait 系统天然适合
2. 配置管理：使用 serde 生态
3. CLI 框架：clap 等 Rust CLI 库成熟

## 8. 可借鉴的设计模式

### 8.1 Platform 抽象接口

gVisor 的 Platform 接口设计非常优雅，值得借鉴：

- 将系统调用拦截机制抽象为可插拔的 Platform
- 通过 `Context.Switch()` 统一了不同拦截机制的控制流
- `AddressSpace` 接口统一了不同平台的内存管理
- 支持运行时选择最合适的 Platform

**对我们的启示**：在 mimobox 中，应当设计类似的 Platform trait，支持不同的系统调用拦截实现（如 seccomp、KVM、自定义拦截器），实现可插拔的隔离策略。

### 8.2 纵深防御架构

gVisor 的多层安全设计：
1. 应用进程 → 无法发出宿主 syscall
2. Sentry → 自身受限 seccomp 过滤
3. Gofer → 独立进程，最小权限
4. 宿主内核 → 标准 Linux 安全机制

**启示**：沙箱方案应采用多层防御，不依赖单一安全边界。

### 8.3 用户态内核的设计

Sentry 的设计展示了一个完整的用户态内核应具备的要素：
- 独立的内存管理（不依赖宿主内核的 malloc/free）
- 独立的文件系统（VFS 抽象 + 多种实现）
- 独立的网络栈（netstack）
- 独立的进程/线程管理
- 独立的信号处理

### 8.4 性能优化的渐进策略

gVisor 的性能优化策略值得学习：
- 先保证正确性和安全性，再逐步优化性能
- 从最大的性能瓶颈开始（ptrace → systrap → directfs → seccomp 优化）
- 使用微基准测试定位问题，但以真实工作负载验证效果
- 不追求所有场景的最佳性能，聚焦关键工作负载

### 8.5 OCI 兼容性

gVisor 通过 `runsc` 实现了 OCI 运行时规范，可以无缝替换 runc，这是其广泛采用的关键。任何沙箱方案都应优先考虑 OCI 兼容。

## 9. 结论与建议

### 9.1 核心结论

1. **gVisor 是最成熟的应用级内核方案**，经过 Google 多年生产验证，代码质量高，架构设计优秀。

2. **性能已大幅改善**：从早期的 ptrace 平台到现在的 systrap + directfs，性能差距已从"不可用"缩小到"可接受"（CPU 密集型工作负载几乎无开销）。

3. **跨平台是硬伤**：深度绑定 Linux 内核特性，无法移植到 Windows/macOS。如果需要跨平台沙箱，需考虑其他方案。

4. **Go 语言选择是双刃剑**：Go 的开发效率高，但 GC 和运行时开销是性能瓶颈的一部分。对于内核级代码，Rust/C 可能更合适。

5. **架构设计非常值得学习**：Platform 抽象、纵深防御、Gofer 代理模式、用户态网络栈等设计都是优秀的工程实践。

### 9.2 对 mimobox 的建议

1. **借鉴 Platform 抽象**：设计可插拔的拦截机制，支持多种隔离策略
2. **借鉴 Sentry 的模块化设计**：VFS、网络栈、内存管理等应独立可替换
3. **采用 Rust 实现**：利用 Rust 的内存安全保证和系统编程能力
4. **优先 OCI 兼容**：确保可以作为 runc 的替代品使用
5. **考虑最小化初始实现**：先实现核心系统调用子集，逐步扩展兼容性
6. **学习 systrap 的优化思路**：共享内存通信 + 信号处理器 + 指令热替换的组合拳

### 9.3 参考资料

- gVisor 官方文档：https://gvisor.dev/docs/
- Systrap 发布博客：https://gvisor.dev/blog/2023/04/28/systrap-release
- Directfs 优化博客：https://opensource.googleblog.com/2023/06/optimizing-gvisor-filesystems-with-directfs.html
- Seccomp 优化博客：https://gvisor.dev/blog/2024/02/01/seccomp
- Platform 可移植性：https://gvisor.dev/blog/2020/10/22/platform-portability
- gVisor GitHub：https://github.com/google/gvisor
- Youki 容器运行时（Rust）：https://github.com/youki-dev/youki
- DigitalOcean gVisor 性能实践：https://digitalocean.com/blog/introducing-new-runtime-performance-improvements-app-platform
