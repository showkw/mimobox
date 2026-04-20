# OS 级沙箱技术深度分析

## 1. 技术概述

操作系统级沙箱（OS-level Sandbox）是指利用操作系统内核提供的安全原语，在不引入虚拟机等重量级抽象的前提下，对进程的资源和行为进行细粒度限制的技术。与基于虚拟机的隔离方案（如 Firecracker microVM）相比，OS 级沙箱具有**启动快、开销低、密度高**的核心优势。

OS 级沙箱技术栈通常由以下几个层次组成：

```
┌─────────────────────────────────────────────┐
│           应用层沙箱策略                       │
├─────────────────────────────────────────────┤
│  系统调用过滤 (seccomp)  │  文件访问控制 (Landlock/MAC)  │
├─────────────────────────────────────────────┤
│  资源命名空间隔离 (namespaces / silos)         │
├─────────────────────────────────────────────┤
│  资源配额限制 (cgroups / Job Objects)          │
├─────────────────────────────────────────────┤
│  身份与权限控制 (user ns / AppContainer / MIC)  │
├─────────────────────────────────────────────┤
│            操作系统内核                        │
└─────────────────────────────────────────────┘
```

不同操作系统平台提供了各自独特的沙箱原语，但核心目标一致：**最小权限原则下的进程隔离**。

---

## 2. Linux 沙箱机制详解

Linux 拥有最丰富、最成熟的沙箱原语生态，是现代容器技术的基石。

### 2.1 seccomp-bpf：系统调用过滤

seccomp（Secure Computing Mode）是 Linux 内核提供的系统调用过滤机制，允许进程定义一个 BPF（Berkeley Packet Filter）程序来限制自身可以调用的系统调用集合。

**工作原理**：

1. 进程通过 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` 安装 BPF 过滤程序
2. 每次系统调用时，内核将 `seccomp_data` 结构体（包含架构、系统调用号、参数）传递给 BPF 程序
3. BPF 程序返回判定结果：`SECCOMP_RET_ALLOW`（允许）、`SECCOMP_RET_KILL`（终止）、`SECCOMP_RET_ERRNO`（返回错误）、`SECCOMP_RET_TRAP`（发送信号）或 `SECCOMP_RET_LOG`（记录）

**关键特性**：

- 过滤程序安装后**不可逆**，子进程自动继承
- 需先调用 `prctl(PR_SET_NO_NEW_PRIVS, 1)` 防止提权绕过
- BPF 程序只能进行**只读判断**，不能修改系统调用参数
- 只能基于系统调用号和参数值做判断，不能基于路径等动态信息

**典型 BPF 程序结构**：

```c
struct sock_filter filter[] = {
    // 加载架构标识
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, arch)),
    // 验证架构（x86_64）
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 4),
    // 加载系统调用号
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, nr)),
    // 允许 write 系统调用
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    // 拒绝其他所有系统调用
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};
```

**实践建议**：生产环境中推荐使用 `libseccomp` 而非手写 BPF 程序。libseccomp 提供了高级 API（如 `seccomp_rule_add()`），可自动处理架构差异和 BPF 程序生成。Rust 生态中有 `libseccomp` crate 可用。

### 2.2 Linux Namespaces：资源隔离

Namespaces 是 Linux 内核提供的资源隔离机制，使一组进程只能看到系统资源的子集。这是 Docker、Podman、LXC 等容器技术的核心基础。

**8 种 Namespace 类型**：

| Namespace | 常量 | 隔离内容 | 引入内核版本 |
|-----------|------|----------|-------------|
| Mount (mnt) | `CLONE_NEWNS` | 文件系统挂载点 | 2.4.19 |
| PID | `CLONE_NEWPID` | 进程 ID 号空间 | 2.6.24 |
| Network (net) | `CLONE_NEWNET` | 网络栈（接口、端口、路由） | 2.6.29 |
| IPC | `CLONE_NEWIPC` | System V IPC、POSIX 消息队列 | 2.6.19 |
| UTS | `CLONE_NEWUTS` | 主机名和 NIS 域名 | 2.6.19 |
| User | `CLONE_NEWUSER` | 用户和组 ID | 3.8 |
| Cgroup | `CLONE_NEWCGROUP` | Cgroup 根目录视图 | 4.6 |
| Time | `CLONE_NEWTIME` | 启动和单调时钟 | 5.6 |

**关键机制详解**：

- **User Namespace**：允许在 namespace 内映射不同的 UID/GID。例如，容器内 UID 0（root）映射到宿主机上的普通用户 UID 1000。这是**无特权容器**（rootless container）的核心技术，使得非 root 用户也能创建功能完整的沙箱。
- **Network Namespace**：创建完全独立的网络栈，包括独立的网络接口、IP 地址、路由表、iptables 规则和端口号。通过 `veth pair`（虚拟以太网对）可以在不同 namespace 间建立网络连接。
- **Mount Namespace**：隔离文件系统挂载点视图。配合 `pivot_root` 或 `chroot` 可以为沙箱提供独立的文件系统根目录。支持 `shared`、`slave`、`private`、`unbindable` 四种传播类型。

**操作接口**：

```bash
# 创建新的 namespace
unshare --net --pid --mount --fork /bin/bash

# 加入已有 namespace
nsenter -t <PID> -m -u -i -n -p /bin/bash

# 查看 namespace
ls -la /proc/$$/ns
```

### 2.3 Cgroups v2：资源限制

Control Groups（cgroups）是 Linux 内核提供的资源限制和记账机制。Cgroups v2（统一层级）自 Linux 4.5 起成为默认版本。

**核心控制器**：

| 控制器 | 功能 | 典型用途 |
|--------|------|----------|
| cpu | CPU 时间分配 | 限制 CPU 使用率 |
| memory | 内存使用限制 | 防止内存耗尽攻击 |
| pids | 进程数限制 | 防止 fork 炸弹 |
| io | 块设备 I/O 限制 | 控制磁盘带宽 |
| cpuacct | CPU 使用记账 | 资源计量 |
| devices | 设备访问控制 | 限制设备文件访问 |

**Cgroups v2 关键改进**：

- 统一层级（single hierarchy）：所有控制器挂在同一个 cgroup 树上
- 更安全的委托模型：非特权进程可以管理自己的 cgroup 子树
- 压力停滞通知（PSI）：提供资源压力的精确度量
- `memory.peak`、`memory.swap.high` 等新接口

**典型使用**：

```bash
# 创建 cgroup 并限制内存为 512MB
echo 536870912 > /sys/fs/cgroup/sandbox/memory.max
echo $$ > /sys/fs/cgroup/sandbox/cgroup.procs
```

### 2.4 Landlock LSM：文件系统访问控制

Landlock 是 Linux 内核的安全模块（LSM），提供**无特权的、细粒度的文件系统访问控制**。自 Linux 5.13 合并主线，是近年来 Linux 沙箱领域最重要的创新之一。

**核心优势**：

- **无需 root 权限**：普通进程即可对自己的权限施加限制
- **路径级别的访问控制**：可以精确控制对特定目录/文件的读、写、执行权限
- **不可逆**：规则集一旦生效，无法撤销
- **可叠加**：与 SELinux、AppArmor 等其他 LSM 共存

**ABI 版本演进**：

| ABI 版本 | 内核版本 | 新增功能 |
|----------|----------|----------|
| V1 | 5.13 | 基础文件系统访问控制（读、写、执行、目录列表等） |
| V2 | 5.19 | 跨目录链接/重命名控制（Refer） |
| V3 | 6.2 | 文件截断控制（Truncate） |
| V4 | 6.7 | TCP 网络端口控制（Bind/Connect） |
| V5 | 6.10 | IOCTL 设备控制 |
| V6 | 6.12 | Scope 限制（信号、抽象 Unix 域套接字） |

**三个系统调用 API**：

1. `landlock_create_ruleset()` — 创建规则集，定义要限制的访问类型
2. `landlock_add_rule()` — 向规则集添加路径规则或网络端口规则
3. `landlock_restrict_self()` — 将规则集应用于当前进程

**Rust 使用示例**：

```rust
use landlock::{ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};

fn sandbox() -> Result<(), landlock::RulesetError> {
    let abi = ABI::V1;
    Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rule(PathBeneath::new(PathFd::new("/usr")?, AccessFs::from_read(abi)))?
        .add_rule(PathBeneath::new(PathFd::new("/tmp")?, AccessFs::from_all(abi)))?
        .restrict_self()?;
    Ok(())
}
```

### 2.5 Linux 沙箱技术组合模型

实际生产中，Linux 沙箱通常组合使用多种机制：

```
┌─────────────────────────────────────────────┐
│              应用进程                         │
├─────────────────────────────────────────────┤
│  seccomp-bpf → 限制可用系统调用               │
│  Landlock    → 限制文件系统/网络访问           │
│  namespaces  → 隔离 PID/网络/文件系统视图      │
│  cgroups v2  → 限制 CPU/内存/进程数            │
│  rlimit      → 限制文件描述符/核心转储等        │
│  capabilities → 限制特权操作                   │
└─────────────────────────────────────────────┘
```

---

## 3. macOS 沙箱机制详解

macOS 的沙箱体系建立在 Apple 自研的安全框架之上，与代码签名体系深度耦合。

### 3.1 Sandbox (Seatbelt)

Seatbelt 是 macOS 的系统级强制访问控制（MAC）框架，最初源自 TrustedBSD MAC 框架。自 Mac OS X 10.5（Leopard）引入。

**架构**：

- **用户态**：`libsandbox.dylib` 将 Scheme 风格的 `.sb` 配置文件编译为字节码策略
- **内核态**：Seatbelt KEXT 通过 Kauth scope 监听器拦截系统调用，依据加载的策略进行判定

**沙箱配置文件语言**：

```scheme
;; 基本沙箱配置示例
(version 1)
(deny default)                          ; 默认拒绝所有
(allow file-read* (subpath "/usr"))     ; 允许读取 /usr
(allow file-write* (subpath "/tmp"))    ; 允许写入 /tmp
(deny network*)                         ; 拒绝所有网络访问
(allow process-exec (literal "/bin/ls")) ; 允许执行 ls
```

**内置配置文件**（位于 `/usr/share/sandbox/`）：

| 配置文件 | 用途 |
|----------|------|
| `no-network` | 阻止所有网络访问 |
| `no-internet` | 阻止互联网但允许本地网络 |
| `pure-computation` | 仅允许纯计算 |

**命令行使用**：

```bash
sandbox-exec -f profile.sb /path/to/command
```

**现状**：自 macOS 10.15 Catalina 起，`sandbox-exec` 已被标记为弃用。Apple 推荐使用 App Sandbox（基于 entitlements 和代码签名），但 Seatbelt 仍然在系统中运行，许多系统服务仍在使用。对于 CLI 工具沙箱场景，Seatbelt 仍是最实用的选择。Anthropic 的 SRT（Sandbox Runtime）在 macOS 上即使用 Seatbelt 实现进程隔离。

### 3.2 Endpoint Security Framework

Endpoint Security（ES）是 Apple 在 macOS 10.15 Catalina 中引入的内核级安全监控框架，替代了已弃用的 Kauth 框架。

**核心特性**：

- 基于事件的架构：监控文件、进程、套接字等系统事件
- 通过 System Extension（而非 KEXT）运行，无需内核扩展
- 提供同步和异步两种事件处理模式
- 事件包括：文件创建/删除/修改、进程创建/退出、套接字连接等

**适用场景**：主要用于安全软件（杀毒、EDR）而非应用沙箱。但可以作为沙箱实现的基础设施，用于监控和执行安全策略。

### 3.3 AMFI 与 Hardened Runtime

**AMFI (Apple Mobile File Integrity)**：

- 强制代码签名验证：确保运行的代码经过合法签名
- 管理Entitlements：控制应用可以使用的特权能力
- 检测代码篡改：验证代码页的加密哈希

**Hardened Runtime**：

自 macOS 10.14 引入，为应用提供额外的运行时保护：

- 禁止动态库注入（除非显式声明 `com.apple.security.cs.allow-unsigned-executable-memory`）
- 禁止修改可执行段
- 禁止加载未签名的第三方插件
- 强制使用 hardened 保护的代码签名

对沙箱的意义：Hardened Runtime 确保沙箱化应用不会被通过动态注入等方式绕过沙箱限制。

### 3.4 XPC 服务隔离

XPC（Inter-Process Communication）是 macOS 的进程间通信和服务隔离框架：

- 将应用拆分为多个独立的 XPC Service，每个服务运行在独立的进程中
- 每个 XPC Service 可以有独立的沙箱配置和 entitlements
- 通过 Mach IPC 进行高效通信
- 服务崩溃不影响主进程

**沙箱应用模式**：

```
┌──────────────┐     XPC     ┌──────────────────┐
│   主应用进程   │◄──────────►│  沙箱化 XPC 服务   │
│  (受限沙箱)   │             │  (严格沙箱)        │
└──────────────┘             └──────────────────┘
```

主应用负责 UI 和用户交互，将危险的文件操作或网络操作委托给受限的 XPC 服务执行。

---

## 4. Windows 沙箱机制详解

Windows 提供了多层次的沙箱机制，从进程级隔离到基于虚拟化的完整隔离。

### 4.1 Job Objects：进程组管理

Job Object 是 Windows 的进程组管理机制，允许将多个进程作为整体进行资源限制和管理。

**核心功能**：

- 将一组进程关联到一个 Job Object
- 设置 CPU 时间限制、工作集大小、进程优先级
- 限制进程数量、用户模式执行时间
- 进程结束通知
- 从 Windows 8 开始支持 Job Object 嵌套

**资源限制能力**：

```c
// 创建 Job Object
HANDLE hJob = CreateJobObject(NULL, L"MySandbox");

// 设置限制
JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimit = {0};
basicLimit.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_TIME |
                         JOB_OBJECT_LIMIT_WORKINGSET;
basicLimit.PerProcessUserTimeLimit.QuadPart = 10000000; // 1秒
basicLimit.MinimumWorkingSetSize = 1 * 1024 * 1024;     // 1MB
basicLimit.MaximumWorkingSetSize = 512 * 1024 * 1024;    // 512MB

SetInformationJobObject(hJob, JobObjectBasicLimitInformation,
                        &basicLimit, sizeof(basicLimit));
```

Job Object 是 Windows 容器（Silos）的基础构建块。

### 4.2 AppContainer：应用隔离

AppContainer 是 Windows 8 引入的应用隔离机制，是 UWP（Universal Windows Platform）应用的默认沙箱。

**隔离机制**：

- **Package SID**：每个 AppContainer 应用拥有唯一的标识 SID，基于 SHA-2 哈希生成
- **低完整性级别**：默认运行在 Low IL，无法写入 Medium IL 及以上的对象
- **显式 ACE**：只能访问明确授权的资源，普通 DACL 的隐式允许被忽略
- **独立命名空间**：使用 `\Sessions\x\AppContainerNamedObjects` 而非共享的 `\BaseNamedObjects`
- **能力 (Capabilities)**：通过 Capability SID 声明需要的系统资源访问权限（如摄像头、网络等）

**Less Privileged AppContainer (LPAC)**：

LPAC 是更严格的 AppContainer 变体，连常规 AppContainer 可访问的系统资源也需要显式授权。适用于最小权限场景。

**Win32 应用隔离**：

Windows 11 扩展了 AppContainer 的适用范围，支持将传统 Win32 应用也运行在 AppContainer 中：
- 进程以低完整性级别运行
- 限制为一组特定的 Windows API
- 禁止进程注入和窗口消息攻击

### 4.3 Windows Sandbox：基于 Hyper-V 的隔离

Windows Sandbox 提供轻量级桌面隔离环境，用于安全运行不可信的 Win32 应用。

**架构特点**：

- 基于 Hyper-V 硬件虚拟化，但不是传统 VM
- **动态基础镜像 (Dynamic Base Image)**：共享宿主机的 Windows 二进制文件，不需要独立的 OS 副本
- **直接映射 (Direct Map)**：沙箱内加载的系统文件使用与宿主机相同的物理内存页
- **协作式内存管理**：与宿主机动态共享内存，而非静态分配

**资源效率**：

| 特性 | 传统 VM | Windows Sandbox |
|------|---------|-----------------|
| 磁盘空间 | 需要独立 OS 镜像 | 共享宿主机 OS 文件 |
| 内存使用 | 静态分配 | 动态共享 |
| 启动时间 | 30-60 秒 | 数秒 |
| GPU 支持 | 需要直通 | WDDM 原生虚拟化 |

### 4.4 MIC (Mandatory Integrity Control)

强制完整性控制（MIC）是 Windows Vista 引入的强制访问控制机制，基于进程的完整性级别（Integrity Level, IL）控制访问权限。

**四个完整性级别**：

| 级别 | SID | 典型用途 |
|------|-----|----------|
| Low | S-1-16-4096 | IE 保护模式、沙箱进程 |
| Medium | S-1-16-8192 | 普通用户进程 |
| High | S-1-16-12288 | 管理员进程 |
| System | S-1-16-16384 | 系统服务 |

**核心规则**：进程只能写入完整性级别等于或低于自身的对象。这意味着 Low IL 进程无法修改 Medium IL 的文件或注册表项。

### 4.5 Silos / Server Silos：Windows 容器基础

Silos 是 Windows 容器的底层隔离机制，对应 Linux 的 namespace 概念。

**两种类型**：

- **Application Silo**：非完整容器，用于 Desktop Bridge 技术
- **Server Silo**：完整的 Windows 容器，是 Docker Windows 容器的基础

**创建流程**（基于逆向工程分析）：

1. `vmcompute.exe` 调用 `CreateJobObject` 创建 Job Object
2. 通过 `NtSetInformationJobObject` 设置限制（CPU 亲和性、内存等）
3. 将 Job Object 转换为 Silo（`NtSetInformationJobObject` 特定信息类）
4. 进一步转换为 Server Silo，注册容器运行时
5. 创建虚拟磁盘 (`sandbox.vhdx`) 作为文件系统
6. 配置虚拟网络适配器 (vNIC)

**与 Linux Namespaces 的对比**：

| Linux | Windows |
|-------|---------|
| PID Namespace | Server Silo 进程隔离 |
| Network Namespace | vNIC + 网络命名空间 |
| Mount Namespace | sandbox.vhdx + 文件系统重定向 |
| Cgroup | Job Object 资源限制 |

---

## 5. 轻量级沙箱工具对比

### 5.1 Bubblewrap (bwrap)

Bubblewrap 是 Flatpak 项目开发的低层级无特权沙箱工具，也是 Anthropic SRT 在 Linux 上的沙箱后端。

**核心特性**：

- 纯粹的 namespace 包装器，零额外开销
- 默认使用 User Namespace（无需 root）
- 通过命令行参数精细控制 mount 命名空间
- 支持 overlayfs、bind mount、tmpfs 等多种挂载方式
- 约 3K 行 C 代码，极简且易于审计

**典型用法**：

```bash
bwrap --ro-bind /usr /usr --dev /dev --proc /proc \
      --bind /workspace /workspace --unshare-net -- claude
```

**性能数据**（Julia Evans 基准测试）：

| 工具 | 启动时间 | 说明 |
|------|----------|------|
| bwrap | ~8ms | 单次 unshare 系统调用 |
| podman | ~279ms | 包含镜像层管理等 |
| docker | ~378ms | 包含 daemon 通信等 |

**优势**：启动极快、零运行时开销、无需 daemon、代码量小可审计
**劣势**：无内置安全策略（需自行组合 seccomp/Landlock）、无镜像管理、API 较底层

### 5.2 nsjail

Google 开发的轻量级进程隔离工具，功能比 Bubblewrap 更丰富。

**核心特性**：

- Linux namespaces + cgroups + rlimits + seccomp-bpf 全支持
- 三种运行模式：一次性执行、守护进程模式、cgroup 重用模式
- 内置 cgroup 资源限制（内存、CPU、PID 数）
- 内置 seccomp-bpf 过滤
- 内置 rlimit 设置
- 约 15K 行 C + 4K 行 C++ 代码

**典型用法**：

```bash
nsjail --mode o --cgroup_mem_max 536870912 \
       --rlimit_as max --time_limit 60 \
       --disable_clone_newnet \
       -- /bin/sh -c "untrusted_code"
```

**与 Bubblewrap 对比**：

| 维度 | Bubblewrap | nsjail |
|------|-----------|--------|
| 代码量 | ~3K C | ~19K C/C++ |
| 启动开销 | ~1ms | 稍高 |
| cgroup 支持 | 无 | 完整 |
| seccomp 支持 | 无内置 | 内置 |
| rlimit 支持 | 无 | 完整 |
| 维护方 | Red Hat | Google |
| 主要用户 | Flatpak、Claude Code | Google 内部、代码执行平台 |

### 5.3 Firejail

Linux 下最易用的沙箱工具之一，拥有 900+ 预置应用安全配置。

- 自动识别应用并加载对应 profile
- 集成 seccomp-bpf、AppArmor、namespaces
- SUID 程序，无需用户 namespace 支持
- 配置文件格式简单直观

### 5.4 gVisor

Google 的用户态应用内核，在内核和应用程序之间插入一个 Go 语言编写的拦截层。

- 拦截每个系统调用并在用户态重新实现
- 提供最强的隔离（仅次于完整 VM）
- I/O 开销 10-30%
- 被 Northflank 用于每月 200 万+ 工作负载

### 5.5 综合对比

| 工具 | 隔离强度 | 启动时间 | 运行时开销 | 易用性 | 适用场景 |
|------|---------|---------|-----------|--------|---------|
| Bubblewrap | 中（依赖配置） | ~8ms | 0% | 低 | 底层构建块 |
| nsjail | 中-高 | ~20ms | <1% | 中 | 代码执行平台 |
| Firejail | 中 | ~10ms | <1% | 高 | 桌面应用沙箱 |
| gVisor | 高 | ~100ms | 10-30% | 中 | 高安全需求 |
| Docker/Podman | 中 | ~300ms | <5% | 高 | 完整容器 |

---

## 6. 跨平台统一抽象可行性

### 6.1 平台差异分析

三大平台的沙箱原语差异显著：

| 隔离维度 | Linux | macOS | Windows |
|----------|-------|-------|---------|
| 文件系统隔离 | Mount Namespace + Landlock | Seatbelt 策略 | AppContainer + sandbox.vhdx |
| 网络隔离 | Network Namespace | Seatbelt deny network | vNIC + 防火墙规则 |
| 进程隔离 | PID Namespace | Seatbelt deny process | Server Silo |
| 资源限制 | cgroups v2 | rlimit + Seatbelt | Job Objects |
| 系统调用过滤 | seccomp-bpf | 无直接等价物 | 无直接等价物 |
| 身份隔离 | User Namespace | Entitlements + 代码签名 | AppContainer SID |
| 特权控制 | Capabilities | Entitlements | Integrity Level |

### 6.2 统一抽象层设计

可行的跨平台沙箱抽象应定义以下核心能力：

```
trait Sandbox {
    // 文件系统访问控制
    fn allow_read(&mut self, paths: &[PathBuf]);
    fn allow_write(&mut self, paths: &[PathBuf]);
    fn allow_execute(&mut self, paths: &[PathBuf]);

    // 网络控制
    fn deny_network(&mut self);
    fn allow_tcp_connect(&mut self, ports: &[u16]);
    fn allow_tcp_bind(&mut self, ports: &[u16]);

    // 资源限制
    fn set_memory_limit(&mut self, bytes: u64);
    fn set_cpu_limit(&mut self, cores: f64);
    fn set_process_limit(&mut self, max: u32);
    fn set_time_limit(&mut self, seconds: u64);

    // 执行
    fn run(&self, command: &Command) -> Result<ExitStatus>;
}
```

### 6.3 各平台后端映射

| 抽象操作 | Linux 后端 | macOS 后端 | Windows 后端 |
|----------|-----------|-----------|-------------|
| allow_read | Landlock PathBeneath | Seatbelt allow file-read* | AppContainer ACE |
| deny_network | unshare(CLONE_NEWNET) | Seatbelt deny network* | Job Object + 防火墙 |
| set_memory_limit | cgroup memory.max | rlimit RLIMIT_AS | Job Object WorkingSet |
| set_process_limit | cgroup pids.max + rlimit | rlimit RLIMIT_NPROC | Job Object Limit |
| run | clone + exec | sandbox_exec | CreateProcessInAppContainer |

### 6.4 统一抽象的挑战

1. **语义差异**：Linux 的 namespace 是"创建隔离的世界"，macOS 的 Seatbelt 是"在当前世界中添加限制"，Windows 的 AppContainer 是"以特殊身份运行"。三者的安全模型根本不同。
2. **能力差异**：seccomp-bpf 在 macOS 和 Windows 上无直接等价物；AppContainer 在 Linux 上无直接等价物。
3. **API 形态差异**：Linux 用系统调用，macOS 用配置文件，Windows 用 Win32 API。
4. **代码签名要求**：macOS 和 Windows 都需要代码签名才能使用完整沙箱功能，Linux 不需要。

### 6.5 现有实践参考

**Anthropic SRT** 的方案最具参考价值：在 macOS 上使用 Seatbelt，在 Linux 上使用 Bubblewrap，通过条件编译选择后端。这证明了跨平台沙箱抽象的可行性，但也表明"最低公共抽象"可能牺牲平台特有的高级功能。

---

## 7. Rust 生态可用库

### 7.1 landlock crate

官方 Rust Landlock 库，提供安全的 Landlock LSM 抽象。

- 支持 ABI V1-V6，自动探测内核支持的最高版本
- 提供 `Ruleset`、`AccessFs`、`AccessNet`、`PathBeneath`、`NetPort` 等类型安全 API
- `path_beneath_rules()` 辅助函数简化批量规则创建
- 优雅降级：内核不支持时返回 `NotEnforced` 而非错误

**ABI 版本对应功能**：

```rust
ABI::V1 // 文件系统访问控制 (Linux 5.13+)
ABI::V2 // 跨目录链接/重命名 (Linux 5.19+)
ABI::V3 // 文件截断 (Linux 6.2+)
ABI::V4 // TCP 端口控制 (Linux 6.7+)
ABI::V5 // IOCTL 控制 (Linux 6.10+)
ABI::V6 // Scope 限制 (Linux 6.12+)
```

### 7.2 hakoniwa crate

一个综合性的 Linux 沙箱库，集成了 namespaces + Landlock + seccomp + cgroups + rlimit。

- 统一的 `Container` API 管理所有隔离机制
- 内置 `Pasta` 网络支持（用户态网络栈）
- 支持 systemd cgroup 集成
- 功能通过 feature flag 按需启用：`landlock`、`seccomp`

```rust
let mut container = Container::new();
container.rootfs("/")?
    .unshare(Namespace::Network)
    .unshare(Namespace::Ipc);

// Landlock 文件系统规则
let mut ruleset = Ruleset::default();
ruleset.restrict(Resource::FS, CompatMode::Enforce);
ruleset.add_fs_rule("/bin", FsAccess::R | FsAccess::X);
ruleset.add_fs_rule("/tmp", FsAccess::W);

container.landlock_ruleset(ruleset);
let status = container.command("/bin/ls").status()?;
```

### 7.3 其他相关 crate

| crate | 平台 | 功能 |
|-------|------|------|
| `libseccomp` | Linux | seccomp-bpf 系统调用过滤 |
| `nix` | Linux/macOS | Unix API 绑定（unshare, clone 等） |
| `windows` | Windows | Windows API 绑定（Job Objects 等） |
| `landrun` | Linux | 基于 Landlock 的沙箱 CLI 工具 |
| `caps` | Linux | Linux Capabilities 操作 |

### 7.4 跨平台沙箱库缺失

目前 Rust 生态中**没有成熟的跨平台沙箱抽象库**。需要自行基于 `cfg(target_os = "...")` 构建条件编译的多后端架构。

---

## 8. 性能对比与选型建议

### 8.1 启动时间对比

| 方案 | 启动时间 | 适用场景 |
|------|----------|----------|
| Bubblewrap (Linux) | ~8ms | 最高性能要求 |
| nsjail (Linux) | ~20ms | 带资源限制的高性能 |
| Seatbelt (macOS) | ~10ms | macOS 原生沙箱 |
| AppContainer (Windows) | ~50ms | Windows 应用隔离 |
| Docker/Podman | ~300ms | 完整容器 |
| gVisor | ~100ms | 增强安全容器 |
| Firecracker microVM | ~125ms | VM 级隔离 |
| Windows Sandbox | ~2-5s | 桌面级 VM 隔离 |

### 8.2 运行时开销

| 方案 | CPU 开销 | 内存开销 | I/O 开销 |
|------|---------|---------|---------|
| Bubblewrap | 0% | ~0 | 0% |
| nsjail | <1% | ~0 | <1% |
| gVisor | 5-15% | 额外 ~50MB | 10-30% |
| Docker (runc) | <1% | 额外 ~5MB | <5% |
| Firecracker | <2% | 额外 ~30MB | <5% |

### 8.3 选型建议

| 需求场景 | 推荐方案 | 理由 |
|----------|----------|------|
| 代码执行平台（Linux） | nsjail 或 Bubblewrap + Landlock | 快速启动、精确控制 |
| 桌面应用沙箱（Linux） | Firejail | 预置 profile、易用 |
| 桌面应用沙箱（macOS） | Seatbelt / App Sandbox | 原生支持、生态完善 |
| 高安全隔离（Linux） | gVisor | 用户态内核、最强隔离 |
| 跨平台 CLI 工具 | Bubblewrap(Linux) + Seatbelt(macOS) | 参考 Anthropic SRT |
| 服务器容器 | Docker/Podman + seccomp + Landlock | 完整生态 |
| Rust 原生集成 | hakoniwa + landlock crate | 类型安全、零成本抽象 |

---

## 9. 结论与建议

### 9.1 核心结论

1. **Linux 拥有最成熟的沙箱生态**：seccomp + namespaces + cgroups + Landlock 的组合提供了全面而灵活的沙箱能力，是容器和沙箱技术的首选平台。
2. **Landlock 是近年来最重要的创新**：无特权、路径级、不可逆的文件系统访问控制填补了 Linux 沙箱的关键空白，特别适合应用自沙箱化场景。
3. **跨平台统一抽象可行但有限**：三大平台的安全模型差异显著，最低公共抽象会牺牲平台特有能力。Anthropic SRT 的实践证明，按平台选择后端 + 轻量抽象层是务实的方案。
4. **Rust 生态尚不完善**：Linux 上有 landlock、hakoniwa 等高质量库，但 macOS 和 Windows 的 Rust 沙箱库几乎空白，跨平台抽象库更是缺失。

### 9.2 对 mimobox 项目的建议

1. **以 Linux 为首要支持平台**，利用 Landlock + namespaces + seccomp 构建沙箱核心能力。
2. **使用 Rust landlock crate** 实现文件系统访问控制，配合 hakoniwa crate 管理 namespace 和 seccomp。
3. **macOS 后端使用 Seatbelt**，通过 `sandbox-init()` API 或生成 `.sb` 配置文件实现。
4. **Windows 后端使用 AppContainer**，利用 `windows-rs` crate 调用 Win32 API。
5. **设计分层的沙箱抽象**：核心 trait 定义跨平台公共操作，平台特有功能通过 extension trait 暴露。

### 9.3 技术路线优先级

```
Phase 1: Linux 沙箱实现（Landlock + namespaces + cgroups）
  ↓
Phase 2: macOS Seatbelt 后端
  ↓
Phase 3: Windows AppContainer 后端
  ↓
Phase 4: 跨平台统一 API + 集成测试
```

---

## 参考资料

- [Linux Kernel seccomp 文档](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Landlock LSM 官方文档](https://docs.kernel.org/userspace-api/landlock.html)
- [rust-landlock crate](https://github.com/landlock-lsm/rust-landlock)
- [hakoniwa crate](https://github.com/souk4711/hakoniwa)
- [Bubblewrap 项目](https://github.com/containers/bubblewrap)
- [nsjail 项目](https://github.com/google/nsjail)
- [macOS Sandbox Architecture](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)
- [Windows Sandbox Architecture](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-architecture)
- [Windows AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [Windows Silos 逆向分析](https://blog.quarkslab.com/reversing-windows-container-episode-i-silo.html)
- [Julia Evans: Bubblewrap 笔记](https://jvns.ca/blog/2022/06/28/some-notes-on-bubblewrap)
- [Agent 沙箱工具对比 2026](https://awesomeagents.ai/tools/best-agent-sandbox-tools-2026/)
