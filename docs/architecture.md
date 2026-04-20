# mimobox 架构设计

本文档描述 `/Users/showkw/dev/mimobox` 当前仓库的架构分层、后端实现机制、预热池设计以及安全边界。文档只记录已经在源码中存在或已在研究文档中明确规划的位置，不把未实现能力写成现状。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
| v1.0 | 2026-04-20 | 首次建立架构设计文档 | 新增 | Codex |

## 术语表

| 术语 | 定义 |
| --- | --- |
| 核心抽象层 | `mimobox-core` 中定义的 trait 与通用类型 |
| 平台后端层 | `mimobox-os` 与 `mimobox-wasm` 中的具体实现 |
| 池化层 | `SandboxPool` 对 OS 级后端的复用层 |
| 安全边界 | 当前实现真正能强制执行的隔离范围 |

## 文章内容大纲目录表

| 章节 | 标题 | 目的 |
| --- | --- | --- |
| 1 | 整体架构 | 解释仓库分层和模块关系 |
| 2 | 核心抽象 | 说明 `Sandbox` trait 的设计理由 |
| 3 | 后端实现 | 展开 Linux、macOS、Wasm 的实现细节 |
| 4 | 预热池 | 解释池化的数据结构与回收策略 |
| 5 | 安全边界 | 明确每个后端当前能保证什么、不能保证什么 |

## 1. 整体架构图

```text
/Users/showkw/dev/mimobox
|
|-- crates/mimobox-core
|    |
|    +-- Sandbox trait
|    +-- SandboxConfig
|    +-- SandboxResult
|    +-- SandboxError
|    +-- SeccompProfile
|
|-- crates/mimobox-os
|    |
|    +-- LinuxSandbox
|    |    +-- Landlock
|    |    +-- Seccomp-bpf
|    |    +-- namespaces
|    |    +-- setrlimit
|    |
|    +-- MacOsSandbox
|    |    +-- sandbox-exec
|    |    +-- Seatbelt policy
|    |
|    +-- SandboxPool
|         +-- PoolConfig
|         +-- PoolStats
|         +-- PooledSandbox
|
|-- crates/mimobox-wasm
|    |
|    +-- WasmSandbox
|         +-- Engine
|         +-- Module cache
|         +-- StoreLimits
|         +-- Fuel / Epoch timeout
|         +-- WASI Preview 1 linker
|
|-- crates/mimobox-cli
|    |
|    +-- 参数解析
|    +-- OS benchmark 入口
|    +-- Pool benchmark 入口
|    +-- Wasm benchmark 入口
|
`-- docs/research
     |
     +-- 路线图、技术调研、代码审查
     `-- microVM 与后续阶段设计依据
```

从调用路径看：

```text
调用方
  |
  v
mimobox-cli / 测试 / 上层集成
  |
  v
mimobox-core::Sandbox trait
  |
  +--> LinuxSandbox
  +--> MacOsSandbox
  +--> WasmSandbox
  |
  `--> SandboxPool（包裹 OS 级后端，负责复用）
```

## 2. `Sandbox` trait 设计理念

### 2.1 目标

`Sandbox` trait 试图用最小接口覆盖多个隔离后端：

- 创建
- 执行
- 销毁

这意味着上层不需要理解 Linux 特有的 Landlock，也不需要理解 Wasmtime 的 Engine/Store 区分，只需要面向统一生命周期编程。

### 2.2 为什么只有三个方法

设计取舍非常直接：

- `new`
  让所有安全约束在执行前确定，避免“先创建后补丁”的竞态窗口。
- `execute`
  保持命令输入模型统一，OS 后端执行进程命令，Wasm 后端把 `cmd[0]` 解释为模块路径。
- `destroy`
  强制调用者对资源收尾负责，避免把后端销毁逻辑完全隐藏在析构行为中。

这种设计带来的结果：

- 抽象简单，适合 CLI、测试和后续 SDK 封装。
- 不支持 trait object，因为 `destroy(self)` 消费 `self`，但支持泛型调用。
- 后端可以保留自己的内部状态，只要不突破统一输入输出契约。

### 2.3 配置与结果统一化

`SandboxConfig`、`SandboxResult` 和 `SandboxError` 统一放在 `mimobox-core`，有几个直接收益：

- 文档不需要为每个后端重新定义输入输出语义。
- 基准、测试和池化逻辑可以复用同一套结果结构。
- 错误边界统一后，更容易做日志、指标和上层错误映射。

## 3. 后端实现细节

### 3.1 Linux 后端

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-os/src/linux.rs`

Linux 后端是当前最完整的实现。`LinuxSandbox::execute` 的主流程可以概括为：

```text
父进程
  |
  +-- 创建 stdout/stderr 管道
  +-- fork
       |
       +-- 子进程 child_main
            |
            +-- setpgid
            +-- clearenv + 注入最小环境变量
            +-- 重定向 stdin/stdout/stderr
            +-- setrlimit(RLIMIT_AS)
            +-- Landlock restrict_self
            +-- unshare namespace
            +-- 如启用 CLONE_NEWPID，执行一次内部 fork
            +-- apply_seccomp(profile)
            +-- execvp(command)
```

#### 3.1.1 Linux 安全顺序

安全顺序是 Linux 后端最关键的实现约束：

1. 先限制资源，再执行后续隔离步骤。
2. Landlock 在 `exec` 前施加，确保文件系统边界已经收敛。
3. namespace 在 Seccomp 前建立，避免过早限制系统调用导致隔离步骤自己失败。
4. Seccomp 作为最后一道“执行前闸门”，只对白名单系统调用放行。

#### 3.1.2 Landlock 设计

- `fs_readonly` 对应只读规则。
- `fs_readwrite` 对应读写规则。
- 规则应用失败会直接 `_exit(122)`，不会带着“无文件系统隔离”的状态继续执行。

#### 3.1.3 Seccomp 设计

Seccomp 实现在 `/Users/showkw/dev/mimobox/crates/mimobox-os/src/seccomp.rs`，使用手工 BPF 白名单：

- `Essential`
  默认最小系统调用集合，不允许 fork。
- `Network`
  在 `Essential` 基础上增加 socket 等网络调用。
- `EssentialWithFork`
  允许 `fork` / `clone` / `wait4` 等。
- `NetworkWithFork`
  同时开放网络和子进程能力。

显式被排除的调用包括：

- 提权相关：`setuid`、`setgid`
- 设备控制：`ioctl`（仅在 fork profile 中开放）
- 进程跟踪：`ptrace`
- 文件系统挂载：`mount`、`umount2`
- 发送信号：`kill`、`tkill`

#### 3.1.4 namespace 设计

Linux 后端尝试 `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC`。

- 若完整 `unshare` 失败，会回退到不带 user namespace 的版本。
- 若回退也失败，会直接退出，不会以“未隔离命名空间”的方式继续运行。

#### 3.1.5 超时与输出收集

- 父进程使用 `waitpid(..., WNOHANG)` 轮询子进程。
- 超时后发送 `SIGKILL`，并把 `timed_out` 标记为 `true`。
- stdout/stderr 通过 `pipe2(O_CLOEXEC)` 捕获。

### 3.2 macOS 后端

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-os/src/macos.rs`

macOS 后端并不复制 Linux 的实现，而是选择系统原生的 Seatbelt 模型：

```text
SandboxConfig
  |
  v
generate_policy()
  |
  v
sandbox-exec -p "<policy>" -- <cmd...>
```

#### 3.2.1 Seatbelt 策略生成

策略结构大致如下：

1. `(version 1)`
2. `(deny default)`
3. `(allow file-read*)`
4. `(allow file-write* (subpath ...))`
5. `(allow process-exec (subpath ...))`
6. `(allow process-fork)`
7. `(deny network*)`，当 `deny_network = true`

#### 3.2.2 为什么文件读取不能像 Linux 一样限制

源码注释已经给出边界说明：

- macOS 进程启动依赖 dyld、`System/Library/Frameworks`、`/usr/lib` 等系统路径。
- 如果盲目收缩只读路径，很多命令根本无法启动。

因此当前实现的策略是：

- 读取范围宽松
- 写入范围严格白名单

这也是 macOS 后端和 Linux 后端在安全边界上的最大差异。

#### 3.2.3 资源限制

当前 macOS 后端会记录内存限制告警，但不会形成真正的硬边界，因为：

- `RLIMIT_AS` 无法像 Linux 那样从无限值安全收缩。
- 当前实现没有引入替代性的宿主级内存控制机制。

### 3.3 Wasm 后端

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-wasm/src/lib.rs`

Wasm 后端的关键设计不是“创建一次进程”，而是“复用 Engine、按次创建 Store”：

```text
WasmSandbox
  |
  +-- Engine（长生命周期，跨 execute 复用）
  +-- cache_dir（磁盘缓存）
  +-- SandboxConfig
  |
  `-- execute()
       |
       +-- 加载/编译 Module
       +-- 创建 MemoryOutputPipe
       +-- 构建 WasiP1Ctx
       +-- 创建带 StoreLimits 的 Store
       +-- 配置 fuel 和 epoch deadline
       +-- instantiate
       +-- 调用 _start 或 main
       +-- 读取 stdout/stderr
```

#### 3.3.1 模块缓存

缓存策略分两层：

1. 轻量级元数据指纹
   使用文件大小和修改时间先查映射文件。
2. 内容哈希
   使用 SHA256 对模块内容生成稳定缓存键，并把序列化后的 `Module` 写入磁盘。

这样做的好处是：

- 热路径不需要每次读取整个 Wasm 文件再算哈希。
- 文件内容变化时仍然能通过 SHA256 避免误命中。

#### 3.3.2 资源限制

Wasm 后端的资源限制通过 `StoreLimitsBuilder` 配置：

- `memory_size`
- `memories(1)`
- `tables(4)`
- `instances(1)`
- `trap_on_grow_failure(true)`

这比单纯依靠操作系统进程上限更贴近 Wasm 运行时模型。

#### 3.3.3 超时模型

Wasm 后端同时使用两条时间限制链路：

- Fuel
  近似限制纯 Wasm 指令执行量。
- Epoch interruption
  限制墙钟时间，覆盖可能阻塞的路径。

两者的组合意义在于：

- Fuel 负责“算力预算”。
- Epoch 负责“墙钟上限”。

#### 3.3.4 I/O 模型

- stdout/stderr 通过 `MemoryOutputPipe` 捕获。
- 输出会被截断到内部设定上限，防止无界增长。
- 当前仍是 WASI Preview 1 模型，尚未暴露自定义宿主能力接口。

### 3.4 microVM 后端的架构位置

当前仓库没有 `mimobox-vm` crate，也没有 VMM 实现代码。microVM 只存在于研究文档和路线图中，因此本文只记录它的设计位置，不对接口做虚构扩展。

预留位置的意义：

- `Sandbox` trait 已经足够容纳一个新的 VM 级后端。
- CLI、配置结构和性能表已经为 Phase 4 留出了空间。
- 研究文档中已经对 Firecracker、smolvm 等方案做了前期分析。

## 4. 预热池设计

### 4.1 目标

`SandboxPool` 的目标不是改变安全边界，而是在不放宽约束的前提下降低获取延迟：

- 提前创建空闲沙箱
- 在热路径上复用对象
- 用健康检查保证回收对象可再次使用
- 用统计数据暴露命中率与驱逐情况

### 4.2 核心数据结构

```text
SandboxPool
  |
  `-- Arc<PoolInner>
       |
       +-- sandbox_config
       +-- pool_config
       +-- health_check_command
       `-- Mutex<PoolState>
            |
            +-- idle: VecDeque<IdleSandbox>
            +-- in_use_count
            +-- hit_count
            +-- miss_count
            `-- evict_count
```

这里有几个设计重点：

- `Arc`
  允许跨线程共享同一个池。
- `Mutex`
  把关键共享状态收束到一个锁中，避免外部并发破坏计数一致性。
- `VecDeque`
  方便同时支持“从尾部取最近使用对象”和“从头部淘汰最久未使用对象”。

### 4.3 获取与归还流程

```text
warm(target)
  |
  +-- 创建缺少的实例
  `-- 放入 idle 队列

acquire()
  |
  +-- 先驱逐空闲超时实例
  +-- 命中 idle -> hit_count++
  `-- 未命中 -> miss_count++ 并创建新实例

PooledSandbox::drop
  |
  +-- 健康检查
  +-- 健康则回收到 idle
  `-- 不健康或容量超限则驱逐
```

### 4.4 为什么没有显式 `release()`

当前实现把归还动作内聚到 `Drop` 有两个直接好处：

- 调用方很难忘记归还资源。
- 池内部可以统一执行健康检查和驱逐逻辑。

代价是：

- API 文档上必须明确“release 是阶段，不是方法”。
- 如果调用方希望更早释放，需要显式 `drop(handle)`。

### 4.5 健康检查与驱逐

回收逻辑会先执行健康检查命令：

- Linux 使用 `/bin/true`
- macOS 使用 `/usr/bin/true`

驱逐触发条件：

- 健康检查失败
- 空闲时间超过 `max_idle_duration`
- 回收时池容量已满，需要 LRU 淘汰最旧空闲对象

## 5. 安全边界说明

### 5.1 已经形成硬边界的部分

Linux：

- 文件系统写入受 Landlock 严格限制
- 系统调用被 Seccomp 白名单过滤
- 网络栈通过 namespace 隔离
- 内存通过 `setrlimit` 收紧

Wasm：

- 线性内存与实例数量被 `StoreLimits` 限制
- 执行时间由 Fuel 与 Epoch 联合控制
- 输出通过内存管道捕获，不直接接管宿主标准流

### 5.2 只能形成软边界或部分边界的部分

macOS：

- 写入控制可靠
- 网络拒绝可靠
- 读取范围无法像 Linux 一样精确收敛
- 内存限制当前不是硬保证

### 5.3 尚未纳入当前安全保证的部分

- Windows AppContainer
- microVM 级隔离
- 更细粒度的宿主能力注入
- Wasm 预热池

### 5.4 文档裁决规则

为了避免误导，本文对安全边界采用以下裁决原则：

1. 只有源码中存在并可从实现推导出的约束，才写成“已实现”。
2. 仅存在于研究文档或路线图中的内容，明确标注为“规划中”。
3. 平台限制不隐藏，例如 macOS 文件读取边界宽松、内存限制不生效，这些都必须直接写明。

## 6. 架构阅读顺序

如果你第一次接触 `mimobox`，建议按以下顺序读源码：

1. `/Users/showkw/dev/mimobox/crates/mimobox-core/src/sandbox.rs`
2. `/Users/showkw/dev/mimobox/crates/mimobox-core/src/seccomp.rs`
3. `/Users/showkw/dev/mimobox/crates/mimobox-os/src/linux.rs`
4. `/Users/showkw/dev/mimobox/crates/mimobox-os/src/pool.rs`
5. `/Users/showkw/dev/mimobox/crates/mimobox-wasm/src/lib.rs`
6. `/Users/showkw/dev/mimobox/crates/mimobox-cli/src/main.rs`

这条路径基本对应了“抽象 -> 平台后端 -> 低延迟优化 -> CLI 验证”的真实依赖关系。
