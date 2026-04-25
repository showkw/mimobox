# mimobox 架构设计

本文档描述 `/Users/showkw/dev/mimobox` 当前仓库的架构分层、后端实现机制、SDK 智能路由、MCP Server、Python 绑定以及安全边界。文档只记录当前源码中真实存在的能力，不把研究文档中的远期规划写成现状。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
| v2.0 | 2026-04-25 | 按 8 crate workspace 重写架构，补充 SDK 路由、MCP Server 与 Python SDK 绑定说明 | 更新 | Codex |
| v1.0 | 2026-04-20 | 首次建立架构设计文档 | 新增 | Codex |

## 术语表

| 术语 | 定义 |
| --- | --- |
| 核心抽象层 | `mimobox-core` 中定义的 trait、配置、结果和错误类型 |
| OS 级后端 | `mimobox-os` 中的 Linux/macOS 原生沙箱实现 |
| Wasm 后端 | `mimobox-wasm` 中基于 Wasmtime 的沙箱实现 |
| microVM 后端 | `mimobox-vm` 中基于 Linux KVM 的硬件级隔离实现 |
| 智能路由 | `mimobox-sdk` 根据命令类型和信任级别选择隔离后端的逻辑 |
| MCP Server | `mimobox-mcp` 通过 rmcp + stdio 暴露给 MCP 客户端的工具服务 |
| Python SDK | `mimobox-python` 通过 PyO3 + maturin 暴露的 Python 绑定 |

## 文章内容大纲目录表

| 章节 | 标题 | 目的 |
| --- | --- | --- |
| 1 | 整体架构 | 解释 8 crate workspace 的职责边界 |
| 2 | 核心抽象 | 说明 `Sandbox` trait 与通用类型 |
| 3 | 后端实现 | 展开 OS、Wasm、microVM 三类后端 |
| 4 | SDK 智能路由 | 说明 `resolve_isolation` 的路由规则 |
| 5 | MCP Server | 说明 rmcp + stdio 工具服务架构 |
| 6 | Python SDK | 说明 PyO3 绑定、类型导出和错误映射 |
| 7 | 池化与快照 | 说明 OS 池、VM 池、RestorePool 和 fork |
| 8 | 安全边界 | 明确当前已形成的隔离保证 |
| 9 | 架构阅读顺序 | 给出推荐源码阅读路径 |

## 1. 整体架构

当前 Cargo workspace 包含 8 个 crate：

```text
/Users/showkw/dev/mimobox
|
|-- crates/mimobox-core
|    |-- Sandbox trait
|    |-- SandboxConfig / SandboxResult
|    |-- SandboxError / ErrorCode
|    `-- SeccompProfile
|
|-- crates/mimobox-os
|    |-- LinuxSandbox
|    |    |-- Landlock
|    |    |-- Seccomp-bpf
|    |    |-- namespaces
|    |    `-- setrlimit
|    |-- MacOsSandbox
|    |    |-- sandbox-exec
|    |    `-- Seatbelt policy
|    `-- SandboxPool
|
|-- crates/mimobox-wasm
|    `-- WasmSandbox
|         |-- Wasmtime Engine
|         |-- Module cache
|         |-- StoreLimits
|         `-- WASI Preview 1 runtime
|
|-- crates/mimobox-vm
|    |-- MicrovmSandbox
|    |-- VmPool
|    |-- RestorePool
|    |-- HTTP proxy
|    |-- snapshot / restore / fork
|    `-- guest serial command protocol
|
|-- crates/mimobox-sdk
|    |-- Sandbox facade
|    |-- ConfigBuilder
|    |-- router::resolve_isolation
|    |-- streaming / HTTP / file operations
|    `-- structured error mapping
|
|-- crates/mimobox-cli
|    |-- run
|    |-- bench
|    |-- setup
|    `-- doctor
|
|-- crates/mimobox-mcp
|    |-- rmcp server
|    |-- stdio transport
|    `-- 10 MCP tools
|
`-- crates/mimobox-python
     |-- PyO3 module
     |-- Python classes
     `-- Python exception hierarchy
```

从上层调用看，统一入口集中在 SDK、CLI、MCP Server 和 Python SDK：

```text
调用方
  |
  +--> Rust SDK: mimobox_sdk::Sandbox
  +--> CLI: mimobox-cli
  +--> MCP Client: mimobox-mcp over stdio
  `--> Python: mimobox.Sandbox
        |
        v
  mimobox-sdk
        |
        +--> mimobox-os
        +--> mimobox-wasm
        `--> mimobox-vm
              |
              v
        mimobox-core 通用 trait / config / error
```

`mimobox-core` 是底层通用契约，`mimobox-sdk` 是面向应用层的统一门面。CLI、MCP Server 和 Python SDK 都不直接复制后端决策逻辑，而是尽量委托给 SDK。

## 2. 核心抽象

### 2.1 `Sandbox` trait

`mimobox-core` 的 `Sandbox` trait 用最小生命周期接口覆盖多个隔离后端：

- `new`：创建隔离环境，并在执行前完成安全约束配置。
- `execute`：执行命令或模块入口，返回统一的 `SandboxResult`。
- `destroy`：释放资源，避免后端生命周期完全依赖析构副作用。

这个抽象保持了 KISS：上层不需要理解 Landlock、Wasmtime Store 或 KVM vCPU，只需要面向统一生命周期编程。

### 2.2 通用配置与错误

`SandboxConfig`、`SandboxResult`、`SandboxError` 和 `ErrorCode` 由 `mimobox-core` 统一定义。收益是：

- 后端实现可以共享资源限制、超时、文件白名单和网络策略语义。
- SDK 可以把后端错误提升为结构化 `SdkError`。
- Python SDK 可以把 `SdkError` 映射到 Python 异常层级。
- MCP Server 可以把错误统一序列化为工具调用错误响应。

## 3. 后端实现

### 3.1 OS 级后端：`mimobox-os`

Linux 后端主流程：

```text
父进程
  |
  +-- 创建 stdout/stderr 管道
  +-- fork
       |
       `-- 子进程
            |-- setpgid
            |-- clearenv + 注入最小环境变量
            |-- 重定向 stdin/stdout/stderr
            |-- setrlimit(RLIMIT_AS)
            |-- Landlock restrict_self
            |-- unshare namespaces
            |-- apply_seccomp(profile)
            `-- execvp(command)
```

Linux 安全顺序是关键约束：先资源限制，再文件系统限制，再 namespace，最后 Seccomp。任何关键隔离步骤失败都会直接失败，不以“半隔离”状态继续执行。

macOS 后端使用系统原生 Seatbelt：

```text
SandboxConfig
  |
  v
generate_policy()
  |
  v
sandbox-exec -p "<policy>" -- <command>
```

macOS 当前能可靠限制写入和网络，但读取范围需要保留系统启动依赖路径，无法像 Linux Landlock 一样精确收敛。

### 3.2 Wasm 后端：`mimobox-wasm`

Wasm 后端基于 Wasmtime：

```text
WasmSandbox
  |
  |-- Engine（长生命周期复用）
  |-- cache_dir（模块缓存）
  |-- SandboxConfig
  `-- execute()
       |-- 加载/编译 Module
       |-- 创建 WasiP1Ctx
       |-- 配置 StoreLimits
       |-- 配置 fuel / epoch deadline
       |-- instantiate
       `-- 调用 _start 或 main
```

Wasm 后端通过 StoreLimits 控制线性内存、实例数量和表数量，通过 fuel 与 epoch deadline 组合限制执行成本和墙钟时间。

### 3.3 microVM 后端：`mimobox-vm`

`mimobox-vm` crate 已存在，并且已经实现 Linux KVM 后端。它不是规划占位，也不是研究文档中的虚构模块。

当前实现包含：

- `MicrovmSandbox`：KVM microVM 生命周期与命令执行入口。
- `VmPool`：预热 microVM 池，降低热路径获取延迟。
- `RestorePool`：预创建空壳 VM，用于池化快照恢复。
- 快照 / restore / fork：支持内存快照、恢复和 CoW fork。
- HTTP 代理：host 侧受控 HTTPS 代理，配合域名白名单。
- 文件传输：通过 guest/host 串口协议读写 microVM 内文件。
- 流式输出：`EXECS` 与 `STREAM:*` 帧支持 stdout/stderr 分流。

microVM 控制面当前依赖 guest `/init` 与串口命令协议：

```text
host SDK / VM backend
  |
  +-- EXEC / EXECS
  +-- FS:READ / FS:WRITE
  +-- HTTP:REQUEST
  +-- PING
  `-- SNAPSHOT / RESTORE / FORK control path
        |
        v
guest /init
  |
  +-- 执行命令
  +-- 回传 stdout/stderr/exit
  +-- 处理文件传输
  `-- 转发 HTTP 代理请求
```

## 4. SDK 智能路由

`mimobox-sdk` 是上层推荐入口。核心路由逻辑位于 `router.rs` 的 `resolve_isolation(config, command)`。

### 4.1 Auto 模式

当 `Config.isolation == IsolationLevel::Auto` 时：

1. 命令以 `.wasm`、`.wat` 或 `.wast` 结尾时优先选择 `Wasm`。
2. `TrustLevel::Untrusted` 必须选择 `MicroVm`。
3. 如果当前平台或 feature 不支持 microVM，不可信代码会 fail-closed，返回错误，不降级到 OS 级。
4. 其他命令默认选择 `Os`。

这使默认路径保持低延迟，同时避免把不可信任务静默降级到弱隔离层。

### 4.2 显式模式

当用户显式配置隔离层时：

- `IsolationLevel::Os`：直接选择 OS 级后端，缺少 `os` feature 时返回 `BackendUnavailable`。
- `IsolationLevel::Wasm`：直接选择 Wasm 后端，缺少 `wasm` feature 时返回 `BackendUnavailable`。
- `IsolationLevel::MicroVm`：直接选择 microVM 后端，仅在 Linux + `vm` feature 可用，否则返回 `BackendUnavailable`。

显式模式不再尝试根据命令内容自动改路由，符合“高级用户完全可控”的定位。

## 5. MCP Server

`mimobox-mcp` 基于 rmcp 框架，通过 stdio transport 与 MCP 客户端通信。服务端核心结构是 `MimoboxServer`：

```text
MimoboxServer
  |
  |-- sandboxes: Arc<Mutex<HashMap<u64, ManagedSandbox>>>
  |-- next_id: Arc<Mutex<u64>>
  `-- tool_router: ToolRouter<Self>
```

`ManagedSandbox` 保存 SDK `Sandbox` 实例、创建时间戳和运行时长统计。MCP 工具函数通过 `Parameters<T>` 反序列化请求参数，再调用 SDK 完成创建、执行、文件、快照、fork 和 HTTP 操作。

当前暴露 10 个工具：

| 工具 | 说明 |
| --- | --- |
| `create_sandbox` | 创建可复用沙箱实例 |
| `execute_code` | 执行代码片段，按语言转换为命令 |
| `execute_command` | 执行 shell 命令 |
| `destroy_sandbox` | 销毁指定沙箱并释放资源 |
| `list_sandboxes` | 列出活动沙箱和元数据 |
| `read_file` | 从 microVM 沙箱读取文件，返回 base64 |
| `write_file` | 向 microVM 沙箱写入 base64 文件内容 |
| `snapshot` | 创建 microVM 内存快照 |
| `fork` | 基于 CoW fork microVM 沙箱 |
| `http_request` | 通过受控代理发起 HTTP 请求 |

`execute_code` 和 `execute_command` 不提供 `sandbox_id` 时会创建临时沙箱，执行完成后自动销毁。

## 6. Python SDK

`mimobox-python` 通过 PyO3 + maturin 把 Rust SDK 暴露为 Python 模块。核心关系是：

```text
Python 调用方
  |
  v
mimobox.Sandbox (PySandbox)
  |
  v
mimobox_sdk::Sandbox (RustSandbox)
  |
  +-- OS backend
  +-- Wasm backend
  `-- microVM backend
```

### 6.1 类型导出

Python 模块导出以下公开类型：

- `Sandbox`
- `Snapshot`
- `ExecuteResult`
- `HttpResponse`
- `StreamEvent`
- `StreamIterator`

`PySandbox` 内部持有 `Option<RustSandbox>`。`__exit__` 或显式关闭后会取出内部实例并调用 `destroy()`，避免重复释放。

### 6.2 错误映射

Python 异常层级：

- `SandboxError`：基类。
- `SandboxProcessError`：命令非零退出或被 kill。
- `SandboxHttpError`：HTTP 代理拒绝、非法 URL、body 过大等。
- `SandboxLifecycleError`：沙箱未就绪、已销毁或创建失败。

标准异常映射：

- `CommandTimeout` / `HttpTimeout` -> `TimeoutError`
- `FileNotFound` -> `FileNotFoundError`
- `FilePermissionDenied` -> `PermissionError`
- `HttpConnectFail` / `HttpTlsFail` -> `ConnectionError`
- `InvalidConfig` -> `ValueError`
- `UnsupportedPlatform` -> `NotImplementedError`

### 6.3 方法委托

Python 方法基本保持对 Rust SDK 的薄封装：

- `execute()` 委托 `execute`、`execute_with_env`、`execute_with_timeout` 或 `execute_with_env_and_timeout`。
- `stream_execute()` 委托 Rust SDK 的 `stream_execute()`，返回 `StreamIterator`。
- `read_file()` / `write_file()` 委托 microVM 文件传输能力。
- `snapshot()` / `from_snapshot()` / `fork()` 委托 SDK 快照与 CoW fork 能力。
- `http_request()` 委托 host 侧 HTTP 代理。

## 7. 池化与快照

### 7.1 OS 级 `SandboxPool`

`mimobox-os` 的 `SandboxPool` 通过预创建和复用 OS 级沙箱降低获取延迟：

```text
SandboxPool
  |
  `-- Arc<PoolInner>
       |-- sandbox_config
       |-- pool_config
       |-- health_check_command
       `-- Mutex<PoolState>
            |-- idle: VecDeque<IdleSandbox>
            |-- in_use_count
            |-- hit_count
            |-- miss_count
            `-- evict_count
```

回收由 `PooledSandbox::drop` 触发，并在归还前执行健康检查。

### 7.2 microVM `VmPool` 与 `RestorePool`

`mimobox-vm` 侧有两类池：

- `VmPool`：预热完整 microVM 实例，优化 acquire + execute 热路径。
- `RestorePool`：预创建可恢复的 VM 壳，优化 snapshot restore-to-ready 路径。

快照和 fork 依赖 microVM 后端。OS 与 Wasm 后端不提供等价内存快照能力，SDK 会返回结构化错误。

## 8. 安全边界

### 8.1 已形成硬边界的部分

Linux OS 级：

- 文件系统写入受 Landlock 严格限制。
- 系统调用被 Seccomp 白名单过滤。
- 网络栈通过 namespace 隔离。
- 内存通过 `setrlimit` 收紧。

Wasm：

- 线性内存与实例数量被 `StoreLimits` 限制。
- 执行时间由 fuel 与 epoch deadline 联合控制。
- stdout/stderr 通过内存管道捕获，不直接接管宿主标准流。

microVM：

- 通过 KVM 提供硬件辅助隔离边界。
- guest 文件操作、HTTP 代理和命令执行经过 host 控制面协议。
- 网络仍默认拒绝，HTTP 代理由域名白名单控制。

### 8.2 只能形成软边界或部分边界的部分

macOS：

- 写入控制可靠。
- 网络拒绝可靠。
- 读取范围无法像 Linux 一样精确收敛。
- 内存限制当前不是强硬边界。

### 8.3 仍需谨慎理解的部分

- Windows 后端仍是规划方向，不属于当前已实现安全边界。
- microVM 的正式数据面仍以后续 vsock 演进为目标，当前串口控制面已可用但更偏 bring-up 和控制协议。
- HTTP 代理开放的是 host 控制的请求路径，不等价于沙箱内任意网络访问。

## 9. 架构阅读顺序

如果第一次接触 `mimobox`，建议按以下顺序读源码：

1. `/Users/showkw/dev/mimobox/crates/mimobox-core/src/sandbox.rs`
2. `/Users/showkw/dev/mimobox/crates/mimobox-core/src/error.rs`
3. `/Users/showkw/dev/mimobox/crates/mimobox-sdk/src/config.rs`
4. `/Users/showkw/dev/mimobox/crates/mimobox-sdk/src/router.rs`
5. `/Users/showkw/dev/mimobox/crates/mimobox-sdk/src/lib.rs`
6. `/Users/showkw/dev/mimobox/crates/mimobox-os/src/linux.rs`
7. `/Users/showkw/dev/mimobox/crates/mimobox-os/src/pool.rs`
8. `/Users/showkw/dev/mimobox/crates/mimobox-wasm/src/lib.rs`
9. `/Users/showkw/dev/mimobox/crates/mimobox-vm/src/lib.rs`
10. `/Users/showkw/dev/mimobox/crates/mimobox-cli/src/main.rs`
11. `/Users/showkw/dev/mimobox/crates/mimobox-mcp/src/main.rs`
12. `/Users/showkw/dev/mimobox/crates/mimobox-python/src/lib.rs`

这条路径对应“通用契约 -> SDK 决策 -> 后端实现 -> 上层入口”的真实依赖关系。
