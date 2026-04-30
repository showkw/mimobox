# AI Agent Sandbox 竞品 SDK 技术调研

> 调研日期：2026-05-01
> 调研人：总指挥 + Codex
> 目标：分析竞品 SDK 技术实现，提炼 mimobox 可落地的改进建议

---

## 1. E2B (e2b-dev/e2b)

### 1.1 项目概述

E2B 是当前最成熟的 AI 代码执行沙箱，采用云端 SaaS 架构。沙箱实例运行在 E2B 云端，通过 HTTP/WebSocket + gRPC 风格的 Connect-RPC 协议与 SDK 通信。Python SDK 提供 async/sync 两套完整 API。

### 1.2 SDK API 设计

**模块化属性访问模式**（最值得借鉴的设计）：

```python
sandbox = await AsyncSandbox.create()
sandbox.commands.run("echo hello")      # 命令执行
sandbox.files.read("/etc/hosts")         # 文件读取
sandbox.files.write("/tmp/test.txt", "content")
sandbox.files.list("/home")             # 目录列表
sandbox.files.watch_dir("/tmp", on_event)  # 目录监控
sandbox.pty                              # PTY 终端
sandbox.git                              # Git 操作
```

**关键设计特点**：

1. **子模块分离**：`commands`、`files`、`pty`、`git` 各自独立模块，每个模块持有独立的 RPC client
2. **async/sync 双版本**：`AsyncSandbox` 和 `Sandbox` 共享接口语义但独立实现
3. **工厂方法模式**：强制用 `create()` 创建实例，构造器不对外暴露
4. **环境管理器**：`async with AsyncSandbox.create() as s:` 自动清理
5. **静态方法 + 实例方法双模式**：`kill()`/`connect()`/`set_timeout()` 既可实例调用也可静态按 ID 调用

**命令执行 API**：

```python
# 前台执行（阻塞等结果）
result = await sandbox.commands.run(
    "echo hello",
    envs={"KEY": "value"},
    user="root",
    cwd="/home/user",
    timeout=60,
    on_stdout=callback,     # 流式 stdout 回调
    on_stderr=callback,     # 流式 stderr 回调
)
result.stdout  # 标准输出字符串
result.stderr  # 标准错误字符串
result.exit_code  # 退出码

# 后台执行（非阻塞，返回 handle）
handle = await sandbox.commands.run("long_task", background=True)
await handle.wait()
handle.kill()
```

**文件系统 API**：

```python
# 多格式读取
content = await sandbox.files.read("/path")          # text
data = await sandbox.files.read("/path", format="bytes")  # bytes
stream = await sandbox.files.read("/path", format="stream")  # 流式

# 批量写入
await sandbox.files.write_files([
    WriteEntry(path="/tmp/a.txt", data="hello"),
    WriteEntry(path="/tmp/b.py", data="print(1)"),
])

# 目录操作
entries = await sandbox.files.list("/home", depth=2)
exists = await sandbox.files.exists("/etc/hosts")
info = await sandbox.files.get_info("/etc/passwd")  # 包含 owner/group/permissions/modified_time
await sandbox.files.remove("/tmp/test")
await sandbox.files.rename("/tmp/a", "/tmp/b")
await sandbox.files.make_dir("/tmp/new/dir")
```

### 1.3 错误处理

```python
class SandboxException(Exception): pass
class TimeoutException(SandboxException): pass
class FileNotFoundException(NotFoundException, SandboxException): pass
class SandboxNotFoundException(NotFoundException, SandboxException): pass
class InvalidArgumentException(SandboxException): pass
class NotEnoughSpaceException(SandboxException): pass
class RateLimitException(SandboxException): pass
class AuthenticationException(Exception): pass
```

**关键特点**：
- 错误提示带修复建议：`"Request timed out — the 'request_timeout' option can be used to increase this timeout"`
- RPC 错误自动映射：gRPC status code → Python exception type
- 版本感知错误：`"Metrics are not supported in this version of the sandbox, please rebuild your template."`

### 1.4 性能优化

- **envd 守护进程**：沙箱内运行一个 envd agent，SDK 通过 Connect-RPC 与其通信
- **连接池复用**：HTTP transport pool 在 commands/files/pty 间共享
- **Keepalive ping**：WebSocket 连接维持心跳，防止超时断开
- **gzip 压缩**：可选请求压缩（当前因 header 压缩问题禁用）
- **流式处理**：命令输出通过 server-streaming RPC 实时推送

### 1.5 mimobox 可借鉴点

| # | 技术点 | 当前 mimobox | 改进方向 |
|---|--------|-------------|---------|
| 1 | **子模块 API 模式** | `sandbox.execute()` + `sandbox.read_file()` 扁平结构 | 拆为 `sandbox.commands.run()`, `sandbox.files.read()` 等子模块，减少主接口膨胀 |
| 2 | **流式回调模式** | `StreamEvent` 枚举需用户手动 match | 增加 `on_stdout`/`on_stderr` 回调参数，降低使用门槛 |
| 3 | **批量文件操作** | 单文件 `write_file()` | 增加 `write_files()` 批量写入，减少 RTT |
| 4 | **目录监控** | 无 | `watch_dir()` 可实时感知沙箱内文件变化，对 Agent 场景有高价值 |
| 5 | **async/sync 双版本** | 仅 Rust async | Python SDK 应同时提供 async/sync 两套 API |

---

## 2. Daytona (daytonaio/daytona)

### 2.1 项目概述

Daytona 是面向开发环境的沙箱平台，架构上采用 server-runner 分离模式。每个沙箱是一个完整的 Docker 容器，通过 toolbox API（HTTP REST）暴露文件/进程/LSP/Git 操作。SDK 层面同时支持多语言（Python/TypeScript/Go/Ruby）。

### 2.2 SDK API 设计

**属性模块化 + 高级特性**：

```python
sandbox = await AsyncSandbox.create()
sandbox.process.exec("echo hello")          # 命令执行
sandbox.process.code_run("print('hello')")  # 代码执行（语言感知）
sandbox.process.create_session("s1")        # 会话管理
sandbox.process.create_pty_session(...)     # PTY 会话
sandbox.fs.upload_file(local, remote)       # 文件上传
sandbox.fs.download_file(remote, local)     # 文件下载
sandbox.fs.find_files(path, pattern)        # 内容搜索
sandbox.fs.search_files(path, pattern)      # 文件名搜索
sandbox.fs.replace_in_files(files, pattern, new)  # 批量替换
sandbox.fs.set_file_permissions(path, mode) # 权限设置
sandbox.git                                 # Git 操作
sandbox.computer_use                        # 桌面自动化
sandbox.code_interpreter                    # 代码解释器（有状态）
sandbox.create_lsp_server("python", path)   # LSP 语言服务器
```

**关键设计特点**：

1. **Session 模式**：长时间有状态的命令序列，保持环境上下文
2. **Code Interpreter**：有状态的代码执行器，支持变量持久化
3. **Computer Use**：桌面自动化操作
4. **LSP 集成**：语言服务器协议，提供补全/诊断等 IDE 功能
5. **资源热调整**：`resize()` 可动态增减 CPU/内存
6. **生命周期管理**：auto-stop/auto-archive/auto-delete 可配置
7. **网络控制**：`network_block_all` + `network_allow_list` CIDR 粒度
8. **Volume 挂载**：持久化存储卷

**文件系统高级特性**：

```python
# 流式下载大文件
await sandbox.fs.download_file("tmp/large.tar.gz", "/local/path")

# 内容搜索（类似 grep）
matches = await sandbox.fs.find_files("src/", "TODO:")
for m in matches:
    print(f"{m.file}:{m.line}: {m.content}")

# 批量搜索替换
results = await sandbox.fs.replace_in_files(
    ["file1.py", "file2.py"],
    "old_function",
    "new_function"
)

# 文件名搜索（glob 模式）
result = await sandbox.fs.search_files("workspace", "*.py")
```

**流式日志获取**：

```python
# WebSocket 流式获取日志
await sandbox.process.get_session_command_logs_async(
    "session-id", "cmd-id",
    on_stdout=lambda log: print(f"[STDOUT]: {log}"),
    on_stderr=lambda log: print(f"[STDERR]: {log}"),
)
```

### 2.3 错误处理

```python
class DaytonaError(Exception):
    message: str
    status_code: int | None
    headers: dict

class DaytonaNotFoundError(DaytonaError): pass
class DaytonaRateLimitError(DaytonaError): pass
class DaytonaTimeoutError(DaytonaError): pass
```

**关键设计**：
- 错误装饰器统一拦截：`@intercept_errors(message_prefix="Failed to xxx: ")`
- HTTP status code 保留在异常中
- OpenTelemetry 自动埋点：`@with_instrumentation()` 装饰器

### 2.4 mimobox 可借鉴点

| # | 技术点 | 当前 mimobox | 改进方向 |
|---|--------|-------------|---------|
| 1 | **Session 会话模式** | 无状态 execute() | 增加有状态会话，保持 cwd/env 上下文 |
| 2 | **文件搜索/替换** | 仅 list_dir/read_file | 增加 `find_files()`/`search_files()` 内容搜索 |
| 3 | **装饰器式错误处理** | 手动 match ErrorCode | SDK 层统一错误拦截+增强消息 |
| 4 | **资源热调整** | 创建时固定 | 增加 `resize()` 动态调整 CPU/内存 |
| 5 | **OpenTelemetry 埋点** | 无 | 关键路径自动埋点，提供可观测性 |
| 6 | **批量文件操作** | 单文件操作 | `upload_files()`/`download_files()` 批量+流式 |

---

## 3. OpenSandbox (alibaba/opensandbox)

### 3.1 项目概述

阿里开源的通用沙箱平台，支持 Docker 和 Kubernetes 运行时。核心特色是**多语言 SDK**（Python/Java/TypeScript/C#/Go）、**安全容器运行时**（gVisor/Kata/Firecracker）、**客户端池化**。SDK 设计与 mimobox 最可比（都关注隔离+性能）。

### 3.2 SDK API 设计

```python
sandbox = await Sandbox.create(
    "python:3.11",
    resource={"cpu": "1", "memory": "500Mi"},
    timeout=timedelta(minutes=30),
    network_policy=NetworkPolicy(...),  # 出站网络策略
    volumes=[Volume(...)],              # 持久化卷
)

sandbox.commands.run("python script.py")
sandbox.files.write_file("script.py", "print('hello')")
sandbox.metrics.get_metrics()          # 资源使用指标
sandbox.get_info()                     # 沙箱状态
sandbox.renew(timedelta(minutes=10))   # 续期
sandbox.kill()                         # 终止
```

### 3.3 错误处理（最值得借鉴）

```python
class SandboxError:
    """标准化错误码"""
    INTERNAL_UNKNOWN_ERROR = "INTERNAL_UNKNOWN_ERROR"
    READY_TIMEOUT = "READY_TIMEOUT"
    UNHEALTHY = "UNHEALTHY"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNEXPECTED_RESPONSE = "UNEXPECTED_RESPONSE"

class SandboxException(Exception):
    message: str
    cause: Exception | None
    error: SandboxError       # 结构化错误码
    request_id: str | None    # 请求追踪

class SandboxApiException(SandboxException):
    status_code: int | None   # HTTP 状态码

class SandboxReadyTimeoutException(SandboxException): pass
class SandboxUnhealthyException(SandboxException): pass
class InvalidArgumentException(SandboxException): pass
```

**关键设计**：
- 错误码+消息+原因链+请求ID 四维错误模型
- `cause` 保留原始异常，不丢失根因
- `request_id` 支持分布式追踪
- 创建失败自动清理僵尸沙箱

### 3.4 客户端池化方案（OSEP-0005）

这是目前看到最完善的客户端池化设计文档：

**核心概念**：
- `SandboxPool`：SDK 侧空闲缓冲池，预创建就绪沙箱
- `PoolStateStore`：可插拔状态存储接口（内存/Redis/etcd）
- `acquire()`：从池中获取沙箱，空池时回退到直接创建
- `PoolReconciler`：后台补充空闲沙箱到目标水位

**关键设计决策**：
- 沙箱用后即弃（kill-only model），不复用已使用的沙箱
- 空闲 TTL 固定 24h，TTL 到期自然淘汰
- 分布式模式下主节点锁控制补充写入
- 池空时两种策略：`DIRECT_CREATE`（回退创建）或 `FAIL_FAST`（快速失败）
- 退避机制：连续创建失败 → DEGRADED 状态 → 指数退避

### 3.5 mimobox 可借鉴点

| # | 技术点 | 当前 mimobox | 改进方向 |
|---|--------|-------------|---------|
| 1 | **四维错误模型** | ErrorCode + message + suggestion | 增加 `cause` 原始异常 + `request_id` 追踪 |
| 2 | **创建失败自动清理** | 无 | 创建过程中异常时自动 kill 僵尸沙箱 |
| 3 | **可插拔池化状态存储** | RestorePool（仅 VM 专用） | 通用化 PoolStateStore 接口，支持内存/Redis |
| 4 | **健康检查+超时等待** | 无 | `check_ready()` 轮询机制，创建后等待就绪 |
| 5 | **Egress 网络策略** | HTTP ACL 白名单 | 增加通用出站网络策略（CIDR/FQDN） |
| 6 | **多语言 SDK** | Python SDK 已有 | 统一 OpenAPI spec，自动生成多语言 SDK |

---

## 4. Semgrep / 静态分析对沙箱的适用性

### 4.1 Semgrep Rust 支持现状

Semgrep 对 Rust 已达 GA（Generally Available）级别，支持：
- 跨函数数据流分析
- 40+ Pro 安全规则
- unsafe 用法检测、不安全哈希检测、TLS 验证跳过检测等

### 4.2 对 mimobox 的适用规则

| 规则 | 对 mimobox 的适用性 |
|------|-------------------|
| `unsafe-usage` | 高 — 检测缺少 SAFETY 注释的 unsafe 块 |
| `insecure-hashes` | 中 — 检测沙箱内是否使用了不安全的哈希算法 |
| `ssl-verify-none` | 高 — 确保 HTTP 代理不跳过 TLS 验证 |
| `reqwest-accept-invalid` | 高 — 同上，reqwest 跳过证书验证检测 |
| `temp-dir` | 中 — 临时目录安全使用 |
| `current-exe` | 低 — 检测 self-modification 风险 |

### 4.3 建议

- 将 `semgrep ci --config auto` 集成到 CI pipeline
- 编写 mimobox 自定义规则：检测 Landlock 规则缺失、Seccomp profile 未应用、网络默认未拒绝等
- 利用 `semgrep-rules/rust/lang/security/` 现有规则覆盖 unsafe 审计

---

## 5. 综合对比矩阵

| 维度 | E2B | Daytona | OpenSandbox | mimobox |
|------|-----|---------|-------------|---------|
| **架构** | 云端 SaaS + envd agent | Docker 容器 + toolbox API | Docker/K8s + execd agent | 本地进程级隔离（Landlock/Seccomp/NS/Wasm/VM） |
| **冷启动** | ~2s（云端调度） | ~3-5s（容器启动） | ~3-5s（容器启动） | **OS: 8ms / Wasm: 1ms / VM: 253ms** |
| **SDK 语言** | Python, JS/TS | Python, TS, Go, Ruby | Python, Java, TS, C#, Go | Rust, Python |
| **错误模型** | 异常层级 + 修复建议 | 装饰器 + HTTP 状态码 | **四维错误码** | **ErrorCode 枚举 + suggestion** |
| **流式输出** | Server-streaming RPC | WebSocket | SSE streaming | 串口帧协议（VM）/ pipe（OS） |
| **文件操作** | HTTP + RPC | HTTP REST + Multipart | HTTP REST | 命令注入（OS）/ 串口协议（VM） |
| **池化** | 云端托管 | 无 | **OSEP-0005 客户端池** | RestorePool（仅 VM） |
| **网络策略** | allow_internet_access 开关 | CIDR 黑白名单 | FQDN/CIDR Egress | HTTP ACL 域名白名单 |
| **自托管** | 否 | 是 | 是 | **是（单 binary）** |

---

## 6. 改进建议（按优先级排序）

### P0 — 核心竞争力强化

| # | 改进项 | 来源 | 预期效果 | 复杂度 |
|---|--------|------|---------|--------|
| 1 | **SDK 子模块 API 拆分** | E2B | `commands`/`files`/`process` 独立模块，接口清晰 | 中 |
| 2 | **错误模型增强：增加 cause + request_id** | OpenSandbox | 保留异常链+分布式追踪 | 低 |
| 3 | **创建失败自动清理僵尸沙箱** | OpenSandbox | 避免创建异常时资源泄漏 | 低 |
| 4 | **流式回调简化：on_stdout/on_stderr 参数** | E2B | 降低流式输出使用门槛 | 低 |

### P1 — 开发者体验提升

| # | 改进项 | 来源 | 预期效果 | 复杂度 |
|---|--------|------|---------|--------|
| 5 | **Session 会话模式** | Daytona | 有状态命令序列，保持 cwd/env 上下文 | 高 |
| 6 | **批量文件操作** | E2B + Daytona | 减少多文件场景 RTT | 中 |
| 7 | **find_files/search_files** | Daytona | Agent 需要搜索文件内容/文件名 | 中 |
| 8 | **健康检查+就绪等待** | OpenSandbox | 创建后确认沙箱可用 | 低 |

### P2 — 架构优化

| # | 改进项 | 来源 | 预期效果 | 复杂度 |
|---|--------|------|---------|--------|
| 9 | **通用池化 StateStore 抽象** | OpenSandbox OSEP-0005 | 支持 OS/Wasm 层级池化 | 高 |
| 10 | **OpenTelemetry 自动埋点** | Daytona | 关键路径可观测性 | 中 |
| 11 | **Semgrep CI 集成** | Semgrep | 自动化安全审计 | 低 |
| 12 | **资源热调整 resize()** | Daytona | 运行时动态调整 CPU/内存 | 高 |

---

## 7. mimobox 独特优势（不需要改变的）

经过调研对比，mimobox 在以下方面具有竞品难以复制的优势：

1. **极致冷启动**：OS 级 8ms / Wasm 级 1ms，比所有竞品快 100-1000x
2. **三层隔离**：OS + Wasm + VM 统一接口，竞品通常只有容器一种
3. **单 binary 自托管**：无 Docker/K8s 依赖，零外部依赖运行
4. **本地优先**：无需云端调度，延迟可控
5. **Rust 原生性能**：内存/启动/CPU 开销极低
6. **HTTP ACL 细粒度控制**：method+host+path 三维 ACL，竞品通常只有 IP/域名级
7. **Seccomp 白名单**：默认最严安全策略，竞品多为容器默认配置
