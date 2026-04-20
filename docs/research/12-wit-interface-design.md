# Agent 工具 WIT 接口设计文档

> 文档编号：12
> 日期：2026-04-20
> 状态：设计原型
> WIT 文件：`wit/mimobox.wit`

---

## 1. 接口总览

### 1.1 架构关系

mimobox 的 Wasm 沙箱中有两个角色：

- **宿主（Host）**：mimobox 运行时，加载并管理 Wasm 组件
- **工具（Tool）**：以 Wasm 组件形式运行的 Agent 工具

两者通过 WIT（WebAssembly Interface Types）定义的接口通信：

```
┌──────────────────────────────────────────────────────────┐
│  mimobox 宿主（Rust / Wasmtime）                          │
│                                                          │
│  ┌─── 导出（Host → Tool）─────────────────────────────┐  │
│  │                                                    │  │
│  │  mimobox:host/sandbox   沙箱信息、日志、资源统计     │  │
│  │  mimobox:host/files     虚拟文件系统读写             │  │
│  │  mimobox:host/http      受限 HTTP 客户端代理         │  │
│  │  mimobox:host/process   受限 Shell 命令执行          │  │
│  │                                                    │  │
│  └──────────────────────────┬─────────────────────────┘  │
│                             │                            │
│                    WIT Canonical ABI                      │
│                             │                            │
│  ┌─── 导入（Tool → Host）──┴─────────────────────────┐  │
│  │                                                    │  │
│  │  mimobox:tool/tool      describe() + execute()     │  │
│  │                                                    │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │           Agent Tool（Wasm Component）              │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### 1.2 包与接口清单

| 包 | 接口 | 方向 | 用途 |
|---|---|---|---|
| `mimobox:tool` | `tool` | 工具导出，宿主导入 | 工具的自描述与执行 |
| `mimobox:host` | `sandbox` | 宿主导出，工具导入 | 沙箱信息、日志、资源监控 |
| `mimobox:host` | `files` | 宿主导出，工具导入 | 虚拟文件系统操作 |
| `mimobox:host` | `http` | 宿主导出，工具导入 | 受限 HTTP 请求代理 |
| `mimobox:host` | `process` | 宿主导出，工具导入 | 受限 Shell 命令执行 |

### 1.3 World 定义

系统定义两个 World：

1. **agent-tool** — 工具组件的世界视图：导出 `tool` 接口，导入 `sandbox` 接口
2. **host** — 宿主的世界视图：导出 `sandbox`、`files`、`http`、`process` 四个接口

---

## 2. 接口详细说明

### 2.1 mimobox:tool/tool — 工具执行接口

这是 Agent 工具组件**必须实现**的接口。宿主通过此接口发现和调用工具。

#### 方法

| 方法 | 签名 | 说明 |
|------|------|------|
| `describe` | `func() -> tool-metadata` | 返回工具的自描述信息，包括名称、版本、参数定义 |
| `execute` | `func(input: string, context: exec-context) -> result<tool-output, tool-error>` | 执行工具逻辑 |

#### 设计决策

**`input` 使用 JSON 字符串而非 WIT record**：

Agent 工具的输入参数结构各异（代码执行工具接收 `code` + `language`，文件工具接收 `path` + `content`）。如果用 WIT record 定义，每种工具都需要不同的 record 类型，导致接口膨胀。使用 JSON 字符串配合 `describe()` 返回的 `param-schema`（JSON Schema 格式）实现自描述的灵活输入，同时保持 WIT 接口的简洁性。

**`exec-context` 携带授权信息**：

每次执行时，宿主通过 `exec-context.capabilities` 明确告知工具当前被授予的权限。工具可以在执行前检查所需能力是否可用，提前返回 `permission-denied` 错误而非在执行中失败。

### 2.2 mimobox:host/sandbox — 沙箱核心接口

工具运行时可通过此接口获取沙箱环境和自身资源使用信息。

#### 方法

| 方法 | 签名 | 说明 |
|------|------|------|
| `info` | `func() -> sandbox-info` | 获取沙箱配置信息（版本、能力、资源限制） |
| `resource-usage` | `func() -> resource-usage` | 获取当前 CPU 时间、内存峰值、挂钟时间 |
| `log` | `func(level: log-level, message: string)` | 通过宿主统一写日志 |

#### 设计决策

**`resource-usage` 允许工具自省**：

工具可以在长时间运行的任务中定期检查资源消耗，在接近限制时主动截断输出或降级处理，而非被宿主强制终止。这是"协作式资源管理"的设计理念。

### 2.3 mimobox:host/files — 虚拟文件系统接口

提供沙箱内的文件操作能力，路径均在虚拟文件系统（VFS）内。

#### 方法

| 方法 | 签名 | 说明 |
|------|------|------|
| `read-file` | `func(path: string) -> result<list<u8>, fs-error>` | 读取文件内容 |
| `write-file` | `func(path: string, content: list<u8>) -> result<(), fs-error>` | 写入文件 |
| `delete-file` | `func(path: string) -> result<(), fs-error>` | 删除文件 |
| `list-dir` | `func(path: string) -> result<list<string>, fs-error>` | 列出目录内容 |
| `stat` | `func(path: string) -> result<file-stat, fs-error>` | 获取文件元数据 |
| `mkdir` | `func(path: string) -> result<(), fs-error>` | 创建目录（含中间目录） |

#### 能力依赖

| 方法 | 所需能力 |
|------|---------|
| read-file, list-dir, stat | `fs-read` |
| write-file, delete-file, mkdir | `fs-write` |

#### 设计决策

**路径安全**：所有路径由宿主解析并限制在 VFS 根目录下。路径遍历攻击（`../../../etc/passwd`）在宿主侧被阻止，工具侧无需关心路径安全性。

**`list<u8>` 而非 `string`**：文件内容使用 `list<u8>`（字节序列）而非 `string`，因为工具可能读写二进制文件。对于文本文件，工具侧自行做 UTF-8 解码。

### 2.4 mimobox:host/http — 受限 HTTP 客户端接口

宿主作为 HTTP 代理，所有请求经过宿主的安全检查。

#### 方法

| 方法 | 签名 | 说明 |
|------|------|------|
| `send-request` | `func(request: http-request) -> result<http-response, http-error>` | 发送 HTTP 请求 |

#### 宿主控制维度

| 控制点 | 策略 |
|--------|------|
| URL 白名单 | 仅允许访问配置的域名/路径模式 |
| 速率限制 | 单位时间内最大请求数 |
| 响应体大小 | 防止大响应耗尽内存 |
| 完全禁用 | 未授权时直接返回 `permission-denied` |

#### 设计决策

**同步请求模型**：WASI 0.2 的 `wasi:http` 使用流式（stream）异步模型，但 Agent 工具场景下大多数请求是小型的同步 API 调用。为简化工具开发，本接口采用同步模型。后续 WASI 0.3 原生 async 支持成熟后可升级为异步流式。

**`http-error` 的 `url-blocked` 变体**：返回被阻止的 URL，方便工具调试和向 Agent 报告限制原因。

### 2.5 mimobox:host/process — 受限进程执行接口

宿主以白名单模式代理 shell 命令执行。

#### 方法

| 方法 | 签名 | 说明 |
|------|------|------|
| `execute` | `func(command: string, args: list<string>, timeout-ms: u32) -> result<shell-result, shell-error>` | 执行受限命令 |
| `allowed-commands` | `func() -> list<string>` | 查询当前允许的命令列表 |

#### 安全过滤

- **命令白名单**：仅允许配置文件中明确列出的命令名
- **参数过滤**：阻止 `| ; & $ \` > <` 等 shell 元字符
- **超时强制**：每个命令有独立的超时限制
- **资源隔离**：子进程在 OS 级沙箱中执行（Linux 下使用 Landlock + Seccomp）

---

## 3. 类型定义解释

### 3.1 Record 类型

| 类型 | 包 | 用途 |
|------|-----|------|
| `param-schema` | tool | 工具参数的 JSON Schema 描述 |
| `tool-metadata` | tool | 工具自描述信息（名称、版本、参数列表） |
| `tool-output` | tool | 工具执行结果（stdout/stderr/exit-code/资源统计） |
| `resource-usage` | tool + host | CPU 时间、内存峰值、挂钟时间（两个包中各定义一份，语义相同） |
| `exec-context` | tool | 宿主传递给工具的执行上下文（超时、内存限制、能力列表） |
| `file-stat` | host | 文件元数据（大小、目录标记、只读标记、修改时间） |
| `http-header` | host | HTTP 请求/响应头的键值对 |
| `http-request` | host | HTTP 请求构造器（方法、URL、请求头、请求体） |
| `http-response` | host | HTTP 响应（状态码、响应头、响应体） |
| `shell-result` | host | Shell 命令执行结果（stdout/stderr/退出码/超时标记） |
| `sandbox-info` | host | 沙箱环境信息（版本、能力、资源限制、VFS 根路径） |

### 3.2 Variant 类型（可辨识联合）

Variant 用于错误类型，每个变体可携带上下文信息：

| 类型 | 变体 | 说明 |
|------|------|------|
| `tool-error` | `invalid-params(string)` | 参数校验失败，附带具体错误 |
| | `timeout` | 执行超时 |
| | `execution-failed(string)` | 运行时错误，附带错误消息 |
| | `permission-denied(string)` | 权限不足，附带被拒绝的能力名 |
| | `resource-exceeded(string)` | 资源超限，附带具体资源类型 |
| `fs-error` | `not-found` | 文件不存在 |
| | `permission-denied` | 未获得文件操作授权 |
| | `invalid-path(string)` | 路径非法，附带原因 |
| | `no-space` | VFS 空间不足 |
| | `io-error(string)` | I/O 错误 |
| `http-error` | `permission-denied` | 未获得 HTTP 授权 |
| | `url-blocked(string)` | URL 不在白名单内 |
| | `timeout` | 请求超时 |
| | `dns-failed(string)` | DNS 解析失败 |
| | `connection-error(string)` | 连接错误 |
| | `response-too-large` | 响应体超出大小限制 |
| | `rate-limited` | 触发速率限制 |
| `shell-error` | `permission-denied` | 未获得 shell 执行授权 |
| | `command-not-allowed(string)` | 命令不在白名单内 |
| | `timeout` | 命令执行超时 |
| | `spawn-failed(string)` | 进程启动失败 |
| | `invalid-args(string)` | 参数含危险字符 |

### 3.3 Enum 类型

| 类型 | 值 | 说明 |
|------|-----|------|
| `capability` | `fs-read`, `fs-write`, `http-request`, `shell-execute` | 能力权限枚举 |
| `http-method` | `get`, `post`, `put`, `delete`, `patch`, `head` | HTTP 请求方法 |
| `log-level` | `trace`, `debug`, `info`, `warn`, `error` | 日志级别 |

### 3.4 Option 类型

- `http-request.body: option<list<u8>>` — 无请求体时为 `none`
- `shell-result.exit-code: option<s32>` — 进程被信号终止时无退出码

---

## 4. 使用示例

### 4.1 宿主侧 Rust 代码（mimobox 运行时）

宿主使用 `wasmtime` 的 `bindgen!` 宏从 WIT 生成绑定，然后加载并调用工具组件。

```rust
use wasmtime::component::{bindgen, Component, Linker};
use wasmtime::{Engine, Store, Config};
use mimobox::wasm_host::{SandboxState, FilesState, HttpState, ProcessState};

// 从 WIT 文件生成绑定
bindgen!("host" in "wit/mimobox.wit");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 配置 Wasmtime 引擎
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.consume_fuel(true);
    let engine = Engine::new(&config)?;

    // 2. 加载工具组件
    let component = Component::from_file(&engine, "target/wasm32-wasip2/release/code_exec_tool.wasm")?;

    // 3. 创建宿主状态
    let state = SandboxState::new()
        .with_capability("fs-read")
        .with_capability("http-request")
        .with_memory_limit(64 * 1024 * 1024)  // 64MB
        .with_timeout_ms(30_000);

    let mut store = Store::new(&engine, state);
    store.set_fuel(1_000_000)?;  // 设置 fuel 上限

    // 4. 链接宿主接口
    let mut linker = Linker::new(&engine);
    Sandbox::add_to_linker(&mut linker, |state: &mut SandboxState| state)?;
    Files::add_to_linker(&mut linker, |state: &mut SandboxState| &mut state.files)?;
    Http::add_to_linker(&mut linker, |state: &mut SandboxState| &mut state.http)?;
    Process::add_to_linker(&mut linker, |state: &mut SandboxState| &mut state.process)?;

    // 5. 实例化组件
    let (tool, _) = Tool::instantiate(&mut store, &component, &linker)?;

    // 6. 获取工具描述
    let metadata = tool.tool().call_describe(&mut store)?;
    println!("工具: {} v{}", metadata.name, metadata.version);

    // 7. 执行工具
    let context = ExecContext {
        timeout_ms: 30_000,
        memory_limit_bytes: 64 * 1024 * 1024,
        execution_id: "exec-001".to_string(),
        capabilities: vec![Capability::FsRead, Capability::HttpRequest],
    };

    let input = r#"{"code": "print(2 + 3)", "language": "python"}"#;
    match tool.tool().call_execute(&mut store, input, &context)? {
        Ok(output) => {
            println!("stdout: {}", output.stdout);
            println!("stderr: {}", output.stderr);
            println!("exit_code: {}", output.exit_code);
            println!("CPU: {}ns, 内存峰值: {}bytes",
                output.resource_usage.cpu_time_ns,
                output.resource_usage.peak_memory_bytes,
            );
        }
        Err(e) => eprintln!("工具执行失败: {:?}", e),
    }

    Ok(())
}
```

### 4.2 工具侧 Rust 代码（Agent 工具组件）

工具开发者使用 `wit-bindgen` 生成的绑定实现工具接口。

```rust
// Cargo.toml 中配置:
// [dependencies]
// wit-bindgen = "0.40"
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"

use serde::Deserialize;

#[derive(Deserialize)]
struct CodeExecInput {
    code: String,
    language: String,
}

// wit-bindgen 为工具侧生成的 trait（伪代码，实际由宏生成）
struct CodeExecTool;

impl Guest for CodeExecTool {
    fn describe() -> ToolMetadata {
        ToolMetadata {
            name: "code-exec".to_string(),
            description: "在沙箱中执行代码片段并返回结果".to_string(),
            version: "0.1.0".to_string(),
            parameters: vec![
                ParamSchema {
                    name: "code".to_string(),
                    type_desc: "string".to_string(),
                    required: true,
                    description: "要执行的代码".to_string(),
                },
                ParamSchema {
                    name: "language".to_string(),
                    type_desc: r#"{"type":"string","enum":["python","javascript","rust"]}"#.to_string(),
                    required: true,
                    description: "编程语言".to_string(),
                },
            ],
        }
    }

    fn execute(input: String, context: ExecContext) -> Result<ToolOutput, ToolError> {
        // 解析输入
        let params: CodeExecInput = serde_json::from_str(&input)
            .map_err(|e| ToolError::InvalidParams(e.to_string()))?;

        // 检查能力
        if !context.capabilities.contains(&Capability::ShellExecute) {
            return Err(ToolError::PermissionDenied("shell-execute".to_string()));
        }

        // 记录日志
        sandbox::log(&LogLevel::Info, &format!("开始执行 {} 代码", params.language));

        // 通过宿主进程接口执行代码
        let result = process::execute(
            &match params.language.as_str() {
                "python" => "python3",
                "javascript" => "node",
                _ => return Err(ToolError::InvalidParams(format!("不支持的语言: {}", params.language))),
            },
            &["-c".to_string(), params.code],
            context.timeout_ms,
        ).map_err(|e| ToolError::ExecutionFailed(format!("进程执行失败: {:?}", e)))?;

        // 检查自身资源使用
        let usage = sandbox::resource_usage();
        if usage.peak_memory_bytes > context.memory_limit_bytes * 9 / 10 {
            sandbox::log(&LogLevel::Warn, "内存使用已超过 90% 限制");
        }

        Ok(ToolOutput {
            stdout: String::from_utf8_lossy(&result.stdout).to_string(),
            stderr: String::from_utf8_lossy(&result.stderr).to_string(),
            exit_code: result.exit_code.unwrap_or(-1),
            timed_out: result.timed_out,
            resource_usage: ResourceUsage {
                cpu_time_ns: usage.cpu_time_ns,
                peak_memory_bytes: usage.peak_memory_bytes,
                wall_time_ns: usage.wall_time_ns,
            },
        })
    }
}

// 导出组件入口
export_tool!(CodeExecTool);
```

---

## 5. 安全模型说明

### 5.1 Deny-by-Default 原则

所有接口遵循**默认拒绝**策略：

```
工具启动 → 无任何能力
    ↓
宿主检查工具配置 → 决定授予哪些能力
    ↓
通过 exec-context.capabilities 传递给工具
    ↓
工具调用宿主接口 → 宿主二次校验能力
    ↓
无能力 → 返回 permission-denied 错误
```

### 5.2 双重校验

能力校验发生在两个层面：

1. **工具侧（协作式）**：工具在 `execute()` 入口检查 `context.capabilities`，提前发现能力不足并返回友好错误
2. **宿主侧（强制式）**：宿主在实现 `files`/`http`/`process` 接口时，独立验证调用方的权限，即使工具绕过自身检查也无法越权

### 5.3 各接口的安全机制

| 接口 | 安全机制 |
|------|---------|
| `files` | 路径限制在 VFS 根目录下；读/写能力分离；宿主侧路径规范化防止遍历攻击 |
| `http` | URL 域名白名单；速率限制；响应体大小限制；超时强制 |
| `process` | 命令名白名单；参数 shell 元字符过滤；超时强制；子进程在 OS 沙箱中运行 |
| `sandbox.log` | 日志消息大小限制（截断过长内容）；日志级别可配置 |

### 5.4 资源限制

| 资源 | 限制方式 | 配置位置 |
|------|---------|---------|
| CPU | Wasmtime Fuel + `exec-context.timeout-ms` | 宿主配置 |
| 内存 | `exec-context.memory-limit-bytes` + Wasmtime 线性内存限制 | 宿主配置 |
| 时间 | `exec-context.timeout-ms` | 每次执行传入 |
| 文件系统 | VFS 容量配额 | 宿主配置 |
| 网络 | URL 白名单 + 速率限制 | 宿主配置 |
| 进程 | 命令白名单 + 参数过滤 + 超时 | 宿主配置 |

### 5.5 与 OS 级沙箱的关系

WIT 接口层的安全控制是"逻辑层"安全。对于通过 `process` 接口执行的子进程，宿主会在底层 OS 级沙箱（Linux: Landlock + Seccomp + Namespaces; macOS: Seatbelt）中执行，形成纵深防御：

```
┌─────────────────────────────────────────┐
│  WIT 接口层（逻辑安全）                    │
│  - 能力校验                              │
│  - 白名单过滤                            │
│  - 参数清洗                              │
├─────────────────────────────────────────┤
│  Wasmtime 运行时层（字节码安全）           │
│  - 内存隔离                              │
│  - Fuel 限制                             │
│  - 控制流完整性                          │
├─────────────────────────────────────────┤
│  OS 沙箱层（内核安全）                    │
│  - Landlock 文件系统隔离                  │
│  - Seccomp 系统调用过滤                   │
│  - Namespace 资源隔离                    │
│  - cgroup 资源限制                       │
└─────────────────────────────────────────┘
```

---

## 6. 未来扩展点

### 6.1 短期（Phase 2 实现）

- **stream 类型**：WASI 0.3 原生 async 支持后，`http.send-request` 可升级为流式请求/响应，支持大文件上传下载
- **resource 类型**：将 `file-handle` 定义为 WIT resource，支持文件的打开-读写-关闭生命周期，避免一次性读取大文件
- **环境变量接口**：在 `sandbox` 接口中增加 `get-env(name: string) -> option<string>` 方法，允许宿主向工具注入配置

### 6.2 中期（Phase 3 实现）

- **工具组合**：定义 `mimobox:tool-registry` 接口，允许工具调用其他工具，实现工具链编排
- **事件通知**：使用 WIT `stream` 或 `future` 类型，允许工具向宿主发送进度事件
- **KV 存储**：在 `sandbox` 接口中增加键值存储方法，支持工具的有状态场景
- **多语言 SDK**：基于 WIT 定义生成 Python / Go / TypeScript 的工具开发 SDK

### 6.3 长期（Phase 4+）

- **WASI 标准 HTTP**：当 `wasi:http` world 足够成熟时，直接使用标准接口替代自定义 `mimobox:host/http`
- **Capability Token**：引入类似 macaroon 的能力令牌机制，支持能力的委托和衰减
- **流式工具输出**：定义 `stream<tool-output-chunk>` 支持流式输出，适用于代码解释器等长时间运行的工具
- **工具市场**：基于 OCI 注册表分发 Wasm 组件，WIT 接口作为组件元数据的标准描述

---

## 附录 A：WIT 文件结构参考

```
wit/
└── mimobox.wit          # 主 WIT 文件（所有接口定义在同一个文件中）
```

随着接口规模增长，可以拆分为：

```
wit/
├── mimobox/
│   ├── tool.wit         # mimobox:tool 包
│   ├── sandbox.wit      # mimobox:host/sandbox 接口
│   ├── files.wit        # mimobox:host/files 接口
│   ├── http.wit         # mimobox:host/http 接口
│   └── process.wit      # mimobox:host/process 接口
├── tool-world.wit       # agent-tool world 定义
└── host-world.wit       # host world 定义
```

## 附录 B：与 WASI 标准接口的对应关系

| mimobox 接口 | WASI 标准对应 | 差异说明 |
|-------------|-------------|---------|
| `mimobox:host/files` | `wasi:filesystem` | mimobox 版本更简化，去掉文件锁、目录迭代器等高级特性 |
| `mimobox:host/http` | `wasi:http` | mimobox 版本使用同步模型，WASI 标准使用 stream 异步模型 |
| `mimobox:host/process` | 无直接对应 | WASI 无进程创建标准，mimobox 自定义实现 |
| `mimobox:host/sandbox` | 无直接对应 | mimobox 特有的沙箱管理接口 |

---

*设计日期：2026-04-20*
*WIT 版本：0.1.0-draft*
*依赖：Wasmtime 25+ / WASI Preview 2 / Component Model*
