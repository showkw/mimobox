# mimobox MCP Server

本文档描述 `mimobox-mcp` 的运行方式、工具列表、参数结构和 Claude Desktop 集成方式。

## 1. 概述

`mimobox-mcp` 是 mimobox 的 MCP Server 实现，基于 `rmcp` 框架，通过 stdio transport 与 MCP 客户端通信。

当前服务暴露 10 个工具，覆盖：

- 沙箱生命周期管理。
- 命令和代码执行。
- microVM 文件读写。
- microVM 快照与 CoW fork。
- 受控 HTTP 代理请求。

服务端内部由 `MimoboxServer` 管理活动沙箱：

```text
MimoboxServer
  |
  |-- HashMap<u64, ManagedSandbox>
  |-- next_id
  `-- rmcp ToolRouter
```

工具请求通过 `Parameters<T>` 反序列化为 Rust 请求结构，再委托给 `mimobox-sdk`。

## 2. 工具列表

| 工具名 | 描述 | 关键参数 | 返回值 |
| --- | --- | --- | --- |
| `create_sandbox` | 创建可复用沙箱实例 | `isolation_level?`, `timeout_ms?`, `memory_limit_mb?` | `sandbox_id`, `isolation_level` |
| `execute_code` | 在沙箱中执行代码片段 | `sandbox_id?`, `code`, `language?`, `timeout_ms?` | `stdout`, `stderr`, `exit_code`, `timed_out`, `elapsed_ms` |
| `execute_command` | 在沙箱中执行 shell 命令 | `sandbox_id?`, `command`, `timeout_ms?` | `stdout`, `stderr`, `exit_code`, `timed_out`, `elapsed_ms` |
| `destroy_sandbox` | 销毁沙箱并释放资源 | `sandbox_id` | `sandbox_id`, `destroyed` |
| `list_sandboxes` | 列出活动沙箱及其元数据 | 无 | `sandboxes[]` |
| `read_file` | 从 microVM 沙箱读取文件（base64） | `sandbox_id`, `path` | `sandbox_id`, `path`, `content`, `size_bytes` |
| `write_file` | 向 microVM 沙箱写入文件（base64） | `sandbox_id`, `path`, `content` | `sandbox_id`, `path`, `size_bytes`, `written` |
| `snapshot` | 创建 microVM 沙箱内存快照 | `sandbox_id` | `sandbox_id`, `size_bytes` |
| `fork` | Fork microVM 沙箱（CoW） | `sandbox_id` | `original_sandbox_id`, `new_sandbox_id` |
| `http_request` | 通过受控代理发起 HTTP 请求 | `sandbox_id`, `url`, `method` | `sandbox_id`, `status`, `body` |

## 3. 工具详情

### 3.1 `create_sandbox`

创建一个可复用沙箱实例，并把实例保存到服务端的活动沙箱表中。

参数：

- `isolation_level?`：可选隔离层级，支持 `auto`、`os`、`wasm`、`microvm`。
- `timeout_ms?`：默认超时时间，单位毫秒。
- `memory_limit_mb?`：内存上限，单位 MiB。

返回值：

- `sandbox_id`：服务端分配的沙箱 ID。
- `isolation_level`：请求的隔离层级。

示例：

```json
{
  "isolation_level": "microvm",
  "timeout_ms": 5000,
  "memory_limit_mb": 256
}
```

### 3.2 `execute_code`

在指定沙箱或临时沙箱中执行代码片段。服务端会根据 `language` 把代码片段转换为命令。

参数：

- `sandbox_id?`：可选沙箱 ID。不提供时创建临时沙箱。
- `code`：要执行的代码片段。
- `language?`：可选语言，支持 `python`、`javascript`、`node`、`bash`、`sh`。
- `timeout_ms?`：本次执行超时时间，单位毫秒；仅对临时沙箱生效。

返回值：

- `stdout`：标准输出字符串。
- `stderr`：标准错误字符串。
- `exit_code`：退出码，超时等场景可能为 `null`。
- `timed_out`：是否超时。
- `elapsed_ms`：执行耗时，单位毫秒。

### 3.3 `execute_command`

在指定沙箱或临时沙箱中执行 shell 命令。

参数：

- `sandbox_id?`：可选沙箱 ID。不提供时创建临时沙箱。
- `command`：要执行的 shell 命令。
- `timeout_ms?`：本次执行超时时间，单位毫秒；仅对临时沙箱生效。

返回值与 `execute_code` 相同。

### 3.4 `destroy_sandbox`

销毁指定沙箱，并从活动沙箱表中移除。

参数：

- `sandbox_id`：要销毁的沙箱 ID。

返回值：

- `sandbox_id`：被销毁的沙箱 ID。
- `destroyed`：是否已从活动列表移除。

### 3.5 `list_sandboxes`

列出当前 MCP Server 管理的活动沙箱。

参数：无。

返回值：

- `sandboxes[]`：活动沙箱列表。
- `sandboxes[].sandbox_id`：沙箱 ID。
- `sandboxes[].isolation_level`：已解析隔离层级，可能为 `null`。
- `sandboxes[].created_at`：创建时间戳，毫秒。
- `sandboxes[].uptime_ms`：运行时长，毫秒。

### 3.6 `read_file`

从 microVM 沙箱读取文件，并以 base64 返回内容。

参数：

- `sandbox_id`：目标沙箱 ID。
- `path`：沙箱内文件路径。

返回值：

- `sandbox_id`：目标沙箱 ID。
- `path`：文件路径。
- `content`：base64 编码后的文件内容。
- `size_bytes`：原始字节长度。

说明：该工具需要启用 `vm` feature。

### 3.7 `write_file`

向 microVM 沙箱写入 base64 编码的文件内容。

参数：

- `sandbox_id`：目标沙箱 ID。
- `path`：沙箱内文件路径。
- `content`：base64 编码后的文件内容。

返回值：

- `sandbox_id`：目标沙箱 ID。
- `path`：文件路径。
- `size_bytes`：写入的原始字节长度。
- `written`：是否写入成功。

说明：该工具需要启用 `vm` feature。

### 3.8 `snapshot`

创建 microVM 沙箱内存快照。

参数：

- `sandbox_id`：目标沙箱 ID。

返回值：

- `sandbox_id`：目标沙箱 ID。
- `size_bytes`：快照大小。

说明：该工具需要启用 `vm` feature。当前 MCP 返回快照大小，不直接返回快照二进制内容。

### 3.9 `fork`

基于 CoW fork 当前 microVM 沙箱，生成一个新的活动沙箱。

参数：

- `sandbox_id`：原始沙箱 ID。

返回值：

- `original_sandbox_id`：原始沙箱 ID。
- `new_sandbox_id`：fork 后的新沙箱 ID。

说明：该工具需要启用 `vm` feature。

### 3.10 `http_request`

通过 host 侧受控 HTTP 代理发起请求。请求仍受 SDK 配置中的域名白名单约束。

参数：

- `sandbox_id`：目标沙箱 ID。
- `url`：请求 URL，当前主要支持 HTTPS。
- `method`：HTTP 方法，当前 MCP 工具限制为 `GET` 或 `POST`。

返回值：

- `sandbox_id`：目标沙箱 ID。
- `status`：HTTP 状态码。
- `body`：响应体字符串。

说明：该工具需要启用 `vm` feature。

## 4. Claude Desktop 集成配置

在 Claude Desktop 的 MCP 配置中添加：

```json
{
  "mcpServers": {
    "mimobox": {
      "command": "cargo",
      "args": ["run", "-p", "mimobox-mcp", "--features", "vm"]
    }
  }
}
```

如果只需要 OS 级后端，可以移除 `--features` 和 `vm`：

```json
{
  "mcpServers": {
    "mimobox": {
      "command": "cargo",
      "args": ["run", "-p", "mimobox-mcp"]
    }
  }
}
```

## 5. 运行方式

OS 级后端：

```bash
cargo run -p mimobox-mcp
```

microVM 后端：

```bash
cargo run -p mimobox-mcp --features vm
```

## 6. Feature Gates

`mimobox-mcp` 的 feature gate 语义：

- `os`：默认启用，提供 OS 级沙箱创建和命令执行能力。
- `vm`：启用 microVM 相关能力，包括 `read_file`、`write_file`、`snapshot`、`fork` 和 `http_request`。

未启用 `vm` 时，microVM 专属工具会返回明确错误，不会静默降级。

## 7. 临时沙箱

`execute_code` 和 `execute_command` 支持不传 `sandbox_id`。

这种情况下 MCP Server 会：

1. 使用 `IsolationLevel::Auto` 创建临时沙箱。
2. 执行代码片段或命令。
3. 自动调用 `destroy()` 释放资源。

临时沙箱适合一次性工具调用；需要多轮文件状态、快照或 fork 时，应先调用 `create_sandbox` 获取可复用 `sandbox_id`。
