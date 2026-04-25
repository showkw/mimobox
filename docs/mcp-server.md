> **Note**: The `mimobox-mcp` binary is currently built for Linux only. macOS users can use the CLI and SDK but cannot run the MCP server at this time.

# mimobox MCP Server

This document describes how `mimobox-mcp` runs, its tool list, parameter structures, and Claude Desktop integration.

## 1. Overview

`mimobox-mcp` is the MCP Server implementation for mimobox. It is built on the `rmcp` framework and communicates with MCP clients through stdio transport.

The current service exposes 10 tools covering:

- Sandbox lifecycle management.
- Command and code execution.
- microVM file reads and writes.
- microVM snapshots and CoW fork.
- Controlled HTTP proxy requests.

Internally, the server manages active sandboxes through `MimoboxServer`:

```text
MimoboxServer
  |
  |-- HashMap<u64, ManagedSandbox>
  |-- next_id
  `-- rmcp ToolRouter
```

Tool requests are deserialized into Rust request structures through `Parameters<T>`, then delegated to `mimobox-sdk`.

## 2. Tool List

| Tool Name | Description | Key Parameters | Return Values |
| --- | --- | --- | --- |
| `create_sandbox` | Creates a reusable sandbox instance | `isolation_level?`, `timeout_ms?`, `memory_limit_mb?` | `sandbox_id`, `isolation_level` |
| `execute_code` | Executes a code snippet in a sandbox | `sandbox_id?`, `code`, `language?`, `timeout_ms?` | `stdout`, `stderr`, `exit_code`, `timed_out`, `elapsed_ms` |
| `execute_command` | Executes a shell command in a sandbox | `sandbox_id?`, `command`, `timeout_ms?` | `stdout`, `stderr`, `exit_code`, `timed_out`, `elapsed_ms` |
| `destroy_sandbox` | Destroys a sandbox and releases resources | `sandbox_id` | `sandbox_id`, `destroyed` |
| `list_sandboxes` | Lists active sandboxes and their metadata | None | `sandboxes[]` |
| `read_file` | Reads a file from a microVM sandbox (base64) | `sandbox_id`, `path` | `sandbox_id`, `path`, `content`, `size_bytes` |
| `write_file` | Writes a file to a microVM sandbox (base64) | `sandbox_id`, `path`, `content` | `sandbox_id`, `path`, `size_bytes`, `written` |
| `snapshot` | Creates a memory snapshot of a microVM sandbox | `sandbox_id` | `sandbox_id`, `size_bytes` |
| `fork` | Forks a microVM sandbox (CoW) | `sandbox_id` | `original_sandbox_id`, `new_sandbox_id` |
| `http_request` | Sends an HTTP request through a controlled proxy | `sandbox_id`, `url`, `method` | `sandbox_id`, `status`, `body` |

## 3. Tool Details

### 3.1 `create_sandbox`

Creates a reusable sandbox instance and stores it in the server's active sandbox table.

Parameters:

- `isolation_level?`: Optional isolation level. Supports `auto`, `os`, `wasm`, and `microvm`.
- `timeout_ms?`: Default timeout in milliseconds.
- `memory_limit_mb?`: Memory limit in MiB.

Return values:

- `sandbox_id`: The sandbox ID assigned by the server.
- `isolation_level`: The requested isolation level.

Example:

```json
{
  "isolation_level": "microvm",
  "timeout_ms": 5000,
  "memory_limit_mb": 256
}
```

### 3.2 `execute_code`

Executes a code snippet in the specified sandbox or in a temporary sandbox. The server converts the snippet into a command based on `language`.

Parameters:

- `sandbox_id?`: Optional sandbox ID. If omitted, a temporary sandbox is created.
- `code`: The code snippet to execute.
- `language?`: Optional language. Supports `python`, `javascript`, `node`, `bash`, and `sh`.
- `timeout_ms?`: Timeout for this execution in milliseconds; only applies to temporary sandboxes.

Return values:

- `stdout`: Standard output string.
- `stderr`: Standard error string.
- `exit_code`: Exit code. May be `null` in timeout and similar scenarios.
- `timed_out`: Whether the execution timed out.
- `elapsed_ms`: Execution duration in milliseconds.

### 3.3 `execute_command`

Executes a shell command in the specified sandbox or in a temporary sandbox.

Parameters:

- `sandbox_id?`: Optional sandbox ID. If omitted, a temporary sandbox is created.
- `command`: The shell command to execute.
- `timeout_ms?`: Timeout for this execution in milliseconds; only applies to temporary sandboxes.

Return values are the same as `execute_code`.

### 3.4 `destroy_sandbox`

Destroys the specified sandbox and removes it from the active sandbox table.

Parameters:

- `sandbox_id`: The ID of the sandbox to destroy.

Return values:

- `sandbox_id`: The ID of the destroyed sandbox.
- `destroyed`: Whether it was removed from the active list.

### 3.5 `list_sandboxes`

Lists the active sandboxes managed by the current MCP Server.

Parameters: None.

Return values:

- `sandboxes[]`: List of active sandboxes.
- `sandboxes[].sandbox_id`: Sandbox ID.
- `sandboxes[].isolation_level`: Resolved isolation level, which may be `null`.
- `sandboxes[].created_at`: Creation timestamp in milliseconds.
- `sandboxes[].uptime_ms`: Uptime in milliseconds.

### 3.6 `read_file`

Reads a file from a microVM sandbox and returns its content as base64.

Parameters:

- `sandbox_id`: Target sandbox ID.
- `path`: File path inside the sandbox.

Return values:

- `sandbox_id`: Target sandbox ID.
- `path`: File path.
- `content`: File content encoded as base64.
- `size_bytes`: Original byte length.

Note: This tool requires the `vm` feature.

### 3.7 `write_file`

Writes base64-encoded file content to a microVM sandbox.

Parameters:

- `sandbox_id`: Target sandbox ID.
- `path`: File path inside the sandbox.
- `content`: File content encoded as base64.

Return values:

- `sandbox_id`: Target sandbox ID.
- `path`: File path.
- `size_bytes`: Original byte length written.
- `written`: Whether the write succeeded.

Note: This tool requires the `vm` feature.

### 3.8 `snapshot`

Creates a memory snapshot of a microVM sandbox.

Parameters:

- `sandbox_id`: Target sandbox ID.

Return values:

- `sandbox_id`: Target sandbox ID.
- `size_bytes`: Snapshot size.

Note: This tool requires the `vm` feature. The current MCP response returns the snapshot size and does not directly return the binary snapshot content.

### 3.9 `fork`

Creates a new active sandbox by applying CoW fork to the current microVM sandbox.

Parameters:

- `sandbox_id`: Original sandbox ID.

Return values:

- `original_sandbox_id`: Original sandbox ID.
- `new_sandbox_id`: New sandbox ID after fork.

Note: This tool requires the `vm` feature.

### 3.10 `http_request`

Sends a request through the host-side controlled HTTP proxy. Requests are still constrained by the domain allowlist in the SDK configuration.

Parameters:

- `sandbox_id`: Target sandbox ID.
- `url`: Request URL. Currently, HTTPS is the primary supported scheme.
- `method`: HTTP method. The current MCP tool is limited to `GET` or `POST`.

Return values:

- `sandbox_id`: Target sandbox ID.
- `status`: HTTP status code.
- `body`: Response body string.

Note: This tool requires the `vm` feature.

## 4. Claude Desktop Integration Configuration

### Quick Setup (Linux)

If you have `mimobox` CLI installed:

```bash
mimobox mcp init claude    # Configure Claude Desktop
mimobox mcp init cursor    # Configure Cursor IDE
mimobox mcp init windsurf  # Configure Windsurf
```

This automatically detects your MCP client and writes the correct configuration.

Install `mimobox-mcp` before configuring Claude Desktop. Download the
precompiled `mimobox-mcp` binary from the
[latest GitHub Release](https://github.com/showkw/mimobox/releases/latest) and
place it in a directory available in your `PATH`, such as `/usr/local/bin/`.

Two binary variants may be published:

- Default binary: OS-level sandbox backend, suitable for standard local usage.
- VM binary: built with `--features vm`, required for microVM-specific tools.

The `scripts/install.sh` helper installs the `mimobox` CLI only. If you need the
MCP server, download `mimobox-mcp` separately from GitHub Releases, or build it
from source as a fallback.

Add the following to the MCP configuration in Claude Desktop:

```json
{
  "mcpServers": {
    "mimobox": {
      "command": "mimobox-mcp",
      "args": [],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

## 5. Running

OS-level backend:

```bash
mimobox-mcp
```

microVM backend:

```bash
mimobox-mcp
```

Install the binary by downloading `mimobox-mcp` from the
[latest GitHub Release](https://github.com/showkw/mimobox/releases/latest) and
placing it in `PATH`. `scripts/install.sh` installs the `mimobox` CLI only; use
the release page to obtain the MCP server binary. If a precompiled binary is not
available for your platform, build from source as a fallback.

## 6. Feature Gates

Feature gate semantics for `mimobox-mcp`:

- `os`: Enabled by default. Provides OS-level sandbox creation and command execution.
- `vm`: Enables microVM-related capabilities, including `read_file`, `write_file`, `snapshot`, `fork`, and `http_request`.

When `vm` is not enabled, microVM-specific tools return explicit errors instead of silently degrading.

## 7. Temporary Sandboxes

`execute_code` and `execute_command` support omitting `sandbox_id`.

In this case, the MCP Server will:

1. Create a temporary sandbox using `IsolationLevel::Auto`.
2. Execute the code snippet or command.
3. Automatically call `destroy()` to release resources.

Temporary sandboxes are suitable for one-off tool calls. If multi-turn file state, snapshots, or fork are needed, call `create_sandbox` first to obtain a reusable `sandbox_id`.

See [MCP Client Integration Guide](mcp-integration.md) for Claude Desktop and Cursor setup.
