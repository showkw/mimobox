# MimoBox MCP Server

This document describes the current `mimobox-mcp` server API, transports,
tool list, parameter structures, and MCP client integration.

## 1. Overview

`mimobox-mcp` is the MCP server implementation for MimoBox. It is built on
the `rmcp` framework and supports two transports:

- `stdio`: default transport for Claude Desktop and local MCP clients.
- `http`: optional Streamable HTTP transport on `/mcp`.

The current service exposes 15 tools:

- Lifecycle: `create_sandbox`, `destroy_sandbox`, `list_sandboxes`.
- Execution: `execute_code`, `execute_command`.
- Files: `read_file`, `write_file`, `list_dir`, `make_dir`, `stat`,
  `remove_file`, `rename`.
- Advanced: `snapshot`, `fork`, `http_request`.

microVM/KVM capabilities are Linux-only. The MCP binary itself is not guarded
by a Linux-only `cfg`, but release artifacts may be platform-specific.

## 2. Tool List

| Tool Name | Description | Key Parameters | Return Values |
| --- | --- | --- | --- |
| `create_sandbox` | Creates a reusable sandbox instance | `isolation_level?`, `timeout_ms?`, `memory_limit_mb?`, `env_vars?` | `sandbox_id`, `sandbox_uuid`, `requested_isolation_level`, `actual_isolation_level` |
| `execute_code` | Executes a code snippet in a sandbox | `sandbox_id?`, `code`, `language?`, `timeout_ms?` | `stdout`, `stderr`, `exit_code`, `timed_out`, `elapsed_ms` |
| `execute_command` | Executes argv or a parsed command string | `sandbox_id?`, `argv?`, `command?`, `timeout_ms?` | `stdout`, `stderr`, `exit_code`, `timed_out`, `elapsed_ms` |
| `destroy_sandbox` | Destroys a sandbox and releases resources | `sandbox_id` | `sandbox_id`, `destroyed` |
| `list_sandboxes` | Lists active sandboxes and metadata | none | `sandboxes[]` |
| `read_file` | Reads a sandbox file as base64 | `sandbox_id`, `path` | `sandbox_id`, `path`, `content`, `size_bytes` |
| `write_file` | Writes a base64 payload to a sandbox file | `sandbox_id`, `path`, `content` | `sandbox_id`, `path`, `size_bytes`, `written` |
| `list_dir` | Lists directory contents | `sandbox_id`, `path` | `sandbox_id`, `path`, `entries[]` |
| `make_dir` | Creates a directory with `mkdir -p` semantics | `sandbox_id`, `path` | `sandbox_id`, `path`, `created` |
| `stat` | Returns file or directory metadata | `sandbox_id`, `path` | `sandbox_id`, `path`, `file_type`, `size`, `mode`, `modified_ms`, `is_dir`, `is_file` |
| `remove_file` | Removes a file or empty directory | `sandbox_id`, `path` | `sandbox_id`, `path`, `removed` |
| `rename` | Renames or moves a sandbox path | `sandbox_id`, `from_path`, `to_path` | `sandbox_id`, `from_path`, `to_path`, `renamed` |
| `snapshot` | Creates a microVM memory snapshot | `sandbox_id` | `sandbox_id`, `size_bytes` |
| `fork` | Forks a microVM sandbox with CoW memory | `sandbox_id` | `original_sandbox_id`, `new_sandbox_id` |
| `http_request` | Sends an HTTPS request through the controlled proxy | `sandbox_id`, `url`, `method` | `sandbox_id`, `status`, `headers`, `body` |

## 3. Shared Limits And Path Rules

The server validates request sizes before dispatch:

- File read/write payloads are capped at 10 MiB per call.
- Directory listings are capped at 10,000 returned entries.
- Command output is capped at 4 MiB per stream in MCP responses.
- `execute_command.command` is capped at 64 KiB.
- `execute_command.argv` is capped at 64 KiB total and 32 KiB per argument.
- `execute_code.code` is capped at 1 MiB.
- Paths are capped at 4096 bytes.
- A server instance keeps at most 64 active sandboxes.
- Timeouts are capped at 3600 seconds.

MCP guest paths for file tools must be absolute and start with `/sandbox/`.
They must not be empty, contain NUL bytes, contain newlines, or contain `..`
path traversal components.

## 4. Tool Details

### 4.1 `create_sandbox`

Parameters:

- `isolation_level?`: `auto`, `os`, `wasm`, `microvm`, `micro_vm`,
  `micro-vm`, or `vm`. Defaults to `auto`.
- `timeout_ms?`: default timeout in milliseconds for commands in this sandbox.
- `memory_limit_mb?`: memory limit in MiB.
- `env_vars?`: persistent environment variables applied to later commands.

Return values:

- `sandbox_id`: MCP server-local numeric sandbox ID.
- `sandbox_uuid`: Rust SDK UUID string.
- `requested_isolation_level`: normalized requested level.
- `actual_isolation_level`: active backend level, or `null` before lazy
  backend initialization.

### 4.2 `execute_code`

Parameters:

- `sandbox_id?`: existing sandbox ID. If omitted, a temporary sandbox is
  created and destroyed after execution.
- `code`: code snippet to execute.
- `language?`: `python`, `python3`, `py`, `javascript`, `js`, `node`,
  `nodejs`, `bash`, `sh`, or `shell`. Defaults to `bash`.
- `timeout_ms?`: timeout for temporary sandboxes only.

Return values are `stdout`, `stderr`, `exit_code`, `timed_out`, and
`elapsed_ms`.

Temporary sandboxes use `IsolationLevel::Auto`, `TrustLevel::Untrusted`,
30 seconds default timeout, and 256 MiB default memory limit.

### 4.3 `execute_command`

Parameters:

- `sandbox_id?`: existing sandbox ID. If omitted, a temporary sandbox is
  created and destroyed after execution.
- `argv?`: direct argument vector. This is preferred because it avoids shell
  parsing.
- `command?`: compatibility field parsed with `shlex::split`. It is not
  executed through `/bin/sh -c`; pass `argv: ["/bin/sh", "-c", "..."]` when
  shell expansion, pipes, or redirection are required.
- `timeout_ms?`: timeout for temporary sandboxes only.

`argv` takes priority over `command`. One of them must be provided.

### 4.4 Lifecycle Tools

`destroy_sandbox` takes `sandbox_id` and returns `sandbox_id`, `destroyed`.

`list_sandboxes` takes no parameters and returns:

- `sandboxes[].sandbox_id`
- `sandboxes[].sandbox_uuid`
- `sandboxes[].isolation_level`
- `sandboxes[].created_at`
- `sandboxes[].uptime_ms`

### 4.5 File Tools

`read_file`, `write_file`, `stat`, `remove_file`, and `rename` require the
`vm` feature and a microVM-capable sandbox. Without `vm`, they return explicit
errors.

`list_dir` first calls the SDK directory API and can fall back to a command
based directory listing when the backend reports an unsupported file API.

`make_dir` uses `mkdir -p` through command execution and does not require the
`vm` feature at compile time, but the path rules above still apply.

All file tools require guest paths under `/sandbox/`.

### 4.6 `snapshot` And `fork`

`snapshot` and `fork` require the `vm` feature and a microVM backend.

`snapshot` returns only `size_bytes`; it does not return the binary snapshot
payload through MCP.

`fork` inserts the forked sandbox into the active sandbox table and returns a
new `new_sandbox_id`.

### 4.7 `http_request`

`http_request` requires the `vm` feature and the microVM HTTP proxy path.

Parameters:

- `sandbox_id`: target sandbox ID.
- `url`: HTTPS URL. Only HTTPS targets are accepted by the proxy.
- `method`: `GET` or `POST`.

Return values:

- `sandbox_id`
- `status`
- `headers`
- `body`

The request remains constrained by the SDK allowlist and HTTP ACL policy.
Direct sandbox networking remains denied by default.

## 5. MCP Client Configuration

If you have the `mimobox` CLI installed:

```bash
mimobox mcp-init claude
mimobox mcp-init cursor
mimobox mcp-init windsurf
```

The helper writes the MCP server entry as `mimobox-mcp`. The server name in a
manual MCP client configuration is client-local and may be customized.

Manual stdio configuration example:

```json
{
  "mcpServers": {
    "mimobox-mcp": {
      "command": "mimobox-mcp",
      "args": [],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

## 6. Installation Notes

`scripts/install.sh` installs the CLI by default. Pass `--with-mcp` to install
the MCP server as well when matching release artifacts are available.

```bash
bash scripts/install.sh --with-mcp
```

Source fallback examples:

```bash
bash scripts/build.sh --release -p mimobox-mcp
bash scripts/build.sh --release -p mimobox-mcp --features vm
```

## 7. Running

Start the default stdio server:

```bash
mimobox-mcp
```

Start the HTTP transport:

```bash
mimobox-mcp --transport http --bind-addr 127.0.0.1 --port 8080 --auth-token my-secret-token
```

## 8. Authentication And HTTP Transport

HTTP mode requires a Bearer token. Configure it with either:

- CLI flag: `--auth-token <secret>`
- Environment variable: `MIMOBOX_AUTH_TOKEN`

If both are set, the CLI flag takes precedence.

HTTP mode may only bind to local loopback addresses: `127.0.0.1`, `::1`, or
`localhost`. Binding to `0.0.0.0`, `[::]`, `::`, or other non-loopback
addresses is rejected.

Every HTTP request must include:

```text
Authorization: Bearer <token>
```

Requests without a valid token receive `401 Unauthorized`.

HTTP MCP client configuration example:

```json
{
  "mcpServers": {
    "mimobox-mcp": {
      "command": "mimobox-mcp",
      "args": ["--transport", "http", "--port", "8080"],
      "env": {
        "RUST_LOG": "info",
        "MIMOBOX_AUTH_TOKEN": "my-secret-token"
      }
    }
  }
}
```

## 9. Feature Gates

- `os`: enabled by default. Provides OS-level sandbox creation and command
  execution.
- `vm`: enables microVM-specific tools: `read_file`, `write_file`, `stat`,
  `remove_file`, `rename`, `snapshot`, `fork`, and `http_request`.

When `vm` is not enabled, microVM-specific tools return explicit errors
instead of silently degrading.

See [MCP Client Integration Guide](mcp-integration.md) for client-specific
setup notes.
