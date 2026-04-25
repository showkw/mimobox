# mimobox-mcp

MCP server for AI agents, exposing mimobox sandbox operations over stdio.

Repository: <https://github.com/showkw/mimobox>

## Architecture

`mimobox-mcp` is the Model Context Protocol adapter for mimobox and uses `mimobox-sdk` for sandbox creation, execution, file I/O, snapshots, forks, HTTP requests, and lifecycle cleanup.

It is built on `rmcp`, runs async on `tokio`, and cleans up active sandboxes on SIGTERM or SIGINT.

## Tools

| Tool | Purpose |
| --- | --- |
| `create_sandbox`, `destroy_sandbox`, `list_sandboxes` | Manage sandbox lifecycle. |
| `execute_code`, `execute_command` | Run code snippets or commands. |
| `read_file`, `write_file` | Move file data through the sandbox boundary. |
| `snapshot`, `fork` | Capture or copy backend state. |
| `http_request` | Send controlled sandbox HTTP requests. |

## Quick Example

```bash
mimobox mcp-init
```

Claude Desktop, Cursor, and Windsurf can use the generated stdio server configuration.

```json
{
  "mcpServers": {
    "mimobox": {
      "command": "mimobox-mcp",
      "args": []
    }
  }
}
```

For local development, point `command` at the built binary or use the project script entrypoint.

## Features

| Feature | Default | Meaning |
| --- | --- | --- |
| `os` | Yes | OS sandbox support through `mimobox-sdk`. |
| `vm` | No | microVM sandbox support through `mimobox-sdk`. |

## License

MIT OR Apache-2.0
