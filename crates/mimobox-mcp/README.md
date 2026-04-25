# mimobox-mcp

MCP Server for AI agents that need secure code and command execution through mimobox Agent Sandbox.

`mimobox-mcp` exposes mimobox sandbox operations over the Model Context Protocol, allowing MCP-compatible clients to create isolated sandboxes, run commands, move files, snapshot state, fork sandboxes, and make controlled HTTP requests.

Repository: <https://github.com/showkw/mimobox>

## Tools

| Tool | Description |
| --- | --- |
| `create_sandbox` | Create a new sandbox with the requested isolation mode. |
| `execute_code` | Execute source code inside a sandbox. |
| `execute_command` | Execute a shell-style command inside a sandbox. |
| `destroy_sandbox` | Destroy a sandbox and release resources. |
| `list_sandboxes` | List active sandboxes known to the server. |
| `read_file` | Read a file from a sandbox. |
| `write_file` | Write a file into a sandbox. |
| `snapshot` | Capture sandbox state where supported. |
| `fork` | Fork a sandbox from an existing sandbox state where supported. |
| `http_request` | Perform a controlled HTTP request through the sandbox proxy. |

## Quick Start

Run the server from the repository:

```bash
cargo run -p mimobox-mcp
```

Run with microVM support enabled on Linux + KVM:

```bash
cargo run -p mimobox-mcp --features vm
```

## Claude Desktop Configuration

Add an MCP server entry similar to the following:

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

For a packaged binary, replace `command` with the absolute path to your `mimobox-mcp` executable and omit the Cargo arguments.

## Feature Flags

| Feature | Default | Description |
| --- | --- | --- |
| `os` | Yes | Enables the OS-level backend through `mimobox-sdk/os`. |
| `vm` | No | Enables the microVM backend through `mimobox-sdk/vm`. |

## License

MIT OR Apache-2.0
