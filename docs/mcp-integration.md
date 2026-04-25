---
# MCP Client Integration Guide

This guide explains how to configure MCP clients (Claude Desktop, Cursor IDE) to connect to the mimobox MCP server.

## 1. Claude Desktop Configuration

Configuration file paths:
- **macOS**: ~/Library/Application Support/Claude/claude_desktop_config.json
- **Linux**: ~/.config/Claude/claude_desktop_config.json

### OS-Level Sandbox (default)

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

### VM-Level Sandbox (requires Linux + KVM)

```json
{
  "mcpServers": {
    "mimobox-vm": {
      "command": "mimobox-mcp",
      "args": [],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

Notes:
- The `command` value must be an absolute path or a binary available in your $PATH.
- Download the precompiled `mimobox-mcp` binary from the latest GitHub Release.
- For VM capabilities, use the VM binary variant or build from source with `--features vm` as a fallback.
- Claude Desktop requires a full restart for configuration changes to take effect.
- MCP communication uses stdio: stdout is reserved for the MCP protocol, and logs are written to stderr.

## 2. Cursor IDE Configuration

Cursor supports MCP servers through configuration files:

- **Global**: ~/.cursor/mcp.json
- **Project-level**: .cursor/mcp.json (in your project root)

```json
{
  "mcpServers": {
    "mimobox": {
      "command": "mimobox-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

Notes:
- Cursor supports hot-reload of MCP configuration (no restart required).
- Project-level configuration takes precedence over global configuration.

## 3. Installation Steps

1. **Install the mimobox CLI helper**:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/showkw/mimobox/main/scripts/install.sh | bash
   ```
   This helper currently installs the `mimobox` CLI only. Download the
   `mimobox-mcp` server binary separately from GitHub Releases.

2. **Download `mimobox-mcp` manually** from the
   [latest GitHub Release](https://github.com/showkw/mimobox/releases/latest).
   Choose the binary for your platform. Use the default binary for OS-level
   sandboxing, or the VM binary variant for microVM capabilities.

3. **Install to PATH** by placing the downloaded `mimobox-mcp` binary in a
   directory such as `/usr/local/bin/`, and ensure it is executable.

4. **Configure your MCP client** using the JSON examples above.

5. **Verify the installation**:
   ```bash
   echo '{"jsonrpc":"2.0","method":"initialize","id":1}' | mimobox-mcp
   ```

## 4. Feature Gates

### Default (no --features vm)

Available tools: `create_sandbox`, `execute_code`, `execute_command`, `destroy_sandbox`, `list_sandboxes`.

These use the OS-level sandbox backend and work on all supported platforms.

### VM-Level (--features vm)

Adds the following tools: `read_file`, `write_file`, `snapshot`, `fork`, `http_request`.

These require Linux with KVM hardware support. macOS users can only use the default mode.

## 5. Troubleshooting

| Problem | Cause | Solution |
| --- | --- | --- |
| Claude Desktop shows "MCP server not responding" | Binary not found or not executable | Verify the `command` path is correct and the binary is in $PATH |
| VM tools return "backend unavailable" | Running the default binary without VM support | Download the VM binary variant, or build from source with `--features vm` as a fallback |
| VM tools return "KVM not available" | Running on a system without KVM | Requires Linux with KVM hardware support |
| No output from MCP server | Binary crashed on startup | Set `RUST_LOG=debug` to see detailed logs on stderr |

**Enable debug logging** by setting the environment variable:
```json
{
  "mcpServers": {
    "mimobox": {
      "command": "mimobox-mcp",
      "args": [],
      "env": {
        "RUST_LOG": "debug"
      }
    }
  }
}
```

---
