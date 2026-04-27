# MCP Configuration Templates

The mimobox MCP Server supports multiple AI coding tools and platforms. Below are the configuration templates for each.

## Claude Desktop

Config file location:
- macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
- Linux: ~/.config/Claude/claude_desktop_config.json

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

## Cursor

Add in Cursor Settings > MCP:

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

## VS Code (Continue.dev)

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "mimobox-mcp"
        }
      }
    ]
  }
}
```

## HTTP Mode (for Web Applications)

Start the server with `mimobox-mcp --transport http --port 8080`, then configure:

```json
{
  "mcpServers": {
    "mimobox": {
      "url": "http://localhost:8080/mcp",
      "transport": "streamable-http"
    }
  }
}
```
