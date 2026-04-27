# MCP 配置模板

mimobox MCP Server 支持多种 AI 编码工具和平台。以下为各平台的配置模板。

## Claude Desktop

配置文件路径：
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

在 Cursor Settings > MCP 中添加：

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

## HTTP 模式（适合 Web 应用）

先启动 mimobox-mcp --transport http --port 8080，然后配置：

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
