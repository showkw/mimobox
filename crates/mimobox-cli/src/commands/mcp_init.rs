use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::*;

pub(crate) fn handle_mcp_init(args: McpInitArgs) -> Result<(), CliError> {
    let clients = if args.all {
        vec![McpClient::Claude, McpClient::Cursor, McpClient::Windsurf]
    } else {
        vec![
            args.client
                .ok_or_else(|| CliError::McpInit("missing MCP client".to_string()))?,
        ]
    };

    let home_dir = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| CliError::McpInit("HOME environment variable is not set".to_string()))?;
    let binary_path = resolve_mimobox_mcp_binary();

    for client in clients {
        let config_path = mcp_config_path(client, current_mcp_os(), &home_dir);
        configure_mcp_client(client, &config_path, &binary_path)?;
    }

    Ok(())
}

pub(crate) fn configure_mcp_client(
    client: McpClient,
    config_path: &Path,
    binary_path: &str,
) -> Result<(), CliError> {
    let existing_config = read_existing_mcp_config(config_path)?;
    let updated_config = inject_mcp_config(existing_config, binary_path)?;

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            CliError::McpInit(format!(
                "failed to create config directory {}: {error}",
                parent.display()
            ))
        })?;
    }

    let json = serde_json::to_string_pretty(&updated_config)?;
    fs::write(config_path, format!("{json}\n")).map_err(|error| {
        CliError::McpInit(format!(
            "failed to write MCP config {}: {error}",
            config_path.display()
        ))
    })?;

    println!("Configured mimobox-mcp for {}", client.display_name());
    println!("Config: {}", config_path.display());
    println!("Binary: {binary_path}");
    println!("Restart {} to apply changes.", client.display_name());

    Ok(())
}

pub(crate) fn read_existing_mcp_config(config_path: &Path) -> Result<serde_json::Value, CliError> {
    match fs::read_to_string(config_path) {
        Ok(content) => {
            if content.trim().is_empty() {
                Ok(serde_json::json!({}))
            } else {
                serde_json::from_str(&content).map_err(|error| {
                    CliError::McpInit(format!(
                        "failed to parse MCP config {}: {error}",
                        config_path.display()
                    ))
                })
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(serde_json::json!({})),
        Err(error) => Err(CliError::McpInit(format!(
            "failed to read MCP config {}: {error}",
            config_path.display()
        ))),
    }
}

pub(crate) fn inject_mcp_config(
    mut config: serde_json::Value,
    binary_path: &str,
) -> Result<serde_json::Value, CliError> {
    if !config.is_object() {
        config = serde_json::json!({});
    }

    let root = config
        .as_object_mut()
        .ok_or_else(|| CliError::McpInit("MCP config root must be a JSON object".to_string()))?;

    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if !servers.is_object() {
        *servers = serde_json::json!({});
    }

    let servers = servers
        .as_object_mut()
        .ok_or_else(|| CliError::McpInit("mcpServers must be a JSON object".to_string()))?;
    servers.insert(
        "mimobox-mcp".to_string(),
        serde_json::json!({
            "command": binary_path,
            "args": []
        }),
    );

    Ok(config)
}

pub(crate) fn resolve_mimobox_mcp_binary() -> String {
    let binary_name = "mimobox-mcp";

    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|path| path.join(binary_name))
                .find(|candidate| candidate.is_file())
        })
        .and_then(|path| fs::canonicalize(&path).ok().or(Some(path)))
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| binary_name.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpOs {
    Macos,
    Linux,
}

pub(crate) fn current_mcp_os() -> McpOs {
    if cfg!(target_os = "macos") {
        McpOs::Macos
    } else {
        McpOs::Linux
    }
}

pub(crate) fn mcp_config_path(client: McpClient, os: McpOs, home_dir: &Path) -> PathBuf {
    match client {
        McpClient::Claude => match os {
            McpOs::Macos => home_dir
                .join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json"),
            McpOs::Linux => home_dir
                .join(".config")
                .join("Claude")
                .join("claude_desktop_config.json"),
        },
        McpClient::Cursor => home_dir.join(".cursor").join("mcp.json"),
        McpClient::Windsurf => home_dir
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
    }
}

impl McpClient {
    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Self::Claude => "Claude",
            Self::Cursor => "Cursor",
            Self::Windsurf => "Windsurf",
        }
    }
}
