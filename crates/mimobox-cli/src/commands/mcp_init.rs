use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::*;

/// Handles the mcp init request.
pub(crate) fn handle_mcp_init(args: McpInitArgs) -> Result<(), CliError> {
    let clients = if args.all {
        vec![
            McpClient::Claude,
            McpClient::ClaudeCode,
            McpClient::Cursor,
            McpClient::Windsurf,
        ]
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

/// Provides the configure mcp client operation.
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
    backup_mcp_config(config_path)?;
    write_mcp_config_atomically(config_path, &format!("{json}\n"))?;

    println!("Configured mimobox-mcp for {}", client.display_name());
    println!("Config: {}", config_path.display());
    println!("Binary: {binary_path}");
    println!("Restart {} to apply changes.", client.display_name());

    Ok(())
}

/// Provides the read existing mcp config operation.
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

/// Provides the inject mcp config operation.
pub(crate) fn inject_mcp_config(
    mut config: serde_json::Value,
    binary_path: &str,
) -> Result<serde_json::Value, CliError> {
    if !config.is_object() {
        return Err(CliError::McpInit(
            "MCP config root must be a JSON object".to_string(),
        ));
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

/// Resolves the mimobox mcp binary value.
pub(crate) fn resolve_mimobox_mcp_binary() -> String {
    let binary_name = "mimobox-mcp";

    let Some(resolved_path) = std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|path| path.join(binary_name))
                .find(|candidate| candidate.is_file())
        })
        .map(|path| fs::canonicalize(&path).unwrap_or(path))
    else {
        return binary_name.to_string();
    };

    warn_if_mcp_binary_outside_cli_dir(&resolved_path);
    resolved_path.to_string_lossy().into_owned()
}

fn backup_mcp_config(config_path: &Path) -> Result<(), CliError> {
    if !config_path.exists() {
        return Ok(());
    }

    let backup_path = path_with_suffix(config_path, ".bak");
    fs::copy(config_path, &backup_path).map_err(|error| {
        CliError::McpInit(format!(
            "failed to create MCP config backup {}: {error}",
            backup_path.display()
        ))
    })?;

    Ok(())
}

fn write_mcp_config_atomically(config_path: &Path, content: &str) -> Result<(), CliError> {
    let tmp_path = path_with_suffix(config_path, &format!(".{}.tmp", std::process::id()));
    fs::write(&tmp_path, content).map_err(|error| {
        CliError::McpInit(format!(
            "failed to write temporary MCP config {}: {error}",
            tmp_path.display()
        ))
    })?;

    fs::rename(&tmp_path, config_path).map_err(|error| {
        CliError::McpInit(format!(
            "failed to replace MCP config {}: {error}",
            config_path.display()
        ))
    })?;

    // MCP 配置文件包含工具路径，限制为当前用户独占读写
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(config_path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            CliError::McpInit(format!(
                "failed to set permissions on MCP config {}: {error}",
                config_path.display()
            ))
        })?;
    }

    Ok(())
}

fn warn_if_mcp_binary_outside_cli_dir(binary_path: &Path) {
    let Some(expected_prefix) = std::env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok())
        .and_then(|path| path.parent().map(Path::to_path_buf))
    else {
        return;
    };

    if !binary_path.starts_with(&expected_prefix) {
        tracing::warn!(
            binary_path = %binary_path.display(),
            expected_prefix = %expected_prefix.display(),
            "resolved mimobox-mcp binary is outside the CLI executable directory"
        );
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpOs {
    Macos,
    Linux,
}

/// Returns the current mcp os value.
pub(crate) fn current_mcp_os() -> McpOs {
    if cfg!(target_os = "macos") {
        McpOs::Macos
    } else {
        McpOs::Linux
    }
}

/// Provides the mcp config path operation.
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
        McpClient::ClaudeCode => home_dir.join(".claude").join("settings.json"),
        McpClient::Cursor => home_dir.join(".cursor").join("mcp.json"),
        McpClient::Windsurf => home_dir
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
    }
}

impl McpClient {
    /// Provides the display name operation.
    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Self::Claude => "Claude",
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
            Self::Windsurf => "Windsurf",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_code_display_name_is_human_readable() {
        assert_eq!(McpClient::ClaudeCode.display_name(), "Claude Code");
    }

    #[test]
    fn inject_mcp_config_rejects_non_object_root() {
        let error = inject_mcp_config(serde_json::json!(["not", "object"]), "/bin/mimobox-mcp")
            .expect_err("non-object MCP config root should be rejected");

        assert_eq!(error.code(), "mcp_init_error");
        assert!(
            error
                .to_string()
                .contains("MCP config root must be a JSON object")
        );
    }
}
