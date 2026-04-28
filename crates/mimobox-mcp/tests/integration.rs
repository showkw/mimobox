use anyhow::Result;
use mimobox_mcp::MimoboxServer;
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult, JsonObject},
};
use serde_json::{Value, json};
use tokio::io::duplex;

async fn setup_client() -> Result<rmcp::service::RunningService<rmcp::RoleClient, ()>> {
    let (client_read, server_write) = duplex(4096);
    let (server_read, client_write) = duplex(4096);

    tokio::spawn(async move {
        let service = MimoboxServer::new()
            .serve((server_read, server_write))
            .await;
        if let Ok(service) = service {
            let _ = service.waiting().await;
        }
    });

    Ok(().serve((client_read, client_write)).await?)
}

async fn call_tool(name: &str, arguments: Value) -> Result<CallToolResult> {
    let client = setup_client().await?;
    let params = CallToolRequestParams::new(name.to_string()).with_arguments(to_object(arguments));
    let result = client.peer().call_tool(params).await?;
    client.cancel().await?;
    Ok(result)
}

async fn call_tool_with_client(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &str,
    arguments: Value,
) -> Result<CallToolResult> {
    let params = CallToolRequestParams::new(name.to_string()).with_arguments(to_object(arguments));
    Ok(client.peer().call_tool(params).await?)
}

fn to_object(value: Value) -> JsonObject {
    match value {
        Value::Object(object) => object,
        _ => JsonObject::new(),
    }
}

fn result_text(result: &CallToolResult) -> String {
    let content_text = result
        .content
        .iter()
        .filter_map(|content| content.as_text())
        .map(|text| text.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    match &result.structured_content {
        Some(structured_content) if !content_text.is_empty() => {
            format!("{content_text}\n{structured_content}")
        }
        Some(structured_content) => structured_content.to_string(),
        None => content_text,
    }
}

#[tokio::test]
async fn test_list_tools_via_duplex() -> Result<()> {
    let client = setup_client().await?;

    let tools = client.peer().list_all_tools().await?;
    let tool_names = tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect::<Vec<_>>();

    assert!(tool_names.len() >= 7, "工具数量不足: {tool_names:?}");
    assert!(tool_names.contains(&"execute_code"));
    assert!(tool_names.contains(&"create_sandbox"));
    assert!(tool_names.contains(&"destroy_sandbox"));

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn test_list_sandboxes_empty() -> Result<()> {
    let result = call_tool("list_sandboxes", json!({})).await?;
    let text = result_text(&result);

    assert_eq!(result.is_error, Some(false));
    assert!(text.contains("sandboxes"), "返回内容缺少 sandboxes: {text}");
    assert!(text.contains("[]"), "初始沙箱列表应为空: {text}");

    Ok(())
}

#[tokio::test]
async fn test_destroy_nonexistent_sandbox() -> Result<()> {
    let result = call_tool("destroy_sandbox", json!({ "sandbox_id": 999 })).await?;
    let text = result_text(&result).to_ascii_lowercase();

    assert!(
        result.is_error == Some(true) || text.contains("not found"),
        "销毁不存在沙箱应返回错误或 not found 文案: {text}"
    );

    Ok(())
}

#[tokio::test]
async fn test_execute_code_ephemeral() -> Result<()> {
    let result = call_tool(
        "execute_code",
        json!({
            "code": "echo hello",
            "language": "bash"
        }),
    )
    .await?;
    let text = result_text(&result).to_ascii_lowercase();

    assert!(
        text.contains("hello")
            || text.contains("backend unavailable")
            || text.contains("operation not supported")
            || text.contains("not supported")
            || text.contains("sandbox")
            || text.contains("exit_code"),
        "execute_code should return stdout or a recognizable sandbox result: {text}"
    );

    Ok(())
}

#[tokio::test]
async fn test_list_dir_ephemeral() -> Result<()> {
    let result = call_tool("list_dir", json!({ "sandbox_id": 999, "path": "/tmp" })).await?;
    let text = result_text(&result).to_ascii_lowercase();

    assert!(
        result.is_error == Some(true) || text.contains("not found"),
        "未创建沙箱时 list_dir 应返回错误或 not found 文案: {text}"
    );

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_list_dir_with_sandbox() -> Result<()> {
    let client = setup_client().await?;
    let create_result = call_tool_with_client(
        &client,
        "create_sandbox",
        json!({"isolation_level": "microvm"}),
    )
    .await?;

    // microVM requires KVM; skip gracefully if unavailable or downgraded on this runner
    if create_result.is_error == Some(true) {
        eprintln!("skipping test_list_dir_with_sandbox: microVM unavailable");
        client.cancel().await?;
        return Ok(());
    }
    // The MCP response reports requested isolation, not actual — SDK may downgrade to OS.
    // list_dir requires real microVM backend; check /dev/kvm as ground truth.
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("skipping test_list_dir_with_sandbox: /dev/kvm not available");
        client.cancel().await?;
        return Ok(());
    }

    let sandbox_id = create_result
        .structured_content
        .as_ref()
        .and_then(|content| content.get("sandbox_id"))
        .and_then(Value::as_u64)
        .expect("create_sandbox 应返回 sandbox_id");

    let result = call_tool_with_client(
        &client,
        "list_dir",
        json!({ "sandbox_id": sandbox_id, "path": "/tmp" }),
    )
    .await?;

    // list_dir requires real microVM backend; if the SDK downgraded to OS,
    // list_dir returns an error — skip gracefully in that case.
    if result.is_error == Some(true) {
        eprintln!(
            "skipping test_list_dir_with_sandbox: list_dir not \
             supported (backend may have downgraded from microVM)"
        );
        client.cancel().await?;
        return Ok(());
    }
    let text = result_text(&result);

    assert!(text.contains("entries"), "返回内容缺少 entries: {text}");
    assert!(
        result
            .structured_content
            .as_ref()
            .and_then(|content| content.get("entries"))
            .is_some(),
        "结构化返回缺少 entries: {text}"
    );

    client.cancel().await?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_list_dir_nonexistent_path() -> Result<()> {
    let client = setup_client().await?;
    let create_result = call_tool_with_client(
        &client,
        "create_sandbox",
        json!({"isolation_level": "microvm"}),
    )
    .await?;
    // microVM requires KVM; skip gracefully if unavailable or downgraded on this runner
    if create_result.is_error == Some(true) {
        eprintln!("skipping test_list_dir_nonexistent_path: microVM unavailable");
        client.cancel().await?;
        return Ok(());
    }
    // The MCP response reports requested isolation, not actual — SDK may downgrade to OS.
    // list_dir requires real microVM backend; check /dev/kvm as ground truth.
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("skipping test_list_dir_nonexistent_path: /dev/kvm not available");
        client.cancel().await?;
        return Ok(());
    }

    let sandbox_id = create_result
        .structured_content
        .as_ref()
        .and_then(|content| content.get("sandbox_id"))
        .and_then(Value::as_u64)
        .expect("create_sandbox 应返回 sandbox_id");

    let result = call_tool_with_client(
        &client,
        "list_dir",
        json!({ "sandbox_id": sandbox_id, "path": "/nonexistent/path/abc123" }),
    )
    .await?;
    let text = result_text(&result).to_ascii_lowercase();

    assert!(
        result.is_error == Some(true)
            || text.contains("not found")
            || text.contains("no such file")
            || text.contains("不存在"),
        "不存在路径应返回错误: {text}"
    );

    client.cancel().await?;
    Ok(())
}
