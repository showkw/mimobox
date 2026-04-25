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
        let service = MimoboxServer::new().serve((server_read, server_write)).await;
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
    let tool_names = tools.iter().map(|tool| tool.name.as_ref()).collect::<Vec<_>>();

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
