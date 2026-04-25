use mimobox_mcp::MimoboxServer;
use rmcp::ServiceExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    tracing::info!("mimobox MCP stdio server 启动");
    MimoboxServer::new()
        .serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    tracing::info!("mimobox MCP stdio server 退出");

    Ok(())
}
