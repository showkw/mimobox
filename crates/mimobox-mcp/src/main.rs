use mimobox_mcp::MimoboxServer;
use rmcp::ServiceExt;
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    tracing::info!("mimobox MCP stdio server 启动");

    let server = MimoboxServer::new();
    let cleanup_handle = server.clone();
    let service = server.serve(rmcp::transport::stdio()).await?;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        result = service.waiting() => {
            result?;
        }
        _ = sigterm.recv() => {
            tracing::info!("收到 SIGTERM，开始清理 sandboxes...");
            cleanup_handle.cleanup_all().await;
        }
        _ = sigint.recv() => {
            tracing::info!("收到 SIGINT，开始清理 sandboxes...");
            cleanup_handle.cleanup_all().await;
        }
    }

    tracing::info!("mimobox MCP stdio server 退出");

    Ok(())
}
