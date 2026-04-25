use mimobox_mcp::MimoboxServer;
use rmcp::ServiceExt;
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    tracing::info!("mimobox MCP stdio server starting");

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
            tracing::info!("Received SIGTERM, cleaning up sandboxes...");
            cleanup_handle.cleanup_all().await;
        }
        _ = sigint.recv() => {
            tracing::info!("Received SIGINT, cleaning up sandboxes...");
            cleanup_handle.cleanup_all().await;
        }
    }

    tracing::info!("mimobox MCP stdio server exiting");

    Ok(())
}
