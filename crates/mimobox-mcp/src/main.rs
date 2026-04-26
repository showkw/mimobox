use clap::Parser;
use mimobox_mcp::MimoboxServer;
use rmcp::ServiceExt;
use tokio::signal::unix::{SignalKind, signal};

mod http;

type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser)]
#[command(name = "mimobox-mcp", about = "mimobox MCP Server")]
struct Cli {
    /// 传输模式：stdio（默认）或 http
    #[arg(long, default_value = "stdio")]
    transport: String,

    /// HTTP 监听端口（仅 HTTP 模式）
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// HTTP 绑定地址（仅 HTTP 模式，默认仅允许本地访问）
    #[arg(long, default_value = "127.0.0.1")]
    bind_addr: String,
}

#[tokio::main]
async fn main() -> AppResult<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(cli.port);

    match cli.transport.as_str() {
        "stdio" => run_stdio().await,
        "http" => http::run_http_server(&cli.bind_addr, port).await,
        _ => {
            tracing::error!("不支持的传输模式: {}，请使用 stdio 或 http", cli.transport);
            std::process::exit(1);
        }
    }
}

async fn run_stdio() -> AppResult<()> {
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
