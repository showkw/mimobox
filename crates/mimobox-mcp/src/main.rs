use clap::Parser;
use mimobox_mcp::{MimoboxServer, http};
use rmcp::ServiceExt;
use tokio::signal::unix::{SignalKind, signal};

type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser)]
#[command(name = "mimobox-mcp", about = "mimobox MCP Server")]
struct Cli {
    /// Transport mode: stdio (default) or http
    #[arg(long, default_value = "stdio")]
    transport: String,

    /// HTTP listen port (HTTP mode only)
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// HTTP bind address (HTTP mode only, local access by default)
    #[arg(long, default_value = "127.0.0.1")]
    bind_addr: String,

    /// Comma-separated list of CORS allowed origins, e.g. 'http://localhost:3000,http://localhost:8080'. Defaults to localhost.
    #[arg(long)]
    allowed_origins: Option<String>,

    /// HTTP Bearer token for authentication, also configurable via MIMOBOX_AUTH_TOKEN
    #[arg(long = "auth-token", env = "MIMOBOX_AUTH_TOKEN")]
    auth_token: Option<String>,
}

#[tokio::main]
async fn main() -> AppResult<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let bind_ip: std::net::IpAddr = cli.bind_addr.parse().map_err(|error| {
        Box::<dyn std::error::Error + Send + Sync>::from(format!("invalid bind_addr: {error}"))
    })?;
    if !bind_ip.is_loopback() {
        tracing::warn!(
            "MCP server is bound to non-loopback address {}; any network client can connect and execute code. Bind to 127.0.0.1 unless this is intentional.",
            bind_ip
        );
    }

    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(cli.port);

    match cli.transport.as_str() {
        "stdio" => run_stdio().await,
        "http" => {
            http::run_http_server(&cli.bind_addr, port, cli.allowed_origins, cli.auth_token).await
        }
        _ => {
            tracing::error!(
                "unsupported transport mode: {}; use stdio or http",
                cli.transport
            );
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
