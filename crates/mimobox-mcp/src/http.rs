//! HTTP 传输模块，提供 MCP Streamable HTTP 端点。

use std::{
    error::Error,
    io,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use mimobox_mcp::MimoboxServer;
use rmcp::transport::{
    StreamableHttpServerConfig, StreamableHttpService,
    streamable_http_server::session::local::LocalSessionManager,
};
use tokio::signal::unix::{SignalKind, signal};

type HttpResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
type McpHttpService = StreamableHttpService<MimoboxServer, LocalSessionManager>;
type ServerRegistry = Arc<Mutex<Vec<MimoboxServer>>>;

const MAX_CONCURRENT_SESSIONS: usize = 100;

/// 启动 MCP HTTP 服务器。
pub async fn run_http_server(bind_addr: &str, port: u16) -> HttpResult<()> {
    tracing::warn!("HTTP 模式未启用认证，请勿在公网环境直接暴露。仅限本地开发和受信网络使用。");
    if !is_local_bind_addr(bind_addr) {
        tracing::warn!(
            bind_addr,
            "MCP HTTP 绑定地址不是本地回环地址，可能暴露到不受信网络"
        );
    }

    let server_registry = Arc::new(Mutex::new(Vec::new()));
    let service = create_mcp_service(server_registry.clone(), bind_addr);
    let app = Router::new()
        .route_service("/mcp", service)
        .layer(axum::middleware::from_fn(cors_middleware));

    let listener = tokio::net::TcpListener::bind((bind_addr, port)).await?;
    let local_addr = listener.local_addr()?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tracing::info!("MCP HTTP server listening on {local_addr}");
    tracing::info!("MCP endpoint: http://{local_addr}/mcp");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("Received SIGTERM, cleaning up sandboxes...");
                }
                _ = sigint.recv() => {
                    tracing::info!("Received SIGINT, cleaning up sandboxes...");
                }
            }
            cleanup_registered_servers(server_registry).await;
        })
        .await?;

    Ok(())
}

fn create_mcp_service(server_registry: ServerRegistry, bind_addr: &str) -> McpHttpService {
    let session_manager = Arc::new(LocalSessionManager::default());
    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(true)
        .with_allowed_hosts(allowed_hosts(bind_addr));

    StreamableHttpService::new(
        move || {
            let server = MimoboxServer::new();
            register_server(&server_registry, server.clone())?;
            Ok(server)
        },
        session_manager,
        config,
    )
}

fn register_server(server_registry: &ServerRegistry, server: MimoboxServer) -> io::Result<()> {
    let mut servers = server_registry
        .lock()
        .map_err(|_| io::Error::other("MCP HTTP server registry lock poisoned"))?;
    if servers.len() >= MAX_CONCURRENT_SESSIONS {
        tracing::warn!(
            max_sessions = MAX_CONCURRENT_SESSIONS,
            "MCP HTTP session registry 已达到上限，移除最早的 server handle"
        );
        drop(servers.remove(0));
    }
    servers.push(server);
    Ok(())
}

fn is_local_bind_addr(bind_addr: &str) -> bool {
    matches!(bind_addr, "127.0.0.1" | "::1")
}

fn allowed_hosts(bind_addr: &str) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if !hosts.iter().any(|host| host == bind_addr) {
        hosts.push(bind_addr.to_string());
    }
    hosts
}

async fn cleanup_registered_servers(server_registry: ServerRegistry) {
    let servers = match server_registry.lock() {
        Ok(mut servers) => std::mem::take(&mut *servers),
        Err(_) => {
            tracing::error!("MCP HTTP server registry lock poisoned, skip sandbox cleanup");
            return;
        }
    };

    for server in servers {
        server.cleanup_all().await;
    }
}

async fn cors_middleware(req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return cors_response();
    }

    let mut response = next.run(req).await;
    apply_cors_headers(response.headers_mut());
    response
}

fn cors_response() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    apply_cors_headers(response.headers_mut());
    response
}

fn apply_cors_headers(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("access-control-allow-origin"),
        HeaderValue::from_static("*"),
    );
    headers.insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
    );
    headers.insert(
        HeaderName::from_static("access-control-allow-headers"),
        HeaderValue::from_static(
            "Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID",
        ),
    );
    headers.insert(
        HeaderName::from_static("access-control-expose-headers"),
        HeaderValue::from_static("Mcp-Session-Id, Mcp-Protocol-Version"),
    );
}
