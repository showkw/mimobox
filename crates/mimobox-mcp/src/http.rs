//! HTTP 传输模块，提供 MCP Streamable HTTP 端点。

use std::{
    error::Error,
    io,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use rmcp::transport::{
    StreamableHttpServerConfig, StreamableHttpService,
    streamable_http_server::session::local::LocalSessionManager,
};
use tokio::signal::unix::{SignalKind, signal};

use crate::MimoboxServer;

type HttpResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
type McpHttpService = StreamableHttpService<MimoboxServer, LocalSessionManager>;
type ServerRegistry = Arc<Mutex<Vec<MimoboxServer>>>;
type AllowedOrigins = Arc<Vec<String>>;

/// HTTP stateful session 最多保留 100 个 server handle，限制 registry 内存增长。
const MAX_CONCURRENT_SESSIONS: usize = 100;
/// CORS 通配符仅允许精确的 "*" 项，避免误把带星号的字符串当成全开放。
const WILDCARD_ORIGIN: &str = "*";

/// 启动 MCP HTTP 服务器。
pub async fn run_http_server(
    bind_addr: &str,
    port: u16,
    allowed_origins: Option<String>,
    auth_token: Option<String>,
) -> HttpResult<()> {
    let is_local_bind = is_local_bind_addr(bind_addr);
    if auth_token.is_none() && !is_local_bind {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "MCP HTTP 绑定到非本地地址但没有配置认证。请设置 --auth-token 或 MIMOBOX_AUTH_TOKEN 环境变量",
        )
        .into());
    }

    if auth_token.is_some() {
        tracing::info!("MCP HTTP 模式已启用 Bearer token 认证");
    } else {
        tracing::warn!("HTTP 模式未启用认证，请勿在公网环境直接暴露。仅限本地开发和受信网络使用。");
    }
    if !is_local_bind {
        tracing::warn!(
            bind_addr,
            "MCP HTTP 绑定地址不是本地回环地址，可能暴露到不受信网络"
        );
    }

    // SECURITY: 在服务启动时即拒绝空 token 配置，避免配置失误导致认证旁路。
    if auth_token
        .as_ref()
        .is_some_and(|token| token.trim().is_empty())
    {
        let msg = "auth_token 不能为空字符串或纯空白字符";
        tracing::error!("{msg}");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, msg).into());
    }

    let allowed_origins = Arc::new(parse_allowed_origins(allowed_origins));
    let auth_token = auth_token.map(Arc::new);
    let server_registry = Arc::new(Mutex::new(Vec::new()));
    let service = create_mcp_service(server_registry.clone(), bind_addr);
    let app = Router::new()
        .route_service("/mcp", service)
        .layer(axum::middleware::from_fn_with_state(
            auth_token,
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            allowed_origins,
            cors_middleware,
        ));

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
        let evicted = servers.remove(0);
        tracing::warn!("Evicting oldest MCP session, cleaning up its sandboxes");
        tokio::spawn(async move {
            evicted.cleanup_all().await;
        });
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

fn parse_allowed_origins(allowed_origins: Option<String>) -> Vec<String> {
    match allowed_origins {
        Some(origins)
            if origins
                .split(',')
                .map(str::trim)
                .any(|o| o == WILDCARD_ORIGIN) =>
        {
            tracing::warn!("CORS 配置为完全开放模式(*)，请勿在生产环境使用");
            vec![WILDCARD_ORIGIN.to_string()]
        }
        Some(origins) => {
            let parsed = origins
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            warn_non_local_origins(&parsed);
            parsed
        }
        None => vec![
            "http://localhost".to_string(),
            "http://127.0.0.1".to_string(),
        ],
    }
}

fn warn_non_local_origins(origins: &[String]) {
    for origin in origins {
        if !is_local_origin(origin) {
            tracing::warn!(origin, "CORS 允许非本地 origin，请确认仅用于受信客户端");
        }
    }
}

fn is_local_origin(origin: &str) -> bool {
    let Some(host_part) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };

    let host_with_port = match host_part.split('/').next() {
        Some(host_with_port) => host_with_port,
        None => host_part,
    };
    let host = if let Some(ipv6_part) = host_with_port.strip_prefix('[') {
        match ipv6_part.split_once(']') {
            Some((host, _)) => host,
            None => host_with_port,
        }
    } else {
        match host_with_port.split_once(':') {
            Some((host, _)) => host,
            None => host_with_port,
        }
    };

    matches!(host, "localhost" | "127.0.0.1" | "::1")
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

async fn cors_middleware(
    State(allowed_origins): State<AllowedOrigins>,
    req: Request,
    next: Next,
) -> Response {
    let allowed_origin = allowed_origin_header(req.headers(), allowed_origins.as_slice()).cloned();

    if req.method() == Method::OPTIONS {
        return cors_response(allowed_origin.as_ref());
    }

    let mut response = next.run(req).await;
    apply_cors_headers(response.headers_mut(), allowed_origin.as_ref());
    response
}

fn cors_response(allowed_origin: Option<&HeaderValue>) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    apply_cors_headers(response.headers_mut(), allowed_origin);
    response
}

fn allowed_origin_header<'a>(
    headers: &'a HeaderMap,
    allowed_origins: &[String],
) -> Option<&'a HeaderValue> {
    let origin = headers.get(HeaderName::from_static("origin"))?;
    if is_origin_allowed(origin, allowed_origins) {
        Some(origin)
    } else {
        None
    }
}

fn is_origin_allowed(origin: &HeaderValue, allowed_origins: &[String]) -> bool {
    if allowed_origins
        .iter()
        .any(|allowed_origin| allowed_origin == WILDCARD_ORIGIN)
    {
        return true;
    }

    let Ok(origin) = origin.to_str() else {
        return false;
    };

    allowed_origins
        .iter()
        .any(|allowed_origin| allowed_origin == origin)
}

fn apply_cors_headers(headers: &mut HeaderMap, allowed_origin: Option<&HeaderValue>) {
    if let Some(origin) = allowed_origin {
        headers.insert(
            HeaderName::from_static("access-control-allow-origin"),
            origin.clone(),
        );
    }
    headers.insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
    );
    headers.insert(
        HeaderName::from_static("access-control-allow-headers"),
        HeaderValue::from_static(
            "Content-Type, Accept, Authorization, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID",
        ),
    );
    headers.insert(
        HeaderName::from_static("access-control-expose-headers"),
        HeaderValue::from_static("Mcp-Session-Id, Mcp-Protocol-Version"),
    );
}

async fn auth_middleware(
    State(auth_token): State<Option<Arc<String>>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(expected_token) = auth_token else {
        return next.run(req).await;
    };

    // SECURITY: 拒绝空/纯空白 token，防止配置失误导致认证旁路。
    if expected_token.trim().is_empty() {
        tracing::error!("auth_token 配置为空字符串，拒绝所有请求");
        return unauthorized_response();
    }

    if bearer_token(req.headers())
        .is_some_and(|token| constant_time_eq(token.as_bytes(), expected_token.as_bytes()))
    {
        return next.run(req).await;
    }

    unauthorized_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let authorization = headers
        .get(HeaderName::from_static("authorization"))?
        .to_str()
        .ok()?;
    let (scheme, token) = authorization.split_once(' ')?;

    if scheme == "Bearer" {
        Some(token)
    } else {
        None
    }
}

fn unauthorized_response() -> Response {
    let mut response = Response::new(Body::from(r#"{"error":"unauthorized"}"#));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/json"),
    );
    response
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_http_server_rejects_non_loopback_without_token() {
        let err = run_http_server("0.0.0.0", 0, None, None)
            .await
            .expect_err("非 loopback 地址且无 token 时必须拒绝启动");
        let io_err = err
            .downcast_ref::<std::io::Error>()
            .expect("拒绝启动必须返回 I/O 权限错误");

        assert_eq!(io_err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_run_http_server_rejects_blank_token() {
        let err = run_http_server("127.0.0.1", 0, None, Some(" \t ".to_string()))
            .await
            .expect_err("SECURITY: 空白 token 必须 fail-closed 拒绝启动");
        let io_err = err
            .downcast_ref::<std::io::Error>()
            .expect("空白 token 应返回 I/O 配置错误");

        assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_parse_allowed_origins_wildcard_requires_exact_segment() {
        let origins = parse_allowed_origins(Some("https://*.example.com".to_string()));

        assert_eq!(origins, vec!["https://*.example.com".to_string()]);
    }

    #[test]
    fn test_parse_allowed_origins_accepts_exact_wildcard_segment() {
        let origins = parse_allowed_origins(Some("http://localhost:3000, *".to_string()));

        assert_eq!(origins, vec![WILDCARD_ORIGIN.to_string()]);
    }

    #[test]
    fn test_constant_time_eq_matches_equal_bytes() {
        assert!(constant_time_eq(b"token", b"token"));
    }

    #[test]
    fn test_constant_time_eq_rejects_different_bytes() {
        assert!(!constant_time_eq(b"token", b"t0ken"));
    }

    #[test]
    fn test_constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq(b"token", b"token-extra"));
    }
}
