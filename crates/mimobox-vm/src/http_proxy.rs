#![cfg_attr(not(all(target_os = "linux", feature = "kvm")), allow(dead_code))]

use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use mimobox_core::{HttpAclPolicy, HttpMethod, SandboxConfig, normalize_path};
use reqwest::Method;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
/// Maximum size of a single header value is 8 KB to prevent guest-driven host memory exhaustion.
const MAX_HEADER_SIZE: usize = 8 * 1024;
/// Maximum combined header key and value size is 64 KB to bound proxy memory usage.
const MAX_TOTAL_HEADERS_SIZE: usize = 64 * 1024;
/// Maximum header count is 64 to prevent many small headers from bypassing the total-size limit.
const MAX_HEADER_COUNT: usize = 64;
/// Allowed HTTP method allowlist. CONNECT can be used for proxy tunneling, and TRACE can enable XST attacks.
/// PUT/PATCH/DELETE are kept to support common REST API calls.
/// Note: this list must stay in sync with `mimobox_core::HttpMethod` variants.
/// When `HttpMethod` adds a new method, this list must be updated as well.
const ALLOWED_METHODS: &[&[u8]] = &[b"GET", b"HEAD", b"POST", b"PUT", b"PATCH", b"DELETE"];
/// Hop-by-hop and sensitive header blocklist. These headers are filtered before forwarding
/// to prevent proxy tunneling and information leaks.
/// - Host: force the host from the URL to prevent Host header injection.
/// - Connection/Keep-Alive/TE/Trailers/Upgrade: hop-by-hop headers that proxies should not forward.
/// - Proxy-Authorization/Proxy-Connection: proxy authentication headers that could leak credentials.
/// - Transfer-Encoding: let reqwest manage chunked encoding.
const BLOCKED_HEADERS: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "te",
    "trailers",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
    "transfer-encoding",
];
/// Absolute cap for HTTP response bodies (100 MB); guest-provided `max_response_bytes` cannot exceed it.
const MAX_RESPONSE_BYTES_HARD_LIMIT: usize = 100 * 1024 * 1024;
/// Absolute cap for HTTP request timeout (5 minutes); guest-provided `timeout_ms` cannot exceed it.
const MAX_TIMEOUT_MS_HARD_LIMIT: u64 = 300_000;
/// Maximum response header count to prevent malicious servers from exhausting host memory.
const MAX_RESPONSE_HEADER_COUNT: usize = 100;
/// Maximum size of a single response header value is 8 KB.
const MAX_RESPONSE_HEADER_VALUE_BYTES: usize = 8192;

/// Raw JSON payload accepted by the guest-to-host HTTP proxy protocol.
///
/// Guests use this shape when sending serialized HTTP requests over the command
/// protocol. The payload is decoded and normalized into [`HttpRequest`] before any
/// host network access is attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProxyRequestPayload {
    /// HTTP method supplied by the guest, such as `GET` or `POST`.
    pub method: String,
    /// Target HTTPS URL supplied by the guest.
    pub url: String,
    /// Request headers supplied by the guest.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Optional base64-encoded request body.
    #[serde(default)]
    pub body_b64: Option<String>,
    /// Optional request timeout in milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Optional maximum response body size in bytes.
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
}

/// Validated and normalized HTTP proxy request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP method to send on the host side, such as `GET` or `POST`.
    pub method: String,
    /// Target HTTPS URL after guest payload normalization.
    pub url: String,
    /// Request headers to forward to the target server.
    pub headers: HashMap<String, String>,
    /// Optional raw request body bytes.
    pub body: Option<Vec<u8>>,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum response body size allowed before the proxy aborts the read.
    pub max_response_bytes: usize,
}

/// HTTP response returned by the host-controlled proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Numeric HTTP status code returned by the target server.
    pub status: u16,
    /// Response headers returned by the target server.
    pub headers: HashMap<String, String>,
    /// Response body bytes, capped by the originating request limit.
    pub body: Vec<u8>,
}

/// Error returned by the host-controlled HTTP proxy.
#[derive(Debug, thiserror::Error)]
pub enum HttpProxyError {
    /// Target host is not in the allowlist.
    #[error("domain not in whitelist: {0}")]
    DeniedHost(
        /// Hostname rejected by the configured allowlist.
        String,
    ),
    /// HTTP request denied by ACL policy.
    #[error("HTTP ACL denied: {0}")]
    DeniedAcl(
        /// ACL denial detail including method/host/path.
        String,
    ),
    /// Request exceeded its timeout.
    #[error("HTTP request timed out")]
    Timeout,
    /// Request or response body exceeded the size limit.
    #[error("HTTP body exceeds size limit")]
    BodyTooLarge,
    /// Failed to connect to the target server.
    #[error("HTTP connection failed: {0}")]
    ConnectFail(
        /// Connection failure detail from the HTTP client or DNS resolver.
        String,
    ),
    /// TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    TlsFail(
        /// TLS failure detail from the HTTP client.
        String,
    ),
    /// Request URL is invalid.
    #[error("invalid URL: {0}")]
    InvalidUrl(
        /// URL parsing or validation failure detail.
        String,
    ),
    /// DNS resolved to a private or reserved address.
    #[error("DNS resolution hit private address: {0}")]
    DnsRebind(
        /// DNS rebinding guard failure detail.
        String,
    ),
    /// Proxy execution failed internally.
    #[error("HTTP proxy internal error: {0}")]
    Internal(
        /// Internal proxy failure detail.
        String,
    ),
}

impl HttpProxyError {
    /// Returns the stable protocol error code for this proxy failure.
    pub fn code(&self) -> &'static str {
        match self {
            Self::DeniedHost(_) => "DENIED_HOST",
            Self::DeniedAcl(_) => "DENIED_ACL",
            Self::Timeout => "TIMEOUT",
            Self::BodyTooLarge => "BODY_TOO_LARGE",
            Self::ConnectFail(_) => "CONNECT_FAIL",
            Self::TlsFail(_) => "TLS_FAIL",
            Self::InvalidUrl(_) => "INVALID_URL",
            Self::DnsRebind(_) => "DNS_REBIND",
            Self::Internal(_) => "INTERNAL",
        }
    }
}

impl TryFrom<HttpProxyRequestPayload> for HttpRequest {
    type Error = HttpProxyError;

    fn try_from(value: HttpProxyRequestPayload) -> Result<Self, Self::Error> {
        let body = match value.body_b64 {
            Some(encoded) => {
                let bytes = BASE64_STANDARD.decode(encoded).map_err(|err| {
                    HttpProxyError::InvalidUrl(format!("body_b64 is not valid base64: {err}"))
                })?;
                if bytes.len() > MAX_REQUEST_BODY_BYTES {
                    return Err(HttpProxyError::BodyTooLarge);
                }
                Some(bytes)
            }
            None => None,
        };

        // 校验 header 数量、单个 value 大小和总量，防止 guest 通过 header 耗尽 host 内存
        if value.headers.len() > MAX_HEADER_COUNT {
            return Err(HttpProxyError::Internal("too many headers".into()));
        }
        let mut total_header_size: usize = 0;
        for (key, val) in &value.headers {
            if val.len() > MAX_HEADER_SIZE {
                return Err(HttpProxyError::Internal("header value too large".into()));
            }
            total_header_size = total_header_size
                .saturating_add(key.len())
                .saturating_add(val.len());
        }
        if total_header_size > MAX_TOTAL_HEADERS_SIZE {
            return Err(HttpProxyError::Internal(
                "total headers size exceeds limit".into(),
            ));
        }

        Ok(Self {
            method: value.method,
            url: value.url,
            headers: value.headers,
            body,
            timeout_ms: value
                .timeout_ms
                .unwrap_or(DEFAULT_TIMEOUT_MS)
                .min(MAX_TIMEOUT_MS_HARD_LIMIT),
            max_response_bytes: value
                .max_response_bytes
                .unwrap_or(DEFAULT_MAX_RESPONSE_BYTES)
                .min(MAX_RESPONSE_BYTES_HARD_LIMIT),
        })
    }
}

impl HttpRequest {
    /// Constructs a new HTTP proxy request and applies default limits.
    ///
    /// The request body is rejected when it exceeds the maximum guest-to-host body
    /// size accepted by the proxy protocol.
    pub fn new(
        method: impl Into<String>,
        url: impl Into<String>,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
        timeout_ms: Option<u64>,
        max_response_bytes: Option<usize>,
    ) -> Result<Self, HttpProxyError> {
        let body = match body {
            Some(bytes) if bytes.len() > MAX_REQUEST_BODY_BYTES => {
                return Err(HttpProxyError::BodyTooLarge);
            }
            other => other,
        };

        // 校验 header 数量、单个 value 大小和总量，与 TryFrom 保持一致
        if headers.len() > MAX_HEADER_COUNT {
            return Err(HttpProxyError::Internal("too many headers".into()));
        }
        let mut total_header_size: usize = 0;
        for (key, val) in &headers {
            if val.len() > MAX_HEADER_SIZE {
                return Err(HttpProxyError::Internal("header value too large".into()));
            }
            total_header_size = total_header_size
                .saturating_add(key.len())
                .saturating_add(val.len());
        }
        if total_header_size > MAX_TOTAL_HEADERS_SIZE {
            return Err(HttpProxyError::Internal(
                "total headers size exceeds limit".into(),
            ));
        }

        Ok(Self {
            method: method.into(),
            url: url.into(),
            headers,
            body,
            timeout_ms: timeout_ms
                .unwrap_or(DEFAULT_TIMEOUT_MS)
                .min(MAX_TIMEOUT_MS_HARD_LIMIT),
            max_response_bytes: max_response_bytes
                .unwrap_or(DEFAULT_MAX_RESPONSE_BYTES)
                .min(MAX_RESPONSE_BYTES_HARD_LIMIT),
        })
    }

    /// Parses an HTTP proxy request from a guest JSON payload.
    ///
    /// Missing timeout and response-size fields are replaced with crate defaults.
    pub fn from_json(json: &str) -> Result<Self, HttpProxyError> {
        let payload = serde_json::from_str::<HttpProxyRequestPayload>(json).map_err(|err| {
            HttpProxyError::InvalidUrl(format!("invalid HTTP request JSON: {err}"))
        })?;
        Self::try_from(payload)
    }
}

/// Executes an HTTP request through the host-controlled proxy.
///
/// Only HTTPS URLs are accepted. Hostnames must match the sandbox allowlist, direct
/// IP literals are rejected, and DNS results must not resolve to loopback, private,
/// link-local, or unspecified addresses.
pub fn execute_http_request(
    config: &SandboxConfig,
    request: &HttpRequest,
) -> Result<HttpResponse, HttpProxyError> {
    let url = reqwest::Url::parse(&request.url)
        .map_err(|err| HttpProxyError::InvalidUrl(err.to_string()))?;
    validate_http_request(config, &url)?;
    validate_acl(&config.http_acl, &request.method, &url)?;
    let verified_ip = validate_dns_resolution(&url)?;
    let host = url
        .host_str()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL missing host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL missing port information".into()))?;
    let socket_addr = SocketAddr::new(verified_ip, port);
    let resolve_key = format!("{host}:{port}");

    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|err| HttpProxyError::InvalidUrl(format!("invalid HTTP method: {err}")))?;
    if !ALLOWED_METHODS.contains(&request.method.as_bytes()) {
        return Err(HttpProxyError::InvalidUrl(format!(
            "HTTP method not allowed: {} (blocked for security: CONNECT/TRACE are forbidden)",
            request.method
        )));
    }
    let timeout = Duration::from_millis(request.timeout_ms.max(1));
    let client = Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .resolve(&resolve_key, socket_addr)
        .build()
        .map_err(|err| HttpProxyError::Internal(format!("failed to build HTTP client: {err}")))?;

    let mut builder = client.request(method, url);
    for (key, value) in &request.headers {
        // 过滤 hop-by-hop 和敏感 header，防止 Host 注入和代理穿透
        if BLOCKED_HEADERS.contains(&key.to_ascii_lowercase().as_str()) {
            continue;
        }
        builder = builder.header(key, value);
    }
    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }

    let mut response = builder.send().map_err(map_reqwest_error)?;
    // 响应 header 安全限制：防止恶意服务器通过大量/超大 header 耗尽 host 内存
    if response.headers().len() > MAX_RESPONSE_HEADER_COUNT {
        return Err(HttpProxyError::Internal("too many response headers".into()));
    }
    for value in response.headers().values() {
        if value.len() > MAX_RESPONSE_HEADER_VALUE_BYTES {
            return Err(HttpProxyError::Internal(
                "response header value too large".into(),
            ));
        }
    }

    let mut headers = HashMap::new();
    for (name, value) in response.headers() {
        headers.insert(
            name.as_str().to_string(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        );
    }
    let body = read_response_body(&mut response, request.max_response_bytes)?;

    Ok(HttpResponse {
        status: response.status().as_u16(),
        headers,
        body,
    })
}

/// Returns whether a hostname matches the sandbox HTTP allowlist.
///
/// The matcher accepts exact host rules and wildcard rules of the form
/// `*.example.com`. Wildcards match subdomains only and do not match the bare
/// suffix itself.
pub fn is_allowed_http_host(config: &SandboxConfig, host: &str) -> bool {
    let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized_host.is_empty() {
        return false;
    }

    config.allowed_http_domains.iter().any(|rule| {
        let rule = rule.trim_end_matches('.').to_ascii_lowercase();
        if let Some(suffix) = rule.strip_prefix("*.") {
            normalized_host.len() > suffix.len()
                && normalized_host.ends_with(suffix)
                && normalized_host
                    .as_bytes()
                    .get(normalized_host.len() - suffix.len() - 1)
                    == Some(&b'.')
        } else {
            normalized_host == rule
        }
    })
}

fn validate_http_request(config: &SandboxConfig, url: &reqwest::Url) -> Result<(), HttpProxyError> {
    if url.scheme() != "https" {
        return Err(HttpProxyError::InvalidUrl(format!(
            "only HTTPS is allowed, got {}",
            url.scheme()
        )));
    }

    let host = url
        .host_str()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL missing host".into()))?;
    validate_host(config, host)
}

fn validate_acl(
    acl_policy: &HttpAclPolicy,
    method_str: &str,
    url: &reqwest::Url,
) -> Result<(), HttpProxyError> {
    if acl_policy.allow.is_empty() && acl_policy.deny.is_empty() {
        return Ok(());
    }

    let normalized_path = normalize_path(url.path());
    let host = url
        .host_str()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL missing host".into()))?;
    let method = HttpMethod::from_str(method_str)
        .map_err(|err| HttpProxyError::InvalidUrl(format!("invalid HTTP method: {err}")))?;

    if acl_policy.evaluate(method, host, &normalized_path) {
        return Ok(());
    }

    Err(HttpProxyError::DeniedAcl(format!(
        "{method_str} {host}{normalized_path}"
    )))
}

fn validate_host(config: &SandboxConfig, host: &str) -> Result<(), HttpProxyError> {
    let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized_host.is_empty() {
        return Err(HttpProxyError::InvalidUrl("host must not be empty".into()));
    }

    if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(HttpProxyError::DeniedHost(normalized_host));
        }
        return Err(HttpProxyError::InvalidUrl(
            "direct IP access is forbidden".into(),
        ));
    }

    if !is_allowed_http_host(config, &normalized_host) {
        return Err(HttpProxyError::DeniedHost(normalized_host));
    }

    Ok(())
}

fn validate_dns_resolution(url: &reqwest::Url) -> Result<IpAddr, HttpProxyError> {
    let host = url
        .host_str()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL missing host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL missing port information".into()))?;

    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|err| HttpProxyError::ConnectFail(format!("DNS resolution failed: {err}")))?;

    select_verified_ip(host, addrs)
}

fn select_verified_ip(
    host: &str,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Result<IpAddr, HttpProxyError> {
    let mut has_addr = false;

    for addr in addrs {
        has_addr = true;
        let ip = addr.ip();
        if is_private_ip(ip) {
            continue;
        }
        return Ok(ip);
    }

    if !has_addr {
        return Err(HttpProxyError::ConnectFail(format!(
            "DNS resolution returned no addresses for {host}"
        )));
    }

    Err(HttpProxyError::DnsRebind(format!(
        "{host} resolved only to private addresses"
    )))
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_non_public_ipv4(ipv4),
        IpAddr::V6(ipv6) => {
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                return is_non_public_ipv4(ipv4);
            }

            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ipv6.is_unique_local()
                || ipv6.is_unicast_link_local()
                || ipv6.is_multicast()
                || is_ipv6_documentation(ipv6)
        }
    }
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_non_public_ipv4(ipv4: Ipv4Addr) -> bool {
    let [a, b, c, _] = ipv4.octets();

    ipv4.is_private()
        || ipv4.is_loopback()
        || ipv4.is_link_local()
        || ipv4.is_unspecified()
        || (a == 100 && (64..=127).contains(&b))
        || ipv4.is_multicast()
        || a >= 240
        || (a == 192 && b == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || (a == 198 && matches!(b, 18 | 19))
}

/// Body reading is guarded by the client-level timeout set in
/// [`execute_http_request`]. The reqwest blocking client will return an error
/// when the overall request timeout fires, preventing slow trickle attacks.
fn read_response_body(
    response: &mut reqwest::blocking::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, HttpProxyError> {
    let mut body = Vec::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read = response.read(&mut buffer).map_err(|err| {
            HttpProxyError::Internal(format!("failed to read HTTP response: {err}"))
        })?;
        if read == 0 {
            break;
        }
        if body.len().saturating_add(read) > max_response_bytes {
            return Err(HttpProxyError::BodyTooLarge);
        }
        body.extend_from_slice(&buffer[..read]);
    }

    Ok(body)
}

fn map_reqwest_error(err: reqwest::Error) -> HttpProxyError {
    if err.is_timeout() {
        return HttpProxyError::Timeout;
    }
    if err.is_connect() {
        let message = err.to_string();
        let lower = message.to_ascii_lowercase();
        if lower.contains("certificate")
            || lower.contains("tls")
            || lower.contains("ssl")
            || lower.contains("handshake")
        {
            return HttpProxyError::TlsFail(message);
        }
        return HttpProxyError::ConnectFail(message);
    }
    if err.is_builder() || err.is_request() {
        return HttpProxyError::InvalidUrl(err.to_string());
    }
    HttpProxyError::Internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimobox_core::HttpAclRule;

    fn config(domains: &[&str]) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.allowed_http_domains = domains.iter().map(|item| (*item).to_string()).collect();
        config
    }

    fn parse_acl_rule(rule: &str) -> HttpAclRule {
        HttpAclRule::parse(rule).expect("HTTP ACL rule must be valid")
    }

    fn acl_policy(allow: &[&str], deny: &[&str]) -> HttpAclPolicy {
        HttpAclPolicy {
            allow: allow.iter().map(|rule| parse_acl_rule(rule)).collect(),
            deny: deny.iter().map(|rule| parse_acl_rule(rule)).collect(),
        }
    }

    fn test_url(path: &str) -> reqwest::Url {
        reqwest::Url::parse(&format!("https://api.openai.com{path}")).expect("URL must be valid")
    }

    #[test]
    fn test_acl_empty_policy_allows_all() {
        let policy = HttpAclPolicy::default();
        let url = test_url("/admin/secret");

        assert!(validate_acl(&policy, "GET", &url).is_ok());
        assert!(validate_acl(&policy, "OPTIONS", &url).is_ok());
    }

    #[test]
    fn test_acl_deny_rule_blocks_request() {
        let policy = acl_policy(&[], &["GET api.openai.com/private/*"]);
        let url = test_url("/private/secret");

        let err = validate_acl(&policy, "GET", &url).expect_err("deny rule must block the request");

        assert!(matches!(
            err,
            HttpProxyError::DeniedAcl(detail) if detail == "GET api.openai.com/private/secret"
        ));
    }

    #[test]
    fn test_acl_allow_rule_permits_request() {
        let policy = acl_policy(&["GET api.openai.com/v1/*"], &[]);
        let url = test_url("/v1/models");

        assert!(validate_acl(&policy, "GET", &url).is_ok());
    }

    #[test]
    fn test_acl_deny_takes_priority_over_allow() {
        let policy = acl_policy(&["* * /*"], &["GET api.openai.com/admin/*"]);
        let url = test_url("/admin/settings");

        let err =
            validate_acl(&policy, "GET", &url).expect_err("deny must take precedence over allow");

        assert!(matches!(err, HttpProxyError::DeniedAcl(_)));
    }

    #[test]
    fn test_acl_path_normalization_blocks_traversal() {
        let policy = acl_policy(&["* * /*"], &["GET api.openai.com/admin/*"]);
        let url = test_url("/public/../admin/settings");

        let err = validate_acl(&policy, "GET", &url).expect_err("normalized path must match deny");

        assert!(matches!(
            err,
            HttpProxyError::DeniedAcl(detail) if detail == "GET api.openai.com/admin/settings"
        ));
    }

    #[test]
    fn wildcard_domain_matches_subdomain_only() {
        let config = config(&["*.openai.com"]);

        assert!(is_allowed_http_host(&config, "api.openai.com"));
        assert!(is_allowed_http_host(&config, "foo.bar.openai.com"));
        assert!(!is_allowed_http_host(&config, "openai.com"));
        assert!(!is_allowed_http_host(&config, "api.openai.org"));
    }

    #[test]
    fn literal_ip_is_rejected() {
        let config = config(&["*.openai.com"]);
        let url = reqwest::Url::parse("https://127.0.0.1/v1/models").expect("URL must be valid");

        let err = validate_http_request(&config, &url)
            .expect_err("direct IP connection must be rejected");
        assert!(matches!(
            err,
            HttpProxyError::DeniedHost(_) | HttpProxyError::InvalidUrl(_)
        ));
    }

    #[test]
    fn non_whitelisted_domain_is_rejected() {
        let config = config(&["*.openai.com"]);
        let url = reqwest::Url::parse("https://example.com/").expect("URL must be valid");

        let err = validate_http_request(&config, &url)
            .expect_err("non-allowlisted domain must be rejected");
        assert!(matches!(err, HttpProxyError::DeniedHost(host) if host == "example.com"));
    }

    #[test]
    fn localhost_is_blocked_by_dns_rebind_guard() {
        let url = reqwest::Url::parse("https://localhost/").expect("URL must be valid");

        let err = validate_dns_resolution(&url).expect_err("localhost must be rejected");
        assert!(matches!(err, HttpProxyError::DnsRebind(_)));
    }

    #[test]
    fn dns_resolution_selects_first_public_address() {
        let private_addr = SocketAddr::from(([127, 0, 0, 1], 443));
        let public_addr = SocketAddr::from(([8, 8, 8, 8], 443));

        let ip = select_verified_ip("example.com", [private_addr, public_addr])
            .expect("must return the non-private IP when one exists");

        assert_eq!(ip, public_addr.ip());
    }
}
