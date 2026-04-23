use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use mimobox_core::SandboxConfig;
use reqwest::Method;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProxyRequestPayload {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body_b64: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpProxyError {
    #[error("域名不在白名单内: {0}")]
    DeniedHost(String),
    #[error("HTTP 请求超时")]
    Timeout,
    #[error("HTTP body 超出大小限制")]
    BodyTooLarge,
    #[error("HTTP 连接失败: {0}")]
    ConnectFail(String),
    #[error("TLS 握手失败: {0}")]
    TlsFail(String),
    #[error("URL 无效: {0}")]
    InvalidUrl(String),
    #[error("DNS 解析命中内网地址: {0}")]
    DnsRebind(String),
    #[error("HTTP 代理内部错误: {0}")]
    Internal(String),
}

impl HttpProxyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DeniedHost(_) => "DENIED_HOST",
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
                let bytes = BASE64_STANDARD
                    .decode(encoded)
                    .map_err(|err| HttpProxyError::InvalidUrl(format!("body_b64 不是合法 base64: {err}")))?;
                if bytes.len() > MAX_REQUEST_BODY_BYTES {
                    return Err(HttpProxyError::BodyTooLarge);
                }
                Some(bytes)
            }
            None => None,
        };

        Ok(Self {
            method: value.method,
            url: value.url,
            headers: value.headers,
            body,
            timeout_ms: value.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
            max_response_bytes: value
                .max_response_bytes
                .unwrap_or(DEFAULT_MAX_RESPONSE_BYTES),
        })
    }
}

impl HttpRequest {
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

        Ok(Self {
            method: method.into(),
            url: url.into(),
            headers,
            body,
            timeout_ms: timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
            max_response_bytes: max_response_bytes.unwrap_or(DEFAULT_MAX_RESPONSE_BYTES),
        })
    }

    pub fn from_json(json: &str) -> Result<Self, HttpProxyError> {
        let payload = serde_json::from_str::<HttpProxyRequestPayload>(json)
            .map_err(|err| HttpProxyError::InvalidUrl(format!("HTTP 请求 JSON 无效: {err}")))?;
        Self::try_from(payload)
    }
}

pub fn execute_http_request(
    config: &SandboxConfig,
    request: &HttpRequest,
) -> Result<HttpResponse, HttpProxyError> {
    let url = reqwest::Url::parse(&request.url)
        .map_err(|err| HttpProxyError::InvalidUrl(err.to_string()))?;
    validate_http_request(config, &url)?;
    validate_dns_resolution(&url)?;

    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|err| HttpProxyError::InvalidUrl(format!("HTTP method 无效: {err}")))?;
    let timeout = Duration::from_millis(request.timeout_ms.max(1));
    let client = Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .build()
        .map_err(|err| HttpProxyError::Internal(format!("构造 HTTP client 失败: {err}")))?;

    let mut builder = client.request(method, url);
    for (key, value) in &request.headers {
        builder = builder.header(key, value);
    }
    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }

    let mut response = builder.send().map_err(map_reqwest_error)?;
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

fn validate_http_request(
    config: &SandboxConfig,
    url: &reqwest::Url,
) -> Result<(), HttpProxyError> {
    if url.scheme() != "https" {
        return Err(HttpProxyError::InvalidUrl(format!(
            "仅允许 HTTPS，实际为 {}",
            url.scheme()
        )));
    }

    let host = url
        .host_str()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL 缺少 host".into()))?;
    validate_host(config, host)
}

fn validate_host(config: &SandboxConfig, host: &str) -> Result<(), HttpProxyError> {
    let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized_host.is_empty() {
        return Err(HttpProxyError::InvalidUrl("host 不能为空".into()));
    }

    if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(HttpProxyError::DeniedHost(normalized_host));
        }
        return Err(HttpProxyError::InvalidUrl("禁止使用 IP 直连".into()));
    }

    if !is_allowed_http_host(config, &normalized_host) {
        return Err(HttpProxyError::DeniedHost(normalized_host));
    }

    Ok(())
}

fn validate_dns_resolution(url: &reqwest::Url) -> Result<(), HttpProxyError> {
    let host = url
        .host_str()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL 缺少 host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| HttpProxyError::InvalidUrl("URL 缺少端口信息".into()))?;

    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|err| HttpProxyError::ConnectFail(format!("DNS 解析失败: {err}")))?;

    for addr in addrs {
        if is_private_ip(addr.ip()) {
            return Err(HttpProxyError::DnsRebind(format!(
                "{host} 解析到内网地址 {}",
                addr.ip()
            )));
        }
    }

    Ok(())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() || ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ipv6.is_unique_local()
                || ipv6.is_unicast_link_local()
        }
    }
}

fn read_response_body(
    response: &mut reqwest::blocking::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, HttpProxyError> {
    let mut body = Vec::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|err| HttpProxyError::Internal(format!("读取 HTTP 响应失败: {err}")))?;
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

    fn config(domains: &[&str]) -> SandboxConfig {
        SandboxConfig {
            allowed_http_domains: domains.iter().map(|item| (*item).to_string()).collect(),
            ..SandboxConfig::default()
        }
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
        let url = reqwest::Url::parse("https://127.0.0.1/v1/models").expect("URL 必须合法");

        let err = validate_http_request(&config, &url).expect_err("IP 直连必须被拒绝");
        assert!(matches!(
            err,
            HttpProxyError::DeniedHost(_) | HttpProxyError::InvalidUrl(_)
        ));
    }

    #[test]
    fn non_whitelisted_domain_is_rejected() {
        let config = config(&["*.openai.com"]);
        let url = reqwest::Url::parse("https://example.com/").expect("URL 必须合法");

        let err = validate_http_request(&config, &url).expect_err("白名单外域名必须被拒绝");
        assert!(matches!(err, HttpProxyError::DeniedHost(host) if host == "example.com"));
    }

    #[test]
    fn localhost_is_blocked_by_dns_rebind_guard() {
        let url = reqwest::Url::parse("https://localhost/").expect("URL 必须合法");

        let err = validate_dns_resolution(&url).expect_err("localhost 必须被拒绝");
        assert!(matches!(err, HttpProxyError::DnsRebind(_)));
    }
}
