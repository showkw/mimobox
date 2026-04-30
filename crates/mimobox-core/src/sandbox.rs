use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crate::seccomp::SeccompProfile;

fn default_cpu_period_us() -> u64 {
    100_000
}

fn has_invalid_domain_wildcard(domain: &str) -> bool {
    let wildcard_count = domain.chars().filter(|character| *character == '*').count();
    wildcard_count > 0 && (wildcard_count != 1 || !domain.starts_with("*.") || domain.len() <= 2)
}

fn is_plain_ip_domain(domain: &str) -> bool {
    let has_digit = domain.chars().any(|character| character.is_ascii_digit());
    let has_dot = domain.contains('.');

    has_digit
        && has_dot
        && domain
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
}

/// Environment variables blocked from persistent sandbox injection because they
/// can affect dynamic loaders, shell startup behavior, or sandbox baseline paths.
pub const BLOCKED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PATH",
    "HOME",
    "TMPDIR",
    "PWD",
    "SHELL",
    "USER",
    "LOGNAME",
];

/// Maximum environment variable key length in bytes.
pub const MAX_ENV_KEY_BYTES: usize = 128;

/// Validates one sandbox environment variable pair.
pub fn validate_sandbox_env_var(key: &str, value: &str) -> Result<(), String> {
    if key.is_empty() || key.contains('=') || key.contains('\0') || key.contains(' ') {
        return Err(format!("env_vars contains invalid key: {key}"));
    }
    if key.len() > MAX_ENV_KEY_BYTES {
        return Err(format!(
            "env_vars key exceeds {MAX_ENV_KEY_BYTES} bytes: {key}"
        ));
    }
    if value.contains('\0') {
        return Err(format!("env_vars value for key {key} contains NUL byte"));
    }
    if BLOCKED_ENV_VARS
        .iter()
        .any(|blocked| key.eq_ignore_ascii_case(blocked))
    {
        return Err(format!("env_vars contains blocked security key: {key}"));
    }
    Ok(())
}

fn validate_persistent_env_vars(
    env_vars: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    for (key, value) in env_vars {
        validate_sandbox_env_var(key, value)?;
    }
    Ok(())
}

fn validate_sandbox_paths(label: &str, paths: &[PathBuf]) -> Result<(), SandboxError> {
    for path in paths {
        if path.as_os_str().is_empty() {
            return Err(SandboxError::new(format!("{label} contains empty path"))
                .suggestion("Remove empty sandbox filesystem paths"));
        }
        if path.to_str().is_none() {
            return Err(SandboxError::new(format!(
                "{label} contains non-UTF-8 path: {}",
                path.display()
            ))
            .suggestion("Use UTF-8 filesystem paths for sandbox filesystem rules"));
        }
    }
    Ok(())
}

/// HTTP method enum used for HTTP ACL rule matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HttpMethod {
    /// HTTP GET method.
    Get,
    /// HTTP POST method.
    Post,
    /// HTTP PUT method.
    Put,
    /// HTTP DELETE method.
    Delete,
    /// HTTP PATCH method.
    Patch,
    /// HTTP HEAD method.
    Head,
    /// Matches any HTTP method.
    Any,
}

impl FromStr for HttpMethod {
    type Err = String;

    fn from_str(method: &str) -> Result<Self, Self::Err> {
        match method.trim().to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            "PATCH" => Ok(Self::Patch),
            "HEAD" => Ok(Self::Head),
            "*" => Ok(Self::Any),
            _ => Err(format!("unsupported HTTP method: {method}")),
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Any => "*",
        })
    }
}

/// HTTP ACL rule defining method + host + path match conditions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpAclRule {
    /// HTTP method match condition.
    pub method: HttpMethod,
    /// Hostname match condition, supporting `*` and `*.example.com`.
    pub host: String,
    /// Path match condition, supporting `/*` and `/prefix/*`.
    pub path: String,
}

impl HttpAclRule {
    /// Parse an HTTP ACL rule in `METHOD host/path` format.
    pub fn parse(rule: &str) -> Result<Self, String> {
        let mut parts = rule.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| "HTTP ACL rule cannot be empty".to_string())?
            .parse::<HttpMethod>()?;
        let target = parts
            .next()
            .ok_or_else(|| "HTTP ACL rule missing host/path".to_string())?;
        let explicit_path = parts.next();

        if parts.next().is_some() {
            return Err("invalid HTTP ACL rule format, use METHOD host/path".to_string());
        }

        let (host, path) = match explicit_path {
            Some(path) => (target, path),
            None => split_acl_target(target),
        };
        if host.is_empty() {
            return Err("HTTP ACL rule host cannot be empty".to_string());
        }

        Ok(Self {
            method,
            host: host.to_string(),
            path: normalize_path(path),
        })
    }

    /// Returns whether this rule matches the given HTTP request.
    pub fn matches(&self, method: HttpMethod, host: &str, path: &str) -> bool {
        self.matches_method(method)
            && matches_acl_host(&self.host, host)
            && matches_acl_path(&self.path, path)
    }

    fn matches_method(&self, method: HttpMethod) -> bool {
        self.method == HttpMethod::Any || self.method == method
    }
}

/// HTTP ACL policy containing allow and deny rule lists.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HttpAclPolicy {
    /// HTTP ACL rules that allow requests.
    pub allow: Vec<HttpAclRule>,
    /// HTTP ACL rules that deny requests.
    pub deny: Vec<HttpAclRule>,
}

impl HttpAclPolicy {
    /// Evaluate whether a request is allowed with deny-first semantics.
    pub fn evaluate(&self, method: HttpMethod, host: &str, path: &str) -> bool {
        if self
            .deny
            .iter()
            .any(|rule| rule.matches(method, host, path))
        {
            return false;
        }

        if self.allow.is_empty() {
            return true;
        }

        self.allow
            .iter()
            .any(|rule| rule.matches(method, host, path))
    }

    /// Validate that HTTP ACL rule configuration is legal.
    pub fn validate(&self) -> Result<(), String> {
        for rule in self.allow.iter().chain(&self.deny) {
            validate_acl_rule(rule)?;
        }

        Ok(())
    }
}

/// Normalize HTTP paths to remove common path bypass forms.
pub fn normalize_path(path: &str) -> String {
    // SAFETY: reqwest::Url::parse() has already percent-decoded the path.
    // This second decode handles paths that still contain encoded segments, such as non-standard URL sources or rule definitions.
    // Double decoding is safe here because rule paths and request paths are normalized uniformly.
    let decoded = percent_decode_path(path);
    let mut segments = Vec::new();

    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }

    if segments.is_empty() {
        return "/".to_string();
    }

    format!("/{}", segments.join("/"))
}

fn split_acl_target(target: &str) -> (&str, &str) {
    match target.find('/') {
        Some(index) => (&target[..index], &target[index..]),
        None => (target, "/*"),
    }
}

fn validate_acl_rule(rule: &HttpAclRule) -> Result<(), String> {
    if rule.host.is_empty() {
        return Err("host cannot be empty".to_string());
    }

    if rule.host.chars().any(char::is_whitespace) {
        return Err(format!("host cannot contain whitespace: {}", rule.host));
    }

    if has_invalid_acl_host_wildcard(&rule.host) {
        return Err(format!(
            "invalid host wildcard format: {}, only * or *.example.com are supported",
            rule.host
        ));
    }

    if !rule.path.starts_with('/') {
        return Err(format!("path must start with /: {}", rule.path));
    }

    Ok(())
}

fn has_invalid_acl_host_wildcard(host: &str) -> bool {
    let wildcard_count = host.chars().filter(|character| *character == '*').count();
    wildcard_count > 0
        && host != "*"
        && (wildcard_count != 1 || !host.starts_with("*.") || host.len() <= 2)
}

fn matches_acl_host(rule_host: &str, host: &str) -> bool {
    let rule_host = normalize_acl_host(rule_host);
    let host = normalize_acl_host(host);

    if rule_host == "*" {
        return true;
    }

    if let Some(domain) = rule_host.strip_prefix("*.") {
        let suffix = format!(".{domain}");
        return host.len() > suffix.len() && host.ends_with(&suffix);
    }

    rule_host == host
}

fn normalize_acl_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn matches_acl_path(rule_path: &str, path: &str) -> bool {
    let rule_path = normalize_path(rule_path);
    let path = normalize_path(path);

    match rule_path.as_str() {
        "*" | "/*" => true,
        s if s.ends_with('*') => {
            let prefix = s.trim_end_matches('*');
            path.starts_with(prefix)
        }
        s => s == path.as_str(),
    }
}

fn percent_decode_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut decoded = String::with_capacity(path.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Some(value) = decode_hex_pair(bytes[index + 1], bytes[index + 2])
        {
            decoded.push(value as char);
            index += 3;
            continue;
        }

        if let Some(character) = path[index..].chars().next() {
            decoded.push(character);
            index += character.len_utf8();
        } else {
            break;
        }
    }

    decoded
}

fn decode_hex_pair(high: u8, low: u8) -> Option<u8> {
    Some(hex_value(high)? * 16 + hex_value(low)?)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Structured error code for programmatic error matching.
///
/// Each variant has a stable string representation via [`ErrorCode::as_str()`],
/// suitable for cross-language transport and log indexing.
///
/// # Examples
///
/// ```
/// use mimobox_core::ErrorCode;
///
/// assert_eq!(ErrorCode::CommandTimeout.as_str(), "command_timeout");
/// assert_eq!(ErrorCode::HttpDeniedHost.as_str(), "http_denied_host");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// The command exceeds its timeout.
    CommandTimeout,
    /// The command exits with a non-zero status code.
    CommandExit(i32),
    /// The command is forcibly terminated by the host.
    CommandKilled,
    /// The target file does not exist.
    FileNotFound,
    /// The target file lacks the required access permission.
    FilePermissionDenied,
    /// The target file or transferred content exceeds the size limit.
    FileTooLarge,
    /// The target path is not a directory.
    NotDirectory,
    /// The HTTP proxy target host is not in the allowlist.
    HttpDeniedHost,
    /// The HTTP proxy request times out.
    HttpTimeout,
    /// The HTTP response body exceeds the allowed size.
    HttpBodyTooLarge,
    /// The HTTP proxy fails to establish a connection.
    HttpConnectFail,
    /// The HTTP proxy TLS handshake fails.
    HttpTlsFail,
    /// The HTTP request URL is invalid.
    HttpInvalidUrl,
    /// The sandbox is not ready to execute commands.
    SandboxNotReady,
    /// The sandbox has been destroyed and cannot be reused.
    SandboxDestroyed,
    /// The sandbox creation flow fails.
    SandboxCreateFailed,
    /// The provided configuration is invalid.
    InvalidConfig,
    /// The current platform or backend does not support this capability.
    UnsupportedPlatform,
    /// Sandbox killed after exceeding the memory limit (OOM killer or cgroups memory.limit).
    MemoryLimitExceeded,
    /// Sandbox exhausted its CPU quota (cgroups cpu.stat throttle).
    CpuLimitExceeded,
    /// HTTP proxy request denied by ACL rule.
    HttpDeniedAcl,
}

impl ErrorCode {
    /// Returns the stable string error code for cross-language transport and log indexing.
    pub fn as_str(&self) -> &'static str {
        #[allow(unreachable_patterns)]
        match self {
            Self::CommandTimeout => "command_timeout",
            Self::CommandExit(_) => "command_exit",
            Self::CommandKilled => "command_killed",
            Self::FileNotFound => "file_not_found",
            Self::FilePermissionDenied => "file_permission_denied",
            Self::FileTooLarge => "file_too_large",
            Self::NotDirectory => "not_directory",
            Self::HttpDeniedHost => "http_denied_host",
            Self::HttpTimeout => "http_timeout",
            Self::HttpBodyTooLarge => "http_body_too_large",
            Self::HttpConnectFail => "http_connect_fail",
            Self::HttpTlsFail => "http_tls_fail",
            Self::HttpInvalidUrl => "http_invalid_url",
            Self::SandboxNotReady => "sandbox_not_ready",
            Self::SandboxDestroyed => "sandbox_destroyed",
            Self::SandboxCreateFailed => "sandbox_create_failed",
            Self::InvalidConfig => "invalid_config",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::MemoryLimitExceeded => "memory_limit_exceeded",
            Self::CpuLimitExceeded => "cpu_limit_exceeded",
            Self::HttpDeniedAcl => "http_denied_acl",
            _ => "unknown_error",
        }
    }
}

/// File type enum used to distinguish directory entry types.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileType {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link.
    Symlink,
    /// Other type, such as device or pipe.
    Other,
}

/// Directory entry representing one item returned by list_dir.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirEntry {
    /// File name.
    pub name: String,
    /// File type.
    pub file_type: FileType,
    /// File size in bytes.
    pub size: u64,
    /// Whether this entry is a symbolic link.
    pub is_symlink: bool,
}

impl DirEntry {
    /// Create a directory entry.
    pub fn new(name: String, file_type: FileType, size: u64, is_symlink: bool) -> Self {
        Self {
            name,
            file_type,
            size,
            is_symlink,
        }
    }
}

/// File metadata returned by stat.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileStat {
    /// File path.
    pub path: String,
    /// Whether the path is a directory.
    pub is_dir: bool,
    /// Whether the path is a regular file.
    pub is_file: bool,
    /// File size in bytes.
    pub size: u64,
    /// File permission mode (Unix mode).
    pub mode: u32,
    /// Last modified time as a millisecond timestamp, if available.
    pub modified_ms: Option<u64>,
}

impl FileStat {
    /// Create file metadata.
    pub fn new(
        path: String,
        is_dir: bool,
        is_file: bool,
        size: u64,
        mode: u32,
        modified_ms: Option<u64>,
    ) -> Self {
        Self {
            path,
            is_dir,
            is_file,
            size,
            mode,
            modified_ms,
        }
    }
}

/// Namespace degradation behavior control policy.
///
/// Defines how to handle Linux namespace creation failures, such as missing CAP_SYS_ADMIN.
/// Defaults to [`NamespaceDegradation::FailClosed`] so security boundaries are not weakened silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum NamespaceDegradation {
    /// Return an error for any namespace creation failure (default, recommended for production).
    #[default]
    FailClosed,
    /// Warn but continue on failure, only for development/CI environments with incomplete namespace support.
    AllowDegradation,
}

/// Sandbox memory limit upper bound in MiB.
///
/// 32 GiB is intentionally above normal sandbox workloads while keeping
/// MiB-to-bytes conversions and backend resource accounting fail-closed.
pub const MAX_MEMORY_LIMIT_MB: u64 = 32 * 1024;

/// Sandbox configuration shared across all backends.
///
/// This struct describes the minimum capability set used by all sandbox
/// implementations, including filesystem permissions, network policy,
/// resource limits, and controlled HTTP proxy whitelist.
///
/// Denies all filesystem access by default; backends and SDK Config fill the minimum permissions needed.
///
/// # Examples
///
/// ```
/// use mimobox_core::SandboxConfig;
///
/// let config = SandboxConfig::default();
/// assert!(config.deny_network);
/// assert_eq!(config.timeout_secs, Some(30));
/// assert!(config.fs_readonly.is_empty());
/// assert!(config.fs_readwrite.is_empty());
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxConfig {
    /// Read-only path list.
    pub fs_readonly: Vec<PathBuf>,
    /// Read-write path list.
    pub fs_readwrite: Vec<PathBuf>,
    /// Whether direct network access from sandboxed processes is denied.
    pub deny_network: bool,
    /// Memory limit in MB, enforced through cgroups v2 or `setrlimit`.
    pub memory_limit_mb: Option<u64>,
    /// Maximum process count inside one sandbox.
    ///
    /// `None` lets the Linux backend use its secure default.
    #[serde(default)]
    pub max_processes: Option<u32>,
    /// CPU time quota in microseconds, used with `cpu_period_us`.
    ///
    /// For example, quota=50000 and period=100000 allows up to 50% CPU.
    /// Set to `None` for no limit.
    #[serde(default)]
    pub cpu_quota_us: Option<u64>,
    /// CPU period in microseconds, defaulting to 100000 (100ms).
    #[serde(default = "default_cpu_period_us")]
    pub cpu_period_us: u64,
    /// Timeout in seconds.
    pub timeout_secs: Option<u64>,
    /// Seccomp filter policy.
    pub seccomp_profile: SeccompProfile,
    /// Whether sandboxed processes may create child processes (`fork`/`clone`).
    /// Defaults to `false`; set to `true` only for shells and other child-process workloads.
    pub allow_fork: bool,
    /// HTTP proxy domain allowlist, including wildcards such as `*.openai.com`.
    /// These domains remain reachable through the controlled proxy even when `deny_network = true`.
    pub allowed_http_domains: Vec<String>,
    /// Namespace degradation behavior. Defaults to FailClosed (any namespace creation failure returns an error).
    #[serde(default)]
    pub namespace_degradation: NamespaceDegradation,
    /// HTTP ACL policy controlling method/host/path access for the host-side HTTP proxy.
    /// When unset (both allow and deny are empty), existing behavior is preserved.
    #[serde(default)]
    pub http_acl: HttpAclPolicy,
    /// 创建沙箱时的持久环境变量，对所有后续命令生效。
    /// 合并优先级（低到高）：后端内置最小环境 < env_vars < per-command env。
    #[serde(default)]
    pub env_vars: std::collections::HashMap<String, String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            fs_readonly: Vec::new(),
            fs_readwrite: Vec::new(),
            deny_network: true,
            memory_limit_mb: Some(512),
            max_processes: None,
            cpu_quota_us: None,
            cpu_period_us: default_cpu_period_us(),
            timeout_secs: Some(30),
            seccomp_profile: SeccompProfile::Essential,
            allow_fork: false,
            allowed_http_domains: Vec::new(),
            namespace_degradation: NamespaceDegradation::FailClosed,
            http_acl: HttpAclPolicy::default(),
            env_vars: std::collections::HashMap::new(),
        }
    }
}

impl SandboxConfig {
    /// Set the CPU time quota in microseconds.
    pub fn cpu_quota(mut self, quota_us: u64) -> Self {
        self.cpu_quota_us = Some(quota_us);
        self
    }

    /// Set the CPU period in microseconds.
    pub fn cpu_period(mut self, period_us: u64) -> Self {
        self.cpu_period_us = period_us;
        self
    }

    /// Validate configuration and return descriptions of invalid settings.
    pub fn validate(&self) -> Result<(), SandboxError> {
        // deny_network only blocks direct network access inside the sandbox; allowed_http_domains is
        // the host-side controlled HTTP proxy whitelist, so both may coexist.

        // memory_limit_mb=Some(0) has no meaningful semantics.
        if self.memory_limit_mb == Some(0) {
            return Err(SandboxError::new(
                "memory_limit_mb=0 invalid, set a positive integer or None",
            )
            .suggestion("memory_limit_mb minimum is 1"));
        }
        if let Some(memory_limit_mb) = self.memory_limit_mb
            && memory_limit_mb > MAX_MEMORY_LIMIT_MB
        {
            return Err(SandboxError::new(format!(
                "memory_limit_mb={memory_limit_mb} exceeds maximum {MAX_MEMORY_LIMIT_MB} MB, set a reasonable value"
            ))
            .suggestion(format!(
                "memory_limit_mb maximum is {MAX_MEMORY_LIMIT_MB}"
            )));
        }

        if self.max_processes == Some(0) {
            return Err(SandboxError::new(
                "max_processes=0 invalid, set a positive integer or None",
            )
            .suggestion("max_processes minimum is 1, or set to None for backend default"));
        }

        validate_sandbox_paths("fs_readonly", &self.fs_readonly)?;
        validate_sandbox_paths("fs_readwrite", &self.fs_readwrite)?;

        // timeout_secs may be disabled, but explicit values must not exceed 24 hours.
        if let Some(timeout_secs) = self.timeout_secs {
            const MAX_TIMEOUT_SECS: u64 = 86_400;
            if timeout_secs == 0 {
                return Err(SandboxError::new(
                    "timeout_secs=0 invalid, set a positive integer or None",
                )
                .suggestion("timeout must be > 0, recommended 30s"));
            }
            if timeout_secs > MAX_TIMEOUT_SECS {
                return Err(SandboxError::new(format!(
                    "timeout_secs={timeout_secs} exceeds maximum 86400 (24 hours), set a reasonable value"
                ))
                .suggestion("timeout_secs maximum is 86400 (24 hours)"));
            }
        }

        for domain in &self.allowed_http_domains {
            if domain.is_empty()
                || domain
                    .chars()
                    .any(|character| matches!(character, ' ' | '\t' | '\n' | '\r'))
                || has_invalid_domain_wildcard(domain)
                || is_plain_ip_domain(domain)
            {
                return Err(SandboxError::new(format!(
                    "allowed_http_domains contains invalid domain: {domain}"
                ))
                .suggestion(
                    "Use standard domain format, e.g. example.com or *.example.com; IP addresses not supported",
                ));
            }
        }

        if self.cpu_period_us == 0 {
            return Err(
                SandboxError::new("cpu_period_us=0 invalid, set a positive integer")
                    .suggestion("cpu_period_us minimum is 1, recommended 100000"),
            );
        }

        if let Err(msg) = self.http_acl.validate() {
            return Err(SandboxError::new(format!("http_acl config invalid: {msg}"))
                .suggestion("Check HTTP ACL rule format"));
        }

        if let Err(msg) = validate_persistent_env_vars(&self.env_vars) {
            return Err(SandboxError::new(format!("env_vars config invalid: {msg}"))
                .suggestion("Remove unsafe or malformed persistent environment variables"));
        }

        Ok(())
    }
}

/// Result of a sandbox command execution.
///
/// Contains raw stdout/stderr bytes, exit code, wall-clock elapsed time,
/// and a timeout flag.
#[derive(Debug)]
pub struct SandboxResult {
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error output.
    pub stderr: Vec<u8>,
    /// Child process exit code; may be `None` when the process does not exit normally.
    pub exit_code: Option<i32>,
    /// Total elapsed time for this execution.
    pub elapsed: Duration,
    /// Whether the execution was terminated because of a timeout.
    pub timed_out: bool,
}

/// 沙箱运行时资源使用指标。
///
/// 在 execute() 返回时采样并缓存，通过 SDK 层 metrics() 方法获取。
/// 所有字段为 Option，表示后端可能不支持某项指标。
#[derive(Debug, Clone, Default)]
pub struct SandboxMetrics {
    /// 当前内存使用量（字节）。
    pub memory_usage_bytes: Option<u64>,
    /// 内存限制（字节）。
    pub memory_limit_bytes: Option<u64>,
    /// 用户态 CPU 时间（微秒）。
    pub cpu_time_user_us: Option<u64>,
    /// 内核态 CPU 时间（微秒）。
    pub cpu_time_system_us: Option<u64>,
    /// Wasm fuel 消耗量（仅 Wasm 后端）。
    pub wasm_fuel_consumed: Option<u64>,
    /// IO 读取字节数。
    pub io_read_bytes: Option<u64>,
    /// IO 写入字节数。
    pub io_write_bytes: Option<u64>,
    /// 指标采样时间。
    pub collected_at: Option<std::time::Instant>,
}

/// Internal storage for sandbox snapshots.
///
/// This enum supports two snapshot storage modes:
/// 1. Stores snapshot content directly as in-memory bytes.
/// 2. Stores only the snapshot file path and size, with the actual data managed externally as a file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SnapshotInner {
    /// In-memory snapshot bytes.
    Bytes(Vec<u8>),
    /// File-backed snapshot reference.
    File {
        /// Snapshot file path.
        path: PathBuf,
        /// Snapshot file size in bytes.
        size: usize,
    },
}

/// Opaque sandbox snapshot handle.
///
/// Carries a backend-generated snapshot without parsing the internal format.
/// Supports two storage modes: in-memory bytes and file-backed references.
///
/// # Examples
///
/// ```
/// use mimobox_core::SandboxSnapshot;
///
/// let snapshot = SandboxSnapshot::from_bytes(b"snapshot-data").unwrap();
/// assert_eq!(snapshot.size(), 13);
/// assert_eq!(snapshot.as_bytes().unwrap(), b"snapshot-data");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSnapshot {
    inner: SnapshotInner,
}

impl SandboxSnapshot {
    /// Creates a snapshot from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SandboxError> {
        if data.is_empty() {
            return Err(SandboxError::new("snapshot data must not be empty"));
        }

        Ok(Self {
            inner: SnapshotInner::Bytes(data.to_vec()),
        })
    }

    /// Creates a snapshot from owned bytes without an extra copy.
    pub fn from_owned_bytes(data: Vec<u8>) -> Result<Self, SandboxError> {
        if data.is_empty() {
            return Err(SandboxError::new("snapshot data must not be empty"));
        }

        Ok(Self {
            inner: SnapshotInner::Bytes(data),
        })
    }

    /// Creates a snapshot reference from a snapshot file.
    ///
    /// This constructor records only the path and file size without reading file content into memory.
    pub fn from_file(path: PathBuf) -> Result<Self, SandboxError> {
        let metadata = std::fs::metadata(&path)?;
        if !metadata.is_file() {
            return Err(SandboxError::InvalidSnapshot);
        }

        let size = usize::try_from(metadata.len()).map_err(|_| SandboxError::InvalidSnapshot)?;
        if size == 0 {
            return Err(SandboxError::InvalidSnapshot);
        }

        Ok(Self {
            inner: SnapshotInner::File { path, size },
        })
    }

    /// Returns the memory file path.
    ///
    /// Returns the corresponding path for file-backed snapshots, or `None` otherwise.
    pub fn memory_file_path(&self) -> Option<&Path> {
        match &self.inner {
            SnapshotInner::Bytes(_) => None,
            SnapshotInner::File { path, .. } => Some(path.as_path()),
        }
    }

    /// Returns the snapshot byte slice without unnecessary copying.
    ///
    /// This operation is supported only for in-memory snapshots; file-backed snapshots return an error.
    pub fn as_bytes(&self) -> Result<&[u8], SandboxError> {
        match &self.inner {
            SnapshotInner::Bytes(data) => Ok(data.as_slice()),
            SnapshotInner::File { .. } => Err(SandboxError::InvalidSnapshot),
        }
    }

    /// Serializes the snapshot into a byte copy.
    ///
    /// File-backed snapshots read file content from disk again.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SandboxError> {
        match &self.inner {
            SnapshotInner::Bytes(data) => Ok(data.clone()),
            SnapshotInner::File { path, size } => read_file_snapshot(path, *size),
        }
    }

    /// Consumes the snapshot and returns the underlying bytes without an extra copy.
    ///
    /// File-backed snapshots read file content from disk again.
    pub fn into_bytes(self) -> Result<Vec<u8>, SandboxError> {
        match self.inner {
            SnapshotInner::Bytes(data) => Ok(data),
            SnapshotInner::File { path, size } => read_file_snapshot(&path, size),
        }
    }

    /// Returns the snapshot size in bytes.
    pub fn size(&self) -> usize {
        match &self.inner {
            SnapshotInner::Bytes(data) => data.len(),
            SnapshotInner::File { size, .. } => *size,
        }
    }
}

fn read_file_snapshot(path: &Path, expected_size: usize) -> Result<Vec<u8>, SandboxError> {
    validate_file_snapshot_metadata(path, expected_size)?;
    let data = std::fs::read(path)?;
    if data.len() != expected_size {
        return Err(SandboxError::InvalidSnapshot);
    }
    validate_file_snapshot_metadata(path, expected_size)?;
    Ok(data)
}

fn validate_file_snapshot_metadata(path: &Path, expected_size: usize) -> Result<(), SandboxError> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(SandboxError::InvalidSnapshot);
    }
    let current_size =
        usize::try_from(metadata.len()).map_err(|_| SandboxError::InvalidSnapshot)?;
    if current_size != expected_size {
        return Err(SandboxError::InvalidSnapshot);
    }
    Ok(())
}

/// PTY terminal dimensions.
///
/// # Examples
///
/// ```
/// use mimobox_core::PtySize;
///
/// let size = PtySize::default();
/// assert_eq!(size.cols, 80);
/// assert_eq!(size.rows, 24);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    /// Terminal column count.
    pub cols: u16,
    /// Terminal row count.
    pub rows: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// PTY session event.
///
/// Events delivered via the PTY output channel.
#[derive(Debug)]
pub enum PtyEvent {
    /// Terminal output data.
    Output(Vec<u8>),
    /// Process exit event.
    Exit(i32),
}

/// PTY session configuration.
///
/// Specifies the command to run, terminal size, environment variables,
/// working directory, and timeout for an interactive PTY session.
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Command and arguments executed when starting the PTY session.
    pub command: Vec<String>,
    /// Initial terminal size.
    pub size: PtySize,
    /// Additional environment variables injected into the session.
    pub env: std::collections::HashMap<String, String>,
    /// Session working directory.
    pub cwd: Option<String>,
    /// Session timeout.
    pub timeout: Option<Duration>,
}

/// PTY session trait for interactive terminal control.
///
/// Backend implementations provide concrete types satisfying this trait.
/// SDK users interact with `mimobox_sdk::PtySession` instead.
pub trait PtySession {
    /// Sends input to the terminal (`stdin`).
    fn send_input(&mut self, data: &[u8]) -> Result<(), SandboxError>;
    /// Resizes the terminal.
    fn resize(&mut self, size: PtySize) -> Result<(), SandboxError>;
    /// Returns the output event receiver.
    fn output_rx(&self) -> &Receiver<PtyEvent>;
    /// Terminates the session.
    fn kill(&mut self) -> Result<(), SandboxError>;
    /// Waits for the process to exit and returns the exit code.
    fn wait(&mut self) -> Result<i32, SandboxError>;
}

/// Structured classification of execution failures.
///
/// Low-level backends pass failure types directly so the SDK does not infer them from strings.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionFailureKind {
    /// Unknown or unclassified execution failure.
    Unknown,
    /// Memory limit exceeded (OOM killer, cgroups memory.limit, or Wasm memory grow failure).
    Oom,
    /// CPU quota exhausted (cgroups CPU throttling or Wasm fuel exhaustion).
    CpuLimit,
    /// Process terminated by signal (SIGKILL/SIGTERM, not timeout or resource limit).
    Killed,
}

/// Sandbox error type.
///
/// Low-level backend errors. The SDK maps these to `mimobox_sdk::SdkError`
/// with structured [`ErrorCode`] values.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The current platform does not support this sandbox implementation.
    #[error("sandbox backend not supported on current platform")]
    Unsupported,

    /// The current backend does not support the requested operation.
    #[error("operation not supported: {0}")]
    UnsupportedOperation(String),

    /// Namespace initialization fails.
    #[error("namespace creation failed: {0}")]
    NamespaceFailed(String),

    /// The `pivot_root` call fails.
    #[error("pivot_root failed: {0}")]
    PivotRootFailed(String),

    /// Filesystem mounting fails.
    #[error("mount failed: {0}")]
    MountFailed(String),

    /// Landlock rule enforcement fails.
    #[error("Landlock rule enforcement failed: {0}")]
    LandlockFailed(String),

    /// Seccomp rule enforcement fails.
    #[error("Seccomp filter enforcement failed: {0}")]
    SeccompFailed(String),

    /// Command execution or protocol handling fails.
    #[error("command execution failed: {message}")]
    ExecutionFailed {
        /// Structured failure classification.
        kind: ExecutionFailureKind,
        /// Human-readable error description.
        message: String,
    },

    /// The snapshot content or access mode is invalid.
    #[error("invalid sandbox snapshot")]
    InvalidSnapshot,

    /// The child process execution times out.
    #[error("child process timed out")]
    Timeout,

    /// Pipe I/O fails.
    #[error("pipe I/O error: {0}")]
    PipeError(String),

    /// A system call fails.
    #[error("syscall error: {0}")]
    Syscall(String),

    /// A standard library I/O error occurs.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Adds a remediation suggestion to an existing sandbox error without
    /// changing the original error kind.
    #[error("{error}")]
    WithSuggestion {
        /// Original sandbox error.
        #[source]
        error: Box<SandboxError>,
        /// Suggested action the caller can take to resolve the error.
        suggestion: Option<String>,
    },
}

impl SandboxError {
    /// Constructs a command execution error with no suggestion.
    pub fn new(message: impl Into<String>) -> Self {
        Self::ExecutionFailed {
            kind: ExecutionFailureKind::Unknown,
            message: message.into(),
        }
    }

    /// Attaches a remediation suggestion while preserving the original error kind.
    pub fn suggestion(self, suggestion: impl Into<String>) -> Self {
        Self::WithSuggestion {
            error: Box::new(self),
            suggestion: Some(suggestion.into()),
        }
    }

    /// Returns the remediation suggestion attached to this error, if any.
    pub fn suggestion_text(&self) -> Option<&str> {
        match self {
            Self::WithSuggestion {
                error, suggestion, ..
            } => suggestion.as_deref().or_else(|| error.suggestion_text()),
            _ => None,
        }
    }

    /// Splits a suggested error into its base error and suggestion.
    pub fn into_base_and_suggestion(self) -> (Self, Option<String>) {
        match self {
            Self::WithSuggestion {
                error, suggestion, ..
            } => {
                let (error, nested_suggestion) = error.into_base_and_suggestion();
                (error, suggestion.or(nested_suggestion))
            }
            error => (error, None),
        }
    }
}

/// Sandbox lifecycle trait.
///
/// Each backend implements this trait to provide unified creation, execution,
/// file transfer, snapshot, and destruction capabilities.
///
/// Most users should use `mimobox_sdk::Sandbox` instead of implementing
/// this trait directly.
///
/// # Examples
///
/// ```rust,ignore
/// use mimobox_core::{Sandbox, SandboxConfig};
/// use mimobox_os::LinuxSandbox;
///
/// let mut sandbox = LinuxSandbox::new(SandboxConfig::default())?;
/// let result = sandbox.execute(&["/bin/echo".into(), "hello".into()])?;
/// assert_eq!(result.exit_code, Some(0));
/// sandbox.destroy()?;
/// ```
pub trait Sandbox {
    /// Creates a new sandbox instance with the given configuration.
    fn new(config: SandboxConfig) -> Result<Self, SandboxError>
    where
        Self: Sized;

    /// Executes a command inside the sandbox and waits for completion.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use mimobox_core::Sandbox;
    /// use mimobox_os::LinuxSandbox;
    ///
    /// let mut sandbox = LinuxSandbox::new(Default::default())?;
    /// let result = sandbox.execute(&["/bin/echo".into(), "hello".into()])?;
    /// assert_eq!(result.exit_code, Some(0));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError>;

    /// Creates an interactive PTY session.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use mimobox_core::{PtyConfig, PtySize, Sandbox};
    /// use mimobox_os::LinuxSandbox;
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let mut sandbox = LinuxSandbox::new(Default::default())?;
    /// let mut session = sandbox.create_pty(PtyConfig {
    ///     command: vec!["/bin/sh".into()],
    ///     size: PtySize { cols: 80, rows: 24 },
    ///     env: HashMap::new(),
    ///     cwd: None,
    ///     timeout: Some(Duration::from_secs(10)),
    /// })?;
    /// session.send_input(b"echo hello\n")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn create_pty(&mut self, config: PtyConfig) -> Result<Box<dyn PtySession>, SandboxError> {
        let _ = config;
        Err(SandboxError::UnsupportedOperation(
            "PTY sessions not supported by current backend".to_string(),
        ))
    }

    /// Reads file content from inside the sandbox.
    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SandboxError> {
        let _ = path;
        Err(SandboxError::new(
            "file reading not supported by current backend",
        ))
    }

    /// Writes file content inside the sandbox.
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SandboxError> {
        let _ = path;
        let _ = data;
        Err(SandboxError::new(
            "file writing not supported by current backend",
        ))
    }

    /// List directory entries under the specified path.
    fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, SandboxError> {
        let _ = path;
        Err(SandboxError::new(
            "list_dir not supported by current backend",
        ))
    }

    /// Check whether a file exists at the specified path.
    fn file_exists(&mut self, path: &str) -> Result<bool, SandboxError> {
        let _ = path;
        Err(SandboxError::UnsupportedOperation(
            "file_exists not supported by current backend".to_string(),
        ))
    }

    /// Delete a file or empty directory at the specified path.
    ///
    /// Note: recursive deletion is not supported for safety.
    fn remove_file(&mut self, path: &str) -> Result<(), SandboxError> {
        let _ = path;
        Err(SandboxError::UnsupportedOperation(
            "remove_file not supported by current backend".to_string(),
        ))
    }

    /// Rename or move a file.
    fn rename(&mut self, from: &str, to: &str) -> Result<(), SandboxError> {
        let _ = from;
        let _ = to;
        Err(SandboxError::UnsupportedOperation(
            "rename not supported by current backend".to_string(),
        ))
    }

    /// Return file metadata.
    fn stat(&mut self, path: &str) -> Result<FileStat, SandboxError> {
        let _ = path;
        Err(SandboxError::UnsupportedOperation(
            "stat not supported by current backend".to_string(),
        ))
    }

    /// Exports a snapshot of the current sandbox state.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use mimobox_core::Sandbox;
    /// use mimobox_vm::MicrovmSandbox;
    /// use mimobox_vm::MicrovmConfig;
    ///
    /// let mut sandbox = MicrovmSandbox::new(MicrovmConfig::default())?;
    /// let snapshot = sandbox.snapshot()?;
    /// assert!(!snapshot.to_bytes()?.is_empty());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn snapshot(&mut self) -> Result<SandboxSnapshot, SandboxError> {
        Err(SandboxError::UnsupportedOperation(
            "snapshot not supported by current backend".to_string(),
        ))
    }

    /// Forks an independent copy from the current sandbox.
    ///
    /// Returns `UnsupportedOperation` by default; only the microVM backend supports this operation.
    fn fork(&mut self) -> Result<Self, SandboxError>
    where
        Self: Sized,
    {
        Err(SandboxError::UnsupportedOperation(
            "fork not supported by current backend".to_string(),
        ))
    }

    /// Destroys the sandbox and releases underlying resources.
    fn destroy(self) -> Result<(), SandboxError>;
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        BLOCKED_ENV_VARS, ErrorCode, HttpAclPolicy, HttpAclRule, HttpMethod, MAX_ENV_KEY_BYTES,
        MAX_MEMORY_LIMIT_MB, PtySize, SandboxConfig, SandboxError, SandboxMetrics, SandboxSnapshot,
        normalize_path,
    };

    fn parse_acl_rule(rule: &str) -> HttpAclRule {
        HttpAclRule::parse(rule).expect("HTTP ACL rule parse must succeed")
    }

    fn acl_policy(allow: &[&str], deny: &[&str]) -> HttpAclPolicy {
        HttpAclPolicy {
            allow: allow.iter().map(|rule| parse_acl_rule(rule)).collect(),
            deny: deny.iter().map(|rule| parse_acl_rule(rule)).collect(),
        }
    }

    #[test]
    fn test_http_method_from_str_uppercase() {
        assert_eq!("GET".parse::<HttpMethod>(), Ok(HttpMethod::Get));
    }

    #[test]
    fn test_http_method_from_str_lowercase() {
        assert_eq!("get".parse::<HttpMethod>(), Ok(HttpMethod::Get));
    }

    #[test]
    fn test_http_method_from_str_wildcard() {
        assert_eq!("*".parse::<HttpMethod>(), Ok(HttpMethod::Any));
    }

    #[test]
    fn test_http_method_from_str_invalid() {
        assert!("INVALID".parse::<HttpMethod>().is_err());
    }

    #[test]
    fn test_acl_rule_parse_full() {
        let rule = parse_acl_rule("GET api.openai.com/v1/models");

        assert_eq!(rule.method, HttpMethod::Get);
        assert_eq!(rule.host, "api.openai.com");
        assert_eq!(rule.path, "/v1/models");
    }

    #[test]
    fn test_acl_rule_parse_wildcard_method() {
        let rule = parse_acl_rule("* *.openai.com/*");

        assert_eq!(rule.method, HttpMethod::Any);
        assert_eq!(rule.host, "*.openai.com");
        assert_eq!(rule.path, "/*");
    }

    #[test]
    fn test_acl_rule_parse_no_path() {
        let rule = parse_acl_rule("GET example.com");

        assert_eq!(rule.method, HttpMethod::Get);
        assert_eq!(rule.host, "example.com");
        assert_eq!(rule.path, "/*");
    }

    #[test]
    fn test_acl_rule_parse_wildcard_all() {
        let rule = parse_acl_rule("* */admin/*");

        assert_eq!(rule.method, HttpMethod::Any);
        assert_eq!(rule.host, "*");
        assert_eq!(rule.path, "/admin/*");
    }

    #[test]
    fn test_acl_rule_parse_post_wildcard_path() {
        let rule = parse_acl_rule("POST api.openai.com/v1/*");

        assert_eq!(rule.method, HttpMethod::Post);
        assert_eq!(rule.host, "api.openai.com");
        assert_eq!(rule.path, "/v1/*");
    }

    #[test]
    fn test_acl_rule_parse_empty_input() {
        assert!(HttpAclRule::parse("").is_err());
    }

    #[test]
    fn test_normalize_path_percent_decode() {
        assert_eq!(normalize_path("/%61dmin"), "/admin");
    }

    #[test]
    fn test_normalize_path_double_slash() {
        assert_eq!(normalize_path("//admin"), "/admin");
    }

    #[test]
    fn test_normalize_path_dotdot() {
        assert_eq!(normalize_path("/public/../admin"), "/admin");
    }

    #[test]
    fn test_normalize_path_complex() {
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
    }

    #[test]
    fn test_normalize_path_already_normal() {
        assert_eq!(normalize_path("/v1/models"), "/v1/models");
    }

    #[test]
    fn test_normalize_path_root() {
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_path_percent_slash() {
        assert_eq!(normalize_path("/%2Fadmin"), "/admin");
    }

    #[test]
    fn test_normalize_path_invalid_percent() {
        assert_eq!(normalize_path("/%GG"), "/%GG");
    }

    #[test]
    fn test_evaluate_deny_first() {
        let policy = acl_policy(&["* * /*"], &["* */admin/*"]);

        assert!(!policy.evaluate(HttpMethod::Get, "any", "/admin/settings"));
    }

    #[test]
    fn test_evaluate_allow_match() {
        let policy = acl_policy(&["GET api.openai.com/v1/*"], &[]);

        assert!(policy.evaluate(HttpMethod::Get, "api.openai.com", "/v1/models"));
    }

    #[test]
    fn test_evaluate_default_deny() {
        let policy = acl_policy(&["GET api.openai.com/v1/*"], &[]);

        assert!(!policy.evaluate(HttpMethod::Post, "api.openai.com", "/v1/models"));
    }

    #[test]
    fn test_evaluate_no_rules() {
        let policy = HttpAclPolicy::default();

        assert!(policy.evaluate(HttpMethod::Get, "any.com", "/any"));
    }

    #[test]
    fn test_evaluate_host_exact() {
        let policy = acl_policy(&["GET example.com/*"], &[]);

        assert!(policy.evaluate(HttpMethod::Get, "example.com", "/path"));
        assert!(!policy.evaluate(HttpMethod::Get, "other.com", "/path"));
    }

    #[test]
    fn test_evaluate_host_wildcard_subdomain() {
        let policy = acl_policy(&["* *.openai.com/*"], &[]);

        assert!(policy.evaluate(HttpMethod::Get, "api.openai.com", "/v1"));
        assert!(!policy.evaluate(HttpMethod::Get, "openai.com", "/v1"));
    }

    #[test]
    fn test_evaluate_host_wildcard_all() {
        let policy = acl_policy(&["* * /*"], &[]);

        assert!(policy.evaluate(HttpMethod::Get, "any.com", "/any"));
    }

    #[test]
    fn test_evaluate_path_prefix() {
        let policy = acl_policy(&["GET example.com/v1/*"], &[]);

        assert!(policy.evaluate(HttpMethod::Get, "example.com", "/v1/models"));
        assert!(!policy.evaluate(HttpMethod::Get, "example.com", "/v2/models"));
    }

    #[test]
    fn test_evaluate_path_exact() {
        let policy = acl_policy(&["GET example.com/v1/models"], &[]);

        assert!(policy.evaluate(HttpMethod::Get, "example.com", "/v1/models"));
        assert!(!policy.evaluate(HttpMethod::Get, "example.com", "/v1/models/123"));
    }

    #[test]
    fn test_evaluate_path_bypass_percent() {
        let policy = acl_policy(&["* * /*"], &["* */admin/*"]);

        assert!(!policy.evaluate(HttpMethod::Get, "any", "/%61dmin/settings"));
    }

    #[test]
    fn test_evaluate_path_bypass_dotdot() {
        let policy = acl_policy(&["* * /*"], &["* */admin/*"]);

        assert!(!policy.evaluate(HttpMethod::Get, "any", "/public/../admin/settings"));
    }

    #[test]
    fn test_evaluate_path_bypass_double_slash() {
        let policy = acl_policy(&["* * /*"], &["* */admin/*"]);

        assert!(!policy.evaluate(HttpMethod::Get, "any", "//admin/settings"));
    }

    #[test]
    fn test_evaluate_serde_rule_path_normalized() {
        // HttpAclRule constructed through serde may contain an unnormalized path.
        let policy = HttpAclPolicy {
            allow: vec![],
            deny: vec![HttpAclRule {
                method: HttpMethod::Any,
                host: "*".to_string(),
                path: "/admin/../secret/*".to_string(),
            }],
        };

        // evaluate should still match correctly even when rule.path is unnormalized.
        assert!(!policy.evaluate(HttpMethod::Get, "any", "/secret/data"));
    }

    #[test]
    fn test_validate_empty_host() {
        let policy = HttpAclPolicy {
            allow: vec![HttpAclRule {
                method: HttpMethod::Get,
                host: String::new(),
                path: "/*".to_string(),
            }],
            deny: Vec::new(),
        };

        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_validate_valid_rules() {
        let policy = acl_policy(
            &["GET example.com/v1/*", "* *.openai.com/*"],
            &["* */admin/*"],
        );

        assert!(policy.validate().is_ok());
    }

    #[test]
    fn pty_size_default_is_80x24() {
        assert_eq!(PtySize::default(), PtySize { cols: 80, rows: 24 });
    }

    #[test]
    fn sandbox_config_allows_denied_network_with_http_proxy_whitelist() {
        let config = SandboxConfig {
            deny_network: true,
            allowed_http_domains: vec!["api.openai.com".to_string()],
            ..Default::default()
        };

        config
            .validate()
            .expect("controlled HTTP proxy whitelist should not enable direct sandbox networking");
    }

    #[test]
    fn sandbox_config_rejects_memory_limit_above_global_max() {
        let config = SandboxConfig {
            memory_limit_mb: Some(MAX_MEMORY_LIMIT_MB + 1),
            ..Default::default()
        };

        let error = config
            .validate()
            .expect_err("memory_limit_mb above the global maximum must be rejected");

        assert_eq!(
            error.suggestion_text(),
            Some("memory_limit_mb maximum is 32768")
        );
        let (error, _) = error.into_base_and_suggestion();
        assert!(
            matches!(error, SandboxError::ExecutionFailed { message, .. } if message.contains("memory_limit_mb"))
        );
    }

    #[test]
    fn sandbox_config_default_env_vars_are_empty_and_valid() {
        let config = SandboxConfig::default();

        assert!(config.env_vars.is_empty());
        config
            .validate()
            .expect("default sandbox env_vars should be valid");
    }

    #[test]
    fn sandbox_config_accepts_safe_persistent_env_vars() {
        let mut env_vars = std::collections::HashMap::new();
        env_vars.insert("MIMOBOX_TOKEN".to_string(), "value".to_string());
        env_vars.insert("APP_MODE".to_string(), "test".to_string());
        let config = SandboxConfig {
            env_vars: env_vars.clone(),
            ..Default::default()
        };

        config
            .validate()
            .expect("safe persistent env_vars should be accepted");
        assert_eq!(config.env_vars, env_vars);
    }

    #[test]
    fn sandbox_config_rejects_empty_env_var_key() {
        let config = SandboxConfig {
            env_vars: std::collections::HashMap::from([("".to_string(), "value".to_string())]),
            ..Default::default()
        };

        let error = config
            .validate()
            .expect_err("empty env var key should be rejected");

        assert!(error.to_string().contains("env_vars config invalid"));
    }

    #[test]
    fn sandbox_config_rejects_empty_filesystem_path() {
        let config = SandboxConfig {
            fs_readonly: vec![std::path::PathBuf::new()],
            ..Default::default()
        };

        let error = config
            .validate()
            .expect_err("empty sandbox filesystem path should be rejected");

        assert!(
            error
                .to_string()
                .contains("fs_readonly contains empty path")
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_config_rejects_non_utf8_filesystem_path() {
        use std::os::unix::ffi::OsStringExt;

        let path = std::ffi::OsString::from_vec(vec![0xff]).into();
        let config = SandboxConfig {
            fs_readwrite: vec![path],
            ..Default::default()
        };

        let error = config
            .validate()
            .expect_err("non-UTF-8 sandbox filesystem path should be rejected");

        assert!(
            error
                .to_string()
                .contains("fs_readwrite contains non-UTF-8 path")
        );
    }

    #[test]
    fn sandbox_config_rejects_overlong_env_var_key() {
        let key = "A".repeat(MAX_ENV_KEY_BYTES + 1);
        let config = SandboxConfig {
            env_vars: std::collections::HashMap::from([(key, "value".to_string())]),
            ..Default::default()
        };

        let error = config
            .validate()
            .expect_err("overlong env var key should be rejected");

        assert!(
            error
                .to_string()
                .contains(&format!("exceeds {MAX_ENV_KEY_BYTES} bytes"))
        );
    }

    #[test]
    fn sandbox_config_rejects_every_blocked_env_var() {
        for blocked_key in BLOCKED_ENV_VARS {
            let config = SandboxConfig {
                env_vars: std::collections::HashMap::from([(
                    (*blocked_key).to_string(),
                    "value".to_string(),
                )]),
                ..Default::default()
            };

            let error = config
                .validate()
                .expect_err("blocked env var should be rejected");

            assert!(
                error.to_string().contains("blocked security key"),
                "blocked key {blocked_key} returned unexpected error: {error}"
            );
        }
    }

    #[test]
    fn blocked_env_vars_cover_loader_shell_and_baseline_keys() {
        let expected = [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "BASH_ENV",
            "ENV",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "PATH",
            "HOME",
            "TMPDIR",
            "PWD",
            "SHELL",
            "USER",
            "LOGNAME",
        ];

        for key in expected {
            assert!(
                BLOCKED_ENV_VARS.contains(&key),
                "BLOCKED_ENV_VARS should contain {key}"
            );
        }

        let unique: std::collections::HashSet<_> = BLOCKED_ENV_VARS.iter().copied().collect();
        assert_eq!(
            unique.len(),
            BLOCKED_ENV_VARS.len(),
            "blocked env var list should not contain duplicates"
        );
    }

    #[test]
    fn sandbox_metrics_default_has_every_field_empty() {
        let metrics = SandboxMetrics::default();

        assert!(metrics.memory_usage_bytes.is_none());
        assert!(metrics.memory_limit_bytes.is_none());
        assert!(metrics.cpu_time_user_us.is_none());
        assert!(metrics.cpu_time_system_us.is_none());
        assert!(metrics.wasm_fuel_consumed.is_none());
        assert!(metrics.io_read_bytes.is_none());
        assert!(metrics.io_write_bytes.is_none());
        assert!(metrics.collected_at.is_none());
    }

    #[test]
    fn sandbox_metrics_clone_preserves_every_field() {
        let collected_at = std::time::Instant::now();
        let metrics = SandboxMetrics {
            memory_usage_bytes: Some(1),
            memory_limit_bytes: Some(2),
            cpu_time_user_us: Some(3),
            cpu_time_system_us: Some(4),
            wasm_fuel_consumed: Some(5),
            io_read_bytes: Some(6),
            io_write_bytes: Some(7),
            collected_at: Some(collected_at),
        };

        let cloned = metrics.clone();

        assert_eq!(cloned.memory_usage_bytes, Some(1));
        assert_eq!(cloned.memory_limit_bytes, Some(2));
        assert_eq!(cloned.cpu_time_user_us, Some(3));
        assert_eq!(cloned.cpu_time_system_us, Some(4));
        assert_eq!(cloned.wasm_fuel_consumed, Some(5));
        assert_eq!(cloned.io_read_bytes, Some(6));
        assert_eq!(cloned.io_write_bytes, Some(7));
        assert_eq!(cloned.collected_at, Some(collected_at));
    }

    #[test]
    fn error_code_as_str_covers_all_current_variants() {
        let cases = [
            (ErrorCode::CommandTimeout, "command_timeout"),
            (ErrorCode::CommandExit(2), "command_exit"),
            (ErrorCode::CommandKilled, "command_killed"),
            (ErrorCode::FileNotFound, "file_not_found"),
            (ErrorCode::FilePermissionDenied, "file_permission_denied"),
            (ErrorCode::FileTooLarge, "file_too_large"),
            (ErrorCode::NotDirectory, "not_directory"),
            (ErrorCode::HttpDeniedHost, "http_denied_host"),
            (ErrorCode::HttpTimeout, "http_timeout"),
            (ErrorCode::HttpBodyTooLarge, "http_body_too_large"),
            (ErrorCode::HttpConnectFail, "http_connect_fail"),
            (ErrorCode::HttpTlsFail, "http_tls_fail"),
            (ErrorCode::HttpInvalidUrl, "http_invalid_url"),
            (ErrorCode::SandboxNotReady, "sandbox_not_ready"),
            (ErrorCode::SandboxDestroyed, "sandbox_destroyed"),
            (ErrorCode::SandboxCreateFailed, "sandbox_create_failed"),
            (ErrorCode::InvalidConfig, "invalid_config"),
            (ErrorCode::UnsupportedPlatform, "unsupported_platform"),
            (ErrorCode::MemoryLimitExceeded, "memory_limit_exceeded"),
            (ErrorCode::CpuLimitExceeded, "cpu_limit_exceeded"),
            (ErrorCode::HttpDeniedAcl, "http_denied_acl"),
        ];

        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
        }
    }

    #[test]
    fn sandbox_error_from_io_preserves_io_kind() {
        let error: SandboxError =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied").into();

        match error {
            SandboxError::Io(io_error) => {
                assert_eq!(io_error.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected SandboxError::Io, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_snapshot_round_trip_preserves_bytes() {
        let original = vec![0x4d, 0x4d, 0x42, 0x58, 0x01, 0x02];

        let snapshot = SandboxSnapshot::from_owned_bytes(original.clone())
            .expect("snapshot creation must succeed");

        assert_eq!(
            snapshot
                .as_bytes()
                .expect("memory snapshot bytes must be readable"),
            original.as_slice()
        );
        assert_eq!(
            snapshot
                .to_bytes()
                .expect("memory snapshot bytes must be copyable"),
            original
        );
        assert_eq!(snapshot.size(), 6);
    }

    #[test]
    fn sandbox_snapshot_rejects_empty_bytes() {
        let error = SandboxSnapshot::from_bytes(&[]).expect_err("empty snapshot must be rejected");

        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn sandbox_snapshot_file_mode_exposes_metadata_only() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be later than UNIX_EPOCH")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mimobox-sandbox-snapshot-{}-{}.bin",
            std::process::id(),
            unique
        ));

        fs::write(&path, b"file-backed-snapshot").expect("test snapshot file write must succeed");

        let snapshot =
            SandboxSnapshot::from_file(path.clone()).expect("file snapshot creation must succeed");

        assert_eq!(snapshot.memory_file_path(), Some(path.as_path()));
        assert_eq!(snapshot.size(), b"file-backed-snapshot".len());
        assert!(matches!(
            snapshot
                .as_bytes()
                .expect_err("file snapshot should not expose memory bytes"),
            SandboxError::InvalidSnapshot
        ));
        assert_eq!(
            snapshot
                .to_bytes()
                .expect("file snapshot bytes must be readable"),
            b"file-backed-snapshot"
        );
        assert_eq!(
            snapshot
                .clone()
                .into_bytes()
                .expect("file snapshot must be convertible into bytes"),
            b"file-backed-snapshot"
        );

        fs::remove_file(path).expect("test snapshot file cleanup must succeed");
    }

    #[test]
    fn sandbox_snapshot_file_mode_rejects_size_change() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be later than UNIX_EPOCH")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mimobox-sandbox-snapshot-resize-{}-{}.bin",
            std::process::id(),
            unique
        ));

        fs::write(&path, b"snapshot").expect("test snapshot file write must succeed");
        let snapshot =
            SandboxSnapshot::from_file(path.clone()).expect("file snapshot creation must succeed");
        fs::write(&path, b"snapshot-replaced").expect("test snapshot replacement must succeed");

        assert!(matches!(
            snapshot
                .to_bytes()
                .expect_err("changed snapshot file size must be rejected"),
            SandboxError::InvalidSnapshot
        ));

        fs::remove_file(path).expect("test snapshot file cleanup must succeed");
    }
}
