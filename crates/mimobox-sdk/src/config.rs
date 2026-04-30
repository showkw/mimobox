use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::SdkError;
use mimobox_core::{
    BLOCKED_ENV_VARS, MAX_ENV_KEY_BYTES, MAX_MEMORY_LIMIT_MB, NamespaceDegradation, SandboxConfig,
    SeccompProfile,
};

/// Isolation level selection strategy.
///
/// Controls which sandboxing backend is used. `Auto` enables smart routing
/// based on command type and trust level; explicit variants force a specific backend.
///
/// # Smart Routing Rules (Auto)
///
/// - `TrustLevel::Untrusted` on Linux + `vm` feature → `MicroVm`
/// - `.wasm` / `.wat` / `.wast` files → `Wasm`
/// - All other commands → `Os`
///
/// `TrustLevel::Untrusted` has priority over Wasm detection so untrusted Wasm
/// files cannot bypass the microVM fail-closed requirement.
///
/// # Examples
///
/// ```
/// use mimobox_sdk::IsolationLevel;
///
/// let level = IsolationLevel::Auto;
/// assert_eq!(level, IsolationLevel::default());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// Smart routing based on command type and `TrustLevel`.
    #[default]
    Auto,
    /// OS-level isolation: Landlock + Seccomp + Namespaces (Linux) or Seatbelt (macOS).
    Os,
    /// Wasm-level isolation via Wasmtime. Sub-millisecond cold start.
    Wasm,
    /// microVM-level isolation via KVM. Hardware-enforced boundary.
    MicroVm,
}

/// Trust level for code being executed.
///
/// Affects auto-routing decisions when `IsolationLevel::Auto` is used.
/// `Untrusted` code is always routed to the strongest available isolation.
///
/// # Fail-Closed Behavior
///
/// When `TrustLevel::Untrusted` is set and the microVM backend is unavailable
/// (non-Linux platform or `vm` feature not enabled), the SDK returns an error
/// instead of silently downgrading to OS-level isolation.
///
/// # Examples
///
/// ```
/// use mimobox_sdk::TrustLevel;
///
/// let level = TrustLevel::SemiTrusted;
/// assert_eq!(level, TrustLevel::default());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustLevel {
    /// Trusted code: self-authored or fully audited.
    Trusted,
    /// Semi-trusted code: third-party libraries or partially audited code.
    #[default]
    SemiTrusted,
    /// Untrusted code: user-submitted, downloaded, or otherwise unverified.
    Untrusted,
}

/// Network access policy for the sandbox.
///
/// Controls whether the sandbox can access the network and through which channels.
/// The default policy denies all network access.
///
/// # Examples
///
/// ```
/// use mimobox_sdk::NetworkPolicy;
///
/// let policy = NetworkPolicy::DenyAll;
/// match policy {
///     NetworkPolicy::DenyAll => {},
///     _ => panic!("expected DenyAll"),
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub enum NetworkPolicy {
    /// Deny all network access. Default policy.
    #[default]
    DenyAll,
    /// Keep direct sandbox network blocked, but allow HTTP requests through the
    /// host-side controlled proxy to the specified domains.
    AllowDomains(Vec<String>),
    /// Allow unrestricted network access. Uses a permissive Seccomp profile.
    AllowAll,
}

/// SDK-level configuration for sandbox creation and behavior.
///
/// Use [`Config::builder()`] to construct a `Config` with the builder pattern.
/// All fields have sensible defaults that prioritize security.
///
/// # Key Behaviors
///
/// - **Memory**: For the microVM backend, effective guest memory is
///   `min(memory_limit_mb, vm_memory_mb)`.
/// - **Processes**: Linux OS backend maps `max_processes` to cgroup v2
///   `pids.max`; `None` uses the backend default.
/// - **Timeout**: Internally rounded up to whole seconds. For example,
///   `1500ms` becomes `2s`.
/// - **HTTP domains**: The `allowed_http_domains` list supports glob patterns
///   like `*.openai.com`. It is combined with `NetworkPolicy::AllowDomains`.
///
/// # Examples
///
/// ```
/// use mimobox_sdk::Config;
///
/// let config = Config::default();
/// assert_eq!(config.vm_vcpu_count, 1);
/// assert_eq!(config.vm_memory_mb, 256);
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    /// Isolation level selection strategy. `Auto` enables smart routing.
    pub isolation: IsolationLevel,
    /// Trust level affecting auto-routing decisions.
    pub trust_level: TrustLevel,
    /// Network access policy.
    pub network: NetworkPolicy,
    /// Command execution timeout. `None` means no timeout.
    pub timeout: Option<Duration>,
    /// Memory limit in MiB. Applied via cgroups v2 or setrlimit.
    pub memory_limit_mb: Option<u64>,
    /// Maximum process count inside one sandbox. `None` uses the backend default.
    pub max_processes: Option<u32>,
    /// CPU time quota in microseconds. `None` means unlimited.
    pub cpu_quota_us: Option<u64>,
    /// CPU period in microseconds. Defaults to 100000 (100ms).
    pub cpu_period_us: u64,
    /// Read-only mount paths inside the sandbox.
    pub fs_readonly: Vec<PathBuf>,
    /// Read-write mount paths inside the sandbox.
    pub fs_readwrite: Vec<PathBuf>,
    /// Optional sandbox-private temporary directory.
    ///
    /// When set, this path is added to the backend read-write allowlist.
    /// `None` keeps the default write surface empty instead of exposing global `/tmp`.
    pub sandbox_tmp_dir: Option<PathBuf>,
    /// HTTP proxy domain whitelist (supports glob patterns like `*.openai.com`).
    pub allowed_http_domains: Vec<String>,
    /// Whether to allow child process creation (fork/clone) inside the sandbox.
    pub allow_fork: bool,
    /// Namespace degradation policy. Defaults to FailClosed.
    pub namespace_degradation: NamespaceDegradation,
    /// microVM vCPU count. Only affects the microVM backend.
    pub vm_vcpu_count: u8,
    /// microVM guest memory size in MiB. Capped by `memory_limit_mb` if set.
    pub vm_memory_mb: u32,
    /// Custom microVM kernel image path. Falls back to `~/.mimobox/assets/vmlinux` if unset.
    pub kernel_path: Option<PathBuf>,
    /// Custom microVM rootfs path. Falls back to `~/.mimobox/assets/rootfs.cpio.gz` if unset.
    pub rootfs_path: Option<PathBuf>,
    /// VM security profile controlling guest kernel Spectre/Meltdown mitigations and KASLR.
    /// Defaults to `Secure` with mitigations preserved. Set to `Performance` for best
    /// performance only in fully trusted environments.
    #[cfg(feature = "vm")]
    pub vm_security_profile: mimobox_vm::VmSecurityProfile,
    /// HTTP ACL policy controlling method/host/path access for the host-side HTTP proxy.
    /// Complements allowed_http_domains: entries are converted to ANY host /* allow rules.
    pub http_acl: mimobox_core::HttpAclPolicy,
    /// Persistent environment variables applied when the sandbox is created.
    /// Merge priority from low to high: backend minimal environment < env_vars < per-command env.
    pub env_vars: std::collections::HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            isolation: IsolationLevel::Auto,
            trust_level: TrustLevel::default(),
            network: NetworkPolicy::default(),
            timeout: Some(Duration::from_secs(30)),
            memory_limit_mb: Some(512),
            max_processes: None,
            cpu_quota_us: None,
            cpu_period_us: 100_000,
            fs_readonly: vec![
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/bin".into(),
                "/sbin".into(),
                "/dev".into(),
                "/proc".into(),
                "/etc".into(),
            ],
            fs_readwrite: Vec::new(),
            sandbox_tmp_dir: None,
            allowed_http_domains: Vec::new(),
            allow_fork: false,
            namespace_degradation: NamespaceDegradation::FailClosed,
            vm_vcpu_count: 1,
            vm_memory_mb: 256,
            kernel_path: None,
            rootfs_path: None,
            #[cfg(feature = "vm")]
            vm_security_profile: mimobox_vm::VmSecurityProfile::default(),
            http_acl: mimobox_core::HttpAclPolicy::default(),
            env_vars: std::collections::HashMap::new(),
        }
    }
}

impl Config {
    /// Returns a [`ConfigBuilder`] for constructing a `Config` with the builder pattern.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::{Config, IsolationLevel};
    /// use std::time::Duration;
    ///
    /// let config = Config::builder()
    ///     .isolation(IsolationLevel::Os)
    ///     .timeout(Duration::from_secs(10))
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.isolation, IsolationLevel::Os);
    /// ```
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Validate SDK config before it reaches backend implementations.
    pub(crate) fn validate(&self) -> Result<(), SdkError> {
        if self.vm_vcpu_count == 0 {
            return Err(invalid_config(
                "vm_vcpu_count must be at least 1",
                "vcpu_count minimum is 1",
            ));
        }

        if self.vm_memory_mb == 0 {
            return Err(invalid_config(
                "vm_memory_mb must be at least 1, recommended 256 MB",
                "vm_memory_mb minimum is 1, recommended 256 MB",
            ));
        }

        if let Some(timeout) = self.timeout
            && timeout.is_zero()
        {
            return Err(invalid_config(
                "timeout cannot be zero",
                "timeout must be > 0, recommended 30s",
            ));
        }

        if self.memory_limit_mb == Some(0) {
            return Err(invalid_config(
                "memory_limit_mb must be at least 1",
                "memory_limit_mb minimum is 1",
            ));
        }

        if let Some(memory_limit_mb) = self.memory_limit_mb
            && memory_limit_mb > MAX_MEMORY_LIMIT_MB
        {
            return Err(invalid_config(
                format!(
                    "memory_limit_mb={memory_limit_mb} exceeds maximum {MAX_MEMORY_LIMIT_MB} MB"
                ),
                format!("memory_limit_mb maximum is {MAX_MEMORY_LIMIT_MB}, recommended 256-512 MB"),
            ));
        }

        if self.max_processes == Some(0) {
            return Err(invalid_config(
                "max_processes must be at least 1, or set to None for backend default",
                "max_processes minimum is 1, or set to None for backend default",
            ));
        }

        if self.cpu_period_us == 0 {
            return Err(invalid_config(
                "cpu_period_us must be at least 1, recommended 100000",
                "cpu_period_us minimum is 1, recommended 100000",
            ));
        }

        // SECURITY: Untrusted code must not open full network access; use DenyAll or AllowDomains.
        if self.trust_level == TrustLevel::Untrusted
            && matches!(self.network, NetworkPolicy::AllowAll)
        {
            return Err(invalid_config(
                "Untrusted trust level cannot use NetworkPolicy::AllowAll",
                "Use DenyAll or AllowDomains for untrusted code",
            ));
        }

        // SECURITY: Untrusted code must have a timeout to prevent resource exhaustion.
        if self.trust_level == TrustLevel::Untrusted && self.timeout.is_none() {
            return Err(invalid_config(
                "Untrusted trust level requires a timeout",
                "Set timeout_secs to a finite value for untrusted code",
            ));
        }

        // SECURITY: Untrusted code must have a memory limit to prevent OOM attacks.
        if self.trust_level == TrustLevel::Untrusted && self.memory_limit_mb.is_none() {
            return Err(invalid_config(
                "Untrusted trust level requires a memory limit",
                "Set memory_limit_mb for untrusted code",
            ));
        }

        if matches!(self.network, NetworkPolicy::DenyAll) && !self.allowed_http_domains.is_empty() {
            return Err(invalid_config(
                "network=DenyAll but allowed_http_domains is non-empty, config conflict",
                "Use NetworkPolicy::AllowDomains or clear allowed_http_domains",
            ));
        }

        for domain in resolve_allowed_http_domains(self) {
            validate_http_domain(&domain)?;
        }

        validate_env_vars(&self.env_vars)?;
        validate_microvm_artifact_paths(self)?;

        // NetworkPolicy::AllowAll is mutually exclusive with http_acl (fail-closed).
        if matches!(self.network, NetworkPolicy::AllowAll)
            && (!self.http_acl.allow.is_empty() || !self.http_acl.deny.is_empty())
        {
            return Err(invalid_config(
                "network=AllowAll conflicts with http_acl, cannot be used together",
                "Use NetworkPolicy::AllowDomains instead of AllowAll, or remove http_acl config",
            ));
        }

        self.to_sandbox_config()
            .validate()
            .map_err(SdkError::from_core_config_error)?;

        Ok(())
    }

    /// Converts to the internal `mimobox_core::SandboxConfig`.
    pub(crate) fn to_sandbox_config(&self) -> SandboxConfig {
        let deny_network = resolve_deny_network(&self.network);
        let domains = resolve_allowed_http_domains(self);

        let mut config = SandboxConfig::default();
        config.fs_readonly = self.fs_readonly.clone();
        config.fs_readwrite = self.fs_readwrite.clone();
        if let Some(sandbox_tmp_dir) = &self.sandbox_tmp_dir
            && !config
                .fs_readwrite
                .iter()
                .any(|path| path == sandbox_tmp_dir)
        {
            config.fs_readwrite.push(sandbox_tmp_dir.clone());
        }
        config.deny_network = deny_network;
        config.memory_limit_mb = self.memory_limit_mb;
        config.max_processes = self.max_processes;
        config.cpu_quota_us = self.cpu_quota_us;
        config.cpu_period_us = self.cpu_period_us;
        config.timeout_secs = self.timeout.map(round_up_timeout_secs);
        config.seccomp_profile = resolve_seccomp_profile(deny_network, self.allow_fork);
        config.allow_fork = self.allow_fork;
        config.allowed_http_domains = domains.clone();
        config.namespace_degradation = self.namespace_degradation;
        config.http_acl = self.http_acl.clone();
        config.env_vars = self.env_vars.clone();

        // Convert allowed_http_domains into http_acl allow rules for backward compatibility.
        for domain in &domains {
            let already_covered = config.http_acl.allow.iter().any(|rule| {
                rule.host == *domain
                    && rule.path == "/*"
                    && rule.method == mimobox_core::HttpMethod::Any
            });
            if !already_covered {
                config.http_acl.allow.push(mimobox_core::HttpAclRule {
                    method: mimobox_core::HttpMethod::Any,
                    host: domain.clone(),
                    path: "/*".to_string(),
                });
            }
        }

        config
    }

    #[cfg(feature = "vm")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    /// Provides the to microvm config operation.
    pub(crate) fn to_microvm_config(&self) -> Result<mimobox_vm::MicrovmConfig, SdkError> {
        let defaults = mimobox_vm::MicrovmConfig::default();
        let memory_mb = resolve_vm_memory_mb(self)?;

        Ok(mimobox_vm::MicrovmConfig {
            vcpu_count: self.vm_vcpu_count,
            memory_mb,
            cpu_quota_us: self.cpu_quota_us,
            kernel_path: self
                .kernel_path
                .clone()
                .unwrap_or_else(|| defaults.kernel_path.clone()),
            rootfs_path: self
                .rootfs_path
                .clone()
                .unwrap_or_else(|| defaults.rootfs_path.clone()),
            security_profile: self.vm_security_profile,
        })
    }
}

fn resolve_deny_network(network: &NetworkPolicy) -> bool {
    match network {
        NetworkPolicy::DenyAll => true,
        NetworkPolicy::AllowDomains(_) => true,
        NetworkPolicy::AllowAll => false,
    }
}

fn resolve_allowed_http_domains(config: &Config) -> Vec<String> {
    let mut domains = Vec::with_capacity(config.allowed_http_domains.len());
    let mut seen = HashSet::with_capacity(config.allowed_http_domains.len());

    for domain in &config.allowed_http_domains {
        if seen.insert(domain.as_str()) {
            domains.push(domain.clone());
        }
    }

    if let NetworkPolicy::AllowDomains(network_domains) = &config.network {
        for domain in network_domains {
            if seen.insert(domain.as_str()) {
                domains.push(domain.clone());
            }
        }
    }
    domains
}

fn round_up_timeout_secs(timeout: Duration) -> u64 {
    if timeout.is_zero() {
        return 0;
    }

    let nanos = timeout.as_nanos();
    let seconds = nanos.div_ceil(1_000_000_000);
    u64::try_from(seconds).unwrap_or(u64::MAX)
}

fn resolve_seccomp_profile(deny_network: bool, allow_fork: bool) -> SeccompProfile {
    match (deny_network, allow_fork) {
        (true, true) => SeccompProfile::EssentialWithFork,
        (true, false) => SeccompProfile::Essential,
        (false, true) => SeccompProfile::NetworkWithFork,
        (false, false) => SeccompProfile::Network,
    }
}

fn validate_http_domain(domain: &str) -> Result<(), SdkError> {
    if domain.is_empty()
        || domain
            .chars()
            .any(|character| matches!(character, ' ' | '\t' | '\n' | '\r'))
        || has_invalid_domain_wildcard(domain)
        || is_plain_ip_domain(domain)
    {
        return Err(invalid_config(
            format!("allowed_http_domains contains invalid domain '{domain}'"),
            "Use standard domain format, e.g. example.com or *.example.com; IP addresses not supported",
        ));
    }

    Ok(())
}

fn validate_env_vars(env_vars: &std::collections::HashMap<String, String>) -> Result<(), SdkError> {
    for (key, value) in env_vars {
        if key.is_empty() || key.contains('=') || key.contains('\0') || key.contains(' ') {
            return Err(invalid_config(
                format!("env_vars contains invalid key: '{key}'"),
                "Environment variable names must be non-empty and must not contain '=', NUL, or spaces",
            ));
        }
        if key.len() > MAX_ENV_KEY_BYTES {
            return Err(invalid_config(
                format!("env_vars key '{key}' exceeds {MAX_ENV_KEY_BYTES} bytes"),
                format!("Environment variable names must be at most {MAX_ENV_KEY_BYTES} bytes"),
            ));
        }
        if value.contains('\0') {
            return Err(invalid_config(
                format!("env_vars value for key '{key}' contains NUL byte"),
                "Environment variable values must not contain NUL bytes",
            ));
        }
        if let Some(blocked) = BLOCKED_ENV_VARS
            .iter()
            .find(|blocked| key.eq_ignore_ascii_case(blocked))
        {
            return Err(invalid_config(
                format!("env_vars contains blocked security-sensitive key: '{key}'"),
                format!("Security-sensitive environment variable is not allowed: {blocked}"),
            ));
        }
    }
    Ok(())
}

fn validate_microvm_artifact_paths(config: &Config) -> Result<(), SdkError> {
    if config.isolation != IsolationLevel::MicroVm {
        return Ok(());
    }

    validate_optional_path_exists("kernel_path", config.kernel_path.as_deref())?;
    validate_optional_path_exists("rootfs_path", config.rootfs_path.as_deref())
}

fn validate_optional_path_exists(label: &str, path: Option<&Path>) -> Result<(), SdkError> {
    let Some(path) = path else {
        return Ok(());
    };

    match path.try_exists() {
        Ok(true) => Ok(()),
        Ok(false) => Err(invalid_config(
            format!("{label} path does not exist: {}", path.display()),
            "Please ensure the path exists",
        )),
        Err(error) => Err(invalid_config(
            format!("{label} path inaccessible: {} ({error})", path.display()),
            "Please check path permissions and ensure it exists",
        )),
    }
}

fn invalid_config(message: impl Into<String>, suggestion: impl Into<String>) -> SdkError {
    SdkError::invalid_config(message, Some(suggestion.into()))
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

#[cfg(feature = "vm")]
fn resolve_vm_memory_mb(config: &Config) -> Result<u32, SdkError> {
    let requested_memory_mb = u64::from(config.vm_memory_mb);
    let effective_memory_mb = match config.memory_limit_mb {
        Some(memory_limit_mb) => requested_memory_mb.min(memory_limit_mb),
        None => requested_memory_mb,
    };

    u32::try_from(effective_memory_mb).map_err(|_| {
        invalid_config(
            format!("microVM guest memory exceeds u32 range: {effective_memory_mb} MB"),
            "Please reduce vm_memory_mb or memory_limit_mb",
        )
    })
}

/// Fluent builder for constructing [`Config`] instances.
///
/// All methods consume and return `self`, enabling method chaining.
/// Call [`build()`](ConfigBuilder::build) to validate and produce the final `Config`.
///
/// # Examples
///
/// ```
/// use mimobox_sdk::{Config, IsolationLevel, NetworkPolicy};
/// use std::time::Duration;
///
/// let config = Config::builder()
///     .isolation(IsolationLevel::MicroVm)
///     .timeout(Duration::from_secs(60))
///     .memory_limit_mb(256)
///     .allowed_http_domains(["api.openai.com"])
///     .build()
///     .expect("config validation failed");
///
/// assert_eq!(config.isolation, IsolationLevel::MicroVm);
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    inner: Config,
}

impl ConfigBuilder {
    /// Set the isolation level selection strategy.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::{Config, IsolationLevel};
    ///
    /// let config = Config::builder()
    ///     .isolation(IsolationLevel::Wasm)
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.isolation, IsolationLevel::Wasm);
    /// ```
    pub fn isolation(mut self, level: IsolationLevel) -> Self {
        self.inner.isolation = level;
        self
    }

    /// Set the trust level, affecting auto-routing decisions.
    ///
    /// When set to `TrustLevel::Untrusted`, the SDK will fail-closed if the
    /// microVM backend is not available, rather than silently downgrading.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::{Config, TrustLevel};
    ///
    /// let config = Config::builder()
    ///     .trust_level(TrustLevel::Untrusted)
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.trust_level, TrustLevel::Untrusted);
    /// ```
    pub fn trust_level(mut self, level: TrustLevel) -> Self {
        self.inner.trust_level = level;
        self
    }

    /// Set the network access policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::{Config, NetworkPolicy};
    ///
    /// let config = Config::builder()
    ///     .network(NetworkPolicy::AllowDomains(vec!["api.openai.com".to_string()]))
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert!(matches!(config.network, NetworkPolicy::AllowDomains(_)));
    /// ```
    pub fn network(mut self, policy: NetworkPolicy) -> Self {
        self.inner.network = policy;
        self
    }

    /// Set the default command execution timeout.
    ///
    /// Internally rounded up to whole seconds. For example, `1500ms` maps to `2s`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    /// use std::time::Duration;
    ///
    /// let config = Config::builder()
    ///     .timeout(Duration::from_secs(10))
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.timeout, Some(Duration::from_secs(10)));
    /// ```
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner.timeout = Some(timeout);
        self
    }

    /// Set the memory limit in MiB.
    ///
    /// For the microVM backend, the effective guest memory is
    /// `min(memory_limit_mb, vm_memory_mb)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .memory_limit_mb(256)
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.memory_limit_mb, Some(256));
    /// ```
    pub fn memory_limit_mb(mut self, mb: u64) -> Self {
        self.inner.memory_limit_mb = Some(mb);
        self
    }

    /// Set the maximum process count inside one sandbox.
    ///
    /// Linux OS backend maps this to cgroup v2 `pids.max`. `Config::default()`
    /// leaves it unset so the backend can apply its secure default.
    pub fn max_processes(mut self, processes: u32) -> Self {
        self.inner.max_processes = Some(processes);
        self
    }

    /// Set the CPU time quota in microseconds.
    ///
    /// Linux OS backend maps this to cgroup v2 `cpu.max`; microVM stores the
    /// value for backend-specific enforcement. Other backends ignore it.
    pub fn cpu_quota(mut self, quota_us: u64) -> Self {
        self.inner.cpu_quota_us = Some(quota_us);
        self
    }

    /// Set the CPU period in microseconds.
    pub fn cpu_period(mut self, period_us: u64) -> Self {
        self.inner.cpu_period_us = period_us;
        self
    }

    /// Set the read-only mount paths.
    ///
    /// Paths listed here are mounted read-only inside the sandbox.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .fs_readonly(["/usr", "/lib"])
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.fs_readonly.len(), 2);
    /// ```
    pub fn fs_readonly(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.inner.fs_readonly = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Set the read-write mount paths.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .fs_readwrite(["/tmp", "/workspace"])
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.fs_readwrite.len(), 2);
    /// ```
    pub fn fs_readwrite(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.inner.fs_readwrite = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Set a sandbox-private temporary directory.
    ///
    /// This is the secure replacement for relying on global `/tmp`: the path is
    /// explicitly added to the backend read-write allowlist, while the default
    /// configuration keeps `fs_readwrite` empty.
    pub fn sandbox_tmp_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.sandbox_tmp_dir = Some(path.into());
        self
    }

    /// Set whether child process creation (fork/clone) is allowed inside the sandbox.
    ///
    /// Default is `false`. Set to `true` for shell or interpreter workloads.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .allow_fork(true)
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert!(config.allow_fork);
    /// ```
    pub fn allow_fork(mut self, allow: bool) -> Self {
        self.inner.allow_fork = allow;
        self
    }

    /// Set Linux namespace degradation behavior.
    ///
    /// Defaults to `FailClosed`; any namespace creation failure rejects execution.
    pub fn namespace_degradation(mut self, policy: NamespaceDegradation) -> Self {
        self.inner.namespace_degradation = policy;
        self
    }

    /// Set the HTTP proxy domain whitelist.
    ///
    /// Supports glob patterns like `*.openai.com`. Combined with
    /// `NetworkPolicy::AllowDomains` without duplicates.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .allowed_http_domains(["api.openai.com", "*.openai.com"])
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.allowed_http_domains.len(), 2);
    /// ```
    pub fn allowed_http_domains(
        mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.inner.allowed_http_domains = domains.into_iter().map(Into::into).collect();
        if matches!(self.inner.network, NetworkPolicy::DenyAll) {
            self.inner.network = NetworkPolicy::AllowDomains(Vec::new());
        }
        self
    }

    /// Set HTTP ACL allow rules in append mode.
    ///
    /// Each rule is a string in 'METHOD host/path' format.
    /// Parse failures return fail-closed errors so misconfigurations are not ignored.
    pub fn http_acl_allow_str(mut self, rules: &[&str]) -> Result<Self, SdkError> {
        for rule_str in rules {
            match mimobox_core::HttpAclRule::parse(rule_str) {
                Ok(rule) => self.inner.http_acl.allow.push(rule),
                Err(err) => {
                    // SECURITY: fail-closed invalid ACL rules instead of silently skipping them.
                    return Err(SdkError::Config(format!(
                        "HTTP ACL allow rule parse failed: {} - {}",
                        rule_str, err
                    )));
                }
            }
        }
        if matches!(self.inner.network, NetworkPolicy::DenyAll)
            && !self.inner.http_acl.allow.is_empty()
        {
            self.inner.network = NetworkPolicy::AllowDomains(Vec::new());
        }
        Ok(self)
    }

    /// Set HTTP ACL allow rules from already parsed rules.
    pub fn http_acl_allow(mut self, rules: Vec<mimobox_core::HttpAclRule>) -> Self {
        self.inner.http_acl.allow.extend(rules);
        if matches!(self.inner.network, NetworkPolicy::DenyAll)
            && !self.inner.http_acl.allow.is_empty()
        {
            self.inner.network = NetworkPolicy::AllowDomains(Vec::new());
        }
        self
    }

    /// Set HTTP ACL deny rules in append mode.
    ///
    /// Each rule is a string in 'METHOD host/path' format.
    /// Parse failures return fail-closed errors so misconfigurations are not ignored.
    pub fn http_acl_deny_str(mut self, rules: &[&str]) -> Result<Self, SdkError> {
        for rule_str in rules {
            match mimobox_core::HttpAclRule::parse(rule_str) {
                Ok(rule) => self.inner.http_acl.deny.push(rule),
                Err(err) => {
                    // SECURITY: fail-closed invalid ACL rules instead of silently skipping them.
                    return Err(SdkError::Config(format!(
                        "HTTP ACL deny rule parse failed: {} - {}",
                        rule_str, err
                    )));
                }
            }
        }
        Ok(self)
    }

    /// Set HTTP ACL deny rules from already parsed rules.
    pub fn http_acl_deny(mut self, rules: Vec<mimobox_core::HttpAclRule>) -> Self {
        self.inner.http_acl.deny.extend(rules);
        self
    }

    /// Set the microVM vCPU count.
    ///
    /// Only affects the microVM backend. Default is `1`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .vm_vcpu_count(4)
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.vm_vcpu_count, 4);
    /// ```
    pub fn vm_vcpu_count(mut self, count: u8) -> Self {
        self.inner.vm_vcpu_count = count;
        self
    }

    /// Set the microVM guest memory size in MiB.
    ///
    /// Capped by `memory_limit_mb` if set. Default is `256` MiB.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .vm_memory_mb(512)
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.vm_memory_mb, 512);
    /// ```
    pub fn vm_memory_mb(mut self, mb: u32) -> Self {
        self.inner.vm_memory_mb = mb;
        self
    }

    /// Set the microVM kernel image path.
    ///
    /// If unset, falls back to `$VM_ASSETS_DIR/vmlinux` or `~/.mimobox/assets/vmlinux`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .kernel_path("/opt/mimobox/vmlinux")
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.kernel_path, Some(std::path::PathBuf::from("/opt/mimobox/vmlinux")));
    /// ```
    pub fn kernel_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.kernel_path = Some(path.into());
        self
    }

    /// Set the microVM rootfs path.
    ///
    /// If unset, falls back to `$VM_ASSETS_DIR/rootfs.cpio.gz` or `~/.mimobox/assets/rootfs.cpio.gz`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .rootfs_path("/opt/mimobox/rootfs.cpio.gz")
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.rootfs_path, Some(std::path::PathBuf::from("/opt/mimobox/rootfs.cpio.gz")));
    /// ```
    pub fn rootfs_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.rootfs_path = Some(path.into());
        self
    }

    #[cfg(feature = "vm")]
    /// Set the VM security profile, controlling kernel mitigations and KASLR.
    ///
    /// Default is `VmSecurityProfile::Secure` (all mitigations enabled).
    /// Set to `Performance` only in fully trusted benchmark environments.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    /// use mimobox_vm::VmSecurityProfile;
    ///
    /// let config = Config::builder()
    ///     .vm_security_profile(VmSecurityProfile::Performance)
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.vm_security_profile, VmSecurityProfile::Performance);
    /// ```
    pub fn vm_security_profile(mut self, profile: mimobox_vm::VmSecurityProfile) -> Self {
        self.inner.vm_security_profile = profile;
        self
    }

    /// Remove the default timeout, allowing commands to run indefinitely.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder()
    ///     .no_timeout()
    ///     .build()
    ///     .expect("config validation failed");
    ///
    /// assert_eq!(config.timeout, None);
    /// ```
    pub fn no_timeout(mut self) -> Self {
        self.inner.timeout = None;
        self
    }

    /// Add a persistent environment variable applied when the sandbox is created.
    ///
    /// Merge priority from low to high: backend minimal environment < env_vars < per-command env.
    /// Security-sensitive variables such as LD_PRELOAD are rejected during build().
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner.env_vars.insert(key.into(), value.into());
        self
    }

    /// Set persistent environment variables applied when the sandbox is created.
    ///
    /// Security-sensitive variables such as LD_PRELOAD are rejected during build().
    pub fn env_vars(mut self, vars: std::collections::HashMap<String, String>) -> Self {
        self.inner.env_vars = vars;
        self
    }

    /// Validate and produce the final `Config`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder().build().expect("config validation failed");
    /// assert_eq!(config.isolation, mimobox_sdk::IsolationLevel::Auto);
    /// ```
    pub fn build(self) -> Result<Config, SdkError> {
        self.inner.validate()?;
        Ok(self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimobox_core::{BLOCKED_ENV_VARS, ErrorCode, MAX_ENV_KEY_BYTES};

    fn assert_invalid_config_suggestion(
        result: Result<Config, SdkError>,
        expected_suggestion: &str,
    ) {
        match result {
            Err(SdkError::Sandbox {
                code, suggestion, ..
            }) => {
                assert_eq!(code, ErrorCode::InvalidConfig);
                assert_eq!(suggestion.as_deref(), Some(expected_suggestion));
            }
            Err(other) => panic!("expected InvalidConfig error, got: {other}"),
            Ok(_) => panic!("invalid config should not build successfully"),
        }
    }

    fn assert_env_vars_rejected(key: &str, value: &str) {
        let result = Config::builder().env_var(key, value).build();

        assert!(
            result.is_err(),
            "env_vars key={key:?}, value={value:?} should be rejected"
        );
    }

    #[test]
    fn default_config_keeps_microvm_artifact_paths_unset() {
        let config = Config::default();

        assert_eq!(config.vm_vcpu_count, 1);
        assert_eq!(config.vm_memory_mb, 256);
        assert_eq!(config.kernel_path, None);
        assert_eq!(config.rootfs_path, None);
        assert_eq!(config.sandbox_tmp_dir, None);
        assert!(config.fs_readwrite.is_empty());
        assert!(config.to_sandbox_config().fs_readwrite.is_empty());
    }

    #[test]
    fn default_config_security_values_are_correct() {
        let config = Config::default();

        assert_eq!(config.isolation, IsolationLevel::Auto);
        assert_eq!(config.trust_level, TrustLevel::SemiTrusted);
        assert!(matches!(config.network, NetworkPolicy::DenyAll));
        assert_eq!(config.timeout, Some(Duration::from_secs(30)));
        assert_eq!(config.memory_limit_mb, Some(512));
        assert_eq!(config.max_processes, None);
        assert_eq!(config.cpu_quota_us, None);
        assert_eq!(config.cpu_period_us, 100_000);
        assert!(!config.allow_fork);
        assert_eq!(
            config.namespace_degradation,
            NamespaceDegradation::FailClosed
        );
        assert!(config.allowed_http_domains.is_empty());
        assert!(config.http_acl.allow.is_empty());
        assert!(config.http_acl.deny.is_empty());

        let sandbox_config = config.to_sandbox_config();
        assert!(sandbox_config.deny_network);
        assert_eq!(sandbox_config.timeout_secs, Some(30));
        assert!(matches!(
            sandbox_config.seccomp_profile,
            SeccompProfile::Essential
        ));
    }

    #[test]
    fn test_env_vars_rejects_nul_in_key() {
        assert_env_vars_rejected("MIMOBOX\0TOKEN", "value");
    }

    #[test]
    fn test_env_vars_rejects_empty_key() {
        assert_env_vars_rejected("", "value");
    }

    #[test]
    fn test_env_vars_rejects_nul_in_value() {
        assert_env_vars_rejected("MIMOBOX_TOKEN", "value\0tail");
    }

    #[test]
    fn test_env_vars_rejects_equals_in_key() {
        assert_env_vars_rejected("MIMOBOX=TOKEN", "value");
    }

    #[test]
    fn test_env_vars_rejects_space_in_key() {
        assert_env_vars_rejected("MIMOBOX TOKEN", "value");
    }

    #[test]
    fn test_env_vars_rejects_overlong_key() {
        assert_env_vars_rejected(&"A".repeat(MAX_ENV_KEY_BYTES + 1), "value");
    }

    #[test]
    fn test_env_vars_rejects_ld_preload() {
        assert_env_vars_rejected("LD_PRELOAD", "/tmp/preload.so");
    }

    #[test]
    fn test_env_vars_rejects_ld_library_path() {
        assert_env_vars_rejected("LD_LIBRARY_PATH", "/tmp/lib");
    }

    #[test]
    fn test_env_vars_rejects_bash_env() {
        assert_env_vars_rejected("BASH_ENV", "/tmp/bashrc");
    }

    #[test]
    fn test_env_vars_rejects_dyld_insert_libraries() {
        assert_env_vars_rejected("DYLD_INSERT_LIBRARIES", "/tmp/lib.dylib");
    }

    #[test]
    fn test_env_vars_rejects_all_blocked_keys() {
        for blocked_key in BLOCKED_ENV_VARS {
            assert_env_vars_rejected(blocked_key, "value");
            assert_env_vars_rejected(&blocked_key.to_ascii_lowercase(), "value");
        }
    }

    #[test]
    fn test_env_vars_accepts_valid_vars() {
        let mut vars = std::collections::HashMap::new();
        vars.insert("MIMOBOX_TOKEN".to_string(), "value".to_string());
        vars.insert("APP_MODE".to_string(), "test".to_string());

        let config = Config::builder()
            .env_vars(vars.clone())
            .build()
            .expect("valid env_vars should build");

        assert_eq!(config.env_vars, vars);
        assert_eq!(config.to_sandbox_config().env_vars, vars);
    }

    #[test]
    fn test_env_vars_case_insensitive_security_check() {
        assert_env_vars_rejected("ld_preload", "/tmp/preload.so");
        assert_env_vars_rejected("dyld_library_path", "/tmp/lib");
    }

    #[test]
    fn env_var_replaces_existing_key_value() {
        let config = Config::builder()
            .env_var("APP_MODE", "dev")
            .env_var("APP_MODE", "test")
            .build()
            .expect("overwriting same env var key should remain valid");

        assert_eq!(config.env_vars.get("APP_MODE"), Some(&"test".to_string()));
        assert_eq!(config.env_vars.len(), 1);
    }

    #[test]
    fn env_vars_replaces_previous_builder_env_state() {
        let vars =
            std::collections::HashMap::from([("FINAL_KEY".to_string(), "final-value".to_string())]);

        let config = Config::builder()
            .env_var("OLD_KEY", "old-value")
            .env_vars(vars.clone())
            .build()
            .expect("replacement env_vars should pass validation");

        assert_eq!(config.env_vars, vars);
        assert!(!config.env_vars.contains_key("OLD_KEY"));
    }

    #[test]
    fn builder_can_override_microvm_resource_config() {
        let config = Config::builder()
            .vm_vcpu_count(4)
            .vm_memory_mb(768)
            .build()
            .expect("config validation failed");

        assert_eq!(config.vm_vcpu_count, 4);
        assert_eq!(config.vm_memory_mb, 768);
    }

    #[test]
    fn builder_can_override_microvm_artifact_paths() {
        let config = Config::builder()
            .kernel_path("/opt/mimobox/vmlinux")
            .rootfs_path("/opt/mimobox/rootfs.cpio.gz")
            .build()
            .expect("config validation failed");

        assert_eq!(
            config.kernel_path,
            Some(PathBuf::from("/opt/mimobox/vmlinux"))
        );
        assert_eq!(
            config.rootfs_path,
            Some(PathBuf::from("/opt/mimobox/rootfs.cpio.gz"))
        );
    }

    #[test]
    fn allow_domains_keep_direct_network_denied_and_forward_whitelist() {
        let config = Config::builder()
            .network(NetworkPolicy::AllowDomains(vec!["example.com".to_string()]))
            .build()
            .expect("config validation failed");

        assert!(config.to_sandbox_config().deny_network);
        assert_eq!(
            config.to_sandbox_config().allowed_http_domains,
            vec!["example.com".to_string()]
        );
    }

    #[test]
    fn allow_all_opens_network_and_uses_network_seccomp_profile() {
        let config = Config::builder()
            .network(NetworkPolicy::AllowAll)
            .allow_fork(true)
            .build()
            .expect("config validation failed");
        let sandbox_config = config.to_sandbox_config();

        assert!(!sandbox_config.deny_network);
        assert!(matches!(
            sandbox_config.seccomp_profile,
            SeccompProfile::NetworkWithFork
        ));
    }

    #[test]
    fn test_untrusted_rejects_allow_all_network() {
        let result = Config::builder()
            .trust_level(TrustLevel::Untrusted)
            .network(NetworkPolicy::AllowAll)
            .build();

        assert_invalid_config_suggestion(result, "Use DenyAll or AllowDomains for untrusted code");
    }

    #[test]
    fn test_untrusted_rejects_no_timeout() {
        let result = Config::builder()
            .trust_level(TrustLevel::Untrusted)
            .no_timeout()
            .build();

        assert_invalid_config_suggestion(
            result,
            "Set timeout_secs to a finite value for untrusted code",
        );
    }

    #[test]
    fn test_untrusted_rejects_no_memory_limit() {
        let config = Config {
            trust_level: TrustLevel::Untrusted,
            memory_limit_mb: None,
            ..Default::default()
        };

        let result = config.validate().map(|()| config);

        assert_invalid_config_suggestion(result, "Set memory_limit_mb for untrusted code");
    }

    #[test]
    fn test_trusted_allows_allow_all_network() {
        let config = Config::builder()
            .trust_level(TrustLevel::Trusted)
            .network(NetworkPolicy::AllowAll)
            .build()
            .expect("Trusted config should allow AllowAll network policy");

        assert!(matches!(config.network, NetworkPolicy::AllowAll));
    }

    #[test]
    fn timeout_rounds_up_instead_of_truncating_subsecond_precision() {
        let config = Config::builder()
            .timeout(Duration::from_millis(1_500))
            .build()
            .expect("config validation failed");
        assert_eq!(config.to_sandbox_config().timeout_secs, Some(2));

        let config = Config::builder()
            .timeout(Duration::from_millis(1))
            .build()
            .expect("config validation failed");
        assert_eq!(config.to_sandbox_config().timeout_secs, Some(1));

        let config = Config::builder()
            .timeout(Duration::from_nanos(1))
            .build()
            .expect("non-zero sub-millisecond timeout should round up to 1 second");
        assert_eq!(config.to_sandbox_config().timeout_secs, Some(1));
    }

    #[test]
    fn explicit_allowed_http_domains_are_forwarded_to_sandbox_config() {
        let config = Config::builder()
            .allowed_http_domains(["api.openai.com", "*.openai.com"])
            .build()
            .expect("config validation failed");
        let sandbox_config = config.to_sandbox_config();

        assert_eq!(
            sandbox_config.allowed_http_domains,
            vec!["api.openai.com".to_string(), "*.openai.com".to_string()]
        );
    }

    #[test]
    fn allow_domains_merge_with_explicit_http_whitelist_without_duplicates() {
        let config = Config::builder()
            .network(NetworkPolicy::AllowDomains(vec![
                "api.openai.com".to_string(),
                "example.com".to_string(),
            ]))
            .allowed_http_domains(["api.openai.com", "*.openai.com"])
            .build()
            .expect("config validation failed");
        let sandbox_config = config.to_sandbox_config();

        assert_eq!(
            sandbox_config.allowed_http_domains,
            vec![
                "api.openai.com".to_string(),
                "*.openai.com".to_string(),
                "example.com".to_string()
            ]
        );
    }

    #[test]
    fn allowed_http_domains_empty_input_builds_empty_whitelist() {
        let config = Config::builder()
            .allowed_http_domains(Vec::<String>::new())
            .build()
            .expect("empty allowed_http_domains input should build");
        let sandbox_config = config.to_sandbox_config();

        assert!(sandbox_config.allowed_http_domains.is_empty());
        assert!(sandbox_config.http_acl.allow.is_empty());
        assert!(sandbox_config.deny_network);
    }

    #[test]
    fn allowed_http_domains_deduplicates_explicit_entries_for_sandbox_config() {
        let config = Config::builder()
            .allowed_http_domains([
                "api.openai.com",
                "api.openai.com",
                "*.openai.com",
                "*.openai.com",
            ])
            .build()
            .expect("duplicate allowed_http_domains should build");

        assert_eq!(
            config.to_sandbox_config().allowed_http_domains,
            vec!["api.openai.com".to_string(), "*.openai.com".to_string()]
        );
    }

    #[test]
    fn allowed_http_domains_deduplicates_network_policy_entries() {
        let config = Config::builder()
            .network(NetworkPolicy::AllowDomains(vec![
                "api.openai.com".to_string(),
                "api.openai.com".to_string(),
                "*.openai.com".to_string(),
            ]))
            .build()
            .expect("duplicate NetworkPolicy::AllowDomains entries should build");

        assert_eq!(
            config.to_sandbox_config().allowed_http_domains,
            vec!["api.openai.com".to_string(), "*.openai.com".to_string()]
        );
    }

    #[test]
    fn builder_rejects_zero_memory_limit() {
        let result = Config::builder().memory_limit_mb(0).build();

        assert_invalid_config_suggestion(result, "memory_limit_mb minimum is 1");
    }

    #[test]
    fn builder_rejects_zero_timeout() {
        let result = Config::builder().timeout(Duration::ZERO).build();

        assert_invalid_config_suggestion(result, "timeout must be > 0, recommended 30s");
    }

    #[test]
    fn builder_rejects_zero_vcpu_count() {
        let result = Config::builder().vm_vcpu_count(0).build();

        assert_invalid_config_suggestion(result, "vcpu_count minimum is 1");
    }

    #[test]
    fn builder_rejects_memory_limit_above_global_max() {
        let result = Config::builder()
            .memory_limit_mb(MAX_MEMORY_LIMIT_MB + 1)
            .build();

        assert_invalid_config_suggestion(
            result,
            &format!("memory_limit_mb maximum is {MAX_MEMORY_LIMIT_MB}, recommended 256-512 MB"),
        );
    }

    #[test]
    fn max_processes_is_forwarded_to_sandbox_config() {
        let config = Config::builder()
            .max_processes(32)
            .build()
            .expect("config validation failed");

        assert_eq!(config.to_sandbox_config().max_processes, Some(32));
    }

    #[test]
    fn sandbox_tmp_dir_is_forwarded_as_explicit_readwrite_path() {
        let config = Config::builder()
            .sandbox_tmp_dir("/tmp/mimobox-private")
            .build()
            .expect("config validation failed");

        assert_eq!(
            config.to_sandbox_config().fs_readwrite,
            vec![PathBuf::from("/tmp/mimobox-private")]
        );
    }

    #[test]
    fn explicit_fs_readwrite_is_not_replaced_by_sandbox_tmp_dir() {
        let config = Config::builder()
            .fs_readwrite(["/workspace"])
            .sandbox_tmp_dir("/tmp/mimobox-private")
            .build()
            .expect("config validation failed");

        assert_eq!(
            config.to_sandbox_config().fs_readwrite,
            vec![
                PathBuf::from("/workspace"),
                PathBuf::from("/tmp/mimobox-private")
            ]
        );
    }

    #[test]
    fn builder_rejects_zero_max_processes() {
        let result = Config::builder().max_processes(0).build();

        assert_invalid_config_suggestion(
            result,
            "max_processes minimum is 1, or set to None for backend default",
        );
    }

    #[test]
    fn builder_rejects_invalid_http_domain() {
        let result = Config::builder()
            .allowed_http_domains(["127.0.0.1"])
            .build();

        assert_invalid_config_suggestion(
            result,
            "Use standard domain format, e.g. example.com or *.example.com; IP addresses not supported",
        );
    }

    #[test]
    fn builder_rejects_missing_explicit_microvm_artifact_path() {
        let missing_path =
            std::env::temp_dir().join(format!("mimobox-missing-kernel-{}", std::process::id()));
        let result = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .kernel_path(missing_path)
            .build();

        assert_invalid_config_suggestion(result, "Please ensure the path exists");
    }

    #[test]
    fn builder_accepts_allowed_domains_policy() {
        let config = Config::builder()
            .network(NetworkPolicy::AllowDomains(vec![
                "*.example.com".to_string(),
            ]))
            .build()
            .expect("AllowDomains should allow controlled proxy whitelist");

        assert_eq!(
            config.to_sandbox_config().allowed_http_domains,
            vec!["*.example.com".to_string()]
        );
    }

    #[test]
    fn builder_http_acl_allow_str_parses_rules() {
        let config = Config::builder()
            .http_acl_allow_str(&["GET api.openai.com/v1/models", "POST api.openai.com/v1/*"])
            .expect("ACL allow rule should parse successfully")
            .build()
            .expect("config validation failed");

        assert_eq!(config.http_acl.allow.len(), 2);
        assert_eq!(
            config.http_acl.allow[0].method,
            mimobox_core::HttpMethod::Get
        );
        assert_eq!(config.http_acl.allow[0].host, "api.openai.com");
        assert_eq!(config.http_acl.allow[0].path, "/v1/models");
        assert_eq!(
            config.http_acl.allow[1].method,
            mimobox_core::HttpMethod::Post
        );
        assert_eq!(config.http_acl.allow[1].path, "/v1/*");
    }

    #[test]
    fn builder_http_acl_deny_str_parses_rules() {
        let config = Config::builder()
            .network(NetworkPolicy::AllowDomains(vec![
                "api.openai.com".to_string(),
            ]))
            .http_acl_deny_str(&["* api.openai.com/v1/admin/*"])
            .expect("ACL deny rule should parse successfully")
            .build()
            .expect("config validation failed");

        assert_eq!(config.http_acl.deny.len(), 1);
        assert_eq!(
            config.http_acl.deny[0].method,
            mimobox_core::HttpMethod::Any
        );
        assert_eq!(config.http_acl.deny[0].host, "api.openai.com");
        assert_eq!(config.http_acl.deny[0].path, "/v1/admin/*");
    }

    #[test]
    fn http_acl_allow_str_invalid_rule_fails_closed() {
        let result = Config::builder()
            .http_acl_allow_str(&["GETT api.openai.com/v1/*", "GET api.openai.com/v2/*"]);

        assert!(result.is_err());
        assert!(
            result
                .expect_err("invalid HTTP ACL allow rule must fail")
                .to_string()
                .contains("HTTP ACL allow rule parse failed")
        );
    }

    #[test]
    fn builder_rejects_allow_all_with_http_acl() {
        let result = Config::builder()
            .network(NetworkPolicy::AllowAll)
            .http_acl_allow_str(&["GET api.openai.com/v1/*"])
            .expect("ACL allow rule should parse successfully")
            .build();

        assert!(result.is_err());
        let err = result.expect_err("AllowAll with HTTP ACL must be rejected");
        assert!(err.to_string().contains("AllowAll"));
    }

    #[test]
    fn allowed_http_domains_auto_converts_to_http_acl() {
        let config = Config::builder()
            .allowed_http_domains(["api.openai.com", "*.openai.com"])
            .build()
            .expect("config validation failed");
        let sandbox_config = config.to_sandbox_config();

        // allowed_http_domains should be automatically converted to http_acl allow rules
        assert!(sandbox_config.http_acl.allow.iter().any(|rule| {
            rule.host == "api.openai.com"
                && rule.path == "/*"
                && rule.method == mimobox_core::HttpMethod::Any
        }));
        assert!(sandbox_config.http_acl.allow.iter().any(|rule| {
            rule.host == "*.openai.com"
                && rule.path == "/*"
                && rule.method == mimobox_core::HttpMethod::Any
        }));
    }

    #[test]
    fn http_acl_backward_compatible_with_allowed_http_domains() {
        // Using only allowed_http_domains without configuring http_acl preserves behavior
        let config = Config::builder()
            .allowed_http_domains(["api.openai.com"])
            .build()
            .expect("config validation failed");
        let sandbox_config = config.to_sandbox_config();

        assert_eq!(
            sandbox_config.allowed_http_domains,
            vec!["api.openai.com".to_string()]
        );
        assert!(
            sandbox_config
                .http_acl
                .allow
                .iter()
                .any(|rule| rule.host == "api.openai.com")
        );
    }

    #[test]
    fn http_acl_allow_str_auto_sets_allow_domains_network() {
        // http_acl_allow_str switches the network policy automatically when setting rules
        let config = Config::builder()
            .http_acl_allow_str(&["GET api.openai.com/v1/*"])
            .expect("ACL allow rule should parse successfully")
            .build()
            .expect("config validation failed");

        assert!(matches!(config.network, NetworkPolicy::AllowDomains(_)));
    }

    #[test]
    fn env_var_single_adds_one_variable() {
        let config = Config::builder()
            .env_var("KEY", "VALUE")
            .env_var("KEY2", "VALUE2")
            .build()
            .expect("env_var should pass validation");

        assert_eq!(
            config
                .env_vars
                .get("KEY")
                .expect("KEY env var should exist"),
            "VALUE"
        );
        assert_eq!(
            config
                .env_vars
                .get("KEY2")
                .expect("KEY2 env var should exist"),
            "VALUE2"
        );
    }

    #[test]
    fn env_vars_default_is_empty() {
        let config = Config::default();

        assert!(config.env_vars.is_empty());
        assert!(config.to_sandbox_config().env_vars.is_empty());
    }

    #[test]
    fn builder_chain_http_acl_allow_and_deny() {
        let config = Config::builder()
            .http_acl_allow_str(&["GET api.openai.com/v1/*"])
            .expect("ACL allow rule should parse successfully")
            .http_acl_deny_str(&["* api.openai.com/v1/admin/*"])
            .expect("ACL deny rule should parse successfully")
            .build()
            .expect("config validation failed");

        assert_eq!(config.http_acl.allow.len(), 1);
        assert_eq!(config.http_acl.deny.len(), 1);
    }

    #[cfg(feature = "vm")]
    #[test]
    fn microvm_config_uses_default_artifact_paths_when_not_overridden() {
        let config = Config::default();
        let microvm_config = config
            .to_microvm_config()
            .expect("microVM config construction failed");
        let defaults = mimobox_vm::MicrovmConfig::default();

        assert_eq!(microvm_config.kernel_path, defaults.kernel_path);
        assert_eq!(microvm_config.rootfs_path, defaults.rootfs_path);
    }

    #[cfg(feature = "vm")]
    #[test]
    fn microvm_config_applies_resource_and_artifact_overrides() {
        let config = Config::builder()
            .vm_vcpu_count(4)
            .vm_memory_mb(768)
            .memory_limit_mb(1024)
            .cpu_quota(50_000)
            .cpu_period(100_000)
            .kernel_path("/srv/mimobox/vmlinux")
            .rootfs_path("/srv/mimobox/rootfs.cpio.gz")
            .build()
            .expect("config validation failed");
        let microvm_config = config
            .to_microvm_config()
            .expect("microVM config construction failed");

        assert_eq!(microvm_config.vcpu_count, 4);
        assert_eq!(microvm_config.memory_mb, 768);
        assert_eq!(microvm_config.cpu_quota_us, Some(50_000));
        assert_eq!(config.to_sandbox_config().cpu_period_us, 100_000);
        assert_eq!(
            microvm_config.kernel_path,
            PathBuf::from("/srv/mimobox/vmlinux")
        );
        assert_eq!(
            microvm_config.rootfs_path,
            PathBuf::from("/srv/mimobox/rootfs.cpio.gz")
        );
    }

    #[cfg(feature = "vm")]
    #[test]
    fn microvm_config_caps_vm_memory_with_memory_limit() {
        let config = Config::builder()
            .vm_memory_mb(768)
            .memory_limit_mb(256)
            .build()
            .expect("config validation failed");
        let microvm_config = config
            .to_microvm_config()
            .expect("microVM config construction failed");

        assert_eq!(microvm_config.memory_mb, 256);
    }

    #[cfg(feature = "vm")]
    #[test]
    fn microvm_config_rejects_out_of_range_memory_limit_even_when_vm_memory_is_lower() {
        let result = Config::builder()
            .vm_memory_mb(768)
            .memory_limit_mb(u64::MAX)
            .build();

        assert_invalid_config_suggestion(
            result,
            &format!("memory_limit_mb maximum is {MAX_MEMORY_LIMIT_MB}, recommended 256-512 MB"),
        );
    }
}
