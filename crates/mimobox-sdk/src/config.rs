use std::path::PathBuf;
use std::time::Duration;

use crate::error::SdkError;
use mimobox_core::{NamespaceDegradation, SandboxConfig, SeccompProfile};

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
    /// CPU time quota in microseconds. `None` means unlimited.
    pub cpu_quota_us: Option<u64>,
    /// CPU period in microseconds. Defaults to 100000 (100ms).
    pub cpu_period_us: u64,
    /// Read-only mount paths inside the sandbox.
    pub fs_readonly: Vec<PathBuf>,
    /// Read-write mount paths inside the sandbox.
    pub fs_readwrite: Vec<PathBuf>,
    /// HTTP proxy domain whitelist (supports glob patterns like `*.openai.com`).
    pub allowed_http_domains: Vec<String>,
    /// Whether to allow child process creation (fork/clone) inside the sandbox.
    pub allow_fork: bool,
    /// Namespace 降级行为控制。默认 FailClosed。
    pub namespace_degradation: NamespaceDegradation,
    /// microVM vCPU count. Only affects the microVM backend.
    pub vm_vcpu_count: u8,
    /// microVM guest memory size in MiB. Capped by `memory_limit_mb` if set.
    pub vm_memory_mb: u32,
    /// Custom microVM kernel image path. Falls back to `~/.mimobox/assets/vmlinux` if unset.
    pub kernel_path: Option<PathBuf>,
    /// Custom microVM rootfs path. Falls back to `~/.mimobox/assets/rootfs.cpio.gz` if unset.
    pub rootfs_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            isolation: IsolationLevel::Auto,
            trust_level: TrustLevel::default(),
            network: NetworkPolicy::default(),
            timeout: Some(Duration::from_secs(30)),
            memory_limit_mb: Some(512),
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
            fs_readwrite: vec!["/tmp".into()],
            allowed_http_domains: Vec::new(),
            allow_fork: false,
            namespace_degradation: NamespaceDegradation::FailClosed,
            vm_vcpu_count: 1,
            vm_memory_mb: 256,
            kernel_path: None,
            rootfs_path: None,
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
    ///     .expect("配置校验失败");
    ///
    /// assert_eq!(config.isolation, IsolationLevel::Os);
    /// ```
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// 校验 SDK 配置，避免非法配置进入后端。
    pub(crate) fn validate(&self) -> Result<(), SdkError> {
        if self.vm_vcpu_count == 0 {
            return Err(SdkError::Config(
                "vm_vcpu_count=0 无效，请设为正整数".to_string(),
            ));
        }

        if self.vm_memory_mb == 0 {
            return Err(SdkError::Config(
                "vm_memory_mb=0 无效，请设为正整数".to_string(),
            ));
        }

        if matches!(self.network, NetworkPolicy::DenyAll) && !self.allowed_http_domains.is_empty() {
            return Err(SdkError::Config(
                "network=DenyAll 但 allowed_http_domains 非空，请使用 allowed_http_domains() builder 或 NetworkPolicy::AllowDomains".to_string(),
            ));
        }

        for domain in resolve_allowed_http_domains(self) {
            validate_http_domain(&domain)?;
        }

        self.to_sandbox_config()
            .validate()
            .map_err(|error| SdkError::Config(error.to_string()))?;

        Ok(())
    }

    /// Converts to the internal `mimobox_core::SandboxConfig`.
    pub(crate) fn to_sandbox_config(&self) -> SandboxConfig {
        let deny_network = resolve_deny_network(&self.network);

        let mut config = SandboxConfig::default();
        config.fs_readonly = self.fs_readonly.clone();
        config.fs_readwrite = self.fs_readwrite.clone();
        config.deny_network = deny_network;
        config.memory_limit_mb = self.memory_limit_mb;
        config.cpu_quota_us = self.cpu_quota_us;
        config.cpu_period_us = self.cpu_period_us;
        config.timeout_secs = self.timeout.map(round_up_timeout_secs);
        config.seccomp_profile = resolve_seccomp_profile(deny_network, self.allow_fork);
        config.allow_fork = self.allow_fork;
        config.allowed_http_domains = resolve_allowed_http_domains(self);
        config.namespace_degradation = self.namespace_degradation;
        config
    }

    #[cfg(feature = "vm")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
    let mut domains = config.allowed_http_domains.clone();
    if let NetworkPolicy::AllowDomains(network_domains) = &config.network {
        for domain in network_domains {
            if !domains.contains(domain) {
                domains.push(domain.clone());
            }
        }
    }
    domains
}

fn round_up_timeout_secs(timeout: Duration) -> u64 {
    let millis = timeout.as_millis();
    let seconds = millis.div_ceil(1_000);
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
        return Err(SdkError::Config(format!(
            "allowed_http_domains 包含无效域名: {domain}"
        )));
    }

    Ok(())
}

fn has_invalid_domain_wildcard(domain: &str) -> bool {
    let wildcard_count = domain.chars().filter(|character| *character == '*').count();
    wildcard_count > 0 && (wildcard_count != 1 || !domain.starts_with("*."))
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
        SdkError::Config(format!(
            "microVM guest memory 超出 u32 范围: {effective_memory_mb} MB"
        ))
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
///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
    ///
    /// assert_eq!(config.memory_limit_mb, Some(256));
    /// ```
    pub fn memory_limit_mb(mut self, mb: u64) -> Self {
        self.inner.memory_limit_mb = Some(mb);
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
    ///
    /// assert_eq!(config.fs_readwrite.len(), 2);
    /// ```
    pub fn fs_readwrite(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.inner.fs_readwrite = paths.into_iter().map(Into::into).collect();
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
    ///     .expect("配置校验失败");
    ///
    /// assert!(config.allow_fork);
    /// ```
    pub fn allow_fork(mut self, allow: bool) -> Self {
        self.inner.allow_fork = allow;
        self
    }

    /// Set Linux namespace 降级行为。
    ///
    /// 默认 `FailClosed`，任何 namespace 创建失败都会拒绝继续执行。
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
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
    ///     .expect("配置校验失败");
    ///
    /// assert_eq!(config.rootfs_path, Some(std::path::PathBuf::from("/opt/mimobox/rootfs.cpio.gz")));
    /// ```
    pub fn rootfs_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.rootfs_path = Some(path.into());
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
    ///     .expect("配置校验失败");
    ///
    /// assert_eq!(config.timeout, None);
    /// ```
    pub fn no_timeout(mut self) -> Self {
        self.inner.timeout = None;
        self
    }

    /// Validate and produce the final `Config`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mimobox_sdk::Config;
    ///
    /// let config = Config::builder().build().expect("配置校验失败");
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

    #[test]
    fn default_config_keeps_microvm_artifact_paths_unset() {
        let config = Config::default();

        assert_eq!(config.vm_vcpu_count, 1);
        assert_eq!(config.vm_memory_mb, 256);
        assert_eq!(config.kernel_path, None);
        assert_eq!(config.rootfs_path, None);
    }

    #[test]
    fn builder_can_override_microvm_resource_config() {
        let config = Config::builder()
            .vm_vcpu_count(4)
            .vm_memory_mb(768)
            .build()
            .expect("配置校验失败");

        assert_eq!(config.vm_vcpu_count, 4);
        assert_eq!(config.vm_memory_mb, 768);
    }

    #[test]
    fn builder_can_override_microvm_artifact_paths() {
        let config = Config::builder()
            .kernel_path("/opt/mimobox/vmlinux")
            .rootfs_path("/opt/mimobox/rootfs.cpio.gz")
            .build()
            .expect("配置校验失败");

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
            .expect("配置校验失败");

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
            .expect("配置校验失败");
        let sandbox_config = config.to_sandbox_config();

        assert!(!sandbox_config.deny_network);
        assert!(matches!(
            sandbox_config.seccomp_profile,
            SeccompProfile::NetworkWithFork
        ));
    }

    #[test]
    fn timeout_rounds_up_instead_of_truncating_subsecond_precision() {
        let config = Config::builder()
            .timeout(Duration::from_millis(1_500))
            .build()
            .expect("配置校验失败");
        assert_eq!(config.to_sandbox_config().timeout_secs, Some(2));

        let config = Config::builder()
            .timeout(Duration::from_millis(1))
            .build()
            .expect("配置校验失败");
        assert_eq!(config.to_sandbox_config().timeout_secs, Some(1));
    }

    #[test]
    fn explicit_allowed_http_domains_are_forwarded_to_sandbox_config() {
        let config = Config::builder()
            .allowed_http_domains(["api.openai.com", "*.openai.com"])
            .build()
            .expect("配置校验失败");
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
            .expect("配置校验失败");
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
    fn builder_rejects_zero_memory_limit() {
        let result = Config::builder().memory_limit_mb(0).build();

        assert!(matches!(result, Err(SdkError::Config(_))));
    }

    #[test]
    fn builder_rejects_invalid_http_domain() {
        let result = Config::builder()
            .allowed_http_domains(["127.0.0.1"])
            .build();

        assert!(matches!(result, Err(SdkError::Config(_))));
    }

    #[test]
    fn builder_accepts_allowed_domains_policy() {
        let config = Config::builder()
            .network(NetworkPolicy::AllowDomains(vec![
                "*.example.com".to_string(),
            ]))
            .build()
            .expect("AllowDomains 应允许受控代理白名单");

        assert_eq!(
            config.to_sandbox_config().allowed_http_domains,
            vec!["*.example.com".to_string()]
        );
    }

    #[cfg(feature = "vm")]
    #[test]
    fn microvm_config_uses_default_artifact_paths_when_not_overridden() {
        let config = Config::default();
        let microvm_config = config.to_microvm_config().expect("构造 microVM 配置失败");
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
            .expect("配置校验失败");
        let microvm_config = config.to_microvm_config().expect("构造 microVM 配置失败");

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
            .expect("配置校验失败");
        let microvm_config = config.to_microvm_config().expect("构造 microVM 配置失败");

        assert_eq!(microvm_config.memory_mb, 256);
    }

    #[cfg(feature = "vm")]
    #[test]
    fn microvm_config_ignores_out_of_range_memory_limit_when_vm_memory_is_lower() {
        let config = Config::builder()
            .vm_memory_mb(768)
            .memory_limit_mb(u64::MAX)
            .build()
            .expect("配置校验失败");
        let microvm_config = config.to_microvm_config().expect("构造 microVM 配置失败");

        assert_eq!(microvm_config.memory_mb, 768);
    }
}
