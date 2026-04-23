use std::path::PathBuf;
use std::time::Duration;

#[cfg(feature = "vm")]
use crate::error::SdkError;
use mimobox_core::{SandboxConfig, SeccompProfile};

/// 隔离层级选择
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// 自动选择：根据命令类型和信任级别智能路由
    #[default]
    Auto,
    /// OS 级：Landlock + Seccomp + Namespaces（Linux）/ Seatbelt（macOS）
    Os,
    /// Wasm 级：Wasmtime 沙箱，亚毫秒冷启动
    Wasm,
    /// microVM 级：KVM 硬件隔离
    MicroVm,
}

/// 信任级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustLevel {
    /// 受信代码：自身编写或已审计的代码
    Trusted,
    /// 半信代码：第三方库或未经完整审计的代码
    #[default]
    SemiTrusted,
    /// 不信代码：用户提交、网络下载等不可信代码
    Untrusted,
}

/// 网络策略
#[derive(Debug, Clone, Default)]
pub enum NetworkPolicy {
    /// 默认拒绝所有网络访问
    #[default]
    DenyAll,
    /// 保持沙箱内直接网络关闭，仅允许通过受控 HTTP 代理访问指定域名
    AllowDomains(Vec<String>),
    /// 允许任意网络访问
    AllowAll,
}

/// SDK 级配置
#[derive(Debug, Clone)]
pub struct Config {
    /// 隔离层级（Auto = 智能路由）
    pub isolation: IsolationLevel,
    /// 信任级别（影响 Auto 路由决策）
    pub trust_level: TrustLevel,
    /// 网络策略
    pub network: NetworkPolicy,
    /// 超时时间
    pub timeout: Option<Duration>,
    /// 内存限制 (MB)
    pub memory_limit_mb: Option<u64>,
    /// 只读路径
    pub fs_readonly: Vec<PathBuf>,
    /// 读写路径
    pub fs_readwrite: Vec<PathBuf>,
    /// HTTP 代理允许的域名白名单
    pub allowed_http_domains: Vec<String>,
    /// 是否允许 fork
    pub allow_fork: bool,
    /// microVM vCPU 数量
    pub vm_vcpu_count: u8,
    /// microVM Guest 内存大小（MB）；若设置了 memory_limit_mb，则以较小值为准
    pub vm_memory_mb: u32,
    /// microVM 内核镜像路径；未配置时使用后端默认路径
    pub kernel_path: Option<PathBuf>,
    /// microVM rootfs 路径；未配置时使用后端默认路径
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
            vm_vcpu_count: 1,
            vm_memory_mb: 256,
            kernel_path: None,
            rootfs_path: None,
        }
    }
}

impl Config {
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// 转换为 mimibox-core 的 SandboxConfig
    pub(crate) fn to_sandbox_config(&self) -> SandboxConfig {
        let deny_network = resolve_deny_network(&self.network);

        SandboxConfig {
            fs_readonly: self.fs_readonly.clone(),
            fs_readwrite: self.fs_readwrite.clone(),
            deny_network,
            memory_limit_mb: self.memory_limit_mb,
            timeout_secs: self.timeout.map(round_up_timeout_secs),
            seccomp_profile: resolve_seccomp_profile(deny_network, self.allow_fork),
            allow_fork: self.allow_fork,
            allowed_http_domains: resolve_allowed_http_domains(self),
        }
    }

    #[cfg(feature = "vm")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn to_microvm_config(&self) -> Result<mimobox_vm::MicrovmConfig, SdkError> {
        let defaults = mimobox_vm::MicrovmConfig::default();
        let memory_mb = resolve_vm_memory_mb(self)?;

        Ok(mimobox_vm::MicrovmConfig {
            vcpu_count: self.vm_vcpu_count,
            memory_mb,
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

/// Config 构建器
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    inner: Config,
}

impl ConfigBuilder {
    pub fn isolation(mut self, level: IsolationLevel) -> Self {
        self.inner.isolation = level;
        self
    }

    pub fn trust_level(mut self, level: TrustLevel) -> Self {
        self.inner.trust_level = level;
        self
    }

    pub fn network(mut self, policy: NetworkPolicy) -> Self {
        self.inner.network = policy;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner.timeout = Some(timeout);
        self
    }

    pub fn memory_limit_mb(mut self, mb: u64) -> Self {
        self.inner.memory_limit_mb = Some(mb);
        self
    }

    pub fn fs_readonly(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.inner.fs_readonly = paths.into_iter().map(Into::into).collect();
        self
    }

    pub fn fs_readwrite(mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        self.inner.fs_readwrite = paths.into_iter().map(Into::into).collect();
        self
    }

    pub fn allow_fork(mut self, allow: bool) -> Self {
        self.inner.allow_fork = allow;
        self
    }

    pub fn allowed_http_domains(
        mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.inner.allowed_http_domains = domains.into_iter().map(Into::into).collect();
        self
    }

    pub fn vm_vcpu_count(mut self, count: u8) -> Self {
        self.inner.vm_vcpu_count = count;
        self
    }

    pub fn vm_memory_mb(mut self, mb: u32) -> Self {
        self.inner.vm_memory_mb = mb;
        self
    }

    pub fn kernel_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.kernel_path = Some(path.into());
        self
    }

    pub fn rootfs_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.rootfs_path = Some(path.into());
        self
    }

    pub fn build(self) -> Config {
        self.inner
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
        let config = Config::builder().vm_vcpu_count(4).vm_memory_mb(768).build();

        assert_eq!(config.vm_vcpu_count, 4);
        assert_eq!(config.vm_memory_mb, 768);
    }

    #[test]
    fn builder_can_override_microvm_artifact_paths() {
        let config = Config::builder()
            .kernel_path("/opt/mimobox/vmlinux")
            .rootfs_path("/opt/mimobox/rootfs.cpio.gz")
            .build();

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
            .build();

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
            .build();
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
            .build();
        assert_eq!(config.to_sandbox_config().timeout_secs, Some(2));

        let config = Config::builder().timeout(Duration::from_millis(1)).build();
        assert_eq!(config.to_sandbox_config().timeout_secs, Some(1));
    }

    #[test]
    fn explicit_allowed_http_domains_are_forwarded_to_sandbox_config() {
        let config = Config::builder()
            .allowed_http_domains(["api.openai.com", "*.openai.com"])
            .build();
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
            .build();
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
            .kernel_path("/srv/mimobox/vmlinux")
            .rootfs_path("/srv/mimobox/rootfs.cpio.gz")
            .build();
        let microvm_config = config.to_microvm_config().expect("构造 microVM 配置失败");

        assert_eq!(microvm_config.vcpu_count, 4);
        assert_eq!(microvm_config.memory_mb, 768);
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
            .build();
        let microvm_config = config.to_microvm_config().expect("构造 microVM 配置失败");

        assert_eq!(microvm_config.memory_mb, 256);
    }

    #[cfg(feature = "vm")]
    #[test]
    fn microvm_config_ignores_out_of_range_memory_limit_when_vm_memory_is_lower() {
        let config = Config::builder()
            .vm_memory_mb(768)
            .memory_limit_mb(u64::MAX)
            .build();
        let microvm_config = config.to_microvm_config().expect("构造 microVM 配置失败");

        assert_eq!(microvm_config.memory_mb, 768);
    }
}
