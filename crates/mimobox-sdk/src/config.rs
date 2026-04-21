use std::path::PathBuf;
use std::time::Duration;

use mimobox_core::SandboxConfig;

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
    /// 仅允许指定域名（未来实现，当前等价于 DenyAll）
    #[allow(dead_code)]
    AllowDomains(Vec<String>),
    /// 拒绝指定域名，允许其余（未来实现）
    #[allow(dead_code)]
    DenyDomains(Vec<String>),
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
    /// 是否允许 fork
    pub allow_fork: bool,
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
            allow_fork: false,
        }
    }
}

impl Config {
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// 转换为 mimibox-core 的 SandboxConfig
    pub(crate) fn to_sandbox_config(&self) -> SandboxConfig {
        SandboxConfig {
            fs_readonly: self.fs_readonly.clone(),
            fs_readwrite: self.fs_readwrite.clone(),
            // 域名级白名单/黑名单尚未实现，当前统一回退到“拒绝所有网络”。
            deny_network: true,
            memory_limit_mb: self.memory_limit_mb,
            timeout_secs: self.timeout.map(round_up_timeout_secs),
            seccomp_profile: mimobox_core::SeccompProfile::Essential,
            allow_fork: self.allow_fork,
        }
    }
}

fn round_up_timeout_secs(timeout: Duration) -> u64 {
    let millis = timeout.as_millis();
    let seconds = millis.div_ceil(1_000);
    u64::try_from(seconds).unwrap_or(u64::MAX)
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

    pub fn build(self) -> Config {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_domains_still_denies_network_until_whitelist_is_implemented() {
        let config = Config::builder()
            .network(NetworkPolicy::AllowDomains(vec!["example.com".to_string()]))
            .build();

        assert!(config.to_sandbox_config().deny_network);
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
}
