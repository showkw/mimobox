use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::PathBuf;

use mimobox_core::{SandboxConfig, SandboxError, SandboxSnapshot, SeccompProfile};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(remote = "SeccompProfile")]
enum SeccompProfileDef {
    Essential,
    Network,
    EssentialWithFork,
    NetworkWithFork,
}

#[derive(Debug, Serialize, Deserialize)]
struct SandboxConfigJson {
    fs_readonly: Vec<PathBuf>,
    fs_readwrite: Vec<PathBuf>,
    deny_network: bool,
    memory_limit_mb: Option<u64>,
    cpu_quota_us: Option<u64>,
    cpu_period_us: u64,
    timeout_secs: Option<u64>,
    #[serde(with = "SeccompProfileDef")]
    seccomp_profile: SeccompProfile,
    allow_fork: bool,
    allowed_http_domains: Vec<String>,
}

impl From<&SandboxConfig> for SandboxConfigJson {
    fn from(config: &SandboxConfig) -> Self {
        Self {
            fs_readonly: config.fs_readonly.clone(),
            fs_readwrite: config.fs_readwrite.clone(),
            deny_network: config.deny_network,
            memory_limit_mb: config.memory_limit_mb,
            cpu_quota_us: config.cpu_quota_us,
            cpu_period_us: config.cpu_period_us,
            timeout_secs: config.timeout_secs,
            seccomp_profile: config.seccomp_profile,
            allow_fork: config.allow_fork,
            allowed_http_domains: config.allowed_http_domains.clone(),
        }
    }
}

impl From<SandboxConfigJson> for SandboxConfig {
    fn from(json: SandboxConfigJson) -> Self {
        let mut config = SandboxConfig::default();
        config.fs_readonly = json.fs_readonly;
        config.fs_readwrite = json.fs_readwrite;
        config.deny_network = json.deny_network;
        config.memory_limit_mb = json.memory_limit_mb;
        config.cpu_quota_us = json.cpu_quota_us;
        config.cpu_period_us = json.cpu_period_us;
        config.timeout_secs = json.timeout_secs;
        config.seccomp_profile = json.seccomp_profile;
        config.allow_fork = json.allow_fork;
        config.allowed_http_domains = json.allowed_http_domains;
        config
    }
}

fn seccomp_profile_name(profile: SeccompProfile) -> &'static str {
    match profile {
        SeccompProfile::Essential => "essential",
        SeccompProfile::Network => "network",
        SeccompProfile::EssentialWithFork => "essential-with-fork",
        SeccompProfile::NetworkWithFork => "network-with-fork",
    }
}

#[test]
fn sandbox_config_round_trips_through_json() -> Result<(), Box<dyn Error>> {
    let mut config = SandboxConfig::default();
    config.fs_readonly = vec![
        PathBuf::from("/opt/tools"),
        PathBuf::from("/var/data/readonly"),
    ];
    config.fs_readwrite = vec![PathBuf::from("/tmp/workdir"), PathBuf::from("/srv/output")];
    config.deny_network = false;
    config.memory_limit_mb = Some(256);
    config.cpu_quota_us = Some(50_000);
    config.cpu_period_us = 100_000;
    config.timeout_secs = Some(9);
    config.seccomp_profile = SeccompProfile::NetworkWithFork;
    config.allow_fork = true;
    config.allowed_http_domains = vec!["api.openai.com".to_string(), "*.openai.com".to_string()];

    let json = serde_json::to_string_pretty(&SandboxConfigJson::from(&config))?;
    let decoded = SandboxConfig::from(serde_json::from_str::<SandboxConfigJson>(&json)?);

    assert_eq!(decoded.fs_readonly, config.fs_readonly);
    assert_eq!(decoded.fs_readwrite, config.fs_readwrite);
    assert_eq!(decoded.deny_network, config.deny_network);
    assert_eq!(decoded.memory_limit_mb, config.memory_limit_mb);
    assert_eq!(decoded.cpu_quota_us, config.cpu_quota_us);
    assert_eq!(decoded.cpu_period_us, config.cpu_period_us);
    assert_eq!(decoded.timeout_secs, config.timeout_secs);
    assert_eq!(
        seccomp_profile_name(decoded.seccomp_profile),
        seccomp_profile_name(config.seccomp_profile)
    );
    assert_eq!(decoded.allow_fork, config.allow_fork);
    assert_eq!(decoded.allowed_http_domains, config.allowed_http_domains);
    assert!(json.contains("\"deny_network\": false"));
    assert!(json.contains("\"allow_fork\": true"));
    assert!(json.contains("\"allowed_http_domains\""));
    assert!(json.contains("\"cpu_quota_us\": 50000"));

    Ok(())
}

#[test]
fn sandbox_config_cpu_builder_sets_quota_and_period() {
    let config = SandboxConfig::default()
        .cpu_quota(25_000)
        .cpu_period(100_000);

    assert_eq!(config.cpu_quota_us, Some(25_000));
    assert_eq!(config.cpu_period_us, 100_000);
}

#[test]
fn sandbox_error_display_and_source_behave_as_expected() {
    let execution_error = SandboxError::ExecutionFailed("boom".to_string());
    assert_eq!(
        execution_error.to_string(),
        "command execution failed: boom"
    );
    assert!(execution_error.source().is_none());

    let unsupported_error = SandboxError::Unsupported;
    assert_eq!(
        unsupported_error.to_string(),
        "sandbox backend not supported on current platform"
    );
    assert!(unsupported_error.source().is_none());

    let io_error = SandboxError::from(io::Error::other("disk full"));
    assert!(io_error.to_string().contains("I/O error: disk full"));
    assert!(io_error.source().is_some());
}

#[test]
fn seccomp_profile_variants_are_complete_and_distinct() {
    let all_profiles = [
        SeccompProfile::Essential,
        SeccompProfile::Network,
        SeccompProfile::EssentialWithFork,
        SeccompProfile::NetworkWithFork,
    ];

    let names = all_profiles
        .into_iter()
        .map(seccomp_profile_name)
        .collect::<BTreeSet<_>>();

    assert_eq!(names.len(), 4);
    assert_eq!(seccomp_profile_name(SeccompProfile::default()), "essential");
    assert!(names.contains("essential"));
    assert!(names.contains("network"));
    assert!(names.contains("essential-with-fork"));
    assert!(names.contains("network-with-fork"));
}

#[test]
fn sandbox_snapshot_round_trips_through_bytes() {
    let bytes = b"opaque-snapshot-payload".to_vec();

    let snapshot = SandboxSnapshot::from_owned_bytes(bytes.clone()).expect("快照创建必须成功");
    let restored =
        SandboxSnapshot::from_bytes(snapshot.as_bytes().expect("内存快照必须可直接读取字节"))
            .expect("快照恢复必须成功");

    assert_eq!(restored.size(), bytes.len());
    assert_eq!(restored.to_bytes().expect("快照导出字节必须成功"), bytes);
}
