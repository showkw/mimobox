use std::path::PathBuf;

use mimobox_core::SandboxConfig;
#[cfg(any(not(target_os = "linux"), not(feature = "kvm")))]
use mimobox_core::{Sandbox, SandboxError};
use mimobox_vm::{MicrovmConfig, MicrovmSandbox, MicrovmSnapshot};

#[test]
fn unsupported_platform_or_disabled_feature_reports_unsupported() {
    #[cfg(any(not(target_os = "linux"), not(feature = "kvm")))]
    {
        let result = <MicrovmSandbox as Sandbox>::new(SandboxConfig::default());
        assert!(matches!(result, Err(SandboxError::Unsupported)));
    }
}

#[test]
fn snapshot_rejects_invalid_magic() {
    match MicrovmSnapshot::restore(b"bad-snapshot") {
        Ok(_) => panic!("非法快照必须失败"),
        Err(err) => assert!(err.to_string().contains("magic")),
    }
}

#[test]
fn snapshot_round_trip_restores_same_bytes() {
    let snapshot = MicrovmSnapshot::new(
        SandboxConfig::default(),
        MicrovmConfig {
            vcpu_count: 2,
            memory_mb: 256,
            cpu_quota_us: Some(50_000),
            kernel_path: PathBuf::from("/opt/mimobox/vmlinux"),
            rootfs_path: PathBuf::from("/opt/mimobox/rootfs.ext4"),
        },
        vec![1, 2, 3, 4],
        vec![5, 6, 7, 8],
    );

    let encoded = snapshot.snapshot().expect("快照序列化必须成功");
    let restored = MicrovmSnapshot::restore(&encoded).expect("快照反序列化必须成功");

    assert_eq!(
        restored.snapshot().expect("恢复后的快照必须可再次序列化"),
        encoded
    );
}

#[test]
fn microvm_config_requires_kernel_and_rootfs_paths_on_supported_backend() {
    // 非 Linux 或未启用 KVM：使用 default config，预期返回 Unsupported
    #[cfg(any(not(target_os = "linux"), not(feature = "kvm")))]
    {
        let config = MicrovmConfig::default();
        let result = MicrovmSandbox::new(config);
        assert!(matches!(result, Err(err) if err.to_string().contains("not supported")));
    }

    // Linux + KVM：构造显式无效配置（vcpu_count=0），确保 validate() 拒绝
    // 不使用 default()，因为 hermes 开发机上 default() 会解析到真实 vm 资产路径，
    // 导致 validate() 通过后在 KvmBackend::create_vm() 阶段因权限失败，错误消息不匹配断言
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    {
        let bad_config = MicrovmConfig {
            vcpu_count: 0,
            memory_mb: 64,
            cpu_quota_us: None,
            kernel_path: PathBuf::from("/nonexistent/vmlinux"),
            rootfs_path: PathBuf::from("/nonexistent/rootfs.cpio.gz"),
        };
        let result = MicrovmSandbox::new(bad_config);
        assert!(result.is_err(), "invalid config (vcpu_count=0) must fail");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("vcpu_count") || msg.contains("kernel_path") || msg.contains("rootfs_path"),
            "unexpected error message: {msg}"
        );
    }
}
