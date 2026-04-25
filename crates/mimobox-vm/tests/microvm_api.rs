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
    let config = MicrovmConfig::default();
    let result = MicrovmSandbox::new(config);

    #[cfg(any(not(target_os = "linux"), not(feature = "kvm")))]
    assert!(matches!(result, Err(err) if err.to_string().contains("not supported")));

    #[cfg(all(target_os = "linux", feature = "kvm"))]
    assert!(matches!(
        result,
        Err(err)
            if err.to_string().contains("kernel_path")
                || err.to_string().contains("rootfs_path")
                || err.to_string().contains("vcpu_count")
                || err.to_string().contains("不存在")
    ));
}
