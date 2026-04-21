#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::env;
use std::path::PathBuf;

use mimobox_core::{Sandbox, SandboxConfig};
use mimobox_vm::{KvmBackend, KvmExitReason, MicrovmConfig, MicrovmSandbox};

fn resolve_vm_assets_dir(
    vm_assets_override: Option<PathBuf>,
    home_dir: Option<PathBuf>,
) -> PathBuf {
    if let Some(path) = vm_assets_override {
        return path;
    }

    home_dir
        .expect("必须存在 HOME 环境变量或设置 VM_ASSETS_DIR")
        .join("mimobox-poc/vm-assets")
}

fn vm_assets_dir() -> PathBuf {
    resolve_vm_assets_dir(
        env::var_os("VM_ASSETS_DIR").map(PathBuf::from),
        env::var_os("HOME").map(PathBuf::from),
    )
}

fn e2e_config() -> MicrovmConfig {
    let assets = vm_assets_dir();
    let kernel_path = assets.join("vmlinux");
    let rootfs_path = assets.join("rootfs.cpio.gz");

    assert!(
        kernel_path.exists(),
        "缺少测试内核镜像: {}",
        kernel_path.display()
    );
    assert!(
        rootfs_path.exists(),
        "缺少测试 rootfs: {}",
        rootfs_path.display()
    );

    MicrovmConfig {
        vcpu_count: 1,
        memory_mb: 256,
        kernel_path,
        rootfs_path,
    }
}

fn guest_cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

#[test]
fn test_vm_assets_dir_prefers_env_override() {
    let override_dir = PathBuf::from("/tmp/mimobox-custom-vm-assets");

    let actual = resolve_vm_assets_dir(Some(override_dir.clone()), None);

    assert_eq!(actual, override_dir);
}

#[test]
fn test_vm_assets_dir_falls_back_to_home_default() {
    let home_dir = PathBuf::from("/tmp/mimobox-home");

    let actual = resolve_vm_assets_dir(None, Some(home_dir.clone()));

    assert_eq!(actual, home_dir.join("mimobox-poc/vm-assets"));
}

#[test]
fn test_kvm_vm_boots() {
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), e2e_config()).expect("创建 VM 必须成功");

    let exit_reason = backend.boot().expect("guest 启动必须成功");
    assert_eq!(exit_reason, KvmExitReason::Hlt);
    assert!(
        String::from_utf8_lossy(backend.serial_output()).contains("mimobox guest booted"),
        "串口必须包含启动横幅"
    );

    backend.shutdown().expect("关闭 VM 必须成功");
}

#[test]
fn test_kvm_vm_executes() {
    let mut sandbox = MicrovmSandbox::new(e2e_config()).expect("创建 microVM 沙箱必须成功");

    let result = sandbox
        .execute(&guest_cmd(&["/bin/echo", "hello"]))
        .expect("guest 命令执行必须成功");

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&result.stdout), "hello\n");
    assert!(result.stderr.is_empty(), "echo 不应产生 stderr");

    sandbox.destroy().expect("销毁 microVM 沙箱必须成功");
}

#[test]
fn test_kvm_snapshot_restore() {
    let config = e2e_config();
    let mut backend = KvmBackend::create_vm(SandboxConfig::default(), config.clone())
        .expect("创建源 VM 必须成功");

    backend.boot().expect("源 VM 启动必须成功");
    let first = backend
        .run_command(&guest_cmd(&["/bin/echo", "hello"]))
        .expect("源 VM 执行 echo 必须成功");
    assert_eq!(String::from_utf8_lossy(&first.stdout), "hello\n");

    let (memory, vcpu_state) = backend.snapshot_state().expect("导出快照必须成功");
    let serial_before = backend.serial_output().to_vec();

    let mut restored =
        KvmBackend::create_vm(SandboxConfig::default(), config).expect("创建恢复 VM 必须成功");
    restored
        .restore_state(&memory, &vcpu_state)
        .expect("恢复 VM 状态必须成功");

    assert_eq!(restored.serial_output(), serial_before.as_slice());

    let second = restored
        .run_command(&guest_cmd(&["/bin/echo", "restored"]))
        .expect("恢复后的 VM 执行 echo 必须成功");
    assert_eq!(String::from_utf8_lossy(&second.stdout), "restored\n");

    backend.shutdown().expect("关闭源 VM 必须成功");
    restored.shutdown().expect("关闭恢复 VM 必须成功");
}
