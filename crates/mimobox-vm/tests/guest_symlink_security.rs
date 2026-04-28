#![cfg(all(target_os = "linux", feature = "kvm"))]

use mimobox_core::SandboxConfig;
use mimobox_vm::{
    GuestFileErrorKind, KvmBackend, MicrovmConfig, MicrovmError, microvm_config_from_vm_assets,
};

fn e2e_config() -> MicrovmConfig {
    microvm_config_from_vm_assets(256).expect("加载 e2e VM assets 配置必须成功")
}

fn guest_cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

#[test]
fn test_symlink_escape_to_host_rejected() {
    let config = e2e_config();
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), config).expect("创建 VM 必须成功");
    backend.boot().expect("VM 启动必须成功");

    backend
        .write_file("/sandbox/normal.txt", b"hello")
        .expect("正常文件写入必须成功");
    let result = backend
        .run_command(&guest_cmd(&[
            "/bin/ln",
            "-s",
            "/etc/passwd",
            "/sandbox/evil_link",
        ]))
        .expect("创建越界 symlink 命令必须成功返回");
    assert_eq!(result.exit_code, Some(0));

    let error = backend
        .read_file("/sandbox/evil_link")
        .expect_err("读取指向 host 文件的 symlink 必须失败");

    assert!(
        matches!(
            error,
            MicrovmError::GuestFile {
                kind: GuestFileErrorKind::PermissionDenied,
                ..
            }
        ),
        "越界 symlink 必须映射为 PermissionDenied: {error}"
    );

    backend.shutdown().expect("关闭 VM 必须成功");
}

#[test]
fn test_symlink_in_path_components_rejected() {
    let config = e2e_config();
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), config).expect("创建 VM 必须成功");
    backend.boot().expect("VM 启动必须成功");

    let mkdir_result = backend
        .run_command(&guest_cmd(&["/bin/mkdir", "-p", "/sandbox/real_dir"]))
        .expect("创建真实目录命令必须成功返回");
    assert_eq!(mkdir_result.exit_code, Some(0));
    let ln_result = backend
        .run_command(&guest_cmd(&[
            "/bin/ln",
            "-s",
            "/sandbox/real_dir",
            "/sandbox/dir_link",
        ]))
        .expect("创建目录 symlink 命令必须成功返回");
    assert_eq!(ln_result.exit_code, Some(0));

    let error = backend
        .write_file("/sandbox/dir_link/target.txt", b"data")
        .expect_err("路径组件中的 symlink 必须被拒绝");

    assert!(
        matches!(
            error,
            MicrovmError::GuestFile {
                kind: GuestFileErrorKind::PermissionDenied,
                ..
            }
        ),
        "路径组件 symlink 必须映射为 PermissionDenied: {error}"
    );

    backend.shutdown().expect("关闭 VM 必须成功");
}

#[test]
fn test_dotdot_traversal_rejected() {
    let config = e2e_config();
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), config).expect("创建 VM 必须成功");
    backend.boot().expect("VM 启动必须成功");

    let error = backend
        .read_file("/sandbox/../../../etc/passwd")
        .expect_err("../ 路径遍历必须被拒绝");

    assert!(
        matches!(
            error,
            MicrovmError::GuestFile {
                kind: GuestFileErrorKind::PermissionDenied | GuestFileErrorKind::NotFound,
                ..
            }
        ),
        "../ 路径遍历必须返回 GuestFile 错误且不能成功: {error}"
    );

    backend.shutdown().expect("关闭 VM 必须成功");
}

#[test]
fn test_normal_file_operations_succeed() {
    let config = e2e_config();
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), config).expect("创建 VM 必须成功");
    backend.boot().expect("VM 启动必须成功");

    backend
        .write_file("/sandbox/test_normal.txt", b"hello world")
        .expect("普通文本文件写入必须成功");
    let normal = backend
        .read_file("/sandbox/test_normal.txt")
        .expect("普通文本文件读取必须成功");
    assert_eq!(normal, b"hello world");

    backend
        .write_file("/sandbox/test_second.bin", b"\x00\x01\x02")
        .expect("普通二进制文件写入必须成功");
    let binary = backend
        .read_file("/sandbox/test_second.bin")
        .expect("普通二进制文件读取必须成功");
    assert_eq!(binary, b"\x00\x01\x02");

    backend.shutdown().expect("关闭 VM 必须成功");
}

#[test]
fn test_symlink_within_sandbox_rejected() {
    let config = e2e_config();
    let mut backend =
        KvmBackend::create_vm(SandboxConfig::default(), config).expect("创建 VM 必须成功");
    backend.boot().expect("VM 启动必须成功");

    backend
        .write_file("/sandbox/target.txt", b"content")
        .expect("symlink 目标文件写入必须成功");
    let result = backend
        .run_command(&guest_cmd(&[
            "/bin/ln",
            "-s",
            "/sandbox/target.txt",
            "/sandbox/inner_link",
        ]))
        .expect("创建沙箱内 symlink 命令必须成功返回");
    assert_eq!(result.exit_code, Some(0));

    let error = backend
        .read_file("/sandbox/inner_link")
        .expect_err("读取沙箱内 symlink 也必须失败");

    assert!(
        matches!(
            error,
            MicrovmError::GuestFile {
                kind: GuestFileErrorKind::PermissionDenied,
                ..
            }
        ),
        "沙箱内 symlink 必须映射为 PermissionDenied: {error}"
    );

    backend.shutdown().expect("关闭 VM 必须成功");
}
