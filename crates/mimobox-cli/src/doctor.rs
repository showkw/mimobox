use std::env;
use std::fs::{self};
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tracing::info;

const APP_HOME_SUBDIR: &str = ".mimobox";
const ASSETS_SUBDIR: &str = ".mimobox/assets";
const LEGACY_VM_ASSETS_DIR: &str = "/var/lib/mimobox/vm";
const MIN_VM_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
#[cfg(target_os = "linux")]
const KVM_GET_API_VERSION_IOCTL: libc::c_ulong = 0xae00;
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckResult {
    name: String,
    status: CheckStatus,
    message: String,
    hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VmAssetPaths {
    assets_dir: PathBuf,
    kernel_path: PathBuf,
    rootfs_path: PathBuf,
}

pub fn run_doctor() -> i32 {
    let results = collect_doctor_results();
    let exit_code = exit_code_for_results(&results);
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    if let Err(error) = render_doctor_report(&mut handle, &results) {
        eprintln!("doctor 输出失败: {error}");
        return 2;
    }

    exit_code
}

pub fn run_setup() -> i32 {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    if let Err(error) = render_setup_header(&mut handle) {
        eprintln!("setup 输出失败: {error}");
        return 2;
    }

    let app_home = match resolve_app_home_dir(env::var_os("HOME").map(PathBuf::from)) {
        Ok(path) => path,
        Err(result) => {
            let _ = render_check(&mut handle, &result);
            return 2;
        }
    };
    let assets_dir = app_home.join("assets");
    let vm_asset_paths = default_vm_asset_paths_for_home(Some(app_home.clone()));

    let initial_kvm = check_kvm();
    let initial_assets = summarize_vm_assets_for_setup();
    let _ = render_check(&mut handle, &initial_kvm);
    let _ = render_check(&mut handle, &initial_assets);

    if let Err(error) = ensure_directory_exists(&app_home) {
        let result = CheckResult {
            name: "mimobox 目录".to_string(),
            status: CheckStatus::Fail,
            message: format!("创建目录失败: {} ({error})", app_home.display()),
            hint: Some("请检查 HOME 目录权限后重试".to_string()),
        };
        let _ = render_check(&mut handle, &result);
        return 2;
    }

    if let Err(error) = ensure_directory_exists(&assets_dir) {
        let result = CheckResult {
            name: "资产目录".to_string(),
            status: CheckStatus::Fail,
            message: format!("创建目录失败: {} ({error})", assets_dir.display()),
            hint: Some("请检查 HOME 目录权限后重试".to_string()),
        };
        let _ = render_check(&mut handle, &result);
        return 2;
    }

    let is_linux = cfg!(target_os = "linux");
    let kvm_feature_enabled = cfg!(feature = "kvm");

    if is_linux && kvm_feature_enabled && missing_any_vm_asset(&vm_asset_paths) {
        if writeln!(&mut handle).is_err() {
            return 2;
        }
        if writeln!(&mut handle, "正在准备 VM 资产...").is_err() {
            return 2;
        }
        if writeln!(
            &mut handle,
            "默认资产目录: {}",
            vm_asset_paths.assets_dir.display()
        )
        .is_err()
        {
            return 2;
        }

        if !vm_asset_paths.kernel_path.exists() {
            match build_missing_kernel(&mut handle, &vm_asset_paths.kernel_path) {
                Ok(()) => {}
                Err(error) => {
                    let _ = writeln!(&mut handle, "❌ kernel 构建失败: {error}");
                    return 2;
                }
            }
        }

        if !vm_asset_paths.rootfs_path.exists() {
            match build_missing_rootfs(&mut handle, &vm_asset_paths.rootfs_path) {
                Ok(()) => {}
                Err(error) => {
                    let _ = writeln!(&mut handle, "❌ rootfs 构建失败: {error}");
                    return 2;
                }
            }
        }

        if writeln!(
            &mut handle,
            "资产已安装到 {}",
            vm_asset_paths.assets_dir.display()
        )
        .is_err()
        {
            return 2;
        }
    } else if !is_linux {
        let result = CheckResult {
            name: "VM 资产引导".to_string(),
            status: CheckStatus::Skip,
            message: "当前平台不是 Linux，跳过 microVM 资产构建".to_string(),
            hint: None,
        };
        let _ = render_check(&mut handle, &result);
    } else if !kvm_feature_enabled {
        let result = CheckResult {
            name: "VM 资产引导".to_string(),
            status: CheckStatus::Skip,
            message: "当前构建未启用 VM feature（Cargo feature: kvm）".to_string(),
            hint: Some("如需 microVM，请使用 `--features kvm` 重新编译 mimobox-cli".to_string()),
        };
        let _ = render_check(&mut handle, &result);
    } else {
        let result = CheckResult {
            name: "VM 资产引导".to_string(),
            status: CheckStatus::Ok,
            message: format!("资产已就绪: {}", vm_asset_paths.assets_dir.display()),
            hint: None,
        };
        let _ = render_check(&mut handle, &result);
    }

    if writeln!(&mut handle).is_err() {
        return 2;
    }
    if writeln!(&mut handle, "重新运行 doctor 验证环境...").is_err() {
        return 2;
    }

    let results = collect_doctor_results();
    let exit_code = exit_code_for_results(&results);
    if let Err(error) = render_doctor_report(&mut handle, &results) {
        eprintln!("setup 验证输出失败: {error}");
        return 2;
    }

    exit_code
}

fn render_setup_header(writer: &mut impl Write) -> io::Result<()> {
    writeln!(writer, "检查 mimobox 运行环境...")
}

fn collect_doctor_results() -> Vec<CheckResult> {
    vec![
        check_os(),
        check_kvm_or_seatbelt(),
        check_memory(),
        check_seccomp(),
        check_landlock(),
        check_huge_pages(),
        check_features(),
        check_kernel_asset(),
        check_rootfs_asset(),
        check_toolchain(),
        check_python_sdk(),
    ]
}

fn render_doctor_report(writer: &mut impl Write, results: &[CheckResult]) -> io::Result<()> {
    for result in results {
        render_check(writer, result)?;
    }

    let warnings = results
        .iter()
        .filter(|result| result.status == CheckStatus::Warn)
        .count();
    let errors = results
        .iter()
        .filter(|result| result.status == CheckStatus::Fail)
        .count();

    writeln!(writer)?;
    writeln!(writer, "{warnings} 个警告，{errors} 个错误")
}

fn render_check(writer: &mut impl Write, result: &CheckResult) -> io::Result<()> {
    writeln!(
        writer,
        "{} {}: {}",
        result.status.icon(),
        result.name,
        result.message
    )?;

    if let Some(hint) = result.hint.as_deref() {
        writeln!(writer, "   建议: {hint}")?;
    }

    Ok(())
}

fn exit_code_for_results(results: &[CheckResult]) -> i32 {
    if results
        .iter()
        .any(|result| result.status == CheckStatus::Fail)
    {
        return 2;
    }

    if results
        .iter()
        .any(|result| result.status == CheckStatus::Warn)
    {
        return 1;
    }

    0
}

impl CheckStatus {
    fn icon(self) -> &'static str {
        match self {
            Self::Ok => "✅",
            Self::Warn => "⚠️",
            Self::Fail => "❌",
            Self::Skip => "⏭️",
        }
    }
}

fn check_os() -> CheckResult {
    let os_name =
        run_command_output("uname", &["-s"]).unwrap_or_else(|| env::consts::OS.to_string());
    let version = run_command_output("uname", &["-r"]).unwrap_or_else(|| "未知版本".to_string());
    let arch =
        run_command_output("uname", &["-m"]).unwrap_or_else(|| env::consts::ARCH.to_string());

    CheckResult {
        name: "操作系统".to_string(),
        status: CheckStatus::Ok,
        message: format!("{os_name} {version} ({arch})"),
        hint: None,
    }
}

fn check_kvm_or_seatbelt() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        return check_kvm();
    }

    #[cfg(target_os = "macos")]
    {
        return check_seatbelt();
    }

    #[allow(unreachable_code)]
    CheckResult {
        name: "平台依赖".to_string(),
        status: CheckStatus::Skip,
        message: "当前平台暂无额外运行时探测".to_string(),
        hint: None,
    }
}

#[cfg(target_os = "linux")]
fn check_kvm() -> CheckResult {
    let device_path = Path::new("/dev/kvm");
    let metadata = match fs::metadata(device_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return CheckResult {
                name: "KVM".to_string(),
                status: CheckStatus::Fail,
                message: "未找到 /dev/kvm".to_string(),
                hint: Some("请确认宿主机已启用硬件虚拟化，并安装 KVM 内核模块".to_string()),
            };
        }
        Err(error) => {
            return CheckResult {
                name: "KVM".to_string(),
                status: CheckStatus::Fail,
                message: format!("读取 /dev/kvm 失败: {error}"),
                hint: Some("请检查 /dev/kvm 是否存在且当前用户有访问权限".to_string()),
            };
        }
    };

    let mode = metadata.permissions().mode();
    let permissions = permission_string_from_mode(mode);

    let file = match OpenOptions::new().read(true).write(true).open(device_path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return CheckResult {
                name: "KVM".to_string(),
                status: CheckStatus::Fail,
                message: format!("/dev/kvm 存在，但当前用户无读写权限 ({permissions})"),
                hint: Some("请将当前用户加入 `kvm` 组，或调整 /dev/kvm 权限后重试".to_string()),
            };
        }
        Err(error) => {
            return CheckResult {
                name: "KVM".to_string(),
                status: CheckStatus::Fail,
                message: format!("打开 /dev/kvm 失败: {error}"),
                hint: Some("请确认宿主机支持 KVM，且当前容器/虚机已透传 /dev/kvm".to_string()),
            };
        }
    };

    match read_kvm_api_version(&file) {
        Ok(version) => CheckResult {
            name: "KVM".to_string(),
            status: CheckStatus::Ok,
            message: format!("/dev/kvm 可访问 ({permissions}, API v{version})"),
            hint: None,
        },
        Err(error) => CheckResult {
            name: "KVM".to_string(),
            status: CheckStatus::Warn,
            message: format!("/dev/kvm 可访问 ({permissions})，但读取 API 版本失败: {error}"),
            hint: Some("请确认内核 KVM 接口可用，或在宿主机上重新加载 KVM 模块".to_string()),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn check_kvm() -> CheckResult {
    CheckResult {
        name: "KVM".to_string(),
        status: CheckStatus::Skip,
        message: "当前平台不是 Linux，跳过 /dev/kvm 检查".to_string(),
        hint: None,
    }
}

#[cfg(target_os = "macos")]
fn check_seatbelt() -> CheckResult {
    let output = match Command::new("sandbox-exec")
        .args(["-p", "(version 1) (allow default)", "/usr/bin/true"])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return CheckResult {
                name: "Seatbelt".to_string(),
                status: CheckStatus::Fail,
                message: "未找到 sandbox-exec".to_string(),
                hint: Some(
                    "当前 macOS 环境缺少 Seatbelt 入口，mimobox OS 后端将不可用".to_string(),
                ),
            };
        }
        Err(error) => {
            return CheckResult {
                name: "Seatbelt".to_string(),
                status: CheckStatus::Fail,
                message: format!("执行 sandbox-exec 探测失败: {error}"),
                hint: Some("请检查系统策略或终端权限，确认 sandbox-exec 可执行".to_string()),
            };
        }
    };

    if output.status.success() {
        return CheckResult {
            name: "Seatbelt".to_string(),
            status: CheckStatus::Ok,
            message: "sandbox-exec 可用".to_string(),
            hint: None,
        };
    }

    let stderr = first_non_empty_line(&String::from_utf8_lossy(&output.stderr))
        .unwrap_or("sandbox-exec 返回非零退出码")
        .to_string();
    CheckResult {
        name: "Seatbelt".to_string(),
        status: CheckStatus::Warn,
        message: format!("sandbox-exec 探测返回异常: {stderr}"),
        hint: Some(
            "如当前系统已弃用 sandbox-exec，请改用支持的 macOS 版本或调整后端策略".to_string(),
        ),
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn check_seatbelt() -> CheckResult {
    CheckResult {
        name: "Seatbelt".to_string(),
        status: CheckStatus::Skip,
        message: "当前平台不是 macOS，跳过 sandbox-exec 检查".to_string(),
        hint: None,
    }
}

fn check_memory() -> CheckResult {
    match detect_memory_bytes() {
        Ok(memory_bytes) if memory_bytes >= MIN_VM_MEMORY_BYTES => CheckResult {
            name: "内存".to_string(),
            status: CheckStatus::Ok,
            message: format!("{} 可用，建议 4GB+ 用于 VM", human_bytes(memory_bytes)),
            hint: None,
        },
        Ok(memory_bytes) => CheckResult {
            name: "内存".to_string(),
            status: CheckStatus::Warn,
            message: format!(
                "{} 可用，低于建议的 4GB VM 运行门槛",
                human_bytes(memory_bytes)
            ),
            hint: Some("建议释放内存或提升主机可用内存后再运行 microVM".to_string()),
        },
        Err(error) => CheckResult {
            name: "内存".to_string(),
            status: CheckStatus::Warn,
            message: format!("读取内存信息失败: {error}"),
            hint: Some("请确认当前系统允许读取内存统计信息".to_string()),
        },
    }
}

fn check_seccomp() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        return match probe_seccomp() {
            Ok(mode) => CheckResult {
                name: "seccomp".to_string(),
                status: CheckStatus::Ok,
                message: format!("内核支持（当前进程模式 {mode}）"),
                hint: None,
            },
            Err(error) => CheckResult {
                name: "seccomp".to_string(),
                status: CheckStatus::Fail,
                message: format!("不可用: {error}"),
                hint: Some("请确认宿主机内核启用了 seccomp 支持".to_string()),
            },
        };
    }

    #[allow(unreachable_code)]
    CheckResult {
        name: "seccomp".to_string(),
        status: CheckStatus::Skip,
        message: "仅 Linux 支持 seccomp 检查".to_string(),
        hint: None,
    }
}

fn check_landlock() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        return match probe_landlock_abi() {
            Ok(abi) => CheckResult {
                name: "Landlock".to_string(),
                status: CheckStatus::Ok,
                message: format!("ABI v{abi} 已支持"),
                hint: None,
            },
            Err(error) => CheckResult {
                name: "Landlock".to_string(),
                status: CheckStatus::Fail,
                message: format!("不可用: {error}"),
                hint: Some("请确认宿主机内核版本 >= 5.13，并启用了 Landlock LSM".to_string()),
            },
        };
    }

    #[allow(unreachable_code)]
    CheckResult {
        name: "Landlock".to_string(),
        status: CheckStatus::Skip,
        message: "仅 Linux 支持 Landlock 检查".to_string(),
        hint: None,
    }
}

fn check_huge_pages() -> CheckResult {
    #[cfg(target_os = "linux")]
    {
        return match read_transparent_huge_pages() {
            Ok(mode) if mode == "always" || mode == "madvise" => CheckResult {
                name: "Huge Pages".to_string(),
                status: CheckStatus::Ok,
                message: format!("Transparent Huge Pages 已启用（{mode}）"),
                hint: None,
            },
            Ok(mode) => CheckResult {
                name: "Huge Pages".to_string(),
                status: CheckStatus::Warn,
                message: format!("Transparent Huge Pages 当前模式为 {mode}"),
                hint: Some(
                    "建议将 `/sys/kernel/mm/transparent_hugepage/enabled` 调整为 `madvise` 或 `always`"
                        .to_string(),
                ),
            },
            Err(error) => CheckResult {
                name: "Huge Pages".to_string(),
                status: CheckStatus::Warn,
                message: format!("读取 Transparent Huge Pages 状态失败: {error}"),
                hint: Some("请手动检查 `/sys/kernel/mm/transparent_hugepage/enabled`".to_string()),
            },
        };
    }

    #[allow(unreachable_code)]
    CheckResult {
        name: "Huge Pages".to_string(),
        status: CheckStatus::Skip,
        message: "仅 Linux 支持 Huge Pages 检查".to_string(),
        hint: None,
    }
}

fn check_features() -> CheckResult {
    let vm = if cfg!(feature = "kvm") {
        "已启用"
    } else {
        "未启用"
    };
    let wasm = if cfg!(feature = "wasm") {
        "已启用"
    } else {
        "未启用"
    };

    CheckResult {
        name: "Feature Flags".to_string(),
        status: CheckStatus::Ok,
        message: format!("vm（Cargo feature: kvm）{vm}，wasm {wasm}"),
        hint: None,
    }
}

fn check_kernel_asset() -> CheckResult {
    if !cfg!(target_os = "linux") {
        return CheckResult {
            name: "kernel 镜像".to_string(),
            status: CheckStatus::Skip,
            message: "当前平台不是 Linux，跳过 microVM kernel 检查".to_string(),
            hint: None,
        };
    }

    if !cfg!(feature = "kvm") {
        return CheckResult {
            name: "kernel 镜像".to_string(),
            status: CheckStatus::Skip,
            message: "当前构建未启用 VM feature（Cargo feature: kvm）".to_string(),
            hint: None,
        };
    }

    let paths = default_vm_asset_paths();
    match fs::metadata(&paths.kernel_path) {
        Ok(metadata) => CheckResult {
            name: "kernel 镜像".to_string(),
            status: CheckStatus::Ok,
            message: format!(
                "{} ({})",
                paths.kernel_path.display(),
                human_bytes(metadata.len())
            ),
            hint: None,
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => CheckResult {
            name: "kernel 镜像".to_string(),
            status: CheckStatus::Fail,
            message: format!("缺少 {}", paths.kernel_path.display()),
            hint: Some(
                "请执行 `mimobox setup`，或手动运行 `scripts/build-kernel.sh` 生成 vmlinux"
                    .to_string(),
            ),
        },
        Err(error) => CheckResult {
            name: "kernel 镜像".to_string(),
            status: CheckStatus::Fail,
            message: format!("读取失败: {} ({error})", paths.kernel_path.display()),
            hint: Some("请检查 kernel 镜像权限和路径配置".to_string()),
        },
    }
}

fn check_rootfs_asset() -> CheckResult {
    if !cfg!(target_os = "linux") {
        return CheckResult {
            name: "rootfs".to_string(),
            status: CheckStatus::Skip,
            message: "当前平台不是 Linux，跳过 microVM rootfs 检查".to_string(),
            hint: None,
        };
    }

    if !cfg!(feature = "kvm") {
        return CheckResult {
            name: "rootfs".to_string(),
            status: CheckStatus::Skip,
            message: "当前构建未启用 VM feature（Cargo feature: kvm）".to_string(),
            hint: None,
        };
    }

    let paths = default_vm_asset_paths();
    match fs::metadata(&paths.rootfs_path) {
        Ok(metadata) => CheckResult {
            name: "rootfs".to_string(),
            status: CheckStatus::Ok,
            message: format!(
                "{} ({})",
                paths.rootfs_path.display(),
                human_bytes(metadata.len())
            ),
            hint: None,
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => CheckResult {
            name: "rootfs".to_string(),
            status: CheckStatus::Fail,
            message: format!("缺少 {}", paths.rootfs_path.display()),
            hint: Some(
                "请执行 `mimobox setup`，或手动运行 `scripts/build-rootfs.sh` 生成 rootfs.cpio.gz"
                    .to_string(),
            ),
        },
        Err(error) => CheckResult {
            name: "rootfs".to_string(),
            status: CheckStatus::Fail,
            message: format!("读取失败: {} ({error})", paths.rootfs_path.display()),
            hint: Some("请检查 rootfs 权限和路径配置".to_string()),
        },
    }
}

fn check_toolchain() -> CheckResult {
    let rustc = run_command_output("rustc", &["--version"]);
    let cargo = run_command_output("cargo", &["--version"]);

    match (rustc, cargo) {
        (Some(rustc), Some(cargo)) => CheckResult {
            name: "Rust 工具链".to_string(),
            status: CheckStatus::Ok,
            message: format!("{rustc}，{cargo}"),
            hint: None,
        },
        (None, Some(cargo)) => CheckResult {
            name: "Rust 工具链".to_string(),
            status: CheckStatus::Fail,
            message: format!("cargo 可用，但未找到 rustc ({cargo})"),
            hint: Some("请确认 Rust toolchain 已完整安装".to_string()),
        },
        (Some(rustc), None) => CheckResult {
            name: "Rust 工具链".to_string(),
            status: CheckStatus::Fail,
            message: format!("rustc 可用，但未找到 cargo ({rustc})"),
            hint: Some("请确认 `cargo` 已加入 PATH".to_string()),
        },
        (None, None) => CheckResult {
            name: "Rust 工具链".to_string(),
            status: CheckStatus::Fail,
            message: "未找到 rustc/cargo".to_string(),
            hint: Some("请先运行 `scripts/setup.sh` 安装 Rust 开发环境".to_string()),
        },
    }
}

fn check_python_sdk() -> CheckResult {
    let python = run_command_output("python3", &["--version"]);
    let maturin = run_command_output("maturin", &["--version"]);

    match (python, maturin) {
        (Some(python), Some(maturin)) => CheckResult {
            name: "Python SDK".to_string(),
            status: CheckStatus::Ok,
            message: format!("{maturin} + {python}"),
            hint: None,
        },
        (Some(python), None) => CheckResult {
            name: "Python SDK".to_string(),
            status: CheckStatus::Warn,
            message: format!("检测到 {python}，但未找到 maturin"),
            hint: Some(
                "如需构建 mimobox-python，请执行 `pipx install maturin` 或 `cargo install maturin`"
                    .to_string(),
            ),
        },
        (None, Some(maturin)) => CheckResult {
            name: "Python SDK".to_string(),
            status: CheckStatus::Warn,
            message: format!("检测到 {maturin}，但未找到 python3"),
            hint: Some("如需构建 mimobox-python，请先安装 Python 3".to_string()),
        },
        (None, None) => CheckResult {
            name: "Python SDK".to_string(),
            status: CheckStatus::Warn,
            message: "未检测到 python3 / maturin（可选）".to_string(),
            hint: Some("如果需要 Python SDK，请安装 Python 3 和 maturin".to_string()),
        },
    }
}

fn resolve_app_home_dir(home_dir: Option<PathBuf>) -> Result<PathBuf, CheckResult> {
    home_dir
        .map(|home| home.join(APP_HOME_SUBDIR))
        .ok_or_else(|| CheckResult {
            name: "mimobox 目录".to_string(),
            status: CheckStatus::Fail,
            message: "未找到 HOME 环境变量".to_string(),
            hint: Some("请先设置 HOME，再执行 `mimobox setup`".to_string()),
        })
}

fn default_vm_asset_paths() -> VmAssetPaths {
    default_vm_asset_paths_for(
        env::var_os("VM_ASSETS_DIR").map(PathBuf::from),
        env::var_os("HOME").map(PathBuf::from),
    )
}

fn default_vm_asset_paths_for_home(home_dir: Option<PathBuf>) -> VmAssetPaths {
    default_vm_asset_paths_for(None, home_dir)
}

fn default_vm_asset_paths_for(
    vm_assets_dir: Option<PathBuf>,
    home_dir: Option<PathBuf>,
) -> VmAssetPaths {
    let assets_dir = vm_assets_dir
        .or_else(|| home_dir.map(|home| home.join(ASSETS_SUBDIR)))
        .unwrap_or_else(|| PathBuf::from(LEGACY_VM_ASSETS_DIR));

    VmAssetPaths {
        kernel_path: assets_dir.join("vmlinux"),
        rootfs_path: assets_dir.join("rootfs.cpio.gz"),
        assets_dir,
    }
}

fn summarize_vm_assets_for_setup() -> CheckResult {
    if !cfg!(target_os = "linux") {
        return CheckResult {
            name: "VM 资产".to_string(),
            status: CheckStatus::Skip,
            message: "当前平台不是 Linux，跳过资产检查".to_string(),
            hint: None,
        };
    }

    if !cfg!(feature = "kvm") {
        return CheckResult {
            name: "VM 资产".to_string(),
            status: CheckStatus::Skip,
            message: "当前构建未启用 VM feature（Cargo feature: kvm）".to_string(),
            hint: None,
        };
    }

    let paths = default_vm_asset_paths();
    if !missing_any_vm_asset(&paths) {
        return CheckResult {
            name: "VM 资产".to_string(),
            status: CheckStatus::Ok,
            message: format!("已就绪: {}", paths.assets_dir.display()),
            hint: None,
        };
    }

    let mut missing = Vec::new();
    if !paths.kernel_path.exists() {
        missing.push("vmlinux");
    }
    if !paths.rootfs_path.exists() {
        missing.push("rootfs.cpio.gz");
    }

    CheckResult {
        name: "VM 资产".to_string(),
        status: CheckStatus::Warn,
        message: format!("缺少 {}", missing.join("、")),
        hint: Some("setup 将尝试自动构建缺失资产".to_string()),
    }
}

fn missing_any_vm_asset(paths: &VmAssetPaths) -> bool {
    !paths.kernel_path.exists() || !paths.rootfs_path.exists()
}

fn ensure_directory_exists(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

fn build_missing_kernel(writer: &mut impl Write, output_path: &Path) -> Result<(), String> {
    let script = find_script("build-kernel.sh").ok_or_else(|| {
        "未找到 scripts/build-kernel.sh，请在仓库根目录执行 `scripts/build-kernel.sh --output <path>`"
            .to_string()
    })?;

    writeln!(writer, "  kernel (vmlinux): 构建中...").map_err(|error| error.to_string())?;
    info!(script = %script.display(), output = %output_path.display(), "开始构建 kernel 资产");
    run_script(&script, &[("--output", output_path.as_os_str())])?;
    writeln!(writer, "  kernel (vmlinux): ✅").map_err(|error| error.to_string())
}

fn build_missing_rootfs(writer: &mut impl Write, output_path: &Path) -> Result<(), String> {
    let script = find_script("build-rootfs.sh").ok_or_else(|| {
        "未找到 scripts/build-rootfs.sh，请在仓库根目录执行 `scripts/build-rootfs.sh` 或自行准备 rootfs"
            .to_string()
    })?;

    writeln!(writer, "  rootfs (rootfs.cpio.gz): 构建中...").map_err(|error| error.to_string())?;
    info!(script = %script.display(), output = %output_path.display(), "开始构建 rootfs 资产");
    run_script_with_env(&script, &[], &[("OUTPUT", output_path.as_os_str())])?;
    writeln!(writer, "  rootfs (rootfs.cpio.gz): ✅").map_err(|error| error.to_string())
}

fn find_script(name: &str) -> Option<PathBuf> {
    if let Ok(current_dir) = env::current_dir() {
        let cwd_candidate = current_dir.join("scripts").join(name);
        if cwd_candidate.is_file() {
            return Some(cwd_candidate);
        }
    }

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)?
        .to_path_buf();
    let repo_candidate = repo_root.join("scripts").join(name);
    if repo_candidate.is_file() {
        return Some(repo_candidate);
    }

    None
}

fn run_script(script_path: &Path, args: &[(&str, &std::ffi::OsStr)]) -> Result<(), String> {
    run_script_with_env(script_path, args, &[])
}

fn run_script_with_env(
    script_path: &Path,
    args: &[(&str, &std::ffi::OsStr)],
    envs: &[(&str, &std::ffi::OsStr)],
) -> Result<(), String> {
    let mut command = Command::new(script_path);

    for (flag, value) in args {
        command.arg(flag).arg(value);
    }

    for (key, value) in envs {
        command.env(key, value);
    }

    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| format!("启动脚本失败: {error}"))?;

    if status.success() {
        return Ok(());
    }

    Err(format!("脚本退出码异常: {status}"))
}

fn run_command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    first_non_empty_line(&text).map(ToOwned::to_owned)
}

fn first_non_empty_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| !line.is_empty())
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0usize;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{bytes} {}", UNITS[unit_index])
    } else {
        format!("{value:.1}{}", UNITS[unit_index])
    }
}

#[cfg(target_os = "linux")]
fn permission_string_from_mode(mode: u32) -> String {
    let table = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];

    table
        .into_iter()
        .map(|(bit, ch)| if mode & bit != 0 { ch } else { '-' })
        .collect()
}

#[cfg(target_os = "linux")]
fn read_kvm_api_version(file: &File) -> io::Result<i32> {
    // SAFETY: `file` 是当前进程持有的有效 `/dev/kvm` fd，`KVM_GET_API_VERSION`
    // 不读写用户态缓冲区，只返回一个整数版本号。
    let version = unsafe { libc::ioctl(file.as_raw_fd(), KVM_GET_API_VERSION_IOCTL) };
    if version < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(version)
}

#[cfg(target_os = "linux")]
fn detect_memory_bytes() -> Result<u64, String> {
    let meminfo = fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("读取 /proc/meminfo 失败: {error}"))?;
    parse_linux_memory_bytes(&meminfo)
}

#[cfg(target_os = "macos")]
fn detect_memory_bytes() -> Result<u64, String> {
    let output = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .map_err(|error| format!("执行 sysctl 失败: {error}"))?;

    if !output.status.success() {
        return Err(format!("sysctl 返回异常状态: {}", output.status));
    }

    let value = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("解析 hw.memsize 失败: {error}"))?;
    Ok(value)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_memory_bytes() -> Result<u64, String> {
    Err("当前平台暂未实现内存探测".to_string())
}

#[cfg(target_os = "linux")]
fn parse_linux_memory_bytes(meminfo: &str) -> Result<u64, String> {
    parse_meminfo_value(meminfo, "MemAvailable")
        .or_else(|_| parse_meminfo_value(meminfo, "MemTotal"))
        .map(|kib| kib.saturating_mul(1024))
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(meminfo: &str, key: &str) -> Result<u64, String> {
    let prefix = format!("{key}:");
    let line = meminfo
        .lines()
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("未找到 {key}"))?;
    let value = line[prefix.len()..]
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("未找到 {key} 数值"))?;
    value
        .parse::<u64>()
        .map_err(|error| format!("解析 {key} 失败: {error}"))
}

#[cfg(target_os = "linux")]
fn probe_seccomp() -> Result<i32, String> {
    // SAFETY: `PR_GET_SECCOMP` 是纯读取操作，不修改进程状态。
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode < 0 {
        return Err(io::Error::last_os_error().to_string());
    }

    Ok(mode)
}

#[cfg(target_os = "linux")]
fn probe_landlock_abi() -> Result<i32, String> {
    // SAFETY: 以 `LANDLOCK_CREATE_RULESET_VERSION` 标志调用时仅探测 ABI 版本，
    // 不创建 ruleset，也不会修改当前进程安全状态。
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if abi < 0 {
        return Err(io::Error::last_os_error().to_string());
    }

    i32::try_from(abi).map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn read_transparent_huge_pages() -> Result<String, String> {
    let content = fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled")
        .map_err(|error| format!("读取 THP 状态失败: {error}"))?;

    for token in content.split_whitespace() {
        if let Some(stripped) = token
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            return Ok(stripped.to_string());
        }
    }

    Err("无法解析当前 THP 模式".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_vm_asset_paths_prefers_home_directory() {
        let home_dir = PathBuf::from("/tmp/mimobox-home");
        let paths = default_vm_asset_paths_for_home(Some(home_dir.clone()));

        assert_eq!(paths.assets_dir, home_dir.join(".mimobox/assets"));
        assert_eq!(paths.kernel_path, home_dir.join(".mimobox/assets/vmlinux"));
        assert_eq!(
            paths.rootfs_path,
            home_dir.join(".mimobox/assets/rootfs.cpio.gz")
        );
    }

    #[test]
    fn resolve_app_home_dir_uses_hidden_directory() {
        let home_dir = PathBuf::from("/tmp/demo-home");
        let app_home = resolve_app_home_dir(Some(home_dir.clone())).expect("应生成默认应用目录");

        assert_eq!(app_home, home_dir.join(".mimobox"));
    }

    #[test]
    fn human_bytes_formats_binary_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0MB");
    }

    #[test]
    fn exit_code_prefers_fail_over_warning() {
        let results = [
            CheckResult {
                name: "warn".to_string(),
                status: CheckStatus::Warn,
                message: String::new(),
                hint: None,
            },
            CheckResult {
                name: "fail".to_string(),
                status: CheckStatus::Fail,
                message: String::new(),
                hint: None,
            },
        ];

        assert_eq!(exit_code_for_results(&results), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_linux_memory_bytes_prefers_memavailable() {
        let meminfo = "MemTotal:       32768000 kB\nMemAvailable:   16384000 kB\n";
        let bytes = parse_linux_memory_bytes(meminfo).expect("应成功解析 MemAvailable");

        assert_eq!(bytes, 16_384_000 * 1024);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn permission_string_from_mode_formats_unix_bits() {
        assert_eq!(permission_string_from_mode(0o660), "rw-rw----");
        assert_eq!(permission_string_from_mode(0o755), "rwxr-xr-x");
    }
}
