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

#[cfg(target_os = "linux")]
use tracing::{info, warn};
#[cfg(not(target_os = "linux"))]
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
        eprintln!("doctor output failed: {error}");
        return 2;
    }

    exit_code
}

pub fn run_setup() -> i32 {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    if let Err(error) = render_setup_header(&mut handle) {
        eprintln!("setup output failed: {error}");
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
            name: "mimobox directory".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "failed to create directory: {} ({error})",
                app_home.display()
            ),
            hint: Some("check HOME directory permissions and retry".to_string()),
        };
        let _ = render_check(&mut handle, &result);
        return 2;
    }

    if let Err(error) = ensure_directory_exists(&assets_dir) {
        let result = CheckResult {
            name: "assets directory".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "failed to create directory: {} ({error})",
                assets_dir.display()
            ),
            hint: Some("check HOME directory permissions and retry".to_string()),
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
        if writeln!(&mut handle, "Preparing VM assets...").is_err() {
            return 2;
        }
        if writeln!(
            &mut handle,
            "Default assets directory: {}",
            vm_asset_paths.assets_dir.display()
        )
        .is_err()
        {
            return 2;
        }

        match crate::asset_download::download_vm_assets(&vm_asset_paths.assets_dir, &mut handle) {
            Ok(true) => {
                let _ = writeln!(&mut handle, "  Pre-built assets downloaded");
            }
            Ok(false) => {
                let _ = writeln!(
                    &mut handle,
                    "  Pre-built assets unavailable, falling back to local build..."
                );
                if let Err(exit_code) = build_missing_vm_assets(&mut handle, &vm_asset_paths) {
                    return exit_code;
                }
            }
            Err(error) => {
                let _ = writeln!(&mut handle, "  Pre-built asset download failed: {error}");
                if let Err(exit_code) = build_missing_vm_assets(&mut handle, &vm_asset_paths) {
                    return exit_code;
                }
            }
        }

        if writeln!(
            &mut handle,
            "Assets installed to {}",
            vm_asset_paths.assets_dir.display()
        )
        .is_err()
        {
            return 2;
        }
    } else if !is_linux {
        let result = CheckResult {
            name: "VM asset bootstrap".to_string(),
            status: CheckStatus::Skip,
            message: "Not on Linux; skipping microVM asset build".to_string(),
            hint: None,
        };
        let _ = render_check(&mut handle, &result);
    } else if !kvm_feature_enabled {
        let result = CheckResult {
            name: "VM asset bootstrap".to_string(),
            status: CheckStatus::Skip,
            message: "VM feature not enabled in current build (Cargo feature: kvm)".to_string(),
            hint: Some(
                "For microVM support, rebuild mimobox-cli with `--features kvm`".to_string(),
            ),
        };
        let _ = render_check(&mut handle, &result);
    } else {
        let result = CheckResult {
            name: "VM asset bootstrap".to_string(),
            status: CheckStatus::Ok,
            message: format!("Assets ready: {}", vm_asset_paths.assets_dir.display()),
            hint: None,
        };
        let _ = render_check(&mut handle, &result);
    }

    if writeln!(&mut handle).is_err() {
        return 2;
    }
    if writeln!(&mut handle, "Re-running doctor to verify environment...").is_err() {
        return 2;
    }

    let results = collect_doctor_results();
    let exit_code = exit_code_for_results(&results);
    if let Err(error) = render_doctor_report(&mut handle, &results) {
        eprintln!("setup verification output failed: {error}");
        return 2;
    }

    exit_code
}

fn render_setup_header(writer: &mut impl Write) -> io::Result<()> {
    writeln!(writer, "Checking mimobox runtime environment...")
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
    writeln!(writer, "{warnings} warning(s), {errors} error(s)")
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
        writeln!(writer, "   hint: {hint}")?;
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
    let version =
        run_command_output("uname", &["-r"]).unwrap_or_else(|| "unknown version".to_string());
    let arch =
        run_command_output("uname", &["-m"]).unwrap_or_else(|| env::consts::ARCH.to_string());

    CheckResult {
        name: "Operating System".to_string(),
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
        name: "Platform dependencies".to_string(),
        status: CheckStatus::Skip,
        message: "No additional runtime probes for this platform".to_string(),
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
                message: "/dev/kvm not found".to_string(),
                hint: Some("Ensure hardware virtualization is enabled on the host and the KVM kernel module is installed".to_string()),
            };
        }
        Err(error) => {
            return CheckResult {
                name: "KVM".to_string(),
                status: CheckStatus::Fail,
                message: format!("Failed to read /dev/kvm: {error}"),
                hint: Some(
                    "Check that /dev/kvm exists and the current user has access".to_string(),
                ),
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
                message: format!(
                    "/dev/kvm exists but current user lacks read/write permissions ({permissions})"
                ),
                hint: Some(
                    "Add the current user to the kvm group or adjust /dev/kvm permissions"
                        .to_string(),
                ),
            };
        }
        Err(error) => {
            return CheckResult {
                name: "KVM".to_string(),
                status: CheckStatus::Fail,
                message: format!("Failed to open /dev/kvm: {error}"),
                hint: Some("Ensure the host supports KVM and /dev/kvm is passed through to the container/VM".to_string()),
            };
        }
    };

    match read_kvm_api_version(&file) {
        Ok(version) => CheckResult {
            name: "KVM".to_string(),
            status: CheckStatus::Ok,
            message: format!("/dev/kvm accessible ({permissions}, API v{version})"),
            hint: None,
        },
        Err(error) => CheckResult {
            name: "KVM".to_string(),
            status: CheckStatus::Warn,
            message: format!(
                "/dev/kvm accessible ({permissions}) but failed to read API version: {error}"
            ),
            hint: Some(
                "Ensure the kernel KVM interface is available or reload the KVM module on the host"
                    .to_string(),
            ),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn check_kvm() -> CheckResult {
    CheckResult {
        name: "KVM".to_string(),
        status: CheckStatus::Skip,
        message: "Not on Linux; skipping /dev/kvm check".to_string(),
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
                message: "sandbox-exec not found".to_string(),
                hint: Some(
                    "Seatbelt entry point missing in current macOS environment; mimobox OS backend will be unavailable".to_string(),
                ),
            };
        }
        Err(error) => {
            return CheckResult {
                name: "Seatbelt".to_string(),
                status: CheckStatus::Fail,
                message: format!("sandbox-exec probe failed: {error}"),
                hint: Some("Check system policy or terminal permissions to ensure sandbox-exec is executable".to_string()),
            };
        }
    };

    if output.status.success() {
        return CheckResult {
            name: "Seatbelt".to_string(),
            status: CheckStatus::Ok,
            message: "sandbox-exec available".to_string(),
            hint: None,
        };
    }

    let stderr = first_non_empty_line(&String::from_utf8_lossy(&output.stderr))
        .unwrap_or("sandbox-exec returned non-zero exit code")
        .to_string();
    CheckResult {
        name: "Seatbelt".to_string(),
        status: CheckStatus::Warn,
        message: format!("sandbox-exec probe returned unexpected result: {stderr}"),
        hint: Some(
            "If sandbox-exec is deprecated on this system, use a supported macOS version or adjust backend strategy".to_string(),
        ),
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn check_seatbelt() -> CheckResult {
    CheckResult {
        name: "Seatbelt".to_string(),
        status: CheckStatus::Skip,
        message: "Not on macOS; skipping sandbox-exec check".to_string(),
        hint: None,
    }
}

fn check_memory() -> CheckResult {
    match detect_memory_bytes() {
        Ok(memory_bytes) if memory_bytes >= MIN_VM_MEMORY_BYTES => CheckResult {
            name: "Memory".to_string(),
            status: CheckStatus::Ok,
            message: format!(
                "{} available (4GB+ recommended for VM)",
                human_bytes(memory_bytes)
            ),
            hint: None,
        },
        Ok(memory_bytes) => CheckResult {
            name: "Memory".to_string(),
            status: CheckStatus::Warn,
            message: format!(
                "{} available, below the recommended 4GB threshold for VM",
                human_bytes(memory_bytes)
            ),
            hint: Some("Free up memory or increase host memory before running microVM".to_string()),
        },
        Err(error) => CheckResult {
            name: "Memory".to_string(),
            status: CheckStatus::Warn,
            message: format!("Failed to read memory info: {error}"),
            hint: Some("Ensure the system allows reading memory statistics".to_string()),
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
                message: format!("kernel supported (current process mode {mode})"),
                hint: None,
            },
            Err(error) => CheckResult {
                name: "seccomp".to_string(),
                status: CheckStatus::Fail,
                message: format!("unavailable: {error}"),
                hint: Some("Ensure the host kernel has seccomp support enabled".to_string()),
            },
        };
    }

    #[allow(unreachable_code)]
    CheckResult {
        name: "seccomp".to_string(),
        status: CheckStatus::Skip,
        message: "seccomp check only supported on Linux".to_string(),
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
                message: format!("ABI v{abi} supported"),
                hint: None,
            },
            Err(error) => CheckResult {
                name: "Landlock".to_string(),
                status: CheckStatus::Fail,
                message: format!("unavailable: {error}"),
                hint: Some("Ensure host kernel >= 5.13 with Landlock LSM enabled".to_string()),
            },
        };
    }

    #[allow(unreachable_code)]
    CheckResult {
        name: "Landlock".to_string(),
        status: CheckStatus::Skip,
        message: "Landlock check only supported on Linux".to_string(),
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
                message: format!("Transparent Huge Pages enabled ({mode})"),
                hint: None,
            },
            Ok(mode) => CheckResult {
                name: "Huge Pages".to_string(),
                status: CheckStatus::Warn,
                message: format!("Transparent Huge Pages current mode: {mode}"),
                hint: Some(
                    "Set `/sys/kernel/mm/transparent_hugepage/enabled` to `madvise` or `always`"
                        .to_string(),
                ),
            },
            Err(error) => CheckResult {
                name: "Huge Pages".to_string(),
                status: CheckStatus::Warn,
                message: format!("Failed to read Transparent Huge Pages status: {error}"),
                hint: Some(
                    "Check `/sys/kernel/mm/transparent_hugepage/enabled` manually".to_string(),
                ),
            },
        };
    }

    #[allow(unreachable_code)]
    CheckResult {
        name: "Huge Pages".to_string(),
        status: CheckStatus::Skip,
        message: "Huge Pages check only supported on Linux".to_string(),
        hint: None,
    }
}

fn check_features() -> CheckResult {
    let vm = if cfg!(feature = "kvm") {
        "enabled"
    } else {
        "disabled"
    };
    let wasm = if cfg!(feature = "wasm") {
        "enabled"
    } else {
        "disabled"
    };

    CheckResult {
        name: "Feature Flags".to_string(),
        status: CheckStatus::Ok,
        message: format!("vm (Cargo feature: kvm) {vm}, wasm {wasm}"),
        hint: None,
    }
}

fn check_kernel_asset() -> CheckResult {
    if !cfg!(target_os = "linux") {
        return CheckResult {
            name: "kernel image".to_string(),
            status: CheckStatus::Skip,
            message: "Not on Linux; skipping microVM kernel check".to_string(),
            hint: None,
        };
    }

    if !cfg!(feature = "kvm") {
        return CheckResult {
            name: "kernel image".to_string(),
            status: CheckStatus::Skip,
            message: "VM feature not enabled in current build (Cargo feature: kvm)".to_string(),
            hint: None,
        };
    }

    let paths = default_vm_asset_paths();
    match fs::metadata(&paths.kernel_path) {
        Ok(metadata) => CheckResult {
            name: "kernel image".to_string(),
            status: CheckStatus::Ok,
            message: format!(
                "{} ({})",
                paths.kernel_path.display(),
                human_bytes(metadata.len())
            ),
            hint: None,
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => CheckResult {
            name: "kernel image".to_string(),
            status: CheckStatus::Fail,
            message: format!("missing {}", paths.kernel_path.display()),
            hint: Some(
                "Run `mimobox setup`, or manually run `scripts/build-kernel.sh` to generate vmlinux"
                    .to_string(),
            ),
        },
        Err(error) => CheckResult {
            name: "kernel image".to_string(),
            status: CheckStatus::Fail,
            message: format!("read failed: {} ({error})", paths.kernel_path.display()),
            hint: Some("Check kernel image permissions and path configuration".to_string()),
        },
    }
}

fn check_rootfs_asset() -> CheckResult {
    if !cfg!(target_os = "linux") {
        return CheckResult {
            name: "rootfs".to_string(),
            status: CheckStatus::Skip,
            message: "Not on Linux; skipping microVM rootfs check".to_string(),
            hint: None,
        };
    }

    if !cfg!(feature = "kvm") {
        return CheckResult {
            name: "rootfs".to_string(),
            status: CheckStatus::Skip,
            message: "VM feature not enabled in current build (Cargo feature: kvm)".to_string(),
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
            message: format!("missing {}", paths.rootfs_path.display()),
            hint: Some(
                "Run `mimobox setup`, or manually run `scripts/build-rootfs.sh` to generate rootfs.cpio.gz"
                    .to_string(),
            ),
        },
        Err(error) => CheckResult {
            name: "rootfs".to_string(),
            status: CheckStatus::Fail,
            message: format!("read failed: {} ({error})", paths.rootfs_path.display()),
            hint: Some("Check rootfs permissions and path configuration".to_string()),
        },
    }
}

fn check_toolchain() -> CheckResult {
    let rustc = run_command_output("rustc", &["--version"]);
    let cargo = run_command_output("cargo", &["--version"]);

    match (rustc, cargo) {
        (Some(rustc), Some(cargo)) => CheckResult {
            name: "Rust toolchain".to_string(),
            status: CheckStatus::Ok,
            message: format!("{rustc}，{cargo}"),
            hint: None,
        },
        (None, Some(cargo)) => CheckResult {
            name: "Rust toolchain".to_string(),
            status: CheckStatus::Fail,
            message: format!("cargo available but rustc not found ({cargo})"),
            hint: Some("Ensure the Rust toolchain is fully installed".to_string()),
        },
        (Some(rustc), None) => CheckResult {
            name: "Rust toolchain".to_string(),
            status: CheckStatus::Fail,
            message: format!("rustc available but cargo not found ({rustc})"),
            hint: Some("Ensure `cargo` is on PATH".to_string()),
        },
        (None, None) => CheckResult {
            name: "Rust toolchain".to_string(),
            status: CheckStatus::Fail,
            message: "rustc/cargo not found".to_string(),
            hint: Some(
                "Run `scripts/setup.sh` to install the Rust development environment".to_string(),
            ),
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
            message: format!("Detected {python} but maturin not found"),
            hint: Some(
                "To build mimobox-python, run `pipx install maturin` or `cargo install maturin`"
                    .to_string(),
            ),
        },
        (None, Some(maturin)) => CheckResult {
            name: "Python SDK".to_string(),
            status: CheckStatus::Warn,
            message: format!("Detected {maturin} but python3 not found"),
            hint: Some("To build mimobox-python, install Python 3 first".to_string()),
        },
        (None, None) => CheckResult {
            name: "Python SDK".to_string(),
            status: CheckStatus::Warn,
            message: "python3 / maturin not detected (optional)".to_string(),
            hint: Some("For Python SDK support, install Python 3 and maturin".to_string()),
        },
    }
}

fn resolve_app_home_dir(home_dir: Option<PathBuf>) -> Result<PathBuf, CheckResult> {
    home_dir
        .map(|home| home.join(APP_HOME_SUBDIR))
        .ok_or_else(|| CheckResult {
            name: "mimobox directory".to_string(),
            status: CheckStatus::Fail,
            message: "HOME environment variable not found".to_string(),
            hint: Some("Set HOME first, then run `mimobox setup`".to_string()),
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
            name: "VM assets".to_string(),
            status: CheckStatus::Skip,
            message: "Not on Linux; skipping asset check".to_string(),
            hint: None,
        };
    }

    if !cfg!(feature = "kvm") {
        return CheckResult {
            name: "VM assets".to_string(),
            status: CheckStatus::Skip,
            message: "VM feature not enabled in current build (Cargo feature: kvm)".to_string(),
            hint: None,
        };
    }

    let paths = default_vm_asset_paths();
    if !missing_any_vm_asset(&paths) {
        return CheckResult {
            name: "VM assets".to_string(),
            status: CheckStatus::Ok,
            message: format!("Ready: {}", paths.assets_dir.display()),
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
        name: "VM assets".to_string(),
        status: CheckStatus::Warn,
        message: format!("missing {}", missing.join(", ")),
        hint: Some("setup will attempt to build missing assets automatically".to_string()),
    }
}

fn missing_any_vm_asset(paths: &VmAssetPaths) -> bool {
    !paths.kernel_path.exists() || !paths.rootfs_path.exists()
}

fn build_missing_vm_assets(writer: &mut impl Write, paths: &VmAssetPaths) -> Result<(), i32> {
    if !paths.kernel_path.exists() {
        match build_missing_kernel(writer, &paths.kernel_path) {
            Ok(()) => {}
            Err(error) => {
                let _ = writeln!(writer, "❌ kernel build failed: {error}");
                return Err(2);
            }
        }
    }

    if !paths.rootfs_path.exists() {
        match build_missing_rootfs(writer, &paths.rootfs_path) {
            Ok(()) => {}
            Err(error) => {
                let _ = writeln!(writer, "❌ rootfs build failed: {error}");
                return Err(2);
            }
        }
    }

    Ok(())
}

fn ensure_directory_exists(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

fn build_missing_kernel(writer: &mut impl Write, output_path: &Path) -> Result<(), String> {
    let script = find_script("build-kernel.sh").ok_or_else(|| {
        "scripts/build-kernel.sh not found; run `scripts/build-kernel.sh --output <path>` from the repo root"
            .to_string()
    })?;

    writeln!(writer, "  kernel (vmlinux): building...").map_err(|error| error.to_string())?;
    info!(script = %script.display(), output = %output_path.display(), "building kernel asset");
    run_script(&script, &[("--output", output_path.as_os_str())])?;
    writeln!(writer, "  kernel (vmlinux): ✅").map_err(|error| error.to_string())
}

fn build_missing_rootfs(writer: &mut impl Write, output_path: &Path) -> Result<(), String> {
    let script = find_script("build-rootfs.sh").ok_or_else(|| {
        "scripts/build-rootfs.sh not found; run `scripts/build-rootfs.sh` from the repo root or prepare rootfs manually"
            .to_string()
    })?;

    writeln!(writer, "  rootfs (rootfs.cpio.gz): building...")
        .map_err(|error| error.to_string())?;
    info!(script = %script.display(), output = %output_path.display(), "building rootfs asset");
    run_script_with_env(&script, &[], &[("OUTPUT", output_path.as_os_str())])?;
    writeln!(writer, "  rootfs (rootfs.cpio.gz): ✅").map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn find_script(name: &str) -> Option<PathBuf> {
    // 安全：仅使用编译时嵌入的仓库路径，不从 CWD 查找。
    // 原因：优先查找 CWD 下的 scripts/ 目录会允许恶意目录注入脚本获得代码执行。
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)?
        .to_path_buf();
    let candidate = repo_root.join("scripts").join(name);
    if validate_script(&candidate, &repo_root) {
        return Some(candidate);
    }

    None
}

#[cfg(not(target_os = "linux"))]
fn find_script(_name: &str) -> Option<PathBuf> {
    None
}

#[cfg(target_os = "linux")]
fn validate_script(path: &Path, allowed_prefix: &Path) -> bool {
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            warn!(path = %path.display(), "script path canonicalize failed");
            return false;
        }
    };

    let canonical_prefix = match allowed_prefix.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            warn!(prefix = %allowed_prefix.display(), "script prefix canonicalize failed");
            return false;
        }
    };

    if !canonical.starts_with(&canonical_prefix) {
        warn!(
            path = %canonical.display(),
            prefix = %canonical_prefix.display(),
            "script path escapes allowed prefix"
        );
        return false;
    }

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            warn!(path = %path.display(), "script metadata read failed");
            return false;
        }
    };
    if !metadata.is_file() {
        warn!(path = %path.display(), "script path is not a regular file");
        return false;
    }

    let mode = metadata.permissions().mode();
    if mode & 0o002 != 0 {
        warn!(path = %path.display(), mode = %format!("{mode:o}"), "script is world-writable");
        return false;
    }

    true
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
        .map_err(|error| format!("failed to start script: {error}"))?;

    if status.success() {
        return Ok(());
    }

    Err(format!("script exited with non-zero code: {status}"))
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
    // SAFETY: `file` is a valid `/dev/kvm` fd held by the current process. `KVM_GET_API_VERSION`
    // does not read or write user-space buffers and only returns an integer version.
    let version = unsafe { libc::ioctl(file.as_raw_fd(), KVM_GET_API_VERSION_IOCTL as _) };
    if version < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(version)
}

#[cfg(target_os = "linux")]
fn detect_memory_bytes() -> Result<u64, String> {
    let meminfo = fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("failed to read /proc/meminfo: {error}"))?;
    parse_linux_memory_bytes(&meminfo)
}

#[cfg(target_os = "macos")]
fn detect_memory_bytes() -> Result<u64, String> {
    let output = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .map_err(|error| format!("sysctl execution failed: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "sysctl returned unexpected status: {}",
            output.status
        ));
    }

    let value = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("failed to parse hw.memsize: {error}"))?;
    Ok(value)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_memory_bytes() -> Result<u64, String> {
    Err("memory detection not implemented for this platform".to_string())
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
        .ok_or_else(|| format!("{key} not found"))?;
    let value = line[prefix.len()..]
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("{key} value not found"))?;
    value
        .parse::<u64>()
        .map_err(|error| format!("failed to parse {key}: {error}"))
}

#[cfg(target_os = "linux")]
fn probe_seccomp() -> Result<i32, String> {
    // SAFETY: `PR_GET_SECCOMP` is a read-only operation and does not modify process state.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode < 0 {
        return Err(io::Error::last_os_error().to_string());
    }

    Ok(mode)
}

#[cfg(target_os = "linux")]
fn probe_landlock_abi() -> Result<i32, String> {
    // SAFETY: With `LANDLOCK_CREATE_RULESET_VERSION`, this only probes the ABI version;
    // it does not create a ruleset or modify the current process security state.
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
        .map_err(|error| format!("failed to read THP status: {error}"))?;

    for token in content.split_whitespace() {
        if let Some(stripped) = token
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            return Ok(stripped.to_string());
        }
    }

    Err("failed to parse current THP mode".to_string())
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
        let app_home = resolve_app_home_dir(Some(home_dir.clone()))
            .expect("should generate default app directory");

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
        let bytes =
            parse_linux_memory_bytes(meminfo).expect("should successfully parse MemAvailable");

        assert_eq!(bytes, 16_384_000 * 1024);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn permission_string_from_mode_formats_unix_bits() {
        assert_eq!(permission_string_from_mode(0o660), "rw-rw----");
        assert_eq!(permission_string_from_mode(0o755), "rwxr-xr-x");
    }
}
