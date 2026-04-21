//! mimobox-sdk: 统一 Agent Sandbox API
//!
//! 默认智能路由，高级用户完全可控。零配置即可安全执行代码，
//! 同时暴露完整三层配置供精细控制。

mod config;
mod error;
mod router;

pub use config::{Config, ConfigBuilder, IsolationLevel, NetworkPolicy, TrustLevel};
pub use error::SdkError;

use mimobox_core::{Sandbox as CoreSandbox, SandboxResult};
use router::resolve_isolation;

/// 沙箱执行结果
pub struct ExecuteResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub elapsed: std::time::Duration,
}

impl From<SandboxResult> for ExecuteResult {
    fn from(r: SandboxResult) -> Self {
        Self {
            stdout: r.stdout,
            stderr: r.stderr,
            exit_code: r.exit_code,
            timed_out: r.timed_out,
            elapsed: r.elapsed,
        }
    }
}

/// 后端实例枚举
enum SandboxInner {
    #[cfg(all(feature = "os", target_os = "linux"))]
    Os(mimobox_os::LinuxSandbox),
    #[cfg(all(feature = "os", target_os = "macos"))]
    OsMac(mimobox_os::MacOsSandbox),
    #[cfg(feature = "wasm")]
    Wasm(mimobox_wasm::WasmSandbox),
}

/// 统一沙箱入口
///
/// 支持零配置默认（智能路由）和完整配置两种模式。
pub struct Sandbox {
    config: Config,
    inner: Option<SandboxInner>,
    active_isolation: Option<IsolationLevel>,
}

macro_rules! dispatch_execute {
    ($inner:expr, $binding:ident, $expr:expr) => {
        match $inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os($binding) => $expr,
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac($binding) => $expr,
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm($binding) => $expr,
        }
    };
}

impl Sandbox {
    /// 零配置创建沙箱，自动路由到最优隔离层级
    pub fn new() -> Result<Self, SdkError> {
        Self::with_config(Config::default())
    }

    /// 使用完整配置创建沙箱
    pub fn with_config(config: Config) -> Result<Self, SdkError> {
        Ok(Self {
            config,
            inner: None,
            active_isolation: None,
        })
    }

    /// 在沙箱中执行命令
    pub fn execute(&mut self, command: &str) -> Result<ExecuteResult, SdkError> {
        let args = parse_command(command)?;
        self.ensure_backend(command)?;
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| SdkError::CreateFailed("后端初始化后缺失实例".to_string()))?;
        let result = dispatch_execute!(inner, s, s.execute(&args))?;
        Ok(result.into())
    }

    /// 销毁沙箱，释放资源
    pub fn destroy(self) -> Result<(), SdkError> {
        match self.inner {
            Some(inner) => destroy_inner(inner),
            None => Ok(()),
        }
    }

    fn ensure_backend(&mut self, command: &str) -> Result<(), SdkError> {
        let isolation = resolve_isolation(&self.config, command)?;

        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            return Ok(());
        }

        if let Some(inner) = self.inner.take() {
            destroy_inner(inner)?;
        }

        self.inner = Some(create_inner(&self.config, isolation)?);
        self.active_isolation = Some(isolation);
        Ok(())
    }
}

fn create_inner(config: &Config, isolation: IsolationLevel) -> Result<SandboxInner, SdkError> {
    let sandbox_config = config.to_sandbox_config();

    match isolation {
        IsolationLevel::Os => {
            #[cfg(all(feature = "os", target_os = "linux"))]
            {
                Ok(SandboxInner::Os(mimobox_os::LinuxSandbox::new(
                    sandbox_config,
                )?))
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            {
                Ok(SandboxInner::OsMac(mimobox_os::MacOsSandbox::new(
                    sandbox_config,
                )?))
            }
            #[cfg(not(any(
                all(feature = "os", target_os = "linux"),
                all(feature = "os", target_os = "macos")
            )))]
            {
                Err(SdkError::BackendUnavailable("os"))
            }
        }
        IsolationLevel::Wasm => {
            #[cfg(feature = "wasm")]
            {
                Ok(SandboxInner::Wasm(mimobox_wasm::WasmSandbox::new(
                    sandbox_config,
                )?))
            }
            #[cfg(not(feature = "wasm"))]
            {
                Err(SdkError::BackendUnavailable("wasm"))
            }
        }
        IsolationLevel::Auto | IsolationLevel::MicroVm => {
            Err(SdkError::BackendUnavailable("请求的后端"))
        }
    }
}

fn destroy_inner(inner: SandboxInner) -> Result<(), SdkError> {
    let result = match inner {
        #[cfg(all(feature = "os", target_os = "linux"))]
        SandboxInner::Os(sandbox) => sandbox.destroy(),
        #[cfg(all(feature = "os", target_os = "macos"))]
        SandboxInner::OsMac(sandbox) => sandbox.destroy(),
        #[cfg(feature = "wasm")]
        SandboxInner::Wasm(sandbox) => sandbox.destroy(),
    };

    result.map_err(|err| SdkError::DestroyFailed(err.to_string()))
}

fn parse_command(command: &str) -> Result<Vec<String>, SdkError> {
    shlex::split(command)
        .ok_or_else(|| SdkError::Config("命令解析失败：shell 风格引号不匹配".to_string()))
}

#[cfg(test)]
fn inner_is_initialized(sandbox: &Sandbox) -> bool {
    sandbox.inner.is_some()
}

#[cfg(test)]
fn active_isolation(sandbox: &Sandbox) -> Option<IsolationLevel> {
    sandbox.active_isolation
}

#[cfg(test)]
#[cfg(feature = "wasm")]
fn has_os_backend(sandbox: &Sandbox) -> bool {
    match sandbox.inner.as_ref() {
        #[cfg(all(feature = "os", target_os = "linux"))]
        Some(SandboxInner::Os(_)) => true,
        #[cfg(all(feature = "os", target_os = "macos"))]
        Some(SandboxInner::OsMac(_)) => true,
        #[cfg(feature = "wasm")]
        Some(SandboxInner::Wasm(_)) => false,
        None => false,
    }
}

#[cfg(test)]
#[cfg(feature = "wasm")]
fn has_wasm_backend(sandbox: &Sandbox) -> bool {
    match sandbox.inner.as_ref() {
        #[cfg(feature = "wasm")]
        Some(SandboxInner::Wasm(_)) => true,
        #[cfg(all(feature = "os", target_os = "linux"))]
        Some(SandboxInner::Os(_)) => false,
        #[cfg(all(feature = "os", target_os = "macos"))]
        Some(SandboxInner::OsMac(_)) => false,
        None => false,
    }
}

#[cfg(test)]
fn parse_for_test(command: &str) -> Result<Vec<String>, SdkError> {
    parse_command(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_config_defers_backend_creation_until_first_execute() {
        let sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        assert!(!inner_is_initialized(&sandbox));
        assert_eq!(active_isolation(&sandbox), None);
    }

    #[test]
    fn invalid_shell_quoting_returns_sdk_error_instead_of_fallback_execution() {
        let result = parse_for_test("'unterminated");

        assert!(matches!(result, Err(SdkError::Config(_))));
    }

    #[cfg(all(
        feature = "os",
        feature = "wasm",
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    fn auto_routing_reinitializes_backend_for_wasm_commands() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");
        sandbox
            .ensure_backend("/bin/echo hello")
            .expect("初始化 OS 后端失败");
        assert!(has_os_backend(&sandbox));
        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Os));

        let script_path = std::path::PathBuf::from(format!(
            "/tmp/mimobox-sdk-auto-route-{}.wasm",
            std::process::id()
        ));
        std::fs::write(&script_path, "#!/bin/sh\necho routed-via-os\n").expect("写入测试脚本失败");
        make_executable(&script_path);

        let command = script_path.to_string_lossy().into_owned();
        sandbox
            .ensure_backend(&command)
            .expect("切换到 Wasm 后端失败");

        let _ = std::fs::remove_file(&script_path);

        assert!(has_wasm_backend(&sandbox));
        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Wasm));
    }

    #[cfg(all(feature = "wasm", unix))]
    fn make_executable(path: &std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).expect("读取测试脚本元数据失败");
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("设置测试脚本权限失败");
    }
}
