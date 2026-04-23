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
#[cfg(feature = "vm")]
use std::sync::Arc;
use tracing::warn;

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

trait ExecuteForSdk {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError>;
}

#[cfg(all(feature = "os", target_os = "linux"))]
impl ExecuteForSdk for mimobox_os::LinuxSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from)
    }
}

#[cfg(all(feature = "os", target_os = "macos"))]
impl ExecuteForSdk for mimobox_os::MacOsSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl ExecuteForSdk for mimobox_vm::MicrovmSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl ExecuteForSdk for mimobox_vm::PooledVm {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        let start = std::time::Instant::now();
        self.execute(args)
            .map(|result| ExecuteResult {
                stdout: result.stdout,
                stderr: result.stderr,
                exit_code: result.exit_code,
                timed_out: result.timed_out,
                elapsed: start.elapsed(),
            })
            .map_err(|error| SdkError::ExecutionFailed(error.to_string()))
    }
}

#[cfg(feature = "wasm")]
impl ExecuteForSdk for mimobox_wasm::WasmSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from)
    }
}

/// 后端实例枚举
enum SandboxInner {
    #[cfg(all(feature = "os", target_os = "linux"))]
    Os(mimobox_os::LinuxSandbox),
    #[cfg(all(feature = "os", target_os = "macos"))]
    OsMac(mimobox_os::MacOsSandbox),
    #[cfg(all(feature = "vm", target_os = "linux"))]
    MicroVm(mimobox_vm::MicrovmSandbox),
    #[cfg(all(feature = "vm", target_os = "linux"))]
    PooledMicroVm(mimobox_vm::PooledVm),
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
    #[cfg(feature = "vm")]
    vm_pool: Option<Arc<mimobox_vm::VmPool>>,
}

macro_rules! dispatch_execute {
    ($inner:expr, $binding:ident, $expr:expr) => {
        match $inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os($binding) => $expr,
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm($binding) => $expr,
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
    #[allow(unused_mut)]
    pub fn with_config(config: Config) -> Result<Self, SdkError> {
        let sandbox = Self::new_uninitialized(config);

        #[cfg(feature = "vm")]
        let mut sandbox = sandbox;

        #[cfg(feature = "vm")]
        {
            sandbox.vm_pool = initialize_default_vm_pool(&sandbox.config)?;
        }

        Ok(sandbox)
    }

    /// 使用显式 microVM 预热池配置创建沙箱。
    #[cfg(feature = "vm")]
    pub fn with_pool(
        config: Config,
        pool_config: mimobox_vm::VmPoolConfig,
    ) -> Result<Self, SdkError> {
        let mut sandbox = Self::new_uninitialized(config);
        let microvm_config = sandbox.config.to_microvm_config()?;
        let pool = mimobox_vm::VmPool::new(microvm_config, pool_config)
            .map_err(|error| SdkError::CreateFailed(error.to_string()))?;
        sandbox.vm_pool = Some(Arc::new(pool));
        Ok(sandbox)
    }

    /// 在沙箱中执行命令
    pub fn execute(&mut self, command: &str) -> Result<ExecuteResult, SdkError> {
        let args = parse_command(command)?;
        self.ensure_backend(command)?;
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| SdkError::CreateFailed("后端初始化后缺失实例".to_string()))?;
        dispatch_execute!(inner, s, s.execute_for_sdk(&args))
    }

    #[cfg(feature = "vm")]
    pub fn read_file(&mut self, _path: &str) -> Result<Vec<u8>, SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| SdkError::CreateFailed("后端初始化后缺失实例".to_string()))?;

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => sandbox
                .read_file(_path)
                .map_err(|error| SdkError::ExecutionFailed(error.to_string())),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => sandbox
                .read_file(_path)
                .map_err(|error| SdkError::ExecutionFailed(error.to_string())),
            _ => Err(SdkError::ExecutionFailed(
                "文件传输仅支持 microVM 后端".to_string(),
            )),
        }
    }

    #[cfg(feature = "vm")]
    pub fn write_file(&mut self, _path: &str, _data: &[u8]) -> Result<(), SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| SdkError::CreateFailed("后端初始化后缺失实例".to_string()))?;

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => sandbox
                .write_file(_path, _data)
                .map_err(|error| SdkError::ExecutionFailed(error.to_string())),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => sandbox
                .write_file(_path, _data)
                .map_err(|error| SdkError::ExecutionFailed(error.to_string())),
            _ => Err(SdkError::ExecutionFailed(
                "文件传输仅支持 microVM 后端".to_string(),
            )),
        }
    }

    /// 返回当前实例实际使用的隔离层级。
    ///
    /// 当 `execute()` 成功执行至少一次后，该值应为非 `None`，可用于上层查询
    /// Auto 路由后的真实后端。
    pub fn active_isolation(&self) -> Option<IsolationLevel> {
        self.active_isolation
    }

    /// 销毁沙箱，释放资源
    pub fn destroy(mut self) -> Result<(), SdkError> {
        self.destroy_inner()
    }

    fn ensure_backend(&mut self, command: &str) -> Result<(), SdkError> {
        let isolation = resolve_isolation(&self.config, command)?;

        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_inner()?;
        }

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        Ok(())
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
        let isolation = match self.config.isolation {
            IsolationLevel::Auto | IsolationLevel::MicroVm => IsolationLevel::MicroVm,
            IsolationLevel::Os | IsolationLevel::Wasm => {
                return Err(SdkError::ExecutionFailed(
                    "文件传输仅支持 microVM 后端".to_string(),
                ));
            }
        };

        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_inner()?;
        }

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        Ok(())
    }

    #[cfg(all(feature = "vm", not(target_os = "linux")))]
    fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
        Err(SdkError::BackendUnavailable("microvm"))
    }

    fn new_uninitialized(config: Config) -> Self {
        Self {
            config,
            inner: None,
            active_isolation: None,
            #[cfg(feature = "vm")]
            vm_pool: None,
        }
    }

    fn create_inner(&self, isolation: IsolationLevel) -> Result<SandboxInner, SdkError> {
        let sandbox_config = self.config.to_sandbox_config();

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
            IsolationLevel::MicroVm => {
                #[cfg(all(feature = "vm", target_os = "linux"))]
                {
                    if let Some(pool) = &self.vm_pool {
                        let pooled = pool
                            .acquire()
                            .map_err(|error| SdkError::CreateFailed(error.to_string()))?;
                        Ok(SandboxInner::PooledMicroVm(pooled))
                    } else {
                        let microvm_config = self.config.to_microvm_config()?;
                        let sandbox = mimobox_vm::MicrovmSandbox::new_with_base(
                            sandbox_config,
                            microvm_config,
                        )
                        .map_err(|error| SdkError::CreateFailed(error.to_string()))?;
                        Ok(SandboxInner::MicroVm(sandbox))
                    }
                }
                #[cfg(not(all(feature = "vm", target_os = "linux")))]
                {
                    Err(SdkError::BackendUnavailable("microvm"))
                }
            }
            IsolationLevel::Auto => Err(SdkError::BackendUnavailable("auto")),
        }
    }

    fn destroy_inner(&mut self) -> Result<(), SdkError> {
        let inner = self.inner.take();
        self.active_isolation = None;

        match inner {
            Some(inner) => destroy_backend_inner(inner),
            None => Ok(()),
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Err(error) = self.destroy_inner() {
            warn!(message = %error, "Sandbox drop 自动清理失败");
        }
    }
}

fn destroy_backend_inner(inner: SandboxInner) -> Result<(), SdkError> {
    match inner {
        #[cfg(all(feature = "os", target_os = "linux"))]
        SandboxInner::Os(sandbox) => sandbox
            .destroy()
            .map_err(|err| SdkError::DestroyFailed(err.to_string())),
        #[cfg(all(feature = "os", target_os = "macos"))]
        SandboxInner::OsMac(sandbox) => sandbox
            .destroy()
            .map_err(|err| SdkError::DestroyFailed(err.to_string())),
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::MicroVm(sandbox) => sandbox
            .destroy()
            .map_err(|err| SdkError::DestroyFailed(err.to_string())),
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::PooledMicroVm(pooled) => {
            drop(pooled);
            Ok(())
        }
        #[cfg(feature = "wasm")]
        SandboxInner::Wasm(sandbox) => sandbox
            .destroy()
            .map_err(|err| SdkError::DestroyFailed(err.to_string())),
    }
}

fn parse_command(command: &str) -> Result<Vec<String>, SdkError> {
    shlex::split(command)
        .ok_or_else(|| SdkError::Config("命令解析失败：shell 风格引号不匹配".to_string()))
}

#[cfg(feature = "vm")]
fn should_prepare_vm_pool(config: &Config) -> bool {
    matches!(resolve_isolation(config, ""), Ok(IsolationLevel::MicroVm))
}

#[cfg(feature = "vm")]
fn initialize_default_vm_pool(
    config: &Config,
) -> Result<Option<Arc<mimobox_vm::VmPool>>, SdkError> {
    if !should_prepare_vm_pool(config) {
        return Ok(None);
    }

    let microvm_config = config.to_microvm_config()?;
    let pool_config = mimobox_vm::VmPoolConfig {
        min_size: 1,
        max_size: 4,
        max_idle_duration: std::time::Duration::from_secs(60),
        health_check_interval: None,
    };

    match mimobox_vm::VmPool::new(microvm_config, pool_config) {
        Ok(pool) => Ok(Some(Arc::new(pool))),
        Err(error) => {
            tracing::warn!("初始化 microVM 预热池失败，回退到冷启动路径: {error}");
            Ok(None)
        }
    }
}

#[cfg(test)]
fn inner_is_initialized(sandbox: &Sandbox) -> bool {
    sandbox.inner.is_some()
}

#[cfg(test)]
fn active_isolation(sandbox: &Sandbox) -> Option<IsolationLevel> {
    sandbox.active_isolation
}

#[cfg(all(test, feature = "vm"))]
fn vm_pool_is_initialized(sandbox: &Sandbox) -> bool {
    sandbox.vm_pool.is_some()
}

#[cfg(test)]
#[cfg(feature = "wasm")]
fn has_os_backend(sandbox: &Sandbox) -> bool {
    match sandbox.inner.as_ref() {
        #[cfg(all(feature = "os", target_os = "linux"))]
        Some(SandboxInner::Os(_)) => true,
        #[cfg(all(feature = "os", target_os = "macos"))]
        Some(SandboxInner::OsMac(_)) => true,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::MicroVm(_)) => false,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::PooledMicroVm(_)) => false,
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
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::MicroVm(_)) => false,
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::PooledMicroVm(_)) => false,
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

    #[cfg(feature = "vm")]
    #[test]
    fn default_auto_config_does_not_prepare_vm_pool() {
        let sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        assert!(!vm_pool_is_initialized(&sandbox));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn explicit_microvm_config_marks_pool_as_eligible_on_supported_builds() {
        let config = Config::builder().isolation(IsolationLevel::MicroVm).build();

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert!(should_prepare_vm_pool(&config));

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(!should_prepare_vm_pool(&config));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn auto_untrusted_config_marks_pool_as_eligible_on_supported_builds() {
        let config = Config::builder().trust_level(TrustLevel::Untrusted).build();

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert!(should_prepare_vm_pool(&config));

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(!should_prepare_vm_pool(&config));
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
