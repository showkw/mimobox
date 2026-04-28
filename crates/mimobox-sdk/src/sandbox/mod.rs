#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

mod execute;
mod files;
mod http;
mod pty;
mod snapshot;

use crate::config::{Config, IsolationLevel, TrustLevel};
use crate::error::SdkError;
use crate::router::resolve_isolation;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::types::SandboxSnapshot;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::types::{RestorePool, RestorePoolConfig};
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::vm_helpers::map_microvm_error;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::vm_helpers::map_restore_pool_error;
use crate::vm_helpers::{destroy_backend_inner, parse_command};
#[cfg(feature = "vm")]
use crate::vm_helpers::{initialize_default_vm_pool, map_pool_error};
use mimobox_core::{ErrorCode, Sandbox as CoreSandbox, SandboxError};
use std::collections::HashMap;
#[cfg(feature = "vm")]
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Internal backend instance enum.
///
/// Each variant wraps a specific sandbox backend. The SDK dispatches
/// method calls to the active variant.
pub(crate) enum SandboxInner {
    #[cfg(all(feature = "os", target_os = "linux"))]
    Os(mimobox_os::LinuxSandbox),
    #[cfg(all(feature = "os", target_os = "macos"))]
    OsMac(mimobox_os::MacOsSandbox),
    #[cfg(all(feature = "vm", target_os = "linux"))]
    MicroVm(mimobox_vm::MicrovmSandbox),
    #[cfg(all(feature = "vm", target_os = "linux"))]
    PooledMicroVm(mimobox_vm::PooledVm),
    #[cfg(all(feature = "vm", target_os = "linux"))]
    RestoredPooledMicroVm(mimobox_vm::PooledRestoreVm),
    #[cfg(feature = "wasm")]
    Wasm(mimobox_wasm::WasmSandbox),
}

/// Primary entry point for all sandbox operations.
///
/// Supports zero-config creation with smart routing ([`Sandbox::new()`])
/// and full configuration via [`Sandbox::with_config()`].
///
/// The backend is initialized lazily on the first operation, not at construction time.
/// Subsequent operations reuse the same backend until the isolation level changes.
///
/// # Resource Cleanup
///
/// Call [`destroy()`](Sandbox::destroy) explicitly when done, or rely on the `Drop`
/// implementation which logs warnings on failure.
///
/// # Examples
///
/// ```rust,no_run
/// use mimobox_sdk::Sandbox;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sandbox = Sandbox::new()?;
/// let result = sandbox.execute("/bin/echo hello")?;
/// assert_eq!(result.exit_code, Some(0));
/// sandbox.destroy()?;
/// # Ok(())
/// # }
/// ```
pub struct Sandbox {
    pub(crate) config: Config,
    pub(crate) inner: Option<SandboxInner>,
    pub(crate) active_isolation: Option<IsolationLevel>,
    #[cfg(feature = "vm")]
    pub(crate) vm_pool: Option<Arc<mimobox_vm::VmPool>>,
}

// ── RestorePool ──

#[cfg(all(feature = "vm", target_os = "linux"))]
impl RestorePool {
    /// Creates a fixed-size restore pool from the base configuration.
    pub fn new(config: RestorePoolConfig) -> Result<Self, SdkError> {
        config.base_config.validate()?;

        let sandbox_config = config.base_config.to_sandbox_config();
        let microvm_config = config.base_config.to_microvm_config()?;
        let inner = mimobox_vm::RestorePool::new(
            sandbox_config,
            microvm_config,
            mimobox_vm::RestorePoolConfig {
                min_size: config.pool_size,
                max_size: config.pool_size,
            },
        )
        .map_err(map_restore_pool_error)?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Restores a new sandbox instance from the given snapshot.
    pub fn restore(&self, snapshot: &SandboxSnapshot) -> Result<Sandbox, SdkError> {
        let restored = self
            .inner
            .restore_snapshot(&snapshot.inner)
            .map_err(map_restore_pool_error)?;
        Ok(Sandbox::from_initialized_inner(
            SandboxInner::RestoredPooledMicroVm(restored),
            Config::builder()
                .isolation(IsolationLevel::MicroVm)
                .build()?,
        ))
    }

    /// Returns the number of idle instances currently in the restore pool.
    pub fn idle_count(&self) -> usize {
        self.inner.idle_count()
    }

    /// Warms the restore pool to at least `target` idle instances.
    pub fn warm(&self, target: usize) -> Result<(), SdkError> {
        self.inner.warm(target).map_err(map_restore_pool_error)
    }
}

/// Dispatch macro for the three VM-only variants (`MicroVm`, `PooledMicroVm`,
/// `RestoredPooledMicroVm`). Non-VM variants uniformly use the fallback expression.
#[cfg(feature = "vm")]
macro_rules! dispatch_vm {
    ($inner:expr, $binding:ident, $expr:expr, $fallback:expr) => {
        match $inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm($binding) => $expr,
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm($binding) => $expr,
            _ => $fallback,
        }
    };
}
#[cfg(feature = "vm")]
pub(crate) use dispatch_vm;

// ── SdkExecOptions + 辅助函数 ──

#[derive(Debug, Clone, Default)]
pub(crate) struct SdkExecOptions {
    pub(crate) env: HashMap<String, String>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) cwd: Option<String>,
}

#[cfg(feature = "vm")]
impl From<mimobox_vm::GuestExecOptions> for SdkExecOptions {
    fn from(options: mimobox_vm::GuestExecOptions) -> Self {
        Self {
            env: options.env,
            timeout: options.timeout,
            cwd: options.cwd,
        }
    }
}

impl SdkExecOptions {
    #[cfg(all(feature = "vm", target_os = "linux"))]
    pub(crate) fn to_guest_exec_options(&self) -> mimobox_vm::GuestExecOptions {
        mimobox_vm::GuestExecOptions {
            env: self.env.clone(),
            timeout: self.timeout,
            cwd: self.cwd.clone(),
        }
    }
}

fn build_fallback_command_args(
    command: &str,
    options: &SdkExecOptions,
) -> Result<Vec<String>, SdkError> {
    // OS/Wasm 后端的超时来自 SandboxConfig；per-command timeout 仅 VM 后端支持。
    if options.timeout.is_some() {
        tracing::warn!(
            "per-command timeout is not supported by OS/Wasm backends;              using sandbox config timeout instead"
        );
    }
    let _ = options.timeout;

    if let Some(cwd) = options.cwd.as_deref() {
        let cwd = shlex::try_quote(cwd).map_err(|_| {
            SdkError::Config("cwd contains characters that cannot be shell-escaped".to_string())
        })?;
        let env_prefix = build_shell_env_prefix(&options.env)?;
        return Ok(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("cd {cwd} && exec {env_prefix}{command}"),
        ]);
    }

    let args = parse_command(command)?;
    if options.env.is_empty() {
        return Ok(args);
    }

    let mut prefixed = Vec::with_capacity(args.len() + options.env.len() + 1);
    prefixed.push("/usr/bin/env".to_string());
    prefixed.extend(build_env_assignments(&options.env)?);
    prefixed.extend(args);
    Ok(prefixed)
}

fn build_shell_env_prefix(env: &HashMap<String, String>) -> Result<String, SdkError> {
    if env.is_empty() {
        return Ok(String::new());
    }

    let mut parts = Vec::with_capacity(env.len() + 1);
    parts.push("/usr/bin/env".to_string());
    for assignment in build_env_assignments(env)? {
        let quoted = shlex::try_quote(&assignment).map_err(|_| {
            SdkError::Config(
                "environment assignment contains characters that cannot be shell-escaped"
                    .to_string(),
            )
        })?;
        parts.push(quoted.into_owned());
    }
    parts.push(String::new());
    Ok(parts.join(" "))
}

fn build_env_assignments(env: &HashMap<String, String>) -> Result<Vec<String>, SdkError> {
    let mut assignments = Vec::with_capacity(env.len());
    for (key, value) in env {
        validate_env_key(key)?;
        if value.contains('\0') {
            return Err(SdkError::Config(format!(
                "environment variable `{key}` contains NUL byte"
            )));
        }
        assignments.push(format!("{key}={value}"));
    }
    Ok(assignments)
}

fn validate_env_key(key: &str) -> Result<(), SdkError> {
    if key.is_empty() || key.contains('=') || key.contains('\0') {
        return Err(SdkError::Config(format!(
            "invalid environment variable name: `{key}`"
        )));
    }
    Ok(())
}

pub(crate) fn validate_cwd(cwd: &str) -> Result<(), SdkError> {
    use std::path::Component;
    if std::path::Path::new(cwd)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(SdkError::Config(
            "invalid cwd: 包含路径遍历符 '..'".to_string(),
        ));
    }

    if cwd.contains(';') || cwd.contains('|') || cwd.contains('&') {
        return Err(SdkError::Config(
            "invalid cwd: 包含 shell 元字符".to_string(),
        ));
    }

    if cwd.contains('\n') || cwd.contains('\r') {
        return Err(SdkError::Config("invalid cwd: 包含换行符".to_string()));
    }

    Ok(())
}

// ── 文件错误映射辅助函数 ──

pub(crate) fn map_core_file_error(error: SandboxError) -> SdkError {
    match error {
        SandboxError::Io(io_err) => SdkError::Io(io_err),
        other => SdkError::from_sandbox_execute_error(other),
    }
}

pub(crate) fn read_file_via_core(
    sandbox: &mut impl CoreSandbox,
    path: &str,
) -> Result<Vec<u8>, SandboxError> {
    CoreSandbox::read_file(sandbox, path)
}

pub(crate) fn write_file_via_core(
    sandbox: &mut impl CoreSandbox,
    path: &str,
    data: &[u8],
) -> Result<(), SandboxError> {
    CoreSandbox::write_file(sandbox, path, data)
}

pub(crate) fn os_file_operation_unsupported(operation: &str, suggestion: &'static str) -> SdkError {
    SdkError::sandbox(
        ErrorCode::UnsupportedPlatform,
        format!(
            "OS backend does not support {operation}: file operations bypass sandbox isolation"
        ),
        Some(suggestion.to_string()),
    )
}

pub(crate) fn map_os_core_file_error(
    operation: &str,
    unsupported_message: &str,
    error: SandboxError,
) -> SdkError {
    match error {
        SandboxError::ExecutionFailed(message) if message == unsupported_message => {
            os_file_operation_unsupported(
                operation,
                "Use microVM backend for isolated file operations, or execute commands inside the sandbox to access files",
            )
        }
        other => map_core_file_error(other),
    }
}

/// Re-export of `map_microvm_error` for sub-modules.
#[cfg(all(feature = "vm", target_os = "linux"))]
pub(crate) fn map_microvm_error(e: mimobox_vm::MicrovmError) -> SdkError {
    crate::vm_helpers::map_microvm_error(e)
}
// ── Sandbox 生命周期方法 ──

impl Sandbox {
    /// Creates a sandbox with default configuration.
    ///
    /// Smart routing automatically selects the optimal isolation level based on
    /// each command and the default `TrustLevel::SemiTrusted`.
    ///
    /// # Errors
    ///
    /// Returns `SdkError::BackendUnavailable` if no backend feature is enabled.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::Sandbox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let result = sandbox.execute("/bin/echo hello")?;
    /// assert_eq!(result.exit_code, Some(0));
    /// sandbox.destroy()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self, SdkError> {
        Self::with_config(Config::default())
    }

    /// Creates a sandbox with explicit configuration.
    ///
    /// Use [`Config::builder()`] to construct a `Config` with the builder pattern.
    ///
    /// # Errors
    ///
    /// Returns `SdkError::BackendUnavailable` if the configured isolation level
    /// requires a backend feature that is not enabled.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{Config, IsolationLevel, Sandbox};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::builder()
    ///     .isolation(IsolationLevel::Os)
    ///     .timeout(std::time::Duration::from_secs(10))
    ///     .build()?;
    /// let mut sandbox = Sandbox::with_config(config)?;
    /// # Ok(())
    /// # }
    /// ```
    #[allow(unused_mut)]
    pub fn with_config(config: Config) -> Result<Self, SdkError> {
        config.validate()?;

        let sandbox = Self::new_uninitialized(config);

        #[cfg(feature = "vm")]
        let mut sandbox = sandbox;

        #[cfg(feature = "vm")]
        {
            sandbox.vm_pool = initialize_default_vm_pool(&sandbox.config)?;
        }

        Ok(sandbox)
    }

    /// Creates a sandbox with an explicit microVM warm pool configuration.
    ///
    /// The pool pre-creates VM instances for sub-millisecond acquisition.
    /// Requires `vm` feature.
    ///
    /// # Errors
    ///
    /// Returns `SdkError::Sandbox` if the pool cannot be initialized.
    #[cfg(feature = "vm")]
    pub fn with_pool(
        config: Config,
        pool_config: mimobox_vm::VmPoolConfig,
    ) -> Result<Self, SdkError> {
        config.validate()?;

        let mut sandbox = Self::new_uninitialized(config);
        let sandbox_config = sandbox.config.to_sandbox_config();
        let microvm_config = sandbox.config.to_microvm_config()?;
        let pool = mimobox_vm::VmPool::new_with_base(sandbox_config, microvm_config, pool_config)
            .map_err(map_pool_error)?;
        sandbox.vm_pool = Some(Arc::new(pool));
        Ok(sandbox)
    }

    /// Returns the isolation level of the currently active backend.
    ///
    /// Returns `None` before the first operation triggers backend initialization.
    /// Useful for querying the result of `Auto` routing after the first execute.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{IsolationLevel, Sandbox};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// assert_eq!(sandbox.active_isolation(), None);
    /// sandbox.execute("/bin/echo hello")?;
    /// assert!(sandbox.active_isolation().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn active_isolation(&self) -> Option<IsolationLevel> {
        self.active_isolation
    }

    /// Waits for the current sandbox backend to become ready.
    ///
    /// For microVM backends, runs a PING/PONG readiness probe; OS/Wasm backends
    /// are considered ready after initialization.
    pub fn wait_ready(&mut self, timeout: std::time::Duration) -> Result<(), SdkError> {
        if timeout.is_zero() {
            return Err(SdkError::Config(
                "wait_ready timeout must not be zero".to_string(),
            ));
        }

        let isolation = match self.config.isolation {
            IsolationLevel::Auto => {
                if self.config.trust_level == TrustLevel::Untrusted {
                    // Auto 模式不能把 Untrusted 探测初始化降级到 OS；
                    // microVM 不可用时必须 fail-closed，而不是创建较弱后端。
                    #[cfg(all(feature = "vm", target_os = "linux"))]
                    {
                        IsolationLevel::MicroVm
                    }
                    #[cfg(not(all(feature = "vm", target_os = "linux")))]
                    {
                        return Err(SdkError::sandbox(
                            ErrorCode::UnsupportedPlatform,
                            "Untrusted requires microVM backend",
                            Some("Use IsolationLevel::Os as alternative".to_string()),
                        ));
                    }
                } else {
                    IsolationLevel::Os
                }
            }
            other => other,
        };
        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            return self.wait_ready_inner(timeout);
        }

        if self.inner.is_some() {
            self.destroy_inner()?;
        }
        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        self.wait_ready_inner(timeout)
    }

    /// Returns whether the current SDK sandbox has been initialized with a usable backend.
    pub fn is_ready(&self) -> bool {
        let Some(inner) = self.inner.as_ref() else {
            return false;
        };

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => sandbox.is_ready(),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(_) | SandboxInner::RestoredPooledMicroVm(_) => true,
            _ => true,
        }
    }

    /// Destroys the sandbox and releases all resources.
    ///
    /// If not called explicitly, the `Drop` implementation will attempt
    /// cleanup automatically with warnings logged on failure.
    ///
    /// # Errors
    ///
    /// Returns `SdkError` if the backend fails to clean up resources.
    pub fn destroy(mut self) -> Result<(), SdkError> {
        self.destroy_inner()
    }

    // ── 私有辅助方法 ──

    /// Returns the initialized backend instance, or a unified error if it is missing.
    pub(crate) fn require_inner(&mut self) -> Result<&mut SandboxInner, SdkError> {
        self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "backend instance missing after initialization",
                Some("check if sandbox initialization was interrupted".to_string()),
            )
        })
    }

    pub(crate) fn ensure_backend(&mut self, command: &str) -> Result<(), SdkError> {
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

    fn wait_ready_inner(&mut self, timeout: std::time::Duration) -> Result<(), SdkError> {
        let _ = timeout;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
                sandbox.wait_ready(timeout).map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => {
                sandbox.ping().map(|_| ()).map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => {
                sandbox.ping().map(|_| ()).map_err(map_microvm_error)
            }
            _ => Ok(()),
        }
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    pub(crate) fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
        let isolation = match self.config.isolation {
            IsolationLevel::Auto | IsolationLevel::MicroVm => IsolationLevel::MicroVm,
            IsolationLevel::Os | IsolationLevel::Wasm => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "file transfer only supports microVM backend",
                    Some("set isolation to `MicroVm`".to_string()),
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

    #[cfg(all(feature = "vm", target_os = "linux"))]
    pub(crate) fn ensure_backend_for_snapshot(&mut self) -> Result<(), SdkError> {
        if self.inner.is_some() {
            return match self.active_isolation {
                Some(IsolationLevel::MicroVm) => Ok(()),
                Some(_) => Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "current sandbox backend does not support snapshot",
                    Some("set isolation to `MicroVm` and recreate sandbox".to_string()),
                )),
                None => Err(SdkError::sandbox(
                    ErrorCode::SandboxCreateFailed,
                    "sandbox backend instance exists but isolation level not recorded",
                    Some("check if sandbox initialization was interrupted".to_string()),
                )),
            };
        }

        let isolation = match self.config.isolation {
            IsolationLevel::Auto | IsolationLevel::MicroVm => IsolationLevel::MicroVm,
            IsolationLevel::Os | IsolationLevel::Wasm => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "configured backend does not support snapshot",
                    Some("set isolation to `MicroVm`".to_string()),
                ));
            }
        };

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        Ok(())
    }

    #[cfg(all(feature = "vm", not(target_os = "linux")))]
    pub(crate) fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
        Err(SdkError::unsupported_backend("microvm"))
    }

    pub(crate) fn ensure_backend_for_pty(&mut self) -> Result<(), SdkError> {
        let isolation = match self.config.isolation {
            IsolationLevel::Auto => {
                if self.config.trust_level == TrustLevel::Untrusted {
                    // PTY 目前依赖 OS 级后端；Untrusted 不能静默降级到 OS，
                    // 而 microVM 暂不支持 PTY，因此这里直接拒绝以保持 fail-closed。
                    return Err(SdkError::sandbox(
                        ErrorCode::UnsupportedPlatform,
                        "PTY sessions require OS-level backend, which is not allowed for Untrusted code",
                        Some("Use TrustLevel::SemiTrusted or Trusted for PTY access".to_string()),
                    ));
                }
                IsolationLevel::Os
            }
            other => other,
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

    fn new_uninitialized(config: Config) -> Self {
        Self {
            config,
            inner: None,
            active_isolation: None,
            #[cfg(feature = "vm")]
            vm_pool: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_initialized_inner(inner: SandboxInner, config: Config) -> Self {
        Self {
            config,
            inner: Some(inner),
            active_isolation: Some(IsolationLevel::MicroVm),
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
                    mimobox_os::LinuxSandbox::new(sandbox_config)
                        .map(SandboxInner::Os)
                        .map_err(SdkError::from_sandbox_create_error)
                }
                #[cfg(all(feature = "os", target_os = "macos"))]
                {
                    mimobox_os::MacOsSandbox::new(sandbox_config)
                        .map(SandboxInner::OsMac)
                        .map_err(SdkError::from_sandbox_create_error)
                }
                #[cfg(not(any(
                    all(feature = "os", target_os = "linux"),
                    all(feature = "os", target_os = "macos")
                )))]
                {
                    Err(SdkError::unsupported_backend("os"))
                }
            }
            IsolationLevel::Wasm => {
                #[cfg(feature = "wasm")]
                {
                    mimobox_wasm::WasmSandbox::new(sandbox_config)
                        .map(SandboxInner::Wasm)
                        .map_err(SdkError::from_sandbox_create_error)
                }
                #[cfg(not(feature = "wasm"))]
                {
                    Err(SdkError::unsupported_backend("wasm"))
                }
            }
            IsolationLevel::MicroVm => {
                #[cfg(all(feature = "vm", target_os = "linux"))]
                {
                    if let Some(pool) = &self.vm_pool {
                        let pooled = pool.acquire().map_err(map_pool_error)?;
                        Ok(SandboxInner::PooledMicroVm(pooled))
                    } else {
                        let microvm_config = self.config.to_microvm_config()?;
                        let sandbox = mimobox_vm::MicrovmSandbox::new_with_base(
                            sandbox_config,
                            microvm_config,
                        )
                        .map_err(map_microvm_error)?;
                        Ok(SandboxInner::MicroVm(sandbox))
                    }
                }
                #[cfg(not(all(feature = "vm", target_os = "linux")))]
                {
                    Err(SdkError::unsupported_backend("microvm"))
                }
            }
            IsolationLevel::Auto => Err(SdkError::unsupported_backend("auto")),
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
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            match self.destroy_inner() {
                Ok(()) => return,
                Err(error) if attempt < MAX_ATTEMPTS - 1 => {
                    warn!(
                        attempt = attempt + 1,
                        error = %error,
                        "Sandbox drop 自动清理失败，重试中"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(
                        100 * u64::from(attempt + 1),
                    ));
                }
                Err(error) => {
                    tracing::error!(
                        attempts = MAX_ATTEMPTS,
                        error = %error,
                        "Sandbox drop 自动清理在多次重试后仍然失败"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "vm")]
    use crate::TrustLevel;
    use crate::types::StreamEvent;
    #[cfg(feature = "vm")]
    use crate::vm_helpers::should_prepare_vm_pool;

    fn inner_is_initialized(sandbox: &Sandbox) -> bool {
        sandbox.inner.is_some()
    }

    fn active_isolation(sandbox: &Sandbox) -> Option<IsolationLevel> {
        sandbox.active_isolation
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    fn assert_os_file_operation_unsupported<T>(
        result: Result<T, SdkError>,
        operation: &str,
        expected_suggestion: &str,
    ) {
        match result {
            Err(SdkError::Sandbox {
                code,
                message,
                suggestion,
            }) => {
                assert_eq!(code, ErrorCode::UnsupportedPlatform);
                assert_eq!(
                    message,
                    format!(
                        "OS backend does not support {operation}: file operations bypass sandbox isolation"
                    )
                );
                assert_eq!(suggestion.as_deref(), Some(expected_suggestion));
            }
            Err(other) => panic!("期望 OS 文件 API 返回 UnsupportedPlatform，实际为: {other}"),
            Ok(_) => panic!("期望 OS 文件 API 被拒绝，实际却成功"),
        }
    }

    #[cfg(all(feature = "os", target_os = "linux"))]
    fn should_skip_os_runtime_tests() -> bool {
        false
    }

    #[cfg(all(feature = "os", target_os = "macos"))]
    fn should_skip_os_runtime_tests() -> bool {
        let Some(reason) = seatbelt_runtime_skip_reason() else {
            return false;
        };

        eprintln!("跳过 SDK macOS Seatbelt 运行时测试: {reason}");
        true
    }

    #[cfg(all(feature = "os", target_os = "macos"))]
    fn seatbelt_runtime_skip_reason() -> Option<&'static str> {
        static SKIP_REASON: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

        SKIP_REASON
            .get_or_init(|| {
                let output = match std::process::Command::new("sandbox-exec")
                    .args(["-p", "(version 1) (allow default)", "/usr/bin/true"])
                    .output()
                {
                    Ok(output) => output,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Some("sandbox-exec not found in current environment".to_string());
                    }
                    Err(error) => {
                        panic!("执行 sandbox-exec 最小探测失败: {error}");
                    }
                };

                if output.status.success() {
                    return None;
                }

                Some(format!(
                    "sandbox-exec unavailable: status={:?}, stderr={}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                ))
            })
            .as_deref()
    }

    #[cfg(feature = "vm")]
    fn vm_pool_is_initialized(sandbox: &Sandbox) -> bool {
        sandbox.vm_pool.is_some()
    }

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
            #[cfg(all(feature = "vm", target_os = "linux"))]
            Some(SandboxInner::RestoredPooledMicroVm(_)) => false,
            #[cfg(feature = "wasm")]
            Some(SandboxInner::Wasm(_)) => false,
            None => false,
        }
    }

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
            #[cfg(all(feature = "vm", target_os = "linux"))]
            Some(SandboxInner::RestoredPooledMicroVm(_)) => false,
            None => false,
        }
    }

    #[test]
    fn with_config_defers_backend_creation_until_first_execute() {
        let sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        assert!(!inner_is_initialized(&sandbox));
        assert_eq!(active_isolation(&sandbox), None);
    }

    #[test]
    fn with_config_rejects_invalid_config_before_backend_creation() {
        let config = Config {
            memory_limit_mb: Some(0),
            ..Config::default()
        };

        let result = Sandbox::with_config(config);

        assert!(matches!(result, Err(SdkError::Config(_))));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn with_pool_rejects_invalid_config_before_backend_creation() {
        let config = Config {
            vm_vcpu_count: 0,
            ..Config::default()
        };

        let result = Sandbox::with_pool(config, mimobox_vm::VmPoolConfig::default());

        assert!(matches!(result, Err(SdkError::Config(_))));
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
        let config = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .build()
            .expect("配置校验失败");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert!(should_prepare_vm_pool(&config));

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(!should_prepare_vm_pool(&config));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn auto_untrusted_config_marks_pool_as_eligible_on_supported_builds() {
        let config = Config::builder()
            .trust_level(TrustLevel::Untrusted)
            .build()
            .expect("配置校验失败");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert!(should_prepare_vm_pool(&config));

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(!should_prepare_vm_pool(&config));
    }

    #[test]
    fn destroy_uninitialized_sandbox_succeeds() {
        let sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        let result = sandbox.destroy();

        assert!(result.is_ok(), "销毁未初始化沙箱应成功: {:?}", result);
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    #[test]
    fn wait_ready_untrusted_fails_without_vm() {
        let config = Config::builder()
            .trust_level(TrustLevel::Untrusted)
            .build()
            .expect("配置校验失败");
        let mut sandbox = Sandbox::with_config(config).expect("创建沙箱失败");

        let result = sandbox.wait_ready(Duration::from_millis(1));

        match result {
            Err(SdkError::Sandbox {
                code,
                message,
                suggestion,
            }) => {
                assert_eq!(code, ErrorCode::UnsupportedPlatform);
                assert_eq!(message, "Untrusted requires microVM backend");
                assert_eq!(
                    suggestion.as_deref(),
                    Some("Use IsolationLevel::Os as alternative")
                );
            }
            other => {
                panic!("期望 Untrusted wait_ready 在无 microVM 时 fail-closed，实际为: {other:?}")
            }
        }
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn destroy_then_drop_does_not_panic() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");
        // 先执行一次命令，确保后端完成懒初始化。
        sandbox.execute("/bin/echo hello").expect("执行命令失败");
        assert!(inner_is_initialized(&sandbox));

        let destroyed = Sandbox::with_config(Config::default())
            .expect("创建沙箱失败")
            .destroy();

        assert!(destroyed.is_ok(), "destroy 应成功: {:?}", destroyed);
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn drop_after_partial_initialization_does_not_panic() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let result = std::panic::catch_unwind(|| {
            let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");
            sandbox.execute("/bin/echo test").expect("执行命令失败");
            // 不主动 destroy，验证 Drop 自动清理路径不会 panic。
            drop(sandbox);
        });

        assert!(result.is_ok(), "Drop 自动清理不应 panic");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn concurrent_execute_via_mutex_does_not_panic() {
        use std::sync::{Arc, Mutex};

        if should_skip_os_runtime_tests() {
            return;
        }

        let sandbox = Arc::new(Mutex::new(
            Sandbox::with_config(Config::default()).expect("创建沙箱失败"),
        ));
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let sandbox = Arc::clone(&sandbox);
                std::thread::spawn(move || {
                    let mut sandbox = sandbox.lock().expect("Mutex 不应 poisoned");
                    let result = sandbox
                        .execute(&format!("/bin/echo thread-{i}"))
                        .expect("并发 execute 不应失败");
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    assert!(
                        stdout.contains(&format!("thread-{i}")),
                        "线程 {i} stdout 应包含标识，实际: {stdout}"
                    );
                    assert_eq!(result.exit_code, Some(0), "退出码应为 0");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("线程不应 panic");
        }

        let sandbox = match Arc::try_unwrap(sandbox) {
            Ok(sandbox) => sandbox,
            Err(_) => panic!("所有引用应已释放"),
        };
        sandbox
            .into_inner()
            .expect("Mutex 不应 poisoned")
            .destroy()
            .expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn create_pty_auto_routes_to_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");
        let mut session = sandbox
            .create_pty("/bin/echo ready")
            .expect("创建 PTY 会话失败");

        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Os));
        assert_eq!(session.wait().expect("等待 PTY 退出失败"), 0);

        drop(session);
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[test]
    fn create_pty_auto_untrusted_fails_closed() {
        let config = Config::builder()
            .trust_level(TrustLevel::Untrusted)
            .build()
            .expect("配置校验失败");
        let mut sandbox = Sandbox::with_config(config).expect("创建沙箱失败");

        let result = sandbox.create_pty("/bin/sh");

        match result {
            Err(SdkError::Sandbox {
                code,
                message,
                suggestion,
            }) => {
                assert_eq!(code, ErrorCode::UnsupportedPlatform);
                assert_eq!(
                    message,
                    "PTY sessions require OS-level backend, which is not allowed for Untrusted code"
                );
                assert_eq!(
                    suggestion.as_deref(),
                    Some("Use TrustLevel::SemiTrusted or Trusted for PTY access")
                );
            }
            other => panic!("期望 Untrusted + Auto + PTY fail-closed，实际为: {other:?}"),
        }
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_returns_unsupported_on_os_backend() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        let result = sandbox.list_dir("/tmp");

        assert_os_file_operation_unsupported(
            result,
            "list_dir",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_nonexistent_returns_error() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        let result = sandbox.list_dir("/nonexistent/path");

        assert_os_file_operation_unsupported(
            result,
            "list_dir",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_file_path_returns_error() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let file_path = temp_dir.path().join("not-a-directory.txt");
        std::fs::write(&file_path, "test").expect("写入测试文件失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let result = sandbox.list_dir(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "list_dir",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_empty_directory_returns_empty() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let result = sandbox.list_dir(&temp_dir.path().to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "list_dir",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_file_exists_returns_unsupported_on_os_backend() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let file_path = temp_dir.path().join("exists.txt");
        std::fs::write(&file_path, "test").expect("写入测试文件失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let result = sandbox.file_exists(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "file_exists",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_remove_file_removes_file() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let file_path = temp_dir.path().join("remove.txt");
        std::fs::write(&file_path, "test").expect("写入测试文件失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let result = sandbox.remove_file(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "remove_file",
            "Use microVM backend for isolated file operations",
        );
        assert!(
            file_path.exists(),
            "remove_file 被拒绝后测试文件应继续存在: {}",
            file_path.display()
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_rename_moves_file() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let source_path = temp_dir.path().join("source.txt");
        let target_path = temp_dir.path().join("target.txt");
        std::fs::write(&source_path, "test").expect("写入测试文件失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let result = sandbox.rename(
            &source_path.to_string_lossy(),
            &target_path.to_string_lossy(),
        );

        assert_os_file_operation_unsupported(
            result,
            "rename",
            "Use microVM backend for isolated file operations",
        );
        assert!(source_path.exists(), "rename 被拒绝后源文件应继续存在");
        assert!(!target_path.exists(), "rename 被拒绝后目标文件不应存在");
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_stat_returns_file_metadata() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let file_path = temp_dir.path().join("stat.txt");
        std::fs::write(&file_path, "stat").expect("写入测试文件失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let result = sandbox.stat(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "stat",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_read_write_file_roundtrip_on_os_backend() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let file_path = temp_dir.path().join("roundtrip.txt");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let write_result = sandbox.write_file(&file_path.to_string_lossy(), b"sdk-roundtrip");
        let read_result = sandbox.read_file(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            write_result,
            "write_file",
            "Use microVM backend for isolated file operations, or execute commands inside the sandbox to access files",
        );
        assert_os_file_operation_unsupported(
            read_result,
            "read_file",
            "Use microVM backend for isolated file operations, or execute commands inside the sandbox to access files",
        );
        assert!(
            !file_path.exists(),
            "write_file 被拒绝后不应在宿主文件系统创建文件"
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_execute_with_env_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::new().expect("创建沙箱失败");
        let mut env = HashMap::new();
        env.insert("MIMOBOX_SDK_ENV_TEST".to_string(), "works".to_string());

        let result = sandbox
            .execute_with_env("/usr/bin/env", env)
            .expect("execute_with_env 应成功");
        let stdout = String::from_utf8_lossy(&result.stdout);

        assert!(
            stdout.contains("MIMOBOX_SDK_ENV_TEST=works"),
            "stdout 应包含注入的环境变量，实际: {stdout}"
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_execute_with_timeout_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let result = sandbox
            .execute_with_timeout("/bin/echo sdk-timeout", Duration::from_secs(5))
            .expect("execute_with_timeout 应成功");

        assert_eq!(result.exit_code, Some(0));
        assert!(String::from_utf8_lossy(&result.stdout).contains("sdk-timeout"));
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_execute_with_cwd_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let temp_dir = tempfile::TempDir::new_in("/tmp").expect("创建临时目录失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let result = sandbox
            .execute_with_cwd("/bin/pwd", &temp_dir.path().to_string_lossy())
            .expect("execute_with_cwd 应成功");
        let stdout = String::from_utf8_lossy(&result.stdout);

        assert!(
            stdout.contains(temp_dir.path().to_string_lossy().as_ref()),
            "stdout 应包含 cwd，实际: {stdout}"
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_stream_execute_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let receiver = sandbox
            .stream_execute("/bin/echo sdk-stream")
            .expect("stream_execute 应成功");
        let events: Vec<_> = receiver.iter().collect();

        assert!(
            events.iter().any(|event| matches!(
                event,
                StreamEvent::Stdout(data)
                    if String::from_utf8_lossy(data).contains("sdk-stream")
            )),
            "stream_execute 应返回 stdout 事件: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, StreamEvent::Exit(0))),
            "stream_execute 应返回 Exit(0) 事件: {events:?}"
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_file_api_rejects_path_traversal() {
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        assert_os_file_operation_unsupported(
            sandbox.file_exists("/../etc/passwd"),
            "file_exists",
            "Use microVM backend for isolated file operations",
        );
        assert_os_file_operation_unsupported(
            sandbox.remove_file("/tmp/../etc/passwd"),
            "remove_file",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    #[test]
    fn create_pty_microvm_is_rejected() {
        let config = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .build()
            .expect("配置校验失败");
        let mut sandbox = Sandbox::with_config(config).expect("创建沙箱失败");

        let result = sandbox.create_pty("/bin/sh");

        match result {
            Err(SdkError::BackendUnavailable("microvm")) => {}
            Err(other) => panic!("期望 microVM 后端不可用，实际为: {other}"),
            Ok(_) => panic!("期望 PTY 在 microVM 配置下被拒绝，实际却创建成功"),
        }
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    #[test]
    fn create_pty_microvm_maps_unsupported_operation_on_supported_vm_build() {
        let Ok(microvm_config) = mimobox_vm::microvm_config_from_vm_assets(256) else {
            return;
        };
        let config = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .vm_memory_mb(microvm_config.memory_mb)
            .kernel_path(microvm_config.kernel_path.clone())
            .rootfs_path(microvm_config.rootfs_path.clone())
            .build()
            .expect("配置校验失败");
        let mut microvm = mimobox_vm::MicrovmSandbox::new_with_base(
            mimobox_core::SandboxConfig::default(),
            microvm_config,
        )
        .expect("创建 microVM 沙箱必须成功");
        let pty_config = PtyConfig {
            command: vec!["/bin/sh".to_string()],
            size: PtySize::default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: config.timeout,
        };

        match CoreSandbox::create_pty(&mut microvm, pty_config) {
            Err(mimobox_core::SandboxError::UnsupportedOperation(message)) => {
                assert!(message.contains("microVM"));
            }
            Err(other) => panic!("期望 microVM PTY 返回 UnsupportedOperation，实际为: {other}"),
            Ok(_) => panic!("期望 microVM PTY 被拒绝，实际却创建成功"),
        }

        let mut sandbox = Sandbox::from_initialized_inner(SandboxInner::MicroVm(microvm), config);
        let result = sandbox.create_pty("/bin/sh");

        match result {
            Err(SdkError::Sandbox { code, message, .. }) => {
                assert_eq!(code, ErrorCode::UnsupportedPlatform);
                assert!(message.contains("microVM"));
            }
            Err(other) => panic!(
                "期望 SDK 将 UnsupportedOperation 映射为 UnsupportedPlatform，实际为: {other}"
            ),
            Ok(_) => panic!("期望 SDK PTY 在 microVM 下被拒绝，实际却创建成功"),
        }

        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    #[test]
    fn file_ops_work_for_pooled_vm_backends() {
        let Ok(microvm_config) = mimobox_vm::microvm_config_from_vm_assets(256) else {
            return;
        };
        let config = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .vm_memory_mb(microvm_config.memory_mb)
            .kernel_path(microvm_config.kernel_path.clone())
            .rootfs_path(microvm_config.rootfs_path.clone())
            .build()
            .expect("配置校验失败");
        let mut sandbox = Sandbox::with_config(config).expect("创建 pooled VM 沙箱失败");
        let source_path = "/sandbox/sdk-file-api.txt";
        let target_path = "/sandbox/sdk-file-api-renamed.txt";

        sandbox
            .write_file(source_path, b"pooled")
            .expect("pooled VM 写文件必须成功");
        assert!(
            sandbox
                .file_exists(source_path)
                .expect("pooled VM file_exists 必须成功"),
            "写入后的文件必须存在"
        );

        let stat = sandbox.stat(source_path).expect("pooled VM stat 必须成功");
        assert!(stat.is_file, "stat 应标记为普通文件: {stat:?}");
        assert_eq!(stat.size, 6);

        let entries = sandbox
            .list_dir("/sandbox/")
            .expect("pooled VM list_dir 必须成功");
        assert!(
            entries.iter().any(|entry| entry.name == "sdk-file-api.txt"),
            "list_dir 应包含写入文件: {entries:?}"
        );

        sandbox
            .rename(source_path, target_path)
            .expect("pooled VM rename 必须成功");
        assert!(
            !sandbox
                .file_exists(source_path)
                .expect("rename 后检查源路径必须成功"),
            "rename 后源路径不应存在"
        );
        assert!(
            sandbox
                .file_exists(target_path)
                .expect("rename 后检查目标路径必须成功"),
            "rename 后目标路径应存在"
        );

        sandbox
            .remove_file(target_path)
            .expect("pooled VM remove_file 必须成功");
        assert!(
            !sandbox
                .file_exists(target_path)
                .expect("remove_file 后检查路径必须成功"),
            "remove_file 后目标路径不应存在"
        );

        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    #[test]
    fn list_dir_vm_backend_unavailable_on_current_platform() {
        // 非 Linux+KVM 平台，VM 后端不可用；实际 VM list_dir 测试在 Linux + vm feature 下运行。
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
