#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

mod execute;
mod files;
mod http;
mod pty;
pub mod registry;
mod snapshot;

use crate::config::{Config, IsolationLevel, TrustLevel};
use crate::error::SdkError;
use crate::router::{resolve_isolation, resolve_isolation_for_executable};
use crate::sandbox::registry::SandboxInfo;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::types::SandboxSnapshot;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::types::{RestorePool, RestorePoolConfig};
use crate::vm_helpers::destroy_backend_inner;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::vm_helpers::map_microvm_error;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::vm_helpers::map_restore_pool_error;
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use crate::vm_helpers::parse_command;
#[cfg(feature = "vm")]
use crate::vm_helpers::{initialize_default_vm_pool, map_pool_error};
#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use mimobox_core::Sandbox as CoreSandbox;
#[cfg(feature = "wasm")]
use mimobox_core::SandboxError;
use mimobox_core::{BLOCKED_ENV_VARS, ErrorCode, MAX_ENV_KEY_BYTES, SandboxMetrics};
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

impl SandboxInner {
    fn metrics(&self) -> Option<SandboxMetrics> {
        match self {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(sandbox) => sandbox.metrics(),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(sandbox) => sandbox.metrics(),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(sandbox) => sandbox.metrics(),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(_)
            | SandboxInner::PooledMicroVm(_)
            | SandboxInner::RestoredPooledMicroVm(_) => {
                let mut metrics = SandboxMetrics::default();
                metrics.collected_at = Some(std::time::Instant::now());
                Some(metrics)
            }
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
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
    pub(crate) id: uuid::Uuid,
    pub(crate) config: Config,
    pub(crate) inner: Option<SandboxInner>,
    pub(crate) active_isolation: Option<IsolationLevel>,
    #[cfg(feature = "vm")]
    pub(crate) vm_pool: Option<Arc<mimobox_vm::VmPool>>,
    pub(crate) cached_metrics: Option<SandboxMetrics>,
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

// -- SdkExecOptions and helpers --

/// Per-command execution options for SDK execute APIs.
#[derive(Debug, Clone, Default)]
pub struct SdkExecOptions {
    /// Environment variables scoped to this command.
    pub env: HashMap<String, String>,
    /// Optional command-level timeout override where the backend supports it.
    pub timeout: Option<Duration>,
    /// Optional working directory for this command.
    pub cwd: Option<String>,
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
    /// Provides the to guest exec options operation.
    pub(crate) fn to_guest_exec_options(&self) -> mimobox_vm::GuestExecOptions {
        mimobox_vm::GuestExecOptions {
            env: self.env.clone(),
            timeout: self.timeout,
            cwd: self.cwd.clone(),
        }
    }
}

/// Merge config-level environment variables with per-command environment variables.
/// Per-command env overrides config env_vars.
pub(crate) fn merge_env_vars(
    config_env: &HashMap<String, String>,
    command_env: &HashMap<String, String>,
) -> Result<HashMap<String, String>, SdkError> {
    validate_env_map(config_env)?;
    validate_env_map(command_env)?;

    if config_env.is_empty() {
        return Ok(command_env.clone());
    }
    if command_env.is_empty() {
        return Ok(config_env.clone());
    }

    let mut merged = HashMap::with_capacity(config_env.len() + command_env.len());
    merged.extend(
        config_env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    merged.extend(
        command_env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    Ok(merged)
}

fn validate_env_map(env: &HashMap<String, String>) -> Result<(), SdkError> {
    for (key, value) in env {
        validate_env_key(key)?;
        if value.contains('\0') {
            return Err(SdkError::Config(format!(
                "environment variable `{key}` contains NUL byte"
            )));
        }
    }
    Ok(())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn build_fallback_command_args(
    command: &str,
    options: &SdkExecOptions,
) -> Result<Vec<String>, SdkError> {
    // OS/Wasm backends take timeout from SandboxConfig; per-command timeout is VM-only.
    if options.timeout.is_some() {
        tracing::warn!(
            "per-command timeout is not supported by OS/Wasm backends;              using sandbox config timeout instead"
        );
    }
    let _ = options.timeout;

    if let Some(cwd) = options.cwd.as_deref() {
        let parsed_args = parse_command(command)?;
        let mut wrapped = Vec::with_capacity(parsed_args.len() + options.env.len() + 6);
        wrapped.push("/bin/sh".to_string());
        wrapped.push("-c".to_string());
        // SECURITY: Pass cwd and command as positional parameters to avoid shell injection.
        wrapped.push(r#"cd "$1" && shift && exec "$@""#.to_string());
        wrapped.push("mimobox-cwd".to_string());
        wrapped.push(cwd.to_string());
        if options.env.is_empty() {
            wrapped.extend(parsed_args);
        } else {
            // SECURITY: Pass env through a /usr/bin/env prefix instead of shell interpolation.
            let mut env_prefixed = Vec::with_capacity(1 + options.env.len() + parsed_args.len());
            env_prefixed.push("/usr/bin/env".to_string());
            env_prefixed.extend(build_env_assignments(&options.env)?);
            env_prefixed.extend(parsed_args);
            wrapped.extend(env_prefixed);
        }
        return Ok(wrapped);
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

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn build_fallback_argv_args(
    args: &[String],
    options: &SdkExecOptions,
) -> Result<Vec<String>, SdkError> {
    // OS/Wasm backends take timeout from SandboxConfig; per-command timeout is VM-only.
    if options.timeout.is_some() {
        tracing::warn!(
            "per-command timeout is not supported by OS/Wasm backends;              using sandbox config timeout instead"
        );
    }
    let _ = options.timeout;

    let mut command_args = if let Some(cwd) = options.cwd.as_deref() {
        let mut wrapped = Vec::with_capacity(args.len() + 5);
        wrapped.push("/bin/sh".to_string());
        wrapped.push("-c".to_string());
        wrapped.push(r#"cd "$1" && shift && exec "$@""#.to_string());
        wrapped.push("mimobox-cwd".to_string());
        wrapped.push(cwd.to_string());
        wrapped.extend(args.iter().cloned());
        wrapped
    } else {
        args.to_vec()
    };

    if options.env.is_empty() {
        return Ok(command_args);
    }

    let mut prefixed = Vec::with_capacity(command_args.len() + options.env.len() + 1);
    prefixed.push("/usr/bin/env".to_string());
    prefixed.extend(build_env_assignments(&options.env)?);
    prefixed.append(&mut command_args);
    Ok(prefixed)
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
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
    if key.is_empty() || key.contains('=') || key.contains('\0') || key.contains(' ') {
        return Err(SdkError::Config(format!(
            "invalid environment variable name: `{key}`"
        )));
    }
    if key.len() > MAX_ENV_KEY_BYTES {
        return Err(SdkError::Config(format!(
            "invalid environment variable name: `{key}` exceeds {MAX_ENV_KEY_BYTES} bytes"
        )));
    }
    if let Some(blocked) = BLOCKED_ENV_VARS
        .iter()
        .find(|blocked| key.eq_ignore_ascii_case(blocked))
    {
        return Err(SdkError::Config(format!(
            "environment variable `{key}` is blocked because it can override sandbox baseline `{blocked}`"
        )));
    }
    Ok(())
}

/// Validates the cwd value.
pub(crate) fn validate_cwd(cwd: &str) -> Result<(), SdkError> {
    use std::path::Component;
    if std::path::Path::new(cwd)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(SdkError::Config(
            "invalid cwd: contains path traversal".to_string(),
        ));
    }

    if cwd.contains(';')
        || cwd.contains('|')
        || cwd.contains('&')
        || cwd.contains('$')
        || cwd.contains('`')
    {
        return Err(SdkError::Config(
            "invalid cwd: contains shell metacharacters".to_string(),
        ));
    }

    if cwd.contains('\n') || cwd.contains('\r') {
        return Err(SdkError::Config(
            "invalid cwd: contains newline".to_string(),
        ));
    }

    Ok(())
}

// -- File error mapping helpers --

#[cfg(feature = "wasm")]
/// Maps the core file error value.
pub(crate) fn map_core_file_error(error: SandboxError) -> SdkError {
    match error {
        SandboxError::Io(io_err) => SdkError::Io(io_err),
        other => SdkError::from_sandbox_execute_error(other),
    }
}

#[cfg(feature = "wasm")]
/// Provides the read file via core operation.
pub(crate) fn read_file_via_core(
    sandbox: &mut impl CoreSandbox,
    path: &str,
) -> Result<Vec<u8>, SandboxError> {
    CoreSandbox::read_file(sandbox, path)
}

#[cfg(feature = "wasm")]
/// Provides the write file via core operation.
pub(crate) fn write_file_via_core(
    sandbox: &mut impl CoreSandbox,
    path: &str,
    data: &[u8],
) -> Result<(), SandboxError> {
    CoreSandbox::write_file(sandbox, path, data)
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
/// Provides the os file operation unsupported operation.
pub(crate) fn os_file_operation_unsupported(operation: &str, suggestion: &'static str) -> SdkError {
    SdkError::sandbox(
        ErrorCode::UnsupportedPlatform,
        format!(
            "OS backend does not support {operation}: file operations bypass sandbox isolation"
        ),
        Some(suggestion.to_string()),
    )
}

// -- Sandbox lifecycle methods --

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

        #[cfg(feature = "vm")]
        let vm_pool = initialize_default_vm_pool(&config)?;

        let mut sandbox = Self::new_uninitialized(config);
        #[cfg(feature = "vm")]
        {
            sandbox.vm_pool = vm_pool;
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

        let sandbox_config = config.to_sandbox_config();
        let microvm_config = config.to_microvm_config()?;
        let pool = mimobox_vm::VmPool::new_with_base(sandbox_config, microvm_config, pool_config)
            .map_err(map_pool_error)?;
        let mut sandbox = Self::new_uninitialized(config);
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

    /// Return the globally unique ID of the current SDK sandbox instance.
    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    /// Return all SDK sandbox instances still registered in the current process.
    pub fn list() -> Vec<SandboxInfo> {
        registry::list()
    }

    /// Return the persistent environment variables configured when the sandbox was created.
    pub fn env_vars(&self) -> &std::collections::HashMap<String, String> {
        &self.config.env_vars
    }

    /// Return the resource usage metrics from the most recent execution.
    ///
    /// Metrics are sampled and cached automatically when execute() returns.
    /// If no command has run yet, returns the default SandboxMetrics with all fields set to None.
    pub fn metrics(&self) -> SandboxMetrics {
        self.cached_metrics.clone().unwrap_or_default()
    }

    /// Return a registry information snapshot for the current SDK sandbox instance.
    pub fn info(&self) -> SandboxInfo {
        registry::get(self.id).unwrap_or_else(|| SandboxInfo {
            id: self.id,
            configured_isolation: Some(self.config.isolation),
            active_isolation: self.active_isolation,
            created_at: std::time::Instant::now(),
            is_ready: self.is_ready(),
        })
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
                    // Auto mode must not downgrade Untrusted probe initialization to OS;
                    // fail closed when microVM is unavailable instead of creating a weaker backend.
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
            if let Err(error) = self.wait_ready_inner(timeout) {
                registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
                registry::update_ready(self.id, false);
                if let Err(cleanup_error) = self.destroy_backend() {
                    tracing::warn!(
                        error = %cleanup_error,
                        "Failed to clean backend after wait_ready failure"
                    );
                }
                return Err(error);
            }
            registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
            registry::update_ready(self.id, true);
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_backend()?;
        }
        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        if let Err(error) = self.wait_ready_inner(timeout) {
            registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
            registry::update_ready(self.id, false);
            if let Err(cleanup_error) = self.destroy_backend() {
                tracing::warn!(
                    error = %cleanup_error,
                    "Failed to clean backend after wait_ready initialization failure"
                );
            }
            return Err(error);
        }
        registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
        registry::update_ready(self.id, true);
        Ok(())
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

    // -- Private helper methods --

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

    /// Provides the ensure backend operation.
    pub(crate) fn ensure_backend(&mut self, command: &str) -> Result<(), SdkError> {
        let isolation = resolve_isolation(&self.config, command)?;
        self.ensure_backend_isolation(isolation)
    }

    /// Provides argv-first backend selection without reparsing the executable path.
    pub(crate) fn ensure_backend_for_executable(
        &mut self,
        executable: &str,
    ) -> Result<(), SdkError> {
        let isolation = resolve_isolation_for_executable(&self.config, executable)?;
        self.ensure_backend_isolation(isolation)
    }

    fn ensure_backend_isolation(&mut self, isolation: IsolationLevel) -> Result<(), SdkError> {
        if self.active_isolation == Some(isolation) && self.inner.is_some() {
            registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
            registry::update_ready(self.id, true);
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_backend()?;
        }

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
        registry::update_ready(self.id, true);
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
    /// Provides the ensure backend for file ops operation.
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
            registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
            registry::update_ready(self.id, true);
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_backend()?;
        }

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
        registry::update_ready(self.id, true);
        Ok(())
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    /// Provides the ensure backend for snapshot operation.
    pub(crate) fn ensure_backend_for_snapshot(&mut self) -> Result<(), SdkError> {
        if self.inner.is_some() {
            return match self.active_isolation {
                Some(IsolationLevel::MicroVm) => {
                    registry::update_isolation(
                        self.id,
                        Some(self.config.isolation),
                        Some(IsolationLevel::MicroVm),
                    );
                    registry::update_ready(self.id, true);
                    Ok(())
                }
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
        registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
        registry::update_ready(self.id, true);
        Ok(())
    }

    #[cfg(all(feature = "vm", not(target_os = "linux")))]
    /// Provides the ensure backend for file ops operation.
    pub(crate) fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
        Err(SdkError::unsupported_backend("microvm"))
    }

    /// Provides the ensure backend for pty operation.
    pub(crate) fn ensure_backend_for_pty(&mut self) -> Result<(), SdkError> {
        let isolation = match self.config.isolation {
            IsolationLevel::Auto => {
                if self.config.trust_level == TrustLevel::Untrusted {
                    // PTY currently depends on the OS backend. Untrusted must not silently
                    // downgrade to OS, and microVM does not support PTY yet, so reject fail-closed.
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
            registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
            registry::update_ready(self.id, true);
            return Ok(());
        }

        if self.inner.is_some() {
            self.destroy_backend()?;
        }

        self.inner = Some(self.create_inner(isolation)?);
        self.active_isolation = Some(isolation);
        registry::update_isolation(self.id, Some(self.config.isolation), Some(isolation));
        registry::update_ready(self.id, true);
        Ok(())
    }

    fn new_uninitialized(config: Config) -> Self {
        Self {
            id: registry::register(),
            config,
            inner: None,
            active_isolation: None,
            #[cfg(feature = "vm")]
            vm_pool: None,
            cached_metrics: None,
        }
    }

    #[allow(dead_code)]
    /// Provides the from initialized inner operation.
    pub(crate) fn from_initialized_inner(inner: SandboxInner, config: Config) -> Self {
        let id = registry::register();
        registry::update_isolation(id, Some(config.isolation), Some(IsolationLevel::MicroVm));
        registry::update_ready(id, true);

        Self {
            id,
            config,
            inner: Some(inner),
            active_isolation: Some(IsolationLevel::MicroVm),
            #[cfg(feature = "vm")]
            vm_pool: None,
            cached_metrics: None,
        }
    }

    /// Provides the sync cached metrics from inner operation.
    pub(crate) fn sync_cached_metrics_from_inner(&mut self) {
        self.cached_metrics = self.inner.as_ref().and_then(SandboxInner::metrics);
    }

    fn create_inner(&self, isolation: IsolationLevel) -> Result<SandboxInner, SdkError> {
        #[cfg(any(
            feature = "wasm",
            all(feature = "os", any(target_os = "linux", target_os = "macos")),
            all(feature = "vm", target_os = "linux")
        ))]
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

    fn destroy_backend(&mut self) -> Result<(), SdkError> {
        let inner = self.inner.take();
        self.active_isolation = None;
        registry::update_isolation(self.id, Some(self.config.isolation), None);
        registry::update_ready(self.id, false);

        match inner {
            Some(inner) => destroy_backend_inner(inner),
            None => Ok(()),
        }
    }

    fn destroy_inner(&mut self) -> Result<(), SdkError> {
        match self.destroy_backend() {
            Ok(()) => {
                registry::unregister(self.id);
                Ok(())
            }
            Err(error) => {
                registry::update_isolation(self.id, Some(self.config.isolation), None);
                registry::update_ready(self.id, false);
                Err(error)
            }
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
                        "Sandbox drop auto-cleanup failed, retrying"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(
                        100 * u64::from(attempt + 1),
                    ));
                }
                Err(error) => {
                    tracing::error!(
                        attempts = MAX_ATTEMPTS,
                        error = %error,
                        "Sandbox drop auto-cleanup still failing after multiple retries"
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
    #[cfg(all(feature = "vm", target_os = "linux"))]
    use mimobox_core::{PtyConfig, PtySize};

    fn inner_is_initialized(sandbox: &Sandbox) -> bool {
        sandbox.inner.is_some()
    }

    fn active_isolation(sandbox: &Sandbox) -> Option<IsolationLevel> {
        sandbox.active_isolation
    }

    #[test]
    fn test_sdk_exec_rejects_empty_argv() {
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");
        let empty: [&str; 0] = [];

        match sandbox.exec(&empty) {
            Err(SdkError::Config(message)) => {
                assert_eq!(message, "argv must not be empty");
            }
            Err(other) => panic!("expected Config error, got: {other}"),
            Ok(_) => panic!("empty argv should not execute successfully"),
        }

        match sandbox.stream_exec(&empty) {
            Err(SdkError::Config(message)) => {
                assert_eq!(message, "argv must not be empty");
            }
            Err(other) => panic!("expected Config error, got: {other}"),
            Ok(_) => panic!("empty argv should not stream successfully"),
        }
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_build_fallback_argv_args_with_cwd_uses_safe_shell_wrapper() {
        let args = vec!["/bin/echo".to_string(), "hello; rm -rf /".to_string()];
        let options = SdkExecOptions {
            cwd: Some("/tmp/mimobox safe".to_string()),
            ..Default::default()
        };

        let wrapped =
            build_fallback_argv_args(&args, &options).expect("argv fallback construction failed");

        assert_eq!(
            wrapped,
            vec![
                "/bin/sh",
                "-c",
                r#"cd "$1" && shift && exec "$@""#,
                "mimobox-cwd",
                "/tmp/mimobox safe",
                "/bin/echo",
                "hello; rm -rf /",
            ]
        );
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_build_fallback_command_args_with_cwd_uses_safe_argv() {
        let mut options = SdkExecOptions {
            cwd: Some("/tmp/mimobox; rm -rf /".to_string()),
            ..Default::default()
        };
        options
            .env
            .insert("TOKEN".to_string(), "value; $(rm -rf /)".to_string());

        let wrapped = build_fallback_command_args("/bin/echo 'hello; rm -rf /'", &options)
            .expect("command fallback construction failed");

        assert_eq!(
            wrapped,
            vec![
                "/bin/sh",
                "-c",
                r#"cd "$1" && shift && exec "$@""#,
                "mimobox-cwd",
                "/tmp/mimobox; rm -rf /",
                "/usr/bin/env",
                "TOKEN=value; $(rm -rf /)",
                "/bin/echo",
                "hello; rm -rf /",
            ]
        );
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
            Err(other) => {
                panic!("expected OS file API to return UnsupportedPlatform, got: {other}")
            }
            Ok(_) => panic!("expected OS file API to be rejected, but it succeeded"),
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

        eprintln!("skipping SDK macOS Seatbelt runtime test: {reason}");
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
                        panic!("minimal sandbox-exec probe failed: {error}");
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
        let sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");

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

        assert!(matches!(
            result,
            Err(SdkError::Sandbox {
                code: ErrorCode::InvalidConfig,
                ..
            })
        ));
    }

    #[test]
    fn metrics_before_first_execute_returns_default_values() {
        let sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");

        let metrics = sandbox.metrics();

        assert!(metrics.memory_usage_bytes.is_none());
        assert!(metrics.memory_limit_bytes.is_none());
        assert!(metrics.cpu_time_user_us.is_none());
        assert!(metrics.cpu_time_system_us.is_none());
        assert!(metrics.wasm_fuel_consumed.is_none());
        assert!(metrics.io_read_bytes.is_none());
        assert!(metrics.io_write_bytes.is_none());
        assert!(metrics.collected_at.is_none());
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn metrics_after_execute_are_cached() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");
        sandbox
            .execute("/bin/echo metrics")
            .expect("command execution failed");

        let metrics = sandbox.metrics();

        assert!(metrics.collected_at.is_some());
        assert_eq!(metrics.memory_limit_bytes, Some(512 * 1024 * 1024));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn with_pool_rejects_invalid_config_before_backend_creation() {
        let config = Config {
            vm_vcpu_count: 0,
            ..Config::default()
        };

        let result = Sandbox::with_pool(config, mimobox_vm::VmPoolConfig::default());

        assert!(matches!(
            result,
            Err(SdkError::Sandbox {
                code: ErrorCode::InvalidConfig,
                ..
            })
        ));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn default_auto_config_does_not_prepare_vm_pool() {
        let sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");

        assert!(!vm_pool_is_initialized(&sandbox));
    }

    #[cfg(feature = "vm")]
    #[test]
    fn explicit_microvm_config_marks_pool_as_eligible_on_supported_builds() {
        let config = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .build()
            .expect("config validation failed");

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
            .expect("config validation failed");

        #[cfg(all(feature = "vm", target_os = "linux"))]
        assert!(should_prepare_vm_pool(&config));

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        assert!(!should_prepare_vm_pool(&config));
    }

    #[test]
    fn destroy_uninitialized_sandbox_succeeds() {
        let sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");

        let result = sandbox.destroy();

        assert!(
            result.is_ok(),
            "destroying an uninitialized sandbox should succeed: {:?}",
            result
        );
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    #[test]
    fn wait_ready_untrusted_fails_without_vm() {
        let config = Config::builder()
            .trust_level(TrustLevel::Untrusted)
            .build()
            .expect("config validation failed");
        let mut sandbox = Sandbox::with_config(config).expect("sandbox creation failed");

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
                panic!(
                    "expected Untrusted wait_ready to fail closed without microVM, got: {other:?}"
                )
            }
        }
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn destroy_then_drop_does_not_panic() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");
        // Execute once so the backend completes lazy initialization.
        sandbox
            .execute("/bin/echo hello")
            .expect("command execution failed");
        assert!(inner_is_initialized(&sandbox));

        let destroyed = Sandbox::with_config(Config::default())
            .expect("sandbox creation failed")
            .destroy();

        assert!(destroyed.is_ok(), "destroy should succeed: {:?}", destroyed);
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn drop_after_partial_initialization_does_not_panic() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let result = std::panic::catch_unwind(|| {
            let mut sandbox =
                Sandbox::with_config(Config::default()).expect("sandbox creation failed");
            sandbox
                .execute("/bin/echo test")
                .expect("command execution failed");
            // Do not call destroy explicitly; verify Drop auto-cleanup does not panic.
            drop(sandbox);
        });

        assert!(result.is_ok(), "Drop auto-cleanup should not panic");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn concurrent_execute_via_mutex_does_not_panic() {
        use std::sync::{Arc, Mutex};

        if should_skip_os_runtime_tests() {
            return;
        }

        let sandbox = Arc::new(Mutex::new(
            Sandbox::with_config(Config::default()).expect("sandbox creation failed"),
        ));
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let sandbox = Arc::clone(&sandbox);
                std::thread::spawn(move || {
                    let mut sandbox = sandbox.lock().expect("Mutex should not be poisoned");
                    let result = sandbox
                        .execute(&format!("/bin/echo thread-{i}"))
                        .expect("concurrent execute should not fail");
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    assert!(
                        stdout.contains(&format!("thread-{i}")),
                        "thread {i} stdout should contain marker, got: {stdout}"
                    );
                    assert_eq!(result.exit_code, Some(0), "exit code should be 0");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let sandbox = match Arc::try_unwrap(sandbox) {
            Ok(sandbox) => sandbox,
            Err(_) => panic!("all references should have been released"),
        };
        sandbox
            .into_inner()
            .expect("Mutex should not be poisoned")
            .destroy()
            .expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn create_pty_auto_routes_to_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");
        let mut session = sandbox
            .create_pty("/bin/echo ready")
            .expect("PTY session creation failed");

        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Os));
        assert_eq!(session.wait().expect("waiting for PTY exit failed"), 0);

        drop(session);
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[test]
    fn create_pty_with_zero_timeout_is_rejected() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");

        let result = sandbox.create_pty_with_config(mimobox_core::PtyConfig {
            command: vec!["/bin/sh".to_string()],
            size: mimobox_core::PtySize::default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: Some(Duration::ZERO),
        });

        let error = result.expect_err("zero PTY timeout should be rejected");
        assert!(
            error.to_string().contains("greater than zero"),
            "error should explain zero timeout handling: {error}"
        );
    }

    #[test]
    fn create_pty_auto_untrusted_fails_closed() {
        let config = Config::builder()
            .trust_level(TrustLevel::Untrusted)
            .build()
            .expect("config validation failed");
        let mut sandbox = Sandbox::with_config(config).expect("sandbox creation failed");

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
            other => panic!("expected Untrusted + Auto + PTY to fail closed, got: {other:?}"),
        }
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_returns_unsupported_on_os_backend() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");

        let result = sandbox.list_dir("/tmp");

        assert_os_file_operation_unsupported(
            result,
            "list_dir",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_nonexistent_returns_error() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");

        let result = sandbox.list_dir("/nonexistent/path");

        assert_os_file_operation_unsupported(
            result,
            "list_dir",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_file_path_returns_error() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory creation failed");
        let file_path = temp_dir.path().join("not-a-directory.txt");
        std::fs::write(&file_path, "test").expect("test file write failed");
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox.list_dir(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "list_dir",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_empty_directory_returns_empty() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory creation failed");
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox.list_dir(&temp_dir.path().to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "list_dir",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_file_exists_returns_unsupported_on_os_backend() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory creation failed");
        let file_path = temp_dir.path().join("exists.txt");
        std::fs::write(&file_path, "test").expect("test file write failed");
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox.file_exists(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "file_exists",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_remove_file_removes_file() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory creation failed");
        let file_path = temp_dir.path().join("remove.txt");
        std::fs::write(&file_path, "test").expect("test file write failed");
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox.remove_file(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "remove_file",
            "Use microVM backend for isolated file operations",
        );
        assert!(
            file_path.exists(),
            "test file should still exist after remove_file is rejected: {}",
            file_path.display()
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_rename_moves_file() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory creation failed");
        let source_path = temp_dir.path().join("source.txt");
        let target_path = temp_dir.path().join("target.txt");
        std::fs::write(&source_path, "test").expect("test file write failed");
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox.rename(
            &source_path.to_string_lossy(),
            &target_path.to_string_lossy(),
        );

        assert_os_file_operation_unsupported(
            result,
            "rename",
            "Use microVM backend for isolated file operations",
        );
        assert!(
            source_path.exists(),
            "source file should still exist after rename is rejected"
        );
        assert!(
            !target_path.exists(),
            "target file should not exist after rename is rejected"
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_stat_returns_file_metadata() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory creation failed");
        let file_path = temp_dir.path().join("stat.txt");
        std::fs::write(&file_path, "stat").expect("test file write failed");
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox.stat(&file_path.to_string_lossy());

        assert_os_file_operation_unsupported(
            result,
            "stat",
            "Use microVM backend for isolated file operations",
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_read_write_file_roundtrip_on_os_backend() {
        let temp_dir = tempfile::TempDir::new().expect("temporary directory creation failed");
        let file_path = temp_dir.path().join("roundtrip.txt");
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

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
            "write_file should not create a file on the host filesystem after rejection"
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_execute_with_env_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::new().expect("sandbox creation failed");
        let mut env = HashMap::new();
        env.insert("MIMOBOX_SDK_ENV_TEST".to_string(), "works".to_string());

        let result = sandbox
            .execute_with_env("/usr/bin/env", env)
            .expect("execute_with_env should succeed");
        let stdout = String::from_utf8_lossy(&result.stdout);

        assert!(
            stdout.contains("MIMOBOX_SDK_ENV_TEST=works"),
            "stdout should contain injected environment variable, got: {stdout}"
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_execute_with_timeout_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox
            .execute_with_timeout("/bin/echo sdk-timeout", Duration::from_secs(5))
            .expect("execute_with_timeout should succeed");

        assert_eq!(result.exit_code, Some(0));
        assert!(String::from_utf8_lossy(&result.stdout).contains("sdk-timeout"));
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_execute_with_cwd_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let temp_dir =
            tempfile::TempDir::new_in("/tmp").expect("temporary directory creation failed");
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox
            .execute_with_cwd("/bin/pwd", &temp_dir.path().to_string_lossy())
            .expect("execute_with_cwd should succeed");
        let stdout = String::from_utf8_lossy(&result.stdout);

        assert!(
            stdout.contains(temp_dir.path().to_string_lossy().as_ref()),
            "stdout should contain cwd, got: {stdout}"
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_stream_execute_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let receiver = sandbox
            .stream_execute("/bin/echo sdk-stream")
            .expect("stream_execute should succeed");
        let events: Vec<_> = receiver.iter().collect();

        assert!(
            events.iter().any(|event| matches!(
                event,
                StreamEvent::Stdout(data)
                    if String::from_utf8_lossy(data).contains("sdk-stream")
            )),
            "stream_execute should return a stdout event: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, StreamEvent::Exit(0))),
            "stream_execute should return an Exit(0) event: {events:?}"
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_exec_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let result = sandbox
            .exec(&["/bin/echo", "hello", "world"])
            .expect("exec should succeed");

        assert_eq!(result.exit_code, Some(0));
        assert!(String::from_utf8_lossy(&result.stdout).contains("hello world"));
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_stream_exec_on_os_backend() {
        if should_skip_os_runtime_tests() {
            return;
        }

        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

        let receiver = sandbox
            .stream_exec(&["/bin/echo", "hello"])
            .expect("stream_exec should succeed");
        let events: Vec<_> = receiver.iter().collect();

        assert!(
            events.iter().any(|event| matches!(
                event,
                StreamEvent::Stdout(data) if String::from_utf8_lossy(data).contains("hello")
            )),
            "stream_exec should return a stdout event: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, StreamEvent::Exit(0))),
            "stream_exec should return an Exit(0) event: {events:?}"
        );
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_file_api_rejects_path_traversal() {
        let mut sandbox = Sandbox::new().expect("sandbox creation failed");

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
        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    #[test]
    fn create_pty_microvm_is_rejected() {
        let config = Config::builder()
            .isolation(IsolationLevel::MicroVm)
            .build()
            .expect("config validation failed");
        let mut sandbox = Sandbox::with_config(config).expect("sandbox creation failed");

        let result = sandbox.create_pty("/bin/sh");

        match result {
            Err(SdkError::BackendUnavailable("microvm")) => {}
            Err(other) => panic!("expected microVM backend to be unavailable, got: {other}"),
            Ok(_) => panic!("expected PTY to be rejected under microVM config, but it succeeded"),
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
            .expect("config validation failed");
        let mut microvm = mimobox_vm::MicrovmSandbox::new_with_base(
            mimobox_core::SandboxConfig::default(),
            microvm_config,
        )
        .expect("microVM sandbox creation must succeed");
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
            Err(other) => {
                panic!("expected microVM PTY to return UnsupportedOperation, got: {other}")
            }
            Ok(_) => panic!("expected microVM PTY to be rejected, but it succeeded"),
        }

        let mut sandbox = Sandbox::from_initialized_inner(SandboxInner::MicroVm(microvm), config);
        let result = sandbox.create_pty("/bin/sh");

        match result {
            Err(SdkError::Sandbox { code, message, .. }) => {
                assert_eq!(code, ErrorCode::UnsupportedPlatform);
                assert!(message.contains("microVM"));
            }
            Err(other) => panic!(
                "expected SDK to map UnsupportedOperation to UnsupportedPlatform, got: {other}"
            ),
            Ok(_) => panic!("expected SDK PTY to be rejected under microVM, but it succeeded"),
        }

        sandbox.destroy().expect("sandbox destroy failed");
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
            .expect("config validation failed");
        let mut sandbox = Sandbox::with_config(config).expect("pooled VM sandbox creation failed");
        let source_path = "/sandbox/sdk-file-api.txt";
        let target_path = "/sandbox/sdk-file-api-renamed.txt";

        sandbox
            .write_file(source_path, b"pooled")
            .expect("pooled VM file write must succeed");
        assert!(
            sandbox
                .file_exists(source_path)
                .expect("pooled VM file_exists must succeed"),
            "file must exist after write"
        );

        let stat = sandbox
            .stat(source_path)
            .expect("pooled VM stat must succeed");
        assert!(
            stat.is_file,
            "stat should mark it as a regular file: {stat:?}"
        );
        assert_eq!(stat.size, 6);

        let entries = sandbox
            .list_dir("/sandbox/")
            .expect("pooled VM list_dir must succeed");
        assert!(
            entries.iter().any(|entry| entry.name == "sdk-file-api.txt"),
            "list_dir should include the written file: {entries:?}"
        );

        sandbox
            .rename(source_path, target_path)
            .expect("pooled VM rename must succeed");
        assert!(
            !sandbox
                .file_exists(source_path)
                .expect("checking source path after rename must succeed"),
            "source path should not exist after rename"
        );
        assert!(
            sandbox
                .file_exists(target_path)
                .expect("checking target path after rename must succeed"),
            "target path should exist after rename"
        );

        sandbox
            .remove_file(target_path)
            .expect("pooled VM remove_file must succeed");
        assert!(
            !sandbox
                .file_exists(target_path)
                .expect("checking path after remove_file must succeed"),
            "target path should not exist after remove_file"
        );

        sandbox.destroy().expect("sandbox destroy failed");
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    #[test]
    fn list_dir_vm_backend_unavailable_on_current_platform() {
        // VM backend is unavailable on non-Linux+KVM platforms; the real VM list_dir test runs on Linux with the vm feature.
    }

    #[cfg(all(
        feature = "os",
        feature = "wasm",
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    fn auto_routing_reinitializes_backend_for_wasm_commands() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("sandbox creation failed");
        sandbox
            .ensure_backend("/bin/echo hello")
            .expect("OS backend initialization failed");
        assert!(has_os_backend(&sandbox));
        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Os));

        let script_path = std::path::PathBuf::from(format!(
            "/tmp/mimobox-sdk-auto-route-{}.wasm",
            std::process::id()
        ));
        std::fs::write(&script_path, "#!/bin/sh\necho routed-via-os\n")
            .expect("test script write failed");
        make_executable(&script_path);

        let command = script_path.to_string_lossy().into_owned();
        sandbox
            .ensure_backend(&command)
            .expect("switching to Wasm backend failed");

        let _ = std::fs::remove_file(&script_path);

        assert!(has_wasm_backend(&sandbox));
        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Wasm));
    }

    #[cfg(all(feature = "wasm", unix))]
    fn make_executable(path: &std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).expect("reading test script metadata failed");
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)
            .expect("setting test script permissions failed");
    }
}
