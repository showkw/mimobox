use crate::config::{Config, IsolationLevel};
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::dispatch::HttpRequestForSdk;
use crate::dispatch::{ExecuteForSdk, StreamExecuteForSdk};
use crate::error::SdkError;
use crate::router::resolve_isolation;
#[cfg(feature = "vm")]
use crate::types::HttpResponse;
use crate::types::{ExecuteResult, PtySession, SandboxSnapshot, StreamEvent};
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::types::{RestorePool, RestorePoolConfig};
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::vm_helpers::map_microvm_error;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::vm_helpers::map_restore_pool_error;
use crate::vm_helpers::{
    build_code_command, destroy_backend_inner, map_pty_create_error, parse_command,
};
#[cfg(feature = "vm")]
use crate::vm_helpers::{initialize_default_vm_pool, map_pool_error};
use mimobox_core::{ErrorCode, FileStat, PtyConfig, PtySize, Sandbox as CoreSandbox};
use std::collections::HashMap;
#[cfg(feature = "vm")]
use std::sync::Arc;
use std::sync::mpsc;
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
    config: Config,
    inner: Option<SandboxInner>,
    active_isolation: Option<IsolationLevel>,
    #[cfg(feature = "vm")]
    vm_pool: Option<Arc<mimobox_vm::VmPool>>,
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl RestorePool {
    /// Creates a fixed-size restore pool from the base configuration.
    pub fn new(config: RestorePoolConfig) -> Result<Self, SdkError> {
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
            Config::builder().isolation(IsolationLevel::MicroVm).build(),
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
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm($binding) => $expr,
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm($binding) => $expr,
        }
    };
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

#[derive(Debug, Clone, Default)]
struct SdkExecOptions {
    env: HashMap<String, String>,
    timeout: Option<Duration>,
    cwd: Option<String>,
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
    fn to_guest_exec_options(&self) -> mimobox_vm::GuestExecOptions {
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

fn map_core_file_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
        other => SdkError::from_sandbox_execute_error(other),
    }
}

#[cfg(feature = "wasm")]
fn read_file_via_core(sandbox: &mut impl CoreSandbox, path: &str) -> Result<Vec<u8>, SdkError> {
    mimobox_core::Sandbox::read_file(sandbox, path).map_err(map_core_file_error)
}

fn read_file_via_core_or_host(
    sandbox: &mut impl CoreSandbox,
    path: &str,
) -> Result<Vec<u8>, SdkError> {
    match mimobox_core::Sandbox::read_file(sandbox, path) {
        Ok(data) => Ok(data),
        Err(mimobox_core::SandboxError::ExecutionFailed(message))
            if message == "file reading not supported by current backend" =>
        {
            read_host_file(path)
        }
        Err(error) => Err(map_core_file_error(error)),
    }
}

#[cfg(feature = "wasm")]
fn write_file_via_core(
    sandbox: &mut impl CoreSandbox,
    path: &str,
    data: &[u8],
) -> Result<(), SdkError> {
    mimobox_core::Sandbox::write_file(sandbox, path, data).map_err(map_core_file_error)
}

fn write_file_via_core_or_host(
    sandbox: &mut impl CoreSandbox,
    path: &str,
    data: &[u8],
) -> Result<(), SdkError> {
    match mimobox_core::Sandbox::write_file(sandbox, path, data) {
        Ok(()) => Ok(()),
        Err(mimobox_core::SandboxError::ExecutionFailed(message))
            if message == "file writing not supported by current backend" =>
        {
            write_host_file(path, data)
        }
        Err(error) => Err(map_core_file_error(error)),
    }
}

fn read_host_file(path: &str) -> Result<Vec<u8>, SdkError> {
    validate_host_file_path(path)?;
    std::fs::read(path).map_err(SdkError::Io)
}

fn write_host_file(path: &str, data: &[u8]) -> Result<(), SdkError> {
    validate_host_file_path(path)?;
    std::fs::write(path, data).map_err(SdkError::Io)
}

fn validate_host_file_path(path: &str) -> Result<(), SdkError> {
    if path.is_empty() {
        return Err(SdkError::sandbox(
            ErrorCode::InvalidConfig,
            "path must not be empty",
            None,
        ));
    }
    if path.contains("..") {
        return Err(SdkError::sandbox(
            ErrorCode::InvalidConfig,
            "path must not contain '..' path traversal",
            None,
        ));
    }
    Ok(())
}

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
    ///     .build();
    /// let mut sandbox = Sandbox::with_config(config)?;
    /// # Ok(())
    /// # }
    /// ```
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
        let mut sandbox = Self::new_uninitialized(config);
        let sandbox_config = sandbox.config.to_sandbox_config();
        let microvm_config = sandbox.config.to_microvm_config()?;
        let pool = mimobox_vm::VmPool::new_with_base(sandbox_config, microvm_config, pool_config)
            .map_err(map_pool_error)?;
        sandbox.vm_pool = Some(Arc::new(pool));
        Ok(sandbox)
    }

    /// Takes a snapshot of the current sandbox.
    ///
    /// This capability is currently only available on `Linux + vm feature + MicroVm` backends.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{Config, IsolationLevel, Sandbox};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::builder()
    ///     .isolation(IsolationLevel::MicroVm)
    ///     .build();
    /// let mut sandbox = Sandbox::with_config(config)?;
    /// let snapshot = sandbox.snapshot()?;
    /// assert!(snapshot.size() > 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn snapshot(&mut self) -> Result<SandboxSnapshot, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        {
            self.ensure_backend_for_snapshot()?;
            let inner = self.require_inner()?;

            let snapshot = match inner {
                SandboxInner::MicroVm(sandbox) => sandbox.snapshot().map_err(map_microvm_error),
                SandboxInner::PooledMicroVm(sandbox) => {
                    sandbox.snapshot().map_err(map_microvm_error)
                }
                SandboxInner::RestoredPooledMicroVm(sandbox) => {
                    sandbox.snapshot().map_err(map_microvm_error)
                }
                _ => Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "current backend does not support snapshot",
                    Some(
                        "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                            .to_string(),
                    ),
                )),
            }?;

            Ok(SandboxSnapshot::from_core(snapshot))
        }

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        {
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "snapshot not supported in current build",
                Some("use snapshot on Linux with vm feature enabled".to_string()),
            ))
        }
    }

    /// Restores a new sandbox from a snapshot.
    pub fn from_snapshot(snapshot: &SandboxSnapshot) -> Result<Self, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        {
            let sandbox =
                mimobox_vm::MicrovmSandbox::restore(&snapshot.inner).map_err(map_microvm_error)?;
            Ok(Self::from_initialized_inner(
                SandboxInner::MicroVm(sandbox),
                Config::builder().isolation(IsolationLevel::MicroVm).build(),
            ))
        }

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        {
            let _ = snapshot;
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "snapshot restore not supported in current build",
                Some("use snapshot restore on Linux with vm feature enabled".to_string()),
            ))
        }
    }

    /// Forks the current sandbox into an independent copy.
    ///
    /// Only the microVM backend supports this. The forked sandbox shares
    /// unmodified memory pages with the original sandbox (CoW), and each keeps
    /// private copies after writes.
    #[cfg(all(feature = "vm", target_os = "linux"))]
    pub fn fork(&mut self) -> Result<Self, SdkError> {
        self.ensure_backend_for_snapshot()?;
        let inner = self.require_inner()?;

        match inner {
            SandboxInner::MicroVm(sandbox) => {
                let forked = sandbox.fork().map_err(map_microvm_error)?;
                Ok(Self::from_initialized_inner(
                    SandboxInner::MicroVm(forked),
                    self.config.clone(),
                ))
            }
            _ => Err(SdkError::unsupported_backend("fork")),
        }
    }

    /// Fork stub for platforms without microVM support. Always returns `BackendUnavailable`.
    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    pub fn fork(&mut self) -> Result<Self, SdkError> {
        Err(SdkError::unsupported_backend("fork"))
    }

    /// Executes a command inside the sandbox.
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
    /// # Ok(())
    /// # }
    /// ```
    pub fn execute(&mut self, command: &str) -> Result<ExecuteResult, SdkError> {
        let args = parse_command(command)?;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;
        dispatch_execute!(inner, s, s.execute_for_sdk(&args))
    }

    /// Execute code in the given language inside the sandbox.
    ///
    /// # Supported languages
    ///
    /// - "bash" -> bash -c <code>
    /// - "sh" / "shell" -> sh -c <code>
    /// - "python" / "python3" / "py" -> python3 -c <code>
    /// - "javascript" / "js" / "node" / "nodejs" -> node -e <code>
    pub fn execute_code(&mut self, language: &str, code: &str) -> Result<ExecuteResult, SdkError> {
        let command = build_code_command(language, code)?;
        self.execute(&command)
    }

    /// Lists directory entries under the specified path.
    ///
    /// Returns each entry's name, type, size, and symlink flag.
    pub fn list_dir(&mut self, path: &str) -> Result<Vec<mimobox_core::DirEntry>, SdkError> {
        self.ensure_backend("/bin/ls")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(s) => {
                mimobox_core::Sandbox::list_dir(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(s) => {
                mimobox_core::Sandbox::list_dir(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.list_dir(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.list_dir(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => s.list_dir(path).map_err(map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => {
                mimobox_core::Sandbox::list_dir(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
        }
    }

    /// 检查指定路径的文件是否存在。
    pub fn file_exists(&mut self, path: &str) -> Result<bool, SdkError> {
        self.ensure_backend("/bin/test")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(s) => {
                mimobox_core::Sandbox::file_exists(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(s) => {
                mimobox_core::Sandbox::file_exists(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.file_exists(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.file_exists(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => {
                s.file_exists(path).map_err(map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => {
                mimobox_core::Sandbox::file_exists(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
        }
    }

    /// 删除指定路径的文件或空目录。
    pub fn remove_file(&mut self, path: &str) -> Result<(), SdkError> {
        self.ensure_backend("/bin/test")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(s) => {
                mimobox_core::Sandbox::remove_file(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(s) => {
                mimobox_core::Sandbox::remove_file(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.remove_file(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.remove_file(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => {
                s.remove_file(path).map_err(map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => {
                mimobox_core::Sandbox::remove_file(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
        }
    }

    /// 重命名/移动文件。
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), SdkError> {
        self.ensure_backend("/bin/test")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(s) => {
                mimobox_core::Sandbox::rename(s, from, to).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(s) => {
                mimobox_core::Sandbox::rename(s, from, to).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.rename(from, to).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.rename(from, to).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => s.rename(from, to).map_err(map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => {
                mimobox_core::Sandbox::rename(s, from, to).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
        }
    }

    /// 返回文件元信息。
    pub fn stat(&mut self, path: &str) -> Result<FileStat, SdkError> {
        self.ensure_backend("/bin/test")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(s) => mimobox_core::Sandbox::stat(s, path).map_err(|err| match err {
                mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                other => SdkError::from_sandbox_execute_error(other),
            }),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(s) => {
                mimobox_core::Sandbox::stat(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.stat(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.stat(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => s.stat(path).map_err(map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => {
                mimobox_core::Sandbox::stat(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
        }
    }

    /// Creates an interactive terminal session.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::Sandbox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox = Sandbox::new()?;
    /// let mut pty = sandbox.create_pty("/bin/sh")?;
    /// pty.send_input(b"echo hello\n")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_pty(&mut self, command: &str) -> Result<PtySession, SdkError> {
        let args = parse_command(command)?;
        if args.is_empty() {
            return Err(SdkError::Config(
                "PTY command must not be empty".to_string(),
            ));
        }

        self.create_pty_with_config(PtyConfig {
            command: args,
            size: PtySize::default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: self.config.timeout,
        })
    }

    /// Creates an interactive terminal session with a complete `PtyConfig`.
    pub fn create_pty_with_config(&mut self, config: PtyConfig) -> Result<PtySession, SdkError> {
        if config.command.is_empty() {
            return Err(SdkError::Config(
                "PTY command must not be empty".to_string(),
            ));
        }

        self.ensure_backend_for_pty()?;
        let inner = self.require_inner()?;

        let session = match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(sandbox) => {
                CoreSandbox::create_pty(sandbox, config.clone()).map_err(map_pty_create_error)?
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(sandbox) => {
                CoreSandbox::create_pty(sandbox, config.clone()).map_err(map_pty_create_error)?
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
                CoreSandbox::create_pty(sandbox, config.clone()).map_err(map_pty_create_error)?
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(_) => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "PTY sessions currently only support OS-level backend, microVM pool not supported yet",
                    Some("set isolation to `Os` or use default Auto".to_string()),
                ));
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(_) => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "PTY sessions currently only support OS-level backend, restored microVM pool not supported yet",
                    Some("set isolation to `Os` or use default Auto".to_string()),
                ));
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(sandbox) => {
                CoreSandbox::create_pty(sandbox, config).map_err(map_pty_create_error)?
            }
        };

        Ok(PtySession::from_inner(session))
    }

    /// Executes a command with additional environment variables for this call.
    pub fn execute_with_env(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_sdk_options(
            command,
            SdkExecOptions {
                env,
                timeout: None,
                cwd: None,
            },
        )
    }

    /// Executes a command with a timeout override where the backend supports it.
    pub fn execute_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_sdk_options(
            command,
            SdkExecOptions {
                env: HashMap::new(),
                timeout: Some(timeout),
                cwd: None,
            },
        )
    }

    /// Executes a command with additional environment variables and a timeout override.
    pub fn execute_with_env_and_timeout(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_sdk_options(
            command,
            SdkExecOptions {
                env,
                timeout: Some(timeout),
                cwd: None,
            },
        )
    }

    /// Executes a command with a working directory override where the backend supports it.
    pub fn execute_with_cwd(
        &mut self,
        command: &str,
        cwd: &str,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_sdk_options(
            command,
            SdkExecOptions {
                cwd: Some(cwd.to_string()),
                ..Default::default()
            },
        )
    }

    #[cfg(feature = "vm")]
    /// Executes a command in the microVM backend with full per-command execution options.
    pub fn execute_with_vm_options_full(
        &mut self,
        command: &str,
        options: mimobox_vm::GuestExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_sdk_options(command, options.into())
    }

    /// Executes a command as a stream of events.
    pub fn stream_execute(
        &mut self,
        command: &str,
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        let args = parse_command(command)?;
        let _ = &args;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;

        dispatch_execute!(inner, sandbox, sandbox.stream_execute_for_sdk(&args))
    }

    /// Reads file contents from the active sandbox backend.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SdkError> {
        self.ensure_backend("/bin/cat")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(s) => read_file_via_core_or_host(s, path),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(s) => read_file_via_core_or_host(s, path),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.read_file(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.read_file(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => s.read_file(path).map_err(map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => read_file_via_core(s, path),
        }
    }

    /// Writes file contents into the active sandbox backend.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SdkError> {
        self.ensure_backend("/bin/sh")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(s) => write_file_via_core_or_host(s, path, data),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(s) => write_file_via_core_or_host(s, path, data),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.write_file(path, data).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.write_file(path, data).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => {
                s.write_file(path, data).map_err(map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => write_file_via_core(s, path, data),
        }
    }

    #[cfg(feature = "vm")]
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    /// Sends a request through the controlled HTTP proxy.
    pub fn http_request(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.http_request_for_sdk(method, url, headers, body),
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "HTTP proxy only supports microVM backend",
                Some("set isolation to `MicroVm` and configure allowed_http_domains".to_string()),
            ))
        )
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
            IsolationLevel::Auto => IsolationLevel::Os,
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
    fn require_inner(&mut self) -> Result<&mut SandboxInner, SdkError> {
        self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "backend instance missing after initialization",
                Some("check if sandbox initialization was interrupted".to_string()),
            )
        })
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

    fn execute_with_sdk_options(
        &mut self,
        command: &str,
        options: SdkExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(sandbox) => {
                let args = build_fallback_command_args(command, &options)?;
                sandbox.execute_for_sdk(&args)
            }
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(sandbox) => {
                let args = build_fallback_command_args(command, &options)?;
                sandbox.execute_for_sdk(&args)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
                let args = parse_command(command)?;
                let start = std::time::Instant::now();
                sandbox
                    .execute_with_options(&args, options.to_guest_exec_options())
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => {
                let args = parse_command(command)?;
                let start = std::time::Instant::now();
                sandbox
                    .execute_with_options(&args, options.to_guest_exec_options())
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => {
                let args = parse_command(command)?;
                let start = std::time::Instant::now();
                sandbox
                    .execute_with_options(&args, options.to_guest_exec_options())
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(sandbox) => {
                let args = parse_command(command)?;
                sandbox.execute_for_sdk(&args)
            }
        }
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
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
    fn ensure_backend_for_snapshot(&mut self) -> Result<(), SdkError> {
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
    fn ensure_backend_for_file_ops(&mut self) -> Result<(), SdkError> {
        Err(SdkError::unsupported_backend("microvm"))
    }

    fn ensure_backend_for_pty(&mut self) -> Result<(), SdkError> {
        let isolation = match self.config.isolation {
            IsolationLevel::Auto => IsolationLevel::Os,
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

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn from_initialized_inner(inner: SandboxInner, config: Config) -> Self {
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
    #[cfg(feature = "vm")]
    use crate::vm_helpers::should_prepare_vm_pool;

    fn inner_is_initialized(sandbox: &Sandbox) -> bool {
        sandbox.inner.is_some()
    }

    fn active_isolation(sandbox: &Sandbox) -> Option<IsolationLevel> {
        sandbox.active_isolation
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
    fn destroy_uninitialized_sandbox_succeeds() {
        let sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        let result = sandbox.destroy();

        assert!(result.is_ok(), "销毁未初始化沙箱应成功: {:?}", result);
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn destroy_then_drop_does_not_panic() {
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
        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");
        let mut session = sandbox
            .create_pty("/bin/echo ready")
            .expect("创建 PTY 会话失败");

        assert_eq!(active_isolation(&sandbox), Some(IsolationLevel::Os));
        assert_eq!(session.wait().expect("等待 PTY 退出失败"), 0);

        drop(session);
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_returns_entries() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        std::fs::write(temp_dir.path().join("entry.txt"), "test").expect("写入测试文件失败");
        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        let entries = sandbox
            .list_dir(&temp_dir.path().to_string_lossy())
            .expect("list_dir 应成功");

        assert!(
            entries.iter().any(|entry| entry.name == "entry.txt"),
            "返回结果应包含测试文件: {entries:?}"
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_nonexistent_returns_error() {
        let mut sandbox = Sandbox::with_config(Config::default()).expect("创建沙箱失败");

        let result = sandbox.list_dir("/nonexistent/path");

        assert!(result.is_err(), "不存在路径应返回错误");
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

        assert!(result.is_err(), "文件路径应返回错误");
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_list_dir_empty_directory_returns_empty() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let entries = sandbox
            .list_dir(&temp_dir.path().to_string_lossy())
            .expect("list_dir 空目录应成功");

        assert!(entries.is_empty(), "空目录应返回空 Vec");
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_file_exists_returns_expected_result() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let file_path = temp_dir.path().join("exists.txt");
        std::fs::write(&file_path, "test").expect("写入测试文件失败");
        let missing_path = temp_dir.path().join("missing.txt");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        assert!(
            sandbox
                .file_exists(&file_path.to_string_lossy())
                .expect("file_exists 应成功"),
            "已存在文件应返回 true"
        );
        assert!(
            !sandbox
                .file_exists(&missing_path.to_string_lossy())
                .expect("file_exists 应成功"),
            "不存在文件应返回 false"
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

        sandbox
            .remove_file(&file_path.to_string_lossy())
            .expect("remove_file 应成功");

        assert!(
            !file_path.exists(),
            "remove_file 后测试文件不应继续存在: {}",
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

        sandbox
            .rename(
                &source_path.to_string_lossy(),
                &target_path.to_string_lossy(),
            )
            .expect("rename 应成功");

        assert!(!source_path.exists(), "源文件应不存在");
        assert!(target_path.exists(), "目标文件应存在");
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_stat_returns_file_metadata() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let file_path = temp_dir.path().join("stat.txt");
        std::fs::write(&file_path, "stat").expect("写入测试文件失败");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        let stat = sandbox
            .stat(&file_path.to_string_lossy())
            .expect("stat 应成功");

        assert_eq!(stat.path, file_path.to_string_lossy().as_ref());
        assert!(stat.is_file, "stat 应标记为普通文件");
        assert!(!stat.is_dir, "stat 不应标记为目录");
        assert!(stat.size > 0, "stat 应返回文件大小");
        assert!(stat.modified_ms.is_some(), "stat 应返回修改时间");
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_read_write_file_roundtrip_on_os_backend() {
        let temp_dir = tempfile::TempDir::new().expect("创建临时目录失败");
        let file_path = temp_dir.path().join("roundtrip.txt");
        let mut sandbox = Sandbox::new().expect("创建沙箱失败");

        sandbox
            .write_file(&file_path.to_string_lossy(), b"sdk-roundtrip")
            .expect("write_file 应成功");
        let data = sandbox
            .read_file(&file_path.to_string_lossy())
            .expect("read_file 应成功");

        assert_eq!(data, b"sdk-roundtrip");
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn test_sdk_execute_with_env_on_os_backend() {
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

        assert!(
            sandbox.file_exists("/../etc/passwd").is_err(),
            "路径遍历应被拒绝"
        );
        assert!(
            sandbox.remove_file("/tmp/../etc/passwd").is_err(),
            "路径遍历应被拒绝"
        );
        sandbox.destroy().expect("销毁沙箱失败");
    }

    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    #[test]
    fn create_pty_microvm_is_rejected() {
        let mut sandbox =
            Sandbox::with_config(Config::builder().isolation(IsolationLevel::MicroVm).build())
                .expect("创建沙箱失败");

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
            .build();
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
            .build();
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
        assert!(true, "VM list_dir 测试在当前平台不可用，此为编译验证骨架");
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
