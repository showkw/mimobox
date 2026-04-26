use crate::config::{Config, IsolationLevel};
use crate::dispatch::ExecuteForSdk;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::dispatch::HttpRequestForSdk;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::dispatch::StreamExecuteForSdk;
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
use mimobox_core::{ErrorCode, PtyConfig, PtySize, Sandbox as CoreSandbox};
#[cfg(feature = "vm")]
use std::collections::HashMap;
#[cfg(feature = "vm")]
use std::sync::Arc;
use std::sync::mpsc;
#[cfg(feature = "vm")]
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
    /// 根据基础配置创建一个固定大小的恢复池。
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

    /// 使用给定快照恢复一个新的沙箱实例。
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

    /// 返回当前恢复池中的空闲实例数量。
    pub fn idle_count(&self) -> usize {
        self.inner.idle_count()
    }

    /// 将恢复池预热到至少 `target` 个空闲实例。
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

/// VM-only 三变体分派宏（MicroVm / PooledMicroVm / RestoredPooledMicroVm）。
/// 用于 read_file、write_file、http_request、stream_execute、execute_with_vm_options 等
/// 仅 VM 后端支持的方法。非 VM 变体统一走 fallback 表达式。
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

    /// 拍摄当前沙箱快照。
    ///
    /// 该能力当前仅在 `Linux + vm feature + MicroVm` 后端上可用。
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

    /// 从快照恢复新沙箱。
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

    /// 从当前沙箱 fork 一个独立的副本。
    ///
    /// 仅 microVM 后端支持。fork 出的沙箱与原沙箱共享未修改的内存页（CoW），
    /// 写入时各自持有私有副本。
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

    /// 在沙箱中执行命令。
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

    /// 列出指定路径下的目录条目。
    ///
    /// 返回目录内所有条目的名称、类型、大小和符号链接标记。
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
            SandboxInner::MicroVm(s) => {
                mimobox_core::Sandbox::list_dir(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(_) | SandboxInner::RestoredPooledMicroVm(_) => {
                Err(SdkError::sandbox(
                    mimobox_core::ErrorCode::UnsupportedPlatform,
                    "list_dir is not yet supported for pooled VM backends",
                    None,
                ))
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => {
                mimobox_core::Sandbox::list_dir(s, path).map_err(|err| match err {
                    mimobox_core::SandboxError::Io(io_err) => SdkError::Io(io_err),
                    other => SdkError::from_sandbox_execute_error(other),
                })
            }
        }
    }

    /// 创建交互式终端会话。
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

    /// 使用完整 `PtyConfig` 创建交互式终端会话。
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

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并为本次调用附加环境变量。
    pub fn execute_with_env(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(
            command,
            mimobox_vm::GuestExecOptions {
                env,
                timeout: None,
                cwd: None,
            },
        )
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并覆写本次调用的超时时间。
    pub fn execute_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(
            command,
            mimobox_vm::GuestExecOptions {
                env: HashMap::new(),
                timeout: Some(timeout),
                cwd: None,
            },
        )
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并同时覆写环境变量与超时时间。
    pub fn execute_with_env_and_timeout(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(
            command,
            mimobox_vm::GuestExecOptions {
                env,
                timeout: Some(timeout),
                cwd: None,
            },
        )
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并覆写本次调用的工作目录。
    pub fn execute_with_cwd(
        &mut self,
        command: &str,
        cwd: &str,
    ) -> Result<ExecuteResult, SdkError> {
        let options = mimobox_vm::GuestExecOptions {
            cwd: Some(cwd.to_string()),
            ..Default::default()
        };
        self.execute_with_vm_options_full(command, options)
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并使用完整的单命令执行选项。
    pub fn execute_with_vm_options_full(
        &mut self,
        command: &str,
        options: mimobox_vm::GuestExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options_full_inner(command, options)
    }

    /// 以流式事件形式执行命令。
    pub fn stream_execute(
        &mut self,
        command: &str,
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        let args = parse_command(command)?;
        let _ = &args;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.stream_execute_for_sdk(&args),
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "streaming execution only supports microVM backend",
                Some(
                    "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                        .to_string()
                ),
            ))
        )
    }

    #[cfg(feature = "vm")]
    /// 从 microVM 沙箱中读取文件内容。
    pub fn read_file(&mut self, _path: &str) -> Result<Vec<u8>, SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.read_file(_path).map_err(map_microvm_error),
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "file transfer only supports microVM backend",
                Some(
                    "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                        .to_string()
                ),
            ))
        )
    }

    #[cfg(feature = "vm")]
    /// 向 microVM 沙箱中写入文件内容。
    pub fn write_file(&mut self, _path: &str, _data: &[u8]) -> Result<(), SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.write_file(_path, _data).map_err(map_microvm_error),
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "file transfer only supports microVM backend",
                Some(
                    "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                        .to_string()
                ),
            ))
        )
    }

    #[cfg(feature = "vm")]
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    /// 通过受控 HTTP 代理发起请求。
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

    /// 等待当前沙箱后端进入可用状态。
    ///
    /// microVM 后端会执行 PING/PONG readiness probe；OS/Wasm 后端初始化后直接视为就绪。
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

    /// 返回当前 SDK 沙箱是否已经初始化为可用后端。
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

    /// 获取已初始化的后端实例引用，若不存在则返回统一错误。
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

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn execute_with_vm_options(
        &mut self,
        command: &str,
        options: mimobox_vm::GuestExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options_full_inner(command, options)
    }

    #[cfg(all(feature = "vm", target_os = "linux"))]
    fn execute_with_vm_options_full_inner(
        &mut self,
        command: &str,
        options: mimobox_vm::GuestExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        let args = parse_command(command)?;
        self.ensure_backend(command)?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            {
                let start = std::time::Instant::now();
                sandbox
                    .execute_with_options(&args, options)
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(map_microvm_error)
            },
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "per-command VM options only support microVM backend",
                Some(
                    "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                        .to_string()
                ),
            ))
        )
    }

    #[cfg(all(feature = "vm", not(target_os = "linux")))]
    fn execute_with_vm_options(
        &mut self,
        _command: &str,
        _options: mimobox_vm::GuestExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        Err(SdkError::unsupported_backend("microvm"))
    }

    #[cfg(all(feature = "vm", not(target_os = "linux")))]
    fn execute_with_vm_options_full_inner(
        &mut self,
        _command: &str,
        _options: mimobox_vm::GuestExecOptions,
    ) -> Result<ExecuteResult, SdkError> {
        Err(SdkError::unsupported_backend("microvm"))
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
    fn list_dir_returns_unsupported_for_pooled_vm_backends() {
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

        sandbox
            .execute("/bin/echo init")
            .expect("初始化 VM 后端失败");

        match sandbox.list_dir("/tmp") {
            Err(SdkError::Sandbox {
                code: ErrorCode::UnsupportedPlatform,
                ..
            }) => {}
            Ok(_) => {}
            Err(other) => panic!("list_dir 返回了意外的错误: {other}"),
        }

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
