//! mimobox-sdk: 统一 Agent Sandbox API
//!
//! 默认智能路由，高级用户完全可控。零配置即可安全执行代码，
//! 同时暴露完整三层配置供精细控制。

mod config;
mod error;
mod router;

pub use config::{Config, ConfigBuilder, IsolationLevel, NetworkPolicy, TrustLevel};
pub use error::SdkError;
pub use mimobox_core::{ErrorCode, PtyConfig, PtyEvent, PtySize};

use mimobox_core::{Sandbox as CoreSandbox, SandboxResult};
use router::resolve_isolation;
#[cfg(feature = "vm")]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
#[cfg(feature = "vm")]
use std::sync::Arc;
use std::sync::mpsc;
#[cfg(feature = "vm")]
use std::time::Duration;
use tracing::warn;

/// 沙箱执行结果
#[non_exhaustive]
pub struct ExecuteResult {
    /// 标准输出字节流。
    pub stdout: Vec<u8>,
    /// 标准错误字节流。
    pub stderr: Vec<u8>,
    /// 退出码；若进程未正常退出则可能为 `None`。
    pub exit_code: Option<i32>,
    /// 是否因超时被终止。
    pub timed_out: bool,
    /// 本次执行的总耗时。
    pub elapsed: std::time::Duration,
}

/// HTTP 代理响应结果。
pub struct HttpResponse {
    /// HTTP 状态码。
    pub status: u16,
    /// 归一化后的响应头集合。
    pub headers: std::collections::HashMap<String, String>,
    /// 响应体字节流。
    pub body: Vec<u8>,
}

/// 沙箱快照。
///
/// 该类型对外保持不透明，只暴露字节级访问方法。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSnapshot {
    inner: mimobox_core::SandboxSnapshot,
}

impl SandboxSnapshot {
    /// 从原始字节恢复快照。
    pub fn from_bytes(data: &[u8]) -> Result<Self, SdkError> {
        mimobox_core::SandboxSnapshot::from_bytes(data)
            .map(Self::from_core)
            .map_err(map_snapshot_bytes_error)
    }

    /// 从文件化快照的 `memory.bin` 创建快照。
    pub fn from_file(path: PathBuf) -> Result<Self, SdkError> {
        mimobox_core::SandboxSnapshot::from_file(path)
            .map(Self::from_core)
            .map_err(map_snapshot_bytes_error)
    }

    /// 返回文件模式快照对应的 memory 文件路径。
    pub fn memory_file_path(&self) -> Option<&Path> {
        self.inner.memory_file_path()
    }

    /// 返回快照字节切片，避免额外拷贝。
    ///
    /// 仅内存模式支持该操作；文件模式会返回错误。
    pub fn as_bytes(&self) -> Result<&[u8], SdkError> {
        self.inner.as_bytes().map_err(map_snapshot_bytes_error)
    }

    /// 返回快照字节副本。
    ///
    /// 文件模式下会重建完整的自描述快照字节。
    pub fn to_bytes(&self) -> Result<Vec<u8>, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        if let Some(memory_path) = self.inner.memory_file_path() {
            return mimobox_vm::MicrovmSnapshot::from_memory_file(memory_path)
                .and_then(|snapshot| snapshot.snapshot())
                .map_err(map_microvm_error);
        }

        self.inner.to_bytes().map_err(map_snapshot_bytes_error)
    }

    /// 消费快照并返回底层字节，避免额外拷贝。
    ///
    /// 文件模式下会重建完整的自描述快照字节。
    pub fn into_bytes(self) -> Result<Vec<u8>, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        if let Some(memory_path) = self.inner.memory_file_path().map(Path::to_path_buf) {
            return mimobox_vm::MicrovmSnapshot::from_memory_file(&memory_path)
                .and_then(|snapshot| snapshot.snapshot())
                .map_err(map_microvm_error);
        }

        self.inner.into_bytes().map_err(map_snapshot_bytes_error)
    }

    /// 返回快照大小（字节）。
    pub fn size(&self) -> usize {
        self.inner.size()
    }

    fn from_core(inner: mimobox_core::SandboxSnapshot) -> Self {
        Self { inner }
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
#[derive(Debug, Clone)]
/// 基于快照恢复池创建恢复态 microVM 的配置。
pub struct RestorePoolConfig {
    /// 恢复池目标大小。
    pub pool_size: usize,
    /// 恢复池使用的基础配置。
    pub base_config: Config,
}

#[cfg(all(feature = "vm", target_os = "linux"))]
#[derive(Clone)]
/// 基于快照的恢复池。
///
/// 该类型会预热一组可恢复的空壳 microVM，用于缩短 snapshot restore 到 ready 的延迟。
pub struct RestorePool {
    inner: Arc<mimobox_vm::RestorePool>,
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

#[cfg(feature = "vm")]
impl From<mimobox_vm::HttpResponse> for HttpResponse {
    fn from(value: mimobox_vm::HttpResponse) -> Self {
        Self {
            status: value.status,
            headers: value.headers,
            body: value.body,
        }
    }
}

/// 流式执行事件。
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// 一段标准输出数据。
    Stdout(Vec<u8>),
    /// 一段标准错误数据。
    Stderr(Vec<u8>),
    /// 进程退出并携带退出码。
    Exit(i32),
    /// 执行因超时被终止。
    TimedOut,
}

/// 交互式 PTY 会话。
///
/// 该类型封装底层后端提供的终端句柄，并暴露统一的输入、尺寸调整、事件接收与回收接口。
pub struct PtySession {
    inner: Box<dyn mimobox_core::PtySession>,
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession").finish_non_exhaustive()
    }
}

impl PtySession {
    /// 向 PTY 会话写入输入数据。
    pub fn send_input(&mut self, data: &[u8]) -> Result<(), SdkError> {
        self.inner.send_input(data).map_err(map_pty_session_error)
    }

    /// 调整 PTY 终端尺寸。
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), SdkError> {
        self.inner
            .resize(PtySize { cols, rows })
            .map_err(map_pty_session_error)
    }

    /// 返回 PTY 输出事件接收端。
    pub fn output(&self) -> &mpsc::Receiver<PtyEvent> {
        self.inner.output_rx()
    }

    /// 强制结束 PTY 会话。
    pub fn kill(&mut self) -> Result<(), SdkError> {
        self.inner.kill().map_err(map_pty_session_error)
    }

    /// 等待 PTY 进程退出并返回退出码。
    pub fn wait(&mut self) -> Result<i32, SdkError> {
        self.inner.wait().map_err(map_pty_session_error)
    }
}

trait ExecuteForSdk {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError>;
}

#[allow(dead_code)]
trait StreamExecuteForSdk {
    fn stream_execute_for_sdk(
        &mut self,
        args: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError>;
}

#[cfg(all(feature = "vm", target_os = "linux"))]
trait HttpRequestForSdk {
    fn http_request_for_sdk(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError>;
}

#[cfg(all(feature = "os", target_os = "linux"))]
impl ExecuteForSdk for mimobox_os::LinuxSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

#[cfg(all(feature = "os", target_os = "macos"))]
impl ExecuteForSdk for mimobox_os::MacOsSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl ExecuteForSdk for mimobox_vm::MicrovmSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl StreamExecuteForSdk for mimobox_vm::MicrovmSandbox {
    fn stream_execute_for_sdk(
        &mut self,
        args: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        self.stream_execute(args)
            .map(bridge_vm_stream)
            .map_err(map_microvm_error)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl HttpRequestForSdk for mimobox_vm::MicrovmSandbox {
    fn http_request_for_sdk(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError> {
        let request = mimobox_vm::HttpRequest::new(
            method,
            url,
            headers,
            body.map(|item| item.to_vec()),
            None,
            None,
        )
        .map_err(map_http_proxy_error)?;
        self.http_request(request)
            .map(HttpResponse::from)
            .map_err(map_microvm_error)
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
            .map_err(map_microvm_error)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl StreamExecuteForSdk for mimobox_vm::PooledVm {
    fn stream_execute_for_sdk(
        &mut self,
        args: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        self.stream_execute(args)
            .map(bridge_vm_stream)
            .map_err(map_microvm_error)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl HttpRequestForSdk for mimobox_vm::PooledVm {
    fn http_request_for_sdk(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError> {
        let request = mimobox_vm::HttpRequest::new(
            method,
            url,
            headers,
            body.map(|item| item.to_vec()),
            None,
            None,
        )
        .map_err(map_http_proxy_error)?;
        self.http_request(request)
            .map(HttpResponse::from)
            .map_err(map_microvm_error)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl ExecuteForSdk for mimobox_vm::PooledRestoreVm {
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
            .map_err(map_microvm_error)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl StreamExecuteForSdk for mimobox_vm::PooledRestoreVm {
    fn stream_execute_for_sdk(
        &mut self,
        args: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        self.stream_execute(args)
            .map(bridge_vm_stream)
            .map_err(map_microvm_error)
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl HttpRequestForSdk for mimobox_vm::PooledRestoreVm {
    fn http_request_for_sdk(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError> {
        let request = mimobox_vm::HttpRequest::new(
            method,
            url,
            headers,
            body.map(|item| item.to_vec()),
            None,
            None,
        )
        .map_err(map_http_proxy_error)?;
        self.http_request(request)
            .map(HttpResponse::from)
            .map_err(map_microvm_error)
    }
}

#[cfg(feature = "wasm")]
impl ExecuteForSdk for mimobox_wasm::WasmSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
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
    #[cfg(all(feature = "vm", target_os = "linux"))]
    RestoredPooledMicroVm(mimobox_vm::PooledRestoreVm),
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

impl Sandbox {
    /// 零配置创建沙箱，自动路由到最优隔离层级。
    pub fn new() -> Result<Self, SdkError> {
        Self::with_config(Config::default())
    }

    /// 使用完整配置创建沙箱。
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
            let inner = self.inner.as_mut().ok_or_else(|| {
                SdkError::sandbox(
                    ErrorCode::SandboxCreateFailed,
                    "后端初始化后缺失实例",
                    Some("检查沙箱初始化流程是否被中断".to_string()),
                )
            })?;

            let snapshot = match inner {
                SandboxInner::MicroVm(sandbox) => sandbox.snapshot().map_err(map_microvm_error)?,
                SandboxInner::PooledMicroVm(sandbox) => {
                    sandbox.snapshot().map_err(map_microvm_error)?
                }
                SandboxInner::RestoredPooledMicroVm(sandbox) => {
                    sandbox.snapshot().map_err(map_microvm_error)?
                }
                _ => {
                    return Err(SdkError::sandbox(
                        ErrorCode::UnsupportedPlatform,
                        "当前后端不支持快照能力",
                        Some(
                            "将 isolation 设置为 `MicroVm` 并在 Linux + vm feature 构建上运行"
                                .to_string(),
                        ),
                    ));
                }
            };

            return Ok(SandboxSnapshot::from_core(snapshot));
        }

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        {
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "当前构建不支持快照能力",
                Some("仅在 Linux + vm feature 构建上使用快照能力".to_string()),
            ))
        }
    }

    /// 从快照恢复新沙箱。
    pub fn from_snapshot(snapshot: &SandboxSnapshot) -> Result<Self, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        {
            let sandbox =
                mimobox_vm::MicrovmSandbox::restore(&snapshot.inner).map_err(map_microvm_error)?;
            return Ok(Self::from_initialized_inner(
                SandboxInner::MicroVm(sandbox),
                Config::builder().isolation(IsolationLevel::MicroVm).build(),
            ));
        }

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        {
            let _ = snapshot;
            Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "当前构建不支持从快照恢复沙箱",
                Some("仅在 Linux + vm feature 构建上使用快照恢复能力".to_string()),
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
        let inner = self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "后端初始化后缺失实例",
                Some("检查沙箱初始化流程是否被中断".to_string()),
            )
        })?;

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
        let inner = self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "后端初始化后缺失实例",
                Some("检查沙箱初始化流程是否被中断".to_string()),
            )
        })?;
        dispatch_execute!(inner, s, s.execute_for_sdk(&args))
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
            return Err(SdkError::Config("PTY 命令不能为空".to_string()));
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
            return Err(SdkError::Config("PTY 命令不能为空".to_string()));
        }

        self.ensure_backend_for_pty()?;
        let inner = self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "后端初始化后缺失实例",
                Some("检查沙箱初始化流程是否被中断".to_string()),
            )
        })?;

        let session =
            match inner {
                #[cfg(all(feature = "os", target_os = "linux"))]
                SandboxInner::Os(sandbox) => CoreSandbox::create_pty(sandbox, config.clone())
                    .map_err(map_pty_create_error)?,
                #[cfg(all(feature = "os", target_os = "macos"))]
                SandboxInner::OsMac(sandbox) => CoreSandbox::create_pty(sandbox, config.clone())
                    .map_err(map_pty_create_error)?,
                #[cfg(all(feature = "vm", target_os = "linux"))]
                SandboxInner::MicroVm(sandbox) => CoreSandbox::create_pty(sandbox, config.clone())
                    .map_err(map_pty_create_error)?,
                #[cfg(all(feature = "vm", target_os = "linux"))]
                SandboxInner::PooledMicroVm(_) => {
                    return Err(SdkError::sandbox(
                        ErrorCode::UnsupportedPlatform,
                        "PTY 会话当前仅支持 OS 级后端，microVM 预热池暂不支持",
                        Some("将 isolation 设置为 `Os` 或使用默认 Auto".to_string()),
                    ));
                }
                #[cfg(all(feature = "vm", target_os = "linux"))]
                SandboxInner::RestoredPooledMicroVm(_) => {
                    return Err(SdkError::sandbox(
                        ErrorCode::UnsupportedPlatform,
                        "PTY 会话当前仅支持 OS 级后端，恢复池返回的 microVM 暂不支持",
                        Some("将 isolation 设置为 `Os` 或使用默认 Auto".to_string()),
                    ));
                }
                #[cfg(feature = "wasm")]
                SandboxInner::Wasm(sandbox) => {
                    CoreSandbox::create_pty(sandbox, config).map_err(map_pty_create_error)?
                }
            };

        Ok(PtySession { inner: session })
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并为本次调用附加环境变量。
    pub fn execute_with_env(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(command, env, None)
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并覆写本次调用的超时时间。
    pub fn execute_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(command, HashMap::new(), Some(timeout))
    }

    #[cfg(feature = "vm")]
    /// 在 microVM 后端中执行命令，并同时覆写环境变量与超时时间。
    pub fn execute_with_env_and_timeout(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
        timeout: Duration,
    ) -> Result<ExecuteResult, SdkError> {
        self.execute_with_vm_options(command, env, Some(timeout))
    }

    /// 以流式事件形式执行命令。
    pub fn stream_execute(
        &mut self,
        command: &str,
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
        let args = parse_command(command)?;
        let _ = &args;
        self.ensure_backend(command)?;
        let inner = self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "后端初始化后缺失实例",
                Some("检查沙箱初始化流程是否被中断".to_string()),
            )
        })?;

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => sandbox.stream_execute_for_sdk(&args),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => sandbox.stream_execute_for_sdk(&args),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => sandbox.stream_execute_for_sdk(&args),
            _ => Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "流式执行仅支持 microVM 后端",
                Some(
                    "将 isolation 设置为 `MicroVm` 并在 Linux + vm feature 构建上运行".to_string(),
                ),
            )),
        }
    }

    #[cfg(feature = "vm")]
    /// 从 microVM 沙箱中读取文件内容。
    pub fn read_file(&mut self, _path: &str) -> Result<Vec<u8>, SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "后端初始化后缺失实例",
                Some("检查沙箱初始化流程是否被中断".to_string()),
            )
        })?;

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => sandbox.read_file(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => {
                sandbox.read_file(_path).map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => {
                sandbox.read_file(_path).map_err(map_microvm_error)
            }
            _ => Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "文件传输仅支持 microVM 后端",
                Some(
                    "将 isolation 设置为 `MicroVm` 并在 Linux + vm feature 构建上运行".to_string(),
                ),
            )),
        }
    }

    #[cfg(feature = "vm")]
    /// 向 microVM 沙箱中写入文件内容。
    pub fn write_file(&mut self, _path: &str, _data: &[u8]) -> Result<(), SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "后端初始化后缺失实例",
                Some("检查沙箱初始化流程是否被中断".to_string()),
            )
        })?;

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
                sandbox.write_file(_path, _data).map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => {
                sandbox.write_file(_path, _data).map_err(map_microvm_error)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => {
                sandbox.write_file(_path, _data).map_err(map_microvm_error)
            }
            _ => Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "文件传输仅支持 microVM 后端",
                Some(
                    "将 isolation 设置为 `MicroVm` 并在 Linux + vm feature 构建上运行".to_string(),
                ),
            )),
        }
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
        let inner = self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "后端初始化后缺失实例",
                Some("检查沙箱初始化流程是否被中断".to_string()),
            )
        })?;

        match inner {
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(sandbox) => {
                sandbox.http_request_for_sdk(method, url, headers, body)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(sandbox) => {
                sandbox.http_request_for_sdk(method, url, headers, body)
            }
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(sandbox) => {
                sandbox.http_request_for_sdk(method, url, headers, body)
            }
            _ => Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "HTTP 代理仅支持 microVM 后端",
                Some("将 isolation 设置为 `MicroVm` 并配置 allowed_http_domains".to_string()),
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

    /// 销毁沙箱并释放资源。
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
    fn execute_with_vm_options(
        &mut self,
        command: &str,
        env: HashMap<String, String>,
        timeout: Option<Duration>,
    ) -> Result<ExecuteResult, SdkError> {
        let args = parse_command(command)?;
        self.ensure_backend(command)?;
        let inner = self.inner.as_mut().ok_or_else(|| {
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                "后端初始化后缺失实例",
                Some("检查沙箱初始化流程是否被中断".to_string()),
            )
        })?;
        let options = mimobox_vm::GuestExecOptions { env, timeout };

        match inner {
            SandboxInner::MicroVm(sandbox) => {
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
            }
            SandboxInner::PooledMicroVm(sandbox) => {
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
            }
            SandboxInner::RestoredPooledMicroVm(sandbox) => {
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
            }
            _ => Err(SdkError::sandbox(
                ErrorCode::UnsupportedPlatform,
                "命令级 env/timeout 仅支持 microVM 后端",
                Some(
                    "将 isolation 设置为 `MicroVm` 并在 Linux + vm feature 构建上运行".to_string(),
                ),
            )),
        }
    }

    #[cfg(all(feature = "vm", not(target_os = "linux")))]
    fn execute_with_vm_options(
        &mut self,
        _command: &str,
        _env: HashMap<String, String>,
        _timeout: Option<Duration>,
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
                    "文件传输仅支持 microVM 后端",
                    Some("将 isolation 设置为 `MicroVm`".to_string()),
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
                    "当前沙箱后端不支持快照能力",
                    Some("将 isolation 设置为 `MicroVm` 后重新创建沙箱".to_string()),
                )),
                None => Err(SdkError::sandbox(
                    ErrorCode::SandboxCreateFailed,
                    "沙箱后端实例存在但未记录隔离层级",
                    Some("检查沙箱初始化流程是否被中断".to_string()),
                )),
            };
        }

        let isolation = match self.config.isolation {
            IsolationLevel::Auto | IsolationLevel::MicroVm => IsolationLevel::MicroVm,
            IsolationLevel::Os | IsolationLevel::Wasm => {
                return Err(SdkError::sandbox(
                    ErrorCode::UnsupportedPlatform,
                    "当前配置的后端不支持快照能力",
                    Some("将 isolation 设置为 `MicroVm`".to_string()),
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
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "os", target_os = "macos"))]
        SandboxInner::OsMac(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::MicroVm(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::PooledMicroVm(pooled) => {
            drop(pooled);
            Ok(())
        }
        #[cfg(all(feature = "vm", target_os = "linux"))]
        SandboxInner::RestoredPooledMicroVm(pooled) => {
            drop(pooled);
            Ok(())
        }
        #[cfg(feature = "wasm")]
        SandboxInner::Wasm(sandbox) => sandbox
            .destroy()
            .map_err(SdkError::from_sandbox_destroy_error),
    }
}

fn parse_command(command: &str) -> Result<Vec<String>, SdkError> {
    shlex::split(command)
        .ok_or_else(|| SdkError::Config("命令解析失败：shell 风格引号不匹配".to_string()))
}

fn map_pty_create_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::UnsupportedOperation(message) => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            message,
            Some("将 isolation 设置为 `Os` 或使用默认 Auto".to_string()),
        ),
        other => SdkError::sandbox(ErrorCode::SandboxCreateFailed, other.to_string(), None),
    }
}

fn map_pty_session_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::UnsupportedOperation(message) => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            message,
            Some("将 isolation 设置为 `Os` 或使用默认 Auto".to_string()),
        ),
        mimobox_core::SandboxError::Timeout => SdkError::sandbox(
            ErrorCode::CommandTimeout,
            "PTY 会话执行超时",
            Some("增大 Config.timeout 或 PtyConfig.timeout".to_string()),
        ),
        other => SdkError::sandbox(ErrorCode::SandboxDestroyed, other.to_string(), None),
    }
}

fn map_snapshot_bytes_error(error: mimobox_core::SandboxError) -> SdkError {
    match error {
        mimobox_core::SandboxError::InvalidSnapshot => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            "无效的沙箱快照",
            Some("文件模式快照请优先使用 from_snapshot()/restore() 或 to_bytes()".to_string()),
        ),
        mimobox_core::SandboxError::ExecutionFailed(message) => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some("确认快照数据非空且来源于 mimobox microVM 快照".to_string()),
        ),
        mimobox_core::SandboxError::Io(error) => SdkError::Io(error),
        other => SdkError::sandbox(ErrorCode::InvalidConfig, other.to_string(), None),
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
fn bridge_vm_stream(
    source: mpsc::Receiver<mimobox_vm::StreamEvent>,
) -> mpsc::Receiver<StreamEvent> {
    let (tx, rx) = mpsc::sync_channel(32);
    std::thread::spawn(move || {
        while let Ok(event) = source.recv() {
            let mapped = match event {
                mimobox_vm::StreamEvent::Stdout(data) => StreamEvent::Stdout(data),
                mimobox_vm::StreamEvent::Stderr(data) => StreamEvent::Stderr(data),
                mimobox_vm::StreamEvent::Exit(code) => StreamEvent::Exit(code),
                mimobox_vm::StreamEvent::TimedOut => StreamEvent::TimedOut,
            };
            if tx.send(mapped).is_err() {
                break;
            }
        }
    });
    rx
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
    let sandbox_config = config.to_sandbox_config();
    let pool_config = mimobox_vm::VmPoolConfig {
        min_size: 1,
        max_size: 4,
        max_idle_duration: std::time::Duration::from_secs(60),
        health_check_interval: None,
    };

    match mimobox_vm::VmPool::new_with_base(sandbox_config, microvm_config, pool_config) {
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
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::RestoredPooledMicroVm(_)) => false,
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
        #[cfg(all(feature = "vm", target_os = "linux"))]
        Some(SandboxInner::RestoredPooledMicroVm(_)) => false,
        None => false,
    }
}

#[cfg(test)]
fn parse_for_test(command: &str) -> Result<Vec<String>, SdkError> {
    parse_command(command)
}

#[cfg(feature = "vm")]
fn map_http_proxy_error(error: mimobox_vm::HttpProxyError) -> SdkError {
    use mimobox_vm::HttpProxyError;

    match error {
        HttpProxyError::DeniedHost(message) => SdkError::sandbox(
            ErrorCode::HttpDeniedHost,
            message,
            Some("确认目标域名在 allowed_http_domains 白名单内".to_string()),
        ),
        HttpProxyError::DnsRebind(message) => SdkError::sandbox(
            ErrorCode::HttpDeniedHost,
            message,
            Some("目标域名解析到了内网或回环地址，拒绝访问".to_string()),
        ),
        HttpProxyError::Timeout => SdkError::sandbox(
            ErrorCode::HttpTimeout,
            "HTTP 请求超时",
            Some("检查目标服务可达性或提高 timeout 配置".to_string()),
        ),
        HttpProxyError::BodyTooLarge => SdkError::sandbox(
            ErrorCode::HttpBodyTooLarge,
            "HTTP body 超出大小限制",
            Some("缩小请求/响应体或调低传输规模".to_string()),
        ),
        HttpProxyError::ConnectFail(message) => SdkError::sandbox(
            ErrorCode::HttpConnectFail,
            message,
            Some("检查目标服务连通性和端口可达性".to_string()),
        ),
        HttpProxyError::TlsFail(message) => SdkError::sandbox(
            ErrorCode::HttpTlsFail,
            message,
            Some("检查目标站点证书链和 TLS 配置".to_string()),
        ),
        HttpProxyError::InvalidUrl(message) => SdkError::sandbox(
            ErrorCode::HttpInvalidUrl,
            message,
            Some("仅支持 HTTPS URL，且不得使用 IP 直连".to_string()),
        ),
        HttpProxyError::Internal(message) => SdkError::Config(message),
    }
}

#[cfg(feature = "vm")]
fn map_microvm_error(error: mimobox_vm::MicrovmError) -> SdkError {
    use mimobox_vm::MicrovmError;

    match error {
        MicrovmError::UnsupportedPlatform => SdkError::sandbox(
            ErrorCode::UnsupportedPlatform,
            "当前平台不支持 KVM microVM 后端",
            Some("仅在 Linux + vm feature 构建上使用 microVM 能力".to_string()),
        ),
        MicrovmError::InvalidConfig(message) => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some("检查 microVM 配置、内核/rootfs 路径与内存参数".to_string()),
        ),
        MicrovmError::Lifecycle(message) => {
            let code = if message.contains("释放") || message.contains("Destroyed") {
                ErrorCode::SandboxDestroyed
            } else {
                ErrorCode::SandboxNotReady
            };
            SdkError::sandbox(
                code,
                message,
                Some("确认沙箱已创建完成且当前状态允许执行该操作".to_string()),
            )
        }
        MicrovmError::HttpProxy(error) => map_http_proxy_error(error),
        MicrovmError::Backend(message) => {
            if message.contains("文件路径错误") {
                return SdkError::sandbox(
                    ErrorCode::FileNotFound,
                    message,
                    Some("确认目标文件存在且路径位于允许访问范围内".to_string()),
                );
            }
            if message.contains("文件权限错误") {
                return SdkError::sandbox(
                    ErrorCode::FilePermissionDenied,
                    message,
                    Some("检查文件权限和沙箱挂载策略".to_string()),
                );
            }
            SdkError::sandbox(
                ErrorCode::SandboxCreateFailed,
                message,
                Some("确认 KVM 可用且 guest 运行时状态正常".to_string()),
            )
        }
        MicrovmError::SnapshotFormat(message) => SdkError::sandbox(
            ErrorCode::InvalidConfig,
            message,
            Some("确认快照来自兼容版本的 mimobox microVM".to_string()),
        ),
        MicrovmError::Io(error) => SdkError::sandbox(
            ErrorCode::SandboxCreateFailed,
            error.to_string(),
            Some("检查快照文件读写与底层虚拟化资源状态".to_string()),
        ),
    }
}

#[cfg(feature = "vm")]
fn map_pool_error(error: mimobox_vm::PoolError) -> SdkError {
    match error {
        mimobox_vm::PoolError::InvalidConfig { min_size, max_size } => SdkError::Config(format!(
            "预热池配置无效: min_size={min_size}, max_size={max_size}"
        )),
        mimobox_vm::PoolError::StatePoisoned => {
            SdkError::Config("预热池内部状态锁已中毒".to_string())
        }
        mimobox_vm::PoolError::Microvm(error) => map_microvm_error(error),
    }
}

#[cfg(all(feature = "vm", target_os = "linux"))]
fn map_restore_pool_error(error: mimobox_vm::RestorePoolError) -> SdkError {
    match error {
        mimobox_vm::RestorePoolError::InvalidConfig { min_size, max_size } => SdkError::Config(
            format!("恢复池配置无效: min_size={min_size}, max_size={max_size}"),
        ),
        mimobox_vm::RestorePoolError::StatePoisoned => SdkError::sandbox(
            ErrorCode::SandboxDestroyed,
            "恢复池内部状态锁已中毒",
            Some("销毁当前恢复池并重新创建".to_string()),
        ),
        mimobox_vm::RestorePoolError::Microvm(error) => map_microvm_error(error),
    }
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
            Err(other) => panic!("期望 SDK 将 UnsupportedOperation 映射为 UnsupportedPlatform，实际为: {other}"),
            Ok(_) => panic!("期望 SDK PTY 在 microVM 下被拒绝，实际却创建成功"),
        }

        sandbox.destroy().expect("销毁沙箱失败");
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
