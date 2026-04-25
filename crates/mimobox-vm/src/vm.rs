use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult, SandboxSnapshot};
use tracing::debug;

use crate::http_proxy::{HttpProxyError, HttpRequest, HttpResponse};
use crate::snapshot::MicrovmSnapshot;
#[cfg(all(target_os = "linux", feature = "kvm"))]
use crate::snapshot::load_state_from_memory_file;

#[cfg(all(target_os = "linux", feature = "kvm", not(feature = "zerocopy-fork")))]
use crate::snapshot::{FILE_SNAPSHOT_VERSION, SnapshotStateFile, create_snapshot_dir};
use crate::vm_assets::resolve_vm_assets_dir;

#[cfg(all(target_os = "linux", feature = "kvm"))]
use crate::kvm::{KvmBackend, restore_runtime_state};

/// microVM-specific configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MicrovmConfig {
    /// Number of vCPUs.
    pub vcpu_count: u8,
    /// Guest memory size in MiB.
    pub memory_mb: u32,
    /// Optional CPU time quota in microseconds.
    #[serde(default)]
    pub cpu_quota_us: Option<u64>,
    /// Guest kernel image path.
    pub kernel_path: PathBuf,
    /// Guest rootfs path.
    pub rootfs_path: PathBuf,
}

impl Default for MicrovmConfig {
    fn default() -> Self {
        let assets_dir = resolve_vm_assets_dir(
            env::var_os("VM_ASSETS_DIR").map(PathBuf::from),
            env::var_os("HOME").map(PathBuf::from),
        )
        .unwrap_or_else(|_| PathBuf::from("/var/lib/mimobox/vm"));

        Self {
            vcpu_count: 1,
            memory_mb: 256,
            cpu_quota_us: None,
            kernel_path: assets_dir.join("vmlinux"),
            rootfs_path: assets_dir.join("rootfs.cpio.gz"),
        }
    }
}

impl MicrovmConfig {
    /// Returns the guest memory size in bytes.
    pub fn memory_bytes(&self) -> Result<usize, MicrovmError> {
        let bytes = u64::from(self.memory_mb)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| {
                MicrovmError::InvalidConfig("memory_mb overflow when converting to bytes".into())
            })?;
        usize::try_from(bytes).map_err(|_| {
            MicrovmError::InvalidConfig(
                "required memory size exceeds platform address space".into(),
            )
        })
    }

    /// Validates the base microVM configuration.
    pub fn validate(&self) -> Result<(), MicrovmError> {
        if self.vcpu_count == 0 {
            return Err(MicrovmError::InvalidConfig(
                "vcpu_count must not be 0".into(),
            ));
        }

        if self.memory_mb < 64 {
            return Err(MicrovmError::InvalidConfig(
                "memory_mb must not be less than 64".into(),
            ));
        }

        if self.kernel_path.as_os_str().is_empty() {
            return Err(MicrovmError::InvalidConfig(
                "kernel_path must not be empty".into(),
            ));
        }

        if self.rootfs_path.as_os_str().is_empty() {
            return Err(MicrovmError::InvalidConfig(
                "rootfs_path must not be empty".into(),
            ));
        }

        if !self.kernel_path.exists() {
            return Err(MicrovmError::InvalidConfig(format!(
                "kernel_path does not exist: {}",
                self.kernel_path.display()
            )));
        }

        if !self.rootfs_path.exists() {
            return Err(MicrovmError::InvalidConfig(format!(
                "rootfs_path does not exist: {}",
                self.rootfs_path.display()
            )));
        }

        Ok(())
    }
}

/// microVM lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicrovmState {
    /// Instance has been created but is not yet executable.
    Created,
    /// Instance is ready to execute commands or file operations.
    Ready,
    /// Instance is currently executing a command or transferring data.
    Running,
    /// Instance has been destroyed and cannot be reused.
    Destroyed,
}

/// Guest command execution result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestCommandResult {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Exit code, or `None` if the process did not exit normally.
    pub exit_code: Option<i32>,
    /// Whether execution was terminated by a timeout.
    pub timed_out: bool,
}

/// Guest command-level execution options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestExecOptions {
    /// Environment variables that only apply to this command.
    pub env: HashMap<String, String>,
    /// Timeout that only applies to this command.
    pub timeout: Option<Duration>,
    /// Working directory that only applies to this command.
    pub cwd: Option<String>,
}

/// Guest streaming execution event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// A chunk of standard output data.
    Stdout(Vec<u8>),
    /// A chunk of standard error data.
    Stderr(Vec<u8>),
    /// Process exited with an exit code.
    Exit(i32),
    /// Execution was terminated by a timeout.
    TimedOut,
}

/// microVM-level error.
/// microVM 生命周期错误的具体语义分类。
///
/// 用于替代原来的字符串匹配模式，提供编译期穷尽检查。
#[derive(Debug, Clone, thiserror::Error)]
pub enum LifecycleError {
    /// 当前状态不允许请求的操作。
    #[error("{message}")]
    InvalidState {
        /// 操作要求的生命周期状态。
        expected: String,
        /// 当前实际生命周期状态描述。
        current: String,
        /// 对外展示的原始错误消息。
        message: String,
    },
    /// 沙箱已被销毁，无法复用。
    #[error("{0}")]
    Destroyed(String),
    /// VM 实例已归还池中，无法再使用。
    #[error("{0}")]
    Released(String),
    /// 仅 Ready 状态允许快照。
    #[error("snapshot only allowed in Ready state")]
    NotReady,
    /// 仅 Ready 状态允许 fork。
    #[error("fork only allowed in Ready state")]
    NotReadyForFork,
    /// vsock 命令通道未连接。
    #[error("vsock command channel is not connected")]
    VsockNotConnected,
    /// vsock 命令通道不可用。
    #[error("vsock command channel unavailable")]
    VsockUnavailable,
    /// 其他生命周期错误。
    #[error("{0}")]
    Other(String),
}

/// microVM-level error.
#[derive(Debug, thiserror::Error)]
pub enum MicrovmError {
    /// KVM microVMs are not supported on the current platform or build configuration.
    #[error("KVM microVM backend not supported on current platform")]
    UnsupportedPlatform,

    /// microVM configuration is invalid.
    #[error("invalid microVM config: {0}")]
    InvalidConfig(String),

    /// Current lifecycle state does not allow the requested operation.
    #[error("microVM lifecycle error: {0}")]
    Lifecycle(LifecycleError),

    /// KVM or guest protocol error.
    #[error("KVM backend error: {0}")]
    Backend(String),

    /// Controlled HTTP proxy error.
    #[error(transparent)]
    HttpProxy(#[from] HttpProxyError),

    /// Snapshot format is invalid or incompatible.
    #[error("invalid snapshot format: {0}")]
    SnapshotFormat(String),

    /// Standard library I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<MicrovmError> for SandboxError {
    fn from(value: MicrovmError) -> Self {
        match value {
            MicrovmError::UnsupportedPlatform => SandboxError::Unsupported,
            MicrovmError::InvalidConfig(message)
            | MicrovmError::Backend(message)
            | MicrovmError::HttpProxy(crate::http_proxy::HttpProxyError::Internal(message))
            | MicrovmError::SnapshotFormat(message) => SandboxError::ExecutionFailed(message),
            MicrovmError::Lifecycle(error) => SandboxError::ExecutionFailed(error.to_string()),
            MicrovmError::HttpProxy(error) => SandboxError::ExecutionFailed(error.to_string()),
            MicrovmError::Io(error) => SandboxError::Io(error),
        }
    }
}

#[allow(dead_code)]
enum BackendHandle {
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    Kvm(Box<KvmBackend>),
    Unsupported,
}

impl BackendHandle {
    fn create(base_config: SandboxConfig, config: MicrovmConfig) -> Result<Self, MicrovmError> {
        #[cfg(all(target_os = "linux", feature = "kvm"))]
        {
            return Ok(Self::Kvm(Box::new(KvmBackend::create_vm(
                base_config,
                config,
            )?)));
        }

        #[allow(unreachable_code)]
        {
            let _ = base_config;
            let _ = config;
            Err(MicrovmError::UnsupportedPlatform)
        }
    }

    fn create_for_restore(
        base_config: SandboxConfig,
        config: MicrovmConfig,
    ) -> Result<Self, MicrovmError> {
        #[cfg(all(target_os = "linux", feature = "kvm"))]
        {
            return Ok(Self::Kvm(Box::new(KvmBackend::create_vm_for_restore(
                base_config,
                config,
            )?)));
        }

        #[allow(unreachable_code)]
        {
            let _ = base_config;
            let _ = config;
            Err(MicrovmError::UnsupportedPlatform)
        }
    }

    #[allow(dead_code)]
    fn run_command(&mut self, _cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        self.run_command_with_options(_cmd, &GuestExecOptions::default())
    }

    fn run_command_with_options(
        &mut self,
        _cmd: &[String],
        _options: &GuestExecOptions,
    ) -> Result<GuestCommandResult, MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.run_command_with_options(_cmd, _options),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    #[allow(dead_code)]
    fn run_command_streaming(
        &mut self,
        _cmd: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        self.run_command_streaming_with_options(_cmd, &GuestExecOptions::default())
    }

    fn run_command_streaming_with_options(
        &mut self,
        _cmd: &[String],
        _options: &GuestExecOptions,
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.run_command_streaming_with_options(_cmd, _options),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn read_file(&mut self, _path: &str) -> Result<Vec<u8>, MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.read_file(_path),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn write_file(&mut self, _path: &str, _data: &[u8]) -> Result<(), MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.write_file(_path, _data),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn ping(&mut self) -> Result<Duration, MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.ping(),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn ping_with_timeout(&mut self, _timeout: Duration) -> Result<Duration, MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.ping_with_timeout(_timeout),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn http_request(&mut self, _request: HttpRequest) -> Result<HttpResponse, MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.http_request(_request),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn shutdown(&mut self) -> Result<(), MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.shutdown(),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn is_destroyed(&self) -> bool {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.lifecycle() == crate::kvm::KvmLifecycle::Destroyed,
            Self::Unsupported => true,
        }
    }

    fn is_ready(&self) -> bool {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.is_guest_ready(),
            Self::Unsupported => false,
        }
    }

    fn snapshot_parts(&self) -> Result<(Vec<u8>, Vec<u8>), MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.snapshot_state(),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn restore_parts(&mut self, _memory: &[u8], _vcpu_state: &[u8]) -> Result<(), MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.restore_state(_memory, _vcpu_state),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    #[cfg(all(target_os = "linux", feature = "kvm"))]
    fn restore_from_file_parts(
        &mut self,
        memory_path: &Path,
        vcpu_state: &[u8],
    ) -> Result<(), MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => {
                let mut restore_profile = backend.take_or_seed_restore_profile();

                let restore_memory_started_at = Instant::now();
                #[cfg(feature = "zerocopy-fork")]
                backend.restore_from_file_zerocopy(memory_path)?;
                #[cfg(not(feature = "zerocopy-fork"))]
                backend.restore_from_file(memory_path)?;
                restore_profile.memory_state_write = restore_memory_started_at.elapsed();

                restore_profile.cpuid_config = backend.prepare_restored_vcpus()?;

                let runtime_restore_profile = restore_runtime_state(backend, vcpu_state)?;
                restore_profile.vcpu_state_restore = runtime_restore_profile.vcpu_state_restore;
                restore_profile.device_state_restore = runtime_restore_profile.device_state_restore;

                backend.set_lifecycle_ready();
                backend.emit_restore_profile_without_resume(&restore_profile);
                backend.set_pending_restore_profile(restore_profile);
                Ok(())
            }
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }
}

/// microVM sandbox implementation.
pub struct MicrovmSandbox {
    base_config: SandboxConfig,
    microvm_config: MicrovmConfig,
    state: MicrovmState,
    backend: BackendHandle,
}

impl std::fmt::Debug for MicrovmSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MicrovmSandbox")
            .field("microvm_config", &self.microvm_config)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl MicrovmSandbox {
    /// Creates a microVM with the default `SandboxConfig`.
    pub fn new(config: MicrovmConfig) -> Result<Self, MicrovmError> {
        Self::new_with_base(SandboxConfig::default(), config)
    }

    /// Creates a microVM with explicit `SandboxConfig` and `MicrovmConfig` values.
    pub fn new_with_base(
        base_config: SandboxConfig,
        microvm_config: MicrovmConfig,
    ) -> Result<Self, MicrovmError> {
        if !cfg!(all(target_os = "linux", feature = "kvm")) {
            return Err(MicrovmError::UnsupportedPlatform);
        }

        microvm_config.validate()?;
        debug!(
            vcpu_count = microvm_config.vcpu_count,
            memory_mb = microvm_config.memory_mb,
            "初始化 microVM 沙箱"
        );
        let backend = BackendHandle::create(base_config.clone(), microvm_config.clone())?;

        Ok(Self {
            base_config,
            microvm_config,
            state: MicrovmState::Ready,
            backend,
        })
    }

    /// Exports a snapshot of the current microVM.
    pub fn snapshot(&mut self) -> Result<SandboxSnapshot, MicrovmError> {
        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(LifecycleError::NotReady));
        }

        let (memory, vcpu_state) = self.backend.snapshot_parts()?;
        MicrovmSnapshot::new(
            self.base_config.clone(),
            self.microvm_config.clone(),
            memory,
            vcpu_state,
        )
        .persist_to_files()
    }

    /// Restores a microVM from a snapshot.
    pub fn restore(snapshot: &SandboxSnapshot) -> Result<Self, MicrovmError> {
        let _span = tracing::info_span!("vm_restore").entered();
        if let Some(memory_path) = snapshot.memory_file_path() {
            return Self::restore_from_file_snapshot(memory_path);
        }

        let data = snapshot.as_bytes().map_err(map_snapshot_access_error)?;
        Self::restore_from_bytes(data)
    }

    /// Restores a microVM from self-describing snapshot bytes.
    pub fn restore_from_bytes(data: &[u8]) -> Result<Self, MicrovmError> {
        let snapshot = MicrovmSnapshot::restore(data)?;
        Self::from_snapshot(snapshot)
    }

    /// Restores from a file-backed snapshot, loading memory through mmap(MAP_PRIVATE).
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    fn restore_from_file_snapshot(memory_path: &Path) -> Result<Self, MicrovmError> {
        let (sandbox_config, microvm_config, vcpu_state) =
            load_state_from_memory_file(memory_path)?;

        let mut backend =
            BackendHandle::create_for_restore(sandbox_config.clone(), microvm_config.clone())?;
        backend.restore_from_file_parts(memory_path, &vcpu_state)?;

        Ok(Self {
            base_config: sandbox_config,
            microvm_config,
            state: MicrovmState::Ready,
            backend,
        })
    }

    /// File snapshot restore fallback for non-Linux platforms.
    #[cfg(not(all(target_os = "linux", feature = "kvm")))]
    fn restore_from_file_snapshot(_memory_path: &Path) -> Result<Self, MicrovmError> {
        Err(MicrovmError::Backend(
            "file snapshot restore only supported on Linux".into(),
        ))
    }

    /// Creates an independent copy from the current microVM.
    ///
    /// When the zerocopy-fork feature is enabled, this directly shares guest memory
    /// and relies on MAP_PRIVATE CoW. Otherwise it keeps the file snapshot restore
    /// path as a fallback.
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "kvm")))]
    pub fn fork(&mut self) -> Result<Self, MicrovmError> {
        let _span = tracing::info_span!("vm_fork").entered();
        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(LifecycleError::NotReadyForFork));
        }

        #[cfg(feature = "zerocopy-fork")]
        {
            let (shared_memory, vcpu_state) = match &self.backend {
                BackendHandle::Kvm(backend) => backend.snapshot_for_fork()?,
                BackendHandle::Unsupported => return Err(MicrovmError::UnsupportedPlatform),
            };

            let mut backend_handle = BackendHandle::create_for_restore(
                self.base_config.clone(),
                self.microvm_config.clone(),
            )?;

            match &mut backend_handle {
                BackendHandle::Kvm(backend) => {
                    backend.restore_from_shared_memory(shared_memory, &vcpu_state)?;
                }
                BackendHandle::Unsupported => return Err(MicrovmError::UnsupportedPlatform),
            }

            return Ok(Self {
                base_config: self.base_config.clone(),
                microvm_config: self.microvm_config.clone(),
                state: MicrovmState::Ready,
                backend: backend_handle,
            });
        }

        #[cfg(not(feature = "zerocopy-fork"))]
        {
            use base64::Engine as _;

            let (memory, vcpu_state) = self.backend.snapshot_parts()?;
            let snapshot_dir = create_snapshot_dir()?;
            let memory_path = snapshot_dir.join("memory.bin");
            let state_path = snapshot_dir.join("state.json");

            let fork_result = (|| {
                std::fs::write(&memory_path, &memory)?;

                let state = SnapshotStateFile {
                    version: FILE_SNAPSHOT_VERSION,
                    sandbox_config: self.base_config.clone(),
                    microvm_config: self.microvm_config.clone(),
                    vcpu_state_base64: base64::engine::general_purpose::STANDARD
                        .encode(&vcpu_state),
                };
                let state_bytes = serde_json::to_vec_pretty(&state).map_err(|error| {
                    MicrovmError::SnapshotFormat(format!("failed to serialize state.json: {error}"))
                })?;
                std::fs::write(&state_path, state_bytes)?;

                Self::restore_from_file_snapshot(&memory_path)
            })();

            let _ = std::fs::remove_dir_all(snapshot_dir);
            fork_result
        }
    }

    /// Attempts to fork the microVM or returns an unsupported-backend error.
    #[cfg(not(all(target_os = "linux", feature = "kvm")))]
    pub fn fork(&mut self) -> Result<Self, MicrovmError> {
        let _span = tracing::info_span!("vm_fork").entered();
        Err(MicrovmError::Backend(
            "fork only supported on Linux + KVM".into(),
        ))
    }

    pub(crate) fn from_snapshot(snapshot: MicrovmSnapshot) -> Result<Self, MicrovmError> {
        let (sandbox_config, microvm_config, memory, vcpu_state) = snapshot.into_parts();
        let backend =
            BackendHandle::create_for_restore(sandbox_config.clone(), microvm_config.clone())?;
        let mut sandbox = Self {
            base_config: sandbox_config,
            microvm_config,
            state: MicrovmState::Ready,
            backend,
        };
        sandbox.backend.restore_parts(&memory, &vcpu_state)?;
        sandbox.state = MicrovmState::Ready;
        Ok(sandbox)
    }

    fn with_ready_state<F, T>(&mut self, op_name: &str, op: F) -> Result<T, MicrovmError>
    where
        F: FnOnce(&mut BackendHandle) -> Result<T, MicrovmError>,
    {
        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(LifecycleError::InvalidState {
                expected: "Ready".into(),
                current: format!("not Ready for {op_name}"),
                message: format!("microVM not ready for {op_name}"),
            }));
        }

        self.state = MicrovmState::Running;
        let result = op(&mut self.backend);
        self.state = if self.backend.is_destroyed() {
            MicrovmState::Destroyed
        } else {
            MicrovmState::Ready
        };
        result
    }

    /// Reads file contents from the guest.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, MicrovmError> {
        self.with_ready_state("read_file", |backend| backend.read_file(path))
    }

    /// Writes file contents into the guest.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), MicrovmError> {
        self.with_ready_state("write_file", |backend| backend.write_file(path, data))
    }

    /// Waits until the microVM is responsive and verifies the command loop with PING/PONG.
    pub fn wait_ready(&mut self, timeout: Duration) -> Result<(), MicrovmError> {
        if timeout.is_zero() {
            return Err(MicrovmError::InvalidConfig(
                "wait_ready timeout must not be zero".into(),
            ));
        }
        if self.state == MicrovmState::Destroyed {
            return Err(MicrovmError::Lifecycle(LifecycleError::Destroyed(
                "microVM destroyed, cannot wait for ready".into(),
            )));
        }

        self.with_ready_state("wait_ready", |backend| {
            backend.ping_with_timeout(timeout).map(|_| ())
        })
    }

    /// Returns whether the microVM is in the Ready state.
    pub fn is_ready(&self) -> bool {
        self.state == MicrovmState::Ready && self.backend.is_ready()
    }

    /// Runs one PING/PONG readiness probe and returns the round-trip duration.
    pub fn ping(&mut self) -> Result<Duration, MicrovmError> {
        self.with_ready_state("ping", BackendHandle::ping)
    }

    /// Executes a command as a stream of events.
    pub fn stream_execute(
        &mut self,
        cmd: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        self.stream_execute_with_options(cmd, GuestExecOptions::default())
    }

    /// Executes a command as a stream of events with command-level options.
    pub fn stream_execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig(
                "command must not be empty".into(),
            ));
        }

        self.with_ready_state("stream_execute", |backend| {
            backend.run_command_streaming_with_options(cmd, &options)
        })
    }

    /// Executes a command with command-level environment variables.
    pub fn execute_with_env(
        &mut self,
        cmd: &[String],
        env: HashMap<String, String>,
    ) -> Result<GuestCommandResult, MicrovmError> {
        self.execute_with_options(
            cmd,
            GuestExecOptions {
                env,
                timeout: None,
                cwd: None,
            },
        )
    }

    /// Executes a command with a command-level timeout override.
    pub fn execute_with_timeout(
        &mut self,
        cmd: &[String],
        timeout: Duration,
    ) -> Result<GuestCommandResult, MicrovmError> {
        self.execute_with_options(
            cmd,
            GuestExecOptions {
                env: HashMap::new(),
                timeout: Some(timeout),
                cwd: None,
            },
        )
    }

    /// Executes a command with the full set of command-level options.
    pub fn execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<GuestCommandResult, MicrovmError> {
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig(
                "command must not be empty".into(),
            ));
        }

        self.with_ready_state("execute", |backend| {
            backend.run_command_with_options(cmd, &options)
        })
    }

    /// Sends a request through the host-controlled HTTP proxy.
    pub fn http_request(&mut self, request: HttpRequest) -> Result<HttpResponse, MicrovmError> {
        self.with_ready_state("http_request", |backend| backend.http_request(request))
    }
}

impl Sandbox for MicrovmSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        Self::new_with_base(config, MicrovmConfig::default()).map_err(Into::into)
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        self.execute_with_options_for_sandbox(cmd, GuestExecOptions::default())
            .map_err(SandboxError::from)
    }

    fn create_pty(
        &mut self,
        _config: mimobox_core::PtyConfig,
    ) -> Result<Box<dyn mimobox_core::PtySession>, SandboxError> {
        Err(SandboxError::UnsupportedOperation(
            "PTY sessions currently only support OS-level backend, microVM not supported"
                .to_string(),
        ))
    }

    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SandboxError> {
        MicrovmSandbox::read_file(self, path).map_err(SandboxError::from)
    }

    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SandboxError> {
        MicrovmSandbox::write_file(self, path, data).map_err(SandboxError::from)
    }

    fn snapshot(&mut self) -> Result<SandboxSnapshot, SandboxError> {
        MicrovmSandbox::snapshot(self).map_err(SandboxError::from)
    }

    fn fork(&mut self) -> Result<Self, SandboxError> {
        MicrovmSandbox::fork(self).map_err(SandboxError::from)
    }

    fn destroy(self) -> Result<(), SandboxError> {
        let mut this = self;
        this.backend.shutdown().map_err(SandboxError::from)?;
        this.state = MicrovmState::Destroyed;
        Ok(())
    }
}

fn map_snapshot_access_error(error: SandboxError) -> MicrovmError {
    match error {
        SandboxError::Io(error) => MicrovmError::Io(error),
        SandboxError::InvalidSnapshot => {
            MicrovmError::SnapshotFormat("invalid sandbox snapshot".into())
        }
        other => MicrovmError::SnapshotFormat(other.to_string()),
    }
}

impl MicrovmSandbox {
    fn execute_with_options_for_sandbox(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<SandboxResult, MicrovmError> {
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig(
                "command must not be empty".into(),
            ));
        }

        self.with_ready_state("execute", |backend| {
            let start = Instant::now();
            let guest = backend.run_command_with_options(cmd, &options)?;
            Ok(SandboxResult {
                stdout: guest.stdout,
                stderr: guest.stderr,
                exit_code: guest.exit_code,
                elapsed: start.elapsed(),
                timed_out: guest.timed_out,
            })
        })
    }
}
