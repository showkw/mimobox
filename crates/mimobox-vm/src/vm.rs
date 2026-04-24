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

/// microVM 专属配置。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MicrovmConfig {
    /// vCPU 数量。
    pub vcpu_count: u8,
    /// Guest 内存大小（MiB）。
    pub memory_mb: u32,
    /// Guest 内核镜像路径。
    pub kernel_path: PathBuf,
    /// Guest rootfs 路径。
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
            memory_mb: 128,
            kernel_path: assets_dir.join("vmlinux"),
            rootfs_path: assets_dir.join("rootfs.cpio.gz"),
        }
    }
}

impl MicrovmConfig {
    /// 返回 guest memory 字节数。
    pub fn memory_bytes(&self) -> Result<usize, MicrovmError> {
        let bytes = u64::from(self.memory_mb)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| MicrovmError::InvalidConfig("memory_mb 转换为字节时溢出".into()))?;
        usize::try_from(bytes)
            .map_err(|_| MicrovmError::InvalidConfig("当前平台无法表示所需内存大小".into()))
    }

    /// 校验 microVM 基础配置。
    pub fn validate(&self) -> Result<(), MicrovmError> {
        if self.vcpu_count == 0 {
            return Err(MicrovmError::InvalidConfig("vcpu_count 不能为 0".into()));
        }

        if self.memory_mb < 64 {
            return Err(MicrovmError::InvalidConfig("memory_mb 不能小于 64".into()));
        }

        if self.kernel_path.as_os_str().is_empty() {
            return Err(MicrovmError::InvalidConfig("kernel_path 不能为空".into()));
        }

        if self.rootfs_path.as_os_str().is_empty() {
            return Err(MicrovmError::InvalidConfig("rootfs_path 不能为空".into()));
        }

        if !self.kernel_path.exists() {
            return Err(MicrovmError::InvalidConfig(format!(
                "kernel_path 不存在: {}",
                self.kernel_path.display()
            )));
        }

        if !self.rootfs_path.exists() {
            return Err(MicrovmError::InvalidConfig(format!(
                "rootfs_path 不存在: {}",
                self.rootfs_path.display()
            )));
        }

        Ok(())
    }
}

/// microVM 生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicrovmState {
    /// 实例已创建但尚未进入可执行状态。
    Created,
    /// 实例已就绪，可执行命令或文件操作。
    Ready,
    /// 实例当前正在执行命令或传输数据。
    Running,
    /// 实例已经销毁，不能再复用。
    Destroyed,
}

/// guest 命令执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestCommandResult {
    /// 标准输出字节流。
    pub stdout: Vec<u8>,
    /// 标准错误字节流。
    pub stderr: Vec<u8>,
    /// 退出码；若进程未正常退出则可能为 `None`。
    pub exit_code: Option<i32>,
    /// 是否因超时被终止。
    pub timed_out: bool,
}

/// guest 命令级执行选项。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestExecOptions {
    /// 仅对本次命令生效的环境变量。
    pub env: HashMap<String, String>,
    /// 仅对本次命令生效的超时时间。
    pub timeout: Option<Duration>,
}

/// guest 流式执行事件。
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

/// microVM 级错误。
#[derive(Debug, thiserror::Error)]
pub enum MicrovmError {
    /// 当前平台或构建配置不支持 KVM microVM。
    #[error("当前平台不支持 KVM microVM 后端")]
    UnsupportedPlatform,

    /// microVM 配置无效。
    #[error("microVM 配置无效: {0}")]
    InvalidConfig(String),

    /// 生命周期状态不允许执行当前操作。
    #[error("microVM 生命周期错误: {0}")]
    Lifecycle(String),

    /// KVM 或 guest 协议层错误。
    #[error("KVM 后端错误: {0}")]
    Backend(String),

    /// 受控 HTTP 代理错误。
    #[error(transparent)]
    HttpProxy(#[from] HttpProxyError),

    /// 快照格式非法或不兼容。
    #[error("快照格式错误: {0}")]
    SnapshotFormat(String),

    /// 标准库 I/O 错误。
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

impl From<MicrovmError> for SandboxError {
    fn from(value: MicrovmError) -> Self {
        match value {
            MicrovmError::UnsupportedPlatform => SandboxError::Unsupported,
            MicrovmError::InvalidConfig(message)
            | MicrovmError::Lifecycle(message)
            | MicrovmError::Backend(message)
            | MicrovmError::HttpProxy(crate::http_proxy::HttpProxyError::Internal(message))
            | MicrovmError::SnapshotFormat(message) => SandboxError::ExecutionFailed(message),
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

/// microVM 沙箱实现。
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
    /// 使用默认 `SandboxConfig` 创建 microVM。
    pub fn new(config: MicrovmConfig) -> Result<Self, MicrovmError> {
        Self::new_with_base(SandboxConfig::default(), config)
    }

    /// 使用显式 `SandboxConfig` + `MicrovmConfig` 创建 microVM。
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

    /// 导出当前 microVM 快照。
    pub fn snapshot(&mut self) -> Result<SandboxSnapshot, MicrovmError> {
        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle("仅 Ready 状态允许创建快照".into()));
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

    /// 从快照恢复 microVM。
    pub fn restore(snapshot: &SandboxSnapshot) -> Result<Self, MicrovmError> {
        let _span = tracing::info_span!("vm_restore").entered();
        if let Some(memory_path) = snapshot.memory_file_path() {
            return Self::restore_from_file_snapshot(memory_path);
        }

        let data = snapshot.as_bytes().map_err(map_snapshot_access_error)?;
        Self::restore_from_bytes(data)
    }

    /// 从自描述快照字节恢复 microVM。
    pub fn restore_from_bytes(data: &[u8]) -> Result<Self, MicrovmError> {
        let snapshot = MicrovmSnapshot::restore(data)?;
        Self::from_snapshot(snapshot)
    }

    /// 从文件化快照恢复，memory 通过 mmap(MAP_PRIVATE) 加载。
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

    /// 非 Linux 平台的文件快照恢复回退。
    #[cfg(not(all(target_os = "linux", feature = "kvm")))]
    fn restore_from_file_snapshot(_memory_path: &Path) -> Result<Self, MicrovmError> {
        Err(MicrovmError::Backend("文件快照恢复仅支持 Linux".into()))
    }

    /// 从当前 microVM 创建一个独立的副本。
    ///
    /// zerocopy-fork feature 开启时直接共享 guest memory 并依赖 MAP_PRIVATE CoW；
    /// 未开启时保留文件快照恢复链路作为回退。
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    pub fn fork(&mut self) -> Result<Self, MicrovmError> {
        let _span = tracing::info_span!("vm_fork").entered();
        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle("仅 Ready 状态允许 fork".into()));
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
                    MicrovmError::SnapshotFormat(format!("序列化 state.json 失败: {error}"))
                })?;
                std::fs::write(&state_path, state_bytes)?;

                Self::restore_from_file_snapshot(&memory_path)
            })();

            let _ = std::fs::remove_dir_all(snapshot_dir);
            return fork_result;
        }
    }

    #[cfg(not(all(target_os = "linux", feature = "kvm")))]
    pub fn fork(&mut self) -> Result<Self, MicrovmError> {
        let _span = tracing::info_span!("vm_fork").entered();
        Err(MicrovmError::Backend("fork 仅支持 Linux + KVM".into()))
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

    /// 读取 guest 内文件内容。
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, MicrovmError> {
        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(
                "microVM 当前不处于可读文件状态".into(),
            ));
        }

        self.state = MicrovmState::Running;
        let result = self.backend.read_file(path);
        self.state = MicrovmState::Ready;
        result
    }

    /// 向 guest 内写入文件内容。
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), MicrovmError> {
        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(
                "microVM 当前不处于可写文件状态".into(),
            ));
        }

        self.state = MicrovmState::Running;
        let result = self.backend.write_file(path, data);
        self.state = MicrovmState::Ready;
        result
    }

    /// 以流式事件形式执行命令。
    pub fn stream_execute(
        &mut self,
        cmd: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        self.stream_execute_with_options(cmd, GuestExecOptions::default())
    }

    /// 以流式事件形式执行命令，并应用命令级选项。
    pub fn stream_execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig("命令为空".into()));
        }

        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(
                "microVM 当前不处于可执行状态".into(),
            ));
        }

        self.state = MicrovmState::Running;
        let result = self
            .backend
            .run_command_streaming_with_options(cmd, &options);
        self.state = if self.backend.is_destroyed() {
            MicrovmState::Destroyed
        } else {
            MicrovmState::Ready
        };
        result
    }

    /// 执行命令并附加命令级环境变量。
    pub fn execute_with_env(
        &mut self,
        cmd: &[String],
        env: HashMap<String, String>,
    ) -> Result<GuestCommandResult, MicrovmError> {
        self.execute_with_options(cmd, GuestExecOptions { env, timeout: None })
    }

    /// 执行命令并覆写命令级超时时间。
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
            },
        )
    }

    /// 执行命令并应用完整的命令级选项。
    pub fn execute_with_options(
        &mut self,
        cmd: &[String],
        options: GuestExecOptions,
    ) -> Result<GuestCommandResult, MicrovmError> {
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig("命令为空".into()));
        }

        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(
                "microVM 当前不处于可执行状态".into(),
            ));
        }

        self.state = MicrovmState::Running;
        let result = self.backend.run_command_with_options(cmd, &options);
        self.state = if self.backend.is_destroyed() {
            MicrovmState::Destroyed
        } else {
            MicrovmState::Ready
        };
        result
    }

    /// 通过宿主受控 HTTP 代理发起请求。
    pub fn http_request(&mut self, request: HttpRequest) -> Result<HttpResponse, MicrovmError> {
        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(
                "microVM 当前不处于可执行 HTTP 代理状态".into(),
            ));
        }

        self.backend.http_request(request)
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
            "PTY 会话当前仅支持 OS 级后端，microVM 后端暂不支持".to_string(),
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
        SandboxError::InvalidSnapshot => MicrovmError::SnapshotFormat("无效的沙箱快照".into()),
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
            return Err(MicrovmError::InvalidConfig("命令为空".into()));
        }

        if self.state != MicrovmState::Ready {
            return Err(MicrovmError::Lifecycle(
                "microVM 当前不处于可执行状态".into(),
            ));
        }

        self.state = MicrovmState::Running;
        let start = Instant::now();
        let result = self.backend.run_command_with_options(cmd, &options);
        self.state = if self.backend.is_destroyed() {
            MicrovmState::Destroyed
        } else {
            MicrovmState::Ready
        };

        let guest = result?;
        Ok(SandboxResult {
            stdout: guest.stdout,
            stderr: guest.stderr,
            exit_code: guest.exit_code,
            elapsed: start.elapsed(),
            timed_out: guest.timed_out,
        })
    }
}
