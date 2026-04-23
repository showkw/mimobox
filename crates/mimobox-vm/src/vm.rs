use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};
use tracing::debug;

use crate::snapshot::MicrovmSnapshot;

#[cfg(all(target_os = "linux", feature = "kvm"))]
use crate::kvm::KvmBackend;

/// microVM 专属配置。
#[derive(Debug, Clone, PartialEq, Eq)]
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
        Self {
            vcpu_count: 1,
            memory_mb: 128,
            kernel_path: PathBuf::from("/var/lib/mimobox/vm/vmlinux"),
            rootfs_path: PathBuf::from("/var/lib/mimobox/vm/rootfs.cpio.gz"),
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
    Created,
    Ready,
    Running,
    Destroyed,
}

/// guest 命令执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestCommandResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

/// guest 流式执行事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    TimedOut,
}

/// microVM 级错误。
#[derive(Debug, thiserror::Error)]
pub enum MicrovmError {
    #[error("当前平台不支持 KVM microVM 后端")]
    UnsupportedPlatform,

    #[error("microVM 配置无效: {0}")]
    InvalidConfig(String),

    #[error("microVM 生命周期错误: {0}")]
    Lifecycle(String),

    #[error("KVM 后端错误: {0}")]
    Backend(String),

    #[error("快照格式错误: {0}")]
    SnapshotFormat(String),

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
            | MicrovmError::SnapshotFormat(message) => SandboxError::ExecutionFailed(message),
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

    fn run_command(&mut self, _cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.run_command(_cmd),
            Self::Unsupported => Err(MicrovmError::UnsupportedPlatform),
        }
    }

    fn run_command_streaming(
        &mut self,
        _cmd: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "kvm"))]
            Self::Kvm(backend) => backend.run_command_streaming(_cmd),
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
    pub fn snapshot(&mut self) -> Result<Vec<u8>, MicrovmError> {
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
        .snapshot()
    }

    /// 从快照恢复 microVM。
    pub fn restore(data: &[u8]) -> Result<Self, MicrovmError> {
        let snapshot = MicrovmSnapshot::restore(data)?;
        Self::from_snapshot(snapshot)
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

    pub fn stream_execute(
        &mut self,
        cmd: &[String],
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
        let result = self.backend.run_command_streaming(cmd);
        self.state = if self.backend.is_destroyed() {
            MicrovmState::Destroyed
        } else {
            MicrovmState::Ready
        };
        result
    }
}

impl Sandbox for MicrovmSandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        Self::new_with_base(config, MicrovmConfig::default()).map_err(Into::into)
    }

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError> {
        if cmd.is_empty() {
            return Err(SandboxError::ExecutionFailed("命令为空".into()));
        }

        if self.state != MicrovmState::Ready {
            return Err(SandboxError::ExecutionFailed(
                "microVM 当前不处于可执行状态".into(),
            ));
        }

        self.state = MicrovmState::Running;
        let start = Instant::now();
        let result = self.backend.run_command(cmd);
        self.state = MicrovmState::Ready;

        let guest = result.map_err(SandboxError::from)?;
        Ok(SandboxResult {
            stdout: guest.stdout,
            stderr: guest.stderr,
            exit_code: guest.exit_code,
            elapsed: start.elapsed(),
            timed_out: guest.timed_out,
        })
    }

    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SandboxError> {
        MicrovmSandbox::read_file(self, path).map_err(SandboxError::from)
    }

    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SandboxError> {
        MicrovmSandbox::write_file(self, path, data).map_err(SandboxError::from)
    }

    fn destroy(self) -> Result<(), SandboxError> {
        let mut this = self;
        this.backend.shutdown().map_err(SandboxError::from)?;
        this.state = MicrovmState::Destroyed;
        Ok(())
    }
}
