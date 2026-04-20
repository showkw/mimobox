//! 最小 `kvm-ioctls` 兼容层。
//!
//! 该 shim 只提供本次骨架实现需要的 `Kvm`、`VmFd`、`VcpuFd` API，
//! 用于在离线环境里完成编译验证。

use std::fmt;
use std::sync::{Arc, Mutex};

/// 兼容层错误类型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Default)]
struct VmState {
    vcpu_ids: Vec<u64>,
}

/// KVM 入口对象。
#[derive(Debug, Clone, Default)]
pub struct Kvm;

impl Kvm {
    pub fn new() -> Result<Self, Error> {
        Ok(Self)
    }

    pub fn create_vm(&self) -> Result<VmFd, Error> {
        Ok(VmFd {
            inner: Arc::new(Mutex::new(VmState::default())),
        })
    }
}

/// VM 文件描述符包装。
#[derive(Debug, Clone)]
pub struct VmFd {
    inner: Arc<Mutex<VmState>>,
}

impl VmFd {
    pub fn create_vcpu(&self, id: u64) -> Result<VcpuFd, Error> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| Error::new("KVM 状态锁已损坏"))?;
        if state.vcpu_ids.contains(&id) {
            return Err(Error::new(format!("重复创建 vCPU {id}")));
        }
        state.vcpu_ids.push(id);
        Ok(VcpuFd { id })
    }

    pub fn vcpu_count(&self) -> Result<usize, Error> {
        let state = self
            .inner
            .lock()
            .map_err(|_| Error::new("KVM 状态锁已损坏"))?;
        Ok(state.vcpu_ids.len())
    }
}

/// vCPU 文件描述符包装。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VcpuFd {
    id: u64,
}

impl VcpuFd {
    pub fn id(&self) -> u64 {
        self.id
    }
}
