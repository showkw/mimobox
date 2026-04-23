//! mimobox-vm: microVM 沙箱后端
//!
//! 当前 crate 提供 microVM 后端的基础骨架：
//! - [`MicrovmConfig`]：microVM 专属配置
//! - [`MicrovmSandbox`]：实现 [`mimobox_core::Sandbox`] 的外部入口
//! - [`MicrovmSnapshot`]：自描述快照格式（magic + version + config + memory + vCPU state）
//! - Linux + `kvm` feature 下的 [`KvmBackend`]：KVM 生命周期基础实现

mod http_proxy;
pub mod pool;
mod snapshot;
mod vm;
mod vm_assets;

#[cfg(all(target_os = "linux", feature = "kvm"))]
mod kvm;
#[cfg(all(target_os = "linux", feature = "kvm"))]
mod restore_pool;

pub use http_proxy::{HttpProxyError, HttpRequest, HttpResponse};
pub use pool::{PoolError, PooledVm, VmPool, VmPoolConfig, VmPoolStats};
pub use snapshot::MicrovmSnapshot;
pub use vm::{
    GuestCommandResult, GuestExecOptions, MicrovmConfig, MicrovmError, MicrovmSandbox,
    MicrovmState, StreamEvent,
};
pub use vm_assets::{
    microvm_config_from_assets_dir, microvm_config_from_vm_assets, resolve_vm_assets_dir,
    vm_assets_dir,
};

#[cfg(all(target_os = "linux", feature = "kvm"))]
pub use kvm::{KvmBackend, KvmExitReason, KvmLifecycle, KvmTransport};
#[cfg(all(target_os = "linux", feature = "kvm"))]
pub use restore_pool::{PooledRestoreVm, RestorePool, RestorePoolConfig, RestorePoolError};
