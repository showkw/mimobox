#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! mimobox-vm: microVM sandbox backend.
//!
//! This crate provides the foundation for the microVM backend:
//! - [`MicrovmConfig`]: microVM-specific configuration.
//! - [`MicrovmSandbox`]: the public entry point implementing [`mimobox_core::Sandbox`].
//! - [`MicrovmSnapshot`]: the self-describing snapshot format
//!   (magic + version + config + memory + vCPU state).
//! - `KvmBackend` on Linux with the `kvm` feature: the basic KVM lifecycle implementation.

mod http_proxy;
/// microVM prewarm pool types.
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
#[cfg_attr(docsrs, doc(cfg(feature = "kvm")))]
pub use kvm::{KvmBackend, KvmExitReason, KvmLifecycle, KvmTransport};
#[cfg(all(target_os = "linux", feature = "kvm"))]
#[cfg_attr(docsrs, doc(cfg(feature = "kvm")))]
pub use restore_pool::{PooledRestoreVm, RestorePool, RestorePoolConfig, RestorePoolError};
