#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! microVM sandbox backend for mimobox.
//!
//! This crate provides the microVM isolation layer used by the higher-level mimobox
//! sandbox APIs. It exposes configuration, lifecycle management, guest command
//! execution, file transfer, controlled HTTP proxying, snapshot serialization, and
//! optional pooling helpers.
//!
//! The main entry point is [`MicrovmSandbox`], which implements
//! [`mimobox_core::Sandbox`]. Linux builds with the `kvm` feature use `KvmBackend`
//! for the underlying VM lifecycle. Other platforms keep the public API available
//! but return [`MicrovmError::UnsupportedPlatform`] for KVM-only operations.
//!
//! Snapshot support is split into [`MicrovmSnapshot`] for self-describing in-memory
//! snapshots and file-backed [`mimobox_core::SandboxSnapshot`] values for fast
//! restore paths. [`VmPool`] prewarms fully booted VMs, while `RestorePool` keeps
//! empty VM shells ready for snapshot restoration on supported KVM builds.
//!
//! HTTP access from guests is intentionally host-mediated. [`HttpRequest`] values
//! are validated against `SandboxConfig::allowed_http_domains` and
//! executed by the host-side proxy rather than by giving the guest direct network
//! access.

mod guest_file_ops;
mod http_proxy;
/// Thread-safe microVM prewarm pool types.
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
    GuestCommandResult, GuestExecOptions, GuestFileErrorKind, LifecycleError, MicrovmConfig,
    MicrovmError, MicrovmSandbox, MicrovmState, StreamEvent,
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
