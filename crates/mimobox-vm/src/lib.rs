//! mimobox-vm: microVM 沙箱后端
//!
//! 当前 crate 提供 microVM 后端的基础骨架：
//! - [`MicrovmConfig`]：microVM 专属配置
//! - [`MicrovmSandbox`]：实现 [`mimobox_core::Sandbox`] 的外部入口
//! - [`MicrovmSnapshot`]：自描述快照格式（magic + version + config + memory + vCPU state）
//! - Linux + `kvm` feature 下的 [`KvmBackend`]：KVM 生命周期基础实现

mod snapshot;
mod vm;

#[cfg(all(target_os = "linux", feature = "kvm"))]
mod kvm;

pub use snapshot::MicrovmSnapshot;
pub use vm::{MicrovmConfig, MicrovmError, MicrovmSandbox, MicrovmState};

#[cfg(all(target_os = "linux", feature = "kvm"))]
pub use kvm::{KvmBackend, KvmLifecycle, KvmTransport};
