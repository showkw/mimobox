#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
//! OS-level sandbox backends for mimobox.
//!
//! This crate provides process-level sandbox implementations that conform to the
//! `mimobox-core` [`Sandbox`](mimobox_core::Sandbox) trait. It is responsible for
//! turning a [`SandboxConfig`](mimobox_core::SandboxConfig) into platform-native
//! isolation mechanisms while preserving the shared SDK result and error model.
//!
//! The Linux backend (`LinuxSandbox`) uses the following kernel mechanisms:
//! - **Landlock** for filesystem access control.
//! - **Seccomp-bpf** for allowlist-based system call filtering.
//! - **Namespaces** for PID, network, mount, and IPC isolation.
//! - **setrlimit** for memory limits.
//!
//! The macOS backend (`MacOsSandbox`) uses Seatbelt through `sandbox-exec`
//! where available. The crate also exposes [`SandboxPool`] for low-latency reuse
//! of pre-warmed OS sandboxes on supported platforms.
//!
//! # Platform Support
//!
//! | Platform | Status |
//! |------|------|
//! | Linux | Complete implementation |
//! | macOS | Complete implementation (Seatbelt / sandbox-exec) |
//! | Windows | Planned (AppContainer) |
//!
//! # Safety Model
//!
//! Platform backends apply sandbox policy in child processes before command
//! execution. Linux applies seccomp as the final step before `exec`, after
//! resource limits, filesystem restrictions, and namespace setup are in place.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod pool;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod pty;

/// Linux OS-level sandbox backend using Landlock, seccomp-bpf, namespaces, and resource limits.
#[cfg(target_os = "linux")]
pub use linux::LinuxSandbox;

/// Report describing the isolation level that was actually applied.
#[cfg(target_os = "linux")]
pub use linux::IsolationReport;

/// Warm pool types for reusing pre-initialized OS sandboxes.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use pool::{PoolConfig, PoolError, PoolStats, PooledSandbox, SandboxPool, run_pool_benchmark};

/// Applies a Linux seccomp-bpf system call filter for the selected profile.
#[cfg(target_os = "linux")]
pub use seccomp::apply_seccomp;

/// macOS OS-level sandbox backend using Seatbelt through `sandbox-exec`.
#[cfg(target_os = "macos")]
pub use macos::MacOsSandbox;
