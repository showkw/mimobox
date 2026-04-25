#![cfg_attr(docsrs, feature(doc_cfg))]
//! mimobox-os: OS-level sandbox backends.
//!
//! Provides process-level sandbox implementations for Linux, macOS, and Windows (skeleton).
//!
//! The Linux backend (`LinuxSandbox`) is currently the only complete implementation and uses
//! the following kernel mechanisms:
//! - **Landlock** — filesystem access control (deny by default, allowlist-based access)
//! - **Seccomp-bpf** — system call filtering (allowlist mode by default)
//! - **Namespaces** — PID / Network / Mount / IPC isolation (including user namespace fallback)
//! - **setrlimit** — memory limits (`RLIMIT_AS`)
//!
//! Also provides the warm pool [`SandboxPool`] for microsecond-level sandbox acquisition.
//!
//! # Platform Support
//!
//! | Platform | Status |
//! |------|------|
//! | Linux | Complete implementation |
//! | macOS | Complete implementation (Seatbelt / sandbox-exec) |
//! | Windows | Planned (AppContainer) |

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

// 公开导出各平台后端
#[cfg(target_os = "linux")]
pub use linux::LinuxSandbox;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use pool::{PoolConfig, PoolError, PoolStats, PooledSandbox, SandboxPool, run_pool_benchmark};

#[cfg(target_os = "linux")]
pub use seccomp::apply_seccomp;

#[cfg(target_os = "macos")]
pub use macos::MacOsSandbox;
