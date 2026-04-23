//! mimobox-os: OS 级沙箱后端
//!
//! 提供 Linux、macOS、Windows（骨架）平台上的进程级沙箱实现。
//!
//! Linux 后端（`LinuxSandbox`）是当前唯一完整实现，使用以下内核机制：
//! - **Landlock** — 文件系统访问控制（默认拒绝所有，白名单放行）
//! - **Seccomp-bpf** — 系统调用过滤（默认白名单模式）
//! - **Namespaces** — PID / Network / Mount / IPC 隔离（含 user namespace 降级）
//! - **setrlimit** — 内存限制（RLIMIT_AS）
//!
//! 还提供预热池 [`SandboxPool`] 用于微秒级沙箱获取。
//!
//! # 平台支持
//!
//! | 平台 | 状态 |
//! |------|------|
//! | Linux | 完整实现 |
//! | macOS | 完整实现（Seatbelt / sandbox-exec） |
//! | Windows | 待实现（AppContainer） |

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
