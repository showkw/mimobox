#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
//! mimobox-sdk: Unified Agent Sandbox API
//!
//! **Smart routing by default, full control for advanced users.**
//!
//! Zero-config sandbox creation with automatic backend selection, plus
//! complete configuration control via [`Config::builder()`].
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use mimobox_sdk::Sandbox;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut sandbox = Sandbox::new()?;
//! let result = sandbox.execute("/bin/echo hello")?;
//! println!("exit: {:?}", result.exit_code);
//! sandbox.destroy()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature Gates
//!
//! | Feature | Backend | Default |
//! |---------|---------|---------|
//! | `os`    | OS-level (Linux/macOS) | Yes |
//! | `vm`    | microVM (Linux + KVM) | No |
//! | `wasm`  | Wasm (Wasmtime) | No |
//!
//! # Key Types
//!
//! - [`Sandbox`] — Primary entry point for all sandbox operations
//! - [`Config`] / [`ConfigBuilder`] — SDK configuration with builder pattern
//! - [`ExecuteResult`] — Command execution result (stdout, stderr, exit code, timing)
//! - [`StreamEvent`] — Streaming output event enum
//! - [`SdkError`] / [`ErrorCode`] — Structured error model
//! - [`SandboxSnapshot`] — Opaque snapshot handle
//! - [`PtySession`] — Interactive terminal session

mod config;
mod dispatch;
mod error;
mod router;
mod sandbox;
mod types;
mod vm_helpers;

pub use config::{Config, ConfigBuilder, IsolationLevel, NetworkPolicy, TrustLevel};
pub use error::SdkError;
pub use mimobox_core::{DirEntry, ErrorCode, FileStat, FileType, PtyConfig, PtyEvent, PtySize};
pub use sandbox::Sandbox;
pub use types::{ExecuteResult, HttpResponse, PtySession, SandboxSnapshot, StreamEvent};
#[cfg(all(feature = "vm", target_os = "linux"))]
pub use types::{RestorePool, RestorePoolConfig};
