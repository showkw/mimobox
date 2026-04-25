#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
//! mimobox-core: core traits and type definitions.
//!
//! Defines the unified sandbox abstraction interface ([`Sandbox`] trait) implemented by each backend
//! (OS-level, Wasm-level, and others).
//!
//! Core types:
//! - [`Sandbox`] — sandbox lifecycle trait (`new` / `execute` / `destroy`)
//! - [`SandboxConfig`] — sandbox configuration (timeouts, memory limits, filesystem isolation, and more)
//! - [`SandboxResult`] — execution result (stdout/stderr, exit code, elapsed time)
//! - [`SandboxError`] — unified error type
//! - [`SeccompProfile`] — Seccomp filter policy enum

mod sandbox;
mod seccomp;

pub use sandbox::{
    ErrorCode, PtyConfig, PtyEvent, PtySession, PtySize, Sandbox, SandboxConfig, SandboxError,
    SandboxResult, SandboxSnapshot,
};
pub use seccomp::SeccompProfile;
