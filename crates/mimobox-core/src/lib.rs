//! mimobox-core: 核心 trait 和类型定义
//!
//! 定义沙箱的统一抽象接口（[`Sandbox`] trait），供各后端（OS 级、Wasm 级等）实现。
//!
//! 核心类型：
//! - [`Sandbox`] — 沙箱生命周期 trait（new / execute / destroy）
//! - [`SandboxConfig`] — 沙箱配置（超时、内存限制、文件系统隔离等）
//! - [`SandboxResult`] — 执行结果（stdout/stderr、退出码、耗时）
//! - [`SandboxError`] — 统一错误类型
//! - [`SeccompProfile`] — Seccomp 过滤策略枚举

mod sandbox;
mod seccomp;

pub use sandbox::{
    ErrorCode, PtyConfig, PtyEvent, PtySession, PtySize, Sandbox, SandboxConfig, SandboxError,
    SandboxResult, SandboxSnapshot,
};
pub use seccomp::SeccompProfile;
