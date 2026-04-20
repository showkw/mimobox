//! Seccomp-bpf 系统调用过滤策略定义
//!
//! 定义 SeccompProfile 枚举供各后端使用。
//! 具体的 BPF 过滤器实现在 mimobox-os crate 的 seccomp 模块中。

/// Seccomp 过滤策略
#[derive(Debug, Clone, Copy, Default)]
pub enum SeccompProfile {
    /// 仅允许核心系统调用（最严格，禁止 fork）
    #[default]
    Essential,
    /// 核心 + 网络系统调用
    Network,
    /// 核心系统调用 + 允许 fork（用于 shell 等需要子进程的场景）
    EssentialWithFork,
    /// 网络 + 允许 fork
    NetworkWithFork,
}
