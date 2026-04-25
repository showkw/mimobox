//! Seccomp-bpf syscall filtering policy definitions
//!
//! Defines the [`SeccompProfile`] enum used by all backends.
//! The actual BPF filter implementation lives in the mimobox-os crate's seccomp module.

/// Seccomp filtering policy.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub enum SeccompProfile {
    /// Allow only essential syscalls (strictest; forking is prohibited).
    #[default]
    Essential,
    /// Essential + networking syscalls.
    Network,
    /// Essential syscalls + allow fork (for shells and other subprocess use cases).
    EssentialWithFork,
    /// Networking + allow fork.
    NetworkWithFork,
}
