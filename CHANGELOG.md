# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-25

### Added
- Initial cross-platform Agent Sandbox implementation
- OS-level sandbox: Linux (Landlock + Seccomp-bpf + Namespaces + setrlimit) + macOS (Seatbelt / sandbox-exec)
- Wasm sandbox: Wasmtime-based execution via wasm feature
- microVM sandbox: KVM backend with ELF loading, initrd, serial output
- Sandbox trait with new / execute / destroy lifecycle
- CLI with run, bench, setup, doctor commands
- OS-level sandbox warm pool (SandboxPool) with P50 0.19us acquire
- microVM warm pool (VmPool): pre-warm pool with hot-path acquire (P50 773us)
- RestorePool: pre-created VM shells for 28ms pooled snapshot restore
- Unified SDK with smart routing (IsolationLevel::Auto) and ConfigBuilder with 14 configurable parameters
- Streaming output protocol (EXECS + STREAM frames): guest + host + SDK + Python full chain
- HTTP proxy: host-side HTTPS proxy with domain whitelist
- Serial file transfer protocol (FS:READ + FS:WRITE)
- Serial protocol stdout/stderr split
- Snapshot/fork SDK API: snapshot(), from_snapshot(), fork(), RestorePool
- CoW Fork: file-based Snapshot + MAP_PRIVATE restore + fork() API full chain
- Fork zero-copy optimization with mmap direct mount to KVM
- PTY interactive terminal session API: create_pty(), PtySession, PtyEvent
- MCP Server crate (mimobox-mcp) with rmcp + 3 core tools
- Python SDK via PyO3 + maturin (mimobox-python crate)
- Guest Python runtime support in rootfs
- Per-command env injection: execute_with_env(), execute_with_timeout(), execute_with_env_and_timeout()
- Structured error model: ErrorCode + SdkError::Sandbox { code, message, suggestion }
- Security: fail-closed for Untrusted on unsupported platforms, NetworkPolicy (DenyAll/AllowDomains/AllowAll)
- Seccomp profile variants: Essential, Network, EssentialWithFork, NetworkWithFork
- CI pipeline: lint, test, release checks + GitHub Actions CI
- Minimum guest kernel build script
- Cold boot profiling: host-side BootProfile + guest-side BOOT_TIME timestamps
- Guest serial command channel for microVM real command execution
- Comprehensive API documentation and Rust doc comments for all public items
- Quick-start examples in README.md for both Rust and Python
- SDK examples: basic, streaming, agent_demo, agent_streaming, http_proxy, env_vars, file_ops
- Agent integration demos: basic execution + streaming output
- Getting Started documentation
- Competitor analysis and product strategy documents
- rust-toolchain.toml pinning Rust edition 2024

### Changed
- Default VM memory adjusted to 256 MB for SDK configurations
- Default memory reduced: CLI 512 MB -> 64 MB, SDK 128 MB -> 64 MB
- Refactored kvm.rs: 3590 lines split into 6 submodules
- README v2.0 with updated examples and Python SDK section
- Removed vendor shim, switched to crates.io rust-vmm crates

### Fixed
- CRITICAL: macOS read whitelist tightened, Linux setsid escape removed
- macOS file read policy: switched to deny-based approach
- Linux sandbox seccomp SIGSYS: added shell-required syscalls to whitelist
- Seccomp architecture validation, ioctl whitelist hardening, process count limit
- RLIMIT_NPROC raised to 256 (64 caused EAGAIN in parallel tests)
- Guest memory shortage + BusyBox URL expiration + Python execution verification
- rootfs build: missing BusyBox applets (printf), unified local/Docker build, use mktemp
- PTY microVM test: silent skip when VM assets unavailable
- Wasm compilation fixes
- CLI exit code propagation
- SDK Sandbox Drop resource leak prevention
- Borrow conflict in restore profiling code
- Pool hot-path regression from profiling code
- HTTP proxy e2e test verification
- Warm pool whitelist bug in HTTP proxy path
- Hermes compilation/test errors: re-export build_guest_exec_payload + PTY test cfg gating
- Workspace-wide clippy warnings
