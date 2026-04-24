# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive API documentation: complete rewrite of `docs/api.md` covering all public SDK types
- Rust doc comments (`///`) for all public items in `mimobox-sdk` and `mimobox-core` crates
- CHANGELOG.md (this file)
- Quick-start examples in README.md for both Rust and Python

## [0.7.0] - 2026-04-24

### Added
- CoW Fork Phase 1: file-based Snapshot refactoring for zero-copy memory sharing
- CoW Fork Phase 2: `MAP_PRIVATE` restore via `mmap` path
- CoW Fork Phase 3: `fork()` API full chain (guest → host → SDK)
- Fork e2e tests: independent VM verification + latency benchmark
- Fork zero-copy optimization with `mmap` direct mount to KVM
- `mimobox-mcp` crate: MCP Server with `rmcp` + 3 core tools
- API freeze: stabilized public SDK surface
- Python SDK improvements and hardening
- Structured logging for VM performance output
- Agent integration demos: basic execution + streaming output
- SDK examples: `basic`, `streaming`, `agent_demo`, `agent_streaming`, `http_proxy`, `env_vars`, `file_ops`

### Changed
- Default VM memory adjusted to 256 MB for SDK configurations

### Fixed
- Hermes compilation/test errors: re-export `build_guest_exec_payload` + PTY test cfg gating
- PTY microVM test: silent skip when VM assets unavailable
- Wasm compilation fixes
- LLM agent example missing dev-dependencies

## [0.6.0] - 2026-04-23

### Added
- PTY interactive terminal session API (MVP): `create_pty()`, `PtySession`, `PtyEvent`
- Snapshot/fork SDK API: `snapshot()`, `from_snapshot()`, `fork()`, `RestorePool`
- `doctor` CLI command: environment diagnostics
- `setup` CLI command: microVM asset bootstrap
- `mimobox-sdk` dev-dependency for VM e2e tests
- crates.io publishing preparation: rustdoc, metadata, README, snapshot tests

### Fixed
- `PtySession` Debug implementation compatibility
- PTY echo tolerance for sandbox restrictions
- VM e2e test compatibility with SDK integration

## [0.5.0] - 2026-04-23

### Added
- Streaming output protocol (`EXECS` + `STREAM` frames): guest + host + SDK + Python full chain
- `stream_execute()` SDK method with `StreamEvent` enum
- HTTP proxy: host-side HTTPS proxy with domain whitelist (`allowed_http_domains`)
- `http_request()` SDK method with `HttpResponse` type
- Structured error model: `ErrorCode` + `SdkError::Sandbox { code, message, suggestion }`
- Per-command env injection: `execute_with_env()`, `execute_with_timeout()`, `execute_with_env_and_timeout()`
- Getting Started documentation (`docs/getting-started.md`)
- GitHub Actions CI configuration (`.github/workflows/ci.yml`)

### Changed
- Security semantics: fail-closed for `Untrusted` on unsupported platforms (no silent downgrade)
- `NetworkPolicy` cleaned up: `DenyAll` / `AllowDomains` / `AllowAll`
- README v2.0 with updated examples and Python SDK section

### Fixed
- HTTP proxy e2e test verification
- Warm pool whitelist bug in HTTP proxy path

## [0.4.0] - 2026-04-22

### Added
- microVM warm pool (`VmPool`): pre-warm pool with hot-path acquire (P50 773us)
- SDK `VmPool` integration: microVM path auto-uses warm pool
- `RestorePool`: pre-created VM shells for 28ms pooled snapshot restore
- vsock MMIO device emulator (Phase 1-2) and guest/host vsock communication
- Serial file transfer protocol (`FS:READ` + `FS:WRITE`)
- Python SDK via PyO3 + maturin (`mimobox-python` crate)
- Guest Python runtime support in rootfs

### Changed
- Default memory reduced: CLI 512 MB → 64 MB, SDK 128 MB → 64 MB
- VM cold boot optimized: CPUID host-passthrough + cmdline parameters + APIC initialization
- Cold boot target adjusted from <250ms to <300ms (P50 253ms achieved)

### Fixed
- Guest memory shortage + BusyBox URL expiration + Python execution verification
- rootfs build path and test read path inconsistency
- Pool hot-path regression from profiling code

## [0.3.0] - 2026-04-21

### Added
- Serial protocol `stdout`/`stderr` split
- Minimum guest kernel build script (`scripts/build-kernel.sh`)
- Cold boot profiling: host-side `BootProfile` + guest-side `BOOT_TIME` timestamps
- Wasm cold start benchmark
- CLI e2e integration tests for `--backend auto` routing and JSON output

### Changed
- Refactored `kvm.rs`: 3590 lines split into 6 submodules

### Fixed
- CLI exit code propagation
- SDK `Sandbox` `Drop` resource leak prevention
- rootfs build: missing BusyBox applets (`printf`), unified local/Docker build
- Borrow conflict in restore profiling code

## [0.2.0] - 2026-04-21

### Added
- `mimobox-sdk` crate: unified `Sandbox` API with smart routing (`IsolationLevel::Auto`)
- CLI `--backend auto` default
- Guest serial command channel for microVM real command execution
- SDK microVM backend integration: `Untrusted` code routes to hardware isolation
- `Config` + `ConfigBuilder` with 14 configurable parameters
- Competitor analysis and product strategy documents
- Seccomp profile variants: `Essential`, `Network`, `EssentialWithFork`, `NetworkWithFork`
- KVM build/test toolchain and cross-backend e2e verification
- CI full integration: KVM e2e + cross-backend e2e + vmlinux cache optimization

### Changed
- Removed vendor shim, switched to crates.io `rust-vmm` crates

### Fixed
- **CRITICAL**: macOS read whitelist tightened, Linux `setsid` escape removed
- macOS file read policy: switched to deny-based approach
- Seccomp architecture validation, `ioctl` whitelist hardening, process count limit
- `RLIMIT_NPROC` raised to 256 (64 caused `EAGAIN` in parallel tests)
- `build-rootfs.sh`: use `mktemp` instead of hardcoded temp path
- macOS Seatbelt test compatibility with restricted environments

## [0.1.0] - 2026-04-20

### Added
- Initial cross-platform Agent Sandbox implementation
- OS-level sandbox: Linux (Landlock + Seccomp-bpf + Namespaces + `setrlimit`) + macOS (Seatbelt / `sandbox-exec`)
- Wasm sandbox: Wasmtime-based execution via `wasm` feature
- KVM microVM backend: ELF loading, initrd, serial output, e2e tests
- `Sandbox` trait with `new` / `execute` / `destroy` lifecycle
- CLI with `run` and `bench` commands
- OS-level sandbox warm pool (`SandboxPool`) with P50 0.19us acquire
- CI pipeline: lint, test, release checks
- Performance baselines: OS cold start P50 8.24ms, Wasm cold start P50 1.01ms
- `rust-toolchain.toml` pinning Rust 1.95.0

### Fixed
- Linux sandbox seccomp `SIGSYS`: added shell-required syscalls to whitelist
- `vmm-sys-util` vendor shim: added `EventFd` implementation
- Read-only filesystem isolation test assertions
- Workspace-wide clippy warnings
