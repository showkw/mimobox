# MimoBox Changelog

All notable changes to mimobox are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2026-04-26

### Added

- Released the initial cross-platform Agent Sandbox version, with OS, Wasm, and microVM three-layer isolation backends, plus default intelligent routing and explicit backend selection.
- Added a unified Rust SDK: `Sandbox`, `Config`, builder configuration, command execution, streaming output, file read/write, directory listing, HTTP requests, snapshots, Fork, PTY, resource closing, and related APIs.
- Added a Python SDK (PyO3): covering command execution, code execution, streaming output, working directory parameters, directory listing, file transfer, HTTP requests, snapshots, Fork, `close()`, type stubs, and structured lifecycle exceptions.
- Added CLI tooling: command execution, JSON output, PTY sessions, snapshot management, environment diagnostics, initialization, shell completions, MCP initialization, and automatic backend routing.
- Added the MCP Server crate, providing stdio transport and 11 sandbox tools based on rmcp, enabling Agents to invoke mimobox capabilities through MCP.
- Added the Linux OS sandbox backend: Landlock, Seccomp-bpf, Namespaces, cgroups v2, network-deny by default, resource limits, and fail-closed security semantics.
- Added the macOS OS sandbox backend: local sandboxed execution and file access restrictions based on Seatbelt.
- Added the Wasm sandbox backend: lightweight isolated execution based on Wasmtime, WASI Preview 2, and the Component Model.
- Added the KVM microVM backend: ELF loading, initrd, serial output, Guest command protocol, file transfer protocol, streaming output protocol, HTTP proxy protocol, and a real command execution path.
- Added CoW Fork zero-copy capability: file-backed Snapshot, `MAP_PRIVATE` restore path, SDK `template/fork` API, warm pool integration, and end-to-end tests.
- Added the microVM warm pool and RestorePool: supporting prestarted reuse, pooled snapshot restore, hot-path acquisition, and restore-to-ready performance optimization.
- Added serial protocol capabilities: stdout/stderr splitting, EXECS/STREAM frames, FS:READ/FS:WRITE file transfer, HTTP proxying, working directory passthrough, and exit code propagation.
- Added HTTP/HTTPS proxying: supporting domain allowlists, DNS rebinding protection, response header completion, warm pool allowlist propagation, and end-to-end validation.
- Added a vsock technical path prototype: guest kernel configuration, vsock MMIO device emulation, vhost-vsock backend, and host/guest command channels; the current official path uses pure serial mode by default.
- Added a VM asset system: minimal guest kernel/rootfs build scripts, prebuilt VM asset downloads, SHA256 verification, and Node.js plus BusyBox applet extensions.
- Added a one-command Docker trial image so users can quickly try the mimobox CLI and example capabilities.
- Added CPU quota configuration: `Config.cpu_quota_us` and cgroup v2 write support.
- Added Agent integration examples: basic execution, streaming output, LLM Agent demo, LangChain integration, OpenAI Agents SDK integration, multilingual execution, and CoW Fork examples.
- Added the Quick Start Demo script, covering core scenarios such as quick execution, timeouts, exit codes, stderr, and repeated execution.
- Added performance benchmarks and metrics: OS-level cold start P50 8.24ms, Wasm cold start P50 1.01ms (cold cache), warm pool acquire only P50 0.19us, full hot path P50 773us, microVM cold start P50 253ms, and microVM snapshot restore P50 69ms (non-pooled) / 28ms (pooled restore-to-ready).
- Added Criterion benchmarks, Wasm cold-start benchmarks, VmPool hot-path benchmarks, SDK benchmarks, and benchmark CI checks.
- Added GitHub Actions CI, Release CI, Python wheel builds, installation scripts, release scripts, release smoke tests, cargo-audit, clippy, fmt, and cross-platform checks.
- Added GitHub community health files, license, contribution guide, security policy, AI agent discovery files, crate metadata, per-crate READMEs, and release documentation.

### Changed

- Converged the SDK design to "default intelligent routing + full advanced-user control", automatically selecting the OS, Wasm, or microVM backend based on code trust level and platform capabilities.
- Changed the CLI default backend to `--backend auto`, and improved SDK-to-CLI error mapping to distinguish unavailable backends, configuration errors, and execution failures.
- Split SDK modules and extracted command, lifecycle, VM error mapping, backend dispatch, and binding logic to reduce coupling and improve maintainability.
- Changed lifecycle errors from string matching to structured enums, improving error handling stability and API testability.
- Changed MCP `next_id` from a lock-protected counter to `AtomicU64`, reducing synchronization overhead.
- Deduplicated Linux security policies by reusing Seccomp/Landlock rule construction logic, reducing duplicate implementation.
- Split the KVM backend from a single large `kvm.rs` into multiple submodules, migrated to the real rust-vmm crates from crates.io, and removed the vendor shim.
- Migrated VM performance output to structured logs, and added host-side BootProfile plus guest-side BOOT_TIME timestamps.
- Optimized microVM cold start: host-passthrough CPUID, streamlined cmdline parameters, APIC initialization optimizations, file caching, large zeroing, skipping redundant rootfs metadata, skipping redundant ELF loading, minimal kernel configuration, and rootfs reduction.
- Optimized default resource configuration: reduced CLI and SDK default memory to 64MB, and completed controllable configuration for vCPU, memory, CPU quota, and related resources.
- Adjusted the microVM cold-start target to P50 <300ms and met it at 253ms; pooled restore-to-ready met the snapshot restore target at 28ms.
- Disabled the vsock data plane by default and restored pure serial mode as the stable execution path, ensuring test and release reliability.
- Extended the Guest Rootfs with Node.js and more BusyBox applets, and unified local and Docker build paths.
- Unified workspace dependency versions and feature aggregation configuration, and added the `full` feature for full-capability builds.
- Fully English-localized the CLI, MCP Server, error messages, README, docs, CONTRIBUTING, and crate documentation to provide a unified public-release user experience.
- Standardized the official domain as `mimobox.io` and updated the README, documentation, and installation instructions accordingly.
- Improved installation and release experience: `install.sh` now supports more platforms, prebuilt binary installation, URL branch fixes, internationalized prompts, and the checksum generation flow.
- Rewrote the README hero section, quick start, product positioning, performance data, competitor comparison, roadmap, and 60-second trial entry point.

### Fixed

- Fixed shell injection risk in the Python SDK `cwd` parameter by switching to safe parameter passing.
- Fixed an HTTP proxy DNS rebinding race vulnerability, ensuring that domain allowlist validation matches the actual connection target.
- Fixed overly broad macOS file read security policy by switching to deny-based restrictions and tightening the read allowlist.
- Fixed Linux `setsid` escape risk, missing Seccomp architecture validation, overly broad ioctl allowlist, insufficient process-count limits, and shell startup SIGSYS issues.
- Fixed resource leak risks: VmPool/RestorePool Drop, defensive Sandbox retry, SDK Sandbox Drop, and MCP SIGTERM handler.
- Fixed MCP synchronous SDK calls blocking the runtime, nested `fork()` locks, stdio integration tests, and exit-code determination under seccomp.
- Fixed VM API tests, PTY microVM tests, VM e2e tests, PtySession Debug, PTY echo compatibility, and panic when VM assets are missing.
- Fixed microVM serial command protocol issues, timeout determination, stderr capture, exit code propagation, warm-pool hot-path degradation, and inconsistent rootfs build/test paths.
- Fixed guest memory shortages, expired BusyBox URLs, and missing minimal-kernel configurations required by guest init such as IOPL/FUTEX/EPOLL.
- Fixed Linux/macOS compilation issues in the Python SDK, Rust SDK, CLI, MCP, and streaming examples, including cfg-gated imports, musl ioctl types, pthread_t Send safety, KVM clippy lint, and release binary names.
- Fixed CLI e2e test failures under seccomp caused by `fork`, `printf`, stderr buffering, and platform limitations.
- Fixed a compilation error in the SDK directory-listing pooled VM branch, and completed list_dir integration tests for all backends.
- Fixed release blockers including LangChain examples, LLM Agent examples, quickstart demo binary name, release workflow, MCP dependency declaration, and api.md version number.
- Fixed install.sh branch name, download timeout, checksum generation order, README git clone URL, build-kernel.sh permissions, and build-rootfs temporary path issues.
- Fixed CI issues including macOS runner, Linux CLI KVM feature, maturin feature, target installation, cargo-audit installation, PID namespace assertion, and clippy installation.
- Cleaned up accidentally committed temporary files, plan files, `scheduled_tasks.lock`, and VM assets to avoid polluting the release package.

### Documentation

- Added and continuously updated API documentation, Python SDK documentation, MCP client integration guide, Getting Started, SPECIFICATION.md, and platform limitation notes.
- Added serial streaming output and HTTP proxy protocol design documents, recording the Guest serial channel, SDK intelligent routing, and microVM integration status.
- Added discussion documents for product strategy, three-layer isolation architecture decisions, competitor analysis, feature gap analysis, feasibility review, code reviews, and performance reports.
- Added contribution guide, security policy, FAQ, troubleshooting, release notes, GitHub community health files, AI discovery index, and per-crate READMEs.
- Updated the README with project positioning, installation and running instructions, quick start, Docker trial, performance metrics, CI status, license badge, documentation index, roadmap, and competitor comparison.
- Updated MCP documentation to use the prebuilt binary installation method, and synchronized API, Python SDK, and latest SDK capabilities.
- Synchronized the Chinese and English README structures, and fixed broken paths, platform limitations, installation commands, user journeys, and the official domain in documentation.

### Internal

- Established a multi-crate Rust workspace architecture: `mimobox-core`, `mimobox-sdk`, `mimobox-os`, `mimobox-wasm`, `mimobox-vm`, `mimobox-cli`, `mimobox-mcp`, and Python bindings.
- Established scripted engineering entry points: rootfs/kernel builds, tests, benchmarks, releases, quickstart, installation, and release smoke tests are all managed through `scripts/`.
- Established a cross-platform CI matrix: Linux OS/VM, macOS default feature, Wasm, KVM e2e, release checks, Python wheels, cargo audit, fmt, clippy, and doc links.
- Established the test system: CLI e2e, SDK integration, VmPool, fork isolation, OS sandbox security, MCP stdio, HTTP proxy, VM API, directory listing, snapshots, PTY, and performance benchmarks.
- Completed clippy zero warnings, unified fmt, rustdoc warning cleanup, documentation link fixes, and Rust toolchain pinning.
- Completed SDK dispatch logic deduplication, extracted macros to reduce duplicate code, and cleaned up duplicate Linux security-policy implementation.
- Completed release pipeline readiness: unified dependencies, community files, crate metadata, license, CHANGELOG, install.sh, release.yml, and automatic release scripts.
- Completed Linux server path migration, KVM build/test toolchain setup, VM asset paths, CI cache setup, and performance validation environment cleanup.
- Completed multiple rounds of product polish: API freeze, Python SDK completion, MCP tool expansion, documentation refresh, example gallery, English-localized errors, and public release preparation.
