**English** | [中文](CONTRIBUTING.zh-CN.md)

# Contributing Guide

## Thank You
Thank you for your interest in contributing code, documentation, tests, or issue reports to mimobox.

mimobox is a cross-platform Agent Sandbox built with Rust. Its goal is to provide a secure, controllable, and high-performance isolated execution environment for AI Agent workloads.

Repository: <https://github.com/showkw/mimobox>

## Development Environment
Prefer using the unified setup script to initialize the environment:

```bash
scripts/setup.sh
```

Basic requirements:
- Rust stable toolchain. This project uses edition 2024.
- macOS: install Xcode Command Line Tools.
- Linux: install `build-essential`, `libssl-dev`, and `python3-dev`.
- Optional: Linux KVM access for microVM testing.

`scripts/setup.sh` installs or checks common tools:
- `rustup`
- `rustfmt`
- `clippy`
- `cargo-nextest`
- `cargo-audit`

If you are only changing documentation, a full KVM environment is usually not required.

## Build and Test
Common commands:

```bash
cargo build
cargo test
scripts/check.sh
scripts/test.sh
```

`scripts/check.sh` runs `clippy` and `fmt` checks.

`scripts/test.sh` runs workspace tests. Test scope can be selected by platform or capability; see the script help output for the exact parameters.

Feature flags:
- `wasm`: enables the Wasm sandbox capability for cross-platform scenarios.
- `kvm`: enables KVM / microVM capability. Linux only.

Examples:

```bash
cargo test --features wasm
cargo test --features kvm
```

Changes involving the Linux OS sandbox, Landlock, Seccomp, KVM, or microVM should be verified in a Linux environment.

Changes involving the macOS sandbox or cross-platform paths should be verified in a macOS environment.

## Code Style
Before submitting, the following requirements must be met:
- `cargo fmt` must pass.
- `cargo clippy` must not report any warnings.
- All `unsafe` code must include a `// SAFETY:` comment explaining the safety assumptions.
- `unwrap()` is forbidden in non-test code.
- Platform-specific code must be isolated with `#[cfg(target_os = "...")]`.
- Error handling should use `thiserror` to define clear error types.

Error handling recommendations:
- Prefer `?` to propagate errors upward.
- When context is needed, use explicit error variants or readable `expect()` messages.
- Do not swallow errors, and do not replace structured errors with broad strings.

Cross-platform code recommendations:
- Put common abstractions in platform-independent modules.
- Put Linux, macOS, Windows, and other platform implementations in separate modules.
- When adding platform capabilities, add corresponding tests or document why testing is not possible.

Security-related code must preserve the default-deny principle:
- The Linux sandbox enables a Seccomp whitelist by default.
- The Linux sandbox enables Landlock by default and denies filesystem access.
- Sandboxes deny network access by default.
- Sandboxes must enforce memory limits.

## PR Process
Recommended workflow:
1. Fork the repository.
2. Create a feature branch from the latest main branch.
3. Complete the code, test, and documentation changes.
4. Run `scripts/check.sh` and `scripts/test.sh`.
5. Commit and push the branch.
6. Create a Pull Request.

PR requirements:
- The PR title should describe the change concisely.
- Commit messages should be concise and descriptive, avoid vague messages like "update code".
- Request review only after CI passes.
- At least one approval is required before merging.
- Commit only files related to this PR, and avoid mixing in unrelated changes.

Commit message examples: `Fix Linux sandbox error propagation logic`, `Add Wasm backend integration tests`.

## Security Reports
If you discover a security vulnerability, please read and follow `SECURITY.md`.

Do not disclose security vulnerability details in public issues, public discussions, or public PRs.

Please report through the private channel specified in `SECURITY.md`, and include reproduction steps, impact scope, and environment information.

## CI Notes
CI runs baseline checks on Pull Requests and main branch updates. These usually include formatting, Clippy, Linux and macOS tests, Wasm backend tests, documentation builds, doctest, and security audits.

microVM tests that require `/dev/kvm` are usually run only in Linux environments with KVM permissions.

## License
mimobox is dual-licensed as `MIT OR Apache-2.0`.

By submitting a contribution, you agree that your contribution is released under the `MIT OR Apache-2.0` dual license.
