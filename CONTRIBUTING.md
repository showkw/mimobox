# Contributing Guide

## Welcome

Contributions to mimobox are welcome.

mimobox is a cross-platform Agent Sandbox built with Rust. It aims to provide a secure, controllable, and high-performance isolated execution environment for AI Agent workloads. The project supports OS-level sandboxes, Wasm sandboxes, and microVM sandboxes, and provides default intelligent routing through a unified SDK.

Repository: <https://github.com/showkw/mimobox>

## Development Requirements

- Rust stable, using edition 2024.
- Linux or macOS.
- `cargo-nextest` and `cargo-audit`, installed by `scripts/setup.sh`.

## Setting Up the Development Environment

Initialize the development environment through the unified script:

```bash
scripts/setup.sh
```

This script installs or configures:

- `rustup`
- `clippy`
- `rustfmt`
- `cargo-nextest`
- `cargo-audit`

## Development Workflow

1. Fork this repository.
2. Create a feature branch: `git checkout -b feature/my-feature`.
3. Complete your code or documentation changes.
4. Run `scripts/check.sh` to execute `cargo check`, `clippy`, and `fmt --check`.
5. Run `scripts/test.sh` to execute workspace tests.
6. Commit and push your branch.
7. Create a Pull Request targeting the `main` branch.

## Commit Message Convention

- Use concise Chinese descriptions.
- Examples: `修复 XXX 问题`, `新增 YYY 功能`, `重构 ZZZ 模块`.
- Use a single-line description and do not end it with a period.

## Code Standards

- unsafe policy: all unsafe code must include a `// SAFETY:` comment explaining why that unsafe usage is sound.
- unwrap policy: `unwrap()` is forbidden in non-test code and is enforced by the workspace clippy lint `unwrap_used = deny`. Use `expect()` with a clear message, or propagate errors with `?`.
- Error handling: define error types with `thiserror`.
- Cross-platform compilation: platform-specific code must be isolated with `#[cfg(target_os = "...")]`.
- Read before writing: read and understand the existing code, interfaces, and tests before making changes.

## Security Standards

- Seccomp: Linux sandboxes must apply a seccomp filter and use whitelist mode by default.
- Landlock: Linux sandboxes must apply Landlock and deny all filesystem access by default.
- Network: all sandboxes must deny network access by default.
- Memory: all sandboxes must set memory limits.

## PR Process

1. Fork the repository, create a branch, submit a PR, receive review, and merge into `main`.
2. Make sure CI passes before requesting review.
3. At least one approval is required.

## CI Notes

CI runs on pushes to `main`, `master`, and on Pull Requests. The main jobs include:

- `lint-and-check`: runs `cargo check`, `fmt`, and `clippy` on `ubuntu-latest`.
- `test-linux-os`: runs `mimobox-os` tests.
- `test-linux-vm`: runs `mimobox-vm` tests, only when triggered manually, and requires `/dev/kvm`.
- `test-sdk`: builds `mimobox-sdk` and runs lib tests.
- `docs-check`: runs `cargo doc` and doc tests.
- `security-audit`: runs `cargo audit` through rustsec.
- `test-macos`: runs `mimobox-os` and `mimobox-wasm` tests on macOS.
- `test-linux-wasm`: runs `mimobox-wasm` tests on Linux.
- `test-mcp`: runs `mimobox-mcp` tests.
- `check-python`: runs `mimobox-python cargo check`.

## Script Entrypoints

All development operations must be executed through script entrypoints under the `scripts/` directory:

- `scripts/setup.sh`: initializes the development environment.
- `scripts/check.sh`: runs lint and static checks.
- `scripts/test.sh [default|linux|macos|wasm|all]`: runs tests.
- `scripts/test-e2e.sh`: runs cross-backend end-to-end tests.
- `scripts/bench.sh`: runs benchmark.

## License

MIT OR Apache-2.0
