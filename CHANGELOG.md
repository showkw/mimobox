# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-25

### Added
- Three-tier isolation sandbox (OS / Wasm / microVM)
- SDK smart routing + Builder configuration
- Python SDK (PyO3): execute, stream_execute, read_file, write_file, http_request, snapshot, fork, close
- MCP Server with 10 tools (rmcp)
- CLI: execute, pty, snapshot, setup, doctor
- Streaming output (EXECS/STREAM frame protocol)
- HTTP proxy (domain whitelist + DNS rebinding protection)
- CoW Fork zero-copy (mmap MAP_PRIVATE)
- VM asset pre-built download + SHA256 verification
- LangChain integration example
- Warm pool (OS + microVM)
- SPECIFICATION.md with 9 performance specifications
- llms.txt AI discovery index
- CONTRIBUTING.md development guide
- Per-crate READMEs (8 crates)
- `full` feature aggregate configuration

### Fixed
- reqwest download timeout (connect 10s + read 300s)
- Resource leak defenses (VmPool/RestorePool Drop + Sandbox retry + MCP SIGTERM handler)
- clippy zero warnings (macOS + Linux)

### Changed
- CLI fully in English
- Error messages fully in English
- Documentation fully in English

## README Documentation History

| Version | Date | Summary | Type | Author |
| --- | --- | --- | --- | --- |
| v2.2 | 2026-04-25 | Refreshed README: synchronized the 8-crate workspace, MCP Server, Python SDK capabilities, section numbering, and Quick Start version number | Update | Codex |
| v2.1 | 2026-04-23 | Added the `doctor` environment diagnostics command and `setup` asset bootstrap command, and unified the default microVM asset directory to `~/.mimobox/assets` | Update | Codex |
| v2.0 | 2026-04-23 | Synchronized streaming output, HTTP proxy, structured error model, command-level env/timeout, Getting Started docs, and GitHub Actions CI status | Update | Codex |
| v1.6 | 2026-04-23 | Synchronized GitHub Actions CI to the streamlined 5-job version and documented KVM manual trigger plus hosted runner limitations | Update | Codex |
| v1.5 | 2026-04-21 | Final README review: synchronized directory structure, three-layer isolation status, SDK/CLI examples, competitive comparison framing, and roadmap status | Update | Codex |
| v1.4 | 2026-04-21 | Synchronized SDK, smart routing, microVM serial command channel, and Guest protocol status | Update | Codex |
| v1.3 | 2026-04-21 | Updated product positioning, performance data, and documentation index | Update | - |
| v1.2 | 2026-04-21 | Rewrote README according to the current workspace, CLI, scripts, and CI status | Update | Codex |
| v1.1 | 2026-04-21 | Synchronized documentation with the current codebase and added `mimobox-vm`, KVM, performance, and CI information | Update | Codex |
| v1.0 | 2026-04-20 | Rewrote the root README with architecture, API, performance, scripts, and security model details | Added | Codex |
