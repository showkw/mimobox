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

