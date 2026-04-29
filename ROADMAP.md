# Roadmap

> This document outlines the planned development direction for MimoBox. Priorities may shift based on community feedback.

## Current Focus (Q2 2026)

### SDK Completeness
- [x] Sandbox registry (`Sandbox.list()`, `Sandbox.id()`)
- [x] Persistent environment variables at creation (`Config::env_var()`)
- [x] Runtime resource metrics (`Sandbox.metrics()`)
- [x] MCP Server file management tools (15 tools total)
- [ ] Background process management
- [ ] Process signal sending (SIGTERM, SIGKILL)
- [ ] Sandbox pause/resume
- [ ] Filesystem watch (`watch_dir`)

### Code Quality & Security
- [x] Comprehensive security audit and fixes (1 P0 + 25 P1 resolved)
- [x] Internationalization (all user-facing strings in English)
- [x] Privacy cleanup (zero personal information in git history)
- [ ] VM-layer serial protocol authentication
- [ ] VM-layer pool reuse isolation hardening

## Near-Term (Q3 2026)

### Network Capabilities
- [ ] HTTP proxy for OS/Wasm backends (currently microVM-only)
- [ ] Network ACL for OS-level isolation
- [ ] DNS interception

### Multi-Language SDKs
- [ ] TypeScript/JavaScript SDK (`@mimobox/sdk`)
- [ ] SDK feature parity across Rust, Python, TypeScript

### Platform Expansion
- [ ] Windows backend (AppContainer + Job Objects)
- [ ] ARM64 Linux prebuilt binaries

## Long-Term (Q4 2026+)

### Enterprise Features
- [ ] Kubernetes operator for production deployment
- [ ] Optional cloud-hosted version
- [ ] GPU passthrough for AI/ML workloads

### Advanced Capabilities
- [ ] Copy-on-write filesystem snapshots (BranchFS)
- [ ] Secret placeholder injection (credentials never enter sandbox)
- [ ] Deterministic execution mode
- [ ] Streaming metrics API
- [ ] Web dashboard for sandbox management

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where we'd especially love help:
- **Windows backend**: AppContainer + Job Objects implementation
- **TypeScript SDK**: napi-rs bindings for Node.js
- **Documentation**: Tutorials, guides, translations
- **Testing**: Integration tests for Linux-specific features

## Feedback

Have suggestions? [Open an issue](https://github.com/showkw/mimobox/issues/new) or start a [discussion](https://github.com/showkw/mimobox/discussions).
