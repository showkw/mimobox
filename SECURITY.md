# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in mimobox, please report it responsibly:

- **Email**: Send details to security@mimobox.dev (or open a GitHub Security Advisory)
- **GitHub**: Use the [Security Advisory](https://github.com/showkw/mimobox/security/advisories/new) feature

Please do not file public issues for security vulnerabilities.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations (optional)

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Status update | Every 7 days until resolved |
| Patch release | Based on severity (Critical: ASAP, High: 7 days, Medium: 30 days) |

## Security Model

mimobox provides three layers of sandboxing for AI agent code execution:

### OS-Level Sandbox (Linux / macOS / Windows)
- **Linux**: Landlock filesystem restrictions + Seccomp-BPF syscall filtering + Linux namespaces + cgroups v2
- **macOS**: Seatbelt (sandbox-exec) profiles
- **Windows**: AppContainer + Job Objects (planned)
- Default deny: filesystem access, network access, and syscalls are restricted by default

### Wasm Sandbox
- Based on Wasmtime runtime with WASI Preview 2
- Memory-limited, capability-based security model
- No direct filesystem or network access unless explicitly granted

### microVM Sandbox
- Hardware-level isolation via KVM / Hypervisor.framework
- Independent guest kernel and root filesystem
- Serial console and vsock communication channels
- Snapshot and CoW fork support for fast state management

### General Principles
- **Default deny**: All sandboxes block network and filesystem access by default
- **Principle of least privilege**: Only the minimum required permissions are granted
- **Defense in depth**: Multiple isolation layers can be composed for critical workloads
- **No unsafe without justification**: All unsafe code requires SAFETY documentation

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes |
| < 0.1   | No |

## Security Audits

mimobox has not yet undergone a formal third-party security audit. We welcome community review and responsible disclosure.
