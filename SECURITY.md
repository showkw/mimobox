# Security Policy

This document describes the security model, supported versions, and disclosure process for mimobox.

## Security Model Overview

mimobox is a defense-in-depth sandbox for untrusted or semi-trusted agent
workloads. The project exposes three isolation layers:

- **OS-level sandbox**: native OS process, filesystem, network, and resource
  isolation.
- **Wasm sandbox**: Wasmtime-based execution for Wasm-compatible workloads.
- **microVM sandbox**: KVM-backed hardware virtualization for the strongest
  boundary available on supported Linux hosts.

Each layer starts from default deny. Files, network, and host resources must be explicitly granted by configuration.

## OS-Level Sandbox - Linux

The Linux OS-level sandbox combines kernel mechanisms to reduce host attack surface.

- **Landlock**: filesystem access is default deny. Only required paths are
  granted.
- **Seccomp-BPF**: filtering uses a whitelist of approximately 40 core syscalls
  needed for basic process execution. Non-whitelisted syscalls use the
  `KILL_PROCESS` action.
- **Namespaces**: PID, mount, and network namespaces isolate process identity,
  filesystem view, and network stack visibility.
- **cgroups v2**: memory, CPU, and PID limits constrain resource consumption.
- **Network**: access is denied by default unless policy permits it.

The threat boundary for this layer is the host kernel. Kernel vulnerabilities,
misconfigured kernel features, or privileged host integrations are the primary
escape vectors.

Known limitations:

- Landlock requires Linux kernel 5.13 or newer.
- The OS-level sandbox shares the host kernel with the sandboxed process.
- Seccomp policies must evolve when legitimate runtime syscall needs change.

## OS-Level Sandbox - macOS

macOS uses Seatbelt through `sandbox-exec` profiles.

- **Seatbelt profile**: a generated profile restricts filesystem, network, and
  process capabilities.
- **Write allowlist**: writes are denied by default and normally limited to
  `/tmp`.
- **Read control**: read access cannot be precisely narrowed in the same way as
  Linux Landlock because `dyld` and system tooling depend on many host paths.
- **Sensitive directories**: `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, and
  `.docker` are explicitly denied.
- **Network**: outbound and inbound network access are denied by default.
- **Process execution**: execution is restricted to `/bin`, `/usr/bin`, and
  other explicitly permitted runtime paths.

Known limitations:

- macOS does not provide a hard memory boundary equivalent to cgroups v2.
- `RLIMIT_AS` cannot be reliably lowered to enforce a strict memory ceiling.
- This layer should not be treated as equivalent to microVM isolation.

## Wasm Sandbox

The Wasm sandbox runs compatible workloads inside Wasmtime with WASI Preview 2.

- **Runtime**: Wasmtime executes WebAssembly components using WASI Preview 2.
- **Memory**: `StoreLimits` enforces bounded memory usage. The default memory
  limit is 64MB.
- **Execution time**: fuel and epoch interruption control CPU time and stop
  runaway execution.
- **Filesystem**: host access is denied unless a directory is explicitly
  preopened.
- **Network**: network access is always denied.

Known limitations:

- Only code compiled or adapted to Wasm can run in this layer.
- Native binaries, host syscalls, and arbitrary dynamic linking are out of
  scope.

## microVM Sandbox

The microVM sandbox provides the strongest isolation boundary in mimobox on
supported Linux hosts.

- **Hardware isolation**: KVM provides hardware-backed guest/host separation.
- **Guest environment**: workloads execute inside an independent guest kernel
  and root filesystem.
- **Control plane**: a serial console protocol is used for lifecycle and command
  control.
- **HTTP proxy**: outbound HTTP access is mediated by a host proxy with domain
  allowlists, DNS rebinding protection, request and response body size limits,
  and HTTPS-only enforcement.
- **Snapshots**: CoW Fork snapshot support enables fast restore and forked guest
  state.

The threat boundary is the virtualization boundary, guest kernel, and host-side
device and proxy implementation.

## Network Security Policy

Network access is denied by default across all layers. Workloads cannot open
arbitrary sockets or reach host-local services unless policy grants access.

For microVM workloads, network egress flows through the HTTP proxy. The proxy
enforces a domain allowlist, DNS rebinding protection, body size limits, and
HTTPS-only external destinations.

## Vulnerability Reporting

If you discover a security vulnerability in mimobox, report it responsibly.

- **Email**: send details to security@mimobox.io.
- **GitHub**: use the GitHub Security Advisory feature at
  https://github.com/showkw/mimobox/security/advisories/new.

Please do not file public issues for security vulnerabilities.

### What to Include

- A description of the vulnerability.
- Steps to reproduce or a proof of concept.
- The potential impact and affected configurations.
- Any suggested mitigations, if available.

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Status update | Every 7 days until resolved |
| Patch release | Based on severity (Critical: ASAP, High: 7 days, Medium: 30 days) |

## Supported Versions

Security fixes are provided for the latest minor release line. Older lines may
receive fixes only when extended support is explicitly announced.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes |
| < 0.1   | No |

## Security Audits

mimobox has not yet undergone a formal third-party security audit. We welcome
community review and responsible disclosure.
