---
# mimobox Performance Specification (v0.1.0)

This document defines the formal performance specifications for mimobox v0.1.0. Each specification includes a precise definition, measurement method, test conditions, and pass/fail criteria. These are measured using criterion benchmarks located in the benches/ directory of each crate.

## 1. OS-Level Cold Start

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 10ms |
| **Definition** | Wall-clock time from `PlatformSandbox::new()` before call to after `execute(/bin/true)` returns successfully, including the full create-execute-destroy lifecycle |
| **Measurement** | Criterion benchmark `bench_cold_create` in `crates/mimobox-os/benches/pool_bench.rs` |
| **Test Conditions** | Linux with Landlock + Seccomp enabled; `SandboxConfig` with `memory_limit_mb = 256`; `sample_size = 20`; measurement over 4 seconds; command: `/bin/true` |
| **Pass Criteria** | P50 latency ≤ 10ms across all samples |

## 2. Wasm Cold Start

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 5ms |
| **Definition** | Wall-clock time from `WasmSandbox::new()` before call to after `execute(noop wasm module)` returns successfully, with the Wasmtime disk cache cleared before each sample |
| **Measurement** | Criterion benchmark `true_cold_start` in `crates/mimobox-wasm/benches/wasm_bench.rs` |
| **Test Conditions** | Linux or macOS; Wasmtime engine; `SandboxConfig` with `memory_limit_mb = 64`, `SeccompProfile::Essential`; `sample_size = 100`; Wasm module is a minimal noop \`_start\` function |
| **Pass Criteria** | P50 latency ≤ 5ms across all samples |

## 3. microVM Cold Start

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 300ms |
| **Definition** | Wall-clock time from `KvmBackend::create_vm()` before call through `boot()` to after `run_command(echo hello)` returns successfully, including full VM shutdown |
| **Measurement** | Criterion benchmark `bench_cold_start` in `crates/mimobox-vm/benches/kvm_bench.rs` |
| **Test Conditions** | Linux with KVM available; Rust feature flag `kvm`; `MicrovmConfig` loaded from VM assets with 256MB guest memory; command: `/bin/echo hello` |
| **Pass Criteria** | P50 latency ≤ 300ms across all samples |

## 4. OS-Level Pool Hot Acquire

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 1ms |
| **Definition** | Wall-clock time from `SandboxPool::acquire()` before call to after `drop()` of the acquired sandbox completes, measuring pure object acquisition cost without any command execution |
| **Measurement** | Criterion benchmark `bench_hot_acquire` in `crates/mimobox-os/benches/pool_bench.rs` |
| **Test Conditions** | Linux or macOS; `SandboxPool` pre-warmed with `min_size = 64`, `max_size = 64`; `sample_size = 60`; `measurement_time = 6s` |
| **Pass Criteria** | P50 latency ≤ 1ms (acquire-only, no command execution) |

## 5. microVM Pool Hot Path

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 1ms |
| **Definition** | Wall-clock time from `VmPool::acquire()` before call through `pooled.execute(echo hello)` return to after `drop()` completes, measuring pool acquire plus a single command execution |
| **Measurement** | Criterion benchmark `bench_pool_hot_path` in `crates/mimobox-vm/benches/kvm_bench.rs` |
| **Test Conditions** | Linux with KVM available; Rust feature flag `kvm`; `VmPool` with `min_size = 1`, `max_size = 4`; command: `/bin/echo hello` |
| **Pass Criteria** | P50 latency ≤ 1ms across all samples |

## 6. microVM Snapshot Restore (Non-Pooled)

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 70ms |
| **Definition** | Wall-clock time from `KvmBackend::create_vm_for_restore()` before call through `restore_state(memory, vcpu_state)` to after `run_command(echo hello)` returns and shutdown completes, using an in-memory snapshot from a previously booted VM |
| **Measurement** | Criterion benchmark `bench_snapshot_restore` in `crates/mimobox-vm/benches/kvm_bench.rs` |
| **Test Conditions** | Linux with KVM available; Rust feature flag `kvm`; in-memory snapshot captured from a fully booted VM; includes full create-restore-execute-shutdown lifecycle |
| **Pass Criteria** | P50 latency ≤ 70ms across all samples |

## 7. microVM Restore Pool (Pooled)

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 30ms |
| **Definition** | Wall-clock time from `RestorePool::restore(memory, vcpu_state)` before call through `restored.execute(echo hello)` return to after `drop()` completes, using pre-created empty-shell VM instances from the restore pool |
| **Measurement** | Criterion benchmark `bench_restore_pool` in `crates/mimobox-vm/benches/kvm_bench.rs` |
| **Test Conditions** | Linux with KVM available; Rust feature flag `kvm`; `RestorePool` with `min_size = 1`, `max_size = 4`; restore-to-ready only (pre-created empty VM shells); command: `/bin/echo hello` |
| **Pass Criteria** | P50 latency ≤ 30ms across all samples |

## 8. microVM Continuous Command Execution

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 5ms |
| **Definition** | Per-command wall-clock time on an already-booted VM, rotating between `/bin/echo alpha`, `/bin/echo beta`, and `/bin/true` commands in a loop |
| **Measurement** | Criterion benchmark `bench_command_execution` in `crates/mimobox-vm/benches/kvm_bench.rs` |
| **Test Conditions** | Linux with KVM available; Rust feature flag `kvm`; single pre-booted VM; 3-command rotation; per-command timing measured inside the boot loop |
| **Pass Criteria** | P50 per-command latency ≤ 5ms across all samples |

## 9. CoW Fork

| Field | Value |
|-------|-------|
| **Target** | P50 ≤ 15ms |
| **Definition** | Wall-clock time from `sandbox.fork()` before call to the forked VM being ready for command execution (i.e., the fork syscall + mmap MAP_PRIVATE setup completes) |
| **Measurement** | Integration test `bench_fork_latency()` in `crates/mimobox-vm/tests/kvm_e2e.rs` (uses `Instant::now` timing) |
| **Test Conditions** | Linux with KVM available; Rust feature flag `kvm`; fork based on `mmap(MAP_PRIVATE)` copy-on-write; VM must be booted before fork |
| **Pass Criteria** | P50 latency ≤ 15ms across all samples |

---

## Summary Table

| # | Specification | Target | Benchmark Location |
|---|--------------|--------|--------------------|
| 1 | OS-Level Cold Start | P50 ≤ 10ms | `crates/mimobox-os/benches/pool_bench.rs` — `bench_cold_create` |
| 2 | Wasm Cold Start | P50 ≤ 5ms | `crates/mimobox-wasm/benches/wasm_bench.rs` — `true_cold_start` |
| 3 | microVM Cold Start | P50 ≤ 300ms | `crates/mimobox-vm/benches/kvm_bench.rs` — `bench_cold_start` |
| 4 | OS-Level Pool Hot Acquire | P50 ≤ 1ms | `crates/mimobox-os/benches/pool_bench.rs` — `bench_hot_acquire` |
| 5 | microVM Pool Hot Path | P50 ≤ 1ms | `crates/mimobox-vm/benches/kvm_bench.rs` — `bench_pool_hot_path` |
| 6 | microVM Snapshot Restore (Non-Pooled) | P50 ≤ 70ms | `crates/mimobox-vm/benches/kvm_bench.rs` — `bench_snapshot_restore` |
| 7 | microVM Restore Pool (Pooled) | P50 ≤ 30ms | `crates/mimobox-vm/benches/kvm_bench.rs` — `bench_restore_pool` |
| 8 | microVM Continuous Command Execution | P50 ≤ 5ms | `crates/mimobox-vm/benches/kvm_bench.rs` — `bench_command_execution` |
| 9 | CoW Fork | P50 ≤ 15ms | `crates/mimobox-vm/tests/kvm_e2e.rs` — `bench_fork_latency` |

---

These specifications are measured using criterion benchmarks located in the `benches/` directory of each crate. They represent v0.1.0 target values and may be adjusted in future versions. To run benchmarks, use `scripts/bench.sh [crate-name] [bench-name|all]`.
---
