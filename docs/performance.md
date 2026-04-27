# MimoBox Performance

This document defines the performance baselines and measurement boundaries used by the root README.

## Current P50 Baselines

| Scenario | Target | Current Baseline | Status |
| --- | --- | --- | --- |
| OS-level cold start | <10ms | P50: 8.24ms | Meets target |
| Wasm-level cold start | <5ms | P50: 1.01ms (cold cache) | Meets target |
| OS warm pool hot acquisition | <100us | P50: 0.19us | Meets target |
| microVM cold start | <300ms | P50: 253ms | Meets target |
| microVM snapshot restore | <50ms | P50: 69ms non-pooled / 28ms pooled restore-to-ready | Pooled path meets target |
| microVM warm pool hot path | <1ms | P50: 773us | Meets target |

## Metric Definitions

| Metric | Start | End | Notes |
| --- | --- | --- | --- |
| OS-level cold start | Before creating OS-level sandbox | After executing `/bin/true` | Includes create, execute, and destroy lifecycle |
| Wasm cold start | Before creating Wasm sandbox | After executing Wasm module | May be affected by module cache |
| Warm pool hot acquisition | Before acquiring from warm pool | After releasing sandbox completes | Measures object acquisition only, excluding command execution |
| microVM cold start | Before creating microVM | After executing echo command | Includes create, boot, execute, and shutdown lifecycle |
| microVM snapshot restore | Before creating microVM for restore | After executing echo command | In-memory snapshot, not file restore |
| microVM pooled snapshot restore | Acquiring pre-created empty-shell VM from pool | After memory write and vCPU restore are complete | Excludes command execution; the empty-shell VM is pre-created by the pool |
| microVM warm pool hot path | Before acquiring from warm pool | After executing echo in pooled VM | Light load |

## Interpretation Notes

- The OS warm pool number measures the object acquisition cost of `acquire()` plus `drop()`, excluding command execution.
- Pooled snapshot restore measures restore-to-ready, excluding command execution and pool refill overhead.
- Non-pooled snapshot restore includes the full lifecycle.
- External product latency is intentionally not tracked here because it changes quickly with version, template, region, and warm state.

## Maintenance

- Update this document when benchmark results, measurement boundaries, or benchmark scripts change.
- Keep the root README table compact and link here for definitions.
- Run benchmark workflows through repository scripts, not ad hoc commands.
