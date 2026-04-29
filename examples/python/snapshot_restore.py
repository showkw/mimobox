# snapshot_restore.py — Snapshot and restore: snapshot() -> to_bytes() -> Sandbox.from_snapshot()
#
# Demonstrates the full snapshot lifecycle: capture snapshot -> serialize to bytes -> restore new sandbox from snapshot.

from mimobox import Sandbox, Snapshot

# Phase 1: Create state in the original sandbox
sandbox = Sandbox()
sandbox.execute("echo 'initial state' > /tmp/state.txt")
print("original sandbox: wrote initial state")

# Phase 2: Capture snapshot
snap = sandbox.snapshot()
print(f"snapshot captured, size: {snap.size} bytes")

# Serialize snapshot to bytes (can be saved to disk or database)
snap_bytes = snap.to_bytes()
print(f"serialized to {len(snap_bytes)} bytes")

# Phase 3: Restore a brand new sandbox from the snapshot
restored = Sandbox.from_snapshot(snap)
result = restored.execute("cat /tmp/state.txt")
print(f"restored sandbox reads: {result.stdout.strip()}")

# Can also reconstruct snapshot object from bytes, then restore as new sandbox
snap2 = Snapshot.from_bytes(snap_bytes)
restored2 = Sandbox.from_snapshot(snap2)
result2 = restored2.execute("cat /tmp/state.txt")
print(f"second restore reads:   {result2.stdout.strip()}")

print("snapshot/restore lifecycle complete")
