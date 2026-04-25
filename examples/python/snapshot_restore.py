# snapshot_restore.py — 快照与恢复：snapshot() → to_bytes() → Sandbox.from_snapshot()
#
# 演示完整的快照生命周期：捕获快照 → 序列化为字节 → 从快照恢复新沙箱。

from mimobox import Sandbox, Snapshot

# 阶段 1：在原沙箱中创建状态
sandbox = Sandbox()
sandbox.execute("echo 'initial state' > /tmp/state.txt")
print("original sandbox: wrote initial state")

# 阶段 2：捕获快照
snap = sandbox.snapshot()
print(f"snapshot captured, size: {snap.size} bytes")

# 序列化快照为字节（可保存到磁盘或数据库）
snap_bytes = snap.to_bytes()
print(f"serialized to {len(snap_bytes)} bytes")

# 阶段 3：从快照恢复一个全新的沙箱
restored = Sandbox.from_snapshot(snap)
result = restored.execute("cat /tmp/state.txt")
print(f"restored sandbox reads: {result.stdout.strip()}")

# 也可以从字节重建快照对象，再恢复为新沙箱
snap2 = Snapshot.from_bytes(snap_bytes)
restored2 = Sandbox.from_snapshot(snap2)
result2 = restored2.execute("cat /tmp/state.txt")
print(f"second restore reads:   {result2.stdout.strip()}")

print("snapshot/restore lifecycle complete")
