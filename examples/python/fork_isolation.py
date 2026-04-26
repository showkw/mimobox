# fork_isolation.py — CoW Fork 演示：毫秒级沙箱复制与隔离验证
#
# fork() 使用 copy-on-write 技术，从运行中的沙箱创建独立副本。
# 副本继承所有状态，但后续修改完全隔离。
# 注意: fork 需要 isolation='microvm'，仅在 Linux + KVM 上可用。

import platform
import time

from mimobox import Sandbox, SandboxError

# fork 仅在 Linux microVM 后端上可用
if platform.system() != 'Linux':
    print(f'CoW Fork requires Linux + KVM (current: {platform.system()})')
    print('This demo will skip. Run on a Linux host with KVM support.')
    raise SystemExit(0)

try:
    # 1. 创建 microVM 沙箱并写入初始状态
    with Sandbox(isolation='microvm') as sb:
        sb.execute("echo 'original state' > /tmp/state.txt")
        print('parent: wrote initial state')

        # 2. Fork — 毫秒级 copy-on-write
        t0 = time.perf_counter()
        child = sb.fork()
        t1 = time.perf_counter()
        print(f'fork completed in {(t1 - t0) * 1000:.1f}ms')

        # 3. 子沙箱修改自己的状态
        child.execute("echo 'modified by child' > /tmp/state.txt")
        print('child:  overwrote state')

        # 4. 验证隔离 — 父沙箱不受影响
        r_parent = sb.execute('cat /tmp/state.txt')
        r_child = child.execute('cat /tmp/state.txt')

        print(f'parent state: {r_parent.stdout.strip()}')
        print(f'child state:  {r_child.stdout.strip()}')

        assert 'original' in r_parent.stdout, 'parent should be unchanged'
        assert 'modified' in r_child.stdout, 'child should see its changes'
        print('isolation verified: parent and child are independent')

        child.close()

except SandboxError as exc:
    print(f'fork demo failed: {exc}')
    print('ensure KVM is available and microVM backend is configured.')
    raise SystemExit(0)
