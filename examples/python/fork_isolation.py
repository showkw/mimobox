# fork_isolation.py — CoW Fork demo: millisecond-level sandbox cloning and isolation verification
#
# fork() uses copy-on-write technology to create independent copies from a running sandbox.
# The clone inherits all state, but subsequent modifications are fully isolated.
# Note: fork requires isolation='microvm', available only on Linux + KVM.

import platform
import time

from mimobox import Sandbox, SandboxError

# fork is only available on the Linux microVM backend
if platform.system() != 'Linux':
    print(f'CoW Fork requires Linux + KVM (current: {platform.system()})')
    print('This demo will skip. Run on a Linux host with KVM support.')
    raise SystemExit(0)

try:
    # 1. Create microVM sandbox and write initial state
    with Sandbox(isolation='microvm') as sb:
        sb.execute("echo 'original state' > /tmp/state.txt")
        print('parent: wrote initial state')

        # 2. Fork — millisecond-level copy-on-write
        t0 = time.perf_counter()
        child = sb.fork()
        t1 = time.perf_counter()
        print(f'fork completed in {(t1 - t0) * 1000:.1f}ms')

        # 3. Child sandbox modifies its own state
        child.execute("echo 'modified by child' > /tmp/state.txt")
        print('child:  overwrote state')

        # 4. Verify isolation — parent sandbox is unaffected
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
