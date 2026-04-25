# context_manager.py — 上下文管理器：with Sandbox() as sb: 自动资源管理
#
# 演示 with 语句自动管理沙箱生命周期。
# __enter__ 返回沙箱自身，__exit__ 自动销毁资源，即使发生异常也会清理。

from mimobox import Sandbox

# 基本用法：with 块结束后沙箱自动销毁
with Sandbox() as sandbox:
    result = sandbox.execute("echo 'inside context manager'")
    print(result.stdout.strip())

print("sandbox automatically destroyed after with block")

# 异常安全：即使命令执行出错，资源也会被正确清理
try:
    with Sandbox() as sandbox:
        sandbox.execute("echo 'before error'")
        raise RuntimeError("simulated error")
except RuntimeError:
    print("exception caught, sandbox was still properly cleaned up")

# 嵌套使用：多个沙箱可以同时存在
with Sandbox() as sb1, Sandbox() as sb2:
    r1 = sb1.execute("echo 'from sandbox 1'")
    r2 = sb2.execute("echo 'from sandbox 2'")
    print(r1.stdout.strip())
    print(r2.stdout.strip())
