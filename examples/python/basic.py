# basic.py — 最小示例：创建沙箱、执行命令、打印结果、销毁
#
# 演示 Sandbox 的最基本用法：不使用上下文管理器，手动管理生命周期。

from mimobox import Sandbox

# 创建沙箱（使用默认隔离级别 auto）
sandbox = Sandbox()

# 执行命令
result = sandbox.execute("echo 'Hello from mimobox!'")

# 打印结果
print(f"exit_code: {result.exit_code}")
print(f"stdout:    {result.stdout.strip()}")
print(f"stderr:    {result.stderr.strip()}")
print(f"timed_out: {result.timed_out}")
if result.elapsed is not None:
    print(f"elapsed:   {result.elapsed:.3f}s")

# 手动销毁（不使用 with 语句时需要自行清理）
sandbox.__exit__(None, None, None)
print("sandbox destroyed")
