"""mimobox 集成 OpenAI Agents SDK 示例。

使用前安装依赖：
    pip install mimobox openai-agents

运行：
    export OPENAI_API_KEY=sk-...
    python sandbox_tool.py
"""

from mimobox import Sandbox
from agents import function_tool


@function_tool
def sandbox_execute(command: str, timeout: float = 30.0) -> str:
    """在安全沙箱中执行 shell 命令。

    Args:
        command: 要执行的 shell 命令
        timeout: 超时时间（秒）

    Returns:
        命令的标准输出
    """
    with Sandbox() as sb:
        result = sb.execute(command, timeout=timeout)
        if result.timed_out:
            return f"命令超时（{timeout}秒）"
        if result.exit_code != 0:
            return f"退出码 {result.exit_code}\nstderr: {result.stderr}"
        return result.stdout


@function_tool
def sandbox_execute_code(language: str, code: str, timeout: float = 30.0) -> str:
    """在安全沙箱中执行代码片段。

    Args:
        language: 编程语言（python/javascript/bash）
        code: 要执行的代码
        timeout: 超时时间（秒）

    Returns:
        代码执行的标准输出
    """
    with Sandbox() as sb:
        result = sb.execute_code(language, code, timeout=timeout)
        if result.timed_out:
            return f"执行超时（{timeout}秒）"
        if result.exit_code != 0:
            return f"退出码 {result.exit_code}\nstderr: {result.stderr}"
        return result.stdout


if __name__ == "__main__":
    # 快速验证
    with Sandbox() as sb:
        print(sb.execute("echo 'Hello from mimobox!'").stdout)
