"""mimobox 集成 LangChain 示例。

使用前安装依赖：
    pip install mimobox langchain langchain-openai

运行：
    export OPENAI_API_KEY=sk-...
    python mimobox_tool.py
"""

from mimobox import Sandbox
from langchain_core.tools import tool


@tool
def sandbox_run_command(command: str) -> str:
    """在安全沙箱中执行 shell 命令，返回输出结果。

    适用于需要运行代码、检查文件、执行系统命令的场景。
    所有命令在隔离的沙箱环境中运行，不会影响主机系统。

    Args:
        command: 要执行的 shell 命令
    """
    with Sandbox() as sb:
        result = sb.execute(command, timeout=30.0)
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr] {result.stderr}"
        if result.exit_code != 0:
            output += f"\n[exit code: {result.exit_code}]"
        return output or "(无输出)"


@tool
def sandbox_run_python(code: str) -> str:
    """在安全沙箱中执行 Python 代码，返回输出结果。

    Args:
        code: 要执行的 Python 代码
    """
    with Sandbox() as sb:
        result = sb.execute_code("python", code, timeout=30.0)
        return result.stdout or "(无输出)"


# 使用示例
if __name__ == "__main__":
    # 快速验证
    with Sandbox() as sb:
        print(sb.execute("python3 --version").stdout)
