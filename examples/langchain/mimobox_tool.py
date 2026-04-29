"""mimobox integration with LangChain example.

Install dependencies first:
    pip install mimobox langchain langchain-openai

Run:
    export OPENAI_API_KEY=sk-...
    python mimobox_tool.py
"""

from mimobox import Sandbox
from langchain_core.tools import tool


@tool
def sandbox_run_command(command: str) -> str:
    """Execute a shell command in a secure sandbox and return the output.

    Suitable for scenarios that require running code, inspecting files, or executing system commands.
    All commands run in an isolated sandbox environment and will not affect the host system.

    Args:
        command: shell command to execute
    """
    with Sandbox() as sb:
        result = sb.execute(command, timeout=30.0)
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr] {result.stderr}"
        if result.exit_code != 0:
            output += f"\n[exit code: {result.exit_code}]"
        return output or "(no output)"


@tool
def sandbox_run_python(code: str) -> str:
    """Execute Python code in a secure sandbox and return the output.

    Args:
        code: Python code to execute
    """
    with Sandbox() as sb:
        result = sb.execute_code("python", code, timeout=30.0)
        return result.stdout or "(no output)"


# Usage example
if __name__ == "__main__":
    # Quick verification
    with Sandbox() as sb:
        print(sb.execute("python3 --version").stdout)
