"""mimobox integration with OpenAI Agents SDK example.

Install dependencies first:
    pip install mimobox openai-agents

Run:
    export OPENAI_API_KEY=sk-...
    python sandbox_tool.py
"""

from mimobox import Sandbox
from agents import function_tool


@function_tool
def sandbox_execute(command: str, timeout: float = 30.0) -> str:
    """Execute a shell command in a secure sandbox.

    Args:
        command: shell command to execute
        timeout: timeout in seconds

    Returns:
        Standard output of the command
    """
    with Sandbox() as sb:
        result = sb.execute(command, timeout=timeout)
        if result.timed_out:
            return f"Command timed out ({timeout}s)"
        if result.exit_code != 0:
            return f"Exit code {result.exit_code}\nstderr: {result.stderr}"
        return result.stdout


@function_tool
def sandbox_execute_code(language: str, code: str, timeout: float = 30.0) -> str:
    """Execute a code snippet in a secure sandbox.

    Args:
        language: programming language (python/javascript/bash)
        code: code to execute
        timeout: timeout in seconds

    Returns:
        Standard output of code execution
    """
    with Sandbox() as sb:
        result = sb.execute_code(language, code, timeout=timeout)
        if result.timed_out:
            return f"Execution timed out ({timeout}s)"
        if result.exit_code != 0:
            return f"Exit code {result.exit_code}\nstderr: {result.stderr}"
        return result.stdout


if __name__ == "__main__":
    # Quick verification
    with Sandbox() as sb:
        print(sb.execute("echo 'Hello from mimobox!'").stdout)
