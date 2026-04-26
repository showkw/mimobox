"""OpenAI Agents SDK 与 mimobox 沙箱集成示例。"""

import asyncio
import os

from agents import Agent, Runner, function_tool
from mimobox import Sandbox, SandboxError


DEFAULT_PROMPT = "Write a Python function that computes the first 20 Fibonacci numbers and test it."


async def run_demo() -> str:
    """创建一个带 mimobox 工具的 Agent，并返回最终输出。"""
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY environment variable is required.")

    # Sandbox 使用上下文管理器，确保 Agent 运行结束后自动释放资源。
    with Sandbox() as sandbox:

        @function_tool
        def execute_code(language: str, code: str, timeout: float = 10.0) -> str:
            """Execute source code in the mimobox sandbox and return stdout, stderr, and status."""
            try:
                result = sandbox.execute_code(
                    language=language,
                    code=code,
                    timeout=timeout,
                )
            except (SandboxError, ValueError) as exc:
                return f"Execution failed: {type(exc).__name__}: {exc}"

            parts = [
                f"exit_code={result.exit_code}",
                f"timed_out={result.timed_out}",
            ]
            if result.elapsed is not None:
                parts.append(f"elapsed={result.elapsed:.3f}s")
            if result.stdout:
                parts.append(f"stdout:\n{result.stdout}")
            if result.stderr:
                parts.append(f"stderr:\n{result.stderr}")

            return "\n".join(parts)

        @function_tool
        def read_file(path: str) -> str:
            """Read a UTF-8 text file from the mimobox sandbox."""
            try:
                # mimobox 返回 bytes，这里按 UTF-8 解码为 Agent 可读文本。
                return sandbox.read_file(path).decode("utf-8")
            except UnicodeDecodeError as exc:
                return f"Read failed: file is not valid UTF-8: {exc}"
            except (SandboxError, OSError) as exc:
                return f"Read failed: {type(exc).__name__}: {exc}"

        @function_tool
        def write_file(path: str, content: str) -> str:
            """Write UTF-8 text content to a file inside the mimobox sandbox."""
            try:
                # mimobox 接收 bytes，这里将工具入参编码后写入沙箱文件系统。
                sandbox.write_file(path, content.encode("utf-8"))
            except (SandboxError, OSError, UnicodeEncodeError) as exc:
                return f"Write failed: {type(exc).__name__}: {exc}"

            return f"Wrote {len(content.encode('utf-8'))} bytes to {path}"

        agent = Agent(
            name="mimobox-demo-agent",
            instructions=(
                "You are a coding agent. Use mimobox tools to write, run, and "
                "inspect code in the sandbox. Prefer executing tests before "
                "returning the final answer."
            ),
            tools=[execute_code, read_file, write_file],
            model="gpt-4o-mini",
        )

        result = await Runner.run(
            starting_agent=agent,
            input=DEFAULT_PROMPT,
        )
        return str(result.final_output)


def main() -> None:
    """同步入口：用 asyncio.run 调用异步 Runner.run。"""
    try:
        print(asyncio.run(run_demo()))
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
