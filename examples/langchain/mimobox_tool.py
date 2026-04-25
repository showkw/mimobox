"""LangChain tools for executing code inside mimobox sandboxes."""

from __future__ import annotations

import shlex
from typing import Dict, Optional, Type

from langchain.tools import BaseTool
from mimobox import Sandbox, SandboxError
from pydantic import BaseModel, ConfigDict, Field


# Persistent sandboxes are keyed by user-provided IDs so agents can reuse state.
_sandbox_registry: Dict[str, Sandbox] = {}


class MimoboxExecuteCodeInput(BaseModel):
    """Input for executing code in a mimobox sandbox."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., description="Code or shell command to execute.")
    language: str = Field(
        default="python",
        description="Language runtime to use: python, node, or bash.",
    )
    sandbox_id: Optional[str] = Field(
        default=None,
        description="Optional persistent sandbox ID to reuse.",
    )
    timeout: Optional[float] = Field(
        default=30.0,
        description="Maximum execution time in seconds.",
    )


class MimoboxCreateSandboxInput(BaseModel):
    """Input for creating a persistent mimobox sandbox."""

    model_config = ConfigDict(extra="forbid")

    sandbox_id: str = Field(..., description="Unique sandbox identifier.")
    isolation: str = Field(
        default="auto",
        description="Isolation backend: auto, os, wasm, or microvm.",
    )


class MimoboxDestroySandboxInput(BaseModel):
    """Input for destroying a persistent mimobox sandbox."""

    model_config = ConfigDict(extra="forbid")
    sandbox_id: str = Field(..., description="Sandbox identifier to destroy.")


def _build_command(code: str, language: str) -> str:
    """Convert tool input into a command understood by mimobox."""
    normalized = language.strip().lower()
    if normalized == "python":
        return f"python3 -c {shlex.quote(code)}"
    if normalized == "node":
        return f"node -e {shlex.quote(code)}"
    if normalized == "bash":
        return code
    raise ValueError("Unsupported language. Use one of: python, node, bash.")


def _format_result(command: str, result) -> str:
    """Render an ExecuteResult in an LLM-friendly format."""
    lines = [
        "Mimobox execution result:",
        f"command: {command}",
        f"exit_code: {result.exit_code}",
        f"timed_out: {result.timed_out}",
    ]
    if result.elapsed is not None:
        lines.append(f"elapsed: {result.elapsed:.3f}s")
    lines.extend(
        [
            "stdout:",
            result.stdout.rstrip() or "<empty>",
            "stderr:",
            result.stderr.rstrip() or "<empty>",
        ]
    )
    return "\n".join(lines)


def _destroy_sandbox(sandbox: Sandbox) -> None:
    """Release sandbox resources using the SDK context-manager protocol."""
    sandbox.__exit__(None, None, None)


class MimoboxExecuteCodeTool(BaseTool):
    """Execute Python, Node.js, or Bash code inside a secure mimobox sandbox.

    Use this tool when the agent needs to run calculations, inspect runtime
    behavior, or execute short scripts without trusting the host environment.
    Provide a sandbox_id to reuse a persistent sandbox created by
    MimoboxCreateSandboxTool; omit it for an isolated temporary sandbox.
    """

    name: str = "mimobox_execute_code"
    description: str = (
        "Execute Python, Node.js, or Bash code inside a mimobox sandbox. "
        "Use sandbox_id to reuse a persistent sandbox, or omit it for a "
        "temporary sandbox that is destroyed after execution."
    )
    args_schema: Type[BaseModel] = MimoboxExecuteCodeInput

    def _run(
        self,
        code: str,
        language: str = "python",
        sandbox_id: Optional[str] = None,
        timeout: Optional[float] = 30.0,
    ) -> str:
        try:
            command = _build_command(code, language)

            if sandbox_id is not None:
                sandbox = _sandbox_registry.get(sandbox_id)
                if sandbox is None:
                    return f"Sandbox not found: {sandbox_id}"
                result = sandbox.execute(command, timeout=timeout)
                return _format_result(command, result)

            with Sandbox() as sandbox:
                result = sandbox.execute(command, timeout=timeout)
                return _format_result(command, result)
        except (SandboxError, ValueError) as exc:
            return f"Mimobox execution failed: {type(exc).__name__}: {exc}"


class MimoboxCreateSandboxTool(BaseTool):
    """Create a persistent mimobox sandbox for multi-step agent workflows.

    Use this tool when the agent needs stateful execution across multiple tool
    calls, such as writing files in one step and executing them in a later step.
    The sandbox remains alive until MimoboxDestroySandboxTool is called.
    """

    name: str = "mimobox_create_sandbox"
    description: str = (
        "Create a persistent mimobox sandbox and store it by sandbox_id for "
        "later tool calls. Use this for stateful multi-step execution."
    )
    args_schema: Type[BaseModel] = MimoboxCreateSandboxInput

    def _run(self, sandbox_id: str, isolation: str = "auto") -> str:
        if sandbox_id in _sandbox_registry:
            return f"Sandbox already exists: {sandbox_id}"

        try:
            sandbox = Sandbox(isolation=isolation)
            _sandbox_registry[sandbox_id] = sandbox
            return f"Created mimobox sandbox '{sandbox_id}' with isolation='{isolation}'."
        except SandboxError as exc:
            return f"Failed to create sandbox: {type(exc).__name__}: {exc}"


class MimoboxDestroySandboxTool(BaseTool):
    """Destroy a persistent mimobox sandbox and remove it from the registry.

    Use this tool when a stateful sandbox is no longer needed so resources are
    released promptly. Temporary sandboxes do not require explicit destruction.
    """

    name: str = "mimobox_destroy_sandbox"
    description: str = (
        "Destroy a persistent mimobox sandbox by sandbox_id and remove it "
        "from the registry."
    )
    args_schema: Type[BaseModel] = MimoboxDestroySandboxInput

    def _run(self, sandbox_id: str) -> str:
        sandbox = _sandbox_registry.pop(sandbox_id, None)
        if sandbox is None:
            return f"Sandbox not found: {sandbox_id}"

        try:
            _destroy_sandbox(sandbox)
            return f"Destroyed mimobox sandbox '{sandbox_id}'."
        except SandboxError as exc:
            return f"Failed to destroy sandbox: {type(exc).__name__}: {exc}"

