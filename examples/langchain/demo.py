"""Minimal LangChain agent demo using mimobox sandbox tools."""

import os

from langchain.agents import AgentExecutor, AgentType, initialize_agent
from langchain_openai import ChatOpenAI

from mimobox_tool import (
    MimoboxCreateSandboxTool,
    MimoboxDestroySandboxTool,
    MimoboxExecuteCodeTool,
)


def main() -> None:
    """Run a small agent task that can decide to execute sandboxed code."""
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY environment variable is required.")

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    tools = [
        MimoboxExecuteCodeTool(),
        MimoboxCreateSandboxTool(),
        MimoboxDestroySandboxTool(),
    ]

    agent: AgentExecutor = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        verbose=True,
        handle_parsing_errors=True,
    )

    prompt = (
        "Use the available tools when useful. Calculate the first 12 Fibonacci "
        "numbers with code, then provide the result and a one-sentence summary."
    )
    response = agent.invoke({"input": prompt})
    print(response["output"])


if __name__ == "__main__":
    main()

