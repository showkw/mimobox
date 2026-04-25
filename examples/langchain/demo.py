"""Minimal LangChain agent demo using mimobox sandbox tools."""

import os

from langchain.agents import create_react_agent, AgentExecutor
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI

from mimobox_tool import (
    MimoboxCreateSandboxTool,
    MimoboxDestroySandboxTool,
    MimoboxExecuteCodeTool,
)

# ReAct prompt template (LangChain 0.3+ 标准写法)
REACT_PROMPT = """Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought: {agent_scratchpad}"""


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

    prompt = PromptTemplate.from_template(REACT_PROMPT)
    agent = create_react_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
    )

    task = (
        "Use the available tools when useful. Calculate the first 12 Fibonacci "
        "numbers with code, then provide the result and a one-sentence summary."
    )
    response = agent_executor.invoke({"input": task})
    print(response["output"])


if __name__ == "__main__":
    main()
