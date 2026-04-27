# LangChain Integration for MimoBox

Use MimoBox as a sandbox tool in your LangChain agents.

This example shows how to expose the mimobox sandbox as LangChain tools. Agents
can execute Python, Node.js, or Bash code in temporary sandboxes, or create a
persistent sandbox and reuse it across multiple tool calls.

## Install

From the repository root, install the Python dependencies:

```bash
pip install -r examples/langchain/requirements.txt
```

Then install the local mimobox Python SDK:

```bash
cd crates/mimobox-python/
maturin develop
```

## Prerequisites

Set an OpenAI API key before running the demo:

```bash
export OPENAI_API_KEY="your-api-key"
```

## Run

From this directory:

```bash
python demo.py
```
