# OpenAI Agents SDK Integration for mimobox

This example shows how to expose the mimobox sandbox as tools for the OpenAI
Agents SDK. The agent can execute code, read files, and write files inside a
temporary mimobox sandbox.

## Install

From the repository root, install the Python dependencies:

```bash
pip install -r examples/openai_agent/requirements.txt
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

## Notes

- The OpenAI Agents SDK package is installed with `pip install openai-agents`,
  but imported as `agents` in Python code.
- `Runner.run` is asynchronous, so the demo wraps it with `asyncio.run`.
- The mimobox sandbox is scoped with `with Sandbox() as sandbox:` and tools
  capture that sandbox through closures.
- `read_file` decodes bytes as UTF-8 text, while `write_file` encodes text to
  bytes before writing into the sandbox.
