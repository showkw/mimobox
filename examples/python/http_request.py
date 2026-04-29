# http_request.py — HTTP request usage: send HTTPS requests through the built-in sandbox proxy
#
# Demonstrates how to make HTTP requests inside a sandbox. When creating a Sandbox,
# specify allowed domains via the allowed_http_domains whitelist.

from mimobox import Sandbox

# Must specify allowed domains at creation time (supports glob patterns, e.g. *.openai.com)
with Sandbox(
    isolation="microvm",
    allowed_http_domains=["api.github.com"],
) as sandbox:
    response = sandbox.http_request(
        "GET",
        "https://api.github.com/zen",
        headers={
            "User-Agent": "mimobox-python-example",
            "Accept": "application/vnd.github+json",
        },
    )
    print(f"status:  {response.status}")
    print(f"headers: {dict(response.headers)}")
    print(f"body:    {response.body.decode('utf-8', errors='replace')}")
