# http_request.py — HTTP 请求使用：通过沙箱内置代理发起 HTTPS 请求
#
# 演示如何在沙箱内发起 HTTP 请求。需要在创建 Sandbox 时
# 通过 allowed_http_domains 白名单指定允许访问的域名。

from mimobox import Sandbox

# 必须在创建时指定允许的域名（支持 glob 模式，如 *.openai.com）
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
