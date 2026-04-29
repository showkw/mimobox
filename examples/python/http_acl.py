# http_acl.py — HTTP ACL 规则配置：细粒度控制沙箱内的 HTTP 请求
#
# 演示如何使用 http_acl_allow 和 http_acl_deny 规则对沙箱内的
# HTTP 请求进行方法级、路径级的访问控制。
# deny 规则优先于 allow 规则；network 必须设为 "allow_domains" 才能使用 HTTP。
# 注意：HTTP 功能需要 Linux + KVM 环境，其他平台可能抛出 NotImplementedError。

from mimobox import Sandbox, SandboxHttpError

# 创建沙箱，配置 HTTP ACL 规则
with Sandbox(
    isolation="microvm",
    network="allow_domains",
    http_acl_allow=[
        # 允许 GET 请求 OpenAI models 列表
        "GET api.openai.com/v1/models",
        # 允许 POST 请求 OpenAI chat completions
        "POST api.openai.com/v1/chat/completions",
        # 允许所有方法访问 Anthropic（通配符 * 匹配任意方法/路径）
        "* *.anthropic.com/*",
    ],
    http_acl_deny=[
        # 拒绝所有对 /admin/ 路径的请求
        "* */admin/*",
        # 拒绝所有 DELETE 请求
        "DELETE * *",
    ],
) as sandbox:
    # 该请求被允许（匹配 GET api.openai.com/v1/models）
    result = sandbox.http_request(
        "GET",
        "https://api.openai.com/v1/models",
        headers={"Authorization": "Bearer $OPENAI_API_KEY"},
    )
    print(f"models request: status={result.status}")

    # 该请求会被 ACL 拒绝（DELETE 方法被 deny 规则拦截）
    try:
        sandbox.http_request("DELETE", "https://api.example.com/admin/users")
    except SandboxHttpError as e:
        print(f"ACL denied: {e}")
