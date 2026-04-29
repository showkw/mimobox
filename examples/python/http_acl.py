# http_acl.py — HTTP ACL rule configuration: fine-grained control over HTTP requests in the sandbox
#
# Demonstrates how to use http_acl_allow and http_acl_deny rules for fine-grained
# method-level and path-level access control over HTTP requests in the sandbox.
# deny rules take priority over allow rules; network must be set to "allow_domains" to use HTTP.
# Note: HTTP features require Linux + KVM; other platforms may raise NotImplementedError.

from mimobox import Sandbox, SandboxHttpError

# Create sandbox with HTTP ACL rules configured
with Sandbox(
    isolation="microvm",
    network="allow_domains",
    http_acl_allow=[
        # Allow GET requests to OpenAI models list
        "GET api.openai.com/v1/models",
        # Allow POST requests to OpenAI chat completions
        "POST api.openai.com/v1/chat/completions",
        # Allow all methods to access Anthropic (wildcard * matches any method/path)
        "* *.anthropic.com/*",
    ],
    http_acl_deny=[
        # Deny all requests to /admin/ paths
        "* */admin/*",
        # Deny all DELETE requests
        "DELETE * *",
    ],
) as sandbox:
    # This request is allowed (matches GET api.openai.com/v1/models)
    result = sandbox.http_request(
        "GET",
        "https://api.openai.com/v1/models",
        headers={"Authorization": "Bearer $OPENAI_API_KEY"},
    )
    print(f"models request: status={result.status}")

    # This request will be denied by ACL (DELETE method blocked by deny rule)
    try:
        sandbox.http_request("DELETE", "https://api.example.com/admin/users")
    except SandboxHttpError as e:
        print(f"ACL denied: {e}")
