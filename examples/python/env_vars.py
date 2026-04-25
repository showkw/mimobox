# env_vars.py — 环境变量注入：execute 时传入 env 参数
#
# 演示如何在执行命令时注入自定义环境变量。

from mimobox import Sandbox

with Sandbox() as sandbox:
    # 注入单个环境变量
    result = sandbox.execute(
        "/bin/sh -c 'echo $GREETING'",
        env={"GREETING": "Hello from env!"},
    )
    print(f"single env var: {result.stdout.strip()}")

    # 注入多个环境变量
    result = sandbox.execute(
        "/bin/sh -c 'echo $APP_NAME v$APP_VERSION running in $APP_ENV'",
        env={
            "APP_NAME": "mimobox",
            "APP_VERSION": "0.1.0",
            "APP_ENV": "sandbox",
        },
    )
    print(f"multiple env:   {result.stdout.strip()}")

    # 环境变量仅在当前命令生效
    result = sandbox.execute("/bin/sh -c 'echo $GREETING'")
    print(f"after scope:    {result.stdout.strip()!r} (empty as expected)")
