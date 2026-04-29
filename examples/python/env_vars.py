# env_vars.py — Environment variable injection: pass env parameter at execute time
#
# Demonstrates how to inject custom environment variables when executing commands.

from mimobox import Sandbox

with Sandbox() as sandbox:
    # Inject a single environment variable
    result = sandbox.execute(
        "/bin/sh -c 'echo $GREETING'",
        env={"GREETING": "Hello from env!"},
    )
    print(f"single env var: {result.stdout.strip()}")

    # Inject multiple environment variables
    result = sandbox.execute(
        "/bin/sh -c 'echo $APP_NAME v$APP_VERSION running in $APP_ENV'",
        env={
            "APP_NAME": "mimobox",
            "APP_VERSION": "0.1.0",
            "APP_ENV": "sandbox",
        },
    )
    print(f"multiple env:   {result.stdout.strip()}")

    # Environment variables only take effect for the current command
    result = sandbox.execute("/bin/sh -c 'echo $GREETING'")
    print(f"after scope:    {result.stdout.strip()!r} (empty as expected)")
