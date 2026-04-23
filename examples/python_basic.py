# Python SDK 示例：演示命令执行、流式输出、HTTP 请求、文件读写和环境变量注入。
from __future__ import annotations

import sys

from mimobox import Sandbox


def print_section(title: str) -> None:
    print(f"\n== {title} ==")


def print_text(value: str) -> None:
    print(value, end="" if value.endswith("\n") else "\n")


def decode_bytes(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def demo_execute() -> None:
    print_section("基本命令执行")
    with Sandbox() as sandbox:
        result = sandbox.execute("/bin/echo hello mimobox from python")
        print(f"exit: {result.exit_code}")
        print_text(result.stdout)


def demo_streaming() -> None:
    print_section("流式执行")
    try:
        with Sandbox(isolation="microvm") as sandbox:
            for event in sandbox.stream_execute(
                "/bin/sh -c 'echo stdout-line; echo stderr-line >&2; echo done'"
            ):
                if event.stdout is not None:
                    print(decode_bytes(event.stdout), end="")
                if event.stderr is not None:
                    print(decode_bytes(event.stderr), end="", file=sys.stderr)
                if event.exit_code is not None:
                    print(f"exit: {event.exit_code}")
                if event.timed_out:
                    print("command timed out")
    except NotImplementedError as exc:
        print(f"当前环境不支持流式执行: {exc}")


def demo_http_request() -> None:
    print_section("HTTP 请求")
    try:
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
            print(f"status: {response.status}")
            print_text(decode_bytes(response.body))
    except NotImplementedError as exc:
        print(f"当前环境不支持 HTTP 代理: {exc}")


def demo_file_ops() -> None:
    print_section("文件读写")
    try:
        with Sandbox(isolation="microvm") as sandbox:
            path = "/tmp/python-mimobox-example.txt"
            expected = b"hello from python example\n"
            sandbox.write_file(path, expected)
            actual = sandbox.read_file(path)
            if actual != expected:
                raise RuntimeError("读回内容与写入内容不一致")
            print_text(decode_bytes(actual))
    except NotImplementedError as exc:
        print(f"当前环境不支持文件操作: {exc}")


def demo_env_vars() -> None:
    print_section("环境变量注入")
    try:
        with Sandbox(isolation="microvm") as sandbox:
            result = sandbox.execute(
                "/bin/sh -c 'echo $MY_VAR'",
                env={"MY_VAR": "hello"},
            )
            if "hello" not in result.stdout:
                raise RuntimeError("输出中未包含 hello")
            print_text(result.stdout)
    except NotImplementedError as exc:
        print(f"当前环境不支持环境变量注入: {exc}")


def main() -> None:
    demo_execute()
    demo_streaming()
    demo_http_request()
    demo_file_ops()
    demo_env_vars()


if __name__ == "__main__":
    main()

