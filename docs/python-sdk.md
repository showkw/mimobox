# mimobox Python SDK

本文档描述 `mimobox-python` 的安装方式、公开 API、异常层级和完整示例。文档使用简体中文说明，代码示例和变量名保持英文。

## 1. 概述

`mimobox-python` 通过 PyO3 + maturin 提供 Python 绑定，把 Rust SDK 的 `mimobox_sdk::Sandbox` 暴露为 Python 模块 `mimobox`。

核心关系：

```text
Python user code
  |
  v
mimobox.Sandbox
  |
  v
mimobox_sdk::Sandbox
  |
  +-- OS sandbox
  +-- Wasm sandbox
  `-- microVM sandbox
```

Python SDK 支持：

- 基础命令执行。
- 命令级环境变量注入和超时。
- 流式输出。
- microVM 文件读写。
- microVM 快照、恢复和 CoW fork。
- host 侧 HTTP 代理。
- Python 异常层级和标准异常映射。

## 2. 安装方式

从源码构建（推荐）：

```bash
cd mimobox && maturin develop --features vm
```

仅 OS 级后端：

```bash
maturin develop
```

说明：

- `--features vm` 需要 Linux + KVM 环境才能完整使用 microVM 能力。
- 仅 OS 级后端适合本地快速开发、基础命令执行和 API 调试。

## 3. 公开类和方法

### 3.1 `Sandbox`

`Sandbox` 是主要入口，内部委托给 Rust SDK 的 `Sandbox`。

构造方法：

```python
Sandbox(*, isolation=None, allowed_http_domains=None)
```

参数：

- `isolation`：隔离层级，默认 `None` 等价于 `"auto"`。
- `allowed_http_domains`：HTTP 代理允许访问的域名列表，可包含通配模式。

公开方法：

```python
execute(command, env=None, timeout=None) -> ExecuteResult
stream_execute(command) -> StreamIterator
read_file(path) -> bytes
write_file(path, data: bytes)
snapshot() -> Snapshot
fork() -> Sandbox
http_request(method, url, headers=None, body=None) -> HttpResponse
wait_ready(timeout_secs=None)
is_ready() -> bool
```

类方法：

```python
Sandbox.from_snapshot(snapshot) -> Sandbox
```

上下文管理器：

```python
with Sandbox() as sb:
    result = sb.execute("/bin/echo hello")
```

`with` 块退出时会释放底层沙箱资源。

### 3.2 `ExecuteResult`

命令执行结果。

属性：

- `stdout: str`：标准输出，使用 UTF-8 lossy 解码。
- `stderr: str`：标准错误，使用 UTF-8 lossy 解码。
- `exit_code: int`：退出码；底层无退出码时为 `-1`。
- `timed_out: bool`：是否超时。
- `elapsed: float | None`：执行耗时，单位秒；未知时为 `None`。

### 3.3 `HttpResponse`

HTTP 代理响应。

属性：

- `status: int`：HTTP 状态码。
- `headers: dict`：响应头。
- `body: bytes`：响应体原始字节。

### 3.4 `Snapshot`

microVM 沙箱快照。

方法：

```python
Snapshot.from_bytes(data: bytes) -> Snapshot
to_bytes() -> bytes
size() -> int
```

说明：

- `from_bytes` 是 classmethod。
- `to_bytes()` 用于把快照序列化为字节。
- `size()` 返回快照大小。

### 3.5 `StreamEvent`

流式执行事件。

属性：

- `stdout: bytes | None`：stdout chunk。
- `stderr: bytes | None`：stderr chunk。
- `exit_code: int | None`：退出码事件。
- `timed_out: bool`：是否为超时事件。

每个事件通常只携带一种信息：stdout、stderr、exit code 或 timeout。

### 3.6 `StreamIterator`

`StreamIterator` 是 `Sandbox.stream_execute()` 返回的迭代器。

行为：

- 实现 Python 迭代协议。
- 每次迭代 yield 一个 `StreamEvent`。
- 底层 stream 结束后停止迭代。

示例：

```python
for event in sb.stream_execute("/bin/sh -c 'echo hello; echo err >&2'"):
    if event.stdout is not None:
        print(event.stdout.decode(), end="")
```

## 4. 异常层级

Python SDK 定义以下 mimobox 异常：

- `SandboxError`：基类。
- `SandboxProcessError`：命令执行错误，例如非零退出或被 kill。
- `SandboxHttpError`：HTTP 代理错误，例如域名拒绝、非法 URL、body 过大。
- `SandboxLifecycleError`：沙箱生命周期错误，例如未就绪、已销毁、创建失败。

同时会映射到 Python 标准异常：

- `TimeoutError`：命令或 HTTP 请求超时。
- `FileNotFoundError`：文件不存在。
- `PermissionError`：文件权限拒绝。
- `ConnectionError`：HTTP 连接或 TLS 失败。
- `ValueError`：配置或参数无效。
- `NotImplementedError`：当前平台或 feature 不支持。

推荐调用方优先捕获具体异常，再用 `SandboxError` 做兜底：

```python
from mimobox import Sandbox, SandboxError, SandboxHttpError

try:
    with Sandbox(isolation="microvm") as sb:
        sb.http_request("GET", "https://example.com")
except SandboxHttpError as exc:
    print(f"HTTP proxy failed: {exc}")
except SandboxError as exc:
    print(f"sandbox failed: {exc}")
```

## 5. `isolation` 参数说明

`Sandbox(isolation=...)` 支持以下值：

- `"auto"`：默认智能路由。
- `"os"`：OS 级沙箱。
- `"wasm"`：Wasm 沙箱。
- `"microvm"`：microVM 沙箱。
- `"micro_vm"`：`"microvm"` 的别名。
- `"micro-vm"`：`"microvm"` 的别名。

未传 `isolation` 时等价于 `"auto"`。

智能路由语义：

- `.wasm`、`.wat`、`.wast` 文件优先走 Wasm。
- 不可信任务在 Rust SDK 中可通过 `TrustLevel::Untrusted` 走 microVM fail-closed 路径。
- 其他普通命令默认走 OS 级沙箱。

## 6. 完整示例

### 6.1 基础执行

```python
from mimobox import Sandbox, Snapshot

with Sandbox(isolation="auto") as sb:
    result = sb.execute("/bin/echo hello")
    print(result.stdout, end="")
    print(f"exit_code={result.exit_code}")
```

### 6.2 命令级环境变量和超时

```python
from mimobox import Sandbox, Snapshot

with Sandbox(isolation="microvm") as sb:
    result = sb.execute(
        "/usr/bin/printenv MIMOBOX_MODE",
        env={"MIMOBOX_MODE": "python-demo"},
        timeout=5.0,
    )
    print(result.stdout, end="")
```

### 6.3 流式输出

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    stream = sb.stream_execute("/bin/sh -c 'echo start; echo err >&2; echo done'")
    for event in stream:
        if event.stdout is not None:
            print(event.stdout.decode("utf-8", errors="replace"), end="")
        if event.stderr is not None:
            print(event.stderr.decode("utf-8", errors="replace"), end="")
        if event.exit_code is not None:
            print(f"exit={event.exit_code}")
        if event.timed_out:
            print("timed out")
```

### 6.4 HTTP 请求

```python
from mimobox import Sandbox

with Sandbox(
    isolation="microvm",
    allowed_http_domains=["example.com"],
) as sb:
    response = sb.http_request("GET", "https://example.com")
    print(response.status)
    print(response.body[:80])
```

### 6.5 文件操作

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as sb:
    sb.write_file("/tmp/hello.txt", b"hello from python\n")
    data = sb.read_file("/tmp/hello.txt")
    print(data.decode("utf-8"), end="")
```

### 6.6 快照与恢复

```python
from mimobox import Sandbox, Snapshot

with Sandbox(isolation="microvm") as sb:
    sb.write_file("/tmp/state.txt", b"before snapshot\n")
    snapshot = sb.snapshot()
    snapshot_bytes = snapshot.to_bytes()

restored_snapshot = Snapshot.from_bytes(snapshot_bytes)

with Sandbox.from_snapshot(restored_snapshot) as restored:
    data = restored.read_file("/tmp/state.txt")
    print(data.decode("utf-8"), end="")
```

### 6.7 Fork

```python
from mimobox import Sandbox

with Sandbox(isolation="microvm") as parent:
    parent.write_file("/tmp/state.txt", b"parent\n")

    child = parent.fork()
    try:
        child.write_file("/tmp/state.txt", b"child\n")

        parent_data = parent.read_file("/tmp/state.txt")
        child_data = child.read_file("/tmp/state.txt")

        print(parent_data.decode("utf-8"), end="")
        print(child_data.decode("utf-8"), end="")
    finally:
        child.__exit__(None, None, None)
```

说明：`fork()` 返回独立沙箱。示例中为了显式释放 child，调用了 context manager 的退出方法；在实际代码中更推荐把 fork 后对象封装到自己的资源管理逻辑中。
