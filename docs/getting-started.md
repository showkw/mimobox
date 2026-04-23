# mimobox 快速入门

## 1. 简介

`mimobox` 是一个用 Rust 实现的跨平台 Agent Sandbox，面向 AI Agent 的安全代码执行场景，统一封装 OS 级、Wasm 级和 microVM 级三层隔离，在保证可控隔离边界的同时追求极致性能：OS 级冷启动 P50 8.24ms、Wasm 冷启动 P50 1.01ms、microVM 冷启动 P50 253ms，并支持预热池与快照恢复路径。

## 2. 安装

### 2.1 前置条件

- Rust 1.82+
- Linux 上启用 microVM 时需要 KVM 支持
- Linux 上执行完整沙箱测试时建议具备 `sudo` 权限、cgroups v2 和常见系统路径（`/usr`、`/bin`、`/proc` 等）
- macOS 当前支持 OS 级后端；Windows 仍处于规划中

### 2.2 基本构建

仓库根目录执行：

```bash
cargo build --workspace
```

这会构建 workspace 默认成员，默认聚焦 OS 级后端，不包含 Wasm crate 和 microVM CLI feature。

### 2.3 Feature 说明

当前仓库里 feature 名称分两层，不是一个统一的全局开关，必须区分：

- 默认构建：直接执行 `cargo build --workspace`
  - `mimobox-sdk` 默认启用 `os`
  - workspace 默认成员不包含 `mimobox-wasm`
  - 适合先验证 OS 级能力和 SDK 基本接口
- `kvm`：CLI 层的 microVM 开关
  - `mimobox-cli` 使用 `kvm`
  - `mimobox-sdk` 对应的是 `vm`，不是 `kvm`
  - 常用构建方式：

```bash
cargo build --workspace --features mimobox-cli/kvm,mimobox-sdk/vm
```

- `wasm`：Wasm 后端开关
  - `mimobox-cli` 使用 `wasm`
  - `mimobox-sdk` 也使用 `wasm`
  - 由于 workspace 默认排除了 `mimobox-wasm`，需要显式启用：

```bash
cargo build --workspace --features mimobox-cli/wasm,mimobox-sdk/wasm
```

如果你要同时启用 Wasm 和 microVM：

```bash
cargo build --workspace --features mimobox-cli/kvm,mimobox-cli/wasm,mimobox-sdk/vm,mimobox-sdk/wasm
```

## 3. 30 秒上手（Rust SDK）

下面示例按当前 `mimobox-sdk` API 调整为可编译版本。注意：`exit_code` 在当前 SDK 中是 `Option<i32>`，不能直接按整数格式化输出。

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("python3 -c 'print(42)'")?;

    println!(
        "exit: {:?}, stdout: {}",
        result.exit_code,
        String::from_utf8_lossy(&result.stdout)
    );

    sandbox.destroy()?;
    Ok(())
}
```

如果只想快速验证命令执行，不关心 Python 是否存在，使用 `/bin/echo` 更稳妥：

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello")?;

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&result.stdout), "hello\n");

    sandbox.destroy()?;
    Ok(())
}
```

## 4. 核心功能示例

### 4.1 命令执行（`execute`）

#### 基本用法

```rust
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo mimobox")?;

    println!("stdout = {}", String::from_utf8_lossy(&result.stdout));
    println!("stderr = {}", String::from_utf8_lossy(&result.stderr));
    println!("exit_code = {:?}", result.exit_code);
    println!("timed_out = {}", result.timed_out);
    println!("elapsed = {:?}", result.elapsed);

    sandbox.destroy()?;
    Ok(())
}
```

#### 超时设置

`Config.timeout` 是 SDK 级统一超时，当前会向上取整到秒传给底层沙箱。

```rust
use std::time::Duration;

use mimobox_sdk::{Config, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .timeout(Duration::from_secs(2))
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let result = sandbox.execute("python3 -c 'import time; time.sleep(1); print(42)'")?;

    assert_eq!(result.exit_code, Some(0));
    assert!(!result.timed_out);

    sandbox.destroy()?;
    Ok(())
}
```

### 4.2 流式输出（`stream_execute`）

`stream_execute` 当前只支持 Linux 上的 microVM 后端。OS 级和 Wasm 后端调用会返回 `UnsupportedPlatform`。

#### 迭代器模式

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let receiver = sandbox.stream_execute("/bin/sh -c 'echo start; echo err >&2; echo done'")?;

    for event in receiver {
        match event {
            StreamEvent::Stdout(chunk) => {
                print!("{}", String::from_utf8_lossy(&chunk));
            }
            StreamEvent::Stderr(chunk) => {
                eprint!("{}", String::from_utf8_lossy(&chunk));
            }
            StreamEvent::Exit(code) => {
                println!("exit = {code}");
            }
            StreamEvent::TimedOut => {
                println!("command timed out");
            }
        }
    }

    sandbox.destroy()?;
    Ok(())
}
```

#### 适合长时间命令

适用场景：

- `pip install`
- 长日志编译
- 模型下载或训练脚本
- 需要边执行边消费输出的 Agent 任务

不适合的场景：

- 仅执行一次短命令，直接用 `execute`
- 非 Linux 或未启用 microVM 构建

### 4.3 文件操作（`read_file` / `write_file`）

文件传输当前只支持 Linux 上的 microVM 后端。`IsolationLevel::Auto` 调这两个接口时，也会强制走 microVM 路径。

#### 读写沙箱内文件

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    sandbox.write_file("/tmp/message.txt", b"hello from host\n")?;

    let result = sandbox.execute("/bin/cat /tmp/message.txt")?;
    assert_eq!(String::from_utf8_lossy(&result.stdout), "hello from host\n");

    let content = sandbox.read_file("/tmp/message.txt")?;
    assert_eq!(content, b"hello from host\n");

    sandbox.destroy()?;
    Ok(())
}
```

### 4.4 HTTP 代理（`http_request`）

HTTP 代理当前只支持 Linux 上的 microVM 后端，通过 host 代理执行请求。文档里必须把两个事实说清楚：

- 默认网络策略仍是拒绝全部网络访问
- `allowed_http_domains` 是 host 代理层的域名白名单，不等价于“沙箱内任意网络已开放”

#### 域名白名单配置

```rust
use mimobox_sdk::{Config, IsolationLevel, Sandbox};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .allowed_http_domains(["api.github.com"])
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "mimobox-example".to_string());

    let response = sandbox.http_request(
        "GET",
        "https://api.github.com",
        headers,
        None,
    )?;

    println!("status = {}", response.status);
    println!("body bytes = {}", response.body.len());

    sandbox.destroy()?;
    Ok(())
}
```

#### 调用外部 API

建议做法：

- 只把必要域名加入 `allowed_http_domains`
- 对请求体大小、超时和错误返回做显式处理
- 不要把该接口当成通用网络已开放的替代说法

### 4.5 Python SDK

当前 Python 绑定 crate 名为 `mimobox-python`，导出的 Python 模块名为 `mimobox`，基于 `PyO3 + maturin` 构建。

#### 安装方式

方式一：在绑定目录直接安装开发版

```bash
cd crates/mimobox-python
pip install -e .
```

方式二：显式使用 `maturin`

```bash
cd crates/mimobox-python
maturin develop
```

#### 基本用法示例

```python
from mimobox import Sandbox


def main() -> None:
    with Sandbox() as sandbox:
        result = sandbox.execute("/bin/echo hello-from-python")
        print(result.stdout, end="")
        print(result.exit_code)


if __name__ == "__main__":
    main()
```

#### Python API 现状

- `Sandbox()` 当前等价于 Rust 侧 `Sandbox::new()`，没有单独暴露 `ConfigBuilder`
- `execute(command: str)` 返回 `ExecuteResult`
- `stream_execute(command: str)` 返回 Python 迭代器
- `read_file` / `write_file` / `http_request` 已暴露
- `stdout` / `stderr` 在 Python 侧会做 UTF-8 lossy 解码
- 缺失退出码时，Python 侧会把 `exit_code` 映射成 `-1`

## 5. 配置参考

`mimobox_sdk::Config` 当前字段如下。

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `isolation` | `IsolationLevel` | `Auto` | 隔离层级选择 |
| `trust_level` | `TrustLevel` | `SemiTrusted` | 影响 `Auto` 路由 |
| `network` | `NetworkPolicy` | `DenyAll` | 网络策略抽象 |
| `timeout` | `Option<Duration>` | `Some(30s)` | 执行超时 |
| `memory_limit_mb` | `Option<u64>` | `Some(512)` | 统一内存上限 |
| `fs_readonly` | `Vec<PathBuf>` | `/usr`、`/lib`、`/lib64`、`/bin`、`/sbin`、`/dev`、`/proc`、`/etc` | 沙箱内只读挂载路径 |
| `fs_readwrite` | `Vec<PathBuf>` | `/tmp` | 沙箱内读写路径 |
| `allowed_http_domains` | `Vec<String>` | 空 | host HTTP 代理白名单 |
| `allow_fork` | `bool` | `false` | 是否允许 fork |
| `vm_vcpu_count` | `u8` | `1` | microVM vCPU 数量 |
| `vm_memory_mb` | `u32` | `256` | microVM Guest 内存 |
| `kernel_path` | `Option<PathBuf>` | `None` | 自定义 microVM 内核路径 |
| `rootfs_path` | `Option<PathBuf>` | `None` | 自定义 microVM rootfs 路径 |

### 5.1 常用字段说明

#### `timeout`

- 作用于命令执行超时
- 当前向底层换算时按秒向上取整
- 例如 `1500ms` 会映射为 `2s`

#### `memory_limit_mb`

- 是统一资源限制
- 对 microVM 路径会与 `vm_memory_mb` 取较小值
- 例如 `memory_limit_mb = 256` 且 `vm_memory_mb = 768` 时，最终 guest 内存为 `256MB`

#### `vm_memory_mb`

- 仅对 microVM 后端生效
- 默认值 `256MB`
- 如果未显式覆盖内核和 rootfs 路径，会走后端默认路径：
  - `VM_ASSETS_DIR/vmlinux`
  - `VM_ASSETS_DIR/rootfs.cpio.gz`
  - 未设置 `VM_ASSETS_DIR` 时，回退到 `~/.mimobox/assets/`

#### `allowed_http_domains`

- 用于 host HTTP 代理白名单
- 不是通用网络放行开关
- 应与 `IsolationLevel::MicroVm` 配合使用

#### `network`

- `NetworkPolicy::DenyAll`：拒绝所有网络访问
- `NetworkPolicy::AllowDomains([...])`：保持沙箱内直接网络关闭，仅允许通过 host HTTP 代理访问白名单域名
- `NetworkPolicy::AllowAll`：允许任意网络访问
- 当 `trust_level = TrustLevel::Untrusted` 且当前平台不支持 microVM 时，SDK 会直接报错，不会静默降级到 OS

### 5.2 隔离层级选择

| 选项 | 含义 | 当前行为 |
| --- | --- | --- |
| `auto` | 智能路由 | 根据命令类型和 `trust_level` 选择后端 |
| `os` | OS 级隔离 | Linux 为 Landlock + Seccomp + Namespaces；macOS 为 Seatbelt |
| `vm` | microVM 隔离 | 当前仅 Linux + KVM 支持 |
| `wasm` | Wasm 隔离 | 适合 `.wasm/.wat/.wast` 负载 |

当前 `IsolationLevel` 的 Rust 枚举名是：

- `IsolationLevel::Auto`
- `IsolationLevel::Os`
- `IsolationLevel::MicroVm`
- `IsolationLevel::Wasm`

`auto` 路由的当前语义：

- `.wasm` / `.wat` / `.wast` 文件优先走 Wasm
- `TrustLevel::Untrusted` 在 Linux 且启用 `vm` feature 时优先走 microVM
- 其他普通命令默认走 OS 级

## 6. 性能数据

以下数据来自当前仓库维护的基线，口径以 `CLAUDE.md` 和 `README.md` 为准：

| 路径 | 指标 | 实测 |
| --- | --- | --- |
| OS 级 | 冷启动 | P50 8.24ms |
| Wasm | 冷启动（清缓存） | P50 1.01ms |
| OS 级预热池 | 热获取 | P50 0.19us（仅 acquire） |
| microVM | 冷启动 | P50 253ms |
| microVM | 快照恢复 | P50 69ms（非池化） |
| microVM | 池化快照恢复 | P50 28ms（restore-to-ready） |
| microVM 预热池 | 热路径 | P50 773us |

解读要点：

- `0.19us` 是 OS 预热池对象获取成本，不包含命令执行
- `28ms` 是池化快照恢复到 ready 状态，不包含命令执行
- `773us` 是 microVM 预热池热路径，包含轻载命令执行

## 7. 下一步

如果你要继续深入，建议按下面顺序看：

- 架构总览：[docs/architecture.md](./architecture.md)
- API 细节：[docs/api.md](./api.md)
- 综合研究：[docs/research/00-executive-summary.md](./research/00-executive-summary.md)
- Wasm 设计：[docs/research/11-wasmtime-api-research.md](./research/11-wasmtime-api-research.md)
- microVM 设计：[docs/research/14-microvm-design.md](./research/14-microvm-design.md)
- 产品与竞品讨论：[discuss/product-strategy-review.md](../discuss/product-strategy-review.md)
- 竞品分析：[discuss/competitive-analysis.md](../discuss/competitive-analysis.md)
- 流式输出方案：[discuss/streaming-output-design.md](../discuss/streaming-output-design.md)
- HTTP 代理方案：[discuss/http-proxy-design.md](../discuss/http-proxy-design.md)
