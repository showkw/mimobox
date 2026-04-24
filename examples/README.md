# examples

`examples/` 收录 `mimobox-sdk` 和 `mimobox` Python 模块的最小可运行示例。

## Rust 示例

- `basic.rs`：基本命令执行，演示 `Sandbox::new()` 和 `execute`
- `streaming.rs`：流式执行，演示 `stream_execute`、`Stdout` / `Stderr` / `Exit` 事件处理
- `agent_demo.rs`：Agent 集成，演示预设请求、命令生成、沙箱执行和交互模式
- `agent_streaming.rs`：Agent 流式执行，演示实时处理 `Stdout` / `Stderr` / `Exit` / `TimedOut` 事件
- `http_proxy.rs`：HTTP 代理，演示 `allowed_http_domains` 和 `http_request`
- `env_vars.rs`：环境变量注入，演示 `execute_with_env`
- `file_ops.rs`：文件读写，演示 `write_file` 和 `read_file`

Rust 示例通过 `crates/mimobox-sdk/Cargo.toml` 注册。校验命令：

```bash
cd crates/mimobox-sdk
cargo check --examples
cargo check --examples --features vm
```

说明：

- `basic.rs` 使用默认后端，适合先验证 SDK 基本执行链路
- `agent_demo.rs` 使用 OS 后端，支持 Linux/macOS，添加 `--interactive` 可进入交互模式
- `streaming.rs`、`agent_streaming.rs`、`http_proxy.rs`、`env_vars.rs`、`file_ops.rs` 需要 Linux + `vm` feature
- 在不满足 microVM 条件的环境中，上述示例会打印提示信息，但仍可通过默认 `cargo check --examples`

## Python 示例

- `python_basic.py`：单文件演示命令执行、流式执行、HTTP 请求、文件读写和环境变量注入

建议先安装 Python 绑定，再运行该示例：

```bash
cd crates/mimobox-python
pip install -e .
python ../../examples/python_basic.py
```

说明：

- Python 示例默认展示基础命令执行
- 需要 microVM 的部分会通过 `Sandbox(isolation="microvm", allowed_http_domains=[...])` 显式请求后端
- 若当前平台或构建不支持 microVM，示例会打印对应提示
