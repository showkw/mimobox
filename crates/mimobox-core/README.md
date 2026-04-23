# mimobox-core

`mimobox-core` 定义 mimobox 各后端共享的核心抽象：

- `Sandbox` trait
- `SandboxConfig`
- `SandboxResult`
- `SandboxError`
- `SandboxSnapshot`
- PTY 相关类型

该 crate 不提供具体沙箱实现，只负责稳定的公共接口与通用错误模型。

完整项目说明、示例与架构背景见仓库根目录 `README.md`。
