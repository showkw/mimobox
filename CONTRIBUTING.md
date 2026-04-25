# 贡献指南

## 欢迎贡献

欢迎参与 mimobox 项目。

mimobox 是一个使用 Rust 构建的跨平台 Agent Sandbox，目标是为 AI Agent 提供安全、可控、高性能的隔离执行环境。项目支持 OS 级沙箱、Wasm 沙箱和 microVM 沙箱，并通过统一 SDK 提供默认智能路由能力。

仓库地址：<https://github.com/showkw/mimobox>

## 开发环境要求

- Rust stable，使用 edition 2024。
- Linux 或 macOS。
- `cargo-nextest` 与 `cargo-audit`，由 `scripts/setup.sh` 安装。

## 搭建开发环境

通过统一脚本初始化开发环境：

```bash
scripts/setup.sh
```

该脚本会安装或配置：

- `rustup`
- `clippy`
- `rustfmt`
- `cargo-nextest`
- `cargo-audit`

## 开发流程

1. Fork 本仓库。
2. 创建功能分支：`git checkout -b feature/my-feature`。
3. 完成代码或文档修改。
4. 运行 `scripts/check.sh`，执行 `cargo check`、`clippy` 和 `fmt --check`。
5. 运行 `scripts/test.sh`，执行 workspace 测试。
6. 提交并推送分支。
7. 创建 Pull Request，目标分支为 `main`。

## Commit Message 规范

- 使用简洁的中文描述。
- 示例：`修复 XXX 问题`、`新增 YYY 功能`、`重构 ZZZ 模块`。
- 单行描述，不以句号结尾。

## 代码规范

- unsafe 规范：所有 unsafe 代码都必须包含 `// SAFETY:` 注释，说明为什么该 unsafe 使用是安全的。
- unwrap 规范：非测试代码禁止使用 `unwrap()`，由 workspace clippy lint `unwrap_used = deny` 强制执行。请使用带明确信息的 `expect()`，或通过 `?` 进行错误传播。
- 错误处理：错误类型使用 `thiserror` 定义。
- 跨平台编译：平台特定代码必须使用 `#[cfg(target_os = "...")]` 隔离。
- 先读后写：修改前先阅读并理解现有代码、接口和测试。

## 安全规范

- Seccomp：Linux 沙箱必须应用 seccomp filter，默认使用白名单模式。
- Landlock：Linux 沙箱必须应用 Landlock，默认拒绝所有文件系统访问。
- Network：所有沙箱默认必须拒绝网络访问。
- Memory：所有沙箱必须设置内存限制。

## PR 流程

1. Fork 仓库，创建分支，提交 PR，接受 review，合并到 `main`。
2. 请求 review 前确保 CI 通过。
3. 至少需要一个 approval。

## CI 说明

CI 会在 push 到 `main`、`master` 以及 Pull Request 时运行。主要 jobs 包括：

- `lint-and-check`：在 `ubuntu-latest` 上运行 `cargo check`、`fmt` 和 `clippy`。
- `test-linux-os`：运行 `mimobox-os` 测试。
- `test-linux-vm`：运行 `mimobox-vm` 测试，仅手动触发，需要 `/dev/kvm`。
- `test-sdk`：构建 `mimobox-sdk` 并运行 lib tests。
- `docs-check`：运行 `cargo doc` 和 doc tests。
- `security-audit`：通过 rustsec 运行 `cargo audit`。
- `test-macos`：在 macOS 上运行 `mimobox-os` 和 `mimobox-wasm` 测试。
- `test-linux-wasm`：在 Linux 上运行 `mimobox-wasm` 测试。
- `test-mcp`：运行 `mimobox-mcp` 测试。
- `check-python`：运行 `mimobox-python cargo check`。

## 脚本入口

所有开发操作都通过 `scripts/` 目录中的脚本入口执行：

- `scripts/setup.sh`：初始化开发环境。
- `scripts/check.sh`：运行 lint 和静态检查。
- `scripts/test.sh [default|linux|macos|wasm|all]`：运行测试。
- `scripts/test-e2e.sh`：跨后端端到端测试。
- `scripts/bench.sh`：运行 benchmark。

## License

MIT OR Apache-2.0
