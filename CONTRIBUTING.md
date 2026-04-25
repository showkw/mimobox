# 贡献指南

## 感谢
感谢你愿意为 mimobox 贡献代码、文档、测试或问题反馈。

mimobox 是使用 Rust 构建的跨平台 Agent Sandbox，目标是为 AI Agent 工作负载提供安全、可控、高性能的隔离执行环境。

仓库地址：<https://github.com/showkw/mimobox>

## 开发环境
请优先通过统一脚本初始化环境：

```bash
scripts/setup.sh
```

基础要求：
- Rust stable toolchain，项目使用 edition 2024。
- macOS：安装 Xcode Command Line Tools。
- Linux：安装 `build-essential`、`libssl-dev`、`python3-dev`。
- 可选：Linux KVM 访问权限，用于 microVM 测试。

`scripts/setup.sh` 会安装或检查常用工具：
- `rustup`
- `rustfmt`
- `clippy`
- `cargo-nextest`
- `cargo-audit`

只修改文档时，通常不需要完整 KVM 环境。

## 构建与测试
常用命令：

```bash
cargo build
cargo test
scripts/check.sh
scripts/test.sh
```

`scripts/check.sh` 用于执行 `clippy` 和 `fmt` 检查。

`scripts/test.sh` 用于执行工作区测试；可按平台或能力选择范围，具体参数以脚本帮助信息为准。

Feature flags：
- `wasm`：启用 Wasm 沙箱能力，面向跨平台场景。
- `kvm`：启用 KVM / microVM 能力，仅支持 Linux。

示例：

```bash
cargo test --features wasm
cargo test --features kvm
```

涉及 Linux OS 沙箱、Landlock、Seccomp、KVM 或 microVM 的变更，应在 Linux 环境验证。

涉及 macOS 沙箱或跨平台路径的变更，应在 macOS 环境验证。

## 代码规范
提交前必须满足以下要求：
- `cargo fmt` 必须通过。
- `cargo clippy` 不允许有 warning。
- 所有 `unsafe` 代码必须带 `// SAFETY:` 注释，说明安全前提。
- 非测试代码禁止使用 `unwrap()`。
- 平台特定代码必须用 `#[cfg(target_os = "...")]` 隔离。
- 错误处理使用 `thiserror` 定义清晰的错误类型。

错误处理建议：
- 优先使用 `?` 向上传递错误。
- 需要上下文时，使用明确的错误变体或可读的 `expect()` 信息。
- 不要吞掉错误，也不要用宽泛字符串替代结构化错误。

跨平台代码建议：
- 公共抽象放在平台无关模块。
- Linux、macOS、Windows 等平台实现放入独立模块。
- 新增平台能力时，同步补充测试或说明无法测试的原因。

安全相关代码必须保持默认拒绝原则：
- Linux 沙箱默认启用 Seccomp 白名单。
- Linux 沙箱默认启用 Landlock 并拒绝文件系统访问。
- 沙箱默认禁止网络访问。
- 沙箱必须设置内存限制。

## PR 流程
推荐流程：
1. Fork 仓库。
2. 从最新主分支创建功能分支。
3. 完成代码、测试和文档变更。
4. 运行 `scripts/check.sh` 和 `scripts/test.sh`。
5. 提交并推送分支。
6. 创建 Pull Request。

PR 要求：
- PR 标题应简洁描述变更内容。
- 提交信息使用中文，避免“更新代码”这类空泛描述。
- 确保 CI 通过后再请求 review。
- 合并前至少需要一个 approval。
- 只提交与本 PR 相关的文件，避免混入无关改动。

提交信息示例：`修复 Linux 沙箱错误传播逻辑`、`新增 Wasm 后端集成测试`。

## 安全报告
如果你发现安全漏洞，请阅读并遵循 `SECURITY.md`。

不要在公开 issue、公开讨论区或公开 PR 中披露安全漏洞细节。

请通过 `SECURITY.md` 中指定的私密渠道报告，并附带复现步骤、影响范围和环境信息。

## CI 说明
CI 会在 Pull Request 和主分支更新时运行基础检查，通常包括格式化、Clippy、Linux 与 macOS 测试、Wasm 后端测试、文档构建、doctest 和安全审计。

需要 `/dev/kvm` 的 microVM 测试通常只在具备 KVM 权限的 Linux 环境执行。

## 许可证
mimobox 使用双许可证：`MIT OR Apache-2.0`。

提交贡献即表示你同意自己的贡献按 `MIT OR Apache-2.0` 双许可证发布。
