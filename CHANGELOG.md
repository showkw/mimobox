# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SDK: `Sandbox::execute_code(language, code)` — 语言运行时代码执行
- SDK: `Sandbox::execute_with_cwd(command, cwd)` — 单命令工作目录覆写
- SDK: `Sandbox::list_dir(path)` — 沙箱内目录列表
- SDK: `DirEntry` / `FileType` 类型导出
- SDK: `Config.cpu_quota_us` — CPU cgroup v2 配额控制
- Python: `execute_code(language, code)` 方法
- Python: `execute()` 新增 `cwd` 参数
- Python: `list_dir()` 方法
- Python: `DirEntry` 类
- Python: `SandboxLifecycleError` 异常
- Python: `Snapshot.from_file()` 方法
- CLI: `completions` 子命令（Bash/Zsh/Fish/PowerShell）
- CLI: 架构拆分为 `commands/` 模块

### Changed
- 生命周期错误从字符串匹配改为 `LifecycleError` 枚举
- Linux 安全策略去重优化（净减 150 行）
- MCP server `next_id` 从 `Mutex<u64>` 改为 `AtomicU64`
- workspace 依赖统一管理（rmcp/schemars/tokio）
- install.sh 添加 Linux aarch64 平台支持
- publish-crates.sh sleep 30 秒、测试改为 check

### Fixed
- VM API 测试：构造显式无效配置替代 `default()`
- 文档：移除不可用的安装路径，添加平台限制标注
- Release CI：SHA256 checksum 在 rename 后生成

## [0.1.0] - 2026-04-25

### Added
- Three-tier isolation sandbox (OS / Wasm / microVM)
- SDK smart routing + Builder configuration
- Python SDK (PyO3): execute, stream_execute, read_file, write_file, http_request, snapshot, fork, close
- MCP Server with 10 tools (rmcp)
- CLI: execute, pty, snapshot, setup, doctor
- Streaming output (EXECS/STREAM frame protocol)
- HTTP proxy (domain whitelist + DNS rebinding protection)
- CoW Fork zero-copy (mmap MAP_PRIVATE)
- VM asset pre-built download + SHA256 verification
- LangChain integration example
- Warm pool (OS + microVM)
- SPECIFICATION.md with 9 performance specifications
- llms.txt AI discovery index
- CONTRIBUTING.md development guide
- Per-crate READMEs (8 crates)
- `full` feature aggregate configuration

### Fixed
- reqwest download timeout (connect 10s + read 300s)
- Resource leak defenses (VmPool/RestorePool Drop + Sandbox retry + MCP SIGTERM handler)
- clippy zero warnings (macOS + Linux)

### Changed
- CLI fully in English
- Error messages fully in English
- Documentation fully in English

