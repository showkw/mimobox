# 更新日志

本文件记录 mimobox 的所有重要变更。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/spec/v2.0.0.html)。

## [0.1.0] - 2026-04-26

### 新增

- 发布跨平台 Agent Sandbox 初始版本，提供 OS、Wasm、microVM 三层隔离后端，并支持默认智能路由与显式后端选择。
- 新增统一 Rust SDK：`Sandbox`、`Config`、Builder 配置、命令执行、流式输出、文件读写、目录列表、HTTP 请求、快照、Fork、PTY、资源关闭等 API。
- 新增 Python SDK（PyO3）：覆盖命令执行、代码执行、流式输出、工作目录参数、目录列表、文件传输、HTTP 请求、快照、Fork、`close()`、类型存根与结构化生命周期异常。
- 新增 CLI 工具：执行命令、JSON 输出、PTY 会话、快照管理、环境诊断、初始化、Shell 补全、MCP 初始化与自动后端路由。
- 新增 MCP Server crate，基于 rmcp 提供 stdio 传输与 10 个沙箱工具，支持 Agent 通过 MCP 调用 mimobox 能力。
- 新增 Linux OS 沙箱后端：Landlock、Seccomp-bpf、Namespaces、cgroups v2、网络默认拒绝、资源限制与 fail-closed 安全语义。
- 新增 macOS OS 沙箱后端：基于 Seatbelt 的本地沙箱执行与文件访问限制。
- 新增 Wasm 沙箱后端：基于 Wasmtime、WASI Preview 2 与 Component Model 的轻量隔离执行。
- 新增 KVM microVM 后端：ELF 装载、initrd、串口输出、Guest 命令协议、文件传输协议、流式输出协议、HTTP 代理协议与真实命令执行链路。
- 新增 CoW Fork 零拷贝能力：文件化 Snapshot、`MAP_PRIVATE` 恢复路径、SDK `template/fork` API、预热池集成与端到端测试。
- 新增 microVM 预热池与 RestorePool：支持预启动复用、池化快照恢复、热路径获取和 restore-to-ready 性能优化。
- 新增串口协议能力：stdout/stderr 拆分、EXECS/STREAM 帧、FS:READ/FS:WRITE 文件传输、HTTP 代理、工作目录透传与退出码传播。
- 新增 HTTP/HTTPS 代理：支持域名白名单、DNS 重绑定防护、响应头补全、预热池白名单传递与端到端验证。
- 新增 vsock 技术链路原型：guest kernel 配置、vsock MMIO 设备模拟、vhost-vsock 后端与 host/guest 命令通道；当前正式路径默认使用纯串口模式。
- 新增 VM 资产体系：最小化 guest kernel/rootfs 构建脚本、预构建 VM 资产下载、SHA256 校验、Node.js 与 BusyBox applet 扩展。
- 新增 Docker 一键试用镜像，便于用户快速体验 mimobox CLI 与示例能力。
- 新增 CPU 配额配置：`Config.cpu_quota_us` 与 cgroup v2 写入支持。
- 新增 Agent 集成示例：基础执行、流式输出、LLM Agent demo、LangChain 集成、OpenAI Agents SDK 集成、多语言执行与 CoW Fork 示例。
- 新增 Quick Start Demo 脚本，覆盖快速执行、超时、退出码、stderr、连续执行等核心场景。
- 新增性能基准与指标体系：OS 级冷启动 P50 8.24ms，Wasm 冷启动 P50 1.01ms（清缓存），预热池 acquire only P50 0.19us，完整热路径 P50 773us，microVM 冷启动 P50 253ms，microVM 快照恢复 P50 69ms（非池化）/ 28ms（池化 restore-to-ready）。
- 新增 Criterion 基准测试、Wasm 冷启动基准、VmPool 热路径 benchmark、SDK 基准测试与 benchmark CI 检查。
- 新增 GitHub Actions CI、Release CI、Python wheel 构建、安装脚本、发布脚本、release smoke test、cargo-audit、clippy、fmt 与跨平台检查。
- 新增 GitHub 社区健康文件、许可证、贡献指南、安全策略、AI 代理发现文件、crate metadata、per-crate README 与发布所需文档。

### 变更

- 将 SDK 设计收敛为“默认智能路由 + 高级用户完全可控”，根据代码可信度和平台能力自动选择 OS、Wasm 或 microVM 后端。
- 将 CLI 默认后端调整为 `--backend auto`，并完善 SDK 到 CLI 的错误映射，区分后端不可用、配置错误与执行失败。
- 将 SDK 模块拆分，抽离命令、生命周期、VM 错误映射、后端分派与绑定逻辑，降低耦合并提升可维护性。
- 将生命周期错误从字符串匹配改为结构化枚举，提升错误处理稳定性与 API 可测试性。
- 将 MCP `next_id` 从锁保护计数改为 `AtomicU64`，减少同步开销。
- 将 Linux 安全策略去重，复用 Seccomp/Landlock 规则构建逻辑，降低重复实现。
- 将 KVM 后端从单个大型 `kvm.rs` 拆分为多个子模块，并迁移到 crates.io 上真实 rust-vmm crate，移除 vendor shim。
- 将 VM 性能输出迁移为结构化日志，并新增 host 侧 BootProfile 与 guest 侧 BOOT_TIME 时间戳。
- 优化 microVM 冷启动：host-passthrough CPUID、cmdline 参数精简、APIC 初始化优化、文件缓存、大块清零、跳过冗余 rootfs metadata、跳过冗余 ELF 加载、最小化内核配置与 rootfs 缩减。
- 优化默认资源配置：CLI 与 SDK 默认内存降低到 64MB，并补齐 vCPU、内存、CPU 配额等可控配置。
- 调整 microVM 冷启动目标为 P50 <300ms，并以 253ms 达标；池化 restore-to-ready 以 28ms 达成快照恢复目标。
- 默认禁用 vsock 数据面，恢复纯串口模式作为稳定执行路径，保证测试与发布可靠性。
- 扩展 Guest Rootfs，加入 Node.js、更多 BusyBox applet，并统一本地与 Docker 构建路径。
- 统一 workspace 依赖版本和 feature 聚合配置，新增 `full` feature 便于完整能力构建。
- 全面英文化 CLI、MCP Server、错误消息、README、docs、CONTRIBUTING 与 crate 文档，面向公开发布统一用户体验。
- 统一官方域名为 `mimobox.io`，并同步更新 README、文档与安装说明。
- 改进安装和发布体验：`install.sh` 支持更多平台、预编译二进制安装、URL 分支修正、国际化提示与 checksum 生成流程。
- 重写 README 首屏、快速上手、产品定位、性能数据、竞品对比、路线图与 60 秒体验入口。

### 修复

- 修复 Python SDK `cwd` 参数 shell 注入风险，改为安全参数传递。
- 修复 HTTP 代理 DNS 重绑定竞态漏洞，保证域名白名单校验与实际连接目标一致。
- 修复 macOS 文件读取安全策略过宽问题，改为 deny-based 限制并收紧读取白名单。
- 修复 Linux `setsid` 逃逸风险、Seccomp 架构校验缺失、ioctl 白名单过宽、进程数限制不足和 shell 启动 SIGSYS 问题。
- 修复资源泄漏风险：VmPool/RestorePool Drop、防御性 Sandbox retry、SDK Sandbox Drop 与 MCP SIGTERM handler。
- 修复 MCP 同步 SDK 调用阻塞 runtime、`fork()` 锁嵌套、stdio 集成测试与 seccomp 环境下退出码判定问题。
- 修复 VM API 测试、PTY microVM 测试、VM e2e 测试、PtySession Debug、PTY echo 兼容性和 VM assets 缺失时 panic 问题。
- 修复 microVM 串口命令协议、超时判定、stderr 捕获、退出码传播、预热池热路径退化与 rootfs 构建/测试路径不一致问题。
- 修复 guest 内存不足、BusyBox URL 过期、最小化内核缺失 IOPL/FUTEX/EPOLL 等 guest init 必需配置问题。
- 修复 Python SDK、Rust SDK、CLI、MCP 与流式示例的 Linux/macOS 编译问题，包括 cfg 门控 import、musl ioctl 类型、pthread_t Send 安全性、KVM clippy lint 与 release binary 名称。
- 修复 CLI e2e 测试在 seccomp 下因 `fork`、`printf`、stderr 缓冲与平台限制导致的失败。
- 修复 SDK 目录列表池化 VM 分支编译错误，并补齐 list_dir 全后端集成测试。
- 修复 LangChain 示例、LLM Agent 示例、quickstart demo binary 名称、release workflow、MCP 依赖声明和 api.md 版本号等发布阻断问题。
- 修复 install.sh 分支名、下载超时、checksum 生成顺序、README git clone URL、build-kernel.sh 权限和 build-rootfs 临时路径问题。
- 修复 CI 中 macOS runner、Linux CLI KVM feature、maturin feature、target 安装、cargo-audit 安装、PID namespace 断言与 clippy 安装等问题。
- 清理误提交的临时文件、计划文件、`scheduled_tasks.lock` 与 VM assets，避免污染发布包。

### 文档

- 新增并持续更新 API 文档、Python SDK 文档、MCP 客户端集成指南、Getting Started、SPECIFICATION.md 与平台限制说明。
- 新增串口流式输出与 HTTP 代理协议设计文档，记录 Guest 串口通道、SDK 智能路由和 microVM 集成状态。
- 新增产品战略、三层隔离架构决策、竞品分析、功能差异分析、可行性评审、代码审查和性能报告等讨论文档。
- 新增贡献指南、安全策略、FAQ、故障排查、发布说明、GitHub 社区健康文件、AI 发现索引与 per-crate README。
- 更新 README：补充项目定位、安装运行、快速上手、Docker 试用、性能指标、CI 状态、许可证 badge、文档索引、路线图与竞品对比。
- 更新 MCP 文档为预编译二进制安装方式，并同步 API、Python SDK 与最新 SDK 能力。
- 同步中英文 README 结构，修正文档中的断裂路径、平台限制、安装命令、用户旅程与官方域名。

### 内部

- 建立 Rust workspace 多 crate 架构：`mimobox-core`、`mimobox-sdk`、`mimobox-os`、`mimobox-wasm`、`mimobox-vm`、`mimobox-cli`、`mimobox-mcp` 与 Python 绑定。
- 建立脚本化工程入口：rootfs/kernel 构建、测试、基准、发布、quickstart、安装与 release smoke test 均通过 `scripts/` 管理。
- 建立跨平台 CI 矩阵：Linux OS/VM、macOS 默认 feature、Wasm、KVM e2e、release 检查、Python wheel、cargo audit、fmt、clippy 与 doc links。
- 建立测试体系：CLI e2e、SDK 集成、VmPool、fork 隔离、OS 沙箱安全、MCP stdio、HTTP 代理、VM API、目录列表、快照、PTY 和性能基准测试。
- 完成 clippy 零 warning、fmt 统一、rustdoc 警告清理、文档链接修复与 Rust 工具链锁定。
- 完成 SDK 分派逻辑去重，提取宏减少重复代码，并清理 Linux 安全策略重复实现。
- 完成发布管线就绪化：依赖统一、社区文件、crate metadata、license、CHANGELOG、install.sh、release.yml 与自动发布脚本。
- 完成 Linux 服务器路径迁移、KVM 构建测试工具链、VM 资产路径、CI 缓存与性能验证环境整理。
- 完成多轮产品打磨：API freeze、Python SDK 完善、MCP 工具扩展、文档刷新、示例画廊、错误英文化与公开发布准备。
