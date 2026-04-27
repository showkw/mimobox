# macOS 沙箱安全最佳实践调研报告

> 调研日期：2026-04-27
> 范围：Seatbelt/sandbox-exec 最佳实践、竞品实现、macOS 安全机制演进、性能对比
> 目标：为 mimobox macOS 后端（`crates/mimobox-os/src/macos.rs`）提供改进建议

---

## 一、关键发现（按影响力排序）

### 1. sandbox_init() 底层 API 比 sandbox-exec 更优

Apple 的 `sandbox_init()` 和 `sandbox_init_with_parameters()` 是私有但稳定的 API，被 Chrome/Chromium、Firefox、Nix 等广泛使用。`sandbox-exec` 命令行工具底层调用的就是 `sandbox_init()`。

直接调用 `sandbox_init()` 的优势：
- 避免外部进程调用开销（消除 `Command::new("sandbox-exec")` 的 fork+exec 开销）
- 可通过 `preexec_fn` 在 fork 后、exec 前直接应用策略，无需中间进程
- 更精确的错误处理（返回错误码而非解析 stderr）
- 避免 PATH 注入风险（无需硬编码 `/usr/bin/sandbox-exec`）

nono 项目使用 `sandbox_init()` 而非 `sandbox_apply_container()`，尽管技术上未文档化，但该 API 已稳定超过十年。参数化 profile 支持 `(param "KEY")` 语法，避免每次拼完整策略字符串。

**参考**：Zameer Manji 博文展示了通过 `ctypes` 从 Python 调用 `sandbox_init_with_parameters()` 的完整示例，证明 FFI 路径可行。

### 2. macOS 网络隔离是行业性难题

Seatbelt **不支持域名级别过滤**，只支持协议（TCP/UDP）、方向（inbound/outbound）、IP 地址。这使得 macOS 上无法像 Linux 那样通过 network namespace + 代理实现细粒度网络控制。

| 项目 | macOS 网络策略 |
|------|---------------|
| Pent | 明确标注 "not yet available"，无 network namespaces |
| sbe | 本地 HTTP 代理 + `HTTP_PROXY` 环境变量注入 |
| Codex (openai/codex) | 同 sbe，代理模式 + 域名白名单 |
| cplt (navikt) | SBPL `(allow network-outbound *:443)` 端口级控制 |
| mimobox 当前 | `(deny network*)` 完全禁止 |

mimobox 当前完全禁止网络的策略对需要联网的场景（如 pip install、API 调用）过于粗暴。

### 3. 竞品 Seatbelt Profile 最佳实践模式

#### OpenAI Codex (`codex-rs/core/src/seatbelt.rs`)

工业级 Seatbelt 实现，核心设计：
- 硬编码 `/usr/bin/sandbox-exec` 防止 PATH 注入
- 基础策略来自 `seatbelt_base_policy.sbpl` 文件，`(deny default)` 为起点
- 文件系统：`(allow file-read*)` + `(deny file-read* (subpath ...))` 排除敏感路径
- 写入策略：基于 `SeatbeltAccessRoot` 的 allowlist + `excluded subpaths` + `require-not` 规则
- 自动保护 `.git`、`.codex`、`.agents` 等目录为只读
- 网络策略：通过 `NetworkSandboxPolicy` + 代理配置
- 策略拆分：`FileSystemSandboxPolicy` 和 `NetworkSandboxPolicy` 独立生成，避免 legacy 投影丢失信息

#### nono — "Allow Discovery, Deny Content" 模式

创新的敏感路径保护策略：

| 操作 | Seatbelt 规则 | 结果 |
|------|--------------|------|
| `stat ~/.ssh` | `file-read-metadata` | 允许（发现目录存在） |
| `test -d ~/.ssh` | `file-read-metadata` | 允许 |
| `ls ~/.ssh` | `file-read-data` (readdir) | 拒绝 |
| `cat ~/.ssh/id_rsa` | `file-read-data` | 拒绝 |

其他亮点：
- **Unix Socket 注意**：`connect()` 在 Unix socket 上被 Seatbelt 归类为 `network-outbound`，不是文件操作。需要同时用 `(deny network-outbound (path "/var/run/docker.sock"))` 阻断
- **APFS Firmlinks**：macOS 10.15+ 的 `/System/Volumes/Data/Users` 路径问题，策略必须同时覆盖 firmlink 路径
- **系统操作精细控制**：只允许 `system-socket`/`system-fsctl`/`system-info`，排除 `system-audit`/`system-privilege`/`system-reboot`

#### sbe (tyrchen/sbe)

Rust 2024 edition，v0.2.0（2026-04-07 发布）：
- 生态感知自动检测（npm -> Node, Cargo.toml -> Rust）
- 本地代理 (`sbe-proxy`) 做域名白名单
- deny-by-default + 生态特化例外
- `--trace` 实时违规日志

#### sandbox-shell (sx)

轻量级 CLI：
- 可堆叠 profiles（base + online + rust）
- `--dry-run` 预览 profile、`--explain` 展示允许/拒绝规则

### 4. sandbox-exec 被标记为 deprecated 但无替代品

Apple 标记 `sandbox-exec` 为 deprecated，但没有提供等价的公开替代。Chromium、Firefox、VS Code 等仍在使用。业界共识：Apple 不太可能在不提供替代的情况下移除，因为 App Sandbox 本身依赖 Seatbelt。

**风险评级**：低-中（短期可控，长期需关注 macOS beta 变化）

### 5. Endpoint Security Framework 可用于监控但非隔离

ESF 是 C API，用于监控/授权系统事件（进程执行、文件系统挂载、fork、signal）。agentsh 项目正在用 ESF + Network Extension 实现 macOS 沙箱（Alpha 阶段）。

**不适合 mimobox 当前阶段**：
- 需要 System Extension（用户在系统设置中手动批准）
- 需要 Apple Developer 账号 + codesign
- 适合审计/监控场景，不适合轻量级进程隔离
- 如果 Apple 未来弃用 Seatbelt，ESF + Network Extension 是最可能的替代路径

### 6. macOS 上无法实现内存限制

`RLIMIT_AS` 无法从 unlimited 缩小，没有 macOS 原生的 cgroups 等价物。mimobox 当前正确处理了这个问题（记录告警，不失败）。唯一方案是通过 microVM（Hypervisor.framework）或 Wasm 限制内存。

### 7. SBPL 语法参考来源

Apple 没有官方文档化 SBPL（Scheme-like DSL）。最佳参考：

- `/System/Library/Sandbox/Profiles/` 目录下的系统 profiles
- `bsd.sb` 提供最小化进程启动规则集，可用 `(import "bsd.sb")` 导入
- `(version 1)` 是当前唯一支持的版本

**关键操作符速查**：

| 类别 | 操作符 |
|------|--------|
| 文件 | `file-read*` `file-write*` `file-read-data` `file-read-metadata` `file-map-executable` `file-write-unlink` |
| 进程 | `process-exec` `process-fork` `process-info*` |
| 网络 | `network-outbound` `network-inbound` `network-bind` |
| 系统 | `sysctl-read` `mach*` `ipc*` `signal` `system-socket` `system-fsctl` `system-info` |
| 路径匹配 | `(subpath ...)` `(literal ...)` `(regex ...)` |
| 组合 | `(require-not ...)` `(require-all ...)` `(require-any ...)` |
| 参数化 | `(param "NAME")` `(define name (param "NAME"))` |

### 8. Rust 生态中的 macOS 沙箱 crate

| 项目 | 特点 | 调用方式 |
|------|------|---------|
| `sbexec` (tyrchen/sbe) | 生态感知 + 代理 + deny-by-default | `sandbox-exec` 命令行 |
| `sandbox-runtime` | 跨平台 Seatbelt + bwrap + seccomp | `sandbox-exec` 命令行 |
| `wardstone` | 跨平台抽象 Seatbelt + Landlock + seccomp | `sandbox-exec` 命令行 |
| `oxsb` (daaa1k) | 统一 YAML 配置，自动后端选择 | `sandbox-exec` 命令行 |
| `Pent` (valentinradu) | Seatbelt + Landlock + overlayfs | `sandbox-exec` 命令行 |

**所有项目都使用 `sandbox-exec` 命令行工具，而非直接调用 `sandbox_init()` FFI**。这是一个差异化机会。

---

## 二、mimobox macOS 后端改进建议

### 建议 1：从 sandbox-exec 命令行迁移到 sandbox_init() FFI

**当前实现**：`Command::new("sandbox-exec")` 启动外部进程（`macos.rs:304`）
**建议改为**：通过 Rust FFI 直接调用 `sandbox_init_with_parameters()`

**实现要点**：
```rust
// 通过 libSystem.dylib 调用（dlopen/dlsym 或直接链接）
// int sandbox_init_with_parameters(
//   const char *profile, uint64_t flags,
//   const char *const parameters[], char **errorbuf
// );
// 在 Command::new(cmd).pre_exec(|| { sandbox_init(...); Ok(()) }) 中使用
```

**优势**：
- 消除外部进程启动开销（~1-2ms）
- 策略在 fork 后、exec 前直接应用，无需中间进程
- 更精确的错误处理
- 避免 PATH 注入风险

**实现难度**：中等（需要 unsafe FFI 绑定 + 错误处理 + 保留 sandbox-exec fallback）
**预期影响**：冷启动性能提升 ~1-2ms，消除外部进程依赖，为"首个使用 sandbox_init() FFI 的 Rust 沙箱"差异化

### 建议 2：引入 "Allow Discovery, Deny Content" 敏感路径保护模式

**当前实现**：`SENSITIVE_HOME_SUBPATHS` 列表完全拒绝读取（包括 metadata），见 `macos.rs:38-54`
**建议改为**：允许 `file-read-metadata`，拒绝 `file-read-data` 和 `file-write*`

**策略变更**：
```
; 当前：(deny file-read* (subpath "~/.ssh"))  -- 连 stat() 都拒绝
; 改为：
(allow file-read-metadata (subpath "~/.ssh"))
(deny file-read-data (subpath "~/.ssh"))
(deny file-write* (subpath "~/.ssh"))
```

**优势**：
- 程序可以 `stat()` 和 `test -d` 敏感目录而不会崩溃
- 实际文件内容仍然无法读取
- 与 macOS TCC 行为一致，用户体验更自然

**实现难度**：低（仅修改 `generate_policy()` 方法）
**预期影响**：提升 macOS 上的兼容性和用户体验

### 建议 3：扩展敏感路径列表

**当前覆盖**（15 个）：.ssh, .gnupg, .aws, .azure, .kube, .docker, .netrc, .gitconfig, .npmrc, .pypirc, .cargo/credentials, .config/gcloud, .config/gh, .config/solana, .config/starknet

**竞品额外覆盖**：

| 类别 | 路径 | 来源 |
|------|------|------|
| macOS Keychain | `~/Library/Keychains` | nono, cplt |
| 密码管理器 | `~/.password-store`, `~/.1password` | nono |
| 浏览器数据 | `~/Library/Application Support/Google/Chrome` 等 | nono |
| macOS 私有数据 | `~/Library/Messages`, `~/Library/Mail`, `~/Library/Cookies` | nono |
| Shell 配置 | `~/.zshrc`, `~/.bashrc`, `~/.profile` | nono |
| 历史文件 | `~/.zsh_history`, `~/.bash_history` | nono |
| Git 凭证 | `~/.git-credentials` | nono, cplt |
| 缓存目录 | `~/Library/Caches`（阻止执行） | cplt |

**实现难度**：低（扩展 `SENSITIVE_HOME_SUBPATHS` 常量）
**预期影响**：提升安全性覆盖面，防止凭证泄露

### 建议 4：增加 process-exec 安全约束

**当前实现**：仅允许 `/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`（`macos.rs:249`）
**建议增加**：

```scheme
; 防止从可写目录执行二进制
(deny process-exec (subpath "/private/tmp"))
(deny file-map-executable (subpath "/private/tmp"))
(deny process-exec (subpath "~/Library/Caches"))
(deny file-map-executable (subpath "~/Library/Caches"))
```

同时考虑是否需要扩展允许的执行路径：
- `/usr/local/bin`（Intel Mac Homebrew）
- `/opt/homebrew/bin`（Apple Silicon Homebrew）

**竞品实践**：cplt 的 `DENIED_CACHE_PREFIXES` 用正则拒绝浏览器/系统缓存中的二进制执行。

**实现难度**：低
**预期影响**：防止二进制投递攻击（从可写目录下载并执行恶意二进制）

### 建议 5：考虑网络代理模式（P1/P2 时间线）

**当前实现**：`(deny network*)` 完全禁止
**建议长期方案**：实现类似 sbe/Codex 的本地代理模式

**架构**：
1. 启动本地 HTTP 代理（127.0.0.1:PORT）
2. 注入 `HTTP_PROXY` 环境变量
3. SBPL 策略：`(deny network*)` + `(allow network-outbound 127.0.0.1:PORT)`
4. 代理层做域名白名单过滤

**前提**：macOS Seatbelt 不支持域名级别过滤，代理层是必须的。mimobox 已有 Linux 侧的 HTTP 代理实现可复用。

**实现难度**：高（需要代理服务器 + 环境变量注入 + 域名过滤逻辑）
**预期影响**：使 macOS 后端支持联网沙箱，与 Linux 后端功能对齐

---

## 三、性能对比

### 冷启动开销

| 方案 | 预估延迟 | 说明 |
|------|---------|------|
| `sandbox-exec` 命令行 | ~1-2ms | 外部进程 fork+exec |
| `sandbox_init()` FFI | ~0.1-0.5ms | 无进程 fork |
| Linux Landlock（mimobox 实测） | P50: 8.24ms | BPF 验证器开销 |
| Wasm（mimobox 实测） | P50: 1.01ms | Wasmtime 引擎 |
| Docker 容器 | 500ms-2s | 完整容器启动 |
| Firecracker microVM | ~125ms | KVM 虚拟化 |

macOS Seatbelt 的开销远低于 Linux Landlock，是最轻量的沙箱方案之一。

### macOS 沙箱优化手段

1. **从 sandbox-exec 迁移到 sandbox_init()**（消除进程开销）
2. **使用 `(import "bsd.sb")`** 避免重复定义基础规则
3. **使用参数化 profile `(param ...)`** 避免每次生成完整策略字符串
4. **缓存编译后的策略**（sandbox_init 内部可能有缓存）
5. **最小化规则数量**（更少的规则 = 更快的策略编译和匹配）

---

## 四、行业趋势与风险评估

### sandbox-exec 弃用风险

| 维度 | 评估 |
|------|------|
| 风险等级 | 低-中 |
| 理由 | Chrome/Firefox/VS Code/Codex 等大量使用，Apple 不太可能无替代移除 |
| 缓解 | 同时维护 sandbox-exec 和 sandbox_init() 两种调用路径 |
| 监控 | 关注 macOS beta 版本的 Seatbelt API 变化 |

### Endpoint Security Framework 的未来

- **当前阶段**：不适合 mimobox（需 System Extension + 用户授权 + codesign）
- **如果 Apple 弃用 Seatbelt**：ESF + Network Extension 是最可能的替代
- **agentsh 项目**：正在验证这条路径（Alpha 阶段）

### 跨平台统一抽象趋势

行业从"每个平台各自实现"转向"统一策略 + 平台适配"。wardstone、oxsb、Pent 等项目提供了跨平台沙箱抽象。mimobox 的 `Sandbox` trait 已经是跨平台抽象的良好基础。

行业洞见（CrabTalk 调研）：Claude Code、Cursor、Codex CLI 都收敛到同一架构 -- OS 级原语（Seatbelt/Landlock/seccomp）+ 无 Docker 依赖。macOS/Windows 维护三套实现是共同的痛点，Apple 标记 sandbox-exec deprecated 增加了紧迫性。

---

## 五、参考项目与资源

### Rust macOS 沙箱项目

| 项目 | 特点 | GitHub |
|------|------|--------|
| sbe (sbexec) | 生态感知 + 代理 + deny-by-default | github.com/tyrchen/sbe |
| sandbox-runtime | 跨平台 Seatbelt + bwrap | crates.io/crates/sandbox-runtime |
| wardstone | 跨平台抽象 Seatbelt + Landlock | docs.rs/wardstone |
| Pent | Seatbelt + Landlock + overlayfs | github.com/valentinradu/Pent |
| oxsb | 统一 YAML 配置 | github.com/daaa1k/oxsb |
| sandbox-shell (sx) | 可堆叠 profiles + trace | github.com/agentic-dev3o/sandbox-shell |
| cplt | GitHub Copilot CLI Seatbelt 包装 | github.com/navikt/cplt |

### 参考文章

- [CrabTalk: Sandboxing AI agents: beyond Docker and WASM](https://openwalrus.xyz/blog/agent-sandbox-permissions) — 2026 年最全面的 AI agent 沙箱调研
- [Zameer Manji: Sandboxing subprocesses in Python on macOS](https://zameermanji.com/blog/2025/4/1/sandboxing-subprocesses-in-python-on-macos/) — sandbox_init_with_parameters 实战
- [Nono Docs: macOS Seatbelt](https://docs.nono.sh/docs/cli/internals/seatbelt) — "Allow Discovery, Deny Content" 模式详解
- [OpenAI Codex seatbelt.rs](https://github.com/openai/codex/blob/main/codex-rs/core/src/seatbelt.rs) — 工业级 Seatbelt 实现
- [OpenAI Codex seatbelt tests](https://github.com/openai/codex/blob/main/codex-rs/sandboxing/src/seatbelt_tests.rs) — 测试覆盖参考
