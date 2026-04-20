# mimobox

Rust 实现的跨平台 Agent Sandbox。`mimobox` 面向需要在本地或服务端安全执行不可信命令、脚本与 Wasm 工具的开发者，提供统一的 `Sandbox` trait、可插拔多后端实现，以及面向低延迟场景的预热池能力。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
| v1.0 | 2026-04-20 | 重写根目录 README，补齐架构、API、性能、脚本与安全模型说明 | 新增 | Codex |

## 术语表

| 术语 | 定义 |
| --- | --- |
| Agent Sandbox | 用于执行不可信代码或命令的受限运行环境 |
| OS 级沙箱 | 基于内核原语对进程进行隔离，例如 Landlock、Seccomp、Seatbelt |
| Wasm 级沙箱 | 基于 Wasmtime/WASI 运行 Wasm 模块的语言级隔离 |
| microVM 级沙箱 | 基于轻量虚拟机的硬件级隔离，本仓库当前处于路线图阶段 |
| 预热池 | 预先创建一批空闲沙箱，通过复用降低获取延迟 |
| `Sandbox` trait | `mimobox-core` 中定义的统一沙箱生命周期抽象 |

## 文章内容大纲目录表

| 章节 | 标题 | 目的 |
| --- | --- | --- |
| 1 | 项目概览 | 定义项目定位、实现状态与核心能力 |
| 2 | 核心特性 | 总结三层隔离路线与关键工程特性 |
| 3 | 快速开始 | 给出安装、构建、运行与验证入口 |
| 4 | 使用示例 | 展示 OS 沙箱、Wasm 沙箱、预热池的真实 API 用法 |
| 5 | 架构与配置 | 解释结构关系、配置字段和安全模型 |
| 6 | 开发与性能 | 给出脚本、支持矩阵与性能目标对照 |
| 7 | 文档与许可 | 提供扩展阅读和许可证信息 |

## 1. 项目概览

`mimobox` 当前是一个 Cargo workspace，根目录位于 `/Users/showkw/dev/mimobox`，主要包含四个 crate：

```text
/Users/showkw/dev/mimobox
├── crates/mimobox-core      # 核心 trait、配置、结果与错误类型
├── crates/mimobox-os        # Linux/macOS OS 级沙箱与预热池
├── crates/mimobox-wasm      # Wasmtime + WASI 的 Wasm 沙箱后端
├── crates/mimobox-cli       # CLI 入口与基准测试命令
├── docs/research            # 技术调研与代码审查报告
├── scripts                  # 构建、测试、基准脚本
└── wit                      # WIT 接口定义与工具协议
```

项目的统一入口是 `mimobox-core` 中的 `Sandbox` trait：

- `new(config)` 负责创建隔离环境。
- `execute(&mut self, cmd)` 负责在隔离环境中执行命令或 Wasm 模块。
- `destroy(self)` 负责显式销毁资源。

当前实现状态：

- Linux OS 沙箱：已实现，使用 Landlock + Seccomp-bpf + namespaces + `setrlimit`。
- macOS OS 沙箱：已实现，使用 Seatbelt `sandbox-exec`。
- Wasm 沙箱：已实现，基于 Wasmtime + WASI Preview 1。
- 预热池：已实现，适用于 Linux/macOS 的 OS 级后端。
- Windows OS 沙箱：规划中，目标后端为 AppContainer。
- microVM 后端：规划中，当前仅保留架构位置和性能目标。

## 2. 核心特性

### 2.1 三层隔离路线

1. OS 级隔离
   Linux 使用 Landlock 限制文件系统、Seccomp 过滤系统调用、PID/NET/IPC/Mount namespaces 隔离命名空间，再通过 `setrlimit(RLIMIT_AS)` 施加内存上限。
2. Wasm 级隔离
   使用 Wasmtime 运行时执行 `.wasm` 模块，基于 Fuel 与 Epoch interruption 限制执行时间，使用 `StoreLimits` 限制内存和实例资源。
3. microVM 级隔离
   当前尚未实现，但设计目标已经明确，后续将承载最高强度的隔离需求。

### 2.2 工程级能力

- 统一抽象：所有后端共享 `SandboxConfig`、`SandboxResult` 和 `SandboxError`。
- 低延迟获取：`SandboxPool` 支持预热、命中/未命中统计、LRU 回收与健康检查。
- 缓存优化：Wasm 后端使用内容哈希与磁盘缓存复用编译产物。
- 可审计安全链路：Linux 后端严格执行“内存限制 -> Landlock -> namespace -> Seccomp -> exec”顺序。
- 明确边界：文档中区分“已实现能力”和“路线图能力”，不把未落地特性描述成现状。

### 2.3 性能速览

以下两项为本次交付要求记录的最新性能数据：

| 阶段 | 指标 | 数值 |
| --- | --- | --- |
| Phase 1 | OS 级沙箱冷启动 | 2.64ms |
| Phase 2 | Wasm 沙箱冷启动 | 0.67ms |

补充说明：

- 仓库内可直接复核的 Linux 审查基线见 `/Users/showkw/dev/mimobox/docs/research/10-code-review-round2.md`，其中记录 `冷启动 P50 ~3.51ms（含全部安全加固）`。
- `scripts/bench.sh` 当前通过 SSH 连接 Linux 基准机；在本次文档整理环境中无法直接复跑该脚本，因此 README 同时保留上述仓库可见基线说明。

## 3. 快速开始

### 3.1 环境要求

- Rust stable 工具链，支持 workspace 使用的 `edition = "2024"`。
- Linux 基准环境可通过 `/Users/showkw/dev/mimobox/scripts/bench.sh` 访问。
- macOS 开发机可用于编辑、静态检查和 Wasm 后端开发。

### 3.2 安装工具链

```bash
cd "/Users/showkw/dev/mimobox"
rustup toolchain install stable
rustup default stable
rustup component add rustfmt clippy
```

### 3.3 构建项目

正式入口优先使用 `scripts/`：

```bash
cd "/Users/showkw/dev/mimobox"
./scripts/setup.sh
```

如果需要编译包含 Wasm 后端的完整 workspace，请启用 CLI feature：

```bash
cd "/Users/showkw/dev/mimobox"
cargo build --workspace --features mimobox-cli/wasm
```

### 3.4 运行功能测试与基准

```bash
cd "/Users/showkw/dev/mimobox"
./scripts/test.sh
./scripts/bench.sh
```

### 3.5 运行 CLI 示例

Linux OS 沙箱执行：

```bash
cd "/Users/showkw/dev/mimobox"
cargo run -p mimobox-cli -- /bin/echo "hello from mimobox"
```

启用 Wasm 后端后执行 `.wasm` 模块：

```bash
cd "/Users/showkw/dev/mimobox"
cargo run -p mimobox-cli --features wasm -- --wasm "/absolute/path/to/tool.wasm"
```

运行 Wasm 基准：

```bash
cd "/Users/showkw/dev/mimobox"
cargo run -p mimobox-cli --features wasm -- --wasm-bench "/absolute/path/to/tool.wasm"
```

## 4. 使用示例

### 4.1 OS 沙箱示例

```rust
#[cfg(target_os = "linux")]
use mimobox_core::{Sandbox, SandboxConfig, SeccompProfile};
#[cfg(target_os = "linux")]
use mimobox_os::LinuxSandbox;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SandboxConfig {
        timeout_secs: Some(5),
        memory_limit_mb: Some(256),
        seccomp_profile: SeccompProfile::Essential,
        allow_fork: false,
        ..Default::default()
    };

    let mut sandbox = LinuxSandbox::new(config)?;
    let command = vec![
        "/bin/echo".to_string(),
        "hello from os sandbox".to_string(),
    ];
    let result = sandbox.execute(&command)?;
    sandbox.destroy()?;

    println!("exit={:?}", result.exit_code);
    println!("stdout={}", String::from_utf8_lossy(&result.stdout));
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("该示例仅在 Linux 上编译运行");
}
```

### 4.2 Wasm 沙箱示例

```rust
#[cfg(feature = "wasm")]
use mimobox_core::{Sandbox, SandboxConfig, SeccompProfile};
#[cfg(feature = "wasm")]
use mimobox_wasm::WasmSandbox;

#[cfg(feature = "wasm")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SandboxConfig {
        timeout_secs: Some(5),
        memory_limit_mb: Some(64),
        deny_network: true,
        fs_readonly: vec![],
        fs_readwrite: vec![],
        seccomp_profile: SeccompProfile::Essential,
        allow_fork: false,
    };

    let mut sandbox = WasmSandbox::new(config)?;
    let command = vec!["/absolute/path/to/tool.wasm".to_string()];
    let result = sandbox.execute(&command)?;
    sandbox.destroy()?;

    println!("exit={:?}", result.exit_code);
    println!("stdout={}", String::from_utf8_lossy(&result.stdout));
    Ok(())
}

#[cfg(not(feature = "wasm"))]
fn main() {
    eprintln!("请使用 `--features wasm` 编译此示例");
}
```

### 4.3 预热池示例

```rust
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mimobox_core::SandboxConfig;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use mimobox_os::{PoolConfig, SandboxPool};

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SandboxPool::new(
        SandboxConfig::default(),
        PoolConfig {
            min_size: 2,
            max_size: 8,
            max_idle_duration: std::time::Duration::from_secs(30),
        },
    )?;

    pool.warm(4)?;

    let mut sandbox = pool.acquire()?;
    let command = if cfg!(target_os = "linux") {
        vec!["/bin/true".to_string()]
    } else {
        vec!["/usr/bin/true".to_string()]
    };
    let result = sandbox.execute(&command)?;

    drop(sandbox); // 通过 Drop 隐式 release

    println!("exit={:?}", result.exit_code);
    println!("stats={:?}", pool.stats()?);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("SandboxPool 当前仅支持 Linux/macOS 的 OS 级后端");
}
```

## 5. 架构图

```text
+----------------------------------------------------+
| 调用方：CLI / 测试 / 上层 Agent Runtime            |
+----------------------------------------------------+
                         |
                         v
+----------------------------------------------------+
| mimobox-core::Sandbox trait                        |
| 生命周期：new(config) -> execute(&mut self, cmd)   |
|          -> destroy(self)                          |
+----------------------------------------------------+
          |                     |                     |
          v                     v                     v
+------------------+  +------------------+  +-------------------+
| LinuxSandbox     |  | MacOsSandbox     |  | WasmSandbox       |
| Landlock         |  | Seatbelt         |  | Wasmtime Engine    |
| Seccomp-bpf      |  | sandbox-exec     |  | WASI Preview 1     |
| namespaces       |  | 写路径白名单     |  | Fuel + Epoch       |
+------------------+  +------------------+  | 模块缓存           |
                                            +-------------------+
          |
          v
+----------------------------------------------------+
| SandboxPool                                         |
| warm() -> acquire() -> PooledSandbox::drop recycle  |
| 统计：hit / miss / evict / idle / in_use            |
+----------------------------------------------------+

+----------------------------------------------------+
| microVM backend（路线图阶段，当前未实现）          |
+----------------------------------------------------+
```

## 6. 配置说明

`SandboxConfig` 定义于 `/Users/showkw/dev/mimobox/crates/mimobox-core/src/sandbox.rs`。

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `fs_readonly` | `Vec<PathBuf>` | `/usr`、`/lib`、`/lib64`、`/bin`、`/sbin`、`/dev`、`/proc`、`/etc` | 允许只读访问的路径集合 |
| `fs_readwrite` | `Vec<PathBuf>` | `/tmp` | 允许读写访问的路径集合 |
| `deny_network` | `bool` | `true` | 是否默认拒绝网络访问 |
| `memory_limit_mb` | `Option<u64>` | `Some(512)` | 内存上限，Linux 通过 `setrlimit`，Wasm 通过 `StoreLimits` |
| `timeout_secs` | `Option<u64>` | `Some(30)` | 执行超时秒数 |
| `seccomp_profile` | `SeccompProfile` | `Essential` | Linux 系统调用过滤策略 |
| `allow_fork` | `bool` | `false` | 是否允许进程创建子进程 |

关键约束：

- Linux 后端会根据 `allow_fork` 自动把 `Essential` 提升为 `EssentialWithFork`，把 `Network` 提升为 `NetworkWithFork`。
- Wasm 后端当前无论 `deny_network` 是否为 `false`，都不会开放网络能力。
- macOS 后端无法可靠施加 `RLIMIT_AS`，因此 `memory_limit_mb` 仅记录告警，不形成强约束。

## 7. 安全模型

### 7.1 Linux

Linux 后端的安全链路由以下步骤组成：

1. 清理环境变量，仅注入最小必要的 `PATH`、`HOME`、`TERM`。
2. 使用 `setrlimit(RLIMIT_AS)` 设定内存硬上限。
3. 应用 Landlock，只对白名单路径开放读或读写权限。
4. 通过 `unshare` 创建 Mount/PID/NET/IPC 命名空间。
5. 在 `execvp` 前应用 Seccomp-bpf 白名单过滤。
6. 执行目标命令，并在超时时发送 `SIGKILL`。

### 7.2 macOS

macOS 后端基于 `sandbox-exec -p "<policy>"` 生成 Seatbelt 策略：

- 默认 `deny default`。
- 允许全部文件读取，这是 macOS 进程启动依赖所决定的现实边界。
- 仅对白名单目录开放写权限。
- 默认拒绝网络访问。
- 允许 `process-fork`，保证 shell 之类命令可运行。

### 7.3 Wasm

Wasm 后端不依赖主机系统调用过滤，而是在运行时层面建立边界：

- `Engine` 全局复用，`Store` 每次执行独立创建。
- `StoreLimits` 限制线性内存、实例数量、表数量。
- Fuel 限制纯 Wasm 指令执行时间。
- Epoch interruption 限制墙钟时间，覆盖阻塞场景。
- `MemoryOutputPipe` 截获 stdout/stderr，避免直接继承宿主流。

### 7.4 当前边界与限制

- Windows 和 microVM 后端尚未落地，不应视为当前安全保证的一部分。
- macOS 文件读取目前无法像 Linux 一样细粒度收敛。
- Wasm 后端默认使用 WASI Preview 1，尚未实现自定义宿主能力注入。

## 8. 跨平台支持矩阵

| 能力 | Linux | macOS | Windows | Wasm 后端 |
| --- | --- | --- | --- | --- |
| OS 级沙箱 | 已实现 | 已实现 | 规划中 | 不适用 |
| 文件系统写白名单 | 已实现 | 已实现 | 未实现 | 通过 WASI 预打开目录控制 |
| 文件系统读白名单 | 已实现 | 部分实现 | 未实现 | 通过 WASI 预打开目录控制 |
| 系统调用过滤 | Seccomp-bpf | 无等价实现 | 未实现 | 不适用 |
| 网络默认拒绝 | 通过 namespace + 策略 | 通过 Seatbelt 策略 | 未实现 | 当前始终拒绝 |
| 内存限制 | `setrlimit` | 不支持硬限制 | 未实现 | `StoreLimits` |
| 预热池 | 已实现 | 已实现 | 未实现 | 未实现 |

## 9. 开发指南

### 9.1 脚本入口

| 脚本 | 路径 | 说明 |
| --- | --- | --- |
| 构建 | `/Users/showkw/dev/mimobox/scripts/setup.sh` | 本地 release 构建 + 远端 Linux 构建 |
| 功能测试 | `/Users/showkw/dev/mimobox/scripts/test.sh` | 通过 SSH 在 Linux 环境执行基本功能测试 |
| 性能基准 | `/Users/showkw/dev/mimobox/scripts/bench.sh` | 通过 SSH 在 Linux 环境运行基准测试 |

### 9.2 crate 职责

| crate | 路径 | 职责 |
| --- | --- | --- |
| `mimobox-core` | `/Users/showkw/dev/mimobox/crates/mimobox-core` | 核心抽象与通用类型 |
| `mimobox-os` | `/Users/showkw/dev/mimobox/crates/mimobox-os` | Linux/macOS OS 级沙箱与预热池 |
| `mimobox-wasm` | `/Users/showkw/dev/mimobox/crates/mimobox-wasm` | Wasm 运行时后端与基准 |
| `mimobox-cli` | `/Users/showkw/dev/mimobox/crates/mimobox-cli` | CLI 参数解析、演示和基准入口 |

### 9.3 文档索引

| 文档 | 路径 | 说明 |
| --- | --- | --- |
| API 参考 | `/Users/showkw/dev/mimobox/docs/api.md` | 公开类型、方法与示例 |
| 架构设计 | `/Users/showkw/dev/mimobox/docs/architecture.md` | 后端设计、池化机制与安全边界 |
| 综合研究 | `/Users/showkw/dev/mimobox/docs/research/00-executive-summary.md` | 技术路线与阶段规划 |

## 10. 性能基准

### 10.1 目标与实际

| 阶段 | 指标 | 目标 | 实际 |
| --- | --- | --- | --- |
| Phase 1 | OS 级冷启动 | `< 10ms` | `2.64ms` |
| Phase 2 | Wasm 冷启动 | `< 5ms` | `0.67ms` |
| Phase 3 | 预热池热获取 | `< 100us` | 代码已提供 `run_pool_benchmark`，当前仓库未固化单一验收值 |
| Phase 4 | microVM 冷启动 | `< 200ms` | 未实现 |

### 10.2 可追溯数据来源

- Linux OS 级基准入口：`/Users/showkw/dev/mimobox/crates/mimobox-cli/src/main.rs` 中的 `run_benchmark()`。
- Wasm 基准入口：`/Users/showkw/dev/mimobox/crates/mimobox-wasm/src/lib.rs` 中的 `run_wasm_benchmark()`。
- Linux 审查基线：`/Users/showkw/dev/mimobox/docs/research/10-code-review-round2.md` 记录 `冷启动 P50 ~3.51ms`。
- 预热池基准入口：`/Users/showkw/dev/mimobox/crates/mimobox-os/src/pool.rs` 中的 `run_pool_benchmark()`。

## 11. 许可证

本项目采用双许可证模式，许可证声明来自 workspace 根 `Cargo.toml`：

- MIT
- Apache-2.0

使用者可以按需选择其中任一许可证条款。
