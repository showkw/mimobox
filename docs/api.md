# mimobox API 参考

本文档说明 `/Users/showkw/dev/mimobox` 当前代码库中已经公开的核心 API，包括 `Sandbox` trait、配置与结果类型、Seccomp 配置、预热池以及 Wasm 后端接口。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
| v1.0 | 2026-04-20 | 首次建立 API 参考文档 | 新增 | Codex |

## 术语表

| 术语 | 定义 |
| --- | --- |
| 生命周期 | 沙箱从 `new` 到 `execute` 再到 `destroy` 的完整过程 |
| 平台后端 | `LinuxSandbox`、`MacOsSandbox`、`WasmSandbox` 这类具体实现 |
| Pool | `SandboxPool`，用于复用 OS 级沙箱实例的对象池 |
| 隐式 release | 当前版本没有显式 `release()` 方法，通过 `Drop` 自动归还 |

## 文章内容大纲目录表

| 章节 | 标题 | 目的 |
| --- | --- | --- |
| 1 | 核心 trait | 解释统一抽象和生命周期约束 |
| 2 | 核心类型 | 说明配置、结果、错误和 Seccomp 策略 |
| 3 | 预热池 API | 说明池化接口与隐式释放模型 |
| 4 | Wasm API | 说明 Wasm 后端与基准接口 |

## 1. `Sandbox` trait

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-core/src/sandbox.rs`

```rust
pub trait Sandbox {
    fn new(config: SandboxConfig) -> Result<Self, SandboxError>
    where
        Self: Sized;

    fn execute(&mut self, cmd: &[String]) -> Result<SandboxResult, SandboxError>;

    fn destroy(self) -> Result<(), SandboxError>;
}
```

### 1.1 设计含义

- `new`
  使用完整的 `SandboxConfig` 初始化后端，实现“配置先于执行”的安全约束。
- `execute`
  以 `&mut self` 执行命令，允许具体后端更新内部状态，例如 Wasm 的缓存与 Store 创建流程。
- `destroy`
  显式消费 `self`，确保调用者在需要时能主动收尾，而不是仅依赖析构。

### 1.2 生命周期示意

```text
SandboxConfig
     |
     v
new(config) -> Sandbox 实例
     |
     v
execute(&mut self, cmd)
     |
     v
SandboxResult / SandboxError
     |
     v
destroy(self)
```

### 1.3 泛型调用示例

```rust
use mimobox_core::{Sandbox, SandboxConfig, SandboxError, SandboxResult};

fn run_once<S: Sandbox>(
    config: SandboxConfig,
    command: &[String],
) -> Result<SandboxResult, SandboxError> {
    let mut sandbox = S::new(config)?;
    let result = sandbox.execute(command)?;
    sandbox.destroy()?;
    Ok(result)
}
```

### 1.4 `new` 示例

```rust
use mimobox_core::{Sandbox, SandboxConfig, SeccompProfile};
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

    let sandbox = LinuxSandbox::new(config)?;
    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
```

### 1.5 `execute` 示例

```rust
use mimobox_core::{Sandbox, SandboxConfig};
use mimobox_os::LinuxSandbox;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = LinuxSandbox::new(SandboxConfig::default())?;
    let command = vec!["/bin/echo".to_string(), "api execute".to_string()];
    let result = sandbox.execute(&command)?;

    assert_eq!(result.exit_code, Some(0));
    println!("{}", String::from_utf8_lossy(&result.stdout));

    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
```

### 1.6 `destroy` 示例

```rust
use mimobox_core::{Sandbox, SandboxConfig};
use mimobox_os::LinuxSandbox;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = LinuxSandbox::new(SandboxConfig::default())?;
    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
```

## 2. 核心类型

### 2.1 `SandboxConfig`

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-core/src/sandbox.rs`

```rust
#[derive(Clone)]
pub struct SandboxConfig {
    pub fs_readonly: Vec<PathBuf>,
    pub fs_readwrite: Vec<PathBuf>,
    pub deny_network: bool,
    pub memory_limit_mb: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub seccomp_profile: SeccompProfile,
    pub allow_fork: bool,
}
```

#### 字段详解

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `fs_readonly` | `Vec<PathBuf>` | 一组系统只读目录 | 后端允许读取但不允许写入的路径 |
| `fs_readwrite` | `Vec<PathBuf>` | `/tmp` | 后端允许读写的路径 |
| `deny_network` | `bool` | `true` | 是否默认拒绝网络访问 |
| `memory_limit_mb` | `Option<u64>` | `Some(512)` | 内存上限，以 MB 计 |
| `timeout_secs` | `Option<u64>` | `Some(30)` | 命令或 Wasm 模块最长执行时间 |
| `seccomp_profile` | `SeccompProfile` | `Essential` | Linux 系统调用过滤策略 |
| `allow_fork` | `bool` | `false` | 是否允许子进程创建 |

#### `Default` 示例

```rust
use mimobox_core::SandboxConfig;

fn main() {
    let config = SandboxConfig::default();
    assert!(config.deny_network);
    assert_eq!(config.timeout_secs, Some(30));
    assert_eq!(config.memory_limit_mb, Some(512));
}
```

#### 自定义配置示例

```rust
use mimobox_core::{SandboxConfig, SeccompProfile};

fn main() {
    let config = SandboxConfig {
        fs_readonly: vec!["/usr".into(), "/etc".into()],
        fs_readwrite: vec!["/tmp".into(), "/var/tmp".into()],
        deny_network: true,
        memory_limit_mb: Some(128),
        timeout_secs: Some(3),
        seccomp_profile: SeccompProfile::Essential,
        allow_fork: false,
    };

    assert_eq!(config.memory_limit_mb, Some(128));
}
```

### 2.2 `SandboxResult`

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-core/src/sandbox.rs`

```rust
#[derive(Debug)]
pub struct SandboxResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub elapsed: Duration,
    pub timed_out: bool,
}
```

语义说明：

- `stdout` / `stderr`
  原始字节流，由调用方自行决定是否按 UTF-8 解码。
- `exit_code`
  进程正常退出时为 `Some(code)`；超时或异常中止场景可能为 `None`。
- `elapsed`
  从后端开始执行到结果返回的耗时。
- `timed_out`
  是否因为超时策略被终止。

示例：

```rust
use mimobox_core::{Sandbox, SandboxConfig};
use mimobox_os::LinuxSandbox;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = LinuxSandbox::new(SandboxConfig::default())?;
    let command = vec!["/bin/echo".to_string(), "result example".to_string()];
    let result = sandbox.execute(&command)?;

    println!("exit_code={:?}", result.exit_code);
    println!("elapsed_ms={:.2}", result.elapsed.as_secs_f64() * 1000.0);
    println!("timed_out={}", result.timed_out);

    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
```

### 2.3 `SandboxError`

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-core/src/sandbox.rs`

```rust
pub enum SandboxError {
    NamespaceFailed(String),
    PivotRootFailed(String),
    MountFailed(String),
    LandlockFailed(String),
    SeccompFailed(String),
    ExecutionFailed(String),
    Timeout,
    PipeError(String),
    Syscall(String),
    Io(std::io::Error),
}
```

错误分层建议：

- 初始化阶段
  `NamespaceFailed`、`PivotRootFailed`、`MountFailed`、`LandlockFailed`、`SeccompFailed`
- 执行阶段
  `ExecutionFailed`、`Timeout`、`PipeError`
- 系统级封装
  `Syscall`、`Io`

示例：

```rust
use mimobox_core::SandboxError;

fn describe(error: &SandboxError) -> &'static str {
    match error {
        SandboxError::Timeout => "执行超时",
        SandboxError::ExecutionFailed(_) => "目标命令运行失败",
        SandboxError::LandlockFailed(_) => "文件系统策略应用失败",
        SandboxError::SeccompFailed(_) => "系统调用过滤失败",
        _ => "其他后端错误",
    }
}
```

### 2.4 `SeccompProfile`

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-core/src/seccomp.rs`

```rust
#[derive(Debug, Clone, Copy, Default)]
pub enum SeccompProfile {
    #[default]
    Essential,
    Network,
    EssentialWithFork,
    NetworkWithFork,
}
```

变体说明：

| 变体 | 适用场景 | 说明 |
| --- | --- | --- |
| `Essential` | 默认最小权限执行 | 仅允许核心系统调用，不允许 fork |
| `Network` | 需要网络系统调用的执行 | 在 `Essential` 基础上追加网络相关系统调用 |
| `EssentialWithFork` | shell、脚本解释器等 | 在 `Essential` 基础上允许 `fork` / `clone` |
| `NetworkWithFork` | 需要网络且会派生子进程 | 综合网络与 fork 需求 |

示例：

```rust
use mimobox_core::{SandboxConfig, SeccompProfile};

fn build_shell_config() -> SandboxConfig {
    SandboxConfig {
        seccomp_profile: SeccompProfile::Essential,
        allow_fork: true,
        ..Default::default()
    }
}
```

说明：

- Linux 后端执行前会根据 `allow_fork` 自动提升实际使用的 profile。
- macOS 与 Wasm 后端不消费该枚举进行系统调用过滤，但字段仍然保留在统一配置中。

## 3. `SandboxPool` API

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-os/src/pool.rs`

### 3.1 类型概览

```rust
pub struct PoolConfig {
    pub min_size: usize,
    pub max_size: usize,
    pub max_idle_duration: Duration,
}

pub struct PoolStats {
    pub hit_count: u64,
    pub miss_count: u64,
    pub evict_count: u64,
    pub idle_count: usize,
    pub in_use_count: usize,
}

pub enum PoolError {
    InvalidConfig { min_size: usize, max_size: usize },
    StatePoisoned,
    Sandbox(SandboxError),
}

#[derive(Clone)]
pub struct SandboxPool { /* omitted */ }

pub struct PooledSandbox { /* omitted */ }
```

### 3.2 `SandboxPool::new`

签名：

```rust
pub fn new(config: SandboxConfig, pool_config: PoolConfig) -> Result<Self, PoolError>
```

行为：

- 校验 `max_size > 0` 且 `min_size <= max_size`。
- 立即根据 `min_size` 预热池。
- 当前仅支持 Linux/macOS 的 OS 级后端。

示例：

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
            min_size: 1,
            max_size: 4,
            max_idle_duration: std::time::Duration::from_secs(30),
        },
    )?;

    assert_eq!(pool.pool_config().max_size, 4);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {}
```

### 3.3 `SandboxPool::warm`

签名：

```rust
pub fn warm(&self, target_idle_size: usize) -> Result<usize, PoolError>
```

行为：

- 把空闲池补齐到目标容量上限。
- 返回本次实际创建的沙箱数量。
- 若超出 `max_size`，多余实例会被立即销毁。

示例：

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
            min_size: 0,
            max_size: 8,
            max_idle_duration: std::time::Duration::from_secs(30),
        },
    )?;

    let created = pool.warm(4)?;
    assert!(created <= 4);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {}
```

### 3.4 `SandboxPool::acquire`

签名：

```rust
pub fn acquire(&self) -> Result<PooledSandbox, PoolError>
```

行为：

- 命中空闲实例时直接返回复用对象。
- 未命中时即时创建新的平台沙箱。
- 返回值为 `PooledSandbox`，不是裸后端对象。

示例：

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
            min_size: 1,
            max_size: 4,
            max_idle_duration: std::time::Duration::from_secs(30),
        },
    )?;

    let mut sandbox = pool.acquire()?;
    let command = if cfg!(target_os = "linux") {
        vec!["/bin/true".to_string()]
    } else {
        vec!["/usr/bin/true".to_string()]
    };
    let result = sandbox.execute(&command)?;
    assert_eq!(result.exit_code, Some(0));
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {}
```

### 3.5 `PooledSandbox` 的 release 阶段

当前版本没有显式 `release()` 方法。释放阶段通过 `Drop` 自动完成：

- `PooledSandbox` 离开作用域后会触发回收逻辑。
- 回收前会执行健康检查。
- 健康检查失败、空闲超时或容量溢出时，底层沙箱会被驱逐销毁。

示例：

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
            min_size: 1,
            max_size: 2,
            max_idle_duration: std::time::Duration::from_secs(30),
        },
    )?;

    {
        let _sandbox = pool.acquire()?;
    } // 这里通过 Drop 隐式 release

    let stats = pool.stats()?;
    assert_eq!(stats.in_use_count, 0);
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {}
```

### 3.6 `SandboxPool::stats`

签名：

```rust
pub fn stats(&self) -> Result<PoolStats, PoolError>
```

示例：

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
            min_size: 1,
            max_size: 2,
            max_idle_duration: std::time::Duration::from_secs(30),
        },
    )?;

    let stats = pool.stats()?;
    println!(
        "hit={} miss={} idle={}",
        stats.hit_count, stats.miss_count, stats.idle_count
    );
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {}
```

## 4. `WasmSandbox` API

源码位置：`/Users/showkw/dev/mimobox/crates/mimobox-wasm/src/lib.rs`

### 4.1 类型概览

```rust
pub struct WasmSandbox {
    engine: Arc<Engine>,
    config: SandboxConfig,
    cache_dir: PathBuf,
}
```

公开 API 由两部分组成：

- `Sandbox` trait 生命周期方法：`new`、`execute`、`destroy`
- 基准入口：`run_wasm_benchmark(wasm_path, iterations)`

### 4.2 `WasmSandbox::new`

示例：

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
        fs_readonly: vec![],
        fs_readwrite: vec![],
        deny_network: true,
        seccomp_profile: SeccompProfile::Essential,
        allow_fork: false,
    };

    let sandbox = WasmSandbox::new(config)?;
    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(feature = "wasm"))]
fn main() {}
```

### 4.3 `WasmSandbox::execute`

约束：

- `cmd[0]` 必须是 `.wasm` 文件绝对路径。
- 若模块同时没有导出 `_start` 和 `main`，会返回 `SandboxError::ExecutionFailed`。
- 超时由 Fuel 与 Epoch interruption 协同实现。

示例：

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
        fs_readonly: vec![],
        fs_readwrite: vec![],
        deny_network: true,
        seccomp_profile: SeccompProfile::Essential,
        allow_fork: false,
    };

    let mut sandbox = WasmSandbox::new(config)?;
    let command = vec!["/absolute/path/to/tool.wasm".to_string()];
    let result = sandbox.execute(&command)?;

    println!("exit={:?}", result.exit_code);
    println!("timed_out={}", result.timed_out);

    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(feature = "wasm"))]
fn main() {}
```

### 4.4 `WasmSandbox::destroy`

```rust
#[cfg(feature = "wasm")]
use mimobox_core::{Sandbox, SandboxConfig};
#[cfg(feature = "wasm")]
use mimobox_wasm::WasmSandbox;

#[cfg(feature = "wasm")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = WasmSandbox::new(SandboxConfig::default())?;
    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(feature = "wasm"))]
fn main() {}
```

### 4.5 `run_wasm_benchmark`

签名：

```rust
pub fn run_wasm_benchmark(
    wasm_path: &str,
    iterations: usize,
) -> Result<(), Box<dyn std::error::Error>>
```

该函数会输出：

- Engine 创建开销
- 首次执行时间（含编译）
- 冷启动分布（每轮 `new + execute`）
- 热路径分布（复用同一 `WasmSandbox`）

示例：

```rust
#[cfg(feature = "wasm")]
use mimobox_wasm::run_wasm_benchmark;

#[cfg(feature = "wasm")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_wasm_benchmark("/absolute/path/to/tool.wasm", 50)?;
    Ok(())
}

#[cfg(not(feature = "wasm"))]
fn main() {}
```

## 5. 相关源码入口

| 主题 | 路径 |
| --- | --- |
| `Sandbox` trait 与基础类型 | `/Users/showkw/dev/mimobox/crates/mimobox-core/src/sandbox.rs` |
| `SeccompProfile` | `/Users/showkw/dev/mimobox/crates/mimobox-core/src/seccomp.rs` |
| Linux/macOS 后端与预热池 | `/Users/showkw/dev/mimobox/crates/mimobox-os/src` |
| Wasm 后端 | `/Users/showkw/dev/mimobox/crates/mimobox-wasm/src/lib.rs` |
| CLI 参数和基准入口 | `/Users/showkw/dev/mimobox/crates/mimobox-cli/src/main.rs` |
