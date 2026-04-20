# Wasmtime API 与 WASI Preview 2 技术调研报告

> 调研日期：2026-04-20
> 调研目标：为 mimobox Wasm 沙箱后端提供 Wasmtime 集成方案
> Wasmtime 最新版本：v43.0.1（crates.io 已发布）/ v44.0.0（GitHub 仓库）

---

## 1. Wasmtime 最新版本和核心 API

### 1.1 版本与依赖配置

mimobox 项目推荐使用 **wasmtime v43.0.1**（crates.io 最新稳定版）。Cargo.toml 依赖配置如下：

```toml
[dependencies]
# Wasmtime 核心 — 默认启用 component-model
wasmtime = { version = "43.0.1", features = ["component-model", "cranelift"] }

# WASI Preview 2 支持 — 必须显式启用 p2 feature
wasmtime-wasi = { version = "43.0.1", features = ["p2"] }

# 错误处理
anyhow = "1"
thiserror = "2"
```

**关键说明：**

- `wasmtime` 的 `default` features 已包含 `component-model` 和 `component-model-async`，但显式声明更清晰
- `wasmtime-wasi` 的 `p2` feature **不是默认启用**的，必须显式指定
- `p2` feature 会自动依赖 `wasmtime/component-model` 和 `wasmtime/async`
- 如果不需要异步，可使用 `wasmtime_wasi::p2::add_to_linker_sync` 代替异步版本

### 1.2 Engine / Store / Module / Instance 创建流程

Wasmtime 的核心对象生命周期遵循 **Engine -> Module -> Store -> Instance** 的层次结构：

```rust
use wasmtime::*;

fn main() -> Result<()> {
    // ===== 第一层：Engine（全局共享，重量级对象） =====
    // Engine 管理编译器配置和全局状态，应在整个进程中共享
    let mut config = Config::new();
    config.wasm_component_model(true);       // 启用 Component Model
    config.consume_fuel(true);                // 启用 Fuel 消耗（防止无限循环）
    config.epoch_interruption(true);          // 启用 Epoch 中断（超时控制）
    config.max_wasm_stack(2 * 1024 * 1024);   // 限制 Wasm 栈大小为 2MB
    let engine = Engine::new(&config)?;

    // ===== 第二层：Module（编译产物，可缓存复用） =====
    // Module::from_file 会触发编译，开销较大
    // Module::deserialize 可从预编译产物加载，跳过编译步骤
    let module = Module::from_file(&engine, "sandbox_guest.wasm")?;

    // ===== 第三层：Store（每个实例一个，持有运行时状态） =====
    // Store 封装了 Wasm 实例的完整运行时状态
    let mut store = Store::new(&engine, ());

    // ===== 第四层：Linker（链接导入项） =====
    let linker = Linker::new(&engine);

    // ===== 第五层：Instance（模块的运行实例） =====
    let instance = linker.instantiate(&mut store, &module)?;

    // ===== 第六层：调用导出函数 =====
    let run_func = instance.get_typed_func::<(i32, i32), i32>(&mut store, "add")?;
    let result = run_func.call(&mut store, (5, 7))?;
    println!("5 + 7 = {}", result);

    Ok(())
}
```

**各对象职责总结：**

| 对象 | 生命周期 | 是否可复用 | 开销 |
|------|----------|------------|------|
| `Engine` | 进程级 | 全局共享 | 重：初始化编译器基础设施 |
| `Config` | 一次性 | 不可复用 | 轻：配置项集合 |
| `Module` | 进程级 | 可缓存、可序列化 | 重：需要编译 Wasm |
| `Linker` | 可复用 | 同一 Engine 下可复用 | 中：注册导入定义 |
| `Store` | 请求级 | 每个实例独立 | 轻：分配运行时状态 |
| `Instance` | 请求级 | 绑定到 Store | 轻：初始化实例数据 |

### 1.3 Linker 使用方式

Linker 用于管理 Wasm 模块的导入项，支持三种定义方式：

```rust
use wasmtime::*;

fn linker_example(engine: &Engine) -> Result<()> {
    let mut linker = Linker::new(engine);

    // 方式 1：定义单个函数导入
    linker.func_wrap("host", "log", |msg: i32| {
        println!("guest log: {}", msg);
    })?;

    // 方式 2：将一个 Instance 的导出作为另一个模块的导入
    let helper_module = Module::new(engine, "(module (func (export \"helper\") ))")?;
    let mut store = Store::new(engine, ());
    let helper_instance = linker.instantiate(&mut store, &helper_module)?;
    linker.instance(&mut store, "helper", helper_instance)?;

    // 方式 3：一次性定义整个模块（自动检测 Command/Reactor 模式）
    linker.module(&mut store, "env", &helper_module)?;

    Ok(())
}
```

### 1.4 错误处理模式

Wasmtime 使用 `anyhow::Result` 作为返回类型，配合自定义错误信息：

```rust
use wasmtime::*;
use anyhow::Context;

fn safe_call(store: &mut Store<()>, instance: &Instance) -> Result<i32> {
    let func = instance
        .get_typed_func::<(i32, i32), i32>(store, "compute")
        .context("模块中未找到 'compute' 函数")?;

    let result = func.call(store, (1, 2)).context("执行 'compute' 函数失败")?;

    // 检查 trap（Wasm 运行时异常）
    if store.get_fuel().map_or(false, |f| f == 0) {
        anyhow::bail!("Fuel 耗尽，可能存在无限循环");
    }

    Ok(result)
}
```

---

## 2. WASI Preview 2 能力控制

### 2.1 WasiCtxBuilder 核心配置

WASI Preview 2 使用 `WasiCtxBuilder` 构建上下文，默认策略为**最小权限**——所有能力默认关闭：

```rust
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, DirPerms, FilePerms};

fn create_sandbox_ctx() -> WasiCtx {
    WasiCtx::builder()
        // 命令行参数
        .arg("guest-program")
        .arg("--verbose")

        // 环境变量
        .env("HOME", "/tmp/sandbox")
        .env("PATH", "/usr/bin")

        // 标准 I/O（默认 stdin 关闭，stdout/stderr 丢弃）
        .inherit_stdio()

        // 文件系统：仅开放指定目录
        .preopened_dir(
            "/tmp/sandbox",     // 宿主机路径
            "/tmp",             // Guest 内看到的路径
            DirPerms::READ,     // 目录权限：只读
            FilePerms::READ,    // 文件权限：只读
        )
        .preopened_dir(
            "/usr",
            "/usr",
            DirPerms::READ,
            FilePerms::READ,
        )

        // 网络：默认已禁用（TCP/UDP 允许但所有地址默认拒绝）
        // 显式禁用可增加安全性
        .allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false)

        .build()
}
```

### 2.2 默认安全策略（开箱即安全）

WasiCtxBuilder 的默认配置本身就具备良好的安全基线：

| 能力 | 默认值 | 说明 |
|------|--------|------|
| stdin | 关闭 | 不可读取标准输入 |
| stdout/stderr | 丢弃 | 输出不报错但被丢弃 |
| 环境变量 | 空 | 无任何环境变量 |
| 命令行参数 | 空 | 无参数 |
| 预开放目录 | 空 | **无文件系统访问** |
| TCP | 允许但地址全拒 | 无法连接任何地址 |
| UDP | 允许但地址全拒 | 无法发送任何数据包 |
| IP 名字查找 | 禁用 | 无法进行 DNS 解析 |

这意味着 **一个不做任何配置的 WasiCtx 默认就是完全隔离的**。

### 2.3 文件系统访问控制

通过 `preopened_dir` 精确控制 Guest 可见的文件系统范围：

```rust
use wasmtime_wasi::{DirPerms, FilePerms};

// 只读访问 /tmp，读写访问工作目录
let ctx = WasiCtx::builder()
    // 只读映射
    .preopened_dir(
        "/host/data/readonly",   // 宿主机实际路径
        "/data",                  // Guest 内的虚拟路径
        DirPerms::READ,
        FilePerms::READ,
    )
    // 读写映射
    .preopened_dir(
        "/host/workspace",
        "/workspace",
        DirPerms::all(),          // READ | MUTATE
        FilePerms::all(),         // READ | WRITE
    )
    .build();
```

**安全保障机制：**
- Guest 无法通过 `..` 穿越 `preopened_dir` 的边界
- Guest 无法访问预开放目录之外的任何文件
- 虚拟路径映射提供了命名空间隔离
- 目录权限和文件权限独立控制

### 2.4 网络访问控制

```rust
use wasmtime_wasi::WasiCtxBuilder;

// 完全禁止网络（推荐用于沙箱）
let ctx = WasiCtxBuilder::new()
    .allow_tcp(false)
    .allow_udp(false)
    .allow_ip_name_lookup(false)
    .build();

// 或者使用 socket_addr_check 进行精细控制
let ctx = WasiCtxBuilder::new()
    .socket_addr_check(|addr, _usage| {
        // 只允许连接 localhost:8080
        matches!(addr, std::net::SocketAddr::V4(v4)
            if v4.ip().is_loopback() && v4.port() == 8080)
    })
    .build();
```

### 2.5 内存限制

Wasmtime 通过 `StoreLimits` 实现资源限制，包括内存上限：

```rust
use wasmtime::{Engine, Store, StoreLimitsBuilder};

struct SandboxState {
    limits: StoreLimits,
}

fn create_limited_store(engine: &Engine) -> Store<SandboxState> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(64 * 1024 * 1024)     // 内存上限 64MB
        .instances(1)                        // 最多 1 个实例
        .tables(4)                           // 最多 4 个表
        .memories(1)                         // 最多 1 个线性内存
        .build();

    let state = SandboxState { limits };
    let mut store = Store::new(engine, state);
    store.limiter(|state| &mut state.limits);
    store
}
```

### 2.6 执行时间限制

使用 Fuel 机制限制 Wasm 执行时间，防止无限循环：

```rust
use wasmtime::{Config, Engine, Store};

fn create_engine_with_limits() -> (Engine, Store<()>) {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).unwrap();

    let mut store = Store::new(&engine, ());
    // 设置 100 万单位 fuel（约等于 100 万条 Wasm 指令）
    store.set_fuel(1_000_000).unwrap();

    (engine, store)
}

fn execute_with_timeout(store: &mut Store<()>, instance: &wasmtime::Instance) -> anyhow::Result<i32> {
    let func = instance.get_typed_func::<(), i32>(store, "run")
        .map_err(|_| anyhow::anyhow!("未找到 run 函数"))?;

    match func.call(store, ()) {
        Ok(result) => Ok(result),
        Err(e) => {
            if store.get_fuel().unwrap() == 0 {
                Err(anyhow::anyhow!("执行超时：Fuel 耗尽"))
            } else {
                Err(e.into())
            }
        }
    }
}
```

---

## 3. Component Model 集成

### 3.1 WIT 接口定义语法

WIT（WebAssembly Interface Types）是 Component Model 的接口定义语言：

```wit
// mimobox-sandbox.wit
package mimobox:sandbox;

interface runner {
    /// 沙箱执行结果
    record execution-result {
        exit-code: u32,
        stdout: string,
        stderr: string,
        timed-out: bool,
    }

    /// 在沙箱中执行代码
    run: func(code: string, args: list<string>) -> execution-result;

    /// 健康检查
    ping: func() -> string;
}

world sandbox-world {
    /// 导入：沙箱运行时需要的宿主能力
    import wasi:cli/stdio@0.2.0;

    /// 导出：沙箱对外暴露的接口
    export runner;
}
```

**WIT 核心语法要素：**

| 语法 | 用途 | 示例 |
|------|------|------|
| `package` | 命名空间 | `package mimobox:sandbox;` |
| `interface` | 接口定义 | `interface runner { ... }` |
| `world` | 组件世界（导入/导出声明） | `world sandbox-world { ... }` |
| `record` | 结构体 | `record execution-result { ... }` |
| `func` | 函数签名 | `run: func(code: string) -> u32;` |
| `import` | 导入依赖 | `import wasi:cli/stdio@0.2.0;` |
| `export` | 导出接口 | `export runner;` |
| `variant` | 联合类型 | `variant result { ok(u32), err(string) }` |
| `enum` | 枚举 | `enum status { ok, error }` |
| `list<T>` | 列表 | `list<string>` |
| `option<T>` | 可选 | `option<string>` |
| `tuple<T1, T2>` | 元组 | `tuple<u32, string>` |

### 3.2 wit-bindgen 生成 Rust 绑定

在 Guest 端（Wasm 模块内），使用 `wit-bindgen` 生成绑定代码：

```rust
// src/lib.rs（Guest 端 Wasm 组件）

use wit_bindgen::generate;

// 根据本地的 WIT 文件生成绑定
generate!({
    world: "sandbox-world",
    path: "../wit",
});

// 实现生成的 Guest trait
struct SandboxRunner;

impl Guest for SandboxRunner {
    fn run(code: String, args: Vec<String>) -> ExecutionResult {
        // 执行用户代码
        ExecutionResult {
            exit_code: 0,
            stdout: format!("executed: {}", code),
            stderr: String::new(),
            timed_out: false,
        }
    }

    fn ping() -> String {
        "pong".to_string()
    }
}

// 导出组件
export!(SandboxRunner);
```

### 3.3 cargo-component 工具链

**安装：**

```bash
cargo install cargo-component
rustup target add wasm32-wasip2
```

**创建组件项目：**

```bash
# 创建库组件（reactor 模式）
cargo component new --lib sandbox-guest
cd sandbox-guest

# 目录结构
# sandbox-guest/
# ├── Cargo.toml
# ├── src/
# │   └── lib.rs
# └── wit/
#     └── world.wit
```

**组件 Cargo.toml：**

```toml
[package]
name = "sandbox-guest"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.40"

[package.metadata.component]
package = "mimobox:sandbox-guest"
target = "wasi:cli/command@0.2.0"
```

**构建与运行：**

```bash
# 编译为 Wasm 组件
cargo component build --release

# 产物路径
ls target/wasm32-wasip2/release/sandbox_guest.wasm

# 用 Wasmtime 运行
wasmtime run --wasm component-model target/wasm32-wasip2/release/sandbox_guest.wasm
```

### 3.4 在 Wasmtime 中加载和实例化 Component

Host 端（mimobox）加载 Component 的完整流程：

```rust
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

/// 组件运行时状态（实现 WasiView trait）
struct ComponentState {
    wasi_ctx: WasiCtx,
    resource_table: ResourceTable,
}

impl WasiView for ComponentState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}

fn load_component(wasm_path: &str) -> anyhow::Result<()> {
    // 1. 配置 Engine（启用 Component Model）
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_multi_memory(true);
    let engine = Engine::new(&config)?;

    // 2. 创建 Linker 并注册 WASI Preview 2
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;

    // 3. 构建 WASI 上下文（沙箱配置）
    let wasi_ctx = WasiCtx::builder()
        .inherit_stdio()
        .preopened_dir("/tmp/sandbox", "/tmp", DirPerms::READ, FilePerms::READ)
        .allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false)
        .build();

    // 4. 创建 Store
    let state = ComponentState {
        wasi_ctx,
        resource_table: ResourceTable::new(),
    };
    let mut store = Store::new(&engine, state);

    // 5. 加载 Component
    let component = Component::from_file(&engine, wasm_path)?;

    // 6. 实例化
    let instance = linker.instantiate(&mut store, &component)?;

    // 7. 调用导出函数（需要通过 bindgen! 宏生成绑定后类型安全调用）
    // 这里演示底层调用方式
    Ok(())
}
```

---

## 4. 性能关键路径

### 4.1 Engine 创建开销

Engine 初始化是整个 Wasmtime 中最重的操作，涉及编译器基础设施的初始化：

```rust
// 正确做法：全局共享 Engine
use std::sync::Arc;
use wasmtime::Engine;

// Engine 应该是全局单例
lazy_static::lazy_static! {
    static ref ENGINE: Engine = {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.cranelift_opt_level(OptLevel::Speed);
        Engine::new(&config).expect("Engine 初始化失败")
    };
}
```

**开销估计：** Engine 首次创建约 1-5ms（取决于平台和配置），应避免频繁创建。

### 4.2 Module::from_file vs Module::from_binary

| 方式 | 输入格式 | 是否编译 | 适用场景 |
|------|----------|----------|----------|
| `Module::from_file` | `.wasm` 文件路径 | 是 | 开发/调试阶段 |
| `Module::from_binary` | `&[u8]` 二进制数据 | 是 | 内存中的 Wasm 字节码 |
| `Module::new` | WAT 文本字符串 | 是 | 内联 Wasm 代码 |
| `Module::deserialize` | 预编译二进制 | **否** | 生产环境（从缓存加载） |
| `Engine::precompile_module` | `.wasm` 字节码 | 输出预编译产物 | 构建时预编译 |

### 4.3 Module 缓存策略

**核心思路：** 首次编译 Wasm 模块，序列化编译产物到磁盘，后续直接反序列化跳过编译步骤。

```rust
use wasmtime::{Engine, Module};
use std::path::Path;
use std::fs;

/// 模块缓存管理器
struct ModuleCache {
    engine: Engine,
    cache_dir: String,
}

impl ModuleCache {
    fn new(engine: Engine, cache_dir: &str) -> Self {
        fs::create_dir_all(cache_dir).ok();
        Self {
            engine,
            cache_dir: cache_dir.to_string(),
        }
    }

    /// 获取或编译模块（带缓存）
    fn get_module(&self, wasm_path: &str) -> anyhow::Result<Module> {
        let cache_path = format!("{}/{}.cwasm", self.cache_dir, self.hash(wasm_path));

        // 尝试从缓存加载
        if Path::new(&cache_path).exists() {
            let cached = fs::read(&cache_path)?;
            // SAFETY：缓存文件由本系统生成，且 Engine 配置未变
            let module = unsafe { Module::deserialize(&self.engine, &cached)? };
            return Ok(module);
        }

        // 缓存未命中，编译并缓存
        let module = Module::from_file(&self.engine, wasm_path)?;
        let serialized = module.serialize()?;
        fs::write(&cache_path, &serialized)?;

        Ok(module)
    }

    fn hash(&self, path: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}
```

### 4.4 冷启动优化技巧

```rust
use wasmtime::*;

fn optimized_cold_start() -> Result<()> {
    let mut config = Config::new();

    // 技巧 1：使用 Cranelift 优化速度（而非体积）
    config.cranelift_opt_level(OptLevel::Speed);

    // 技巧 2：启用并行编译（多核加速模块编译）
    config.parallel_compilation(true);

    // 技巧 3：禁用不需要的 Wasm 特性以减少编译开销
    // config.wasm_reference_types(false);  // 如果不需要 externref

    // 技巧 4：使用 AOT 预编译（部署前）
    // engine.precompile_module(&wasm_bytes)? -> 保存产物
    // 运行时用 Module::deserialize 加载

    // 技巧 5：减少内存分配
    // 设置合理的 max_wasm_stack
    config.max_wasm_stack(512 * 1024);  // 512KB 通常足够

    let engine = Engine::new(&config)?;

    Ok(())
}
```

### 4.5 各阶段性能基准（参考值）

| 操作 | 耗时 | 说明 |
|------|------|------|
| Engine 创建 | 1-5ms | 全局只做一次 |
| Module 编译（小型） | 0.5-5ms | 取决于 Wasm 复杂度 |
| Module 反序列化 | 0.01-0.1ms | 比编译快 10-100x |
| Store 创建 | 0.001-0.01ms | 极轻量 |
| Instance 创建 | 0.01-0.1ms | 分配线性内存和数据段 |
| 函数调用（热路径） | <0.001ms | 接近原生函数调用 |
| WASI 上下文构建 | 0.01-0.05ms | 配置各子系统 |

---

## 5. 实际代码示例

### 场景 A：最小 Wasmtime 沙箱

```rust
use anyhow::{Context, Result};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimitsBuilder, OptLevel};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// 沙箱状态：组合 WASI 上下文和资源限制
struct SandboxState {
    wasi_ctx: WasiCtx,
    limits: wasmtime::StoreLimits,
}

impl WasiView for SandboxState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut wasmtime::component::ResourceTable::new(),
        }
    }
}

/// 最小沙箱配置
const MEMORY_LIMIT: usize = 64 * 1024 * 1024;  // 64MB
const FUEL_LIMIT: u64 = 10_000_000;             // 1000 万单位

fn create_sandbox_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.cranelift_opt_level(OptLevel::Speed);
    config.consume_fuel(true);
    config.max_wasm_stack(512 * 1024);
    let engine = Engine::new(&config)?;
    Ok(engine)
}

fn run_in_sandbox(wasm_path: &str) -> Result<i32> {
    let engine = create_sandbox_engine()?;

    // 配置 Linker：注册 WASI
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |state: &mut SandboxState| {
        // 注意：preview1 使用 WasiP1Ctx，这里简化处理
        // 实际生产中建议使用 Preview 2
        state
    })?;

    // 配置 WASI 上下文：仅允许 /tmp 只读，禁止网络
    let wasi_ctx = WasiCtx::builder()
        .inherit_stdio()
        .preopened_dir("/tmp", "/tmp", DirPerms::READ, FilePerms::READ)
        .allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false)
        .env("SANDBOX", "1")
        .build();

    // 配置资源限制
    let limits = StoreLimitsBuilder::new()
        .memory_size(MEMORY_LIMIT)
        .instances(1)
        .build();

    // 创建 Store
    let state = SandboxState { wasi_ctx, limits };
    let mut store = Store::new(&engine, state);
    store.limiter(|state| &mut state.limits);
    store.set_fuel(FUEL_LIMIT)?;

    // 加载并实例化模块
    let module = Module::from_file(&engine, wasm_path)
        .context(format!("加载 Wasm 模块失败: {}", wasm_path))?;
    let instance = linker.instantiate(&mut store, &module)
        .context("Wasm 模块实例化失败")?;

    // 调用 "run" 函数
    let run_func = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .context("未找到导出函数 'run'")?;

    let result = run_func.call(&mut store, ())
        .context("执行 'run' 函数失败")?;

    // 检查是否 Fuel 耗尽
    let remaining = store.get_fuel()?;
    if remaining == 0 {
        eprintln!("警告：Fuel 耗尽，执行可能被截断");
    }

    Ok(result)
}

fn main() -> Result<()> {
    let exit_code = run_in_sandbox("guest.wasm")?;
    println!("退出码: {}", exit_code);
    Ok(())
}
```

### 场景 B：WASI Preview 2 能力控制

```rust
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

struct WasiState {
    ctx: WasiCtx,
    table: ResourceTable,
}

impl WasiView for WasiState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

fn sandbox_with_preview2(wasm_path: &str) -> anyhow::Result<()> {
    // 配置 Engine
    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_multi_memory(true);
    let engine = Engine::new(&config)?;

    // 配置 Linker（Component Model 版本）
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;

    // 配置 WASI 上下文：严格的沙箱策略
    let wasi_ctx = WasiCtx::builder()
        // 只允许读取 /usr 和 /tmp
        .preopened_dir("/usr", "/usr", DirPerms::READ, FilePerms::READ)
        .preopened_dir("/tmp/sandbox", "/tmp", DirPerms::all(), FilePerms::all())

        // 完全禁止网络
        .allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false)

        // 设置环境变量
        .env("HOME", "/tmp")
        .env("PATH", "/usr/bin")
        .env("SANDBOX_MODE", "strict")

        // 设置命令行参数
        .arg("sandbox-guest")
        .arg("--safe-mode")

        // 标准 I/O：继承宿主的
        .inherit_stdio()

        .build();

    // 创建 Store
    let state = WasiState {
        ctx: wasi_ctx,
        table: ResourceTable::new(),
    };
    let mut store = Store::new(&engine, state);

    // 加载 Component 并实例化
    let component = Component::from_file(&engine, wasm_path)?;
    let _instance = linker.instantiate(&mut store, &component)?;

    println!("沙箱实例创建成功，文件系统仅限 /usr(只读) 和 /tmp(读写)，网络已禁用");
    Ok(())
}
```

### 场景 C：Component Model 加载（带类型安全绑定）

**第一步：定义 WIT 接口**

```wit
// wit/world.wit
package mimobox:sandbox;

interface runner {
    record result {
        code: u32,
        output: string,
    }

    /// 执行代码并返回结果
    execute: func(code: string) -> result;

    /// 健康检查
    ping: func() -> string;
}

world sandbox {
    export runner;
}
```

**第二步：Host 端加载和调用**

```rust
use anyhow::Result;
use wasmtime::component::{bindgen, Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

// 使用 bindgen! 宏生成类型安全的绑定
bindgen!({
    world: "sandbox",
    path: "wit",
});

struct SandboxState {
    wasi_ctx: WasiCtx,
    resource_table: ResourceTable,
}

impl WasiView for SandboxState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}

fn run_component(wasm_path: &str) -> Result<()> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    // 注册 WASI Preview 2
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
    Sandbox::add_to_linker(&mut linker, |state: &mut SandboxState| state)?;

    // 构建 Store
    let wasi_ctx = WasiCtx::builder()
        .inherit_stdio()
        .build();
    let state = SandboxState {
        wasi_ctx,
        resource_table: ResourceTable::new(),
    };
    let mut store = Store::new(&engine, state);

    // 加载并实例化 Component
    let component = Component::from_file(&engine, wasm_path)?;
    let (bindings, _) = Sandbox::instantiate(&mut store, &component, &linker)?;

    // 类型安全地调用导出函数
    let pong = bindings.call_ping(&mut store)?;
    println!("ping -> {}", pong);  // 输出: ping -> pong

    let result = bindings.call_execute(&mut store, "print('hello')")?;
    println!("执行结果: code={}, output={}", result.code, result.output);

    Ok(())
}
```

---

## 6. mimobox 集成方案建议

### 6.1 推荐 Cargo.toml 配置

```toml
[dependencies]
# Wasmtime 核心
wasmtime = { version = "43", features = [
    "component-model",   # Component Model 支持
    "cranelift",         # Cranelift JIT 编译器
] }

# WASI Preview 2
wasmtime-wasi = { version = "43", features = ["p2"] }

# 错误处理
anyhow = "1"
thiserror = "2"

# 日志
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

### 6.2 沙箱安全清单

针对 mimobox 项目的安全需求，Wasm 沙箱必须满足以下安全检查项：

| 安全项 | Wasmtime 实现方式 | 默认状态 |
|--------|-------------------|----------|
| 文件系统隔离 | `WasiCtxBuilder::preopened_dir` | 默认无访问 |
| 网络隔离 | `allow_tcp(false)` + `allow_udp(false)` | 默认地址全拒 |
| 内存限制 | `StoreLimitsBuilder::memory_size` | 需显式配置 |
| 执行时间限制 | `Store::set_fuel` + `Config::consume_fuel` | 需显式配置 |
| 栈溢出防护 | `Config::max_wasm_stack` | 有默认值 |
| 环境变量隔离 | `WasiCtxBuilder::env` | 默认无变量 |
| 系统调用限制 | Wasm 本身无法直接进行系统调用 | 天然隔离 |

### 6.3 架构建议

```
┌─────────────────────────────────────────────┐
│                  mimobox                     │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │        WasmBackend (Sandbox trait)     │  │
│  │                                        │  │
│  │  Engine (全局共享，进程级单例)          │  │
│  │    ↓                                   │  │
│  │  ModuleCache (模块编译缓存)            │  │
│  │    ↓                                   │  │
│  │  ┌──────────────────────────────────┐  │  │
│  │  │ SandboxInstance                  │  │  │
│  │  │  Store + WasiCtx + Limits        │  │  │
│  │  │  (每个沙箱实例独立)              │  │  │
│  │  └──────────────────────────────────┘  │  │
│  └────────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

**关键设计决策：**

1. **Engine 全局共享** — 整个进程使用同一个 Engine 实例
2. **Module 缓存** — 编译产物持久化到磁盘，避免重复编译
3. **Store 独立** — 每个沙箱请求创建独立的 Store + WasiCtx
4. **预热池** — 预先创建若干个配置好的 Store，实现微秒级获取（Phase 3 目标）

---

## 7. 已知限制与风险

| 风险项 | 说明 | 缓解措施 |
|--------|------|----------|
| Module::deserialize 是 unsafe | 需要确保反序列化数据来自可信源 | 使用校验和或签名验证缓存文件 |
| Fuel 不是精确的执行时间 | Fuel 消耗与实际 CPU 时间不严格对应 | 结合 Epoch 中断作为辅助超时机制 |
| Wasm 沙箱不能完全替代 OS 沙箱 | Wasm 指令集有限，无法运行任意二进制 | 对非 Wasm 场景使用 OS 级沙箱 |
| Component Model 仍在演进 | API 可能在后续版本变更 | 锁定 Wasmtime 版本，跟踪上游更新 |
| WASI Preview 2 网络控制粒度 | `socket_addr_check` 是异步回调 | 对 mimobox 场景直接禁用所有网络 |

---

## 参考链接

- [Wasmtime 官方文档](https://docs.rs/wasmtime)
- [wasmtime-wasi API 文档](https://docs.rs/wasmtime-wasi)
- [wit-bindgen 仓库](https://github.com/bytecodealliance/wit-bindgen)
- [cargo-component 仓库](https://github.com/bytecodealliance/cargo-component)
- [Component Model 规范](https://github.com/WebAssembly/component-model)
- [WIT 接口定义语言](https://component-model.bytecodealliance.org/design/wit.html)
- [Wasmtime 示例代码](https://github.com/bytecodealliance/wasmtime/tree/main/examples)
