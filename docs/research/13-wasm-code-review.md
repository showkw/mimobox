# Wasm 沙箱后端代码审查报告

> 审查日期：2026-04-20
> 审查范围：Phase 2 Wasm 后端实现
> 审查文件：
> - `src/wasm_backend.rs` -- Wasm 沙箱后端（核心）
> - `Cargo.toml` -- 依赖更新
> - `src/lib.rs` -- 模块导出
> - `src/main.rs` -- CLI 集成
> - `src/sandbox.rs` -- Sandbox trait 定义（参考）

---

## 总体评价

Wasm 后端整体实现思路清晰，正确地采用了 Engine 全局共享 + Module 缓存 + Store 独立创建的架构模式。代码注释充分，模块职责划分合理，与 LinuxSandbox 的 API 一致性良好。但存在 **1 个致命问题（内存限制未实现）**、**3 个重要问题** 和若干改进建议，需要在合入主干前修复。

---

## 审查发现

### FATAL-01: memory_limit_mb 配置未实际生效

```
[严重级别] FATAL
[文件] src/wasm_backend.rs
[行号] 182-201, 238
[标题] SandboxConfig.memory_limit_mb 配置被读取但未应用到 Wasm 运行时
```

**描述：**

`WasmSandbox::new()` 中仅将 `memory_limit_mb` 用于日志打印，从未实际配置 Wasmtime 的内存限制。Wasmtime 的内存限制需要通过 `StoreLimitsBuilder` 配合 `store.limiter()` 回调实现，当前代码完全没有这一层。

虽然 Wasm 线性内存默认上限为 4GB（32 位），且 Wasmtime 本身有一定保护，但这不符合项目强制性规则第 10 条「所有沙箱必须设置内存上限」，也与 Linux 后端（通过 setrlimit 实现）的行为不一致。

**风险：**
- 恶意或缺陷 Wasm 模块可通过 `memory.grow` 消耗大量宿主内存
- 与项目安全性目标不一致：64MB 限制在文档中被明确声明，但实际未生效
- 不同后端行为不一致，违反 Sandbox trait 的统一契约

**建议修复：**

将 Store 的 data type 从 `WasiP1Ctx` 改为包含 `WasiP1Ctx` 和 `StoreLimits` 的组合结构体，通过 `store.limiter()` 回调设置内存限制：

```rust
/// 沙箱 Store 状态：组合 WASI 上下文和资源限制
struct WasmState {
    wasi: WasiP1Ctx,
    limits: wasmtime::StoreLimits,
}

// 在 execute() 中构建 Store 时：
let limits = wasmtime::StoreLimitsBuilder::new()
    .memory_size(memory_limit_bytes)
    .instances(1)
    .memories(1)
    .build();
let state = WasmState { wasi: wasi_ctx, limits };
let mut store = Store::new(&self.engine, state);
store.limiter(|state| &mut state.limits);
```

同时需要调整 Linker 的闭包签名，从 `|cx| cx` 改为 `|state| &mut state.wasi`。

---

### IMPORTANT-01: timeout_secs 配置未实际生效

```
[严重级别] IMPORTANT
[文件] src/wasm_backend.rs
[行号] 39, 240
[标题] SandboxConfig.timeout_secs 被忽略，使用硬编码的 fuel 上限替代
```

**描述：**

`SandboxConfig.timeout_secs` 在 WasmSandbox 中完全未使用。当前用硬编码的 `DEFAULT_FUEL_LIMIT`（1000 万 fuel 单位）作为唯一的超时机制。Fuel 与实际执行时间没有精确的线性映射关系——1000 万 fuel 在不同模块上的实际耗时差异可能很大（简单的计算密集型代码 vs 包含大量 WASI 调用的 I/O 密集型代码）。

Fuel 仅在 Wasm 纯指令执行时消耗，WASI I/O 操作（如文件读写）期间的等待时间不计入 fuel。这意味着一个大量做 I/O 操作的模块可能在远超预期的时间内完成，而 fuel 不会耗尽。

**风险：**
- 用户设置 `timeout_secs: Some(5)` 期望 5 秒超时，但实际行为与此无关
- I/O 密集型 Wasm 模块可能长时间运行而不触发 fuel 耗尽
- 与 Linux 后端的超时行为不一致

**建议修复：**

实现 timeout_secs 到 fuel 上限的动态映射，或引入 `epoch_interruption` 作为辅助超时机制。至少应做到：

1. 根据 `timeout_secs` 动态计算 fuel 上限（粗略映射，如 1 秒约 100 万 fuel）
2. 在 execute() 开始时记录时间戳，结束后检查实际耗时是否超过 timeout_secs
3. 长期方案：启用 `epoch_interruption`，配合后台线程定期 bump epoch 实现真正的超时控制

---

### IMPORTANT-02: Module 缓存机制存在竞态条件和安全隐患

```
[严重级别] IMPORTANT
[文件] src/wasm_backend.rs
[行号] 54-117
[标题] path_hash 函数的缓存策略有竞态条件和路径冲突风险
```

**描述：**

`path_hash()` 函数使用 `DefaultHasher`（基于 SipHash）对路径 + 修改时间做哈希作为缓存键。存在以下问题：

1. **竞态条件**：在检查缓存存在 (`cache_path.exists()`) 和读取缓存之间，文件可能被其他进程删除或替换（TOCTOU 问题）
2. **哈希冲突**：`DefaultHasher` 是 64 位哈希，不同路径可能产生相同哈希（概率低但非零）
3. **缓存目录固定为全局临时目录**：`std::env::temp_dir().join("mimobox-wasm-cache")`，不同用户的 mimobox 实例会共享缓存目录，可能导致权限问题和缓存污染
4. **缓存清理缺失**：没有缓存大小上限和清理机制，长时间运行可能导致磁盘占用持续增长
5. **不安全路径拼接**：`format!("{:x}.cwasm", hash)` 中的哈希值虽然不包含路径分隔符，但未做防御性检查

**风险：**
- 并发场景下缓存文件被破坏，导致反序列化失败（已有 fallback 处理，但增加了日志噪音）
- 缓存目录无隔离，可能被其他用户恶意替换缓存文件
- 磁盘空间持续增长无回收

**建议修复：**

1. 将缓存目录改为用户专属路径（如 `~/.cache/mimobox/wasm/`）
2. 在反序列化失败时增加完整性校验（如存储文件大小，读取后比对）
3. 增加缓存清理机制（如 LRU 或基于时间的过期）
4. 考虑使用 SHA-256 替代 DefaultHasher 降低碰撞风险

---

### IMPORTANT-03: stdout/stderr 缓冲区无大小上限防护

```
[严重级别] IMPORTANT
[文件] src/wasm_backend.rs
[行号] 42, 223-226
[标题] OUTPUT_BUFFER_CAPACITY 是初始容量而非上限，输出可能无限增长
```

**描述：**

`MemoryOutputPipe::new(OUTPUT_BUFFER_CAPACITY)` 中的 `OUTPUT_BUFFER_CAPACITY`（1MB）是缓冲区的**初始容量**，不是内存使用上限。当 Wasm 模块输出超过 1MB 时，`MemoryOutputPipe` 内部的 `BytesMut` 会自动扩容，理论上可增长到可用内存上限。

在 LinuxSandbox 中，输出通过管道读取，受管道缓冲区（64KB）和 `read_to_end()` 的实际数据量限制。但在 Wasm 沙箱中，输出直接写入内存，恶意模块可通过大量输出耗尽宿主内存。

**风险：**
- 恶意 Wasm 模块通过无限 `print` 循环在 fuel 耗尽前消耗大量宿主内存
- 1000 万 fuel 足够执行数百万次 `write()` 调用，每次写入可产生可观数据量

**建议修复：**

在读取 `stdout_reader.contents()` / `stderr_reader.contents()` 后，检查总输出大小是否超过合理上限（如 10MB），超过则截断并在 stderr 中追加警告。或者在 execute() 完成后、返回前检查并限制输出大小。

---

### MINOR-01: WASI 文件系统配置忽略路径不存在的静默失败

```
[严重级别] MINOR
[文件] src/wasm_backend.rs
[行号] 160-173
[标题] preopened_dir 配置中路径不存在时静默忽略，用 let _ 丢弃错误
```

**描述：**

```rust
if path.exists() {
    let _ = builder.preopened_dir(path, path_str, DirPerms::READ, FilePerms::READ);
}
```

两个问题：
1. 路径不存在时静默跳过，不记录任何日志，用户可能不知道配置的路径未生效
2. `preopened_dir` 的错误（如权限不足）被 `let _` 丢弃

**风险：**
- 安全配置被静默忽略，用户可能误以为文件系统隔离已按预期工作
- 调试困难，问题发生时无日志可追踪

**建议修复：**

对路径不存在和 `preopened_dir` 调用失败都记录 warn 级别日志：

```rust
for path in &config.fs_readonly {
    if let Some(path_str) = path.to_str() {
        if path.exists() {
            if let Err(e) = builder.preopened_dir(path, path_str, DirPerms::READ, FilePerms::READ) {
                log_warn!("开放只读目录失败 {:?}: {}", path, e);
            }
        } else {
            log_warn!("只读路径不存在: {:?}", path);
        }
    }
}
```

---

### MINOR-02: 模块缓存使用 get_cached_module 自由函数而非 WasmSandbox 方法

```
[严重级别] MINOR
[文件] src/wasm_backend.rs
[行号] 71-117
[标题] get_cached_module 作为自由函数而非 WasmSandbox 的方法，限制了未来扩展
```

**描述：**

`get_cached_module` 是一个自由函数，接收 `engine` 和 `cache_dir` 作为参数。由于它不属于 `WasmSandbox`，未来如果要：
- 添加内存缓存层（避免磁盘 I/O）
- 在缓存命中/未命中时更新统计信息
- 实现缓存清理策略

都需要修改函数签名或添加全局状态。

**建议：**
考虑将 `get_cached_module` 改为 `WasmSandbox` 的方法（`&self`），这样可以直接访问 `self.engine` 和 `self.cache_dir`，也为后续扩展预留了空间。

---

### MINOR-03: 调用 _start 和 main 函数时的退出码处理存在语义模糊

```
[严重级别] MINOR
[文件] src/wasm_backend.rs
[行号] 252-301
[标题] 非 WASI 模块调用 main() 函数时，退出码的语义与 WASI Command 模式不一致
```

**描述：**

当模块没有 `_start` 函数时，代码尝试查找 `main` 函数（签名为 `() -> i32`），并将其返回值作为退出码。但 C/C++ 的 main 函数签名是 `(int, char**) -> int`，而非 `() -> i32`。这段代码能工作的场景仅限于手动导出 `main() -> i32` 的 Wasm 模块，覆盖面很有限。

此外，当 `_start` 存在但执行出错且既不是 I32Exit 也不是 fuel 耗尽时，退出码硬编码为 `Some(1)`，这可能不是模块的真实意图。

**建议：**
- 对 `main` 函数的 fallback 增加日志说明其局限性
- 非零退出时考虑返回 `None` 而非硬编码 `Some(1)`，让调用方知道退出码不可靠
- 或者在找不到 `_start` 时直接报错，要求用户使用符合 WASI Command 规范的模块

---

### MINOR-04: Cargo.toml 中 anyhow 依赖被引入但未在 wasm_backend.rs 中使用

```
[严重级别] MINOR
[文件] Cargo.toml:24, src/wasm_backend.rs
[标题] anyhow 作为 wasm feature 的依赖被引入，但 wasm_backend.rs 使用 thiserror 而非 anyhow
```

**描述：**

Cargo.toml 的 `wasm` feature 包含了 `anyhow` 依赖，但 `wasm_backend.rs` 中所有错误处理都通过 `SandboxError`（基于 thiserror）完成，没有任何地方使用 `anyhow`。虽然 wasmtime 内部使用 anyhow，wasmtime 的错误类型已经通过 `.map_err(|e| SandboxError::...)` 转换，anyhow 依赖是多余的。

**建议：**
- 如果 wasmtime 的 Error 类型不需要 anyhow 来 downcast，可以从 wasm feature 中移除 anyhow
- 如果是为了未来扩展保留，在代码中添加注释说明

---

### MINOR-05: 日志宏使用 eprintln! 而非结构化日志框架

```
[严重级别] MINOR
[文件] src/wasm_backend.rs
[行号] 26-36
[标题] 日志通过 eprintln! 实现，与项目 CLAUDE.md 中「所有关键执行路径必须有日志输出」的要求部分匹配，但缺乏结构化
```

**描述：**

`log_info!` 和 `log_warn!` 宏使用 `eprintln!` 输出日志。这与 Linux 后端的日志方式一致（也用 `eprintln!`），保持了项目内部的一致性。但 eprintln! 的输出缺乏时间戳、日志级别过滤、文件输出等能力，不利于生产环境的问题排查。

**风险：**
- 生产环境日志无法按级别过滤
- 无时间戳，难以分析性能问题
- 无文件输出，与 CLAUDE.md 中「必须配置 Logger with File Output」的要求不完全匹配

**建议：**
这是项目整体的技术债，非 Wasm 后端独有。建议在后续统一引入 `tracing` / `log` 框架，此处仅标记为已知问题。

---

### MINOR-06: benchmark 函数中的 unwrap 和 expect

```
[严重级别] MINOR
[文件] src/wasm_backend.rs
[行号] 371-490
[标题] run_wasm_benchmark 函数中多处使用 ? 和 expect，属于合理用法但值得记录
```

**描述：**

`run_wasm_benchmark` 是公开的基准测试函数，返回 `Result<(), Box<dyn std::error::Error>>`。函数内部使用 `?` 传播错误，`expect()` 仅用于 `WasmSandbox::new` 的结果（这在测试上下文中是可接受的）。

**评价：**
这是合理的。基准测试函数与生产代码的错误处理标准不同，当前实现没有问题。

---

### MINOR-07: Wasm 模块文件大小未做预检查

```
[严重级别] MINOR
[文件] src/wasm_backend.rs
[行号] 210-219
[标题] 加载 Wasm 模块前未检查文件大小，恶意超大文件可能消耗大量编译内存
```

**描述：**

`execute()` 仅检查文件是否存在，未检查文件大小。Wasmtime 在编译时会将整个模块加载到内存，一个几 GB 的恶意文件可能导致宿主进程 OOM。

**建议：**
在调用 `get_cached_module` 前检查文件大小是否超过合理上限（如 100MB），超过则直接拒绝：

```rust
if let Ok(meta) = std::fs::metadata(wasm_path) {
    const MAX_WASM_SIZE: u64 = 100 * 1024 * 1024; // 100MB
    if meta.len() > MAX_WASM_SIZE {
        return Err(SandboxError::ExecutionFailed(
            format!("Wasm 文件过大: {} bytes (上限 {} bytes)", meta.len(), MAX_WASM_SIZE)
        ));
    }
}
```

---

## 架构与设计评价

### 优点

1. **Sandbox trait 实现完整**：`new` / `execute` / `destroy` 三个方法均正确实现，与 LinuxSandbox 的 API 契约一致
2. **Engine 共享设计合理**：通过 `Arc<Engine>` 实现 Engine 跨多次 execute 复用，避免了 Engine 重复创建的开销
3. **Module 缓存策略有价值**：基于路径哈希 + 修改时间的缓存策略能显著减少重复编译开销
4. **WASI Preview 1 选择正确**：当前 WASI Preview 1（`p1`）比 Preview 2 的生态更成熟，大多数现有 Wasm 工具链支持更好
5. **feature flag 使用正确**：`#[cfg(feature = "wasm")]` 隔离了 Wasm 相关代码，非 Wasm 构建不受影响
6. **错误处理规范**：所有错误通过 `SandboxError` 统一返回，使用 `map_err` 转换 Wasmtime 错误
7. **I32Exit 退出码处理**：`find_exit_code` 函数通过多层 downcast + 字符串 fallback 处理退出码提取，覆盖了 Wasmtime 不同版本的错误包装方式
8. **unsafe 代码有 SAFETY 注释**：`Module::deserialize` 的 unsafe 调用有充分的 SAFETY 注释说明（第 84-86 行）
9. **fuel 耗尽特殊处理**：检测到 fuel 耗尽时返回 `timed_out: true`，与 Linux 后端的超时语义一致

### 不足

1. **Store data type 设计**：直接使用 `WasiP1Ctx` 作为 Store data type，导致无法通过 `store.limiter()` 设置资源限制。这是一个架构设计层面的限制，需要重构 Store data type 才能解决
2. **WASI 网络控制**：注释说明了 WASI 默认禁止网络，但未在代码中显式调用 `allow_tcp(false)` 等 API。虽然功能等价，但显式调用更安全、更清晰
3. **destroy 方法为空操作**：与 Linux 后端一致（Linux 的 destroy 也是空操作），但如果未来需要清理缓存或释放资源，需要在 trait 层面增加 `Drop` 约束

---

## 安全性审查总结

| 安全检查项 | 状态 | 说明 |
|-----------|------|------|
| 文件系统隔离 | PASS | 通过 `preopened_dir` 限制，默认无访问 |
| 网络隔离 | PASS | WASI 默认禁止网络（建议显式调用） |
| 内存限制 | **FAIL** | `memory_limit_mb` 未实际生效（FATAL-01） |
| 执行时间限制 | PARTIAL | Fuel 机制有效，但与 timeout_secs 配置脱钩（IMPORTANT-01） |
| 栈溢出防护 | PASS | `max_wasm_stack(512KB)` 已配置 |
| 环境变量隔离 | PASS | 仅设置最小必要环境变量 |
| 系统调用限制 | PASS | Wasm 天然无法直接进行系统调用 |
| stdout/stderr 安全 | PARTIAL | 捕获机制正确，但输出大小无上限（IMPORTANT-03） |
| 模块加载安全 | PARTIAL | 无文件大小预检查（MINOR-07） |
| unsafe 审计 | PASS | 唯一的 unsafe 调用有 SAFETY 注释 |

---

## 与 LinuxSandbox 的 API 一致性对比

| 行为 | LinuxSandbox | WasmSandbox | 一致性 |
|------|-------------|-------------|--------|
| 空命令处理 | 返回 ExecutionFailed | 返回 ExecutionFailed | 一致 |
| 文件不存在处理 | N/A（由 execvp 报错） | 返回 ExecutionFailed | 合理差异 |
| memory_limit_mb | setrlimit(RLIMIT_AS) 生效 | **未生效** | **不一致** |
| timeout_secs | WNOHANG 轮询 + SIGKILL | Fuel 机制（硬编码 1000 万） | **不一致** |
| deny_network | CLONE_NEWNET 命名空间 | WASI 默认禁止 | 功能等价 |
| 文件系统隔离 | Landlock | preopened_dir | 功能等价 |
| stdout/stderr | pipe 捕获 | MemoryOutputPipe | 功能等价 |
| 超时标记 | timed_out: true | timed_out: true | 一致 |
| destroy | 空操作 | 空操作 | 一致 |

---

## 代码质量检查

| 检查项 | 状态 |
|--------|------|
| 非测试代码中无 unwrap() | PASS |
| unsafe 有 SAFETY 注释 | PASS |
| 使用 thiserror 定义错误类型 | PASS |
| 文件头模块级文档注释 | PASS |
| 关键函数有文档注释 | PASS |
| 无 hardcoded 密码/密钥 | PASS |
| feature flag 正确使用 | PASS |
| 测试覆盖基本场景 | PASS（创建、空命令、文件不存在、销毁） |

---

## 需修复问题清单

### 必须修复（合入主干前）

| 编号 | 严重级别 | 问题 | 建议优先级 |
|------|---------|------|-----------|
| FATAL-01 | FATAL | memory_limit_mb 未生效 | P0 -- 阻断性 |
| IMPORTANT-01 | IMPORTANT | timeout_secs 未生效 | P1 -- 高优先级 |

### 应当修复（下一个迭代）

| 编号 | 严重级别 | 问题 | 建议优先级 |
|------|---------|------|-----------|
| IMPORTANT-02 | IMPORTANT | Module 缓存竞态条件和安全隐患 | P2 |
| IMPORTANT-03 | IMPORTANT | stdout/stderr 输出无大小上限 | P2 |
| MINOR-01 | MINOR | WASI 文件系统配置静默失败 | P3 |
| MINOR-07 | MINOR | Wasm 模块文件大小未预检查 | P3 |

### 建议改进（后续优化）

| 编号 | 严重级别 | 问题 |
|------|---------|------|
| MINOR-02 | MINOR | get_cached_module 设计改进 |
| MINOR-03 | MINOR | 非 WASI 模块退出码语义 |
| MINOR-04 | MINOR | 移除未使用的 anyhow 依赖 |
| MINOR-05 | MINOR | 结构化日志框架 |

---

## 附录：审查过程中的参考依据

- 项目强制性规则（CLAUDE.md）：第 6/7/9/10 条
- 技术调研报告：`docs/research/11-wasmtime-api-research.md`（StoreLimitsBuilder 方案）
- Wasmtime 官方文档：`Store::limiter()` / `StoreLimitsBuilder` API
- Linux 后端实现：`src/linux_backend.rs`（API 一致性参考）
