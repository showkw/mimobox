# mimobox 代码审查报告

**审查日期**: 2026-04-20
**审查范围**: 全部源文件 + 脚本 + CLAUDE.md
**审查人**: Code Review Agent

---

## 审查结论

**有条件通过** — 代码整体架构清晰，安全分层设计（Landlock + Seccomp + Namespaces）方向正确，但存在若干安全性、正确性和代码质量问题需要修复后方可用于任何非实验环境。部分致命问题必须在合并前修复。

---

## 致命问题（必须修复）

### 1. [安全] Seccomp 白名单过宽 — 包含多种危险系统调用

`src/seccomp.rs` 的 Essential profile 允许了以下危险系统调用：

| 系统调用 | 风险 |
|----------|------|
| `CLONE` (56) / `FORK` (57) | 允许沙箱内进程创建新进程，可能 fork 炸弹 |
| `SETUID` (105) / `SETGID` (106) | 允许改变 UID/GID，在 user namespace 内虽受限但仍不必要 |
| `SETGROUPS` (116) | 配合 SETUID/SETGID 可修改进程凭证 |
| `CHMOD` (90) / `FCHMODAT` (268) | 允许修改文件权限 |
| `SYMLINK` (88) / `SYMLINKAT` (266) | 可创建符号链接，配合 Landlock 可能实现路径遍历 |
| `KILL` (62) / `TKILL` (200) | 允许向其他进程发送信号 |
| `PRCTL` (157) | 可用于修改进程属性，潜在绕过安全机制 |
| `IOCTL` (16) | 攻击面极大，TIOCSTI 等可注入终端命令 |
| `SYSLOG` (103) | 可读取内核日志，泄露系统信息 |

**建议**: 从 Essential profile 中移除以上系统调用（除非有明确的运行时需求），并按需添加。

### 2. [安全] Seccomp BPF 跳转逻辑存在 Off-by-One 错误

`src/seccomp.rs:267-272`，BPF JEQ 指令的 `jt` 跳转偏移计算有误：

```rust
let remaining = (allowed.len() - i) as u8;
prog.push(SockFilter {
    code: BPF_JMP | BPF_JEQ | BPF_K,
    jt: remaining, // 这里应该是 remaining 个 JEQ 指令数
    jf: 0,
    k: nr,
});
```

问题：`remaining` 的值 = `allowed.len() - i`，而 `i` 是当前 JEQ 指令的索引。设共有 N 条 JEQ 指令，对于第 i 条：
- 后面还有 `N - i - 1` 条 JEQ 指令
- 之后有 1 条 KILL 指令
- 再之后有 1 条 ALLOW 指令

要从当前位置跳到 ALLOW，需要跳过 `(N - i - 1) + 1 = N - i` 条指令，即 `remaining = N - i`。

但当前代码 `remaining = N - i`，这恰好是正确的！然而，BPF 的 `jt` 是"如果匹配跳过 jt 条指令"，即从下一条指令开始计数的偏移量。

**重新分析**：对于第 i 条 JEQ（总共有 N 条）：
- 下一条是第 i+1 条 JEQ
- 需要跳到 ALLOW 指令
- 中间隔着 `(N - i - 1)` 条 JEQ + 1 条 KILL = `N - i` 条指令
- 所以 `jt = N - i = allowed.len() - i`

代码中的 `remaining = (allowed.len() - i) as u8`，这确实是 `N - i`。

**结论**：逻辑正确，但代码意图不清晰，容易造成审查混淆。建议添加详细注释说明跳转偏移的计算方式，并将变量重命名为更具描述性的名称（如 `jump_to_allow`）。

### 3. [安全] fork 到 Seccomp 应用之间存在竞态窗口

`src/linux_backend.rs:128-151` 中，中间进程 fork 后，孙进程在 `child_main` 中才应用 Seccomp（第 154 行）。从 fork 到 Seccomp 应用之间，孙进程可以执行任意系统调用。

攻击者如果能在 exec 的程序中利用这个窗口（例如通过 LD_PRELOAD 注入），可以在 Seccomp 生效前建立恶意通道。

**建议**: 使用 `SECCOMP_FILTER_FLAG_TSYNC` 或在 fork 后立即应用 Seccomp（在 Landlock 之前），将窗口最小化。或者使用 `clone3()` 的 `CLONE_INTO_CGROUP` 等新特性。

### 4. [安全] Landlock 错误被静默忽略

`src/linux_backend.rs:99-101`：

```rust
if let Err(e) = result {
    unsafe { write_error(2, &format!("Landlock error: {e}")); }
}
```

Landlock 应用失败后仅打印错误消息，子进程继续执行。这意味着如果 Landlock 规则未能应用（例如内核不支持），沙箱进程将**没有任何文件系统隔离**。

**建议**: Landlock 失败应视为致命错误，直接 `_exit`。如果需要兼容不支持 Landlock 的内核，应在 `SandboxConfig` 中提供明确的 `require_landlock: bool` 选项。

### 5. [安全] unshare 失败被静默忽略

`src/linux_backend.rs:114-121`：如果 `unshare` 完全失败（用户尝试两种 flags 组合均失败），代码仍然继续执行命令，此时进程**没有命名空间隔离**。

**建议**: 应根据配置要求决定是否继续。如果 `deny_network: true` 且 `unshare(CLONE_NEWNET)` 失败，应终止执行。

### 6. [正确性] `need_reexec` 逻辑可能导致双重 fork

`src/linux_backend.rs:124-126`：

```rust
let need_reexec = ns_result.is_ok() ||
    nix::sched::unshare(CloneFlags::CLONE_NEWPID).is_ok();
```

如果第一次 `unshare(full_flags)` 成功（`ns_result.is_ok()`），`need_reexec` 为 true，这是正确的。但如果第一次失败，代码又尝试 `nix::sched::unshare(CloneFlags::CLONE_NEWPID)`，此时 `CLONE_NEWPID` 已经包含在第一次的 `ns_flags` 中，为何第二次单独尝试会成功？

更严重的是：如果第一次 `unshare` 失败但 `CLONE_NEWNET` 和 `CLONE_NEWNS` 等已部分生效（理论上不可分割，但行为未定义），再单独尝试 `CLONE_NEWPID`，可能导致不一致的状态。

**建议**: 移除第二次 `unshare(CLONE_NEWPID)` 尝试，或者在首次失败时直接报错。

---

## 重要问题（强烈建议修复）

### 7. [正确性] 管道 fd 管理存在泄漏风险

`src/linux_backend.rs:201-202`：

```rust
std::mem::forget(stdout_read);
std::mem::forget(stderr_read);
```

通过 `mem::forget` 防止 `drop` 关闭 fd，然后在 fork 后的父子进程中分别管理。但在 **超时路径**（第 226-229 行）中：

```rust
unsafe {
    libc::close(stdout_raw);
    libc::close(stderr_raw);
}
```

在正常路径中通过 `from_raw_fd` 重新接管了 fd，由 `File::drop` 关闭。但如果 `read_to_end` 失败（第 222-223 行用 `let _` 忽略了错误），fd 仍然能正确关闭。

然而，更关键的问题是：在 fork 后的**子进程**中（第 272-275 行），关闭了 `stdout_raw` 和 `stderr_raw`，但没有关闭可能的额外继承 fd。建议使用 `close_range()` 或在 fork 后关闭所有非必要 fd（`CLOEXEC` 设置）。

### 8. [正确性] 超时轮询使用 sleep(1ms) 导致不必要的延迟和 CPU 占用

`src/linux_backend.rs:311-313`：

```rust
std::thread::sleep(Duration::from_millis(1));
```

1ms 轮询既浪费 CPU（在高频场景下），又可能导致最多 1ms 的超时精度损失。

**建议**: 使用 `waitid` with `WNOWAIT` + `timerfd` 或 `signalfd` 的方式实现精确超时，或者至少将轮询间隔调整为指数退避。

### 9. [安全] 未设置 RLIMIT 对资源消耗进行硬限制

CLAUDE.md 规则 #10 要求"所有沙箱必须设置内存上限"，但代码中 `memory_limit_mb` 字段仅存在于配置中，**从未实际使用**。

`SandboxConfig` 有 `memory_limit_mb: Some(512)` 默认值，但 `LinuxSandbox::execute` 中没有调用 `setrlimit(RLIMIT_AS, ...)` 来实际限制内存。

**建议**: 在子进程中通过 `setrlimit` 设置 `RLIMIT_AS` 和 `RLIMIT_NPROC` 等资源限制。

### 10. [安全] 未使用 CLOEXEC 标志创建管道

`src/linux_backend.rs:192-195` 使用 `pipe()` 创建管道，但未使用 `pipe2(O_CLOEXEC)`。如果在 fork 和 exec 之间有其他线程创建了新的 fd（在多线程场景中），这些 fd 可能泄漏到沙箱进程中。

虽然当前代码在 fork 后的子进程中手动关闭了 fd，但使用 `O_CLOEXEC` 是更安全的做法。

### 11. [代码质量] benchmark 中的 unwrap() 违反 CLAUDE.md 规则

CLAUDE.md 规则 #6："禁止 unwrap() 在非测试代码中使用"。

`src/main.rs:107` 和 `src/main.rs:133`：

```rust
times.sort_by(|a, b| a.partial_cmp(b).unwrap());
create_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
```

虽然 f64 的 `partial_cmp` 在存在 NaN 时返回 None，但这里数据来源是 `Duration` 转换，不会产生 NaN。不过为遵守项目规则，应使用 `total_cmp`（Rust 1.62+）或 `.unwrap_or(std::cmp::Ordering::Equal)`。

### 12. [代码质量] execvp 前的 unwrap() 可能导致子进程 panic 而非优雅退出

`src/linux_backend.rs:162-165`：

```rust
let c_cmd = CString::new(cmd[0].as_str()).unwrap();
let c_args: Vec<CString> = cmd
    .iter()
    .map(|s| CString::new(s.as_str()).unwrap())
    .collect();
```

在 fork 后的子进程中使用 `unwrap()`。如果命令包含内嵌 NUL 字节，会导致 panic。在 fork 后 panic 可能导致不一致状态。

**建议**: 使用 `unwrap_or_else` 配合 `libc::_exit` 处理错误。

### 13. [架构] main.rs 缺少条件编译保护

`src/main.rs:2`：

```rust
use mimobox::linux_backend::LinuxSandbox;
```

此导入无条件引用 Linux 后端，在 macOS/Windows 上将编译失败。应使用 `#[cfg(target_os = "linux")]` 保护。

---

## 改进建议（可选）

### 14. [安全] 建议使用 SCMP_ACT_ERRNO 替代 SCMP_ACT_KILL_THREAD

当前 Seccomp 默认动作为 `SECCOMP_RET_KILL_THREAD`，这会使进程立即被终止且无法记录审计日志。建议改为 `SECCOMP_RET_ERRNO(EPERM)` 在开发阶段，便于调试；在生产环境再切换为 KILL。或者至少添加 `SECCOMP_RET_LOG` 选项。

### 15. [性能] BPF 程序可优化为二分查找结构

当前 BPF 程序使用线性扫描（~90 条 JEQ 指令），可优化为二叉树结构的跳转，将最坏情况从 O(N) 降到 O(log N)。对 ~90 个系统调用，这可将 BPF 执行指令数从 90+ 降到 ~7。

### 16. [性能] 冷启动路径的 Landlock 规则创建可延迟

Landlock ruleset 的创建和规则添加可以在 `LinuxSandbox::new` 中预构建，仅在 fork 后的子进程中调用 `restrict_self()`，避免在 fork 的关键路径上执行 Landlock 规则构建逻辑。

### 17. [代码质量] 日志系统应使用 tracing 或 log crate

CLAUDE.md 规则 #2 要求"所有关键执行路径必须有日志输出"，当前使用自定义 `eprintln!` 宏作为日志。虽然功能上可行，但缺乏日志级别控制、结构化输出和文件输出能力。项目增长后建议迁移到 `tracing`。

### 18. [代码质量] Sandbox::destroy 无操作

`src/linux_backend.rs:281-283` 中 `destroy` 为空操作。如果未来需要清理 cgroups 或回收预热池中的沙箱，应在此处添加清理逻辑，或在文档中说明当前 destroy 为 no-op 的原因。

### 19. [测试] 缺少单元测试

项目无任何 `#[cfg(test)]` 模块或测试文件。建议至少添加：
- Seccomp BPF 程序生成的单元测试
- SandboxConfig 默认值的验证测试
- 系统调用号常量正确性的编译期检查

### 20. [脚本] scripts/setup.sh 名称不精确

`scripts/setup.sh` 实际执行的是构建（build）操作，而非环境设置（setup）。建议重命名为 `build.sh` 或在脚本内明确区分 setup/build 两个阶段。

---

## 各文件审查详情

### Cargo.toml

- edition 2024 使用正确
- 依赖版本合理：landlock 0.4、nix 0.30、thiserror 2、clap 4
- nix 的 features 选择恰当，仅启用了需要的子系统
- release profile 配置合理（LTO + panic=abort + opt-level=3）
- **问题**: 缺少 `[dev-dependencies]` 用于测试

### src/lib.rs

- 模块导出结构清晰
- `#[cfg(target_os = "linux")]` 正确隔离了 Linux 后端
- 无问题

### src/sandbox.rs

- `SandboxConfig` 默认值合理
- `SandboxError` 使用 thiserror 定义，符合项目规则
- `Sandbox` trait 设计简洁，三个方法（new/execute/destroy）覆盖核心生命周期
- **问题**: `memory_limit_mb` 字段存在但未使用（见问题 #9）
- **问题**: `deny_network` 字段存在但未使用 — 网络隔离依赖 unshare(CLONE_NEWNET)，但未检查该字段是否生效

### src/seccomp.rs

- BPF 手写实现正确但维护成本高，建议使用 libseccomp crate 或 scmp crate
- 系统调用号常量定义完整
- SAFETY 注释到位
- **致命问题**: 白名单过宽（见问题 #1）
- **问题**: 仅支持 x86_64 架构 — 在 aarch64 上所有系统调用号都不同，但代码没有任何架构检查
- **问题**: 硬编码 `SECCOMP_DATA_NR = 0` 假设 x86_64 的 `seccomp_data` 结构布局
- **问题**: `SockFprog.len` 使用 `u16`，当系统调用数超过 65535 时会溢出（理论风险，实际不会发生）

### src/linux_backend.rs

- fork/exec 流程基本正确
- 命名空间创建策略（用户命名空间 + 其他命名空间）合理
- 日志宏简洁实用
- **致命问题**: Landlock 错误被忽略（见问题 #4）
- **致命问题**: unshare 失败被忽略（见问题 #5）
- **重要问题**: 管道 fd 管理（见问题 #7）
- **重要问题**: 内存限制未实施（见问题 #9）
- **重要问题**: execvp 前的 unwrap()（见问题 #12）
- **设计问题**: 双重 fork（中间进程 + 孙进程）增加了复杂性和进程管理负担

### src/main.rs

- CLI 设计合理，使用 clap derive 模式
- "none" seccomp 参数实际使用 Network profile 而非完全禁用 — 这是合理的安全默认行为
- **问题**: 缺少 `#[cfg(target_os = "linux")]`（见问题 #13）
- **问题**: benchmark 中使用 unwrap()（见问题 #11）
- **问题**: 使用 `Box<dyn std::error::Error>` 作为返回类型过于宽泛，应使用 `SandboxError`

### scripts/

- 三个脚本均使用 `set -euo pipefail`，符合健壮性要求
- `cd "$(dirname "$0")/.."` 确保从项目根目录执行
- test.sh 和 bench.sh 通过 SSH 在远程 Linux 执行，符合 CLAUDE.md 中的开发环境要求
- **问题**: setup.sh 名称误导（见建议 #20）
- **问题**: 缺少 `scripts/run.sh` 用于本地运行

---

## 修复优先级建议

| 优先级 | 问题编号 | 描述 |
|--------|----------|------|
| P0 | #1 | Seccomp 白名单过宽 |
| P0 | #4 | Landlock 错误被忽略 |
| P0 | #5 | unshare 失败被忽略 |
| P0 | #9 | 内存限制未实施 |
| P1 | #3 | fork-seccomp 竞态窗口 |
| P1 | #6 | need_reexec 逻辑不清 |
| P1 | #12 | 子进程中的 unwrap() |
| P1 | #13 | 缺少条件编译 |
| P2 | #7 | 管道 fd 泄漏风险 |
| P2 | #8 | 轮询超时效率 |
| P2 | #10 | CLOEXEC 标志 |
| P2 | #11 | benchmark unwrap() |
| P3 | #14-20 | 改进建议 |

---

## 总结

mimobox 的安全架构设计思路正确（Landlock + Seccomp + Namespaces 三层防御），代码组织清晰，Rust 惯用法基本得当。但存在多个**安全层面的实现缺陷**：关键安全机制（Landlock、unshare）失败后静默继续执行、Seccomp 白名单过宽、资源限制未实施。这些问题在 PoC 阶段可以理解，但**在进入任何实际使用之前必须修复**。

核心改进方向：
1. **安全失败**（fail-safe）：所有安全机制应用失败必须终止执行
2. **收紧白名单**：按最小权限原则精简系统调用白名单
3. **实施资源限制**：兑现 CLAUDE.md 中对内存限制的承诺
4. **消除竞态**：缩短 fork 到安全策略应用之间的窗口

---

## 修复验证

**验证日期**: 2026-04-20
**验证人**: Code Review Agent（verification pass）

### 致命问题验证

| 编号 | 问题 | 结果 | 说明 |
|------|------|------|------|
| #1 | Seccomp 白名单过宽 | **PASS** | `essential_syscalls()` 已移除 fork/clone/setuid/setgid/setgroups/chmod/symlink/kill/tkill/prctl/ioctl/syslog/chroot/ptrace/mount/bpf 等危险系统调用。注释清晰列出了排除原因。新增 `EssentialWithFork`/`NetworkWithFork` profile 用于需要 fork 的场景（shell），fork profile 中允许 clone/fork/wait4/ioctl 但仍禁止 kill/prctl。设计合理，符合最小权限原则。 |
| #2 | BPF 跳转逻辑注释不清 | **PASS** | 变量已重命名为 `instructions_to_skip`，函数顶部添加了完整的 BPF 程序结构文档注释（含指令布局和跳转偏移计算公式），每条指令行内有简短注释说明用途。 |
| #3 | fork-seccomp 竞态窗口 | **PASS** | `child_main` 中执行顺序已调整为：fd 重定向 -> 内存限制 -> Landlock -> unshare -> **Seccomp（最后一步，exec 前立即应用）** -> execvp。注释明确标注"致命 #3 修复：Seccomp 在所有安全策略配置完成后、exec 之前立即应用"。Seccomp 作为最后一道防线在 exec 前立即设置，窗口已最小化。 |
| #4 | Landlock 错误被静默忽略 | **PASS** | `linux_backend.rs:156-162`，Landlock 失败后调用 `write_error` 记录错误信息，然后 `libc::_exit(122)` 终止子进程。注释标注"致命 #4 修复"。不再静默继续执行。 |
| #5 | unshare 失败被静默忽略 | **PASS** | `linux_backend.rs:175-186`，两次 unshare 尝试均失败后，调用 `write_error` 并 `libc::_exit(121)` 终止。注释标注"致命 #5 修复"。回退策略（先尝试 full_flags 含 CLONE_NEWUSER，失败后尝试不含 user ns）仍然保留，但最终失败会终止。 |
| #6 | need_reexec 逻辑不清 | **PASS** | 原来的 `need_reexec` 三段式逻辑（含独立的 `unshare(CLONE_NEWPID)` 二次尝试）已简化为 `if ns_result.is_ok() { fork }`。注释标注"致命 #6 修复：简化逻辑 — 仅在首次 unshare 成功时需要 reexec"。消除了不一致状态的风险。 |

### 重要问题验证

| 编号 | 问题 | 结果 | 说明 |
|------|------|------|------|
| #7 | 管道 fd 管理 | **PASS** | 子进程（`ForkResult::Child`）中明确关闭读端（`close(stdout_read_fd/stderr_read_fd)`），父进程关闭写端。超时路径中单独关闭读端。正常路径通过 `from_raw_fd` 转移所有权给 `File`，由 Rust drop 自动关闭。路径覆盖完整。 |
| #9 | memory_limit_mb 未实施 | **PASS** | 新增 `set_memory_limit()` 函数（`linux_backend.rs:73-86`），通过 `setrlimit(RLIMIT_AS)` 实施内存限制。在 `child_main` 中最早调用（步骤 1），位于 Landlock/unshare/Seccomp 之前。失败时 `_exit(124)` 终止。 |
| #10 | pipe2 + O_CLOEXEC | **PASS** | 新增 `create_pipe_cloexec()` 函数（`linux_backend.rs:30-41`），使用 `libc::pipe2(fds, O_CLOEXEC)`。注释说明"O_CLOEXEC 确保 fork+exec 后管道 fd 自动关闭"。同时新增 `PipeError` 变体到 `SandboxError`。 |
| #11 | benchmark unwrap() | **PASS** | `main.rs:114` 和 `main.rs:140` 均改为 `times.sort_by(f64::total_cmp)` 和 `create_times.sort_by(f64::total_cmp)`。`total_cmp` 是 Rust 1.62+ 稳定的方法，对 NaN 也有定义行为，消除了 unwrap。 |
| #12 | 子进程中 unwrap() | **PASS** | `linux_backend.rs:228-242`，`CString::new()` 调用改为 `.unwrap_or_else(|_| { write_error(...); libc::_exit(127); })`。注释标注"重要 #12 修复"。NUL 字节现在导致优雅退出而非 panic。 |

### 未在验证清单中但已修复的问题

| 编号 | 问题 | 结果 | 说明 |
|------|------|------|------|
| #13 | 缺少条件编译 | **PASS** | `main.rs:2` 添加了 `#[cfg(target_os = "linux")]`，`LinuxSandbox` 导入在非 Linux 平台上不会编译。 |

### 新引入问题检查

| 检查项 | 结果 | 说明 |
|--------|------|------|
| 新的安全漏洞 | **未发现** | 所有安全策略失败路径均调用 `_exit()` 终止，无静默继续执行的情况 |
| 回归风险 | **低** | `allow_fork` 机制需要显式配置（默认 false），不会意外启用 fork 权限 |
| fd 泄漏 | **未发现** | `create_pipe_cloexec` 使用 O_CLOEXEC，所有路径（正常/超时/错误）都正确关闭 fd |
| 编译正确性 | **需验证** | `rlim_max` 使用 `libc::RLIM64_INFINITY as u64`，应确认在目标平台上 `rlimit.rlim_max` 类型为 `u64`（glibc/musl 均为 `u64`，正确） |

### 验证总结

**全部 12 个验证项通过（PASS）**，修复质量高，每个修复都有对应的问题编号注释，便于追溯。

修复亮点：
1. Seccomp profile 设计为 Essential/Network + WithFork 四档，既收紧了默认权限又保留了灵活性
2. 安全策略应用顺序合理：内存限制 -> Landlock -> unshare -> Seccomp -> exec，层层递进
3. 所有 fail-safe 路径都使用不同的退出码（121-127），便于诊断失败原因

遗留事项（非本次修复范围，属于改进建议 #14-20）：
- 轮询仍使用 `sleep(1ms)`（问题 #8 未修复）
- 缺少单元测试（问题 #19）
- `destroy()` 仍为 no-op（问题 #18）
