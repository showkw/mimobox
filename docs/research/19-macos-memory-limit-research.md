# macOS 子进程内存限制技术调研

**日期**: 2026-04-29
**目标**: 为 MimoBox macOS 沙箱后端找到可靠的内存限制方案
**当前问题**: `memory_limit_mb` 配置在 macOS 上完全不生效，仅记录 warning

---

## 1. rlimit (setrlimit RLIMIT_AS / RLIMIT_RSS / RLIMIT_DATA)

### 1.1 RLIMIT_AS

**结论: 不可用。macOS 的 XNU 内核不执行 RLIMIT_AS 限制。**

macOS 定义了 `RLIMIT_AS`（在 xnu 源码中 `RLIMIT_RSS` 是 `RLIMIT_AS` 的别名），但内核的 `setrlimit` 系统调用在处理 `RLIMIT_AS` 时 **完全不执行任何限制逻辑**。调用成功返回 0，但不产生任何效果。

证据来源:
- [avast/retdec#379](https://github.com/avast-tl/retdec/issues/379): "setrlimit() with RLIMIT_AS is broken on macOS and simply does not work"
- [StackOverflow](https://stackoverflow.com/questions/3274385/): "RLIMIT_DATA and RLIMIT_AS options to setrlimit() don't actually do anything in current versions of XNU"
- [Apple Developer Forums](https://developer.apple.com/forums/thread/702803): macOS 12.3+ (Monterey) 上 `RLIMIT_DATA` 设置低于 ~390GB 的值会返回 `EINVAL`
- Chromium bug #853873: "macOS does not respect RLIMIT_DATA or RLIMIT_AS"

### 1.2 RLIMIT_RSS

在 macOS 上 `RLIMIT_RSS` 就是 `RLIMIT_AS`（`#define RLIMIT_RSS RLIMIT_AS`），同上不生效。

### 1.3 RLIMIT_DATA

从 macOS Monterey 12.3 开始，`setrlimit(RLIMIT_DATA, ...)` 只接受大于约 390GB 的值（`rlim_cur >= 418301149184`），低于此值返回 `EINVAL`。实际上也无法用于限制内存。

### 1.4 fork+exec 继承性

即使 rlimit 可用，其行为是：子进程通过 `fork()` 继承父进程的限制，`execve()` 后限制保留。在 pre_exec 闭包中调用 `setrlimit()` 是正确的时机。但 macOS 上这些限制本身不生效，继承性无意义。

### 评估

| 维度 | 评分 |
|------|------|
| 技术可行性 | 1/5（macOS 上完全不生效） |
| 实现复杂度 | 0.5 天（如果有效的话） |
| 精度 | N/A |
| 副作用 | 无（因为不生效） |

---

## 2. Jetsam / per-process memory limiting

### 2.1 Jetsam 机制

macOS/iOS 的 jetsam（也叫 memorystatus）是内核级的内存压力管理机制，它会按优先级杀死进程。这是系统行为，**不可从用户空间编程控制**。进程无法给子进程设置 jetsam 优先级或内存上限。

### 2.2 `proc_rlimit` 系统调用

xnu 内核有 `proc_rlimit` 测试用例（`xnu/tests/proc_rlimit.c`），但这只是 `setrlimit`/`getrlimit` 的内核测试包装，不提供新的内存限制能力。

### 2.3 `ledger()` 系统调用

macOS 内核使用 ledger 机制跟踪进程资源使用（包括内存），但 `ledger()` 系统调用是 **私有 API**，只有 Apple 自身的 launchd 等系统服务可以调用。第三方应用无法使用。

### 2.4 launchd `SoftResourceLimits`

launchd plist 支持 `SoftResourceLimits` / `HardResourceLimits` 配置，但底层仍然调用 `setrlimit()`，受相同的限制。

### 评估

| 维度 | 评分 |
|------|------|
| 技术可行性 | 1/5（私有 API 或不可编程） |
| 实现复杂度 | N/A |
| 精度 | N/A |
| 副作用 | 使用私有 API 会被 App Store 拒绝 |

---

## 3. 进程监控 Watchdog（推荐方案）

### 3.1 核心思路

父进程定期采样子进程及其进程组的内存使用，超限时发送 SIGTERM/SIGKILL。

### 3.2 正确的内存指标: `phys_footprint`

**RSS 在 macOS 上是错误的指标**:
- RSS 忽略压缩内存。Apple Silicon 上内存压缩是常见操作，一个进程的实际物理足迹可能是 2GB，但压缩后 RSS 只报告 500MB
- RSS 对共享库页面重复计数（10 个进程映射同一个库，每个都计入完整 RSS）

**正确指标是 `phys_footprint`**（Activity Monitor "Memory" 列使用的值）:
- 通过 `proc_pid_rusage(pid, RUSAGE_INFO_V2, ...)` 获取 `ri_phys_footprint`
- 包含压缩页面、可清除内存、IOKit 映射
- 不需要 root 权限，同用户进程即可读取

### 3.3 进程组枚举

使用 `proc_listallpids()` + `proc_pidinfo()` 枚举系统中所有进程，过滤属于目标进程组的成员。

### 3.4 已有参考实现

**[rmk40/memlimit](https://github.com/rmk40/memlimit)**:
- 零依赖单二进制，跨平台内存限制工具
- macOS: `proc_listallpids()` + `proc_pidinfo()` 过滤进程组 + `proc_pid_rusage()` 获取 `ri_phys_footprint`
- Linux: `/proc/PID/smaps_rollup` 获取 PSS
- 每 250ms 采样一次
- 超限时 SIGTERM 进程组 → grace period → SIGKILL
- 使用 `posix_spawnp()` + `POSIX_SPAWN_SETPGROUP`

**[denispol/procguard](https://github.com/denispol/procguard)**:
- macOS 进程监控工具，支持 `--mem-limit`
- 使用 `proc_pid_rusage` 获取内存统计
- 使用 `kqueue` 实现零 CPU 等待
- 支持 CPU 节流

### 3.5 与 MimoBox 现有架构的集成

MimoBox macOS 后端（`macos.rs`）已有:
- `create_child_process_group()` — `pre_exec` 中调用 `setpgid(0, 0)` 建立进程组
- `wait_child_with_timeout()` — 带超时的 waitpid 逻辑
- SIGKILL 进程组清理（`libc::kill(-pid, libc::SIGKILL)`）

集成路径：
1. 在 `spawn_output_reader` 线程旁边增加一个 **内存监控线程**
2. 监控线程每隔 ~200ms 采样一次子进程组的 `phys_footprint` 总和
3. 超过 `memory_limit_mb` 时，设置 `AtomicBool` 标记，发送 SIGTERM → 等待 grace → SIGKILL
4. 主线程在 `wait_child_with_timeout` 返回后检查标记

### 3.6 采样频率 vs 精度权衡

| 采样间隔 | CPU 开销 | 最坏情况超额 | 适用场景 |
|----------|----------|-------------|---------|
| 50ms | 较高 | 短暂超额 | 精确限制 |
| 200ms | 低 | 中等超额 | **推荐：平衡方案** |
| 500ms | 极低 | 较大超额 | 宽松场景 |

对于沙箱场景，200ms 采样间隔足够。进程在 200ms 内能超额分配的内存量有限（通常 <100MB），且我们会在检测到超限后立即终止进程组。

### 3.7 已知局限

- **基于采样的，不是内核强制的**: 子进程在采样间隔内可能短暂超额
- **同用户限制**: `proc_pid_rusage` 只能读取同用户进程的信息
- **进程组逃逸**: 如果子进程调用 `setpgid()` 离开进程组，不会被计入。但 MimoBox 的 Seatbelt 策略未阻止 `process-fork`，所以可以配合 Seatbelt 规则进一步限制

### 评估

| 维度 | 评分 |
|------|------|
| 技术可行性 | 5/5 |
| 实现复杂度 | 2-3 天 |
| 精度 | ±50MB（取决于采样间隔和进程行为） |
| 副作用 | 极小。采样线程 CPU 占用 <0.1%，仅在超限时终止进程 |

---

## 4. Seatbelt (sandbox-exec) 内存相关规则

### 4.1 SBPL 规则能力

通过研究 Chromium V2 沙箱设计文档、OpenAI Codex 的 SBPL 策略以及 HackTricks 上的 macOS 沙箱分析，Seatbelt 的 SBPL 支持以下操作类别:

- `file-read*` / `file-write*` / `file-read-data` / `file-read-metadata`
- `process-exec` / `process-fork`
- `network*`
- `mach-lookup` / `mach-register`
- `sysctl-read`
- `signal`
- `device`

**Seatbelt 没有任何内存限制相关的规则**。不存在 `(limit process ...)` 或类似语法。Seatbelt 是一个 MACF (Mandatory Access Control Framework) 策略引擎，专注于操作访问控制（文件、网络、进程、IPC），不涉及资源配额管理。

### 4.2 Apple 私有 entitlement

一些 Apple 自身的应用通过 `com.apple.security.temporary-exception.sbpl` entitlement 使用自定义 SBPL 策略，但这些也仅涉及访问控制，不包含内存限制。

### 评估

| 维度 | 评分 |
|------|------|
| 技术可行性 | 1/5（SBPL 不支持内存限制） |
| 实现复杂度 | N/A |
| 精度 | N/A |
| 副作用 | N/A |

---

## 5. 竞品做法

### 5.1 Docker Desktop for Mac

**方案: 虚拟机级别硬限制**

Docker Desktop 在 macOS 上运行一个完整的 Linux 虚拟机:
- Apple Silicon: 使用 Apple Virtualization Framework (`Virtualization.framework`)
- Intel Mac (已弃用): 使用 HyperKit (基于 `Hypervisor.framework`)
- 新方案: Docker VMM (自研优化虚拟机管理器)

内存限制在 VM 创建时通过 Hypervisor API 设置，是硬件级别的硬限制。VM 内的 Linux 内核使用 cgroups 对容器施加更细粒度的限制。

**关键点**: Docker 的内存限制不是进程级的，而是 VM 级的。整个 Linux VM 在创建时就分配了固定大小的内存（`hv_vm_map`），物理内存无法动态增减。

### 5.2 Lima / Colima

**方案: 同 Docker，虚拟机级别**

Lima 使用 `Virtualization.framework` 或 QEMU 创建 Linux VM，`limactl start` 时通过 YAML 配置指定内存大小。Colima 基于 Lima，同样在 VM 层面限制。

### 5.3 Microsandbox (libkrun)

**方案: microVM 硬限制**

Microsandbox 使用 libkrun 创建 microVM:
- macOS: 通过 `Hypervisor.framework` (HVF)
- Linux: 通过 KVM

API: `krun_set_vm_config(ctx_id, num_vcpus, ram_mib)` 设置 VM 内存大小。

内存限制机制: libkrun 调用 `hv_vm_map` 将指定大小的内存映射给 guest。这是 Hypervisor Framework 的硬件级隔离——guest 内核只能访问映射的内存区域。超出限制的分配在 guest 内部触发 OOM，而非由宿主强制。

**关键洞察**: libkrun 的内存限制本质上是"你只有这么多内存"，而不是"你不能超过这么多"。Guest 内核负责管理这个有限池。

### 5.4 E2B

**方案: 纯云服务，不运行在本地 macOS**

E2B 的沙箱全部运行在云端（基于 Firecracker microVM），macOS 只是客户端。内存限制通过 Firecracker 的 `machine-config` 设置（`mem_size_mib`），在 VM 创建时硬性分配。

E2B 不支持本地 macOS 沙箱执行。

### 5.5 OpenAI Codex CLI

**方案: 不做内存限制**

Codex CLI 的 macOS 沙箱仅使用 Seatbelt 进行文件/网络/进程访问控制。其 `pre_main_hardening_macos()` 仅使用 `setrlimit(RLIMIT_CORE, 0)` 禁用 core dump。

有用户在 [issue#11523](https://github.com/openai/codex/issues/11523) 请求内存治理功能，Codex 团队的回复是: "I don't think this is something we can solve in the agent harness itself"，建议使用 Docker 容器。

### 5.6 竞品做法总结

| 竞品 | macOS 内存限制方案 | 级别 |
|------|-------------------|------|
| Docker Desktop | VM 硬限制 (Hypervisor.framework) | 虚拟机级 |
| Lima/Colima | VM 硬限制 (Virtualization.framework/QEMU) | 虚拟机级 |
| Microsandbox | microVM 硬限制 (libkrun + HVF) | 虚拟机级 |
| E2B | 不运行在本地 | N/A |
| OpenAI Codex | 不做内存限制 | N/A |
| memlimit (rmk40) | Watchdog 采样 (proc_pid_rusage) | 进程级 |
| procguard | Watchdog 采样 (proc_pid_rusage) | 进程级 |

**核心发现**: 所有需要可靠内存限制的方案都走 VM 路线。不使用 VM 的方案（Codex）选择不做内存限制，或使用 watchdog 采样。

---

## 6. Mach API

### 6.1 `mach_task_self()` + `task_info` 监控

通过 `task_info(mach_task_self(), TASK_VM_INFO, ...)` 获取 `task_vm_info_data_t`，其中包含 `phys_footprint` 字段。这是 Activity Monitor 获取内存信息的方式之一。

**限制**: 只能获取自己 task 的信息。要监控子进程，需要通过 `task_for_pid()` 获取子进程的 task port，但这需要：
- 同用户 + 代码签名 entitlement `com.apple.security.cs.debugger`，或
- root 权限

对于沙箱场景，使用 `proc_pid_rusage()` 是更好的选择（不需要特殊 entitlement）。

### 6.2 `mach_vm_allocate` 拦截

理论上可以通过 mach exception port 拦截内存分配，但这是：
1. 极其复杂，需要处理所有 VM 操作
2. 性能影响巨大
3. Apple 不支持第三方使用
4. 与 Seatbelt 不兼容

### 评估

| 维度 | 评分 |
|------|------|
| 技术可行性 | 2/5（监控可行，拦截不可行） |
| 实现复杂度 | 3 天（仅监控） |
| 精度 | 与 watchdog 方案相同 |
| 副作用 | 需要 debug entitlement |

---

## 7. 综合评估与推荐

### 7.1 方案对比总结

| 方案 | 可行性 | 复杂度 | 精度 | 推荐度 |
|------|--------|--------|------|--------|
| rlimit (RLIMIT_AS) | 1/5 | 0.5天 | N/A | 不推荐 |
| Jetsam / ledger | 1/5 | N/A | N/A | 不推荐 |
| Seatbelt | 1/5 | N/A | N/A | 不推荐 |
| Mach API 拦截 | 2/5 | 7天+ | N/A | 不推荐 |
| **Watchdog 采样** | **5/5** | **2-3天** | **±50MB** | **推荐（进程级方案）** |
| **VM 硬限制** | **5/5** | **已有** | **精确** | **推荐（VM 方案）** |

### 7.2 推荐方案: Watchdog 采样（进程级 OS 后端）

对于 MimoBox 的 macOS OS 级沙箱后端（`mimobox-os`），推荐 **Watchdog 采样方案**:

**理由**:
1. MimoBox macOS 后端是进程级沙箱（Seatbelt），不是 VM。在进程级别，watchdog 是唯一可行方案
2. 对于 VM 后端（`mimobox-vm`），内存限制通过 VM 配置（KVM 的 memory slot / Hypervisor.framework 的 `hv_vm_map`）已天然实现
3. OpenAI Codex 等竞品在 macOS 进程级沙箱上同样不做内存限制，实现此功能是差异化优势
4. `proc_pid_rusage()` + `ri_phys_footprint` 是经过验证的正确指标（被 memlimit、procguard、Activity Monitor 使用）

**具体实现路径**:

```
阶段 1: 内存监控线程 (2天)
├── 新建 MemoryWatcher 结构体
│   ├── 配置: memory_limit_mb, sample_interval (200ms), grace_period (1s)
│   ├── 使用 proc_listallpids() + proc_pidinfo() 枚举进程组
│   ├── 使用 proc_pid_rusage() 获取每个进程的 ri_phys_footprint
│   └── 求和后与限制比较
├── 集成到 MacOsSandbox::execute()
│   ├── spawn 后启动监控线程
│   ├── 超限时: SIGTERM 进程组 → grace → SIGKILL
│   └── 返回标志: memory_exceeded (类似 timed_out)
└── 测试
    ├── 正常进程不触发限制
    ├── 内存炸弹进程被正确终止
    └── 进程组所有成员都被计入

阶段 2: SDK 层暴露 (0.5天)
├── SandboxResult 增加 memory_exceeded: bool
├── 日志记录内存峰值
└── 文档更新
```

**关键 Rust 代码框架**:

```rust
// 使用 libc 绑定
const RUSAGE_INFO_V2: i32 = 2;
const PROC_ALLPIDS: u32 = 1;
const PROC_PIDTASKINFO: i32 = 4;

struct RUsageInfoV2 {
    ri_uuid: [u8; 16],
    ri_user_time: u64,
    ri_system_time: u64,
    ri_pkg_idle_wkups: u64,
    ri_sched_int: u64,
    ri_pageins: u64,
    ri_wired_size: u64,
    ri_resident_size: u64,     // RSS (不准确)
    ri_phys_footprint: u64,    // 正确的内存指标
    ri_proc_start_abstime: u64,
    ri_proc_exit_abstime: u64,
    ri_cpu_time: u64,
    ri_pmemory: u64,
    // ... 更多字段
}

extern "C" {
    fn proc_pid_rusage(
        pid: i32,
        flavor: i32,
        buffer: *mut RUsageInfoV2,
    ) -> i32;

    fn proc_listallpids(
        buffer: *mut libc::c_void,
        buffersize: i32,
    ) -> i32;

    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: i32,
    ) -> i32;
}
```

### 7.3 长期路线

对于需要精确内存限制的场景，长期方向是：
1. macOS VM 后端（使用 `Hypervisor.framework` 或 `Virtualization.framework`）天然支持精确内存限制
2. Wasm 后端通过 Wasmtime 的 ` ConsumingMemory` 已有限制
3. OS 级后端（Seatbelt）的 watchdog 是最佳折中方案——精度有限但实用

---

## 参考

- [memlimit - 跨平台内存限制工具](https://github.com/rmk40/memlimit)
- [procguard - macOS 进程监控工具](https://github.com/denispol/procguard)
- [Activity Monitor Anatomy - 内存指标分析](https://www.bazhenov.me/posts/activity-monitor-anatomy/)
- [Apple Developer Forums - setrlimit RLIMIT_DATA](https://developer.apple.com/forums/thread/702803)
- [avast/retdec#379 - macOS setrlimit 无效](https://github.com/avast-tl/retdec/issues/379)
- [Chromium Mac Sandbox V2 Design](https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/mac/seatbelt_sandbox_design.md)
- [libkrun 内存限制实现](https://github.com/containers/libkrun)
- [OpenAI Codex issue#11523 - 内存治理请求](https://github.com/openai/codex/issues/11523)
- [Docker Desktop VMM](https://docs.docker.com/desktop/features/vmm/)
