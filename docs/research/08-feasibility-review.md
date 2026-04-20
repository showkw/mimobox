# mimobox Agent Sandbox 可行性评审报告

> 评审日期：2026-04-20
> 评审范围：docs/research/00~07 全部技术文档
> 评审角色：系统架构评审官（沙箱/安全/虚拟化领域）

---

## 评审结论摘要

### 总体评价

mimobox Agent Sandbox 技术方案是一份**广度和深度兼备**的研究报告，覆盖了从 OS 级沙箱到 microVM 到 Wasm 到学术前沿的完整技术谱系。推荐采用分层混合架构（OS 级 + Wasm + microVM）的核心结论是**数据驱动的，技术方向正确**。

然而，方案存在若干需要正视的弱点：部分性能目标过于激进（缺乏自身基准测试支撑）、跨平台统一抽象的难度被低估、工期估算偏乐观、安全模型中存在共同的弱点层。方案在工程落地时需要特别注意 Windows AppContainer 的代码签名要求和 macOS Seatbelt 的弃用风险。

**总体判断：方案可行，但需要在若干关键问题上做深入验证后再全面投入。**

### 关键发现

1. **做得好的部分**：研究覆盖面广（7 个并行研究 Agent）、竞品分析更新至 2026.04 且包含多个新发布产品、Rust 生态选型论证充分、分层架构理念正确
2. **主要风险**：性能数据几乎全部引用外部来源而非自测；跨平台抽象层的实际复杂度可能比预估高出 50-100%；Phase 3 的 macOS/Windows 后端开发存在隐藏的外部依赖（代码签名、未文档化的 API 行为）
3. **关键建议**：在全面投入前，先用 4-6 周完成 Linux OS 级沙箱的 PoC（Proof of Concept），获取真实基准数据；将 Phase 3 的 Windows 后端降为可选而非核心；优先保证 Linux + macOS 两个平台的质量

### 致命问题（必须解决才能推进）

1. 所有性能目标缺乏自有基准测试验证——应先做 PoC 获取实际数据
2. Windows AppContainer 要求代码签名证书——未评估获取成本和 CI/CD 影响
3. macOS Seatbelt 已被 Apple 标记弃用——未充分评估备选方案的可行性和工期

---

## 维度 1：技术可行性

### 评估

推荐的分层架构（OS 级 + Wasm + microVM）在技术上是可行的，这一点已被 Codex、SRT、Hyperlight 等多个生产系统部分验证。各层的技术选型（Landlock/Seccomp + Wasmtime + rust-vmm）均有成熟的开源 crate 支撑。

**Linux 后端**：可行性最高。hakoniwa crate 已集成 namespace + Landlock + seccomp + cgroups，landlock crate 支持 ABI V1-V6 自动探测。OpenAI Codex 和 Anthropic SRT 的实践已验证了 Landlock + Seccomp + Bubblewrap 的组合方案。`nix`、`libseccomp`、`cgroups-rs` 等 crate 均在生产使用中。唯一需要注意的是 Landlock ABI V1 要求 Linux 5.13+，这意味着 Ubuntu 20.04 LTS（内核 5.15，但部分云镜像使用 5.4）以下无法使用 Landlock——方案中提到的"降级到纯 namespace"是合理的缓解措施。

**macOS 后端**：可行性中等。Seatbelt（sandbox-exec）是当前最实用的选择，Anthropic SRT 已在使用。但 Seatbelt 已被 Apple 标记为"旧版 API"，虽然实际短期内不会被移除（大量系统服务依赖它），但长期风险存在。备选的 Endpoint Security Framework 需要系统扩展（System Extension），这意味着：
- 必须经过 Apple 公证（Notarization）
- 需要用户在"系统设置"中手动授权
- 无法在 CI/CD 环境中自动部署

方案中未充分评估这些限制对开发和测试流程的影响。

**Windows 后端**：可行性较低。AppContainer 本身是成熟技术，但存在几个关键障碍：

1. **代码签名要求**：AppContainer 需要有效的代码签名证书才能完整使用。开发阶段可以使用自签名证书，但发布时需要购买 EV 代码签名证书（约 $200-400/年）。更关键的是，CI/CD 环境中的签名流程需要额外配置。
2. **CreateProcessInAppContainer API 的复杂性**：这个 API 的文档相对薄弱，实际行为在不同 Windows 版本上存在差异。Rust 的 `windows-rs` crate 虽然是微软官方维护，但 AppContainer 相关的 API 绑定覆盖不够完整，可能需要补充自定义绑定。
3. **Job Object 的嵌套限制**：虽然 Windows 8+ 支持 Job Object 嵌套，但在某些场景下（如沙箱进程自身创建了 Job Object）可能出现意外行为。

**Wasm 后端**：可行性高。Wasmtime 是最成熟的选择，Component Model + WIT 接口已被 Microsoft Wassette、Fermyon Spin 等项目验证。Rust 工具链（cargo-component、wit-bindgen）是所有语言中最成熟的。主要限制是 WASI 线程支持仍在标准化中，以及部分 Rust crate 不兼容 `wasm32-wasip2` target。

**microVM 后端**：可行性中等偏下。Phase 4 才实施，这是正确的决策。自研 VMM 的工程量巨大——即使复用 rust-vmm crate，仍需实现：
- Hypervisor 抽象层（KVM / HV.framework / WHPX 三套）
- 精简 VirtIO 设备模型
- 快照/恢复机制
- Guest 内核精简和 rootfs 管理

仅 KVM 后端就参考 Firecracker 约 5 万行 Rust 代码。三套 hypervisor 后端意味着 3 倍的平台特定代码。方案中 Phase 4 分配 3-4 月（4-6 PM），这个估算明显偏低——Firecracker 团队花了数年才达到生产级别。

### 发现的问题

1. **跨平台抽象的"最小公共"陷阱**：文档中提到"设计最小公共抽象 + 平台 extension trait"，但没有具体说明哪些功能会被排除在最小公共之外。实际执行中，Linux 有 seccomp（系统调用过滤）而 macOS/Windows 无等价物，这是一个**根本性的安全能力差异**。如果最小公共抽象不包含系统调用过滤，那么跨平台 API 的安全保证将是不一致的。

2. **缺少对 Apple Silicon 虚拟化的评估**：macOS 上 Hypervisor.framework 是实现 microVM 后端的唯一路径，但文档中对其限制（如不支持嵌套虚拟化、vCPU 数量限制、与沙箱策略的交互）缺乏深入分析。

3. **hakoniwa crate 的维护风险**：文档推荐 hakoniwa 作为 Linux 后端的候选基础库，但该 crate 由个人开发者维护，GitHub 星标仅约 100，社区活跃度有限。如果发现 bug 或需要新功能，响应时间可能很长。建议同时评估直接使用 landlock + libseccomp + nix crate 组合的方案。

### 建议

1. **立即启动 Linux PoC**：用 4-6 周时间实现一个最小可用的 Linux OS 级沙箱原型，获取真实的冷启动、内存开销和系统调用延迟数据。这是所有后续决策的基础。
2. **将 Windows 后端从核心路线图中降级**：Phase 3 改为"macOS 支持 + 跨平台 API 固化"，Windows 支持作为社区贡献或后续版本目标。
3. **为 macOS 后端准备 Endpoint Security 备选方案**：即使 Seatbelt 短期内不会消失，也需要在架构层面预留可替换的后端接口。
4. **评估 hakoniwa vs 直接组合 landlock+libseccomp+nix 的方案**：后者虽然代码量更大，但每个 crate 都有更强的社区支持。

### 结论：有条件通过

分层架构方向正确，各层的核心技术栈可行。但跨平台抽象的难度被低估，Windows 后端的可行性存疑，microVM 后端的工期估算不足。建议先做 Linux PoC 验证核心假设。

---

## 维度 2：性能目标可达性

### 评估

方案设定了四个阶段的性能目标。逐一分析：

**Phase 1：OS 级沙箱 <20ms 冷启动**

Bubblewrap 的 8ms 启动时间来自 Julia Evans 的基准测试，这是一个可靠的第三方数据点。但 Bubblewrap 仅做 namespace 创建，不包含 Landlock 规则集创建和 Seccomp 过滤器安装。从文档 16.1 节的系统调用序列来看，完整的沙箱创建包含约 20 个系统调用步骤（Landlock 规则集创建、规则添加、Seccomp 过滤器生成和加载、cgroup 创建和配置、clone + pivot_root 等）。

合理估算：
- namespace 创建（clone）：~2-5ms
- Landlock 规则集（取决于规则数量）：~1-3ms
- Seccomp 过滤器（取决于 BPF 程序大小）：~1-2ms
- cgroup 创建和配置：~1-2ms
- pivot_root + mount：~1-2ms
- 管道通信和同步：~1-2ms

**总计约 7-16ms**。考虑实际环境中的调度抖动和缓存冷热状态，<20ms 的目标在 Linux 上是**可达的**，但前提是：
- 预编译 Seccomp BPF 程序（参考 Firecracker 的 seccompiler 做法）
- Landlock 规则数量控制在合理范围（<100 条）
- 使用 user namespace 避免需要 root 权限

**Phase 2：Wasm <5ms 冷启动**

Wasmtime 的冷启动约 1-3ms（JIT 编译）到 <1ms（AOT），这来自多个生产系统的公开数据（Fastly、Akamai），是可靠的。但需要注意：
- 这里的"冷启动"指的是 Wasm 模块实例化时间，不包含 Engine 创建时间（约 10-30ms）
- Engine 应该是全局共享的，只需创建一次
- Component Model 的实例化可能比 Core Module 稍慢（需要额外的类型检查和适配层）

<5ms 的目标**可达**，前提是预创建 Wasmtime Engine 并启用模块缓存。

**Phase 3：预热池 <100us 热获取**

文档引用了 Hyperlight 的 <1us 热获取数据。但需要注意：
- Hyperlight 使用的是无 Guest OS 的 microVM，内存占用仅数 MB，恢复速度天然极快
- mimobox 的预热池是 OS 级进程沙箱或 Wasm 实例的预热池
- OS 级进程的"热获取"本质上是 resume 一个被 pause 的进程（SIGSTOP → SIGCONT），这涉及内核调度器的唤醒延迟，通常在 10-100us 范围
- Wasm 实例的热获取是从池中取出一个预实例化的对象，理论上接近零开销

<100us 的目标**在 Wasm 后端上可达**，在 OS 级后端上**有风险**（取决于内核调度延迟和 CPU 负载）。

**Phase 4：microVM <100ms 冷启动、<10ms 快照恢复**

Firecracker 的 125ms 冷启动是官方规范中的上限值，实际测试中通常在 60-100ms。但 Firecracker 是经过数年优化的成熟项目，mimobox 自研 VMM 很难在第一版就达到这个水平。更现实的目标是 200-500ms 冷启动。

快照恢复的 <10ms 目标来自 Firecracker 的 userfaultfd + 按需加载方案。但这个数据依赖于：
- 使用 Huge Pages
- 快照内存被操作系统缓存
- 恢复时不立即访问大部分内存页

在非理想条件下（快照需要从磁盘读取），恢复时间可能是 50-200ms。

### 发现的问题

1. **性能数据几乎全部引用外部来源**：方案中没有任何 mimobox 自身的基准测试数据。所有性能目标都建立在"其他项目做到了，所以我们也应该能做到"的逻辑上。这种推理在技术选型阶段可以接受，但在进入工程实施前，必须用 PoC 数据验证。

2. **缺乏对"冷启动"定义的精确化**：不同项目的"冷启动"测量起点和终点不同。Firecracker 测量的是从 API 调用到 /sbin/init 执行的时间；Bubblewrap 测量的是从命令执行到子进程启动的时间。mimobox 需要定义自己的测量标准，否则性能目标没有意义。

3. **忽略了预热池的资源成本**：预热池的 <100us 热获取是以常驻内存为代价的。每个预热的 OS 级沙箱进程至少占用 1-5MB（进程栈、文件描述符表、页表等），10 个预热实例就是 10-50MB。Wasm 实例的内存开销更大（5-15MB/实例）。方案中未分析池大小对总内存占用的影响。

### 建议

1. **在 PoC 中建立性能基准测试框架**：使用 criterion.rs，定义清晰的冷启动测量起点（SandboxFactory.create() 调用）和终点（execute() 首次返回）。
2. **为每个性能目标设定 P50/P95/P99**：而不是仅设定单一阈值。沙箱创建延迟的尾部分布对用户体验影响更大。
3. **分析预热池的内存-延迟权衡**：建立模型计算不同池大小下的内存占用和平均获取延迟。

### 结论：有条件通过

Phase 1 和 Phase 2 的性能目标合理可达。Phase 3 的目标在 Wasm 后端上可行，在 OS 级后端上需要验证。Phase 4 的目标偏乐观，建议首版 microVM 后端将目标放宽到 200ms 冷启动 / 50ms 快照恢复。

---

## 维度 3：工程复杂度与工期评估

### 评估

方案估算总工期 9-14 月，15-21 人月。逐一分析各 Phase：

**Phase 1（1-2 月，3-4 PM）**：估算基本合理。Sandbox trait 设计 + Linux 后端 + 预热池 + 基准测试，对 2 名 Rust 系统工程师来说是可完成的。风险点：
- hakoniwa 或 landlock crate 的 API 不如预期，需要额外适配工作
- Seccomp profile 的分级设计（参考 sandbox-rs）需要实际测试和调优
- 预热池的"暂停/恢复"机制在 OS 级沙箱上不像在 Wasm 上那么自然

**Phase 2（1-2 月，2-3 PM）**：估算偏乐观。Wasmtime 集成本身不复杂，但以下工作可能被低估：
- WASI 能力控制的实现需要深入理解 WASI Preview 2 的权限模型
- WIT 接口定义需要反复迭代（Agent 工具的接口规范不是一次性设计好的）
- cargo-component 工具链的构建流程配置（涉及交叉编译、target 配置）
- Wasm AOT 预编译缓存的失效和更新策略

**Phase 3（2-3 月，4-5 PM）**：估算严重偏低。这是整个方案中**风险最高的阶段**。

macOS Seatbelt 后端的开发可能需要 2-3 月，这包括：
- Seatbelt 策略语言的学习和测试（Apple 的官方文档非常有限，很多行为只能通过实验发现）
- .sbpl 文件的生成和验证
- 在不同 macOS 版本上的兼容性测试（macOS 12/13/14/15 的 Seatbelt 行为有差异）
- rlimit 在 macOS 上的非标准行为（如 RLIMIT_NPROC 是 per-uid 而非 per-process）

Windows AppContainer 后端的开发可能需要 3-4 月，这包括：
- AppContainer API 的 Rust 绑定编写（windows-rs 可能不覆盖所有需要的 API）
- 代码签名证书的获取和 CI/CD 集成
- Job Object 在不同 Windows 版本上的行为差异测试
- MIC (Mandatory Integrity Control) 与 AppContainer 的交互测试

跨平台测试套件的编写可能需要 1-2 月。

**合理的 Phase 3 估算应为 4-6 月**，而非 2-3 月。

**Phase 4（3-4 月，4-6 PM）**：估算严重偏低。自研 VMM 是一个庞大的工程：
- Firecracker 团队（AWS 专职）花了 2 年达到生产级别
- Cloud Hypervisor 团队（Intel 等）也在持续开发 3 年以上
- 即使只实现 KVM 后端 + 精简设备模型，也需要 6-12 月

**合理的 Phase 4 估算应为 6-12 月**，而非 3-4 月。

**修正后的总估算：18-30 月，25-40 PM**，显著高于方案中的 15-21 PM。

### 发现的问题

1. **团队技能组合未充分规划**：方案中列出了"Rust 系统工程师"、"Wasm 工程师"、"VMM 工程师"等角色，但未评估招聘难度。市场上同时精通 Rust + 虚拟化 + 安全的工程师非常稀缺。更现实的做法是培养现有工程师，但这需要额外的学习曲线时间。

2. **Phase 3 和 Phase 4 的依赖关系**：方案中各 Phase 是线性递进的，但 Phase 3（跨平台）和 Phase 4（microVM）实际上是独立的。可以考虑并行开发以缩短总工期，但需要更多的工程师。

3. **测试基础设施的建设被低估**：跨三平台的 CI/CD 矩阵（Linux x86_64/ARM64 + macOS Apple Silicon/Intel + Windows x86_64/ARM64）的建设和维护本身就是一项持续的工程投入。macOS 和 Windows 的 GitHub Actions runner 有限，可能需要自建 runner 基础设施。

### 建议

1. **重新评估工期**：将 Phase 3 扩展到 4-6 月，Phase 4 扩展到 6-12 月。总工期修正为 18-24 月。
2. **Phase 3 中将 Windows 后端改为可选**：先保证 Linux + macOS 的质量，Windows 支持作为社区贡献或 v2.0 目标。
3. **制定详细的 Phase 1 验收标准**：在 Phase 1 完成后再评估后续 Phase 的工期和可行性。

### 结论：不通过

15-21 PM 的估算显著低估了跨平台和 VMM 开发的复杂度。修正后的 25-40 PM 更接近现实。建议重新规划。

---

## 维度 4：安全模型完备性

### 评估

方案采用了分层防御架构（OS 级 + Wasm + microVM），理念正确。但需要审视各层是否存在共同的弱点。

**纵深防御的实际效果**：

分层防御只有在各层的安全边界独立时才有效。如果各层共享同一类弱点，攻击者可以一次性突破所有层。分析各层的共同弱点：

1. **所有层都依赖 Rust 编译器的正确性**：如果 Rust 编译器存在代码生成 bug（历史上发生过），导致本应隔离的内存被意外暴露，那么无论用多少层都无法防御。缓解措施是使用多个独立的验证手段（如 Wasm 的形式化验证）。

2. **所有层都依赖操作系统内核的正确性**：OS 级沙箱直接依赖内核；Wasm 运行时在用户态运行但仍然依赖内核的内存隔离；microVM 依赖内核的 KVM 实现。如果内核存在权限提升漏洞（如近年的 io_uring 漏洞系列），所有层都可能受影响。

3. **Wasm 运行时自身的漏洞风险**：Wasmtime 虽然有持续的 OSS-Fuzz 测试和形式化验证努力，但仍不是形式化验证的运行时。历史上 Wasm 运行时（包括 V8 和 Wasmtime）都曾出现过沙箱逃逸漏洞。方案中将 Wasm 作为中间层而非唯一安全边界是正确的设计。

**OS 级沙箱的进程逃逸风险**：

OS 级沙箱的逃逸风险主要来自：
- 内核漏洞（Linux 内核 CVE 中每年有多个权限提升漏洞）
- 配置错误（如 Landlock 规则不够严格、Seccomp 白名单过宽）
- 竞争条件（在 Landlock/Seccomp 应用之前的时间窗口内，子进程可能执行恶意操作）

方案中提到的"在 execve 之前应用 Landlock + Seccomp"是正确的时序，但需要特别注意 clone() 和 execve() 之间的窗口——如果子进程在 execve 之前被 ptrace attach，可能绕过某些限制。

**侧信道攻击**：

方案中**未提及侧信道攻击**，这是一个重要遗漏。在多租户场景中：
- 时序攻击：通过测量系统调用延迟推断其他沙箱的行为
- 缓存攻击：通过 L1/L2 缓存状态推断其他沙箱的数据
- 分支预测攻击：Spectre 类攻击可能跨越沙箱边界

OS 级沙箱对侧信道攻击几乎没有防护能力。microVM 提供一定的隔离（独立的页表），但共享的 L3 缓存和内存总线仍是攻击面。Wasm 的线性内存模型在理论上有更好的隔离性，但实际实现仍依赖运行时的 Spectre 缓解措施。

### 发现的问题

1. **侧信道攻击完全未考虑**：应在风险评估中增加侧信道攻击的分析，并在多租户部署指南中说明缓解措施（如核心绑定、缓存分区）。

2. **Seccomp 用户通知机制未充分讨论**：文档提到"seccomp 用户通知"作为动态策略调整的手段（Phase 4），但未分析其安全影响——seccomp 用户通知需要在沙箱外运行一个监督进程来处理被拦截的系统调用，这引入了新的攻击面（恶意沙箱可以通过大量触发通知来 DoS 监督进程）。

3. **沙箱实例间的信息泄漏**：预热池中复用的沙箱实例可能残留上一个任务的数据（环境变量、临时文件、内存内容）。方案中未描述沙箱实例在归还到池中后的清理策略。

### 建议

1. **增加侧信道攻击的风险评估**：至少覆盖时序攻击和缓存攻击，说明在不同隔离层级下的缓解措施。
2. **定义沙箱实例的清理标准**：预热池中的实例在归还时必须清理哪些状态（环境变量、临时文件、内存清零）。
3. **增加安全回归测试套件**：建立一套自动化的沙箱逃逸测试，每次代码变更后运行。

### 结论：有条件通过

分层防御的基本框架合理，但侧信道攻击的遗漏是一个重要的缺口。沙箱实例复用的清理策略需要明确定义。建议补充侧信道攻击分析和实例清理规范。

---

## 维度 5：竞争力分析准确性

### 评估

方案的竞品分析覆盖面较广，包含了 Codex、SRT、E2B、Modal、Replit、Daytona、Fly.io、Deno Sandbox、Jupyter Kernel、Hyperlight 等主要玩家。数据更新至 2026 年 4 月，时效性良好。

**遗漏的竞品**：

1. **Google GKE Sandbox（基于 gVisor）**：方案分析了 gVisor 技术（文档 02），但未将其作为直接竞品分析。GKE Sandbox 是 Google 云上的托管沙箱服务，在 K8s 生态中有重要影响。

2. **Vercel Sandbox / v0.dev**：Vercel 的 AI 代码执行环境虽然不是独立产品，但其前端代码沙箱方案与 mimobox 的目标用户（AI Agent 开发者）高度重叠。

3. **Cloudflare Workers / Durable Objects**：Cloudflare 的 V8 Isolate 方案在边缘 AI Agent 场景有直接竞争关系。方案中提到了 V8 Isolate 但未深入分析 Cloudflare 的最新产品（如 Workers AI）。

4. **WasmEdge + crun + containerd 集成方案**：CNCF 生态中的 Wasm 容器运行时方案正在快速发展，可能成为 mimobox 的替代品。

**差异化优势的验证**：

方案声称的差异化优势：

1. **跨平台本地执行**：确实成立。E2B/Modal/Replit/Daytona 都是云端方案。但需要注意，Codex 和 SRT 也支持本地执行（Linux + macOS），mimobox 增加的主要是 Windows 支持——而这个支持的工程成本很高。

2. **分层隔离**：理论上的差异化，但在实践中，多数用户只会使用 OS 级沙箱。Wasm 层的价值需要 Agent 工具生态的支持才能体现，而这是一个鸡生蛋的问题。microVM 层在本地执行场景下的价值有限（开发者通常不需要 VM 级隔离来运行自己的 Agent）。

3. **Wasm 原生支持**：这是一个真正的差异化特性。目前没有其他 Agent 沙箱提供 Wasm Component Model 集成。但需要注意 Microsoft Wassette 已经在做类似的事情（Wasm + MCP）。

4. **Rust 实现**：Codex 的 codex-rs 也是 Rust。Rust 本身不是差异化，但与 Rust Wasm 生态的无缝集成是。

**开源决策的影响**：

方案选择开源，这是一个正确的战略决策——在 Codex（部分开源）和 SRT（开源 NPM）已经存在的市场中，闭源很难获得采用。但需要考虑：
- 开源后，大型云厂商可能 fork 并集成到自己的产品中
- 开源社区的维护成本（Issue、PR Review、社区治理）需要长期投入
- 商业化路径需要与开源策略兼容（如 Open Core、企业支持、SaaS 托管版）

### 发现的问题

1. **对"本地执行"场景的市场需求缺乏分析**：方案强调"无云依赖"是优势，但当前 AI Agent 沙箱的主要使用场景（如 ChatGPT Code Interpreter、Claude Artifacts）都是云端执行。本地执行的需求主要来自安全敏感的企业和开发者工具场景，市场规模需要验证。

2. **竞品分析的深度不均**：对 Codex 和 SRT 的分析非常深入（包含源码级别的细节），但对 E2B、Daytona、Deno Sandbox 的分析停留在功能列表层面。

### 建议

1. **补充市场定位分析**：明确 mimobox 的首要目标用户是（a）AI Agent 框架开发者、（b）企业安全团队、还是（c）个人开发者。不同用户对跨平台、性能、安全的需求差异很大。
2. **深入分析 Wasm 差异化的落地路径**：制定 Agent 工具 WIT 接口的推广策略，如何吸引工具开发者使用 mimobox 的 Wasm 工具链。
3. **评估"云+本地"混合部署场景**：考虑提供可选的云端托管版，扩大潜在用户群。

### 结论：有条件通过

竞品分析覆盖面广但深度不均，差异化优势大部分成立但需要进一步验证市场需求。遗漏了几个重要的间接竞品。

---

## 维度 6：风险评估充分性

### 评估

方案的风险评估涵盖了技术风险和工程风险两大类，但存在几个被低估或遗漏的风险。

**被低估的风险**：

1. **Landlock 内核版本要求**（影响"中"，概率"中"）：方案提到"Linux 5.13+ 限制用户群"和"降级到纯 namespace"的缓解措施。但实际影响可能更大：
   - Ubuntu 20.04 LTS（大量服务器仍在使用）默认内核 5.4，不支持 Landlock
   - 即使升级到 Ubuntu 22.04（内核 5.15），也仅支持 Landlock ABI V1，缺少 V2-V6 的功能
   - 降级到"纯 namespace"意味着失去文件系统访问控制能力（这是 Landlock 的核心价值）
   - 建议：明确 Landlock 的最低 ABI 版本要求和对应的降级行为

2. **WASI 标准演进**（影响"中"，概率"高"）：方案评估为"中"概率，但实际上 WASI 从 Preview 1 到 Preview 2 已经是一次重大 Breaking Change。WASI 0.3（async 网络）可能引入更多变化。Wasmtime 的 API 也在持续演进（最近从 v14 到 v20 多个版本）。

3. **Wasm 运行时漏洞**（影响"高"，概率"中"）：方案评估为"低"概率，但历史数据不支持这个判断。V8 每年都有多个安全漏洞修复，Wasmtime 也有 CVE 记录。作为沙箱的核心安全边界，运行时漏洞的影响是致命的。

**被遗漏的风险**：

1. **Rust 编译器版本和依赖兼容性**：wasmtime、rust-vmm 等 crate 对 Rust 工具链版本有严格要求。MSRV（Minimum Supported Rust Version）的变更可能破坏用户环境。

2. **cgroup v2 可用性**：方案依赖 cgroup v2 进行资源限制，但部分环境（如 WSL2、某些 Docker-in-Docker 配置）可能不提供 cgroup v2 支持。

3. **macOS 上的 sandbox-exec SIP（系统完整性保护）交互**：在 SIP 启用的 macOS 上，某些沙箱操作可能受到额外限制。

4. **供应链安全**：mimobox 的依赖链包含约 200+ 个 Rust crate（传递依赖），任何其中一个被恶意维护者篡改都可能引入后门。方案中提到了 cargo audit 但未讨论更严格的供应链安全措施（如依赖锁定、可信源验证）。

**缓解措施的质量**：

大部分缓解措施是"泛泛而谈"级别的（如"运行时检测 + 降级"、"关注安全公告"）。这些在技术方案阶段可以接受，但在工程实施时需要转化为具体的行动计划。例如：
- "运行时检测 + 降级" → 具体实现为：在 SandboxFactory 创建时检测 Landlock ABI 版本，自动选择最高可用版本，在日志中记录降级信息
- "关注安全公告" → 具体实现为：CI 中每日运行 cargo audit，新漏洞超过 7 天未处理则阻止合并

### 建议

1. **增加供应链安全策略**：使用 cargo vet 或类似工具对直接依赖进行安全审查；锁定所有传递依赖的版本；定期更新但通过 CI 验证。
2. **将 Wasm 运行时漏洞风险从"低"提升为"中"**：并增加双层防御的具体实现方案（Wasm + OS 级双层沙箱）。
3. **为每个风险制定量化的可接受标准**：如"Landlock 降级后的文件系统隔离覆盖率不低于 80%"。

### 结论：有条件通过

主要风险已识别但部分被低估，缓解措施缺乏具体性。遗漏了供应链安全和 cgroup v2 可用性等重要风险。

---

## 维度 7：推荐方案一致性

### 评估

**推荐的混合分层架构是否是数据驱动的结论？**

是的。方案通过 7 个并行研究 Agent 深度调研了不同技术路线，然后基于性能、安全、跨平台三个维度的综合分析得出结论。数据支撑的关键推理链：

1. "不存在单一银弹方案" ← 被所有研究文档的对比数据证实
2. "OS 级最快启动" ← Bubblewrap 8ms vs Firecracker 125ms vs Wasmtime 1-3ms
3. "Wasm 最佳跨平台" ← Wasmtime 支持 Linux/macOS/Windows，其他方案均有平台限制
4. "microVM 最强隔离" ← 硬件级隔离 vs 进程级隔离，这是安全领域的共识
5. "渐进交付" ← Phase 1 即可提供可用沙箱，后续增量增强

**是否存在更优但被忽略的方案？**

有几个值得考虑的替代路径：

1. **基于 smolvm 而非自研 VMM**：smolvm 已实现跨 macOS/Linux 的 microVM，TSI 网络透明代理解决了网络配置的痛点。方案分析了 smolvm 但未充分考虑直接基于其构建 microVM 后端的选项。smolvm 的主要风险是其安全模型偏弱（VMM 和 Guest 在同一安全上下文），但这可以通过在 VMM 外部增加 OS 级沙箱来弥补。

2. **基于 Hyperlight 的预温池方案**：Hyperlight 已经实现了亚微秒级热获取和 Wasm + microVM 双层安全模型。如果 mimobox 的目标平台是 Linux（生产环境）+ macOS（开发环境），可以考虑在 Linux 上集成 Hyperlight 而非自研 VMM。

3. **纯 Wasm 方案（放弃运行任意代码的能力）**：如果 Agent 工具全部用 Wasm 实现（这在 Component Model 生态成熟后是可行的），可以完全跳过 OS 级和 microVM 后端。这将大幅降低工程复杂度，但牺牲了运行 shell 命令等能力。

**各 Phase 的优先级排序是否合理？**

基本合理，但有两个调整建议：
1. Phase 2（Wasm）应与 Phase 1（OS 级）更紧密结合——Wasm 后端的 API 设计会影响 Sandbox trait 的接口定义。建议在 Phase 1 后期就开始 Wasm 接口的原型设计。
2. Phase 5（极致优化）中的 CoW Fork 和 PKU 探索过于前沿，不应与 Phase 4 并行投入。建议将这些探索性工作作为独立的研究项目，不影响主线开发。

### 发现的问题

1. **方案的"自研 vs 复用"决策缺乏量化分析**：对于 microVM 后端，方案选择"自研 VMM（复用 rust-vmm crate）"而非"基于 Firecracker/Cloud Hypervisor/smolvm 二次开发"，但没有提供详细的比较分析。建议补充一个决策矩阵（功能覆盖度、代码量、维护成本、跨平台能力）。

2. **Phase 4 的 microVM 后端在本地执行场景下的价值不够明确**：开发者在自己机器上运行 Agent 时，通常不需要 VM 级隔离。microVM 的主要价值在多租户云端场景。如果 mimobox 的首要定位是"本地执行"，那么 Phase 4 的优先级可能应该降低。

### 建议

1. **评估基于 smolvm 或 Hyperlight 构建 microVM 后端的可行性**：可能比自研 VMM 节省 6-12 月的工期。
2. **制定"自研 vs 复用"决策矩阵**：在 Phase 3 完成后，基于实际经验评估是否值得自研 VMM。
3. **明确 microVM 后端的目标用户场景**：是本地多租户、云端部署、还是边缘计算？

### 结论：有条件通过

推荐的分层架构是数据驱动的合理结论。但"自研 VMM"的决策缺乏充分的替代方案比较。建议在投入 Phase 4 之前，重新评估基于现有项目（smolvm、Hyperlight、Cloud Hypervisor）构建的可行性。

---

## 综合评分

| 维度 | 评分(1-10) | 结论 |
|------|-----------|------|
| 技术可行性 | 7 | 有条件通过 — 核心方向正确，Windows 后端和 microVM 工期存疑 |
| 性能可达性 | 7 | 有条件通过 — Phase 1/2 目标合理，Phase 3/4 目标偏乐观 |
| 工程复杂度 | 5 | 不通过 — 15-21 PM 显著低估，修正后 25-40 PM |
| 安全完备性 | 6 | 有条件通过 — 分层防御合理，侧信道和实例清理未覆盖 |
| 竞争力分析 | 7 | 有条件通过 — 覆盖面广，深度不均，市场定位待明确 |
| 风险评估 | 6 | 有条件通过 — 主要风险已识别，部分被低估，缓解措施不够具体 |
| 方案一致性 | 7 | 有条件通过 — 数据驱动结论，自研 VMM 决策需更多论证 |
| **综合** | **6.4** | **有条件通过 — 方向正确，需要在工期、跨平台策略、VMM 选型上做重大调整** |

---

## 致命问题清单（必须解决才能推进）

1. **性能目标缺乏自有基准测试验证**：所有性能数据引用自外部项目。在投入 Phase 1 工程开发前，必须完成一个最小 PoC，获取 Linux OS 级沙箱的真实冷启动数据。如果实际数据与目标差距超过 2 倍，需要重新评估性能目标或技术选型。

2. **Windows AppContainer 的代码签名要求**：AppContainer 需要有效的代码签名证书才能完整使用。这影响开发、测试和分发的全流程。必须在 Phase 3 启动前明确：是否将 Windows 支持作为核心目标？如果是，需要提前获取签名证书并建立签名流程。

3. **macOS Seatbelt 的长期可行性**：Apple 已将 sandbox-exec 标记为弃用。虽然短期内不会移除，但 mimobox 作为长期项目需要明确备选方案。建议在 Phase 3 中预留时间调研 Endpoint Security Framework 的可行性。

4. **microVM 后端的"自研 vs 复用"决策**：自研 VMM 的工期估算（3-4 月）不现实。在 Phase 4 启动前，必须完成一个决策分析：基于 smolvm / Hyperlight / Cloud Hypervisor 构建的成本 vs 自研的成本。

---

## 重要建议清单（强烈建议采纳）

1. **将 Windows 后端从核心路线图中降级**：Phase 3 改为"macOS 支持 + 跨平台 API 固化"。Windows 支持作为社区贡献或 v2.0 目标。这将节省 3-4 月工期和大量测试成本。

2. **修正工期估算**：总估算从 15-21 PM 修正为 25-40 PM。Phase 3 从 2-3 月扩展到 4-6 月，Phase 4 从 3-4 月扩展到 6-12 月。宁可预留缓冲，也不要在中途发现工期不足。

3. **在 Phase 1 末期进行 Go/No-Go 决策**：基于 PoC 的实际性能数据和开发体验，决定是否继续后续 Phase。如果 Phase 1 的冷启动时间超过 50ms（目标的 2.5 倍），需要重新评估技术方案。

4. **增加侧信道攻击的风险分析**：在安全文档中增加对时序攻击和缓存攻击的分析，说明在不同隔离层级下的缓解措施。这对多租户部署场景尤为重要。

5. **建立沙箱实例清理规范**：定义预热池中实例归还时的状态清理标准（环境变量、临时文件、内存清零），防止实例间的信息泄漏。

6. **优先保证 Linux + macOS 的质量**：集中资源做好两个核心平台，而不是三个平台都做得勉强。Windows 可以通过 WSL2 间接支持作为过渡方案。

---

## 改进建议清单（可选但有价值）

1. **建立性能回归检测的 CI 门禁**：每次 PR 触发性能基准测试，回归超过阈值自动阻止合并。使用 criterion.rs + 自定义 benchmark harness。

2. **增加模糊测试（Fuzz Testing）计划**：对 SandboxConfig 的解析、Landlock 规则生成、Seccomp BPF 程序生成等关键路径进行 cargo-fuzz 模糊测试。

3. **制定 Agent 工具 WIT 接口的社区推广计划**：Wasm 差异化需要工具生态的支持。考虑提供模板项目、示例代码和教程降低工具开发者的入门门槛。

4. **评估 WASI 0.3 的跟进策略**：WASI 0.3 的原生 async 网络支持将显著改善 Agent 工具的网络性能。建议指派一名工程师跟踪 Wasmtime 的 WASI 0.3 进展。

5. **考虑提供沙箱模板市场**：类似 OCI 镜像仓库的概念，用户可以分享和复用沙箱配置模板（如"Python 代码执行沙箱"、"Node.js 工具沙箱"等）。

6. **增加可观测性设计**：在沙箱生命周期中加入结构化日志和指标导出（如 Prometheus metrics），便于在生产环境中监控沙箱的健康状况和性能。

7. **制定安全漏洞响应流程**：定义沙箱逃逸漏洞的披露、评估、修复和通知流程。考虑设立 Bug Bounty 计划吸引安全研究者。

8. **探索 eBPF 作为 Linux 沙箱策略引擎**：eBPF LSM 可以提供比 Seccomp 更灵活的策略定义（如基于文件路径、进程树等），值得在 Phase 5 中评估。

---

*评审完成于 2026-04-20。以上评审基于文档 00-07 的内容，未进行实际代码审查或性能测试。建议在关键决策点前进行独立的技术验证。*
