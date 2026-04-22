结论先说：这组数据不是“凭空编的”，但当前展示方式存在明显包装，不能直接当作严谨的对外性能宣传材料使用。

最明显的 5 个问题

1. microVM 冷启动 <250ms，表里却写 P50: 252ms 且标 ✅。这在逻辑上直接自相矛盾，除非团队另有未公开的判定口径，否则应判为未达标。
2. Phase 3 P99: 0.38us 的统计口径不稳定，且不是业务可用延迟。
   当前 2026-04-22 在 hermes 复跑时，同一 benchmark 的 criterion 聚合样本折算 p99 约 0.272us，但 bench 自己 stderr 打出的 sampled_p99 是 2.47us。这说明它混用了不同统计对象，而且测的是 pool.acquire() + drop()，不是“沙箱已执行完首个请
   求”。
3. 官方 bench 复现路径不完整。
   scripts/bench.sh 只执行 cargo bench -p <crate>，不会带 --features kvm。而 kvm_bench.rs 在未启用 kvm feature 时 main() 是空实现，所以 ./scripts/bench.sh mimobox-vm kvm_bench 会“成功结束”，但并没有真正跑 microVM benchmark。
4. snapshot restore 测的是内存中的快照恢复，不是文件/磁盘快照恢复。
   bench_snapshot_restore 先在进程内生成 (Vec<u8>, Vec<u8>)，再直接 restore_state(memory.as_slice(), vcpu_state.as_slice())。这不是典型生产环境里“从落盘 snapshot 加载恢复”的成本。
5. 多个对外数字缺少可追溯原始证据，且与当前复跑不一致。
   例如 README/CLAUDE 中的 OS 冷启动 3.51ms，当前 2026-04-22 在 hermes 复跑得到的是约 8.35ms；OS 热获取 0.38us P99 当前复跑的 sampled_p99 是 2.47us。仓库当前也没有可绑定这些数字的 Git commit，hermes 上甚至还是未提交仓库。

需索取的原始材料清单

| 材料 | 当前情况 | 审计判断 |
  |---|---|---|
| benchmark 源码 / 脚本 | 已取得部分源码与脚本 | 可分析实现，但不能证明 README 数字就是由这些脚本跑出来的 |
| 计时点定义 | 可从源码反推 | 需要团队给出正式定义文档，否则容易偷换口径 |
| 原始测试日志 | 仅有我 2026-04-22 的复跑输出；历史宣称值原始日志缺失 | 无法确认历史宣称值真实性 |
| 样本数量 N | OS/microVM 当前 criterion 样本可得；Wasm 缺失 | Wasm 与历史宣称值 N 不明 |
| P50 / P95 / P99 / max | 当前 OS/microVM 可由 sample.json 重算；公开表只给 P50 或单个 P99 | 对外表明显著隐藏尾延迟 |
| 测试机器配置 | 已取得 hermes 的 CPU/内存/磁盘/内核/虚拟化信息 | 当前复跑环境可描述，但历史宣称值未绑定机器快照 |
| 构建模式 / Rust 版本 | 当前为 cargo bench，toolchain 1.95.0 | 当前复跑可确认；历史宣称值缺乏绑定 |
| sandbox 实际负载内容 | 代码可确认多为 /bin/true、/bin/echo hello | 明显偏空负载 / 轻负载 |
| snapshot 体积 / 恢复流程 / page cache | 代码可确认是整块 guest memory dump，且 bench 用内存中的 snapshot | 恢复路径偏理想化，不是文件恢复 |
| warm pool 大小 / 预热策略 | 代码可确认 OS 池大小 64，microVM 池 min=1,max=4 | 资源成本未量化，RSS / CPU 缺证据 |
| Git commit / branch hash | 关键缺失，hermes 上为未提交仓库 | 重大可追溯性缺陷 |

证据基线

关键源码依据在这些文件里：

- README.md:124
- scripts/bench.sh:30
- crates/mimobox-os/benches/pool_bench.rs:86
- crates/mimobox-vm/benches/kvm_bench.rs:69
- crates/mimobox-cli/src/main.rs:469
- crates/mimobox-wasm/src/lib.rs:620
- crates/mimobox-vm/src/kvm.rs:190
- crates/mimobox-vm/src/kvm.rs:1545

真实性审计报告

A. 结论摘要

- 总体判断：存在明显包装
- 最可信的数据：
    - microVM 预热池热路径 <1ms 这一方向较可信。当前 2026-04-22 复跑为 P50 773us，与宣称 788us 接近。
    - microVM snapshot restore 的“量级在几十毫秒”较可信，但到底是 restore-to-ready 还是 restore+首个命令完成，口径没有写清。
- 最可疑的数据：
    - Wasm 冷启动 P50 0.61ms
    - OS 级预热池 P99 0.38us
    - OS 级冷启动 P50 3.51ms
- 应改写的状态标记：
    - microVM 冷启动 252ms / ✅ 应改为 未达标
    - Wasm 0.61ms / ✅ 应改为 无法确认
    - OS 预热池 0.38us / ✅ 应改为 仅说明 acquire 基础能力，不可视为业务端到端达标
    - snapshot restore 70ms / 进行中 应改为 按 full lifecycle 未达标；按 restore-to-ready 可能达标

一致性审查

| 指标 | 目标 | 表中实际 | 表中状态 | 审计判断 | 修正后状态 |
  |---|---:|---:|---|---|---|
| Phase 1 OS 级冷启动 | <10ms | 3.51ms P50 | 达标 | 目标上可能达标，但当前无证据支持 3.51ms 这个精确值；2026-04-22 复跑约 8.35ms | 达标，但原值待重测 |
| Phase 2 Wasm 冷启动 | <5ms | 0.61ms P50 | 达标 | 缺原始日志、缺官方复跑入口，且代码含模块缓存 | 无法确认 |
| Phase 3 预热池热获取 | <100us | 0.38us P99 | 达标 | 仅测 acquire/drop；同一 bench 当前复跑 sampled_p99=2.47us，统计口径混杂 | 基础能力达标，业务口径不成立 |
| Phase 4 microVM 冷启动 | <250ms | 252ms P50 | 达标 | 逻辑矛盾；当前复跑 P50 253.06ms，P99 391.92ms | 未达标 |
| Phase 4 microVM 快照恢复 | <50ms | 70ms P50 | 优化中 | 如果定义是 full lifecycle，当前复跑 P50 68.95ms 仍未达标；如果定义是 restore-to-ready，内部 profile 显示约 35-45ms | 口径不清；full lifecycle 未达标 |
| Phase 4 microVM 预热池热路径 | <1ms | 788us P50 | 达标 | 当前复跑 P50 773us，方向可信，但 workload 很轻 | 达标，但仅轻载 |

B. 逐项审计表

| 指标 | 原始声称 | 是否口径清晰 | 是否证据充分 | 是否可能被美化 | 你的修正判断 | 风险等级 |
  |---|---|---|---|---|---|---|
| OS 级冷启动 | <10ms, P50 3.51ms | 部分清晰。代码口径是 new + execute(/bin/true) + destroy | 不充分。当前只有源码与 2026-04-22 复跑值，缺历史原始日志 | 是。当前复跑约 8.24ms P50，与公开值差距大 | 可认为“目标达标”，但 3.51ms 不能继续
  直接引用 | 中 |
| Wasm 级冷启动 | <5ms, P50 0.61ms | 不清晰。代码里有 engine 创建、模块缓存、热路径复用，但无正式 bench 产物 | 不充分。无 sample.json、无官方脚本、无原始日志 | 是，高疑点。代码含磁盘模块缓存，所谓“冷启动”可能命中缓存 | 高疑点。当前只
  能判“无法确认真实性” | 高 |
| 预热池热获取 | <100us, P99 0.38us | 不清晰。它测的是 acquire()+drop()，不是“可执行任务完成” | 部分充分。源码和当前复跑可见，但历史 0.38us 原始日志缺失 | 是，高疑点。统计混用了 criterion 聚合值和自定义 sampled p99 | 高疑点。只能说“对
  象获取极快”，不能当业务延迟宣传 | 高 |
| microVM 冷启动 | <250ms, P50 252ms | 清晰。代码口径是 create + boot + run_command(echo) + shutdown | 充分。当前有 raw sample 与 2026-04-22 spot-check | 是。只展示 P50，隐藏 P99 391.92ms / max 396.14ms | 方向可信，但未达标，且尾延迟
  明显差 | 高 |
| microVM 快照恢复 | <50ms, P50 70ms | 不清晰。bench 是 create_for_restore + restore_state + run_command + shutdown，但内部 profile 另报 restore-to-ready | 充分但口径冲突。当前复跑 P50 68.95ms，内部 restore-to-ready 约 35-45ms | 是。
  容易把“恢复到 READY”偷换成“首个请求完成” | 若按 full lifecycle，未达标；若按 restore-to-ready，可能已达标 | 高 |
| microVM 预热池热路径 | <1ms, P50 788us | 清晰。代码口径是 pool.acquire + pooled.execute(echo) + drop | 充分。当前复跑 P50 773us，与宣称接近 | 有一定美化空间。workload 很轻，pool 成本未披露 | 基础能力较可信，当前可判达标，但不等于真
  实业务都 <1ms | 中 |

指标严格定义

| 指标 | 起点 | 终点 | 实例已可接收任务 | 用户代码已真正开始运行 | 首个请求已完成 | 是否足以代表用户感知延迟 |
  |---|---|---|---|---|---|---|
| OS 级冷启动 | 调用 PlatformSandbox::new 之前 | execute(/bin/true) 返回并 destroy 完成 | 是 | 是 | 是 | 部分代表，但只代表极轻载命令 |
| Wasm 级冷启动 | WasmSandbox::new 之前 | sb.execute(wasm) 返回 | 是 | 是 | 是 | 部分代表，但缓存命中与否会强烈影响结果 |
| 预热池热获取 | pool.acquire() 之前 | drop(sandbox) 完成 | 是 | 否 | 否 | 不代表 用户感知延迟 |
| microVM 冷启动 | create_vm / create_backend 之前 | run_command(echo) 返回并 shutdown 完成 | 是 | 是 | 是 | 部分代表，但仅轻载、cache-hot 条件 |
| microVM 快照恢复 | create_vm_for_restore 之前 | restore_state + run_command + shutdown 完成 | 是 | 是 | 是 | 部分代表，但当前 bench 不是文件快照恢复 |
| microVM 预热池热路径 | pool.acquire() 之前 | pooled.execute(echo) 返回并 drop 完成 | 是 | 是 | 是 | 部分代表，但 workload 极轻、资源成本未披露 |

复现实验与当前复跑

当前我实际完成的复核

- 时间：2026-04-22
- 机器：hermes
- CPU：Intel Xeon E5-2686 v4 @ 2.30GHz，72 CPU
- 内存：93GiB
- 磁盘：NVMe + HDD 混合
- 内核：5.14.0-611.5.1.el9_7.x86_64
- 虚拟化：systemd-detect-virt = none
- Rust：rustc 1.95.0，cargo 1.95.0
- 构建：cargo bench 的 bench profile，优化开启

复跑命令与结论

| 命令 | 结果 | 说明 |
  |---|---|---|
| ./scripts/bench.sh mimobox-os pool_bench | 成功 | 能复现 OS bench |
| ./scripts/bench.sh mimobox-vm kvm_bench | 表面成功，实际无效 | 因未带 --features kvm，kvm_bench 主函数为空，不是真正复现 |
| cargo bench -p mimobox-vm --features kvm --bench kvm_bench bench_cold_start -- --noplot | 成功 | 用于补做 microVM cold start spot-check |
| cargo bench -p mimobox-vm --features kvm --bench kvm_bench bench_snapshot_restore -- --noplot | 成功 | 用于补做 snapshot restore spot-check |
| cargo bench -p mimobox-vm --features kvm --bench kvm_bench bench_pool_hot_path -- --noplot | 成功 | 用于补做 pool hot path spot-check |

2026-04-22 当前 raw sample 结果

| 指标 | N | P50 | P95 | P99 | Max | 说明 |
  |---|---:|---:|---:|---:|---:|---|
| OS 冷启动 | 20 | 8.239ms | 8.807ms | 8.988ms | 8.988ms | 当前复跑，与公开 3.51ms 明显不一致 |
| OS 热获取 | 60 | 0.194us | 0.228us | 0.272us | 0.272us | 这是 batch-aggregated 结果；同次 stderr sampled_p99=2.47us |
| microVM 冷启动 | 100 | 253.064ms | 286.019ms | 391.918ms | 396.139ms | 当前未达标，且尾延迟明显 |
| microVM 快照恢复 | 100 | 68.946ms | 78.977ms | 81.988ms | 82.025ms | 按 full lifecycle 未达标 |
| microVM 命令执行 | 100 | 715.712us | 744.571us | 754.533us | 757.346us | 已 boot VM 内的连续命令，不是冷启动 |
| microVM 预热池热路径 | 100 | 773.235us | 781.567us | 787.047us | 793.812us | 当前与公开值接近 |

我确认到的“测得很好看但不代表真实业务”的问题

- 是，只测了非常轻的 workload。
  OS 级多用 /bin/true；microVM 多用 /bin/echo hello 和 /bin/true；Wasm 也没有公开接近真实业务的 workload 证明。
- 是，关键初始化可能被不同指标分拆后选择性展示。
  create_vm_total 常见只有十几到几十毫秒，但真实 full cold start 要加上 boot_wait，当前常见约 190-240ms，偶发更高。
- 是，对外表基本只展示了 P50 或单个 P99。
  当前 microVM 冷启动 P99 391.92ms，这和“P50 252ms”给人的印象完全不同。
- 是，warm pool 指标没有披露资源成本。
  OS hot acquire 使用了 warmed_pool(64)；microVM pool hot path 用 memory_mb=64 的预热 VM。精确 RSS/CPU 没有公开。
- 是，Phase 3 P99 0.38us 高疑点很高。
  这更像“对象句柄获取成本”，而不是“完整 sandbox 可用成本”。它已经接近计时器、锁和 cache 命中的微基准范围。
- 是，microVM snapshot restore 口径存在偷换空间。
  当前 bench 的 70ms 类数字其实是 restore + 首个 echo 命令 + shutdown；内部 restore profile 的 35-45ms 则更接近“恢复到 READY”。如果不写清楚，很容易被包装。

snapshot / warm pool 的资源真实性

- snapshot 体积：
  从代码看，snapshot_state() 直接 dump_guest_memory()，而 dump_guest_memory() 会分配 self.config.memory_bytes() 大小的完整内存块。
  当前 benchmark config 是 64MiB，所以快照 memory blob 代码上可推断为完整 64MiB，不是增量快照。
  这是基于代码的推断，不是团队提供的正式测量值。
- microVM asset cache：
  AssetCache 会缓存 kernel 和 rootfs 字节，避免重复磁盘读取。
  这意味着所谓 microVM “cold start” 在同一进程多轮 bench 中并不是磁盘冷 cache。
- Wasm cache：
  WasmSandbox 使用 /tmp/mimobox-cache-<uid> 模块缓存。
  所谓 Wasm “冷启动”如果没有明确清缓存，就很可能不是“首次编译冷启动”。

最小可行复核方案

1. 固定一台专用 benchmark 机器，先记录 commit hash、cargo/rustc 版本、kernel、CPU governor、NUMA、systemd-detect-virt。
2. 每项 benchmark 至少跑 1000 次。
   如果 microVM cold start 场景耗时太高，允许 300 x 5 轮，但必须同时报告轮间方差。
3. 每项分别在 4 个场景下跑：
    - 单实例串行
    - 多实例并发
    - 宿主机有干扰负载
    - 冷 cache 与热 cache
4. 每次输出统一指标：
    - P50 / P95 / P99 / max
    - mean / stddev
    - 失败率
5. 每项至少拆成两类口径：
    - 基础能力 benchmark
    - 业务可用 benchmark
6. 每次结果必须保存：
    - 原始 stdout/stderr
    - criterion sample.json / estimates.json
    - 执行命令
    - 机器信息
    - commit hash
7. microVM 额外必须补：
    - restore-to-ready
    - restore-to-first-command-done
    - file-backed snapshot restore
    - page cache miss 场景
8. warm pool 额外必须补：
    - pool size
    - 命中率 / miss rate
    - RSS / CPU / idle cost
9. workload 必须分级：
    - 空负载：true / echo
    - 轻业务：启动解释器并执行 1 个小脚本
    - 中业务：含文件 I/O、模块导入、少量计算
10. 对外只允许发布“带 commit、带原始附件、带 workload 说明”的版本。

当前仍无法确认的项目

- Wasm 0.61ms 的原始日志、样本 N、P95/P99/max
- README 中 3.51ms 与 0.38us 对应的历史 commit
- warm pool 的 RSS / CPU 实测
- snapshot 的真实文件大小与文件恢复耗时
- 并发下 microVM cold start / restore 的分布
- 冷 cache 下的真实结果

C. 关键问题列表

1. 252ms > 250ms 为什么在 README 和 CLAUDE 中被标成“达标”？
2. 3.51ms、0.61ms、0.38us、252ms、70ms、788us 各自对应哪一个 commit hash、哪一天、哪条命令、哪台机器？
3. 为什么官方 scripts/bench.sh 不能复现 microVM bench，却仍对外发布 microVM 指标？
4. Phase 3 P99 0.38us 到底取自 criterion estimates、sample.json 折算，还是 stderr 里的 sampled_p99？
5. 同一个 OS hot acquire benchmark，为什么当前会同时出现 p99≈0.272us 和 sampled_p99=2.47us 两套结果？团队准备对外采用哪套，理由是什么？
6. Wasm 0.61ms 是否命中了 /tmp/mimobox-cache-* 模块缓存？如果清空缓存、换进程、drop page cache 后是多少？
7. snapshot restore <50ms 的正式定义到底是“恢复到 READY”还是“恢复后首个请求完成”？如果是后者，为什么内部 profile 只展示 35-45ms 的 restore-to-ready？
8. snapshot 当前为什么用进程内 Vec<u8> 恢复，而不是 file-backed snapshot？这与真实产品路径相差多大？
9. 为什么公开表不展示 microVM 冷启动 P95/P99/max？当前复跑 P99≈392ms、max≈396ms 是否被认为可以接受？
10. warm pool 的命中率、RSS、CPU idle cost 是多少？没有资源成本，为什么可以把热路径成绩单独当作卖点？

D. 真实性风险点评

- 是否存在“只展示中位数”：
  是。公开表几乎只展示 P50，而当前 microVM 冷启动尾延迟明显更差。
- 是否存在“空负载 benchmark”：
  是。OS 级多为 /bin/true，microVM 多为 /bin/echo hello。这不足以代表真实业务。
- 是否存在“状态标记过于乐观”：
  是。252ms 对 <250ms 标 达标 是最典型的乐观标记。
- 是否存在“warm path 成绩掩盖真实资源成本”：
  是。OS 用了 pool size=64，microVM 用了预热 VM，但没有公开 RSS / CPU / miss rate。
- 是否存在“microVM 指标定义偷换”：
  是。至少有两种明显偷换空间：
    - create_vm_total 与 full cold start
    - restore-to-ready 与 restore-to-first-command-done

E. 最终判词

- 这组数据不能作为对外宣传材料直接使用。
- 如果必须降级表述，建议改成：
  截至 2026-04-22 的内部轻载基准，mimobox 在 OS、Wasm、microVM 三层路径上都已具备可观性能；其中 microVM 预热热路径约 0.77ms，microVM 冷启动约 0.25s，snapshot full-lifecycle 恢复约 0.069s。不同指标口径不同，当前结果主要反映基础能力基
  准，不直接代表真实业务端到端延迟。
- 如果要严谨对外发布，至少还缺这些证据：
    - 每个指标绑定的 commit hash
    - 历史宣称值的原始 stdout/stderr
    - criterion sample.json / estimates.json
    - 明确的起点/终点定义
    - P50 / P95 / P99 / max / mean / stddev / failure rate
    - Wasm 原始数据与复跑入口
    - file-backed snapshot restore 数据
    - 并发、干扰负载、冷 cache 数据
    - warm pool 的 RSS / CPU 成本
    - workload 分级说明

本次审计没有修改代码。核心结论只有一句话：这些 benchmark 有真实实现基础，但当前汇总表的呈现方式不够诚实，尤其是状态标记、统计口径和“冷启动/恢复”定义。