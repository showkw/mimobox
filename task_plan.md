# Task Plan: microVM 最小 KVM guest 内核构建

## Goal
在 `hermes` 上构建并替换一个用于 KVM guest 启动的最小 Linux 内核，使 `~/mimobox-codex-assets/vmlinux` 尽量接近并优于 `< 5MB` 目标，并通过指定的 `mimobox-vm` KVM e2e 验证。

## Current Phase
Phase 1

## Phases

### Phase 1: 需求与现状确认
- [x] 理解用户目标、约束和验收标准
- [x] 检查仓库规则、测试入口与现有脚本
- [x] 记录 hermes 上当前内核资产、源码和工具链现状
- **Status:** complete

### Phase 2: 最小内核方案设计
- [ ] 确定内核源码获取方式与可用版本
- [ ] 基于 `defconfig` 或 `tinyconfig` 生成最小化 `.config`
- [ ] 记录必须保留与明确裁剪的配置项
- **Status:** in_progress

### Phase 3: 编译与资产替换
- [ ] 在 hermes 上编译 size-optimized guest 内核
- [ ] 备份旧 `~/mimobox-codex-assets/vmlinux`
- [ ] 替换为新内核并记录产物大小
- **Status:** pending

### Phase 4: 测试与验证
- [ ] 运行指定 `cargo test` 命令
- [ ] 核对测试总数、通过情况与失败信息
- [ ] 如失败则修复并重测
- **Status:** pending

### Phase 5: 交付
- [ ] 汇总内核大小、关键配置策略与测试结果
- [ ] 明确未达成项、风险和后续建议
- **Status:** pending

## Key Questions
1. `hermes` 上是否已有可直接复用的 Linux kernel 源码与构建依赖？
2. 当前 `mimobox-vm` guest 实际依赖哪些设备与功能，哪些可以彻底裁剪？
3. 最终使用未压缩 ELF `vmlinux` 还是压缩镜像参与 KVM 启动，`< 5MB` 目标具体约束在哪个产物上？

## Decisions Made
| Decision | Rationale |
|----------|-----------|
| 先验证现有脚本和远端环境，再决定是否新增 `scripts/build-kernel.sh` | 避免重复实现，优先利用已有资产流程 |
| 使用文件化计划记录本次多阶段优化 | 任务跨本地和远端、多次验证，易丢上下文 |
| 暂不新增仓库脚本，先在 hermes 上完成一次构建闭环 | 当前缺口主要是远端工具链与源码，不是脚本入口；先验证最小配置可行性 |

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
|       | 1       |            |

## Notes
- 先确认 `mimobox-vm` 读取的是 ELF `vmlinux`，避免错误追求 bzImage 体积
- 每完成一个阶段同步更新 `findings.md` 与 `progress.md`
- `CONFIG_KERNEL_GZIP/XZ` 只影响压缩启动镜像，对当前直接加载 ELF `vmlinux` 的路径收益有限，但仍可按要求开启
