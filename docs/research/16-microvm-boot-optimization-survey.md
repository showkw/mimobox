# microVM Guest Kernel Boot 优化调研报告

> 调研目标：分析主流竞品如何将 microVM cold boot 压到 200ms 以下，提取可复用的技术手段。
> 调研日期：2026-04-22

---

## 1. 各竞品 Boot Time 基准数据

| 竞品 | 冷启动 (kernel → init) | 快照恢复 | 备注 |
|------|----------------------|---------|------|
| **Firecracker** | **~125ms** (官方) / ~400ms (含完整 guest init) | **<10ms** (API 级) / ~43ms (实际 load+resume) | i3.metal 裸金属 + 定制 4.14 内核 |
| **Cloud Hypervisor** | **~91ms** (kernel boot) / ~131ms (含 VMM 初始化 ~40ms) | 未公开具体数据 | 简单配置，含异步内核加载优化 |
| **QEMU microvm** | **~115ms** (PVH 直启) / ~808ms (传统 Q35 对比) | N/A | 无 PCI/无 ACPI，virtio-mmio |
| **libkrun** | **~20-50ms** (估计) | 不使用快照 | 极简设备模型 + 自定义 initramfs |
| **crosvm** | 未公开具体数据 | 实验性快照支持 | Chrome OS Crostini/ARCVM 场景 |
| **NetBSD MICROVM** | **~10ms** (kernel boot) | N/A | 专用 MICROVM 内核配置，无 PCI/ACPI |

### 关键发现

1. **Firecracker 的 125ms 是"理想条件"数据**：NumaVM 2026 年实测表明，在 AWS Graviton 上从零到 SSH ready 需 **1,133ms**（其中 Firecracker 自身仅 38ms，kernel boot ~400ms，其余为 host 侧编排）。[来源](https://numavm.com/blog/2026-03-10-1-second-boot/)
2. **真正快的冷启动在 90ms 以下**：Cloud Hypervisor 的 kernel-to-userspace 仅 ~91ms（简单配置）。
3. **快照恢复是终极武器**：Firecracker 快照恢复 ~43ms（load+resume），比冷启动快 **6.4 倍**。

---

## 2. 内核裁剪策略

### 2.1 Firecracker 内核配置分析

Firecracker 官方内核配置文件位于 `resources/guest_configs/` 目录。以下是从其 x86_64 5.10 内核配置中提取的关键决策：

**启用的核心特性：**
```
CONFIG_SMP=y                    # 多核支持
CONFIG_KVM_GUEST=y              # KVM 准虚拟化
CONFIG_ACPI=y                   # ACPI（用于关机等基本操作）
CONFIG_PCI=y                    # PCI 总线（可选，非 PCI 模式更快）
CONFIG_VIRTIO_MMIO=y            # virtio MMIO 传输
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
CONFIG_VIRTIO_BLK=y             # 块设备
CONFIG_VIRTIO_NET=y             # 网络设备
CONFIG_VIRTIO_VSOCKETS=y        # vsock
CONFIG_VIRTIO_CONSOLE=y         # 控制台
CONFIG_VIRTIO_BALLOON=y         # 内存气球
CONFIG_SERIAL_8250=y            # 串口（可禁用以加速）
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_EXT4_FS=y                # ext4 文件系统
CONFIG_NET=y                    # 网络栈
CONFIG_INET=y                   # TCP/IP
CONFIG_PRINTK=y                 # 保留 printk（调试用）
CONFIG_KERNEL_GZIP=y            # gzip 压缩
CONFIG_BLK_DEV_INITRD=y         # initrd 支持
CONFIG_DEVTMPFS=y               # devtmpfs 自动挂载
```

**关键禁用项：**
- 绝大部分 ACPI 子功能（电池、风扇、温控、WMI 等）
- 绝大部分加密算法（仅保留 AES/SHA/RSA 等必需项）
- CONFIG_MODULE_UNLOAD — 不支持卸载模块
- 大量不需要的硬件驱动

### 2.2 各竞品裁剪策略对比

| 维度 | Firecracker | Cloud Hypervisor | QEMU microvm | libkrun |
|------|-------------|-----------------|--------------|---------|
| PCI | 可选（非 PCI 模式更快） | 必须（支持热插拔） | 禁用（virtio-mmio） | 禁用 |
| ACPI | 启用（子功能精简） | 启用 | 禁用 | 禁用 |
| SMP | 启用 | 启用 | 可选 | 通常 1 vCPU |
| USB | 禁用 | 禁用 | 禁用 | 禁用 |
| 网络栈 | 启用 | 启用 | 可选 | 可选 |
| 串口 | 启用（可禁用加速） | 使用 hvc0 | 可选 | 可选 |
| 模块加载 | nomodule | built-in | built-in | built-in |

---

## 3. 启动优化技巧详解

### 3.1 直接内核加载（Bypass Bootloader）

**这是最关键的单项优化，可省 20-30ms。**

所有竞品都采用直接内核加载，跳过 BIOS/UEFI/GRUB：

- **Firecracker**：直接加载 vmlinux ELF 到 0x200（64-bit entry point），跳过 real mode 和 bootloader
- **Cloud Hypervisor**：支持 PVH (Plain Virtual Hardware) 直接启动，也支持 firmware 启动（Rust Hypervisor Firmware / edk2 UEFI）
- **QEMU microvm**：默认使用 PVH 直启（比 SeaBIOS 快 ~12ms，比 qboot 快 ~1ms）
- **libkrun**：直接加载 kernel image + initramfs 到 guest 内存
- **crosvm**：直接加载 bzImage 或 ELF kernel

**不使用 initramfs** 也可省时间。Firecracker 论文指出：如果不使用 initramfs，可以减少 boot time 和内存占用。

### 3.2 内核压缩算法

| 算法 | 解压速度 | 压缩率 | 竞品选择 |
|------|---------|--------|---------|
| gzip | 中 | 中 | Firecracker 默认 |
| lz4 | **最快** | 低 | 未被竞品广泛使用 |
| xz | 慢 | 高 | 不适合 fast boot |
| zstd | 快 | 高 | 新兴选择 |

**Firecracker 使用 gzip**，但实际上 Firecracker 直接加载未压缩的 vmlinux ELF，完全跳过内核解压步骤（省 20-30ms）。

> 如果必须使用压缩内核：选择 **lz4** 解压最快。

### 3.3 内核 cmdline 参数优化

**Firecracker 默认 cmdline：**
```
reboot=k panic=1 nomodule 8250.nr_uarts=0 pci=off
i8042.noaux i8042.nomux i8042.dumbkbd swiotlb=noforce
```

**各参数效果分析：**

| 参数 | 作用 | 预估节省 |
|------|------|---------|
| `pci=off` | 跳过 PCI 总线枚举 | **~25ms**（最大单项） |
| `8250.nr_uarts=0` | 禁用串口 UART 探测 | ~5ms |
| `nomodule` | 禁用可加载模块 | ~3ms |
| `console=hvc0` (替代 ttyS0) | 使用 virtio console | ~5ms |
| `quiet` | 抑制控制台输出 | ~2-5ms |
| `tsc=reliable` | 跳过 TSC 校准 | **~30ms**（4.14 内核，5.x 已优化） |
| `no_timer_check` | 跳过 timer IRQ 验证 | ~5ms |
| `mitigations=off` | 禁用 Spectre/Meltdown 缓解 | ~10-20ms（**安全风险**） |
| `acpi=off` | 跳过 ACPI 表解析 | ~12ms |
| `fastboot` | 跳过异步设备探测延迟 | ~5ms |
| `rcupdate.rcu_expedited=1` | 加速 RCU | ~3ms |
| `i8042.noaux/nopnp/noaux` | 禁用 i8042 键盘控制器探测 | ~3ms |

**Cloud Hypervisor 参考 cmdline：**
```
root=/dev/vda1 console=hvc0 quiet rw panic=1
```

**QEMU microvm 最优 cmdline（来自邮件列表讨论）：**
```
console=hvc0 reboot=k panic=1 pci=off tsc=reliable
no_timer_check rcupdate.rcu_expedited=1
i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1
```

### 3.4 禁用子系统效果量化

来自 QEMU 邮件列表的实测数据（基于 microvm machine type）：

| 优化手段 | 节省时间 |
|---------|---------|
| `-cpu host`（暴露 TSC_DEADLINE） | **~120ms**（避免 APIC timer 校准） |
| 禁用 PCI（microvm vs Q35） | **~45ms**（QEMU 10ms + firmware 10ms + kernel 25ms） |
| 禁用 ACPI | **~12ms**（内核 ~12ms + QEMU ~5ms） |
| qboot 替代 SeaBIOS | **~11ms** |
| PVH 直启替代 qboot | **~1ms** |

### 3.5 关键发现：`-cpu host` 的巨大影响

QEMU 邮件列表测试表明，使用 `-cpu host` 暴露 `TSC_DEADLINE` 特性可以节省 **~120ms**（避免 `calibrate_APIC_clock`）。这是最大的单项优化之一。

---

## 4. 快照恢复 vs 冷启动

### 4.1 竞品快照策略

| 竞品 | 快照支持 | 恢复时间 | 策略 |
|------|---------|---------|------|
| **Firecracker** | 完整支持 | **<10ms**（API 级）/ ~43ms（含 load） | 生产级，AWS Lambda 依赖此功能 |
| **Cloud Hypervisor** | 完整支持 | ~50ms（live upgrade 路径） | 用于 live migration 和升级 |
| **QEMU microvm** | 通过 QEMU 快照 | 取决于内存大小 | 通用方案 |
| **libkrun** | 不使用 | N/A | 纯冷启动，靠极简设计实现快启 |
| **crosvm** | 实验性 | 未公开 | Chrome OS 场景探索中 |

### 4.2 Firecracker 快照恢复实测（NumaVM 2026）

| 阶段 | 耗时 |
|------|------|
| Host 设置（TAP + Firecracker spawn） | 97ms |
| Snapshot load + resume | 43ms |
| iptables DNAT | 33ms |
| Readiness check | 2ms |
| **总计** | **176ms** |

对比冷启动 1,133ms，快照恢复 **快 6.4 倍**。其中 Firecracker 自身的 snapshot load+resume 仅 **43ms**。

### 4.3 快照恢复的适用场景

- **适用**：预热池、serverless 函数热启动、短期任务
- **不适用**：首次启动、内存快照过期后需重建

### 4.4 对 mimobox 的启示

mimobox 已有预热池方案（P99: 0.38us 热路径），快照恢复是补充手段而非替代。但参考 Firecracker 的 43ms 恢复速度，如果冷启动能压到 200ms 以下，预热池方案的整体效果会更优。

---

## 5. VMM 层面优化

### 5.1 Cloud Hypervisor 的优化实践

1. **异步内核加载**：内核加载与设备配置并行执行，复杂配置下节省 20-30ms
2. **PCI MSI-X 优化**：减少 MSI-X 表更新次数，解决 5.18 内核引入的 ~83% 启动回退
3. **并行内存预分配（prefault）**：v38.0 引入 `MAP_POPULATE` 并行化，使用大页减少 IOMMU 映射数量
4. **IOAPIC 默认 mask**：减少启动期不必要的中断处理
5. **PCI bus 范围修正**：正确的 MCFG 表 PCI bus 范围减少内核扫描

### 5.2 Firecracker 的 MMDS 与启动流程

Firecracker 的 MMDS (Microvm Metadata Service) 不直接影响 boot time，它是一个轻量级 metadata 服务，运行在 VMM 进程内。Firecracker 启动流程的关键优化：

1. **最小设备模型**：仅 6 个设备（virtio-net、virtio-balloon、virtio-block、virtio-vsock、serial console、minimal keyboard controller）
2. **所有设备使用 virtio-mmio**（非 PCI 模式下），避免 PCI 枚举
3. **VMM 启动自身仅耗时 ~38ms**（内核加载 + vCPU 启动）

### 5.3 sched_ext 调度优化（2025 年新发现）

[arighi 的博客](http://arighi.blogspot.com/2025/01/accelerating-micro-vm-boot-time-with.html) 展示了使用 `sched_ext`（BPF 调度器）加速 microVM boot 的实验：

- 通过自定义调度策略（scx_bpfland），让 VM 启动任务在 CPU 间快速迁移
- 实现 **~11% 的 boot time 加速**（1.437s → 1.295s）
- 核心思路：VM boot 是 CPU 密集型短任务，默认 CFS 调度器不够激进

---

## 6. 可参考的最佳实践配置

### 6.1 推荐的最小内核 cmdline

```
console=hvc0 quiet reboot=k panic=1 pci=off nomodule
8250.nr_uarts=0 tsc=reliable no_timer_check
rcupdate.rcu_expedited=1 fastboot
i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd
```

### 6.2 推荐的内核裁剪清单

**必须禁用：**
- PCI 子系统（如不需要）
- USB 子系统
- 所有 GPU/DRM 驱动
- 所有声卡驱动
- 所有蓝牙驱动
- 所有无线网络驱动
- 所有物理网卡驱动（仅保留 virtio-net）
- 所有存储控制器驱动（仅保留 virtio-blk）
- ACPI 电池/风扇/温控/热插拔
- 可加载模块支持（nomodule）

**必须启用：**
- `CONFIG_VIRTIO_MMIO=y`
- `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`
- `CONFIG_VIRTIO_BLK=y`
- `CONFIG_VIRTIO_NET=y`（如需网络）
- `CONFIG_VIRTIO_VSOCKETS=y`（如需 vsock）
- `CONFIG_KVM_GUEST=y`
- `CONFIG_DEVTMPFS=y`
- `CONFIG_DEVTMPFS_MOUNT=y`
- `CONFIG_SERIAL_8250=y`（调试用，生产可禁用）
- `CONFIG_EXT4_FS=y`（或目标文件系统）

**可选启用：**
- `CONFIG_PRINTK=n`（彻底移除 printk 开销，生产环境）
- `CONFIG_ACPI=n`（如不需要 ACPI 关机等操作）
- `CONFIG_SMP=n`（单 vCPU 场景）

### 6.3 VMM 层面建议

1. **使用 `-cpu host`** 或至少暴露 `TSC_DEADLINE` 特性
2. **禁用 UART/serial** 在生产环境（使用 virtio-console 替代）
3. **异步加载内核**：与设备初始化并行
4. **使用大页（hugepages）**：减少 IOMMU 映射开销
5. **避免 MSI-X 过度更新**：最小化中断配置表写入

---

## 7. 对 mimobox microVM 的具体建议

### 当前状态
- mimobox microVM 冷启动 P50: **323ms**（目标 <200ms）
- 快照恢复 P50: **71ms**（目标 <50ms）
- 预热池热路径 P99: **0.38us**（已达标）

### 优化路径（按投入产出比排序）

| 优先级 | 优化项 | 预估节省 | 难度 |
|--------|-------|---------|------|
| **P0** | Guest kernel 使用 `pci=off` + virtio-mmio | ~25ms | 低 |
| **P0** | cmdline 添加 `tsc=reliable no_timer_check fastboot` | ~30-40ms | 低 |
| **P0** | 禁用串口 console（生产模式） | ~5-10ms | 低 |
| **P1** | 使用未压缩 vmlinux 直启（跳过解压） | ~20-30ms | 中 |
| **P1** | 定制最小内核 defconfig | ~30-50ms | 中 |
| **P1** | VMM 层异步内核加载 | ~20-30ms | 中 |
| **P2** | `-cpu host` 暴露 TSC_DEADLINE | ~50-120ms | 需测试 |
| **P2** | `mitigations=off`（安全评估后） | ~10-20ms | 需评估 |
| **P2** | `CONFIG_PRINTK=n`（生产构建） | ~5ms | 低 |

### 预期效果

综合 P0+P1 优化，预计可将冷启动从 323ms 降至 **~150-200ms**。加上 P2 优化，有望达到 **<150ms**。

---

## 8. 参考资料

- [Firecracker 官方仓库 - 内核配置](https://github.com/firecracker-microvm/firecracker/tree/main/resources/guest_configs)
- [NumaVM: Benchmarking Firecracker Boot and Restore (2026)](https://numavm.com/blog/2026-03-10-1-second-boot/)
- [QEMU microvm machine type 文档](https://www.qemu.org/docs/master/system/i386/microvm.html)
- [Cloud Hypervisor Boot Time Issue #1728](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/1728)
- [Cloud Hypervisor PCI Boot Optimizations PR #1739](https://github.com/cloud-hypervisor/cloud-hypervisor/pull/1739)
- [Cloud Hypervisor Async Kernel Loading PR #4022](https://github.com/cloud-hypervisor/cloud-hypervisor/pull/4022)
- [Cloud Hypervisor Boot Time Regression Issue #4273](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/4273)
- [Firecracker Long Boot Time Issue #792](https://github.com/firecracker-microvm/firecracker/issues/792)
- [Firecracker TSC Frequency Issue #477](https://github.com/firecracker-microvm/firecracker/issues/477)
- [Firecracker MAP_POPULATE PR #3944](https://github.com/firecracker-microvm/firecracker/pull/3944)
- [QEMU microvm PATCH v3 邮件列表讨论](https://lists.gnu.org/archive/html/qemu-devel/2019-07/msg00654.html)
- [加速 microVM Boot 的 sched_ext 实验](http://arighi.blogspot.com/2025/01/accelerating-micro-vm-boot-time-with.html)
- [Firecracker 论文 (arXiv)](https://arxiv.org/pdf/2005.12821)
- [libkrun GitHub](https://github.com/containers/libkrun)
- [NetBSD MICROVM 内核配置](https://wiki.netbsd.org/users/imil/microvm/)
- [Ubuntu QEMU microvm 文档](https://ubuntu.com/server/docs/explanation/virtualisation/qemu-microvm/)
