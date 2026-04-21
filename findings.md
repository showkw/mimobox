# Findings & Decisions

## Requirements
- 在 `hermes` 上分析当前 `~/mimobox-poc/vm-assets/vmlinux` 的大小与文件类型。
- 构建最小化 KVM guest 内核，仅保留必需功能：串口、initrd/initramfs、virtio、ext4/cpio、KVM guest 基础能力。
- 开启 `CC_OPTIMIZE_FOR_SIZE=y`，并启用 `CONFIG_KERNEL_XZ` 或 `CONFIG_KERNEL_GZIP`。
- 目标内核大小 `< 5MB`。
- 备份并替换 `~/mimobox-codex-assets/vmlinux`。
- 通过指定 KVM e2e 测试验证，期望 8 个测试全部通过。

## Research Findings
- 仓库已有 KVM 相关脚本：`scripts/build-rootfs.sh`、`scripts/extract-vmlinux.sh`、`scripts/test-e2e.sh`。
- `scripts/test-e2e.sh` 默认使用 `VM_ASSETS_DIR/vmlinux` 与 `rootfs.cpio.gz`。
- `crates/mimobox-vm/src/kvm.rs` 当前仅支持 `64 位小端 ELF vmlinux` 镜像，不是 bzImage。
- `hermes` 上当前 `~/mimobox-poc/vm-assets/vmlinux` 为 `64M`，`file` 识别为 `ELF 64-bit LSB executable, x86-64, stripped`。
- `hermes` 上已有 `gcc/make/ld/cargo/rustc`，但缺少内核构建常用依赖：`flex`、`bison`、`bc`、`elfutils-libelf-devel`、`perl` 等。
- `hermes` 上未发现现成 Linux kernel source 目录，需要自行下载或安装源码。
- `guest-init.c` 依赖能力包括：`ttyS0` 串口、`ioperm`、`devtmpfs`、`proc`、`sysfs`、`fork/execve`、`pipe`、`waitpid`。
- 当前 `mimobox-vm` KVM 实现没有 virtio 设备模型；根文件系统通过外部加载的 `gzip cpio initrd` 提供，不依赖 ext4 或 virtio-blk。

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| 优先构建最小 ELF `vmlinux`，再评估压缩配置的附带收益 | KVM loader 明确读取 ELF，压缩内核镜像不能直接替代当前加载路径 |
| 是否新增 `scripts/build-kernel.sh` 取决于 hermes 现有环境和一次性命令复杂度 | 只有在远端重复构建需求明显时才固化脚本，避免 YAGNI |
| 先采用 `allnoconfig/tiny` 思路，再按 `guest-init` 依赖补最小功能 | 当前 guest 路径非常窄，先从最小集收敛更容易达到体积目标 |
| 暂不把 ext4/virtio 作为首轮强制项 | 现有 e2e 仅使用串口 + initrd，额外子系统会直接抬高 `vmlinux` 体积 |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| hermes 缺少 kernel source | 下一阶段下载上游内核源码到用户目录 |
| hermes 缺少内核构建依赖 | 使用 `sudo dnf install` 补齐最小工具链 |

## Resources
- `CLAUDE.md`
- `scripts/test-e2e.sh`
- `scripts/build-rootfs.sh`
- `scripts/extract-vmlinux.sh`
- `crates/mimobox-vm/src/kvm.rs`
- `crates/mimobox-vm/guest/guest-init.c`

## Visual/Browser Findings
- 当前任务未涉及浏览器或图像信息。
