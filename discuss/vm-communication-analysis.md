# VM 通信技术可行性分析

## 背景与结论摘要

这份分析只基于当前仓库代码，不引入猜测。

先给结论：

1. 当前 `mimobox-vm` 里的 KVM 路径还不是“真实可运行的 VM 执行链路”，而是“内存装载 + 生命周期骨架 + host 侧合成退出事件”。关键证据是：`KvmBackend` 没有真实 `KVM_RUN`、没有寄存器初始化、没有设备模拟，`run_command()` 也没有把命令真正送进 guest，只是调用 host 侧的 `emulate_guest_command()` stub 生成结果。参考 `crates/mimobox-vm/src/kvm.rs:96-156`、`crates/mimobox-vm/src/kvm.rs:347-375`、`crates/mimobox-vm/src/kvm.rs:471-501`。
2. 在**当前 shim 限制下**，无论是 `vsock`、串口还是共享内存 / hypercall，都**不具备生产可行性**。根因不是“协议没选好”，而是底层缺失真实 KVM 运行循环、设备模型、事件注入和 guest 侧 agent。
3. 明确推荐路径是：**不要继续在现有 shim 上尝试实现真实通信**。先替换为真正的 rust-vmm crates，完成真实 KVM 启动、寄存器初始化和 exit loop；然后先用**串口控制通道**打通最小闭环，最终再把 `vsock` 作为正式生产数据面。

---

## 1. 当前 VM 启动流程的完整描述

先说明一个重要事实：仓库里**并不存在** `KvmBackend::new()`、`setup_memory()`、`load_elf()`、`setup_registers()`、`run_vcpu()` 这些函数。当前代码里的对应关系是：

| 需求概念 | 当前实际实现 |
|---|---|
| `KvmBackend::new()` | `KvmBackend::create_vm()` |
| `setup_memory()` | `GuestMemoryMmap::from_ranges()` + `write_guest_bytes()` |
| `load_elf()` | `load_kernel()` |
| `setup_registers()` | **未实现** |
| `run_vcpu()` | `run_vcpu_loop()`，但它只是合成退出事件，不是真实 `KVM_RUN` |

证据：`KvmBackend::create_vm()` 定义在 `crates/mimobox-vm/src/kvm.rs:98-156`，`run_vcpu_loop()` 定义在 `crates/mimobox-vm/src/kvm.rs:401-422`。

### 1.1 上层抽象入口

`mimobox-vm` crate 的模块导出非常薄，只把 `snapshot`、`vm` 和 Linux + `kvm` feature 下的 `kvm` 暴露出来。参考 `crates/mimobox-vm/src/lib.rs:1-19`。

对外真正的抽象不是单独的 `Vm trait`，而是 `mimobox_core::Sandbox`：

- `Sandbox::new(config)`  
- `Sandbox::execute(&mut self, cmd)`  
- `Sandbox::destroy(self)`  

参考 `crates/mimobox-core/src/sandbox.rs:97-103`。

`MicrovmSandbox` 实现了这个 trait，并把底层 backend 封装在 `BackendHandle` 里。参考 `crates/mimobox-vm/src/vm.rs:135-191`、`crates/mimobox-vm/src/vm.rs:193-309`。

控制流是：

1. `MicrovmSandbox::new()` / `new_with_base()` 做平台检查和 `MicrovmConfig::validate()`。参考 `crates/mimobox-vm/src/vm.rs:210-239`。
2. `BackendHandle::create()` 在 Linux + `kvm` feature 下直接调用 `KvmBackend::create_vm()`。参考 `crates/mimobox-vm/src/vm.rs:142-158`。
3. `Sandbox::execute()` 把命令转交给 backend 的 `run_command()`。参考 `crates/mimobox-vm/src/vm.rs:272-301`。

### 1.2 `MicrovmConfig` 在启动前做了什么

`MicrovmConfig` 只校验了四类事情：

1. `vcpu_count != 0`
2. `memory_mb >= 64`
3. `kernel_path` / `rootfs_path` 非空
4. `kernel_path` / `rootfs_path` 文件存在

参考 `crates/mimobox-vm/src/vm.rs:36-79`。

这一步没有检查：

- 内核是否包含 KVM guest 所需驱动
- rootfs 是否包含 guest agent
- 通信协议所需的用户态二进制是否存在

这些都直接影响后续通信方案可行性。

### 1.3 `KvmBackend::create_vm()` 的完整控制流

`KvmBackend::create_vm()` 是当前真实的 backend 入口。完整控制流如下。

#### 第 1 步：校验配置并创建 shim 对象

代码：

- `config.validate()?`：`crates/mimobox-vm/src/kvm.rs:102`
- `let kvm = Kvm::new()`：`crates/mimobox-vm/src/kvm.rs:109`
- `let vm_fd = kvm.create_vm()`：`crates/mimobox-vm/src/kvm.rs:110`

注意这里调用的不是官方 crate 的真实 `/dev/kvm` 打开和 ioctl，而是 vendor shim：

- `Kvm::new()` 只是 `Ok(Self)`，没有任何系统调用。参考 `vendor/kvm-ioctls/src/lib.rs:36-39`
- `Kvm::create_vm()` 只是创建一个 `Arc<Mutex<VmState>>`。参考 `vendor/kvm-ioctls/src/lib.rs:41-45`

所以从这一步开始，`kvm` / `vm_fd` 就已经不是“真实 KVM fd”。

#### 第 2 步：分配 guest memory

代码：

- `GuestMemoryMmap::from_ranges(&[(GuestAddress(0), config.memory_bytes()?)])`：`crates/mimobox-vm/src/kvm.rs:111-113`

数据流：

1. `memory_mb` 先被换算成字节数。参考 `crates/mimobox-vm/src/vm.rs:37-44`
2. `GuestMemoryMmap::from_ranges()` 创建一块从 GPA 0 开始的连续内存。参考 `vendor/vm-memory/src/lib.rs:50-75`

但这个 shim 的实现不是 `mmap` 出来的 guest RAM，而是一个 `Vec<u8>`：

- `bytes: Arc<Mutex<Vec<u8>>>`：`vendor/vm-memory/src/lib.rs:44-48`

也就是说，这里的“guest memory”本质上只是 host 内存缓冲区。

#### 第 3 步：读入 kernel 和 rootfs

代码：

- `kernel_bytes = fs::read(&config.kernel_path)`：`crates/mimobox-vm/src/kvm.rs:115`
- `rootfs_bytes = fs::read(&config.rootfs_path)`：`crates/mimobox-vm/src/kvm.rs:116`
- `validate_initrd_image(&rootfs_bytes)`：`crates/mimobox-vm/src/kvm.rs:117`

`validate_initrd_image()` 只检查 gzip magic，不检查 cpio 内容，也不检查 guest 用户态程序。参考 `crates/mimobox-vm/src/kvm.rs:580-587`。

#### 第 4 步：创建命令事件对象

代码：

- `let command_event = EventFd::new(0)`：`crates/mimobox-vm/src/kvm.rs:119`

这里的 `EventFd` 是 vendor shim 里唯一实现得比较接近真实系统调用的模块。它确实调用了 Linux `eventfd(2)`。参考 `vendor/vmm-sys-util/src/eventfd.rs:20-35`。

但后续 `mimobox-vm` 只对它做了 `write(1)`，没有任何一端去 `read()`，也没有把它绑定到 `ioeventfd` / `irqfd` / virtio 队列。参考 `crates/mimobox-vm/src/kvm.rs:361`，以及 `vendor/vmm-sys-util/src/eventfd.rs:37-50`。

#### 第 5 步：创建 vCPU 句柄

代码：

- 循环调用 `vm_fd.create_vcpu(vcpu_index)`：`crates/mimobox-vm/src/kvm.rs:121-125`

shim 实现同样只是把 vCPU id 记录到内存里：

- `VmFd::create_vcpu()`：`vendor/kvm-ioctls/src/lib.rs:54-65`
- `VcpuFd` 只有一个 `id()` 方法：`vendor/kvm-ioctls/src/lib.rs:76-85`

这里没有：

- `get_vcpu_mmap_size`
- `VcpuFd::run`
- `set_regs` / `set_sregs`
- `set_cpuid2`

也就是说 vCPU 只有“编号”，没有“可运行状态”。

#### 第 6 步：填充 backend 运行时字段

`KvmBackend` 初始化时把若干关键字段设为默认值：

- `transport = KvmTransport::Serial`：`crates/mimobox-vm/src/kvm.rs:136`
- `boot_params_addr = 0x7000`：`crates/mimobox-vm/src/kvm.rs:144`
- `cmdline_addr = 0x20000`：`crates/mimobox-vm/src/kvm.rs:145`
- `initrd_addr = 0`：`crates/mimobox-vm/src/kvm.rs:146`
- `guest_booted = false`：`crates/mimobox-vm/src/kvm.rs:147`
- `serial_buffer = Vec::new()`：`crates/mimobox-vm/src/kvm.rs:148`

这里有两个直接影响通信的事实：

1. `transport` 虽然有 `Serial` / `Vsock` 两个枚举值，但当前初始化永远是 `Serial`。参考 `crates/mimobox-vm/src/kvm.rs:38-41`、`crates/mimobox-vm/src/kvm.rs:136`
2. `KvmTransport::Vsock` 在当前代码里没有任何实际分支使用。仓库检索只有定义和字段赋值，没有实际逻辑。

#### 第 7 步：装载内核 ELF

`load_kernel()` 做的是“把 ELF 的 PT_LOAD 段拷到 guest memory”，并记录入口点和装载上界。参考 `crates/mimobox-vm/src/kvm.rs:181-257`。

数据流：

1. 解析 ELF header 里的 `entry_point`、`phoff`、`phentsize`、`phnum`。参考 `crates/mimobox-vm/src/kvm.rs:188-191`
2. `validate_elf_header()` 检查 ELF magic、64 位、小端、program header 表边界。参考 `crates/mimobox-vm/src/kvm.rs:193`、`crates/mimobox-vm/src/kvm.rs:589-617`
3. 遍历 `PT_LOAD` 段，把 `segment_bytes` 写入 `guest_memory`。参考 `crates/mimobox-vm/src/kvm.rs:197-243`
4. 记录 `LoadedKernel { entry_point, high_watermark }`。参考 `crates/mimobox-vm/src/kvm.rs:252-255`

这一步只是**拷内存**，还不是**设置 vCPU 启动状态**。

#### 第 8 步：装载 initrd

`load_initrd()` 用“内核装载上界 + 0x20_0000 再按 4K 对齐”的方式计算 initrd 地址，然后直接把整个 `rootfs_bytes` 拷进 guest memory。参考 `crates/mimobox-vm/src/kvm.rs:259-270`。

这里没有把 initrd 注册为单独内存槽，也没有做真正的设备映射。

#### 第 9 步：写入 zero page / boot_params / cmdline

`write_boot_params()` 做了 Linux x86 boot protocol 的一部分准备：

- 把 `DEFAULT_CMDLINE` 写到 `cmdline_addr`：`crates/mimobox-vm/src/kvm.rs:275-277`
- 构造一个 4KiB zero page：`crates/mimobox-vm/src/kvm.rs:279`
- 写入 `code32_start`、`ramdisk_image`、`ramdisk_size`、`cmd_line_ptr`：`crates/mimobox-vm/src/kvm.rs:282-320`
- 写入一条 E820 RAM 区间：`crates/mimobox-vm/src/kvm.rs:322-328`
- 最终写回 `boot_params_addr`：`crates/mimobox-vm/src/kvm.rs:330`

默认内核命令行是：

```text
console=ttyS0 panic=-1 rdinit=/init
```

参考 `crates/mimobox-vm/src/kvm.rs:16`。

这表明设计意图是“guest 走串口控制台 + initrd 里的 `/init` 作为初始进程”。

#### 第 10 步：写入 rootfs 元信息

`load_rootfs_metadata()` 把一段纯文本元信息写到固定 guest 地址 `0x30000`，内容包括 rootfs 路径、大小、initrd 地址、cmdline 地址和 transport。参考 `crates/mimobox-vm/src/kvm.rs:333-344`。

这是一个用于测试 / 观测的 host side metadata 注入，不是 guest 通信协议。

#### 第 11 步：将 lifecycle 标为 Ready

最后，`create_vm()` 把 lifecycle 从 `Created` 改为 `Ready`。参考 `crates/mimobox-vm/src/kvm.rs:155-156`。

### 1.4 boot 阶段到底做了什么

`boot()` 的代码非常短：

- 检查 `lifecycle == Ready`：`crates/mimobox-vm/src/kvm.rs:165-168`
- 调用 `run_vcpu_loop(&[SerialWrite(SERIAL_BOOT_BANNER), Hlt])`：`crates/mimobox-vm/src/kvm.rs:170-174`
- 把 `guest_booted = true`：`crates/mimobox-vm/src/kvm.rs:175-177`

关键点在于：

1. `SERIAL_BOOT_BANNER` 是 host 常量 `b"mimobox guest booted\n"`。参考 `crates/mimobox-vm/src/kvm.rs:34`
2. `run_vcpu_loop()` 只识别两种**合成事件**：`SerialWrite(bytes)` 和 `Hlt`。参考 `crates/mimobox-vm/src/kvm.rs:68-71`、`crates/mimobox-vm/src/kvm.rs:401-422`
3. `SerialWrite(bytes)` 只是把字节追加到 `serial_buffer`，并记录 `KvmExitReason::Io`。参考 `crates/mimobox-vm/src/kvm.rs:407-410`
4. `Hlt` 直接返回 `KvmExitReason::Hlt`。参考 `crates/mimobox-vm/src/kvm.rs:411-414`

所以当前 `boot()` 不是“让 vCPU 开始执行内核”，而是“向串口缓存写入一行固定文本，然后返回 HLT”。

### 1.5 当前 rootfs 实际会做什么

`scripts/build-rootfs.sh` 生成的 rootfs 非常简单：

1. 下载静态 BusyBox。参考 `scripts/build-rootfs.sh:37-45`
2. 创建 `sh/echo/cat/ls/...` 等 BusyBox applet 链接。参考 `scripts/build-rootfs.sh:50-52`
3. 写入 `/init` 脚本：

```sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo "mimobox-kvm: init OK"
exec sh
```

参考 `scripts/build-rootfs.sh:62-69`。

这个 rootfs **没有**：

- guest agent
- vsock 服务端
- 串口协议守护进程
- 从共享内存读取命令的程序

也就是说，即使未来变成真实 KVM boot，当前 rootfs 也没有任何“接命令并返回结果”的用户态逻辑。

### 1.6 当前端到端测试实际验证了什么

`crates/mimobox-vm/tests/kvm_e2e.rs` 主要验证三件事：

1. `test_kvm_vm_boots()`：`boot()` 返回 `Hlt`，且串口输出包含 `"mimobox guest booted"`。参考 `crates/mimobox-vm/tests/kvm_e2e.rs:75-88`
2. `test_kvm_vm_executes()`：执行 `echo hello` 返回 `hello\n`。参考 `crates/mimobox-vm/tests/kvm_e2e.rs:90-103`
3. `test_kvm_snapshot_restore()`：快照恢复后还能继续 `echo`。参考 `crates/mimobox-vm/tests/kvm_e2e.rs:105-135`

这里最关键的信号是：

- rootfs `/init` 实际应该打印的是 `"mimobox-kvm: init OK"`，参考 `scripts/build-rootfs.sh:67`
- 测试却只断言 `"mimobox guest booted"`，而这正是 host 注入的 `SERIAL_BOOT_BANNER`，参考 `crates/mimobox-vm/src/kvm.rs:34`、`crates/mimobox-vm/tests/kvm_e2e.rs:80-85`

所以当前 E2E 验证的是**host 模拟启动横幅**，不是“guest 内核真的跑起来并执行了 `/init`”。

---

## 2. `emulate_guest_command` stub 的局限

### 2.1 当前实现到底做了什么

`run_command()` 的控制流是：

1. 若未 boot，则先调用 `boot()`。参考 `crates/mimobox-vm/src/kvm.rs:355-357`
2. `encode_command_payload(cmd)` 把命令编码成 `argc + len + bytes`。参考 `crates/mimobox-vm/src/kvm.rs:360`、`crates/mimobox-vm/src/kvm.rs:664-675`
3. `command_event.write(1)`。参考 `crates/mimobox-vm/src/kvm.rs:361`
4. 把编码后的 payload 存入 `last_command_payload`。参考 `crates/mimobox-vm/src/kvm.rs:362`
5. 直接在 host 侧调用 `emulate_guest_command(cmd)` 生成结果。参考 `crates/mimobox-vm/src/kvm.rs:364`
6. 如果结果有 `stdout`，就把 `stdout` 再通过 `run_vcpu_loop()` 伪装成一次串口输出 + HLT。参考 `crates/mimobox-vm/src/kvm.rs:365-371`

`emulate_guest_command()` 自身只支持三种情况：

1. `echo` / `/bin/echo`：拼参数并加换行，返回 `exit_code = 0`
2. `true` / `/bin/true`：返回空输出，`exit_code = 0`
3. 其他命令：`stderr = "guest 命令尚未实现: ..."`，`exit_code = 127`

参考 `crates/mimobox-vm/src/kvm.rs:471-501`。

### 2.2 它缺什么

缺失项不是“还没补几个命令”，而是**整个 guest 执行闭环都不存在**。

#### 1. 命令 payload 根本没有进入 guest

`encode_command_payload()` 的结果只写到了 `self.last_command_payload`，没有写入 guest memory，没有放进 virtqueue，也没有通过串口逐字节送到 guest。参考 `crates/mimobox-vm/src/kvm.rs:360-363`。

所以 guest 根本看不到命令。

#### 2. `command_event` 没有消费者

当前代码只做了 `command_event.write(1)`，但：

- `mimobox-vm` 里没有任何 `read()`
- 没有 `ioeventfd`
- 没有 `irqfd`
- 没有设备线程
- guest 侧也没有映射这个 eventfd 的机制

证据：

- 写入发生在 `crates/mimobox-vm/src/kvm.rs:361`
- `EventFd` 能做 `read()` / `try_clone()`，但 `mimobox-vm` 没用。参考 `vendor/vmm-sys-util/src/eventfd.rs:37-50`

#### 3. 没有真实 vCPU 执行

当前没有任何 `VcpuFd::run()`，因为 shim 里压根没有这个 API；`run_vcpu_loop()` 只是遍历一组 host 构造出来的 `SyntheticVmExit`。参考 `crates/mimobox-vm/src/kvm.rs:401-422`，以及 `vendor/kvm-ioctls/src/lib.rs:54-85`。

#### 4. 没有寄存器初始化，也没有真正 boot 到 guest userspace

虽然 `load_kernel()` 解析了 ELF entry point，`write_boot_params()` 也写了 `code32_start`，但代码从未设置 vCPU 的 `RIP`、`RSP`、`SREGS`、`CPUID`。参考 `crates/mimobox-vm/src/kvm.rs:188-193`、`crates/mimobox-vm/src/kvm.rs:284-287`。

因此 guest 不可能真的开始执行内核入口。

#### 5. `stdout` 只是 host 侧回灌到 `serial_buffer`

`stdout` 若非空，会被包装成 `SyntheticVmExit::SerialWrite(&result.stdout)`。参考 `crates/mimobox-vm/src/kvm.rs:365-369`。

也就是说：

- 串口输出不是 guest 设备发出来的
- 只是 host 把 stub 结果拷进了 `serial_buffer`

#### 6. `stderr` 甚至不会进入串口缓冲

当前代码只把 `result.stdout` 写回 `serial_buffer`，`stderr` 只留在 `GuestCommandResult` 里返回。参考 `crates/mimobox-vm/src/kvm.rs:364-375`。

所以串口也不是一个完整的 stdout/stderr 通道。

#### 7. 没有超时、没有信号、没有进程语义

`GuestCommandResult` 里有 `timed_out` 字段，但 stub 永远写 `false`。参考 `crates/mimobox-vm/src/kvm.rs:476-480`、`crates/mimobox-vm/src/kvm.rs:486-493`、`crates/mimobox-vm/src/kvm.rs:495-500`。

当前也没有：

- guest PID
- wait/kill
- shell 管道
- 环境变量
- 工作目录
- 文件描述符重定向

#### 8. 快照不是“真实 VM 设备状态快照”

`snapshot_state()` 序列化的是：

- vCPU id 列表
- `guest_booted`
- `last_exit_reason`
- `last_command_payload`
- `serial_buffer`
- `entry_point/high_watermark/boot_params_addr/cmdline_addr/initrd_addr`

参考 `crates/mimobox-vm/src/kvm.rs:378-381`、`crates/mimobox-vm/src/kvm.rs:504-517`。

这不是 KVM vCPU register state，也不是设备状态，只是当前 skeleton 的 host 运行时状态。

### 2.3 为什么它不能用于生产

综合上面几点，当前 stub 不能用于生产的根因是：

1. 它不执行 guest 内任何代码
2. 它不依赖 guest rootfs 里的程序
3. 它不经过真实设备或 hypervisor 通道
4. 它不具备命令执行的完整语义
5. 它对测试是“伪阳性友好”的，`echo` / `true` 这类命令很容易看起来像真执行

所以当前 `test_kvm_vm_executes()` 通过，不能说明“VM 内命令执行已经可用”，只能说明“host stub 能返回和 BusyBox `echo` 类似的输出”。参考 `crates/mimobox-vm/tests/kvm_e2e.rs:90-103`。

---

## 3. vendor shim 的能力边界

下面的表只基于实际读到的 shim 代码。

### 3.1 `kvm-ioctls` shim

`vendor/kvm-ioctls/src/` 下只有一个 `lib.rs` 文件，说明当前 shim 没有隐藏子模块。仓库文件列表可见 `vendor/kvm-ioctls/src/lib.rs` 是唯一源码文件。

| 类别 | 已实现 API | 代码证据 | 缺失 / 未实现 API | 对通信方案的影响 |
|---|---|---|---|---|
| KVM 入口 | `Kvm::new()` | `vendor/kvm-ioctls/src/lib.rs:36-39` | 打开 `/dev/kvm` 的真实逻辑未实现 | 现在拿到的不是内核 KVM handle |
| VM 创建 | `Kvm::create_vm()` | `vendor/kvm-ioctls/src/lib.rs:41-45` | `set_user_memory_region`、`create_irq_chip`、`create_pit2`、`set_tss_address`、`set_identity_map_addr` | 无法建立真实 guest 内存槽和 IRQ 基础设施 |
| vCPU 创建 | `VmFd::create_vcpu()` | `vendor/kvm-ioctls/src/lib.rs:54-65` | `get_vcpu_mmap_size`、`VcpuFd::run()`、`set_regs/get_regs`、`set_sregs/get_sregs`、`set_cpuid2` | 无法启动 vCPU，也无法设置启动寄存器状态 |
| 基础查询 | `VmFd::vcpu_count()`、`VcpuFd::id()` | `vendor/kvm-ioctls/src/lib.rs:67-73`、`vendor/kvm-ioctls/src/lib.rs:82-85` | exit reason 解码、KVM capability 查询、device 创建 | 无法做 device model、virtio、vsock、串口 IO 拦截 |

补充说明：

1. 这个 shim **完全没有**任何 `ioctl` 调用；它只是内存里的状态容器。参考 `vendor/kvm-ioctls/src/lib.rs:27-85`。
2. 在 `vendor/kvm-ioctls/src` 中检索 `set_user_memory_region`、`run(`、`set_regs`、`set_sregs`、`create_irq_chip`、`register_ioevent`、`register_irqfd`、`create_device` 等关键 API，结果为空。

### 3.2 `vm-memory` shim

`vendor/vm-memory/src/` 也只有一个 `lib.rs` 文件。

| 类别 | 已实现 API | 代码证据 | 缺失 / 未实现 API | 对通信方案的影响 |
|---|---|---|---|---|
| 地址类型 | `GuestAddress(u64)`、`raw_value()` | `vendor/vm-memory/src/lib.rs:8-16` | 更高层的 region/translation API | 只能做非常原始的 GPA 偏移操作 |
| 内存创建 | `GuestMemoryMmap::from_ranges()` | `vendor/vm-memory/src/lib.rs:50-75` | `MmapRegion`、file-backed region、多 region 管理、atomic guest memory | 不能映射真实 KVM userspace memory region，也不利于设备共享内存 |
| 字节读写 | `Bytes::write_slice()`、`read_slice()` | `vendor/vm-memory/src/lib.rs:36-40`、`vendor/vm-memory/src/lib.rs:122-141` | `read_obj` / `write_obj`、volatile memory、bitmap / dirty tracking | 做设备寄存器和快照增量同步会很吃力 |
| 快照辅助 | `dump()`、`restore()` | `vendor/vm-memory/src/lib.rs:81-103` | region 级别快照、脏页跟踪 | 只能全量复制整块内存 |

边界非常明确：

1. 这是一个 `Vec<u8>` 包装，不是实际 `mmap` 到 KVM 的 guest RAM。参考 `vendor/vm-memory/src/lib.rs:43-48`
2. 当前只支持**连续** guest memory range，不能表达真实 microVM 常见的多段内存布局。参考 `vendor/vm-memory/src/lib.rs:56-68`

### 3.3 `vmm-sys-util` shim

`vendor/vmm-sys-util/src/lib.rs` 只导出两个模块：`errno` 和 `eventfd`。参考 `vendor/vmm-sys-util/src/lib.rs:1-13`。目录里也确实只有 `lib.rs` 和 `eventfd.rs` 两个源码文件。

| 类别 | 已实现 API | 代码证据 | 缺失 / 未实现 API | 对通信方案的影响 |
|---|---|---|---|---|
| errno | `errno::Error(pub i32)` | `vendor/vmm-sys-util/src/lib.rs:6-10` | 更完整错误包装和工具函数 | 影响不大 |
| 事件通知 | `EventFd::new/write/read/try_clone`，以及 `AsRawFd/FromRawFd/IntoRawFd` | `vendor/vmm-sys-util/src/eventfd.rs:20-74` | `epoll`、`timerfd`、`signalfd`、`poll`、终端/控制 socket 辅助 | 没法搭一个完整的设备事件循环 |

这里最重要的结论是：

- `EventFd` 本身是可用的
- 但只有 `EventFd` 还不够做 vsock / virtio / UART 设备模型
- 缺的是“事件多路复用 + KVM exit loop + device dispatch”

### 3.4 汇总判断

| shim | 当前定位 | 适合做什么 | 不适合做什么 |
|---|---|---|---|
| `kvm-ioctls` | 纯骨架占位 | 让 `mimobox-vm` 在离线环境里先编译、先搭生命周期结构 | 真实 KVM 启动、设备模拟、vsock、串口 IO |
| `vm-memory` | host 侧内存缓冲区 | 让内核 / initrd / boot params 有地方可写，支持假的快照 | 真实 guest RAM 管理、脏页跟踪、设备共享内存 |
| `vmm-sys-util` | 基础 `eventfd` 可用 | 未来真实设备模型里的一个原语 | 单独支撑完整通信系统 |

---

## 4. 通信方案可行性评估

这一节的结论严格限定在**当前 shim 和当前 guest rootfs** 条件下。

### 4.1 `vsock` 通信是否可行

结论：**当前不可行。**

#### 需要哪些能力

如果要做真实 `vsock`，至少需要：

1. 真实的 KVM VM / vCPU 运行链路  
   需要 `set_user_memory_region`、`VcpuFd::run()`、寄存器初始化、exit 处理。
2. 真实的 virtio 设备栈  
   至少要有 virtio transport、virtqueue、kick/notify、中断注入。
3. host 侧事件机制  
   通常需要 `eventfd` + `ioeventfd` / `irqfd` + 事件循环。
4. guest 侧用户态 agent  
   rootfs 里必须有能监听 `AF_VSOCK` 的进程。

#### 当前卡在哪里

1. `kvm-ioctls` shim 没有任何 `run` / memory slot / irq / device API。参考 `vendor/kvm-ioctls/src/lib.rs:36-85`
2. `KvmTransport::Vsock` 只是一个枚举值，当前没有使用路径。参考 `crates/mimobox-vm/src/kvm.rs:38-41`、`crates/mimobox-vm/src/kvm.rs:136`
3. `run_vcpu_loop()` 不是真实 exit loop。参考 `crates/mimobox-vm/src/kvm.rs:401-422`
4. rootfs 只会 `exec sh`，没有任何 vsock 服务进程。参考 `scripts/build-rootfs.sh:62-69`
5. guest 内核是否启用了 `CONFIG_VSOCKETS` / `CONFIG_VIRTIO_VSOCKETS`，**当前未确认**，因为本次没有检查 `vmlinux` 配置。

#### 评估

在当前代码基础上，`vsock` 不是“再补几百行”能完成的事情，而是要先补全整套真实 KVM + virtio 基础设施。

### 4.2 串口通信是否可行

结论：**当前也不可行，但它比 `vsock` 更适合作为第一阶段 bring-up 方案。**

#### 需要哪些能力

最小可用串口控制通道，至少要有：

1. 真实 `KVM_RUN` 循环
2. 对串口相关 `KVM_EXIT_IO` 的处理
3. 一个最小 UART/16550 设备模型，或者等价的 PIO 模拟
4. guest 侧读取 / 写回串口的进程

如果还想做得更像生产系统，还要有：

5. 中断支持
6. 协议 framing
7. 控制通道和 console log 的隔离

#### 当前卡在哪里

1. `DEFAULT_CMDLINE` 虽然写了 `console=ttyS0`，但当前没有真实串口设备。参考 `crates/mimobox-vm/src/kvm.rs:16`
2. `serial_buffer` 只是 host 内存缓冲，不是 UART backend。参考 `crates/mimobox-vm/src/kvm.rs:92`、`crates/mimobox-vm/src/kvm.rs:160-162`
3. `run_vcpu_loop()` 处理的是 host 构造的 `SyntheticVmExit::SerialWrite`，不是 guest 触发的串口 IO exit。参考 `crates/mimobox-vm/src/kvm.rs:68-71`、`crates/mimobox-vm/src/kvm.rs:401-422`
4. rootfs `/init` 最后是 `exec sh`，没有读命令协议的 agent。参考 `scripts/build-rootfs.sh:62-69`

#### 为什么串口仍然更适合作为第一阶段方案

因为它比 `vsock` 少掉整套 virtio/vsock 设备栈。只要真实 `KVM_RUN` 能跑起来，理论上就可以先靠 PIO exit 做一个最小 UART 模拟，把命令和结果从串口流里搬过去。

但这里有一个设计风险必须正视：

- 现在内核命令行把 `ttyS0` 作为 console。参考 `crates/mimobox-vm/src/kvm.rs:16`
- 如果命令协议也走同一条串口，boot log、shell 提示符、命令结果会混在一起

所以即使未来选择串口方案，也应当：

1. 用第二路 UART 做控制通道，或
2. 只把 `ttyS0` 用作 bring-up/debug，不把它当最终生产协议

### 4.3 其他方案

#### 方案 A：共享内存 mailbox

结论：**当前不可行，不建议作为首个方案。**

原因：

1. 当前 `GuestMemoryMmap` 只是 host `Vec<u8>`，不是正在运行 guest 可见的真实 memory slot。参考 `vendor/vm-memory/src/lib.rs:43-48`
2. 当前 guest rootfs 没有 agent，也没有读取固定 GPA 区域的用户态机制。参考 `scripts/build-rootfs.sh:62-69`
3. 即便未来接上真实 KVM，guest userspace 直接访问约定 GPA 也通常需要额外内核支持或 `/dev/mem` 类方案，工程性很差

共享内存更适合做“已经有 guest agent 之后的优化手段”，不适合做第一个通信通道。

#### 方案 B：hypercall / `vmcall`

结论：**当前不可行，而且不推荐作为主路径。**

原因：

1. 当前没有真实 vCPU run loop，自然不可能截获 hypercall exit。参考 `crates/mimobox-vm/src/kvm.rs:401-422`
2. shim 里没有任何与 hypercall / exit decode 相关的 API。参考 `vendor/kvm-ioctls/src/lib.rs:36-85`
3. 从 guest userspace 直接触发 hypercall 并不自然，通常需要内核支持或特权代码

这条路线的心智负担和调试成本都比串口高，不适合作为 P0。

#### 方案 C：virtio-console / virtio-serial

结论：**中长期可行，但在当前代码基础上工作量接近 `vsock`，不适合先于真实 KVM 基础设施落地。**

原因：

1. 它同样需要 virtio transport、队列、事件通知、中断注入
2. 当前缺的底层能力和 `vsock` 基本同级

### 4.4 综合判断

| 方案 | 当前 shim 下是否可行 | 缺口级别 | 备注 |
|---|---|---|---|
| `vsock` | 不可行 | 极高 | 先缺真实 KVM，再缺 virtio-vsock |
| 串口 | 不可行 | 高 | 但是真实 KVM 打通后，它是最小 bring-up 路径 |
| 共享内存 mailbox | 不可行 | 高 | guest 侧访问模型很差 |
| hypercall | 不可行 | 极高 | 调试成本高，不适合作为主路径 |
| virtio-console | 不可行 | 极高 | 与 `vsock` 一样先要完整 virtio 栈 |

---

## 5. 替换 shim 为真正 rust-vmm crate 的工作量评估

先看仓库依赖形态：

- workspace 依赖版本已经指向真实 crate 版本：`kvm-ioctls = "0.19"`、`vm-memory = "0.16"`、`vmm-sys-util = "0.12"`。参考 `Cargo.toml:44-46`
- 但 `[patch.crates-io]` 把它们重定向到了 `vendor/` 下的本地 shim。参考 `Cargo.toml:49-52`

这意味着：

1. Cargo 层面的“切回真 crate”动作本身不重
2. 真正重的是 `crates/mimobox-vm/src/kvm.rs` 当前基本是 skeleton，接不住真实 API

### 5.1 哪些 shim 需要替换

| shim | 是否必须替换 | 原因 |
|---|---|---|
| `kvm-ioctls` | 必须 | 当前没有真实 KVM ioctl、没有 `run`、没有 memory slot、没有 irq/device API |
| `vm-memory` | 必须 | 当前只是 `Vec<u8>`，不能代表真实 guest RAM 和 memory slot |
| `vmm-sys-util` | 建议一起替换 | 当前只有 `eventfd`，未来做设备事件循环通常还需要更多系统工具 |

### 5.2 预计改动范围

| 改动点 | 预计范围 | 主要文件 |
|---|---|---|
| Cargo 依赖切换 | 小 | `Cargo.toml` |
| KVM 生命周期重写 | 极大 | `crates/mimobox-vm/src/kvm.rs` |
| guest memory / 内存槽接入 | 大 | `crates/mimobox-vm/src/kvm.rs` |
| vCPU 初始化（regs/sregs/cpuid） | 大 | `crates/mimobox-vm/src/kvm.rs` |
| 真实 exit loop | 极大 | `crates/mimobox-vm/src/kvm.rs` |
| 串口 / vsock 设备模型 | 极大 | `crates/mimobox-vm/src/kvm.rs` + 新模块 |
| guest rootfs 注入 agent | 中到大 | `scripts/build-rootfs.sh` |
| 测试改造 | 中 | `crates/mimobox-vm/tests/kvm_e2e.rs` |
| 快照格式调整 | 中 | `crates/mimobox-vm/src/kvm.rs`、`crates/mimobox-vm/src/snapshot.rs` |

### 5.3 为什么 `kvm.rs` 会是最大改造面

`kvm.rs` 当前 788 行里，核心执行链路几乎全部是 synthetic 逻辑：

- `create_vm()` 虽然有“像 KVM”的字段名，但底层对象是 shim。参考 `crates/mimobox-vm/src/kvm.rs:98-156`
- `boot()` 是固定 banner + HLT。参考 `crates/mimobox-vm/src/kvm.rs:165-179`
- `run_command()` 是 host stub。参考 `crates/mimobox-vm/src/kvm.rs:347-375`
- `run_vcpu_loop()` 不是真实 run loop。参考 `crates/mimobox-vm/src/kvm.rs:401-422`

因此这不是“局部替换几个 API 名称”的工作，而是**大比例重写**。

### 5.4 主要风险点

#### 1. Linux boot protocol 只做了一半

当前只做了 ELF 段装载和 boot params 写入，没做 vCPU register/sregs/cpuid 初始化。参考 `crates/mimobox-vm/src/kvm.rs:181-330`。

切到真实 KVM 后，这块是第一个硬门槛。

#### 2. 通信方案会反向要求 rootfs 改造

当前 rootfs 只有 BusyBox + `/init -> sh`。参考 `scripts/build-rootfs.sh:50-69`。

无论选串口还是 `vsock`，都需要把 guest agent 打进 rootfs。

#### 3. 快照格式会失真

现在 `snapshot_state()` 只保存 skeleton 运行时状态。参考 `crates/mimobox-vm/src/kvm.rs:504-517`。

接入真实 KVM 后，至少要考虑：

- vCPU regs/sregs/fpu/xsave
- 设备状态
- 中断状态
- 队列状态

当前快照格式大概率需要升级版本。

#### 4. 测试将从“伪成功”转为“真失败”

现在 `kvm_e2e` 能通过，是因为 `echo` 是 stub。参考 `crates/mimobox-vm/tests/kvm_e2e.rs:90-103`。

一旦切成真实执行，测试会立刻暴露：

- guest 根本没有 agent
- 串口 / `vsock` 没有连起来
- boot 过程不完整

### 5.5 粗略工作量估算

下面给的是“单名熟悉 Rust、Linux 虚拟化、rust-vmm 的工程师”的量级估计：

| 目标 | 估计工作量 |
|---|---|
| 仅把 Cargo 从 shim 切回真实 crate 并修到能编译 | 1-2 天 |
| 打通真实 KVM 启动（内存槽、寄存器、真实 run loop） | 1-2 周 |
| 加 guest agent，完成最小串口命令闭环 | 再加 1-2 周 |
| 完成可维护的 `vsock` 正式通道 | 再加 2-4 周 |

换句话说：

- **“替换 shim”本身不重**
- **“让真实 VM 通信跑起来”才是主要工作量**

---

## 6. 推荐实现路径

## 明确结论

**推荐方案：先停止在当前 shim 上继续堆通信能力；先切换到真实 rust-vmm crate，完成真实 KVM 基础链路；P0 用串口打通最小可用控制面，P1 再升级到 `vsock` 作为正式生产通信通道。**

这个结论不是折中，而是当前代码现实下最稳的路线：

1. 现在最大问题不是“选串口还是 `vsock`”，而是**根本没有真实 VM 执行链路**
2. 在真实 KVM 没打通前，直接做 `vsock` 只会把复杂度堆到最难的地方
3. 串口虽然不是最终形态，但它对底层要求最低，最适合先验证“guest agent 真能收命令并回结果”

### 6.1 为什么不是“直接上 vsock”

因为 `vsock` 需要三层东西同时成立：

1. 真实 KVM run loop
2. virtio 设备栈
3. guest agent

而当前三层都没有。

如果此时直接做 `vsock`，你会同时调试：

- boot protocol
- vCPU 初始化
- exit loop
- virtio 队列
- 事件通知
- guest 用户态服务

这会显著拉高不确定性。

### 6.2 推荐路线图

#### 阶段 0：停止在 shim 上扩展通信

动作：

1. 保留当前 skeleton 作为研究骨架
2. 不再往 `emulate_guest_command()` 上追加新命令
3. 把“当前不是实际 guest 执行”的事实写进文档和测试说明

原因：

再往 stub 上加能力，只会增加后续替换时的无效资产。

#### 阶段 1：切回真实 rust-vmm crate，完成真实 KVM bring-up

动作：

1. 去掉 `[patch.crates-io]` 对三个 shim 的覆盖。参考 `Cargo.toml:49-52`
2. 用真实 `kvm-ioctls` 重写 `KvmBackend::create_vm()` 的底层资源创建
3. 用真实 `vm-memory` 建立 guest memory region，并调用 KVM memory slot 注册
4. 补全 vCPU 的 regs/sregs/cpuid 初始化
5. 把 `run_vcpu_loop()` 改成真实 `KVM_RUN` 循环

验收标准：

1. 不再依赖 `SERIAL_BOOT_BANNER`
2. 串口里能看到 rootfs `/init` 打印的 `mimobox-kvm: init OK`

这里的验收标准直接来自现有 rootfs 脚本。参考 `scripts/build-rootfs.sh:62-69`。

#### 阶段 2：把 rootfs 改造成“guest agent rootfs”

动作：

1. 在 `build-rootfs.sh` 里加入一个静态 guest agent
2. `/init` 不再直接 `exec sh`，而是拉起 agent
3. agent 定义固定协议：接命令、执行、返回 stdout/stderr/exit code

验收标准：

1. guest 内真实执行 `/bin/echo hello`
2. 未实现命令的返回来自 guest，而不是来自 host stub

#### 阶段 3：P0 先用串口通道打通闭环

动作：

1. 建一个最小 UART/串口设备模型
2. host 通过串口下发命令帧
3. guest agent 从串口读命令、执行后写回结果

注意事项：

1. 不建议把正式协议和 `ttyS0` console 混用
2. 可以先把串口方案限定为 bring-up / 调试控制面

验收标准：

1. `kvm_e2e` 不再依赖 `emulate_guest_command()`
2. 串口里能收发结构化协议，不只是 log 文本

#### 阶段 4：P1 再上 `vsock`

动作：

1. 引入 virtio transport 和 `vsock` 设备模型
2. guest agent 改成 `AF_VSOCK` 服务
3. host 侧建立正式 RPC / stream 协议

理由：

1. `vsock` 更适合作为长期正式通信通道
2. 它不会和 console log 混流
3. 语义上更接近“host <-> guest 服务调用”

#### 阶段 5：最后再做快照一致性和性能优化

动作：

1. 升级 snapshot 格式，保存真实 vCPU / 设备状态
2. 基于真实通信通道重做 benchmark
3. 评估串口与 `vsock` 的冷启动 / 单次调用延迟

### 6.3 最终建议

如果目标是“尽快得到一个真实可工作的 VM 命令执行通道”，建议按下面的优先级做：

1. **第一优先级**：替换 shim，打通真实 KVM 启动
2. **第二优先级**：在 rootfs 中加入 guest agent
3. **第三优先级**：先用串口完成最小控制面闭环
4. **第四优先级**：再做 `vsock` 作为正式生产通道

不建议的路径：

1. 在现有 shim 上继续堆 `vsock`
2. 直接跳过串口 bring-up 去做完整 virtio-vsock
3. 以共享内存 mailbox 或 hypercall 作为 P0 主方案

---

## 附：本次分析中最关键的代码证据

| 主题 | 证据位置 |
|---|---|
| `mimobox-vm` 模块与导出 | `crates/mimobox-vm/src/lib.rs:1-19` |
| `MicrovmSandbox` 和 `Sandbox` 抽象 | `crates/mimobox-vm/src/vm.rs:142-309`、`crates/mimobox-core/src/sandbox.rs:97-103` |
| `KvmBackend::create_vm()` 生命周期骨架 | `crates/mimobox-vm/src/kvm.rs:98-156` |
| `boot()` 只是 synthetic banner + HLT | `crates/mimobox-vm/src/kvm.rs:165-179` |
| `run_command()` 走 host stub | `crates/mimobox-vm/src/kvm.rs:347-375` |
| `emulate_guest_command()` 只支持 `echo/true` | `crates/mimobox-vm/src/kvm.rs:471-501` |
| `run_vcpu_loop()` 不是真实 `KVM_RUN` | `crates/mimobox-vm/src/kvm.rs:401-422` |
| `kvm-ioctls` shim 只提供最小对象壳子 | `vendor/kvm-ioctls/src/lib.rs:1-85` |
| `vm-memory` shim 是 `Vec<u8>` | `vendor/vm-memory/src/lib.rs:42-141` |
| `vmm-sys-util` 只实现了 `EventFd` | `vendor/vmm-sys-util/src/lib.rs:1-13`、`vendor/vmm-sys-util/src/eventfd.rs:1-74` |
| rootfs 只启动 BusyBox shell，没有 guest agent | `scripts/build-rootfs.sh:50-80` |
| 当前 E2E 只验证 synthetic boot / stub echo | `crates/mimobox-vm/tests/kvm_e2e.rs:75-135` |

