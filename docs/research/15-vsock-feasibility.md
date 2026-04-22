# 15. vsock 数据面技术可行性研究

> 撰写日期：2026-04-22
>
> 适用范围：`mimobox` Linux/KVM microVM 后端，面向 host-guest 正式数据面替换方案。
>
> 当前代码基线：
> - `crates/mimobox-vm/src/kvm.rs` 仍使用自研 COM1/PIO 串口模拟作为命令通道。
> - `crates/mimobox-vm/guest/guest-init.c` 通过 `ioperm + inb/outb` 直接访问 COM1。
> - workspace 已引入 `kvm-ioctls = 0.19`、`vm-memory = 0.16`、`vmm-sys-util = 0.12.1`。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
|---|---|---|---|---|
| v1.0 | 2026-04-22 | 首次建立 vsock 数据面可行性研究 | 新增 | Codex |

## 术语表

| 术语 | 定义 |
|---|---|
| `AF_VSOCK` | Linux 的 VM socket 地址族，供 host 与 guest 以 CID + Port 方式通信 |
| `virtio-vsock` | guest 可见的 virtio 设备类型，承载 vsock 数据包 |
| `vhost-vsock` | Linux host 侧内核加速后端，VMM 通过 `/dev/vhost-vsock` 配置它 |
| `CID` | Context ID，vsock 地址中的“节点标识”；guest 通常取大于 2 的值，host 是保留 CID 2 |
| `UDS bridge` | Firecracker 风格的宿主侧 `AF_UNIX` 桥接，而不是直接暴露 `AF_VSOCK` |

## 文章内容大纲目录表

| 章节 | 标题 | 目的 |
|---|---|---|
| 1 | 结论摘要 | 先给出是否可做、推荐路线和主要工程量 |
| 2 | 当前架构基线 | 明确仓库现状与当前串口方案的限制 |
| 3 | rust-vmm 生态调研 | 回答 crate、仓库、设备模拟能力是否已存在 |
| 4 | KVM/Linux 实现路径 | 解释 `AF_VSOCK`、`virtio-vsock`、`vhost-vsock` 的关系 |
| 5 | 集成方案 | 结合当前 `KvmBackend`/guest init 设计落地路线 |
| 6 | 性能预期 | 比较 vsock 与串口的性能收益与边界 |
| 7 | 实施路线 | 分阶段给出最小上线方案 |
| 8 | 风险与开放问题 | 说明推进时的主要风险与待裁决事项 |
| 9 | 参考资料 | 保留可追溯证据链接 |

## 1. 结论摘要

结论先行：**vsock 作为 mimobox microVM 正式数据面是可行的，但工程量明显大于“把串口协议改成 socket 协议”。**

核心判断如下：

1. **从产品目标看，vsock 值得做。**
   当前串口方案已经证明命令控制面足够快，但它天然把 stdout/stderr 混在一条字节流里，而且对大输出不友好。vsock 提供标准 socket API、天然端口寻址、可维护的流语义，更适合作为正式数据面。

2. **从实现形态看，推荐路线是：`virtio-vsock front-end + /dev/vhost-vsock back-end`。**
   如果目标是“host 侧直接使用 `AF_VSOCK` 套接字收发命令”，那就不应该走 Firecracker 式 `AF_UNIX` bridge；应该让 `KvmBackend` 把 guest virtqueue 接到 Linux 的 `vhost-vsock` 内核后端上。

3. **当前代码的最大缺口不在 guest/host 应用层，而在 VMM 设备层。**
   现在的 `KvmBackend` 只有串口 PIO 模拟，`MMIO` 退出基本被当成空设备处理，这意味着要支持 vsock，实际上要先补齐一套最小 virtio transport/device 框架。

4. **对短命令延迟，vsock 不一定带来数量级改善；对大输出、流分离和可扩展性，收益会非常明显。**
   当前串口 P50 `763μs` 已经不慢，因此 vsock 的第一优先收益不是把 `763μs` 变成 `50μs`，而是：
   - 解除大输出时的串口瓶颈；
   - 去掉 `OUTPUT:` 文本转义协议；
   - 支持 stdout/stderr 分流；
   - 为后续网络代理通道复用同一机制。

5. **实施上应保留串口作为调试控制台，而不是把串口彻底删除。**
   正式数据面切到 vsock 后，串口仍然适合保留为：
   - early boot 日志；
   - `panic` / guest bring-up 失败时的最后观测面；
   - 不依赖 virtio bring-up 的故障回退路径。

## 2. 当前架构基线

### 2.1 当前代码路径

当前 host-guest 命令流大致如下：

```text
Host (Rust)
  -> KvmBackend::run_command()
  -> serial_device.queue_input("EXEC:<len>:<payload>\\n")
  -> guest /init 轮询 COM1
  -> /bin/sh -lc "<cmd>"
  -> 子进程 stdout/stderr 合并到同一 pipe
  -> guest 输出 "OUTPUT:..." / "EXIT:..."
  -> host 解析文本帧
```

当前仓库里已经有两个与本次研究直接相关的事实：

1. `crates/mimobox-vm/src/kvm.rs` 里定义了 `KvmTransport::{Serial, Vsock}`，但 `create_vm()` 仍固定把 `transport` 设为 `Serial`，说明“支持 vsock”还停留在枚举层，没有真正设备模型。
2. `crates/mimobox-vm/guest/guest-init.c` 直接做 `ioperm()`，然后通过 `inb()` / `outb()` 读写 `0x3f8`，说明 guest 侧目前根本没有 socket 数据面。

### 2.2 当前串口方案的技术约束

当前方案的主要问题不是“能不能用”，而是“难以继续扩成正式数据面”：

| 维度 | 当前串口方案 | 结果 |
|---|---|---|
| 传输方式 | COM1 PIO，字节级 I/O | guest/host 两端都要承担高频 VM exit 与逐字节处理 |
| 协议模型 | 文本帧 `EXEC:` / `OUTPUT:` / `EXIT:` | 易调试，但不适合二进制、流分离和高吞吐 |
| stdout/stderr | 合并到同一 pipe 再编码回传 | 无法保留原始通道语义 |
| 数据转义 | guest 需要做 `\\n`、`\\r`、`\\xHH` 转义 | 输出越大，协议处理越重 |
| 扩展性 | 基本只有“一条流” | 后续做网络代理、文件传输都不自然 |

这决定了串口更像“bring-up / debug 通道”，而不是长期正式数据面。

## 3. rust-vmm 生态调研

### 3.1 结论概览

截至 **2026-04-22**，rust-vmm 生态对 vsock 的支持是“**有构件，但没有一个可直接嵌入当前 `KvmBackend` 的成品**”。

更具体地说：

1. **没有检索到 `vm-vsockio` 这个 crate 或 rust-vmm 仓库。**
   - crates.io 搜索 `vm-vsockio` 返回空结果。
   - GitHub `org:rust-vmm vm-vsockio` 搜索结果为 `0`。
   - 因此，本次研究把它视为“命名误差或历史记忆偏差”，当前 rust-vmm 的主入口不是它。

2. **`vmm-sys-util` 不是 vsock 设备模拟实现。**
   它是系统工具箱，提供 `eventfd`、`epoll`、`ioctl`、文件/错误等基础设施，对实现 VMM 很有用，但不提供 `virtio-vsock` 前端或 `AF_VSOCK` 协议桥接。

3. **`vm-virtio` workspace 内有 `virtio-vsock`，但它不是“插上即用”的完整 VMM 数据面。**
   `vm-virtio` README 明确写到：
   - workspace 包含 `virtio-vsock`；
   - 除了队列与设备抽象外，**VMM 仍然需要自己提供 device backend 和 event handling**。

4. **`vhost-device-vsock` 是可运行的 vhost-user backend，但前提是你的 VMM 已经具备 vhost-user frontend。**
   当前 mimobox 的 `KvmBackend` 还没有 vhost-user frontend，也没有 PCI/MMIO virtio 总线，因此它更适合作为参考实现，而不是直接 drop-in。

### 3.2 crates.io 上与 virtio-vsock 直接相关的 crate

下表基于 crates.io API 截至 **2026-04-22** 的结果：

| crate | 当前最高版本 | 定位 | 对 mimobox 的价值 |
|---|---:|---|---|
| `virtio-vsock` | `0.11.0` | rust-vmm 的 virtio vsock 设备实现入口 | 适合作为自研 virtio-vsock 前端的基础参考 |
| `vhost-device-vsock` | `0.3.0` | rust-vmm 的 vhost-user vsock backend | 适合参考其后端设计，不适合当前仓库直接复用 |
| `vhost` | `0.16.0` | rust-vmm 的 vhost/vhost-user 协议库 | 若接 `/dev/vhost-vsock` 或未来上 vhost-user，会很有价值 |
| `vsock` | `0.5.4` | Rust 同步 `AF_VSOCK` socket 封装 | 适合 host 命令服务端/客户端 |
| `tokio-vsock` | `0.7.2` | Rust 异步 `AF_VSOCK` socket 封装 | 若 host 侧命令服务走异步 reactor，优先考虑 |
| `vmm-sys-util` | `0.15.0` | rust-vmm 系统工具集 | 只提供基础设施，不提供 vsock 设备模型 |

其中最关键的生态判断是：

- **host 应用层 socket：** `vsock` / `tokio-vsock` 已经足够成熟。
- **VMM 设备层：** rust-vmm 提供的是组件，不是当前 `KvmBackend` 可以直接装上的整机方案。

### 3.3 rust-vmm 组织下与 vsock 相关的仓库

在 rust-vmm GitHub 组织下，和 vsock 直接相关的仓库主要是：

| 仓库 | 作用 | 研究结论 |
|---|---|---|
| `vm-virtio` | virtio 抽象与设备实现 workspace | 含 `virtio-vsock`，但 VMM 仍要自己补 backend + event loop |
| `vhost-device` | 多种 vhost-user backend workspace | 含 `vhost-device-vsock`，适合参考或未来做外部 backend |
| `vhost` | vhost / vhost-user 协议库 | 适合打通 `/dev/vhost-vsock` 或未来的 vhost-user |
| `vmm-reference` | rust-vmm 参考 VMM | README 仍写明“希望在不久的将来支持 network 和 vsock devices”，说明它也不是现成答案 |
| `vmm-sys-util` | eventfd/epoll/ioctl 等工具 | 不是设备模拟实现 |

### 3.4 对当前仓库的直接启示

对 mimobox 而言，最重要的不是“有没有 vsock crate”，而是“**这些 crate 解决了哪一层问题**”：

| 层级 | 推荐参考 | 当前是否直接可用 |
|---|---|---|
| Host 应用层 `AF_VSOCK` | `vsock` / `tokio-vsock` | 是 |
| VMM vhost 协议层 | `vhost` | 部分可用，需要自己接入 |
| Virtio 设备抽象层 | `vm-virtio` / `virtio-vsock` | 部分可用，需要自己做总线与事件循环 |
| 独立 backend 进程 | `vhost-device-vsock` | 否，当前仓库没有 vhost-user frontend |

**结论：** rust-vmm 生态对 mimobox 的帮助主要是“减少自研量”，而不是“省掉设备层工作”。 

## 4. KVM/Linux 中 vsock 的实现路径

### 4.1 正确的数据路径

如果采用 Linux/KVM 的标准内核路径，host-guest 数据面应当是：

```text
Guest userspace
  -> socket(AF_VSOCK, ...)
  -> guest virtio_vsock driver
  -> virtio-vsock virtqueues (TX / RX / EVENT)
  -> host VMM front-end
  -> /dev/vhost-vsock
  -> vhost_vsock kernel backend
  -> AF_VSOCK socket API on host
  -> Host userspace
```

这条路径里有三个很容易混淆的点：

1. **`AF_VSOCK` 是 userspace API。**
   host 和 guest 应用都通过 `socket(AF_VSOCK, ...)` 使用它。

2. **`virtio-vsock` 是 guest 看到的虚拟设备。**
   它负责把 guest 的 socket 流量放进 virtqueue。

3. **`vhost-vsock` 是 host 内核加速后端。**
   VMM 通过 `/dev/vhost-vsock` 配置它，让 host 内核网络栈接管实际的数据搬运。

### 4.2 `VHOST_VSOCK` / `/dev/vhost-vsock`

Linux 内核 `include/uapi/linux/vhost.h` 定义了两个 vsock 相关 ioctl：

```c
#define VHOST_VSOCK_SET_GUEST_CID _IOW(VHOST_VIRTIO, 0x60, __u64)
#define VHOST_VSOCK_SET_RUNNING   _IOW(VHOST_VIRTIO, 0x61, int)
```

这说明 `vhost-vsock` 的控制面是：

1. VMM 打开 `/dev/vhost-vsock`；
2. 设置 guest CID；
3. 配置 vring 地址、`kick` / `call` eventfd 等通用 vhost 资源；
4. 把设备切到 running 状态。

Linux `drivers/vhost/vsock.c` 里 `miscdevice` 的名字就是 `"vhost-vsock"`，因此 host 上会出现：

```text
/dev/vhost-vsock
```

**关键澄清：`/dev/vhost-vsock` 是 host 侧设备，不是 guest 侧设备。**

### 4.3 `AF_VSOCK` socket 地址族

`vsock(7)` 说明：

- `socket(AF_VSOCK, SOCK_STREAM, 0)` 创建流式 vsock；
- 地址是 `<CID, Port>`；
- `VMADDR_CID_HOST` 是保留的 host CID `2`；
- `SOCK_STREAM` 和 `SOCK_DGRAM` 是否可用，取决于底层 hypervisor/transport。

这与 mimobox 的目标非常契合：命令通道可以直接建成 `SOCK_STREAM`。

### 4.4 guest 侧到底看到什么

Firecracker 官方文档给出的 guest 检查方式是：

```bash
ls /dev/vsock
```

它明确区分了：

- host 内核需要 `CONFIG_VHOST_VSOCK`；
- guest 内核需要 `CONFIG_VIRTIO_VSOCKETS`；
- guest 可见的验证节点是 `/dev/vsock`。

这里还要再纠正一个概念误区：

1. guest 用户态程序**通常不会直接操作 `/dev/vsock`**；
2. guest 正常的编程接口仍然是 `socket(AF_VSOCK, ...)`；
3. `/dev/vsock` 更像驱动可用性的验证标志。

### 4.5 Firecracker 为什么不用 `/dev/vhost-vsock`

Firecracker 官方文档明确说明，它的 virtio-vsock 设计是：

- **在 host 端绕过 vhost kernel code**；
- 把 guest 的 `AF_VSOCK` 端口映射到 host 的 `AF_UNIX` socket；
- host 发起连接时先连到 UDS，再发 `"CONNECT <port>\n"`。

这条路线很适合作为轻量桥接方案，但它有一个和本次目标直接冲突的事实：

> **Firecracker 风格默认导出的 host API 是 `AF_UNIX`，不是 `AF_VSOCK`。**

因此，如果 mimobox 的产品约束是“host 侧用 `AF_VSOCK` 套接字收发命令”，Firecracker 的设计更适合作为参考，不应当作为最终目标形态。

## 5. 与当前架构的集成方案

### 5.1 推荐方案：KVM 前端 + `vhost-vsock` 内核后端

推荐的正式集成路线如下：

```text
KvmBackend
  -> 新增最小 virtio/MMIO 总线
  -> 新增 virtio-vsock front-end
  -> 通过 /dev/vhost-vsock 接内核 backend
  -> host 侧直接 listen/connect AF_VSOCK
```

对应到当前仓库：

1. **`KvmBackend`**
   - 新增 MMIO 设备注册表；
   - 为 virtio-vsock 分配 MMIO 区间、IRQ、eventfd；
   - 在 `run_vcpu_step()` 里把相关 `MmioRead/MmioWrite` 转发到 virtio 设备，而不是一律填零。

2. **guest `/init`**
   - 从 `COM1` 文本协议改为 `AF_VSOCK` 流连接；
   - 启动后主动 `connect()` 到 host 控制端口；
   - 收到命令后执行，再按二进制帧回传 stdout/stderr/exit。

3. **host 命令服务**
   - 用 `vsock` 或 `tokio-vsock` 监听控制端口；
   - 保持长连接，避免每次命令都重新建连；
   - 输出流按 phase 逐步拆分。

### 5.2 为什么这不是“小改动”

从当前实现看，vsock 不是“把 `serial_device` 换成 socket”那么简单，至少还缺三块：

| 缺口 | 当前状态 | vsock 所需能力 |
|---|---|---|
| Virtio transport | 没有 | 需要 MMIO 或 PCI 前端 |
| Device event loop | 没有通用设备层 | 需要 vring 状态机与 eventfd |
| vhost 接入 | 没有 | 需要把 guest virtqueue 暴露给 `/dev/vhost-vsock` |

因此，**Phase 1 的真实工作量是“为 mimobox 引入第一块真正的 virtio 设备”**。

### 5.3 备选方案比较

| 方案 | 说明 | 优点 | 缺点 | 是否推荐 |
|---|---|---|---|---|
| A. `virtio-vsock` + `/dev/vhost-vsock` | host 侧直接 `AF_VSOCK` | 最符合目标；语义最干净；后续可复用 | 需要先补齐 virtio/MMIO 前端 | **推荐** |
| B. Firecracker 风格 UDS bridge | guest `AF_VSOCK`，host `AF_UNIX` | 用户态实现简单；原型快 | 不满足“host 侧 AF_VSOCK”目标 | 仅做原型 |
| C. `vhost-device-vsock` 外部 backend | vhost-user 模式 | 可以复用 rust-vmm 现成 backend | 当前仓库没有 vhost-user frontend；引入面更大 | 中长期可评估 |

### 5.4 在 `KvmBackend` 中的建议落点

建议在 `crates/mimobox-vm/src/kvm.rs` 之外新拆一个最小设备层，而不是继续把所有逻辑塞回 `kvm.rs`：

```text
crates/mimobox-vm/src/
├── kvm.rs                # KVM bring-up / run loop
├── devices/
│   ├── mod.rs
│   ├── mmio_bus.rs       # MMIO 地址分发
│   └── vsock.rs          # virtio-vsock front-end
└── host/
    └── vsock_server.rs   # host AF_VSOCK 命令服务
```

这样做的原因很直接：

1. 避免 `kvm.rs` 继续膨胀成“大而全”文件；
2. 未来 block/rng/net 设备可以沿同一模式接入；
3. snapshot、池化、设备状态可以按模块拆开保存。

### 5.5 guest `/init` 的改造方式

建议 guest 端从“轮询串口读取命令”改成“启动即建立持久 vsock 连接”：

```text
guest boot
  -> init 完成最小挂载
  -> socket(AF_VSOCK, SOCK_STREAM)
  -> connect(host_cid=2, control_port=19000)
  -> 进入命令循环
```

这样做有三个直接收益：

1. 连接建立成本只付一次；
2. host-initiated 逻辑更简单，不需要额外反向连接握手；
3. phase 2 做 stdout/stderr 独立流时，只需让 guest 再连两条固定端口。

### 5.6 host 侧 `AF_VSOCK` 命令服务

host 侧建议提供一个常驻 listener，而不是把命令发送逻辑直接塞进 `KvmBackend::run_command()`：

```text
KvmBackend
  -> boot guest
  -> wait control connection established
  -> run_command() 只负责在已建立的 stream 上发帧/收帧
```

这样可以把“VM bring-up”和“命令收发”分层，避免后续 phase 2/3 时 `KvmBackend` 再次重构。

### 5.7 代码示例

#### 示例 1：guest 侧 C 代码，用 `AF_VSOCK` 连接 host 控制端口

```c
#include <linux/vm_sockets.h>
#include <sys/socket.h>
#include <unistd.h>

int connect_control_channel(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK,
        .svm_cid = VMADDR_CID_HOST,   // host 保留 CID = 2
        .svm_port = 19000,            // 约定的控制端口
    };

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}
```

#### 示例 2：host 侧 Rust 代码，用 `vsock` crate 监听控制端口

```rust
use std::io::{Read, Write};
use vsock::{VsockListener, VMADDR_CID_ANY};

const CONTROL_PORT: u32 = 19_000;

fn main() -> std::io::Result<()> {
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, CONTROL_PORT)?;
    let (mut stream, peer) = listener.accept()?;
    eprintln!("accepted vsock peer: {:?}", peer);

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;

    // TODO: 执行命令并回写结果
    stream.write_all(b"OK")?;
    Ok(())
}
```

#### 示例 3：`KvmBackend` 里的 `vhost-vsock` 初始化草图

```rust
fn init_vsock_backend(&mut self, guest_cid: u64) -> Result<(), MicrovmError> {
    // 伪代码：展示初始化顺序，而不是可直接编译的最终实现。
    let vhost_fd = open_vhost_vsock()?;

    // 1. 配置三个 virtqueue 的 desc/avail/used 地址
    configure_vrings(&vhost_fd, &self.vsock_queues)?;

    // 2. 给每个 queue 绑定 kick / call eventfd
    configure_eventfds(&vhost_fd, &self.vsock_irqs)?;

    // 3. 设置 guest CID，并切到运行态
    set_guest_cid(&vhost_fd, guest_cid)?;
    set_running(&vhost_fd, true)?;

    self.vsock_backend = Some(vhost_fd);
    Ok(())
}
```

## 6. 性能预期

### 6.1 带宽：vsock 会显著优于当前串口

这个结论非常稳，不依赖于某个特定 benchmark 数字。

原因有三层：

1. **当前串口路径是逐字节 PIO。**
   guest 通过 `inb/outb` 访问 COM1，host 通过 `KVM_EXIT_IO` 逐次模拟，这天然意味着高 VM-exit 密度。

2. **当前串口协议还有文本转义成本。**
   guest 需要把原始输出转成 `OUTPUT:` 文本帧，大输出时要做大量转义和拷贝。

3. **vsock 走的是 virtqueue + socket API。**
   内核侧还有 `MSG_ZEROCOPY` 对 virtio transport 的专门支持，说明 Linux 已经把它当作高吞吐通道优化。

从公开基准看，Linux 内核维护者在 QEMU/KVM 环境下报告过：

- `SOCK_STREAM pingpong` 512B 负载总体往返延迟约 `780ns` 量级；
- 4KB 负载总体往返延迟约 `1.5us` 量级；
- 吞吐可以到 `29~50 Gb/s` 量级，具体取决于 payload 大小与并发流数。

这些数字不能直接拿来承诺 mimobox 最终表现，但它们足以证明：**vsock 的瓶颈远高于当前串口方案，正式数据面不会被带宽卡死。**

### 6.2 连接建立延迟：不要放在每条命令上

对于连接建立延迟，本次没有找到与 mimobox 完全同构、可直接复用的官方端到端基准。

但根据 `vsock(7)` 的 socket 语义，以及 KVM Forum 对 vsock “two-way handshake”的说明，可以做出一个保守的工程判断：

- **推断：** 单次 `connect()` / `accept()` 成本通常是微秒到亚毫秒量级，不会像 TCP 跨网络那样高；
- **但推断同样说明：** 这个成本不该摊到每一条命令上。

因此，mimobox 的正确做法应当是：

1. guest 启动后建立一次持久控制连接；
2. `run_command()` 只在现有连接上交换帧；
3. phase 2 的 stdout/stderr 也使用持久连接，而不是每次命令新建。

### 6.3 对命令执行延迟的影响

把当前串口 P50 `763μs` 作为基线，可以得到一个更贴近项目现状的判断：

| 场景 | 预期影响 | 原因 |
|---|---|---|
| 极短命令、几乎无输出 | 小幅改善或基本持平 | 主要成本仍在 guest `fork/exec/sh -lc`，不是传输 |
| 中等输出 | 明显改善 | 不再走逐字节串口 + 文本转义 |
| 大输出 / 流式输出 | 大幅改善 | virtqueue + socket API 明显优于 COM1 PIO |
| stdout/stderr 分离 | 明显改善可维护性 | 不再做单流复用与后解析 |

因此，对 mimobox 的业务收益排序应该是：

1. **大输出与流式场景；**
2. **stdout/stderr 语义恢复；**
3. **后续网络代理/复用能力；**
4. **最后才是极短命令的纯延迟优化。**

## 7. 实施路线

### Phase 1：最小 vsock 设备模拟，仅命令通道

目标：把正式命令通道切到 vsock，但保留串口日志。

建议范围：

1. `KvmBackend` 新增最小 MMIO/virtio 框架，只支持一块 `virtio-vsock` 设备；
2. 通过 `/dev/vhost-vsock` 接入 host 内核后端；
3. guest `/init` 启动后主动连 host `19000` 控制端口；
4. 控制协议改成**长度前缀二进制帧**，不再复用 `EXEC:` 文本协议；
5. 串口仅保留 `init OK`、`panic`、bring-up 日志。

验收标准：

- guest 能成功建立 vsock 控制连接；
- host 能下发命令并拿回退出码；
- 与当前串口方案相比，短命令延迟不显著退化；
- 中等以上输出量场景明显优于串口。

### Phase 2：stdout/stderr 分离到独立 vsock 流

目标：恢复输出语义，去掉单流复用。

建议设计：

| 流 | 端口 | 方向 |
|---|---:|---|
| control | `19000` | guest -> host 建立持久连接 |
| stdout | `19001` | guest -> host 建立持久连接 |
| stderr | `19002` | guest -> host 建立持久连接 |

协议约束：

1. `control` 流承载命令请求、退出码、心跳、错误码；
2. `stdout` / `stderr` 只传原始字节块；
3. 每个输出块都带 `command_id`，避免多个命令并发时串流。

这样设计的好处是简单、可观测、容易抓包分析；缺点是连接数从 1 条变成 3 条，但对当前单 guest 单 host 模式完全可接受。

### Phase 3：网络代理 vsock 通道

目标：为未来“域名白名单网络代理”预留宿主代理通道。

建议范围：

1. 新增 `19010` 代理控制端口；
2. guest 侧通过 control 流申请网络访问；
3. host 侧代理进程做 DNS / TCP / TLS 出站；
4. 实际流量通过独立 vsock 流或复用数据流转发。

注意事项：

1. phase 3 不应该与 phase 1/2 混做；
2. 先把命令数据面稳定，再把网络代理叠上去；
3. snapshot 恢复时默认不承诺保活现有代理连接，应以“断开后重建”为失败语义。

## 8. 风险与开放问题

### 8.1 主要风险

| 风险 | 说明 | 缓解建议 |
|---|---|---|
| 当前没有 virtio 设备框架 | 这是 phase 1 最大工程量 | 单独抽 `devices/` 层，不把逻辑继续堆到 `kvm.rs` |
| guest kernel/rootfs 配置不足 | 需要 `CONFIG_VIRTIO_VSOCKETS` 且 guest 内可用 | 在 rootfs 构建脚本里加入 vsock 自检 |
| snapshot 与长连接语义 | 打开的 vsock 流不应默认跨快照恢复 | 明确失败语义：恢复后重连 |
| CID/端口管理 | 多 VM 或预热池会遇到冲突 | 统一 CID 分配器与端口约定表 |
| bring-up 可观测性下降 | 如果完全移除串口，早期失败难排查 | 永久保留串口 debug console |

### 8.2 开放问题

1. 是否在 Phase 1 就引入 `tokio-vsock` 异步 host 服务，还是先用同步 `vsock` 降低复杂度？
2. `virtio-vsock` 前端是基于 rust-vmm `vm-virtio` 自己拼，还是先手写一版最小 MMIO 前端，再逐步替换？
3. `command_id` 是否允许并发命令，还是 Phase 1 明确规定单连接串行执行？

建议答案：

- Phase 1 先同步、先串行、先一条控制流；
- Phase 2 再引入多流和并发；
- Phase 3 再考虑异步化与代理复用。

## 9. 参考资料

以下链接均为本次研究直接使用的原始证据：

| 类别 | 链接 | 用途 |
|---|---|---|
| rust-vmm `vm-virtio` README | https://github.com/rust-vmm/vm-virtio | 确认 `virtio-vsock` 所在 workspace，以及 “VMM 仍需 backend + event handling” |
| rust-vmm `vhost-device` README | https://github.com/rust-vmm/vhost-device | 确认 `vhost-device-vsock` 存在且属于 vhost-user backend |
| rust-vmm `vhost-device-vsock` README | https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md | 确认其支持 UDS backend 与 VSOCK backend |
| rust-vmm community README | https://github.com/rust-vmm/community | 确认 `virtio-vsock` 已在 rust-vmm 公开组件列表中 |
| rust-vmm `vmm-reference` README | https://github.com/rust-vmm/vmm-reference | 确认参考 VMM 仍把 vsock 视为“near future”能力 |
| crates.io `virtio-vsock` | https://crates.io/crates/virtio-vsock | 确认 crate 版本与仓库归属 |
| crates.io `vhost-device-vsock` | https://crates.io/crates/vhost-device-vsock | 确认 crate 版本与定位 |
| crates.io `vsock` | https://crates.io/crates/vsock | 确认 host/guest userspace Rust socket crate |
| crates.io `tokio-vsock` | https://crates.io/crates/tokio-vsock | 确认异步 userspace Rust socket crate |
| Linux `vsock(7)` | https://man7.org/linux/man-pages/man7/vsock.7.html | 确认 `AF_VSOCK` 语义、CID/Port 地址格式 |
| Linux 内核 `include/uapi/linux/vhost.h` | https://github.com/torvalds/linux/blob/master/include/uapi/linux/vhost.h | 确认 `VHOST_VSOCK_SET_GUEST_CID` / `VHOST_VSOCK_SET_RUNNING` |
| Linux 内核 `drivers/vhost/vsock.c` | https://github.com/torvalds/linux/blob/master/drivers/vhost/vsock.c | 确认 `vhost-vsock` miscdevice 与 `/dev/vhost-vsock` |
| Linux 内核 `include/uapi/linux/vm_sockets.h` | https://github.com/torvalds/linux/blob/master/include/uapi/linux/vm_sockets.h | 确认 `struct sockaddr_vm` 与 `IOCTL_VM_SOCKETS_GET_LOCAL_CID` |
| Linux 内核 `tools/testing/vsock/vsock_test_zerocopy.c` | https://github.com/torvalds/linux/blob/master/tools/testing/vsock/vsock_test_zerocopy.c | 证明内核已有 vsock zerocopy 自测路径 |
| Linux Kernel Documentation `MSG_ZEROCOPY` | https://docs.kernel.org/networking/msg_zerocopy.html | 确认 zerocopy 已覆盖 VSOCK(virtio transport) |
| Firecracker vsock 文档 | https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md | 区分 Firecracker 的 UDS bridge 与标准 `AF_VSOCK` 路线 |
| KVM Forum 2015 virtio-vsock slides | https://events.static.linuxfound.org/sites/events/files/slides/stefanha-kvm-forum-2015.pdf | 确认 virtio-serial 局限、`AF_VSOCK` 地址模型和 `vhost-vsock` 架构 |
| Linux mailing list virtio-vsock benchmark | https://www.spinics.net/lists/kernel/msg5288124.html | 提供近期 latency / throughput 量级参考 |
