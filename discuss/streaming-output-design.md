---
title: 串口流式输出协议设计
date: 2026-04-23
status: reviewed
scope: P0-a
reviewers: [Codex gpt-5.4, Claude 总指挥]
---

# 串口流式输出协议设计

## 1. 背景与动机

当前 mimobox 串口协议在命令执行完毕后一次性返回全部输出：

```
host → guest:  EXEC:<len>:<payload>\n
guest → host:  OUTPUT:<stdout_len>:<stdout>\n
guest → host:  STDERR:<stderr_len>:<stderr>\n
guest → host:  EXIT:<code>\n
```

问题：长时间运行的命令（`pip install`、模型训练）执行期间无中间输出。

竞品方案：
- E2B：gRPC Server-Streaming，`DataEvent` 带 stdout/stderr bytes，逐 chunk 推送，无应用层批处理
- Modal：Python generator yield 模式
- Daytona：PTY + REST streaming

## 2. 协议设计（综合 Codex + 总指挥方案）

### 2.1 帧类型

```
# 流式执行命令（EXEC 的流式变体）
EXECS:<id>:<len>:<payload>\n

# 流式输出开始
STREAM:START:<id>\n

# 流式输出 chunk（可多次发送）
STREAM:STDOUT:<id>:<len>:<bytes>\n
STREAM:STDERR:<id>:<len>:<bytes>\n

# 流式命令结束
STREAM:END:<id>:<exit_code>\n
```

`<id>` 为十进制整数，预留未来并发命令支持（当前固定为 0）。
二进制安全性通过 `<len>` 长度前缀保证，与 FS:READ/FS:WRITE 一致。

### 2.2 向后兼容

- `EXEC:` → 非流式，行为完全不变
- `EXECS:` → 流式，guest 立即开始推送 STREAM 帧
- 旧 guest 不识别 `EXECS` 时 host 可降级为 `EXEC`

### 2.3 完整交互示例

```
host → guest:  EXECS:0:17:/usr/bin/python3 -c "import time; [print(f'tick {i}') or time.sleep(0.5) for i in range(3)]"

guest → host:  STREAM:START:0
guest → host:  STREAM:STDOUT:0:7:tick 0\n
guest → host:  STREAM:STDOUT:0:7:tick 1\n
guest → host:  STREAM:STDOUT:0:7:tick 2\n
guest → host:  STREAM:END:0:0
```

## 3. Guest 侧改动（guest-init.c）

1. `serial_command_loop()` 新增 `EXECS:` 前缀识别
2. `execute_command()` 拆分为 `execute_command_blocking()` 和 `execute_command_streaming()`
3. 流式模式：`pipe()` + `fork()` + 非阻塞 read
4. `poll()` 循环：stdout/stderr pipe 读到数据立即发送 `STREAM:STDOUT/STDERR` 帧
5. 子进程退出后 `waitpid()` 并发送 `STREAM:END`
6. 超时由 host 侧 watchdog 管理（不变）

## 4. Host 侧改动

### 4.1 串口设备层（serial.rs）

- 新增常量：`SERIAL_EXECS_PREFIX`、`SERIAL_STREAM_PREFIX`
- `SerialProtocolResult` 新增 `StreamStart(u32)`、`StreamStdout(u32, Vec<u8>)`、`StreamStderr(u32, Vec<u8>)`、`StreamEnd(u32, i32)` 变体
- `SerialResponseCollector` 新增 `Streaming` 模式

### 4.2 KVM 后端（kvm.rs）

- 新增 `run_command_streaming()` 方法
- 返回 `mpsc::Receiver<StreamEvent>` 而非一次性 `GuestCommandResult`
- KVM_RUN 循环中根据 `EXECS`/`EXEC` 前缀选择收集模式

### 4.3 SDK（mimobox-sdk）

```rust
pub enum StreamEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}

impl Sandbox {
    pub fn stream_execute(&mut self, command: &str) -> Result<impl Stream<Item = StreamEvent>>;
}
```

### 4.4 Python SDK

```python
@dataclass
class StreamEvent:
    stdout: bytes | None = None
    stderr: bytes | None = None
    exit_code: int | None = None

class Sandbox:
    def stream_execute(self, command: str) -> Iterator[StreamEvent]: ...
```

## 5. 性能考虑

- CHUNK 大小：guest pipe 缓冲区 4KB，读到多少推多少
- 频率：不刻意合并，读到就推（与 E2B 策略一致）
- 串口吞吐：~11KB/s（代码输出足够，大文件传输走 FS:READ/FS:WRITE）

## 6. 风险

1. **串口写阻塞**：host 消费慢时 guest write() 阻塞 → 天然背压，不需额外处理
2. **Guest 崩溃**：中途崩溃 host 收不到 STREAM:END → 现有 watchdog 超时机制覆盖
3. **向后兼容**：纯新增协议，不修改 EXEC/OUTPUT/EXIT

## 7. 实现计划

| 步骤 | 文件 | 预估 |
|------|------|------|
| Guest 流式执行 | guest-init.c | 2h |
| Host 帧解析 | serial.rs | 1h |
| Host 后端方法 | kvm.rs | 1h |
| VM 层集成 | vm.rs | 0.5h |
| SDK streaming API | mimobox-sdk | 1h |
| Python SDK | mimobox-python | 0.5h |
| E2E 测试 | kvm_e2e.rs | 1h |
