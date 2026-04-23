# mimobox-vm

`mimobox-vm` 提供 mimobox 的 microVM 沙箱后端，当前聚焦 Linux + KVM：

- `MicrovmSandbox`
- 快照与恢复
- microVM 预热池与恢复池
- 受控 HTTP 代理
- guest 文件传输与流式执行

该 crate 是 `mimobox-sdk` 的高级隔离后端。

完整项目说明、示例与架构背景见仓库根目录 `README.md`。
