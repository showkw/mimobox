# mimobox-sdk

`mimobox-sdk` 是 mimobox 的统一 Rust SDK，对上层暴露一致的沙箱接口：

- 默认智能路由
- 显式隔离层选择
- 命令执行、PTY、流式输出
- microVM 快照与恢复
- 文件传输与受控 HTTP 代理

推荐大多数 Rust 用户直接从该 crate 开始使用。

完整项目说明、示例与架构背景见仓库根目录 `README.md`。
