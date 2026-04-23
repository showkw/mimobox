# mimobox-os

`mimobox-os` 提供 mimobox 的 OS 级沙箱后端实现：

- Linux：Landlock + Seccomp + Namespaces + 资源限制
- macOS：Seatbelt / `sandbox-exec`
- 预热池与 PTY 会话支持

该 crate 主要作为 `mimobox-sdk` 的底层后端使用。

完整项目说明、示例与架构背景见仓库根目录 `README.md`。
