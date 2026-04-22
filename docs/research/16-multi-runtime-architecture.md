# microVM 多语言运行时架构设计

> 结论：正式采纳方案 D，即“基础快照 + 只读运行时 Bundle + Guest 请求式补齐”。本文严格区分当前实现与目标态演进，不把规划写成现状。

## 版本记录表

| 版本 | 日期 | 变更摘要 | 变更类型 | 责任人 |
| --- | --- | --- | --- | --- |
| v1.0 | 2026-04-23 | 首次建立 microVM 多语言运行时架构设计，正式确定方案 D | 新增 | Codex |

## 术语表

| 术语 | 定义 |
| --- | --- |
| 基础控制快照 | 只包含 guest 控制平面最小能力的快照，不包含具体语言运行时 |
| 运行时 Bundle | 只读、不可变、可版本化的语言或工具链镜像 |
| Capability | guest 可请求、host 可补齐的最小运行能力 |
| Guest 请求式补齐 | guest 在真实执行路径上发现缺失依赖，再向 host 请求补齐 |
| Hint | host 基于历史、任务描述或静态扫描做的预热建议，只影响性能 |

## 文章内容大纲目录表

| 章节 | 标题 | 目的 |
| --- | --- | --- |
| 1 | 背景与动机 | 解释为何必须放弃语言模板思路 |
| 2 | 方案评审 | 对比四个候选方案并给出结论 |
| 3 | 最终方案详细设计 | 定义基础快照、bundle、协议和 hint |
| 4 | Capability 模型 | 统一命名、粒度和错误语义 |
| 5 | 与现有架构的集成 | 说明对 RestorePool、协议、脚本和后端的影响 |
| 6 | 分阶段实施计划 | 给出 P0-P3 路线 |
| 7 | 风险与权衡 | 明确主要技术风险 |
| 8 | 性能预期 | 以当前基线给出目标态预期 |

## 1. 背景与动机

Agent 在 sandbox 中执行代码时，真实链路通常跨语言、跨工具链。典型场景不是“只跑 Python”或“只跑 Node”，而是 Python 调 Node，Node 再调 GCC；或 `npm install` 触发 `node-gyp`，反向依赖 Python 与编译器。真正的依赖闭包往往只能在 guest 内执行到某一步时才暴露出来。

这使“按语言模板预构建 rootfs + snapshot”行不通。若 host 先猜任务是 Python，就恢复 `python-rootfs`，但运行中再调 Node 与 GCC，猜测立即失效；若为所有组合预建模板，又会演化出 `python`、`python+node`、`python+gcc`、`python+node+gcc` 的组合爆炸。当前实现本身已经给出边界：rootfs 仍是单个最小 `gzip cpio initrd`，控制面仍是 `READY / EXEC / OUTPUT / EXIT`，`RestorePool` 预建的是不带语言维度的空壳 VM。因此多语言支持必须建立在“基础快照稳定、运行时动态组合”之上，而不是把 host 语言猜测变成正确性前提。

## 2. 方案评审

| 方案 | 实现复杂度 | 启动延迟影响 | 资源效率 | 灵活性 | RestorePool 兼容性 | 生产可靠性 |
| --- | --- | --- | --- | --- | --- | --- |
| A：胖 rootfs（多运行时合一） | 低 | 差 | 差 | 低 | 差 | 中 |
| B：按需挂载 overlay | 高 | 中 | 中 | 中高 | 中 | 低到中 |
| C：Host 端智能准备 | 中 | 中 | 中 | 低到中 | 中 | 中 |
| D：基础快照 + 只读 Bundle + Guest 请求式补齐 | 中高 | 好 | 高 | 高 | 高 | 高 |

方案 A 短期最容易做，但会把 rootfs 体积直接转成冷启动与恢复成本，侵蚀当前 restore-to-ready 优势。方案 B 方向正确，但通用 overlayfs 会引入层级管理、脏写隔离、回收和一致性复杂度。方案 C 可作为优化层，但只能做 hint，不能做 gate。方案 D 把“基础恢复”与“运行时补齐”解耦，是唯一同时兼顾性能、池化兼容性、动态组合和生产治理的方案。

## 3. 最终方案详细设计

### 3.1 基础控制快照

基础控制快照只保留四类内容：`/init`、BusyBox、runtime manager、最小挂载逻辑。当前最小 rootfs 已具备 `guest-init + BusyBox + /proc /sys /dev` 的雏形；目标态是在此基础上增加 runtime manager 职责，但不把 Python、Node、GCC 等运行时打进基础 rootfs。快照必须只表示“控制平面 ready”，而不是“某语言已就绪”。

### 3.2 运行时 Bundle 规范

运行时 Bundle 必须是只读、不可变、可版本化的镜像，文件系统格式可选 `squashfs` 或 `erofs`。命名必须稳定，例如 `python-3.11`、`node-22`、`gcc-14-musl`。bundle 由 host 以 `virtio-blk` 或 `virtio-fs` 暴露给 guest；bundle 只承载运行时文件，不承载任务输出，也不承担可写层。

### 3.3 Guest 请求式补齐协议

目标态应沿用当前基于文本行的串口控制面，连续演进新增三类帧，而不是推倒重来：

```text
Guest -> Host
NEED_RUNTIME:runtime/python-3.11

Host -> Guest
RUNTIME_OK:runtime/python-3.11
RUNTIME_ERR:runtime/python-3.11:not-found
```

执行序列如下：

```text
RestorePool restore 基础快照
  -> host 发送 EXEC
  -> guest 真正执行时发现缺 capability
  -> guest 发送 NEED_RUNTIME
  -> host 附加只读 bundle
  -> guest 挂载并收到 RUNTIME_OK
  -> 继续原始调用链
```

guest 必须是“真实依赖发现者”。即使出现“Python 调 Node 再调 GCC”，也应由 guest 按真实执行顺序逐步补齐；host 只能响应请求，不能替 guest 决定依赖闭包。

### 3.4 Host 预热 Hint 机制

Hint 是可选优化层，不影响正确性。host 可基于历史命中、任务描述和静态扫描预先附加 bundle；命中时更快，失误时仍由 guest 按协议补齐。系统必须满足“无 hint 也正确，有 hint 只更快”。

## 4. Capability 模型

架构必须从“语言模板”改为“能力 bundle”。一个 capability 表示 guest 可请求的最小运行能力，通常映射到一个只读 bundle。命名建议采用 `<domain>/<name>-<version>`，例如 `runtime/python-3.11`、`runtime/node-22`、`toolchain/gcc-14-musl`。bundle 文件名与 capability id 应保持一致，避免路径、协议、日志和错误语义各写一套名字。

错误返回也必须是 capability 级，而不是模板级。例如：

- `RUNTIME_ERR:runtime/node-22:not-found`
- `RUNTIME_ERR:toolchain/gcc-14-musl:attach-failed`
- `RUNTIME_ERR:runtime/python-3.11:mount-failed`

## 5. 与现有架构的集成

对 RestorePool，核心原则是 pool key 不以 runtime 为维度。当前 `RestorePool` 只围绕 `SandboxConfig + MicrovmConfig` 创建空壳 slot，这与方案 D 一致；后续即使引入显式 key，也只应锚定基础快照版本、内核、基础 rootfs、vCPU 和内存等控制面参数。

对串口协议，演进方式必须从现有 `EXEC / OUTPUT / EXIT` 连续扩展。目标态只是在当前 line-oriented bring-up 控制面上增加 `NEED_RUNTIME` 与 `RUNTIME_OK / RUNTIME_ERR`，而不是另起一套控制通道。

对 `build-rootfs.sh`，应从“构建唯一 rootfs”扩展为“两段式产物”：基础 rootfs 继续输出最小 `rootfs.cpio.gz`，bundle 构建逻辑产出版本化只读镜像。基础 rootfs 职责应收缩，运行时内容应外移。

对 `KvmBackend`，影响主要集中在三处：增加 bundle 资源注册与设备附加能力；扩展串口状态机；保持“基础快照不固化 bundle 集合”的快照语义。当前快照已保存 guest boot/ready、串口 FIFO 和设备寄存器，后续不应让 bundle 集合重新把快照拉回模板化。

## 6. 分阶段实施计划

- P0（0-1 月）：定义 capability 模型，扩展串口协议帧。
- P1（1-2 月）：实现只读 bundle 暴露与 guest 挂载，先跑通 Python + Node。
- P2（2-3 月）：建立 bundle 构建管线、版本管理与更多工具链 bundle。
- P3（3-4 月）：加入 host hint 预热、命中统计和更多 runtime bundle。

## 7. 风险与权衡

- 只读 bundle 首次挂载一定有延迟，收益来自后续复用与不污染基础快照。
- guest 内核必须支持 `squashfs` 或 `erofs`，这会反向约束 guest kernel 配置。
- bundle 升级不能破坏基础快照兼容性，因此快照与 bundle 必须分版本治理。
- 挂载多个 bundle 会增加 VFS 元数据和 page cache 压力，但仍比胖 rootfs 更可控。

## 8. 性能预期

性能目标必须以当前 README 基线为参照。基础快照恢复应保持现有约 `28ms` 的 restore-to-ready 水平；运行时 bundle 首次附加会带来额外延迟，但这部分成本只应由真正需要该 capability 的实例承担。Hint 命中后，bundle 可在执行前已就位，因此命令侧可做到零额外补齐等待。

与胖 rootfs 相比，方案 D 的关键优势不是“首次必然更快”，而是把成本从“所有实例统一承担”改成“按能力按需承担”，从而让恢复性能与语言组合数量解耦。对于当前 `69ms` 的非池化快照恢复和约 `28ms` 的池化 restore-to-ready 基线，目标态应保持后者稳定，并把新增成本限制在首次附加 bundle 的局部路径上。
