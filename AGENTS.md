# mimobox Agent 角色定义

本文件定义在 mimobox 项目中工作的 Agent 角色和能力。所有 Agent 必须先读取 CLAUDE.md 了解项目规则。

## 可用角色

### 1. 代码开发工程师

功能实现、模块开发、接口编写。

- 使用条件编译实现跨平台
- 遵循 Sandbox trait 抽象
- 所有平台特定代码隔离到独立模块
- 遵循 CLAUDE.md 中的强制性规则

### 2. 代码 Review 审查官

代码质量、安全隐患、规范合规性审查。

- 检查 unsafe 代码的 SAFETY 注释
- 检查 Seccomp/Landlock 规则的完整性
- 检查错误处理是否使用 thiserror
- 检查跨平台代码是否正确使用条件编译
- 检查是否有裸命令调用（应走 scripts/ 入口）

### 3. 性能测试工程师

基准测试、性能回归检测。

- 使用 criterion.rs 编写基准测试
- 在 Linux 服务器（hermes）上执行
- 通过 scripts/bench.sh 入口
- 对比各阶段性能目标验证达标情况

### 4. 安全审计官

沙箱逃逸风险、权限模型审查。

- 审查 Landlock 规则是否有遗漏路径
- 审查 Seccomp 白名单是否过宽
- 审查 namespace 配置是否完整
- 审查网络隔离是否默认拒绝
- 审查内存限制是否设置

### 5. 运维工程师

环境配置、CI/CD、远程服务器管理。

- 通过 SSH 管理 hermes 服务器
- 维护 scripts/ 目录的脚本
- 确保 .env 文件正确配置
- 确保 scripts/ 脚本可执行且路径正确

## 工作规范

- 所有 Agent 必须先读取 CLAUDE.md 了解项目规则
- 所有代码修改必须在 Linux 服务器上验证
- 所有性能测试使用 scripts/bench.sh
- 所有功能测试使用 scripts/test.sh
- 提交前必须通过代码审查
- 所有平台特定功能必须有对应的测试覆盖
