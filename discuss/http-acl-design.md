---
title: mimobox HTTP 级 ACL 功能调研与设计
date: 2026-04-29
status: draft
scope: microVM host-side HTTP proxy / SDK / Python bindings
---

# mimobox HTTP 级 ACL 功能调研与设计

## 1. 评审结论

mimobox 应在现有 host-side HTTP proxy 上增加 **method + host + path**
粒度的 ACL 过滤层，而不是照搬 sandlock 的透明 MITM 架构。

核心原因：

| 维度 | sandlock | mimobox 建议 |
|------|----------|--------------|
| 网络模型 | seccomp-unotify 拦截 `connect` 后透明重定向 | guest 通过命令协议显式请求 host 代发 HTTP |
| HTTPS 处理 | hudsucker MITM，需要 CA 注入与信任链处理 | host 侧 `reqwest` 直接构造 URL，天然可见 method/host/path |
| ACL 检查点 | 代理收到真实 HTTP 请求后检查 | `execute_http_request` 解析 URL 后、发起网络前检查 |
| 绕过面 | 需防 Host header 欺骗与 CONNECT 透明代理绕过 | 需保证 guest 直连网络始终关闭，且 Host header 不透传 |
| 复杂度 | 高：seccomp notif + MITM + CA 生命周期 | 中：规则模型 + 路径规范化 + SDK/API 映射 |

因此，P0 目标应聚焦为：

1. 引入 `HttpAclRule` / `HttpMethod` / deny-first 规则评估。
2. 将现有 `allowed_http_domains` 自动转换为 `ANY host /*` allow 规则。
3. 在 `crates/mimobox-vm/src/http_proxy.rs` 的 host 代发前做 ACL 检查。
4. 暂不引入 hudsucker / MITM / seccomp-unotify 透明代理。

## 2. 调研范围

本次调研读取了以下 mimobox 文件：

- `crates/mimobox-vm/src/http_proxy.rs`
- `crates/mimobox-core/src/sandbox.rs`
- `crates/mimobox-sdk/src/config.rs`
- `crates/mimobox-python/src/lib.rs`
- `crates/mimobox-sdk/src/sandbox/http.rs`
- `crates/mimobox-vm/src/kvm.rs`

竞品 sandlock 通过 `gh api` 读取：

- `repos/multikernel/sandlock/contents/crates/sandlock-core/src/http_acl.rs`
- `repos/multikernel/sandlock/contents/crates/sandlock-core/src/policy.rs`
- `repos/multikernel/sandlock/contents/crates/sandlock-core/src/network.rs`
- `repos/multikernel/sandlock/contents/python/src/sandlock/policy.py`

sandlock 参考提交：`4aae0236d0c05e14044765f94b26ee56d8911797`。

## 3. mimobox 现状分析

当前 HTTP proxy 的关键行为：

- guest 通过串口 / vsock 命令协议发送结构化 HTTP 请求。
- host 在 `execute_http_request` 中解析 `HttpRequest.url`。
- 当前只允许 `https://` URL。
- 当前只按 `SandboxConfig.allowed_http_domains` 做域名白名单。
- 当前拒绝 IP 直连，并通过 DNS 预解析 + `reqwest::ClientBuilder::resolve`
  将 host 固定到已验证的 public IP。
- 当前过滤 `Host`、`Connection`、`Proxy-Authorization`、`Transfer-Encoding`
  等 hop-by-hop / 敏感 header。
- 当前禁用 redirect，避免跳转到未校验 URL。
- 当前限制 method、请求 body、请求 header、响应 header 和响应 body 大小。

当前配置链路：

- `mimobox_core::SandboxConfig` 保存 `allowed_http_domains`。
- `mimobox_sdk::NetworkPolicy::AllowDomains(Vec<String>)` 与
  `Config.allowed_http_domains` 合并后写入 `SandboxConfig`。
- Python `Sandbox(..., allowed_http_domains=[...], network="allow_domains")`
  最终调用 Rust SDK builder。
- `Sandbox.http_request()` 目前仅在 Linux + `vm` feature + microVM 后端可用。

现状结论：

- mimobox 已具备受控 host 代理、安全 header 过滤和 DNS rebinding 基础防护。
- 缺口是 ACL 维度只有 host，没有 method/path。
- 不需要引入透明代理即可在 host 侧看到完整 URL 和 method。

## 4. sandlock 实现分析

### 4.1 HttpRule 数据模型

sandlock 的 HTTP ACL 规则模型为：

```rust
pub struct HttpRule {
    pub method: String,
    pub host: String,
    pub path: String,
}
```

规则字符串格式为：

```text
METHOD host/path
```

典型示例：

```text
GET api.example.com/v1/*
* */admin/*
POST example.com/upload
GET example.com
```

语义：

- `method="*"` 表示任意 HTTP method。
- `host="*"` 表示任意 host。
- 未显式提供 path 时默认 `/*`。
- path 仅支持尾部 `*` 的前缀匹配，不支持中段 glob。
- method 与 host 匹配大小写不敏感。

### 4.2 http_acl_check 评估逻辑

sandlock 的评估顺序是：

1. 先检查 deny 规则，命中任一 deny 立即拒绝。
2. 再检查 allow 规则，命中任一 allow 立即允许。
3. allow 规则非空且未命中时拒绝。

需要注意一个实现细节：

- sandlock 当前代码在 `allow=[]` 且 `deny=[]` 时允许全部请求。
- sandlock 当前代码在只有 deny 规则时，未命中 deny 的请求允许。

mimobox 建议采用更保守的产品语义：

- 未配置 HTTP ACL 时保持现有行为。
- 一旦配置了 `http_acl_allow` 或从 `allowed_http_domains` 迁移出 allow 规则，
  就进入 allowlist 模式：deny 优先，allow 命中才允许，默认拒绝。
- 只有 deny 规则且没有 allow 规则的模式容易被误用，不建议作为 P0 API 暴露为
  “允许除 deny 外所有请求”。如确需支持，应在文档中明确标注为高级模式。

### 4.3 seccomp-unotify 透明代理架构

sandlock 的网络架构是透明拦截：

```text
sandboxed process
  -> connect(dest_ip:80/443)
  -> seccomp user notification
  -> supervisor 复制 sockaddr 并校验 IP/端口
  -> supervisor 将 connect 目标改写为 127.0.0.1:<proxy_port>
  -> hudsucker proxy 接收 HTTP/HTTPS 流量
  -> HTTP ACL 检查
  -> 转发或返回 403
```

关键点：

- `network.rs` 拦截 `connect`、`sendto`、`sendmsg`。
- `connect_on_behalf` 复制 child memory 中的 sockaddr，避免 TOCTOU。
- 对 HTTP ACL 端口命中时，将连接重定向到本地代理。
- 重定向前记录 `client_addr -> original_dest_ip`，供代理侧验证 Host。
- IPv6 socket 会使用 IPv4-mapped IPv6 地址连接本地代理。

### 4.4 HTTPS MITM 实现

sandlock 使用 hudsucker 作为 HTTP/HTTPS 代理：

- `spawn_http_acl_proxy` 绑定 `127.0.0.1:0`。
- 提供 `https_ca` 与 `https_key` 时，使用 `RcgenAuthority` 进行 HTTPS MITM。
- 未提供 CA 时仍构造 dummy CA，但仅用于 HTTP-only 模式，避免每次启动生成 key。
- 默认 HTTP ACL 拦截端口为 80；配置 HTTPS CA 后追加 443。

MITM 模式的实际前提：

- sandboxed process 必须信任该 CA，否则 TLS 握手会失败。
- 需要管理 CA/key 的生成、注入、轮换与泄漏风险。
- 对证书 pinning 的客户端无效。

### 4.5 Host header 验证防欺骗

透明代理必须防止如下攻击：

```text
connect evil.com:80
Host: allowed.com
GET /allowed/path
```

sandlock 的防护方式：

- seccomp supervisor 在重定向前记录原始目标 IP。
- hudsucker handler 从 URI authority 或 Host header 提取 claimed host。
- handler DNS 解析 claimed host，并检查解析结果是否包含 original dest IP。
- claimed host 如果本身是 IP，则直接与 original dest IP 比较。
- 验证失败返回 403。

mimobox 当前模型不需要 `orig_dest` map：

- guest 不直接建立 TCP 连接。
- host 直接解析 `HttpRequest.url`。
- `Host` header 已被过滤，不会覆盖 URL host。
- `reqwest` 通过 `.resolve(host:port, verified_ip)` 固定连接 IP。

### 4.6 路径规范化防绕过

sandlock 对 request path 和 rule path 都做规范化：

- percent-decode：`%2F` -> `/`，`%61` -> `a`。
- 合并重复斜线：`//` -> `/`。
- 解析 `.` 与 `..` 段。
- 确保 path 以 `/` 开头。

目标是防止：

```text
/admin/settings
//admin/settings
/%61dmin/settings
/public/../admin/settings
```

这些路径在 ACL 层被视为等价，避免 deny 或 allow 边界被编码绕过。

## 5. mimobox 规则模型设计

### 5.1 Rust 数据结构

建议在 `mimobox-core` 中定义基础模型，使 SDK、VM proxy、Python 绑定共享同一套序列化结构：

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpAclRule {
    pub method: HttpMethod,
    pub host: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Any,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HttpAclPolicy {
    pub allow: Vec<HttpAclRule>,
    pub deny: Vec<HttpAclRule>,
}
```

设计原则：

- `HttpMethod` 使用 enum，避免在内部到处传递任意字符串。
- P0 与当前 `ALLOWED_METHODS` 对齐，仅支持
  `GET/HEAD/POST/PUT/PATCH/DELETE/ANY`。
- `OPTIONS`、`TRACE`、`CONNECT` 不进入 P0；`CONNECT` 和 `TRACE` 继续禁止。
- `host` 保持字符串，支持精确域名、`*` 和现有 `*.example.com`。
- `path` 存储规范化后的 pattern。

### 5.2 字符串解析

字符串规则格式与 sandlock 对齐：

```text
METHOD host/path
```

解析规则：

- `METHOD` 大小写不敏感。
- `*` 解析为 `HttpMethod::Any`。
- `host/path` 以第一个 `/` 分割。
- 未提供 path 时默认 `/*`。
- path 为空时默认 `/` 或拒绝，建议 P0 统一为 `/*` 以兼容 sandlock。
- 解析时立即规范化 path，并保留尾部 `*` 的前缀匹配语义。

示例映射：

```text
GET api.openai.com/v1/models   -> Get,  api.openai.com, /v1/models
POST api.openai.com/v1/*       -> Post, api.openai.com, /v1/*
* *.openai.com/*               -> Any,  *.openai.com, /*
* */admin/*                    -> Any,  *, /admin/*
GET example.com                -> Get,  example.com, /*
```

### 5.3 通配符匹配

method 匹配：

- `Any` 匹配所有允许的 method。
- 其他 method 必须精确匹配。

host 匹配：

- `*` 匹配所有 host。
- `example.com` 精确匹配，大小写不敏感，忽略尾部 `.`。
- `*.example.com` 复用当前域名白名单语义：只匹配子域名，不匹配裸域名。
- 不支持 `api.*.com`、`foo*` 等中段 glob，避免规则语义过宽。

path 匹配：

- `/*` 与 `*` 匹配所有 path。
- `/v1/*` 做前缀匹配。
- `/v1/models` 做精确匹配。
- 不支持 `/v1/*/models` 等中段 glob。

### 5.4 路径规范化

mimobox 应实现与 sandlock 等价的规范化算法：

1. 对 `%XX` 做 percent-decode。
2. 合并空段，消除重复 `/`。
3. 解析 `.` 与 `..` 段。
4. 保证结果以 `/` 开头。
5. 对 rule path 与 request path 使用同一函数。

安全要求：

- percent-decode 应只解码合法 `%XX`，非法编码保留原样。
- `/../../x` 解析为 `/x`，不得生成空 path 或相对 path。
- query string 不参与 P0 path ACL；如业务要按 query 控制，应作为后续能力单独设计。

## 6. API 设计

### 6.1 Rust SDK 扩展

推荐采用新增 `HttpAclPolicy` 字段，而不是把所有语义塞进
`NetworkPolicy` enum。

原因：

- `NetworkPolicy` 当前表达的是“直连网络是否允许”。
- HTTP ACL 表达的是“host-side proxy 允许哪些 HTTP 请求”。
- 两者处在不同层级，强行合并会让 `DenyAll` 语义混乱。

建议结构：

```rust
pub enum NetworkPolicy {
    DenyAll,
    AllowDomains(Vec<String>),
    AllowAll,
}

pub struct Config {
    pub network: NetworkPolicy,
    pub allowed_http_domains: Vec<String>,
    pub http_acl: HttpAclPolicy,
}
```

Builder 扩展：

```rust
impl ConfigBuilder {
    pub fn http_acl_allow(
        self,
        rules: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self;

    pub fn http_acl_deny(
        self,
        rules: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self;
}
```

建议行为：

- `http_acl_allow([...])` 解析并追加 allow 规则。
- `http_acl_deny([...])` 解析并追加 deny 规则。
- 解析失败在 `build()` 阶段返回 `SdkError::invalid_config`。
- 配置 HTTP ACL 时，`deny_network` 必须保持 `true`，否则 guest 可直连绕过 ACL。
- `network=AllowAll` 与 `http_acl` 同时配置时应 fail-closed。

向后兼容：

- `allowed_http_domains(["api.openai.com"])` 自动转换为：

```rust
HttpAclRule {
    method: HttpMethod::Any,
    host: "api.openai.com".to_string(),
    path: "/*".to_string(),
}
```

- `NetworkPolicy::AllowDomains(vec!["*.openai.com"])` 同样转换为 allow 规则。
- 旧字段暂不删除，标记为 legacy domain allowlist。
- `SandboxConfig.allowed_http_domains` 可在 P0 保留，用于兼容快照和旧调用；
  同时新增 `SandboxConfig.http_acl` 作为真实执行依据。

### 6.2 Python SDK 扩展

Python 构造参数新增：

```python
Sandbox(
    isolation="microvm",
    network="allow_domains",
    allowed_http_domains=["api.openai.com"],
    http_allow=[
        "GET api.openai.com/v1/models",
        "POST api.openai.com/v1/chat/completions",
    ],
    http_deny=[
        "* api.openai.com/v1/admin/*",
    ],
)
```

建议签名：

```python
Sandbox(
    *,
    isolation=None,
    allowed_http_domains=None,
    http_allow=None,
    http_deny=None,
    memory_limit_mb=None,
    timeout_secs=None,
    max_processes=None,
    trust_level=None,
    network=None,
)
```

Python API 规则：

- `http_allow` / `http_deny` 类型为 `list[str] | None`。
- 字符串格式与 sandlock 保持一致。
- `allowed_http_domains` 继续可用，并自动转换为 allow 规则。
- 解析错误抛 `ValueError`。
- 请求被 ACL 拒绝时抛 `SandboxHttpError`，错误 code 建议为
  `http_denied_acl`。

## 7. 实现路径

### 7.1 Rust core

涉及模块：

- `crates/mimobox-core/src/sandbox.rs`

建议改动：

1. 新增 `HttpMethod`、`HttpAclRule`、`HttpAclPolicy`。
2. `SandboxConfig` 新增 `http_acl: HttpAclPolicy`。
3. `SandboxConfig::validate()` 增加规则校验。
4. `ErrorCode` 新增 `HttpDeniedAcl`，字符串为 `http_denied_acl`。
5. 保留 `allowed_http_domains`，但文档标记为 legacy。

### 7.2 Rust SDK

涉及模块：

- `crates/mimobox-sdk/src/config.rs`

建议改动：

1. `Config` 新增 `http_acl: HttpAclPolicy`。
2. `ConfigBuilder` 新增 `http_acl_allow` / `http_acl_deny`。
3. `resolve_allowed_http_domains` 结果转换为 `Any host /*`。
4. `to_sandbox_config()` 同步写入 `SandboxConfig.http_acl`。
5. `validate()` 禁止 `NetworkPolicy::AllowAll` 与 HTTP ACL 同时出现。
6. 保持 `allowed_http_domains()` builder 的旧行为，但内部补充 ACL 规则。

### 7.3 VM HTTP proxy

涉及模块：

- `crates/mimobox-vm/src/http_proxy.rs`
- `crates/mimobox-vm/src/kvm.rs`

建议改动：

1. 将 `validate_http_request(config, &url)` 扩展为同时接收 method：

```rust
validate_http_request(config, method, &url)?;
```

2. URL 基础校验继续先执行：

- scheme 必须为 `https`。
- host 非空。
- 拒绝 IP 直连。
- host 必须满足 legacy domain allowlist 或 HTTP ACL allowlist。

3. ACL 检查在发起 `reqwest` 请求前执行：

```text
method = normalize_method(request.method)
host = normalize_host(url.host_str())
path = normalize_path(url.path())
deny match -> reject
allow match -> continue
otherwise -> reject
```

4. 新增 `HttpProxyError::DeniedAcl`：

```rust
#[error("HTTP request denied by ACL: {method} {host}{path}")]
DeniedAcl { method: String, host: String, path: String }
```

5. guest 协议无需修改，因为 `HttpRequest` 已包含 method 与 URL。

### 7.4 快照与序列化

涉及模块：

- `crates/mimobox-vm/src/snapshot.rs`

建议改动：

- 在快照编码中加入 `http_acl.allow` 与 `http_acl.deny`。
- 旧快照缺失该字段时默认 `HttpAclPolicy::default()`。
- 如当前快照格式没有版本字段，应先补版本或使用兼容解码策略。

### 7.5 测试

Rust 单元测试：

- `HttpRule::parse` 覆盖 method、host、path 默认值。
- path 规范化覆盖 `%2F`、`%2e%2e`、`//`、`.`、`..`。
- deny 优先覆盖 allow/deny 冲突。
- allow 非空默认拒绝覆盖未命中规则。
- `allowed_http_domains` 转换为 `Any host /*`。

VM proxy 测试：

- 允许 `GET api.example.com/v1/models`。
- 拒绝 `POST api.example.com/v1/models`。
- 拒绝 `GET api.example.com/v1/admin/*`。
- 拒绝 path 绕过：`/%61dmin`、`/public/../admin`。
- 保持 Host header 过滤行为。
- 保持 redirect 禁用行为。

Python 测试：

- 构造参数接收 `http_allow` / `http_deny`。
- 非法规则抛 `ValueError`。
- legacy `allowed_http_domains` 行为不变。

## 8. HTTPS 处理策略

mimobox P0 不引入 HTTPS MITM。

原因：

- 当前 guest 不是直接访问公网，而是通过 host 侧 HTTP 请求协议。
- host 已经拿到完整 method、URL、headers、body。
- ACL 可以直接在 URL 层检查 method/host/path。
- `reqwest` 发起的是 host 到目标站点的 TLS 连接，不需要解密 guest 的 TLS。

保持现有策略：

- guest 直连网络继续通过 sandbox policy 禁止。
- guest 只能调用 host 暴露的 HTTP request 协议。
- host 在代发前完成 ACL 和 DNS 防护。
- host 不转发 guest 提供的 `Host` header。

不做 MITM 的收益：

- 不需要 CA 注入。
- 不破坏证书 pinning。
- 不引入 CA 私钥管理风险。
- 不需要透明代理和 seccomp-unotify 重定向。

限制：

- 仅对经过 mimobox HTTP proxy 的请求生效。
- 如果未来某个后端允许 guest 直连网络，HTTP ACL 将被绕过。
- 因此 HTTP ACL 配置必须与 direct network deny 绑定校验。

## 9. 与 sandlock 的架构差异

### 9.1 sandlock

```text
process socket API
  -> kernel seccomp user notification
  -> supervisor 重定向 connect
  -> local MITM proxy
  -> HTTP ACL
  -> network
```

适合：

- 不修改应用代码。
- 透明拦截任意进程 HTTP/HTTPS。
- 对普通 CLI / package manager 更自然。

代价：

- 需要 Linux seccomp user notification。
- HTTPS 需要 MITM CA。
- 需要 Host header 与原始目的 IP 绑定校验。
- 实现复杂度和运行时状态都更高。

### 9.2 mimobox

```text
guest HTTP command
  -> host command protocol
  -> HttpRequest(method, url, headers, body)
  -> HTTP ACL
  -> reqwest
  -> network
```

适合：

- microVM 强隔离下的显式 host capability。
- Agent SDK 由宿主控制网络出口。
- 不需要透明代理和 CA。
- 更容易跨平台复用到未来 macOS / Windows host proxy。

代价：

- 只能约束通过 mimobox HTTP API 的请求。
- 不能透明拦截 guest 内任意程序直接发起的 HTTPS。
- 需要确保 guest 直连网络始终 fail-closed。

## 10. 安全考虑

### 10.1 HTTPS 绕过风险

主要风险不是 TLS 解密，而是 **绕过 host proxy**。

防护要求：

- `http_acl.allow` 或 `http_acl.deny` 非空时，`deny_network` 必须为 `true`。
- `NetworkPolicy::AllowAll` 与 HTTP ACL 同时配置应返回配置错误。
- microVM guest 默认不应获得可直连公网的 virtio-net 出口。
- 文档必须说明：HTTP ACL 不是通用防火墙，只保护 host HTTP proxy。

### 10.2 规则冲突处理

采用 deny 优先：

```text
deny match -> reject
allow match -> allow
allow configured but no match -> reject
no acl configured -> fall back to legacy allowed_http_domains behavior
```

建议 P0 不提供“只有 deny，其他全部允许”的默认体验。
这种模式容易让用户误以为已经进入白名单控制。

### 10.3 路径规范化绕过防护

必须在 rule parse 和 request match 两侧使用同一规范化函数。

必须覆盖测试：

```text
/admin
//admin
/%61dmin
/public/../admin
/v1/%2e%2e/admin
```

否则 deny rule 和 allow rule 都可能被编码绕过。

### 10.4 DNS rebinding 防护

现有 mimobox 防护已经包含两个关键点：

- 拒绝 IP literal。
- DNS 预解析后拒绝 private / loopback / link-local / reserved 地址，并将
  `reqwest` 固定到已验证 IP。

建议保留并补强：

- mixed DNS 结果中只允许使用已验证 public IP。
- 继续禁用 redirect；如未来启用 redirect，必须对每次跳转重新执行 ACL 和 DNS 校验。
- host 匹配使用 URL host，不使用 request header 的 Host。
- 继续过滤 `Host` header，避免 upstream 收到与 URL host 不一致的值。

### 10.5 Header 与 method 安全

当前 header blocklist 应保留。

method 处理建议：

- 在 ACL 检查前将 method 解析为 `HttpMethod`。
- 只允许 P0 method enum 中的值。
- 保持禁止 `CONNECT` 与 `TRACE`。
- 对小写 method 给出明确错误或规范化为大写；建议规范化后再匹配。

### 10.6 日志与审计

ACL 拒绝应有结构化日志：

```text
request_id
method
host
path
matched_rule_type=deny|none
matched_rule_index
error_code=http_denied_acl
```

注意不要记录敏感 header、body 或完整 query，避免泄露 API key。

## 11. 工作量估算

| 模块 | 工作内容 | 估算 |
|------|----------|------|
| Rust core | `HttpAclRule` / `HttpMethod` / `HttpAclPolicy`、validate、error code | 0.5-1 天 |
| Rust SDK | Config 字段、builder、legacy 域名转换、配置冲突校验 | 0.5-1 天 |
| VM proxy | ACL 检查层、路径规范化、错误映射、日志 | 1-1.5 天 |
| Python | 构造参数、类型解析、错误映射、Python 单测 | 0.5-1 天 |
| 快照兼容 | 新字段序列化、旧快照兼容解码 | 0.5 天 |
| 测试 | Rust 单测、VM proxy 测试、Python binding 测试 | 1-1.5 天 |
| 文档示例 | SDK README / Python 示例 / migration note | 0.5 天 |

P0 总工期：约 **4-6 个开发日**。

如果额外引入 sandlock 式透明 HTTPS MITM：

- seccomp-unotify 重定向、hudsucker 集成、CA 管理、guest trust store 注入、
  Host header 原始目的地验证、端口策略和跨平台降级都需要新增设计。
- 估算至少 **3-5 周**，且会显著提高维护成本。

## 12. 推荐里程碑

### M1：规则模型与 SDK

- 完成 core / SDK / Python API。
- `allowed_http_domains` 可无损迁移到 HTTP ACL allow rules。
- 所有规则解析和路径规范化单测通过。

### M2：VM proxy enforcement

- `execute_http_request` 发起网络前完成 ACL 检查。
- ACL 拒绝返回稳定错误码 `http_denied_acl`。
- 保持现有 DNS、header、body、redirect 安全边界不退化。

### M3：端到端验证

- Linux + KVM 环境通过 VM HTTP proxy 集成测试。
- Python SDK 参数与异常行为验证通过。
- 文档明确说明：P0 是 host proxy ACL，不是透明网络防火墙。

## 13. 最终建议

先做 **非 MITM 的 host proxy ACL**，作为 mimobox P0 HTTP 级 ACL。

这条路径利用了 mimobox 已有架构优势：

- guest 无直连网络。
- host 已有结构化 HTTP request。
- host 可在 TLS 前看到完整 URL。
- 现有 DNS、防 header 注入、响应限制可以继续复用。

透明 MITM 不是当前阶段的必要复杂度。
只有当 mimobox 明确要支持“guest 内任意二进制透明联网且无需改代码”时，
才需要重新评估 sandlock 式 seccomp-unotify + MITM 方案。
