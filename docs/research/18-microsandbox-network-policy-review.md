# Microsandbox 网络策略源码评审与 mimobox 改进建议

> 评审日期：2026-04-28
> 评审对象：`superradcompany/microsandbox` 网络策略实现
> 评审范围：`crates/network/lib/{config,policy,dns,secrets,tls,shared}.rs`
> 输出目标：为 mimobox 网络策略、DNS 可信链路和密钥注入设计提供可落地建议

---

## 1. 评审背景与目标

mimobox 当前坚持“网络默认拒绝”的安全基线，并已经在 microVM 路径上提供
host-side HTTP proxy，用于在 direct network 被阻断时开放受控 HTTPS 出口。
这个方向正确，但当前模型仍以 `deny_network: bool` 和
`allowed_http_domains: Vec<String>` 为核心，表达能力不足，难以承载后续
pip/npm/git/database 等更通用的网络访问场景。

Microsandbox 的价值不在于简单“允许网络”，而在于把网络能力拆成三个边界清晰的层次：
声明式策略层、DNS 可信解析链、host 侧数据面 enforcement。该架构对 mimobox
后续从“HTTP proxy allowlist”演进到“可审计、可组合、可跨协议的网络能力”有直接参考价值。

本次研究目标如下：

1. 评审 Microsandbox `NetworkPolicy` 数据结构，提取可迁移到 mimobox 的声明式策略模型。
2. 评审 Rule target 匹配模式，重点分析 CIDR、Domain、DomainSuffix 和 IP group 的组合方式。
3. 评审 DNS interceptor 的 rebind protection 与 DNS-to-IP pinning 机制，判断 mimobox 是否需要引入可信 DNS 反向索引。
4. 评审 secret injection 与 TLS MITM 的联动方式，设计 mimobox 短中期可实现的 placeholder 密钥注入方案。

---

## 2. Microsandbox 网络策略架构总览

### 2.1 整体架构

Microsandbox 以 `NetworkConfig` 作为网络配置总入口。它聚合了网络开关、接口参数、published ports、`NetworkPolicy`、`DnsConfig`、`TlsConfig`、`SecretsConfig`、连接上限和 host CA 信任设置。默认策略是 `NetworkPolicy::public_only()`，DNS rebind protection 默认开启。

架构上可拆为三层：

1. 策略层：`NetworkPolicy` 定义方向、协议、端口、目标和动作，使用 ordered rules + default fallback。
2. DNS 层：`DnsInterceptor` 和 `DnsForwarder` 拦截 DNS 查询，统一处理 block list、rebind protection、DNS-to-IP pinning。
3. 数据面：smoltcp poll loop、TCP/UDP/DNS/TLS proxy 任务执行真实流量转发，并在连接路径上调用策略评估。

该分层使 DNS 结果、域名策略和真实连接 enforcement 在 host 侧闭环，而不是把安全判断交给 guest。

### 2.2 核心模块关系图

模块调用关系可以概括为：

```text
NetworkConfig
├── policy: NetworkPolicy
│   ├── Rule / Action / Direction / Protocol / PortRange
│   ├── Destination
│   └── DestinationGroup -> destination::addr_classify()
├── dns: DnsConfig
│   ├── DnsInterceptor
│   │   └── UDP/53 smoltcp socket -> query channel
│   ├── TCP/53 proxy
│   ├── DoT proxy
│   └── DnsForwarder
│       ├── domain block exact/suffix
│       ├── rebind protection
│       └── SharedState::cache_resolved_hostname()
├── tls: TlsConfig
│   └── TlsState -> per-domain cert / bypass pattern
├── secrets: SecretsConfig
│   └── SecretsHandler -> placeholder substitution / violation detection
└── SharedState
    ├── TtlReverseIndex<ResolvedHostnameKey, IpAddr>
    ├── gateway IPv4/IPv6
    └── termination hook / metrics
```

关键链路如下：

1. guest 发起 DNS 查询，`DnsInterceptor` 捕获 `gateway:53` 和显式 resolver 请求。
2. `DnsForwarder` 对查询域名先执行 block list，再选择 upstream。
3. DNS 响应经过 rebind protection 后，A/AAAA 结果写入 `SharedState` 的 TTL 反向索引。
4. guest 后续连接某个 IP 时，`NetworkPolicy` 的 Domain/DomainSuffix rule 通过反向索引判断该 IP 是否来自允许域名。
5. HTTPS/TLS 流量如果进入 MITM 路径，TLS proxy 提取 SNI，构造 `SecretsHandler`，按 host allowlist 替换 placeholder。

---

## 3. 核心代码模式分析

### 3.1 NetworkPolicy 数据结构设计

Microsandbox 的 `NetworkPolicy` 是完整的声明式策略模型，而不是单个布尔开关。

完整类型系统包括：

1. `NetworkPolicy`：包含 `default_egress`、`default_ingress` 和 ordered `rules`。
2. `Rule`：包含 `direction`、`destination`、`protocols`、`ports` 和 `action`。
3. `Action`：`Allow` / `Deny`。
4. `Direction`：`Egress` / `Ingress` / `Any`。
5. `Destination`：`Any` / `Cidr` / `Domain` / `DomainSuffix` / `Group`。
6. `DestinationGroup`：`Public` / `Loopback` / `Private` / `LinkLocal` / `Metadata` / `Multicast` / `Host`。

核心源码模式如下：

```rust
pub struct NetworkPolicy {
    #[serde(default = "Action::deny")]
    pub default_egress: Action,
    #[serde(default = "Action::deny")]
    pub default_ingress: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

pub struct Rule {
    pub direction: Direction,
    pub destination: Destination,
    #[serde(default)]
    pub protocols: Vec<Protocol>,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    pub action: Action,
}
```

预设策略：

1. `none()`：egress/ingress 全部 deny。
2. `allow_all()`：egress/ingress 全部 allow。
3. `public_only()`：默认 egress deny，只允许 `DestinationGroup::Public`，ingress 默认 allow。
4. `non_local()`：默认 egress deny，允许 `Public` 和 `Private`，拒绝 loopback/link-local/metadata。

评估算法是 first-match-wins + default fallback：

```rust
pub fn evaluate_egress(
    &self,
    dst: SocketAddr,
    protocol: Protocol,
    shared: &SharedState,
) -> Action {
    for rule in &self.rules {
        if !matches!(rule.direction, Direction::Egress | Direction::Any) {
            continue;
        }
        if !rule_matches(rule, dst.ip(), Some(dst.port()), protocol, shared) {
            continue;
        }
        return rule.action;
    }
    self.default_egress
}
```

该模式的优势是可组合、可审计、可序列化。缺点是 rule 顺序成为策略语义的一部分，后续需要提供 builder、lint 和测试用例，避免“前置 allow 掩盖后置 deny”的误配置。

### 3.2 Rule Target 匹配模式

`Destination` 的五种匹配类型覆盖了网络策略的主要表达维度：

1. `Any`：匹配所有地址。
2. `Cidr(IpNetwork)`：匹配 IP 或 CIDR。
3. `Domain(DomainName)`：精确域名匹配。
4. `DomainSuffix(DomainName)`：apex + 子域名匹配。
5. `Group(DestinationGroup)`：预定义 IP 分类组。

Domain/DomainSuffix 的关键点是：连接时不重新解析域名，而是通过 DNS forwarder 写入的反向索引把目标 IP 映射回此前解析过的 hostname。

```rust
fn matches_destination(dest: &Destination, addr: IpAddr, shared: &SharedState) -> bool {
    match dest {
        Destination::Any => true,
        Destination::Cidr(network) => matches_cidr(network, addr),
        Destination::Group(group) => matches_group(*group, addr, shared),
        Destination::Domain(domain) => {
            shared.any_resolved_hostname(addr, |hostname| hostname == domain.as_str())
        }
        Destination::DomainSuffix(suffix) => {
            shared.any_resolved_hostname(addr, |hostname| matches_suffix(hostname, suffix.as_str()))
        }
    }
}
```

`DestinationGroup` 的优先级排序由 `addr_classify()` 固化：

```rust
fn addr_classify(addr: IpAddr, shared: &SharedState) -> DestinationGroup {
    if matches_host(addr, shared) {
        DestinationGroup::Host
    } else if is_metadata(addr) {
        DestinationGroup::Metadata
    } else if is_loopback(addr) {
        DestinationGroup::Loopback
    } else if is_private(addr) {
        DestinationGroup::Private
    } else if is_link_local(addr) {
        DestinationGroup::LinkLocal
    } else if is_multicast(addr) {
        DestinationGroup::Multicast
    } else {
        DestinationGroup::Public
    }
}
```

该顺序很重要：

1. `Host` 高于 `Private`，因为 gateway IP 可能位于 CGNAT 或 ULA 范围。
2. `Metadata` 高于 `LinkLocal`，因为 `169.254.169.254` 本身属于 link-local。
3. `Public` 是兜底分类，而不是靠维护“非某些组”的排除列表。

`DomainName` 类型将 canonicalization 做成类型不变量：

```rust
pub struct DomainName(String);

impl FromStr for DomainName {
    type Err = DomainNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim_start_matches('.').trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(DomainNameError::Empty);
        }
        let _name: Name = trimmed.parse()?;
        Ok(Self(trimmed.to_ascii_lowercase()))
    }
}
```

这比在每个匹配路径上临时 `to_lowercase()` 更稳健，也避免结构体字面量绕过校验。

### 3.3 DNS Interceptor 架构

Microsandbox 的 DNS 拓扑是：

```text
guest DNS query
  -> smoltcp UDP/TCP/DoT proxy
  -> DnsInterceptor / DNS proxy
  -> DnsForwarder
  -> configured upstream 或 policy-gated direct upstream
```

`DnsInterceptor` 绑定 `addr: None, port: 53`，因此不仅能接住默认 gateway DNS，也能捕获 `dig @1.1.1.1 example.com` 这类显式 resolver 请求，并通过 `original_dst` 保留 guest 原本瞄准的 resolver。

```rust
socket.bind(IpListenEndpoint {
    addr: None,
    port: DNS_PORT,
})?;

let query = DnsQuery {
    data: Bytes::copy_from_slice(&buf[..n]),
    source: meta.endpoint,
    original_dst: meta.local_address,
};
```

DNS 端口被分为四类：

```rust
pub(crate) enum DnsPortType {
    Dns,
    EncryptedDns,
    AlternativeDns,
    Other,
}

impl DnsPortType {
    pub(crate) fn from_tcp(port: u16) -> Self {
        match port {
            53 => Self::Dns,
            853 => Self::EncryptedDns,
            _ => Self::Other,
        }
    }

    pub(crate) fn from_udp(port: u16) -> Self {
        match port {
            53 => Self::Dns,
            853 | 5353 | 5355 | 137 => Self::AlternativeDns,
            _ => Self::Other,
        }
    }
}
```

设计意图：

1. `Dns`：统一交给 DNS forwarder，block list 和 rebind protection 在应用层执行。
2. `EncryptedDns`：DoT 可在 TLS MITM 配置下解密后转 forwarder，否则拒绝。
3. `AlternativeDns`：DoQ/mDNS/LLMNR/NetBIOS-NS 无法可靠做域名策略，直接拒绝或丢弃。
4. `Other`：不是 DNS，交给普通网络策略处理。

Rebind Protection 的实现点在 forwarder 响应路径：DNS 响应中只要 A/AAAA 出现 private/reserved 地址，就合成 `REFUSED`，而不是把危险答案交给 guest。

```rust
if self.config.rebind_protection {
    for record in response_msg.answers() {
        let is_private = match record.data() {
            RData::A(a) => is_private_ipv4((*a).into()),
            RData::AAAA(aaaa) => is_private_ipv6((*aaaa).into()),
            _ => false,
        };
        if is_private {
            return build_status_response(&query_msg, ResponseCode::Refused);
        }
    }
}
```

DNS-to-IP Pinning 使用 `SharedState` 内部的 TTL 反向索引：

```rust
resolved_hostnames: RwLock<TtlReverseIndex<ResolvedHostnameKey, IpAddr>>,

pub fn cache_resolved_hostname(
    &self,
    domain: &str,
    family: ResolvedHostnameFamily,
    addrs: impl IntoIterator<Item = IpAddr>,
    ttl: Duration,
) {
    let hostname = normalize_hostname(domain);
    let key = ResolvedHostnameKey { hostname, family };
    self.resolved_hostnames.write().insert(key, addrs, ttl, Instant::now());
}
```

零 TTL 会被抬到 1 秒，避免“DNS 刚成功，连接立即因 pin 过期而 fail closed”：

```rust
const RESOLVED_HOSTNAME_MIN_TTL_SECS: u32 = 1;

let record_ttl =
    Duration::from_secs(u64::from(record.ttl().max(RESOLVED_HOSTNAME_MIN_TTL_SECS)));
```

Domain Block 采用 exact + suffix 两套结构：

1. exact：`blocked_domains: HashSet<String>`，O(1) 查找。
2. suffix：预处理为普通 suffix 和点前缀 suffix，避免每次查询动态分配。

### 3.4 Secret Injection 联动机制

Microsandbox 的 secret injection 核心不是“把 secret 放进 guest”，而是 placeholder 模式：
guest 只看到 `$MSB_...` 占位符，真实 secret 留在 host/network engine。

配置结构如下：

```rust
pub struct SecretsConfig {
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,
    #[serde(default)]
    pub on_violation: ViolationAction,
}

pub struct SecretEntry {
    pub env_var: String,
    pub value: String,
    pub placeholder: String,
    #[serde(default)]
    pub allowed_hosts: Vec<HostPattern>,
    #[serde(default)]
    pub injection: SecretInjection,
    #[serde(default = "default_true")]
    pub require_tls_identity: bool,
}
```

`HostPattern` 支持三类过滤：

1. `Exact(String)`：精确 hostname。
2. `Wildcard(String)`：例如 `*.openai.com`，可覆盖 apex 和子域名。
3. `Any`：任意 host，注释中也明确标为危险。

TLS MITM 的联动点在 `tls/proxy.rs`：

1. 先从 ClientHello 提取 SNI。
2. 如果命中 bypass pattern，则走纯 TCP splice，不解密，不替换 secret。
3. 如果进入 intercept 路径，则为该 SNI 创建 `SecretsHandler`。
4. 代理解密 guest -> server 方向 HTTP plaintext，执行 substitution。

```rust
let (sni_name, initial_buf) = sni_name?;

if tls_state.should_bypass(&sni_name) {
    bypass_relay(dst, initial_buf, from_smoltcp, to_smoltcp, shared).await
} else {
    intercept_relay(dst, &sni_name, initial_buf, from_smoltcp, to_smoltcp, shared, tls_state).await
}
```

`SecretsHandler` 会按 SNI 过滤 eligible secrets，并保留全部 placeholder 用于 violation 检测：

```rust
let host_allowed = secret.allowed_hosts.is_empty()
    || secret.allowed_hosts.iter().any(|p| p.matches(sni));

if host_allowed {
    eligible.push(EligibleSecret {
        placeholder: secret.placeholder.clone(),
        value: secret.value.clone(),
        inject_headers: secret.injection.headers,
        inject_basic_auth: secret.injection.basic_auth,
        inject_query_params: secret.injection.query_params,
        inject_body: secret.injection.body,
        require_tls_identity: secret.require_tls_identity,
    });
}
```

Violation 检测与动作：

1. placeholder 发往未授权 host 时返回 `None`，阻断请求。
2. `BlockAndLog` 会写安全日志。
3. `BlockAndTerminate` 会触发终止路径，由上层调用 termination hook。

```rust
if self.has_violation(&text) {
    match self.on_violation {
        ViolationAction::Block => return None,
        ViolationAction::BlockAndLog => {
            tracing::warn!("secret violation: placeholder detected for disallowed host");
            return None;
        }
        ViolationAction::BlockAndTerminate => {
            tracing::error!("secret violation: placeholder detected for disallowed host");
            return None;
        }
    }
}
```

如果 body substitution 改变了请求体长度，`Content-Length` 会被自动修正：

```rust
if boundary.is_some() && body_str.len() != body_bytes.len() {
    header_str = update_content_length(&header_str, body_str.len());
}
```

这说明 Microsandbox 把 secret injection 当作 HTTP 语义层能力处理，而不是简单字节替换。

---

## 4. mimobox 当前网络实现分析

### 4.1 策略模型

mimobox 当前有两层网络配置：

1. core 层：`SandboxConfig` 暴露 `deny_network: bool` 和 `allowed_http_domains: Vec<String>`。
2. SDK 层：`NetworkPolicy` 枚举包含 `DenyAll`、`AllowDomains(Vec<String>)`、`AllowAll`。

现有 core 结构：

```rust
pub struct SandboxConfig {
    pub deny_network: bool,
    pub allowed_http_domains: Vec<String>,
}
```

SDK 策略枚举：

```rust
pub enum NetworkPolicy {
    DenyAll,
    AllowDomains(Vec<String>),
    AllowAll,
}
```

SDK 映射逻辑是：

```rust
fn resolve_deny_network(network: &NetworkPolicy) -> bool {
    match network {
        NetworkPolicy::DenyAll => true,
        NetworkPolicy::AllowDomains(_) => true,
        NetworkPolicy::AllowAll => false,
    }
}
```

这里的语义其实是“direct network denied，但 host proxy 可按域名放行”。然而 core `SandboxConfig::validate()` 仍拒绝 `deny_network=true + allowed_http_domains 非空`：

```rust
if self.deny_network && !self.allowed_http_domains.is_empty() {
    return Err(SandboxError::ExecutionFailed(
        "deny_network=true 但 allowed_http_domains 非空...".to_string(),
    ));
}
```

这是配置语义债务。SDK 测试已经表达了 `AllowDomains` 应保持 direct network denied，并转发 HTTP allowlist；core validate 却仍按旧语义校验，后续会制造跨层不一致。

### 4.2 HTTP Proxy 现有优势

mimobox 的 `crates/mimobox-vm/src/http_proxy.rs` 已经具备较好的 HTTP 出口安全基线：

1. 只接受 HTTPS URL。
2. 拒绝 direct IP literal。
3. 域名必须命中 `allowed_http_domains`，支持 `*.example.com` 通配符。
4. 每次请求前执行 DNS 解析，拒绝解析到 loopback/private/link-local/unspecified。
5. 使用 `reqwest::ClientBuilder::resolve()` 把本次请求 pin 到预校验 IP，避免校验后再次解析漂移。
6. 禁用自动 redirect，降低 allowlist 被跳转绕过的风险。

关键模式：

```rust
let verified_ip = validate_dns_resolution(&url)?;
let socket_addr = SocketAddr::new(verified_ip, port);
let resolve_key = format!("{host}:{port}");

let client = Client::builder()
    .timeout(timeout)
    .redirect(Policy::none())
    .resolve(&resolve_key, socket_addr)
    .build()?;
```

这说明 mimobox 短期不需要先上完整 smoltcp 栈，也能把 HTTP proxy 继续做强。

### 4.3 已识别差距

当前差距如下：

1. 无声明式策略模型：不能表达 direction、protocol、port、CIDR、IP group、domain suffix。
2. 无通用 DNS interceptor：`AllowDomains` 只适用于 host HTTP proxy，不适用于未来 direct TCP/UDP。
3. 无 DNS-to-IP TTL 反向索引：未来一旦允许透明 TCP/UDP，就缺少“这个 IP 来自哪个已解析域名”的 host 侧证据。
4. 无 secret placeholder 注入：真实 secret 如果通过 env 给 guest，会扩大 agent 泄密面。
5. rebind 分类未覆盖 CGN、metadata、multicast、reserved 等类别。
6. 配置语义矛盾：SDK 的 `AllowDomains` 需要 `deny_network=true + allowed_http_domains`，core validate 却拒绝。

---

## 5. 改进方案与数据结构设计

### 5.1 P0：声明式 NetworkPolicy 模型（3-5 人日）

建议先在 SDK/core 层引入声明式策略模型，但执行层第一阶段只映射到现有 HTTP proxy，不立即实现任意 TCP/UDP 数据面。

具体 Rust 数据结构定义：

```rust
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetworkPolicy {
    pub default_egress: NetworkAction,
    pub default_ingress: NetworkAction,
    pub rules: Vec<NetworkRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetworkRule {
    pub direction: NetworkDirection,
    pub target: NetworkTarget,
    #[serde(default)]
    pub protocols: Vec<NetworkProtocol>,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    pub action: NetworkAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDirection {
    Egress,
    Ingress,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTarget {
    Any,
    Cidr(IpCidr),
    Domain(DomainName),
    DomainSuffix(DomainName),
    Group(NetworkGroup),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkGroup {
    Public,
    Loopback,
    Private,
    LinkLocal,
    Metadata,
    Multicast,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainName(String);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IpCidr {
    V4 { addr: std::net::Ipv4Addr, prefix: u8 },
    V6 { addr: std::net::Ipv6Addr, prefix: u8 },
}
```

与现有 HTTP proxy 的映射关系：

1. `NetworkPolicy::DenyAll` 映射为 direct network denied，HTTP proxy allowlist 为空。
2. `AllowDomains(domains)` 可兼容为 `default_egress=Deny` + 若干 `Domain/DomainSuffix + TCP/443 Allow` rule。
3. `AllowAll` 映射为 direct network allowed，并使用网络型 seccomp profile。
4. 第一阶段 only-http enforcement：只从 allow rules 中提取 HTTPS domain/suffix，写入 `allowed_http_domains`。
5. CIDR/IP group/UDP/ICMP/ingress rule 第一阶段只进入配置模型和校验，不承诺执行。

工作量预估：3-5 人日。

依赖关系：

1. 依赖 P0 配置语义修复，否则声明式 policy 落到 core 后仍可能被 validate 拒绝。
2. 依赖序列化兼容性设计，需要保留现有 `NetworkPolicy` 枚举的迁移路径。
3. 依赖 SDK README 和示例更新，避免用户误解“声明式 policy 已全协议 enforcement”。

风险提示：

1. 如果数据结构一次性暴露太多字段，但执行层只支持 HTTP，会产生“配置可表达但无法生效”的语义落差。
2. ordered rules 会引入策略顺序风险，需要 builder 或 linter 防止宽泛 allow 覆盖精细 deny。
3. 不建议在没有 DNS 反向索引前承诺 Domain rule 适用于 direct TCP/UDP。

### 5.2 P0：配置语义修复（1-2 人日）

应先修复 `SandboxConfig::validate()` 中的矛盾逻辑，将 `deny_network` 重新定义为 direct network 开关，而不是“任何网络能力都禁止”。

建议新增更清晰的配置字段，但为了兼容可先保留旧字段：

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxConfig {
    /// 是否禁止 guest 进程直接创建外部网络连接。
    pub deny_network: bool,
    /// 允许通过 host-controlled HTTP proxy 访问的域名。
    #[serde(default)]
    pub allowed_http_domains: Vec<String>,
    /// 后续替代字段：语义更清晰，避免 deny_network 与 proxy allowlist 冲突。
    #[serde(default)]
    pub network_proxy: NetworkProxyConfig,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NetworkProxyConfig {
    pub enabled: bool,
    pub allowed_http_domains: Vec<DomainPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DomainPattern {
    Exact(DomainName),
    WildcardSuffix(DomainName),
}
```

短期 validate 逻辑建议：

```rust
impl SandboxConfig {
    pub fn validate(&self) -> Result<(), SandboxError> {
        for domain in &self.allowed_http_domains {
            validate_http_domain(domain)?;
        }

        if !self.deny_network && !self.allowed_http_domains.is_empty() {
            tracing::warn!(
                "direct network is allowed; HTTP proxy allowlist no longer bounds all egress"
            );
        }

        Ok(())
    }
}
```

工作量预估：1-2 人日。

依赖关系：

1. 无强依赖，应作为最先合入项。
2. 需要补充 core 层 contract test，覆盖 `deny_network=true + allowed_http_domains 非空` 合法。
3. 需要确认 OS backend、Wasm backend、VM backend 对该字段的解释一致。

风险提示：

1. 字段名 `deny_network` 已有历史语义，直接改语义会影响老用户认知。
2. 如果 `deny_network=false` 同时设置 allowlist，allowlist 不再是完整 egress 边界，应在文档和日志中明确提示。
3. 如果保留旧字段和新增 `network_proxy`，需要处理双写冲突。

### 5.3 P1：统一 IpClass 与 Rebind Guard（2-3 人日）

mimobox 当前 `is_private_ip()` 已覆盖 private、loopback、link-local、unspecified、IPv6 ULA，但未覆盖 CGN、metadata、multicast 和更多 reserved 类别。建议抽出统一 `IpClass` 分类器，供 HTTP proxy、未来 DNS forwarder 和策略层共用。

具体 Rust 数据结构定义：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    Public,
    Host,
    Metadata,
    Loopback,
    Private,
    Cgnat,
    LinkLocal,
    Multicast,
    Unspecified,
    Documentation,
    Reserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostGatewayIps {
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebindGuardConfig {
    pub allow_public: bool,
    pub allow_private: bool,
    pub allow_host: bool,
    pub allow_metadata: bool,
}

pub fn classify_ip(ip: std::net::IpAddr, host: HostGatewayIps) -> IpClass {
    // 实现顺序必须稳定：Host > Metadata > Loopback > Private/CGN >
    // LinkLocal > Multicast > Unspecified > Reserved > Public。
    if is_host_gateway(ip, host) {
        IpClass::Host
    } else if is_metadata_ip(ip) {
        IpClass::Metadata
    } else if ip.is_loopback() {
        IpClass::Loopback
    } else if is_rfc1918_or_ula(ip) {
        IpClass::Private
    } else if is_cgnat(ip) {
        IpClass::Cgnat
    } else if is_link_local(ip) {
        IpClass::LinkLocal
    } else if is_multicast(ip) {
        IpClass::Multicast
    } else if ip.is_unspecified() {
        IpClass::Unspecified
    } else if is_documentation_or_reserved(ip) {
        IpClass::Reserved
    } else {
        IpClass::Public
    }
}

pub fn reject_dns_rebind(
    host: &str,
    addrs: impl IntoIterator<Item = std::net::IpAddr>,
    config: RebindGuardConfig,
    gateway: HostGatewayIps,
) -> Result<Vec<std::net::IpAddr>, RebindViolation> {
    let mut accepted = Vec::new();
    for ip in addrs {
        let class = classify_ip(ip, gateway);
        if !config.allows(class) {
            return Err(RebindViolation::DisallowedClass {
                host: host.to_string(),
                ip,
                class,
            });
        }
        accepted.push(ip);
    }
    if accepted.is_empty() {
        return Err(RebindViolation::NoUsableAddress {
            host: host.to_string(),
        });
    }
    Ok(accepted)
}

#[derive(Debug, thiserror::Error)]
pub enum RebindViolation {
    #[error("{host} resolved to disallowed IP class {class:?}: {ip}")]
    DisallowedClass {
        host: String,
        ip: std::net::IpAddr,
        class: IpClass,
    },
    #[error("{host} resolved no usable addresses")]
    NoUsableAddress { host: String },
}
```

建议默认策略：

1. HTTP proxy 默认只允许 `IpClass::Public`。
2. 如果后续支持 `host.mimobox.internal`，只允许该显式 host alias 命中 `IpClass::Host`。
3. metadata、loopback、link-local、multicast、unspecified、reserved 默认拒绝。
4. DNS 响应只要包含不允许类别，默认拒绝整次解析，而不是挑一个 public 地址继续用。

工作量预估：2-3 人日。

依赖关系：

1. 可独立于 P0 NetworkPolicy 实施。
2. HTTP proxy 可先接入该分类器替换 `is_private_ip()`。
3. 后续 P2 `DnsPinStore` 可复用分类结果与审计字段。

风险提示：

1. IP 分类容易受标准库版本能力影响，建议显式写 CIDR 判断并加测试。
2. “只要响应含私网地址就拒绝”更安全，但可能误伤 split-horizon DNS 或企业内网场景。
3. 如果未来允许 private LAN，需要按策略显式开启，不能通过默认配置放宽。

### 5.4 P1：Secret Placeholder 注入（4-7 人日）

建议 mimobox 先在现有 HTTP proxy 中实现 secret placeholder 注入，不立即引入 TLS MITM。原因是当前 HTTP proxy 已经在 host 侧构造 `reqwest` 请求，本身能看到 URL、headers 和 body 的明文语义。

具体 Rust 数据结构定义：

```rust
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecretsConfig {
    #[serde(default)]
    pub entries: Vec<SecretEntry>,
    #[serde(default)]
    pub on_violation: SecretViolationAction,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretEntry {
    /// guest 环境变量名，例如 OPENAI_API_KEY。
    pub env_var: String,
    /// guest 看到的占位符，例如 $MSB_SECRET_OPENAI_API_KEY。
    pub placeholder: SecretPlaceholder,
    /// host 侧 secret 来源，不直接序列化真实值到 guest。
    pub value_ref: SecretValueRef,
    /// 允许接收该 secret 的域名范围。
    #[serde(default)]
    pub allowed_hosts: Vec<DomainPattern>,
    /// 允许替换的位置。
    #[serde(default)]
    pub scopes: SecretScopes,
    /// 单 secret 级违规动作，None 时使用全局配置。
    #[serde(default)]
    pub on_violation: Option<SecretViolationAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretPlaceholder(String);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SecretValueRef {
    Env(String),
    InlineRedacted(String),
    File(std::path::PathBuf),
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct SecretScopes {
    pub headers: bool,
    pub authorization: bool,
    pub query_params: bool,
    pub body: bool,
}

impl Default for SecretScopes {
    fn default() -> Self {
        Self {
            headers: true,
            authorization: true,
            query_params: false,
            body: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretViolationAction {
    Block,
    #[default]
    BlockAndLog,
    BlockAndTerminate,
}
```

HTTP proxy 集成方式：

1. sandbox guest env 只注入 `env_var -> placeholder`。
2. host HTTP proxy 收到 request 后，根据目标 host 筛选 eligible secrets。
3. 在 request headers/query/body 中按 `SecretScopes` 做替换。
4. 若发现 placeholder 发往不在 allowlist 的 host，按 `SecretViolationAction` 阻断、记录或终止。
5. 如果替换 body，必须更新 `Content-Length` 或让 `reqwest` 重新计算 body 长度。

工作量预估：4-7 人日。

依赖关系：

1. 依赖 P0 配置语义修复，确保 proxy allowlist 语义清晰。
2. 建议依赖 P1 `DomainPattern` / `DomainName`，避免 secret allowlist 自己实现一套域名匹配。
3. 若要支持 `BlockAndTerminate`，需要 VM/OS 后端提供统一 termination hook。

风险提示：

1. Secret 替换必须避免把真实 secret 写入日志、错误信息和 Debug 输出。
2. 如果支持 body 替换，必须处理非 UTF-8、multipart、streaming body、chunked body 等边界；首版可限制为 UTF-8 小 body。
3. 仅在 HTTP proxy 中实现时，不能保护 guest 直接出网路径；因此必须保持 direct network 默认 deny。
4. `DomainPattern::Any` 应不建议开放，至少需要显式 unsafe/dangerous 命名或 lint。

### 5.5 P2：DnsPinStore（3-5 人日）

短期可先引入 `DnsPinStore` 服务 HTTP proxy 和审计日志。它不必立即成为透明 TCP/UDP enforcement 的依赖，但应按未来 DNS-to-IP 反向索引设计。

具体 Rust 数据结构定义：

```rust
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsPinKey {
    pub domain: DomainName,
    pub family: AddressFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone)]
pub struct DnsPin {
    pub key: DnsPinKey,
    pub ips: HashSet<IpAddr>,
    pub expires_at: Instant,
    pub source: DnsPinSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPinSource {
    HttpProxy,
    DnsInterceptor,
    StaticHostAlias,
}

#[derive(Debug, Default)]
pub struct DnsPinStore {
    by_domain: HashMap<DnsPinKey, DnsPin>,
    by_ip: HashMap<IpAddr, HashSet<DnsPinKey>>,
}

impl DnsPinStore {
    pub fn insert(
        &mut self,
        domain: DomainName,
        family: AddressFamily,
        ips: impl IntoIterator<Item = IpAddr>,
        ttl: Duration,
        source: DnsPinSource,
        now: Instant,
    ) {
        let key = DnsPinKey { domain, family };
        let expires_at = now + ttl.max(Duration::from_secs(1));
        let ips: HashSet<IpAddr> = ips.into_iter().collect();

        if let Some(old) = self.by_domain.remove(&key) {
            for ip in old.ips {
                remove_reverse_mapping(&mut self.by_ip, ip, &key);
            }
        }

        for ip in &ips {
            self.by_ip.entry(*ip).or_default().insert(key.clone());
        }

        self.by_domain.insert(
            key.clone(),
            DnsPin {
                key,
                ips,
                expires_at,
                source,
            },
        );
    }

    pub fn any_hostname_for_ip(
        &mut self,
        ip: IpAddr,
        now: Instant,
        mut predicate: impl FnMut(&DomainName) -> bool,
    ) -> bool {
        self.evict_expired(now);
        self.by_ip
            .get(&ip)
            .into_iter()
            .flatten()
            .filter_map(|key| self.by_domain.get(key))
            .any(|pin| predicate(&pin.key.domain))
    }

    pub fn evict_expired(&mut self, now: Instant) {
        let expired: Vec<DnsPinKey> = self
            .by_domain
            .iter()
            .filter_map(|(key, pin)| (pin.expires_at <= now).then_some(key.clone()))
            .collect();

        for key in expired {
            if let Some(pin) = self.by_domain.remove(&key) {
                for ip in pin.ips {
                    remove_reverse_mapping(&mut self.by_ip, ip, &key);
                }
            }
        }
    }
}
```

首版用途：

1. HTTP proxy DNS 解析后写入 pin store。
2. 请求审计日志记录“host -> selected IP -> TTL/expiry”。
3. 未来 direct TCP/UDP policy 可复用 `any_hostname_for_ip()` 判断 Domain rule。
4. 为未来 DNS interceptor 留好 `DnsPinSource::DnsInterceptor`。

工作量预估：3-5 人日。

依赖关系：

1. 建议依赖 P1 `DomainName` 和 `IpClass`。
2. 不强依赖通用 DNS interceptor。
3. 需要在 HTTP proxy 中保留 DNS TTL；标准 `to_socket_addrs()` 不返回 TTL，可能需要切换到 hickory-resolver 或平台 DNS API。

风险提示：

1. 如果解析 API 拿不到 TTL，只能使用保守短 TTL，会降低缓存价值。
2. 反向索引需要定期清理，否则长时间运行的 daemon 可能积累过期映射。
3. 多域名共用 CDN IP 时，反向索引是多对多关系，不能假设一个 IP 只属于一个域名。

### 5.6 P3：通用网络数据面（3-5 周 Linux / 8-12 周跨 OS）

只有当 mimobox 明确需要透明支持 pip/npm/git/database 等非 HTTP proxy 场景时，才建议进入通用网络数据面阶段。短期不建议复制 Microsandbox 完整 smoltcp 栈。

候选路径：

1. Linux microVM：host proxy + virtio-net/smoltcp 数据面，接管 guest TCP/UDP。
2. OS sandbox：优先使用平台能力阻断 direct network，必要时提供显式代理。
3. 跨 OS：抽象为统一 `NetworkBackend`，不同平台实现不同 enforcement 能力。

具体 Rust 数据结构定义：

```rust
#[async_trait::async_trait]
pub trait NetworkBackend: Send + Sync {
    async fn start(&mut self, config: NetworkRuntimeConfig) -> Result<NetworkHandle, NetworkError>;
    async fn stop(&mut self) -> Result<(), NetworkError>;
    fn guest_env_vars(&self) -> Vec<(String, String)>;
    fn metrics(&self) -> NetworkMetricsSnapshot;
}

#[derive(Debug, Clone)]
pub struct NetworkRuntimeConfig {
    pub enabled: bool,
    pub policy: NetworkPolicy,
    pub dns: DnsRuntimeConfig,
    pub tls: TlsRuntimeConfig,
    pub secrets: SecretsConfig,
    pub max_connections: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct DnsRuntimeConfig {
    pub intercept_plain_dns: bool,
    pub block_encrypted_dns_without_mitm: bool,
    pub rebind_guard: RebindGuardConfig,
    pub blocked_domains: Vec<DomainName>,
    pub blocked_suffixes: Vec<DomainName>,
    pub nameservers: Vec<NameserverConfig>,
}

#[derive(Debug, Clone)]
pub enum NameserverConfig {
    Udp(std::net::SocketAddr),
    Tcp(std::net::SocketAddr),
    Dot { addr: std::net::SocketAddr, server_name: DomainName },
}

#[derive(Debug, Clone)]
pub struct TlsRuntimeConfig {
    pub mitm_enabled: bool,
    pub bypass_hosts: Vec<DomainPattern>,
    pub ca_cert_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone)]
pub struct NetworkHandle {
    pub gateway_ipv4: Option<std::net::Ipv4Addr>,
    pub gateway_ipv6: Option<std::net::Ipv6Addr>,
    pub dns_pin_store: std::sync::Arc<parking_lot::RwLock<DnsPinStore>>,
}
```

必须包含的能力：

1. smoltcp 或 host proxy 数据面，承接 guest TCP/UDP。
2. DNS interceptor，统一处理 UDP/53、TCP/53，必要时处理 DoT。
3. DoT/DoQ/mDNS/LLMNR/NetBIOS-NS 阻断策略，避免 DNS policy 绕过。
4. TLS MITM，用于 HTTPS 语义层 secret injection 和 DoH/SNI 级策略。
5. 与 `NetworkPolicy`、`DnsPinStore`、`SecretsConfig` 的统一联动。

工作量预估：

1. Linux microVM 首版：3-5 周。
2. 加 TLS MITM 和 secret injection 完整链路：额外 2-4 周。
3. 跨 OS 抽象和平台兼容：8-12 周。

依赖关系：

1. 强依赖 P0 声明式策略模型。
2. 强依赖 P1 `IpClass` / `RebindGuard`。
3. 强依赖 P2 `DnsPinStore`。
4. 若要 secret 安全闭环，依赖 P1 secret placeholder 注入。

风险提示：

1. smoltcp 数据面复杂度高，可能引入连接状态、MTU、TCP backpressure、性能调优等大量工程成本。
2. TLS MITM 涉及 CA 信任分发、证书生成缓存、SNI 缺失、HTTP/2/HTTP/3 兼容问题。
3. QUIC/DoH 很难只靠端口分类处理，需要 SNI/IP allowlist 或完整 TLS/QUIC 策略。
4. 跨 OS enforcement 能力差异大，不应承诺完全一致的网络隔离语义。

---

## 6. 总体评估与建议

短期路线：做强 HTTP proxy 策略平面。优先修复配置语义，抽出声明式 `NetworkPolicy`、`DomainName`、`DomainPattern`、`IpClass` 和 secret placeholder。执行层仍落到现有 HTTPS proxy，保持 direct network 默认 deny。

中期路线：建设 DNS 可信解析链。引入 `DnsPinStore`，在 HTTP proxy 中记录解析证据，并为未来 DNS interceptor 预留反向索引能力。此阶段重点是让 Domain/DomainSuffix rule 具备 host 侧可验证依据。

长期路线：通用网络数据面。只有当产品确实需要透明 TCP/UDP 出口时，再投入 smoltcp 或 host proxy 数据面、DNS interceptor、DoT/DoQ 阻断和 TLS MITM。

不建议短期复制 Microsandbox 完整 smoltcp 栈。mimobox 当前最有性价比的路径是延续“默认拒绝 + host-controlled proxy”，先把策略模型、DNS rebind、DNS pinning 和 secret placeholder 做扎实。这样既能解决当前 HTTP 出口安全问题，也不会过早承担完整 TCP/IP 数据面带来的复杂度。
