---
title: 串口 HTTP 代理协议设计
date: 2026-04-23
status: reviewed
scope: P0-b
reviewers: [Codex gpt-5.4, Claude 总指挥]
---

# 串口 HTTP 代理协议设计

## 1. 背景与动机

Agent 在 guest 中执行代码时需要调用外部 API（如 api.openai.com）。
mimobox 不给 guest 完整网络能力，而是在串口通道上增加 HTTP 代理命令帧。

竞品方案：
- E2B：默认开放互联网，sandbox 级网络控制
- Kata：virtio-net + CNI 网络插件
- Modal：完整容器网络

mimobox 方案差异化：**零 guest 网络栈**，host 侧白名单代理。

## 2. 协议设计

### 2.1 请求帧

```
HTTP:REQUEST:<id>:<len>:<json>\n
```

JSON 载荷：
```json
{
  "method": "GET",
  "url": "https://api.openai.com/v1/chat/completions",
  "headers": {"Authorization": "Bearer sk-...", "Content-Type": "application/json"},
  "body_b64": null,
  "timeout_ms": 30000,
  "max_response_bytes": 1048576
}
```

- `method`：GET/POST/PUT/PATCH/DELETE
- `url`：完整 HTTPS URL（仅支持 HTTPS）
- `headers`：可选请求头
- `body_b64`：请求体（base64 编码，可选）
- `timeout_ms`：超时（默认 30s）
- `max_response_bytes`：响应体大小上限（默认 1MB）

### 2.2 响应帧

多帧响应（处理大响应体）：

```
# 响应头
HTTPRESP:HEADERS:<id>:<len>:<json>\n
# JSON: {"status": 200, "headers": {...}, "body_len": 1234, "truncated": false}

# 响应体（可分多帧）
HTTPRESP:BODY:<id>:<len>:<bytes>\n

# 响应结束
HTTPRESP:END:<id>\n
```

### 2.3 错误帧

```
HTTPRESP:ERROR:<id>:<code>:<len>:<msg>\n
```

错误码：
| code | 含义 |
|------|------|
| DENIED_HOST | 域名不在白名单 |
| TIMEOUT | 请求超时 |
| BODY_TOO_LARGE | 响应体超过 max_response_bytes |
| CONNECT_FAIL | 连接失败 |
| TLS_FAIL | TLS 握手失败 |
| INVALID_URL | URL 格式无效 |
| INTERNAL | 内部错误 |

### 2.4 完整交互示例

```
guest → host:  HTTP:REQUEST:0:156:{"method":"GET","url":"https://api.openai.com/v1/models","headers":{"Authorization":"Bearer sk-xxx"},"timeout_ms":10000}

host → guest:  HTTPRESP:HEADERS:0:42:{"status":200,"headers":{"content-type":"application/json"},"body_len":1024}
host → guest:  HTTPRESP:BODY:0:1024:<json bytes>
host → guest:  HTTPRESP:END:0
```

被拒绝的请求：
```
guest → host:  HTTP:REQUEST:0:89:{"method":"GET","url":"https://evil.com/api",...}
host → guest:  HTTPRESP:ERROR:0:DENIED_HOST:14:域名不在白名单
```

## 3. 安全设计

### 3.1 白名单

- SandboxConfig 新增 `allowed_http_domains: Vec<String>`
- 通配符支持：`*.openai.com`
- 仅 HTTPS（拒绝 HTTP）
- 禁止 IP 直连（`1.2.3.4` 形式）
- 禁止内网地址（`10.x`、`192.168.x`、`127.x`）
- 禁止跟随重定向到非白名单域名

### 3.2 资源限制

- 最大响应体：可配置，默认 1MB
- 超时：可配置，默认 30s
- 并发请求数：上限 4（串口带宽有限）
- 请求体大小：上限 1MB

### 3.3 审计

- 每次 HTTP 请求记录：域名、method、状态码、耗时
- 拒绝的请求单独记录

## 4. 实现位置

```
crates/mimobox-vm/src/
├── http_proxy.rs       # 新建：HTTP 代理核心逻辑
├── kvm/
│   ├── devices/
│   │   └── serial.rs   # 修改：新增 HTTP:REQUEST/HTTPRESP 帧解析
│   └── kvm.rs          # 修改：KVM_RUN 循环中处理 HTTP 帧
└── guest/
    └── guest-init.c    # 修改：新增 HTTP:REQUEST 帧发送辅助函数
```

`http_proxy.rs` 独立于 `kvm/devices/`，设备层只负责帧收发。

## 5. Guest 侧改动

guest-init.c 新增辅助函数（供 guest 内 Python 调用）：

```c
// 发送 HTTP 请求并通过串口接收响应
// 不需要解析 HTTP，只负责串口帧的发送和接收
int http_request(const char *method, const char *url, ...);
```

但更实际的方式是：**guest Python 直接通过串口协议发送 HTTP:REQUEST 帧**。
guest-init.c 只需要识别并透传，或者在 /sandbox 下提供一个 FIFO 接口。

## 6. SDK API

### Rust SDK
```rust
impl Sandbox {
    pub fn http_request(
        &mut self,
        method: &str,
        url: &str,
        headers: HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse>;
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
```

### Python SDK
```python
class Sandbox:
    def http_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponse: ...

@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
```

## 7. 实现计划

| 步骤 | 文件 | 预估 |
|------|------|------|
| 串口帧定义 | serial.rs | 1h |
| HTTP 代理核心 | http_proxy.rs（新建） | 3h |
| 域名白名单 | SandboxConfig + http_proxy | 1h |
| KVM 集成 | kvm.rs | 1h |
| SDK API | mimobox-sdk | 1h |
| Python SDK | mimobox-python | 0.5h |
| E2E 测试 | kvm_e2e.rs | 1h |

## 8. 风险

1. **串口带宽**：大响应体通过串口传输慢 → 分帧传输 + 大小限制
2. **JSON 编解码**：guest C 代码没有 JSON 库 → host 侧编解码，guest 侧只透传
3. **并发**：串口天然串行，多个 HTTP 请求必须排队 → `<id>` 字段预留但当前串行执行
