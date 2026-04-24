//! mimobox MCP Server.
//!
//! Exposes 7 tools over stdio:
//! - create_sandbox
//! - destroy_sandbox
//! - list_sandboxes
//! - execute_code
//! - execute_command
//! - read_file
//! - write_file

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use mimobox_sdk::{Config, ExecuteResult, IsolationLevel, Sandbox, SdkError};
use rmcp::handler::server::wrapper::Json;
use rmcp::schemars::JsonSchema;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{error, info};

#[derive(Clone)]
struct MimoboxServer {
    sandboxes: Arc<Mutex<HashMap<u64, ManagedSandbox>>>,
    next_id: Arc<Mutex<u64>>,
    tool_router: ToolRouter<Self>,
}

struct ManagedSandbox {
    sandbox: Sandbox,
    created_at_ms: u64,
    created_at_instant: Instant,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CreateSandboxRequest {
    /// 可选隔离层级：auto、os、wasm、microvm。
    isolation_level: Option<String>,
    /// 沙箱默认超时时间，单位毫秒。
    timeout_ms: Option<u64>,
    /// 沙箱内存上限，单位 MiB。
    memory_limit_mb: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct CreateSandboxResponse {
    sandbox_id: u64,
    isolation_level: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ExecuteCodeRequest {
    /// 不提供时创建临时沙箱，执行完成后立即销毁。
    sandbox_id: Option<u64>,
    /// 要执行的代码片段。
    code: String,
    /// 可选语言：python、javascript、node、bash、sh。
    language: Option<String>,
    /// 本次执行的超时时间，单位毫秒。仅对临时沙箱生效。
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ExecuteCommandRequest {
    /// 不提供时创建临时沙箱，执行完成后立即销毁。
    sandbox_id: Option<u64>,
    /// 要执行的 shell 命令。
    command: String,
    /// 本次执行的超时时间，单位毫秒。仅对临时沙箱生效。
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DestroySandboxRequest {
    /// 要销毁的沙箱 ID。
    sandbox_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListSandboxesRequest {}

#[derive(Debug, Deserialize, JsonSchema)]
#[cfg_attr(not(feature = "vm"), allow(dead_code))]
struct ReadFileRequest {
    /// 目标沙箱 ID。
    sandbox_id: u64,
    /// 沙箱内文件路径。
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[cfg_attr(not(feature = "vm"), allow(dead_code))]
struct WriteFileRequest {
    /// 目标沙箱 ID。
    sandbox_id: u64,
    /// 沙箱内文件路径。
    path: String,
    /// Base64 编码后的文件内容。
    content: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ExecuteResponse {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed_ms: u128,
}

#[derive(Debug, Serialize, JsonSchema)]
struct DestroySandboxResponse {
    sandbox_id: u64,
    destroyed: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ListSandboxesResponse {
    sandboxes: Vec<SandboxSummary>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct SandboxSummary {
    sandbox_id: u64,
    isolation_level: Option<String>,
    created_at: u64,
    uptime_ms: u128,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ReadFileResponse {
    sandbox_id: u64,
    path: String,
    content: String,
    size_bytes: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
struct WriteFileResponse {
    sandbox_id: u64,
    path: String,
    size_bytes: usize,
    written: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ErrorResponse {
    error: String,
}

impl MimoboxServer {
    fn new() -> Self {
        Self {
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl MimoboxServer {
    #[tool(description = "Create a reusable mimobox sandbox instance")]
    async fn create_sandbox(
        &self,
        Parameters(request): Parameters<CreateSandboxRequest>,
    ) -> Result<Json<CreateSandboxResponse>, Json<ErrorResponse>> {
        let isolation =
            parse_isolation_level(request.isolation_level.as_deref()).map_err(to_error)?;
        let sandbox =
            create_sandbox_with_options(isolation, request.timeout_ms, request.memory_limit_mb)
                .map_err(|error| to_error(format_sdk_error(error)))?;

        let mut next_id = self.next_id.lock().await;
        let sandbox_id = *next_id;
        *next_id = next_id.saturating_add(1);
        drop(next_id);

        let mut sandboxes = self.sandboxes.lock().await;
        sandboxes.insert(
            sandbox_id,
            ManagedSandbox {
                sandbox,
                created_at_ms: unix_timestamp_ms(),
                created_at_instant: Instant::now(),
            },
        );

        Ok(Json(CreateSandboxResponse {
            sandbox_id,
            isolation_level: format_isolation_level(isolation).to_string(),
        }))
    }

    #[tool(description = "Destroy a reusable mimobox sandbox and release its resources")]
    async fn destroy_sandbox(
        &self,
        Parameters(request): Parameters<DestroySandboxRequest>,
    ) -> Result<Json<DestroySandboxResponse>, Json<ErrorResponse>> {
        let mut sandboxes = self.sandboxes.lock().await;
        let managed = sandboxes
            .remove(&request.sandbox_id)
            .ok_or_else(|| to_error(sandbox_not_found(request.sandbox_id)))?;
        drop(sandboxes);

        if let Err(err) = managed.sandbox.destroy() {
            error!(
                sandbox_id = request.sandbox_id,
                error = %format_sdk_error(err),
                "沙箱销毁失败，实例已从活动列表移除"
            );
        }

        Ok(Json(DestroySandboxResponse {
            sandbox_id: request.sandbox_id,
            destroyed: true,
        }))
    }

    #[tool(description = "List active mimobox sandboxes with their IDs and basic metadata")]
    async fn list_sandboxes(
        &self,
        Parameters(_request): Parameters<ListSandboxesRequest>,
    ) -> Result<Json<ListSandboxesResponse>, Json<ErrorResponse>> {
        let sandboxes = self.sandboxes.lock().await;
        let mut summaries = sandboxes
            .iter()
            .map(|(sandbox_id, managed)| SandboxSummary {
                sandbox_id: *sandbox_id,
                isolation_level: managed
                    .sandbox
                    .active_isolation()
                    .map(format_isolation_level)
                    .map(str::to_string),
                created_at: managed.created_at_ms,
                uptime_ms: managed.created_at_instant.elapsed().as_millis(),
            })
            .collect::<Vec<_>>();
        summaries.sort_by_key(|summary| summary.sandbox_id);

        Ok(Json(ListSandboxesResponse {
            sandboxes: summaries,
        }))
    }

    #[tool(description = "Execute a code snippet in a mimobox sandbox")]
    async fn execute_code(
        &self,
        Parameters(request): Parameters<ExecuteCodeRequest>,
    ) -> Result<Json<ExecuteResponse>, Json<ErrorResponse>> {
        let command =
            build_code_command(request.language.as_deref(), &request.code).map_err(to_error)?;
        let result = self
            .execute_with_optional_sandbox(request.sandbox_id, &command, request.timeout_ms)
            .await
            .map_err(to_error)?;

        Ok(Json(format_execute_result(result)))
    }

    #[tool(description = "Execute a shell command in a mimobox sandbox")]
    async fn execute_command(
        &self,
        Parameters(request): Parameters<ExecuteCommandRequest>,
    ) -> Result<Json<ExecuteResponse>, Json<ErrorResponse>> {
        let result = self
            .execute_with_optional_sandbox(request.sandbox_id, &request.command, request.timeout_ms)
            .await
            .map_err(to_error)?;

        Ok(Json(format_execute_result(result)))
    }

    #[tool(description = "Read a file from a microVM-backed mimobox sandbox as base64")]
    async fn read_file(
        &self,
        Parameters(request): Parameters<ReadFileRequest>,
    ) -> Result<Json<ReadFileResponse>, Json<ErrorResponse>> {
        #[cfg(feature = "vm")]
        {
            let mut sandboxes = self.sandboxes.lock().await;
            let managed = sandboxes
                .get_mut(&request.sandbox_id)
                .ok_or_else(|| to_error(sandbox_not_found(request.sandbox_id)))?;
            let content = managed
                .sandbox
                .read_file(&request.path)
                .map_err(|error| to_error(format_sdk_error(error)))?;
            let size_bytes = content.len();

            Ok(Json(ReadFileResponse {
                sandbox_id: request.sandbox_id,
                path: request.path,
                content: encode_base64(&content),
                size_bytes,
            }))
        }

        #[cfg(not(feature = "vm"))]
        {
            let _ = request;
            Err(to_error(file_transfer_requires_vm()))
        }
    }

    #[tool(description = "Write a base64-encoded file into a microVM-backed mimobox sandbox")]
    async fn write_file(
        &self,
        Parameters(request): Parameters<WriteFileRequest>,
    ) -> Result<Json<WriteFileResponse>, Json<ErrorResponse>> {
        #[cfg(feature = "vm")]
        {
            let data = decode_base64(&request.content).map_err(to_error)?;
            let size_bytes = data.len();
            let mut sandboxes = self.sandboxes.lock().await;
            let managed = sandboxes
                .get_mut(&request.sandbox_id)
                .ok_or_else(|| to_error(sandbox_not_found(request.sandbox_id)))?;
            managed
                .sandbox
                .write_file(&request.path, &data)
                .map_err(|error| to_error(format_sdk_error(error)))?;

            Ok(Json(WriteFileResponse {
                sandbox_id: request.sandbox_id,
                path: request.path,
                size_bytes,
                written: true,
            }))
        }

        #[cfg(not(feature = "vm"))]
        {
            let _ = request;
            Err(to_error(file_transfer_requires_vm()))
        }
    }

    async fn execute_with_optional_sandbox(
        &self,
        sandbox_id: Option<u64>,
        command: &str,
        timeout_ms: Option<u64>,
    ) -> Result<ExecuteResult, String> {
        if let Some(sandbox_id) = sandbox_id {
            let mut sandboxes = self.sandboxes.lock().await;
            let managed = sandboxes
                .get_mut(&sandbox_id)
                .ok_or_else(|| sandbox_not_found(sandbox_id))?;
            return managed.sandbox.execute(command).map_err(format_sdk_error);
        }

        let mut sandbox = create_sandbox_with_options(IsolationLevel::Auto, timeout_ms, None)
            .map_err(format_sdk_error)?;
        let result = sandbox.execute(command).map_err(format_sdk_error);
        if let Err(err) = sandbox.destroy() {
            error!(error = %format_sdk_error(err), "临时沙箱销毁失败");
        }
        result
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MimoboxServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "mimobox MCP Server: sandbox lifecycle, execution, and microVM file transfer tools",
        )
    }
}

fn unix_timestamp_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    millis.min(u128::from(u64::MAX)) as u64
}

fn create_sandbox_with_options(
    isolation: IsolationLevel,
    timeout_ms: Option<u64>,
    memory_limit_mb: Option<u64>,
) -> Result<Sandbox, SdkError> {
    let mut builder = Config::builder().isolation(isolation);
    if let Some(timeout_ms) = timeout_ms {
        builder = builder.timeout(Duration::from_millis(timeout_ms));
    }
    if let Some(memory_limit_mb) = memory_limit_mb {
        builder = builder.memory_limit_mb(memory_limit_mb);
    }

    Sandbox::with_config(builder.build())
}

fn parse_isolation_level(value: Option<&str>) -> Result<IsolationLevel, String> {
    match value.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "auto" => Ok(IsolationLevel::Auto),
        "os" => Ok(IsolationLevel::Os),
        "wasm" => Ok(IsolationLevel::Wasm),
        "microvm" | "micro_vm" | "micro-vm" | "vm" => Ok(IsolationLevel::MicroVm),
        other => Err(format!(
            "不支持的 isolation_level={other}，可选值为 auto、os、wasm、microvm"
        )),
    }
}

fn format_isolation_level(level: IsolationLevel) -> &'static str {
    match level {
        IsolationLevel::Auto => "auto",
        IsolationLevel::Os => "os",
        IsolationLevel::Wasm => "wasm",
        IsolationLevel::MicroVm => "microvm",
    }
}

fn sandbox_not_found(sandbox_id: u64) -> String {
    format!("未找到 sandbox_id={sandbox_id} 的沙箱实例")
}

#[cfg(not(feature = "vm"))]
fn file_transfer_requires_vm() -> String {
    "文件传输需要 microVM 后端支持，请启用 vm feature 并使用 MicroVm 隔离层级".to_string()
}

fn build_code_command(language: Option<&str>, code: &str) -> Result<String, String> {
    let escaped_code = shell_single_quote(code);
    match language.unwrap_or("bash").to_ascii_lowercase().as_str() {
        "python" | "python3" | "py" => Ok(format!("python3 -c {escaped_code}")),
        "javascript" | "js" | "node" | "nodejs" => Ok(format!("node -e {escaped_code}")),
        "bash" => Ok(format!("bash -c {escaped_code}")),
        "sh" | "shell" => Ok(format!("sh -c {escaped_code}")),
        other => Err(format!(
            "不支持的 language={other}，可选值为 python、node、bash、sh"
        )),
    }
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn format_execute_result(result: ExecuteResult) -> ExecuteResponse {
    ExecuteResponse {
        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        exit_code: result.exit_code,
        timed_out: result.timed_out,
        elapsed_ms: result.elapsed.as_millis(),
    }
}

#[cfg(feature = "vm")]
const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[cfg(feature = "vm")]
fn encode_base64(data: &[u8]) -> String {
    let mut encoded = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);

        encoded.push(BASE64_TABLE[(first >> 2) as usize] as char);
        encoded.push(BASE64_TABLE[(((first & 0b0000_0011) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(
                BASE64_TABLE[(((second & 0b0000_1111) << 2) | (third >> 6)) as usize] as char,
            );
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(BASE64_TABLE[(third & 0b0011_1111) as usize] as char);
        } else {
            encoded.push('=');
        }
    }
    encoded
}

#[cfg(feature = "vm")]
fn decode_base64(content: &str) -> Result<Vec<u8>, String> {
    let bytes = content.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("content 不是合法 base64：长度必须是 4 的倍数".to_string());
    }

    let mut decoded = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunk_count = bytes.len() / 4;
    for (chunk_index, chunk) in bytes.chunks(4).enumerate() {
        let pad_count = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if pad_count > 2 {
            return Err("content 不是合法 base64：padding 过长".to_string());
        }
        if pad_count > 0 && chunk_index + 1 != chunk_count {
            return Err("content 不是合法 base64：padding 后存在数据".to_string());
        }

        let mut values = [0u8; 4];
        for (index, byte) in chunk.iter().enumerate() {
            values[index] = if *byte == b'=' {
                if index < 2 {
                    return Err("content 不是合法 base64：padding 位置无效".to_string());
                }
                0
            } else if pad_count > 0 && index >= 4 - pad_count {
                return Err("content 不是合法 base64：padding 后存在数据".to_string());
            } else {
                decode_base64_byte(*byte).ok_or_else(|| {
                    format!("content 不是合法 base64：包含非法字符 `{}`", *byte as char)
                })?
            };
        }

        decoded.push((values[0] << 2) | (values[1] >> 4));
        if pad_count < 2 {
            decoded.push((values[1] << 4) | (values[2] >> 2));
        }
        if pad_count == 0 {
            decoded.push((values[2] << 6) | values[3]);
        }
    }

    Ok(decoded)
}

#[cfg(feature = "vm")]
fn decode_base64_byte(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn format_sdk_error(error: SdkError) -> String {
    match error {
        SdkError::Sandbox {
            code,
            message,
            suggestion,
        } => match suggestion {
            Some(suggestion) => format!("[{}] {message}；建议：{suggestion}", code.as_str()),
            None => format!("[{}] {message}", code.as_str()),
        },
        SdkError::BackendUnavailable(message) => format!("后端不可用：{message}"),
        SdkError::Config(message) => format!("配置错误：{message}"),
        SdkError::Io(error) => format!("IO 错误：{error}"),
        error => format!("SDK 错误：{error}"),
    }
}

fn to_error(error: impl Into<String>) -> Json<ErrorResponse> {
    Json(ErrorResponse {
        error: error.into(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    info!("mimobox MCP stdio server 启动");
    MimoboxServer::new()
        .serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    info!("mimobox MCP stdio server 退出");

    Ok(())
}
