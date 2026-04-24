use std::{collections::HashMap, sync::Arc, time::Duration};

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
    sandboxes: Arc<Mutex<HashMap<u64, Sandbox>>>,
    next_id: Arc<Mutex<u64>>,
    tool_router: ToolRouter<Self>,
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

#[derive(Debug, Serialize, JsonSchema)]
struct ExecuteResponse {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed_ms: u128,
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
    #[tool(description = "创建一个可复用的 mimobox 沙箱实例")]
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
        sandboxes.insert(sandbox_id, sandbox);

        Ok(Json(CreateSandboxResponse {
            sandbox_id,
            isolation_level: format_isolation_level(isolation).to_string(),
        }))
    }

    #[tool(description = "在 mimobox 沙箱中执行指定语言的代码片段")]
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

    #[tool(description = "在 mimobox 沙箱中执行 shell 命令")]
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

    async fn execute_with_optional_sandbox(
        &self,
        sandbox_id: Option<u64>,
        command: &str,
        timeout_ms: Option<u64>,
    ) -> Result<ExecuteResult, String> {
        if let Some(sandbox_id) = sandbox_id {
            let mut sandboxes = self.sandboxes.lock().await;
            let sandbox = sandboxes
                .get_mut(&sandbox_id)
                .ok_or_else(|| format!("未找到 sandbox_id={sandbox_id} 的沙箱实例"))?;
            return sandbox.execute(command).map_err(format_sdk_error);
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
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("mimobox MCP Server：提供隔离沙箱创建与命令/代码执行工具")
    }
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
