//! mimobox MCP Server.
//!
//! Exposes 11 tools over stdio:
//! - create_sandbox
//! - destroy_sandbox
//! - list_sandboxes
//! - execute_code
//! - execute_command
//! - read_file
//! - write_file
//! - list_dir
//! - snapshot
//! - fork
//! - http_request

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "vm")]
use base64::{Engine, engine::general_purpose::STANDARD};
use mimobox_sdk::{
    Config, DirEntry, ExecuteResult, FileType, IsolationLevel, MAX_MEMORY_LIMIT_MB, Sandbox,
    SdkError,
};
use rmcp::handler::server::wrapper::Json;
use rmcp::schemars::JsonSchema;
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::task::JoinError;
use tracing::error;

pub mod http;

/// MCP 文件读写单次最大 10MB，避免 base64 请求或响应耗尽内存。
#[cfg_attr(not(feature = "vm"), allow(dead_code))]
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;
/// MCP 目录列表最多返回 10,000 项，兼顾大型目录排查和响应体大小控制。
const MAX_LIST_DIR_ENTRIES: usize = 10_000;
/// MCP 命令 stdout/stderr 单流最大 4MB，与底层 OS 输出保护保持同量级。
const MAX_EXECUTE_OUTPUT: usize = 4 * 1024 * 1024;
/// 单个 MCP server 最多保留 64 个沙箱，防止客户端无限创建实例造成 DoS。
const MAX_SANDBOXES: usize = 64;
/// MCP sandbox 和命令执行最大超时 3600 秒（1 小时），防止客户端占用资源过久。
const MAX_SANDBOX_TIMEOUT_SECS: u64 = 3600;

#[derive(Clone)]
pub struct MimoboxServer {
    pub(crate) sandboxes: Arc<Mutex<HashMap<u64, ManagedSandbox>>>,
    pub(crate) ephemeral_count: Arc<AtomicUsize>,
    pub next_id: Arc<AtomicU64>,
    pub tool_router: ToolRouter<Self>,
}

struct ManagedSandbox {
    sandbox: Sandbox,
    created_at_ms: u64,
    created_at_instant: Instant,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateSandboxRequest {
    /// Optional isolation level: auto, os, wasm, microvm.
    isolation_level: Option<String>,
    /// Default execution timeout in milliseconds for commands run in this sandbox.
    timeout_ms: Option<u64>,
    /// Sandbox memory limit in MiB.
    memory_limit_mb: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CreateSandboxResponse {
    sandbox_id: u64,
    requested_isolation_level: String,
    actual_isolation_level: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteCodeRequest {
    /// If not provided, a temporary sandbox is created and destroyed after execution.
    sandbox_id: Option<u64>,
    /// Code snippet to execute.
    code: String,
    /// Optional language: python, javascript, node, bash, sh.
    language: Option<String>,
    /// Execution timeout in milliseconds. Only applies when sandbox_id is not provided (temporary sandbox). For existing sandboxes, use the sandbox's own timeout.
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteCommandRequest {
    /// If not provided, a temporary sandbox is created and destroyed after execution.
    sandbox_id: Option<u64>,
    /// Shell command to execute.
    command: String,
    /// Execution timeout in milliseconds. Only applies to temporary sandboxes.
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DestroySandboxRequest {
    /// ID of the sandbox to destroy.
    sandbox_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListSandboxesRequest {}

#[derive(Debug, Deserialize, JsonSchema)]
#[cfg_attr(not(feature = "vm"), allow(dead_code))]
pub struct ReadFileRequest {
    /// Target sandbox ID.
    sandbox_id: u64,
    /// File path inside the sandbox.
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[cfg_attr(not(feature = "vm"), allow(dead_code))]
pub struct WriteFileRequest {
    /// Target sandbox ID.
    sandbox_id: u64,
    /// File path inside the sandbox.
    path: String,
    /// Base64-encoded file content.
    content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[cfg_attr(not(feature = "vm"), allow(dead_code))]
pub struct SnapshotRequest {
    /// Target sandbox ID.
    sandbox_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[cfg_attr(not(feature = "vm"), allow(dead_code))]
pub struct ForkRequest {
    /// ID of the sandbox to fork.
    sandbox_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[cfg_attr(not(feature = "vm"), allow(dead_code))]
pub struct McpHttpRequest {
    /// Target sandbox ID.
    sandbox_id: u64,
    /// Request URL (HTTPS only).
    url: String,
    /// HTTP method: GET or POST.
    method: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListDirRequest {
    /// Target sandbox ID.
    sandbox_id: u64,
    /// Directory path inside the sandbox.
    path: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ExecuteResponse {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed_ms: u128,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DestroySandboxResponse {
    sandbox_id: u64,
    destroyed: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListSandboxesResponse {
    sandboxes: Vec<SandboxSummary>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SandboxSummary {
    sandbox_id: u64,
    isolation_level: Option<String>,
    created_at: u64,
    uptime_ms: u128,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReadFileResponse {
    sandbox_id: u64,
    path: String,
    content: String,
    size_bytes: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct WriteFileResponse {
    sandbox_id: u64,
    path: String,
    size_bytes: usize,
    written: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SnapshotResponse {
    sandbox_id: u64,
    size_bytes: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ForkResponse {
    original_sandbox_id: u64,
    new_sandbox_id: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct McpHttpResponse {
    sandbox_id: u64,
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListDirEntry {
    name: String,
    file_type: String,
    size: u64,
    is_symlink: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListDirResponse {
    sandbox_id: u64,
    path: String,
    entries: Vec<ListDirEntry>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ErrorResponse {
    error: String,
}

impl MimoboxServer {
    pub fn new() -> Self {
        Self {
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            ephemeral_count: Arc::new(AtomicUsize::new(0)),
            next_id: Arc::new(AtomicU64::new(1)),
            tool_router: Self::tool_router(),
        }
    }

    /// Clean up all active sandbox instances. Called on SIGTERM/SIGINT.
    pub async fn cleanup_all(&self) {
        let mut sandboxes = self.sandboxes.lock().await;
        let count = sandboxes.len();
        let drained = sandboxes.drain().collect::<Vec<_>>();
        drop(sandboxes);

        for (id, managed) in drained {
            tracing::debug!(sandbox_id = id, "Signal cleanup: destroying sandbox");
            match tokio::task::spawn_blocking(move || {
                use std::panic::{AssertUnwindSafe, catch_unwind};

                // Keep cleanup best-effort: a destroy panic for one sandbox must not abort
                // cleanup of the remaining drained sandboxes.
                match catch_unwind(AssertUnwindSafe(|| managed.sandbox.destroy())) {
                    Ok(result) => result,
                    Err(_) => {
                        tracing::error!(
                            sandbox_id = id,
                            "Sandbox destroy panicked during signal cleanup"
                        );
                        Err(SdkError::Config("destroy operation panicked".to_string()))
                    }
                }
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    tracing::warn!(
                        sandbox_id = id,
                        error = %format_sdk_error(err),
                        "Failed to destroy sandbox during signal cleanup"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        sandbox_id = id,
                        error = %format_join_error(err),
                        "Sandbox cleanup task failed during signal cleanup"
                    );
                }
            }
        }
        tracing::info!(count, "Signal cleanup complete");
    }

    async fn with_managed_sandbox<T, F>(&self, sandbox_id: u64, operation: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce(&mut Sandbox) -> Result<T, SdkError> + Send + 'static,
    {
        let mut sandboxes = self.sandboxes.lock().await;
        let mut managed = sandboxes
            .remove(&sandbox_id)
            .ok_or_else(|| sandbox_not_found(sandbox_id))?;
        drop(sandboxes);

        let (managed, result) = tokio::task::spawn_blocking(move || {
            use std::panic::{AssertUnwindSafe, catch_unwind};

            // Recover the managed sandbox even if the operation panics after removal
            // from the map; otherwise the active sandbox entry would be lost.
            let result = catch_unwind(AssertUnwindSafe(|| operation(&mut managed.sandbox)));
            let result = match result {
                Ok(result) => result,
                Err(_) => {
                    tracing::error!(
                        sandbox_id,
                        "Sandbox operation panicked, sandbox recovered to prevent resource leak"
                    );
                    Err(SdkError::Config("operation panicked".to_string()))
                }
            };

            (managed, result)
        })
        .await
        .map_err(format_join_error)?;

        let mut sandboxes = self.sandboxes.lock().await;
        sandboxes.insert(sandbox_id, managed);

        result.map_err(format_sdk_error)
    }
}

impl Default for MimoboxServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl MimoboxServer {
    #[tool(
        description = "Create a reusable sandbox instance. Supports isolation levels: auto (default, routes to best backend), os (OS-level sandbox), wasm (WebAssembly sandbox), microvm (KVM-based microVM, Linux only). Optional timeout_ms and memory_limit_mb."
    )]
    async fn create_sandbox(
        &self,
        Parameters(request): Parameters<CreateSandboxRequest>,
    ) -> Result<Json<CreateSandboxResponse>, Json<ErrorResponse>> {
        let isolation =
            parse_isolation_level(request.isolation_level.as_deref()).map_err(to_error)?;
        let timeout_ms = request.timeout_ms;
        let memory_limit_mb = request.memory_limit_mb;
        let sandbox = tokio::task::spawn_blocking(move || {
            create_sandbox_with_options(isolation, timeout_ms, memory_limit_mb)
        })
        .await
        .map_err(|error| to_error(format_join_error(error)))?
        .map_err(|error| to_error(format_sdk_error(error)))?;

        let mut sandboxes = self.sandboxes.lock().await;
        if sandboxes.len() >= MAX_SANDBOXES {
            drop(sandboxes);
            match tokio::task::spawn_blocking(move || sandbox.destroy()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    tracing::warn!(
                        error = %format_sdk_error(err),
                        "Failed to destroy created sandbox on quota exceeded"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        error = %format_join_error(err),
                        "Created sandbox cleanup task failed on quota exceeded"
                    );
                }
            }
            return Err(to_error(sandbox_quota_exceeded()));
        }

        let sandbox_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let actual_isolation_level = sandbox
            .active_isolation()
            .map(format_isolation_level)
            .map(str::to_string);
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
            requested_isolation_level: format_isolation_level(isolation).to_string(),
            actual_isolation_level,
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

        match tokio::task::spawn_blocking(move || {
            use std::panic::{AssertUnwindSafe, catch_unwind};

            // The sandbox is already removed from the active map; catch unwind so
            // destroy panics are logged through the normal error path.
            match catch_unwind(AssertUnwindSafe(|| managed.sandbox.destroy())) {
                Ok(result) => result,
                Err(_) => {
                    error!(
                        sandbox_id = request.sandbox_id,
                        "Sandbox destroy panicked, instance removed from active list"
                    );
                    Err(SdkError::Config("destroy operation panicked".to_string()))
                }
            }
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                error!(
                    sandbox_id = request.sandbox_id,
                    error = %format_sdk_error(err),
                    "Sandbox destroy failed, instance removed from active list"
                );
            }
            Err(err) => {
                error!(
                    sandbox_id = request.sandbox_id,
                    error = %format_join_error(err),
                    "Sandbox destroy task failed, instance removed from active list"
                );
            }
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

    #[tool(
        description = "Execute a code snippet in a sandbox. Supports languages: python, javascript, node, bash, sh. If sandbox_id is provided, runs in an existing sandbox; otherwise creates a temporary sandbox for this execution."
    )]
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

    #[tool(
        description = "Read a file from a sandbox and return its content as base64. Requires microVM isolation level. The path must be absolute."
    )]
    async fn read_file(
        &self,
        Parameters(request): Parameters<ReadFileRequest>,
    ) -> Result<Json<ReadFileResponse>, Json<ErrorResponse>> {
        #[cfg(feature = "vm")]
        {
            let path = request.path;
            let content = self
                .with_managed_sandbox(request.sandbox_id, {
                    let path = path.clone();
                    move |sandbox| sandbox.read_file(&path)
                })
                .await
                .map_err(to_error)?;
            if content.len() > MAX_FILE_SIZE {
                return Err(to_error(format!(
                    "文件过大：{} 字节，超过 {} 字节限制。提示：请读取较小的文件",
                    content.len(),
                    MAX_FILE_SIZE
                )));
            }
            let size_bytes = content.len();

            Ok(Json(ReadFileResponse {
                sandbox_id: request.sandbox_id,
                path,
                content: STANDARD.encode(&content),
                size_bytes,
            }))
        }

        #[cfg(not(feature = "vm"))]
        {
            let _ = request;
            Err(to_error(vm_feature_required("read_file")))
        }
    }

    #[tool(
        description = "Write base64-encoded content to a file in a sandbox. Requires microVM isolation level. The path must be absolute."
    )]
    async fn write_file(
        &self,
        Parameters(request): Parameters<WriteFileRequest>,
    ) -> Result<Json<WriteFileResponse>, Json<ErrorResponse>> {
        #[cfg(feature = "vm")]
        {
            let data = STANDARD
                .decode(&request.content)
                .map_err(|err| to_error(format!("内容不是有效的 base64 编码：{err}。提示：请确保内容为标准 base64 编码字符串")))?;
            if data.len() > MAX_FILE_SIZE {
                return Err(to_error(format!(
                    "内容过大：{} 字节，超过 {} 字节限制。提示：请写入较小的内容或拆分为多次写入",
                    data.len(),
                    MAX_FILE_SIZE
                )));
            }
            let size_bytes = data.len();
            let path = request.path;
            self.with_managed_sandbox(request.sandbox_id, {
                let path = path.clone();
                move |sandbox| sandbox.write_file(&path, &data)
            })
            .await
            .map_err(to_error)?;

            Ok(Json(WriteFileResponse {
                sandbox_id: request.sandbox_id,
                path,
                size_bytes,
                written: true,
            }))
        }

        #[cfg(not(feature = "vm"))]
        {
            let _ = request;
            Err(to_error(vm_feature_required("write_file")))
        }
    }

    #[tool(
        description = "Create a memory snapshot of a microVM-backed sandbox. The snapshot can later be restored or used to fork new sandbox instances."
    )]
    async fn snapshot(
        &self,
        Parameters(request): Parameters<SnapshotRequest>,
    ) -> Result<Json<SnapshotResponse>, Json<ErrorResponse>> {
        #[cfg(feature = "vm")]
        {
            let snapshot = self
                .with_managed_sandbox(request.sandbox_id, |sandbox| sandbox.snapshot())
                .await
                .map_err(to_error)?;

            Ok(Json(SnapshotResponse {
                sandbox_id: request.sandbox_id,
                size_bytes: snapshot.size(),
            }))
        }

        #[cfg(not(feature = "vm"))]
        {
            let _ = request;
            Err(to_error(vm_feature_required("snapshot")))
        }
    }

    #[tool(
        description = "Fork a microVM-backed sandbox, creating an independent copy with CoW memory"
    )]
    async fn fork(
        &self,
        Parameters(request): Parameters<ForkRequest>,
    ) -> Result<Json<ForkResponse>, Json<ErrorResponse>> {
        #[cfg(feature = "vm")]
        {
            let mut sandboxes = self.sandboxes.lock().await;
            let mut managed = sandboxes
                .remove(&request.sandbox_id)
                .ok_or_else(|| to_error(sandbox_not_found(request.sandbox_id)))?;
            drop(sandboxes);

            let (managed, fork_result) = tokio::task::spawn_blocking(move || {
                use std::panic::{AssertUnwindSafe, catch_unwind};

                // Recover the managed sandbox even if fork panics after removal
                // from the map; otherwise the original sandbox would be lost.
                let fork_result = catch_unwind(AssertUnwindSafe(|| managed.sandbox.fork()));
                let fork_result = match fork_result {
                    Ok(result) => result,
                    Err(_) => {
                        tracing::error!(
                            sandbox_id = request.sandbox_id,
                            "Sandbox fork panicked, sandbox recovered to prevent resource leak"
                        );
                        Err(SdkError::Config("fork operation panicked".to_string()))
                    }
                };

                (managed, fork_result)
            })
            .await
            .map_err(|error| to_error(format_join_error(error)))?;

            let forked = match fork_result {
                Ok(forked) => forked,
                Err(error) => {
                    let mut sandboxes = self.sandboxes.lock().await;
                    sandboxes.insert(request.sandbox_id, managed);
                    return Err(to_error(format_sdk_error(error)));
                }
            };

            let mut sandboxes = self.sandboxes.lock().await;
            sandboxes.insert(request.sandbox_id, managed);
            if sandboxes.len() >= MAX_SANDBOXES {
                drop(sandboxes);
                match tokio::task::spawn_blocking(move || forked.destroy()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        tracing::warn!(
                            error = %format_sdk_error(err),
                            "Failed to destroy forked sandbox on quota exceeded"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %format_join_error(err),
                            "Forked sandbox cleanup task failed on quota exceeded"
                        );
                    }
                }
                return Err(to_error(sandbox_quota_exceeded()));
            }

            let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);
            sandboxes.insert(
                new_id,
                ManagedSandbox {
                    sandbox: forked,
                    created_at_ms: unix_timestamp_ms(),
                    created_at_instant: Instant::now(),
                },
            );

            Ok(Json(ForkResponse {
                original_sandbox_id: request.sandbox_id,
                new_sandbox_id: new_id,
            }))
        }

        #[cfg(not(feature = "vm"))]
        {
            let _ = request;
            Err(to_error(vm_feature_required("fork")))
        }
    }

    #[tool(
        description = "Send an HTTP GET or POST request through the sandbox proxy. Requires microVM isolation level with domain whitelist configured. Only HTTPS targets on whitelisted domains are allowed."
    )]
    async fn http_request(
        &self,
        Parameters(request): Parameters<McpHttpRequest>,
    ) -> Result<Json<McpHttpResponse>, Json<ErrorResponse>> {
        #[cfg(feature = "vm")]
        {
            let method = request.method.to_ascii_uppercase();
            if !matches!(method.as_str(), "GET" | "POST") {
                return Err(to_error("HTTP 方法仅支持 GET 和 POST。提示：请使用 GET 或 POST".to_string()));
            }

            let url = request.url;
            let response = self
                .with_managed_sandbox(request.sandbox_id, move |sandbox| {
                    sandbox.http_request(&method, &url, HashMap::new(), None)
                })
                .await
                .map_err(to_error)?;

            Ok(Json(McpHttpResponse {
                sandbox_id: request.sandbox_id,
                status: response.status,
                headers: response.headers,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            }))
        }

        #[cfg(not(feature = "vm"))]
        {
            let _ = request;
            Err(to_error(vm_feature_required("http_request")))
        }
    }

    #[tool(
        description = "List directory entries in a sandbox. Returns file name, type (file/dir/symlink), size, and symlink flag for each entry. Requires microVM isolation level."
    )]
    async fn list_dir(
        &self,
        Parameters(request): Parameters<ListDirRequest>,
    ) -> Result<Json<ListDirResponse>, Json<ErrorResponse>> {
        let path = request.path;
        let sdk_entries = self
            .with_managed_sandbox(request.sandbox_id, {
                let path = path.clone();
                move |sandbox| sandbox.list_dir(&path)
            })
            .await;

        let entries = match sdk_entries {
            Ok(mut entries) => {
                truncate_list_dir_entries(&mut entries);
                entries.into_iter().map(format_list_dir_entry).collect()
            }
            Err(error) if should_fallback_list_dir(&error) => {
                let command = build_list_dir_fallback_command(&path);
                let result = self
                    .with_managed_sandbox(request.sandbox_id, move |sandbox| {
                        sandbox.execute(&command)
                    })
                    .await
                    .map_err(to_error)?;
                if result.exit_code != Some(0) {
                    return Err(to_error(format!(
                        "list_dir 执行失败，路径 {path}: {}。提示：请确认路径存在且为目录",
                        String::from_utf8_lossy(&result.stderr)
                    )));
                }

                let mut entries = format_list_dir_fallback_entries(&result.stdout);
                truncate_list_dir_entries(&mut entries);
                entries
            }
            Err(error) => return Err(to_error(error)),
        };

        Ok(Json(ListDirResponse {
            sandbox_id: request.sandbox_id,
            path,
            entries,
        }))
    }

    async fn execute_with_optional_sandbox(
        &self,
        sandbox_id: Option<u64>,
        command: &str,
        timeout_ms: Option<u64>,
    ) -> Result<ExecuteResult, String> {
        validate_timeout_ms(timeout_ms)?;

        if let Some(sandbox_id) = sandbox_id {
            let command = command.to_string();
            return self
                .with_managed_sandbox(sandbox_id, move |sandbox| sandbox.execute(&command))
                .await;
        }

        {
            let sandboxes = self.sandboxes.lock().await;
            let persistent = sandboxes.len();
            let ephemeral = self.ephemeral_count.load(Ordering::Relaxed);
            if persistent + ephemeral >= MAX_SANDBOXES {
                return Err(sandbox_quota_exceeded());
            }
            self.ephemeral_count.fetch_add(1, Ordering::Relaxed);
        }

        let command = command.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let mut sandbox = create_sandbox_with_options(IsolationLevel::Auto, timeout_ms, None)?;
            let result = sandbox.execute(&command);
            if let Err(err) = sandbox.destroy() {
                error!(error = %format_sdk_error(err), "Temporary sandbox destroy failed");
            }
            result
        })
        .await;

        self.ephemeral_count.fetch_sub(1, Ordering::Relaxed);

        result.map_err(format_join_error)?.map_err(format_sdk_error)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MimoboxServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "MimoBox MCP Server — Local Sandbox Runtime for AI Agents.\n\nProvides 11 tools for secure code execution and sandbox management:\n\nLIFECYCLE: create_sandbox (isolation: auto/os/wasm/microvm), destroy_sandbox, list_sandboxes\nEXECUTION: execute_code (python/node/bash/sh), execute_command (shell commands)\nFILES: read_file, write_file, list_dir (microVM only for read/write)\nADVANCED: snapshot, fork (microVM CoW memory cloning), http_request (HTTPS proxy with domain whitelist)\n\nTYPICAL WORKFLOW:\n1. create_sandbox -> get sandbox_id\n2. execute_code/execute_command with sandbox_id for persistent sessions\n3. Use snapshot+fork for fast parallel execution from pre-warmed state\n4. destroy_sandbox when done\n\nOr use execute_code/execute_command without sandbox_id for fire-and-forget ephemeral execution.",
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
    validate_create_sandbox_memory_limit(memory_limit_mb)?;
    validate_timeout_ms(timeout_ms).map_err(SdkError::Config)?;

    let mut builder = Config::builder().isolation(isolation);
    if let Some(timeout_ms) = timeout_ms {
        builder = builder.timeout(Duration::from_millis(timeout_ms));
    }
    if let Some(memory_limit_mb) = memory_limit_mb {
        builder = builder.memory_limit_mb(memory_limit_mb);
    }

    Sandbox::with_config(builder.build()?)
}

fn validate_create_sandbox_memory_limit(memory_limit_mb: Option<u64>) -> Result<(), SdkError> {
    if let Some(memory_limit_mb) = memory_limit_mb
        && memory_limit_mb > MAX_MEMORY_LIMIT_MB
    {
        return Err(SdkError::Config(format!(
            "create_sandbox memory_limit_mb={memory_limit_mb} 超过最大值 {MAX_MEMORY_LIMIT_MB} MB。提示：请设为合理值，推荐 256-512 MB"
        )));
    }

    Ok(())
}

fn validate_timeout_ms(timeout_ms: Option<u64>) -> Result<(), String> {
    if let Some(timeout_ms) = timeout_ms {
        let timeout_secs = timeout_ms / 1000;
        if timeout_secs > MAX_SANDBOX_TIMEOUT_SECS {
            return Err(format!(
                "timeout_ms={timeout_ms} 超过最大值 {} 毫秒（{MAX_SANDBOX_TIMEOUT_SECS} 秒）。提示：请减小超时时间，推荐 30000 毫秒（30 秒）",
                MAX_SANDBOX_TIMEOUT_SECS * 1000
            ));
        }
    }

    Ok(())
}

fn parse_isolation_level(value: Option<&str>) -> Result<IsolationLevel, String> {
    match value.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "auto" => Ok(IsolationLevel::Auto),
        "os" => Ok(IsolationLevel::Os),
        "wasm" => Ok(IsolationLevel::Wasm),
        "microvm" | "micro_vm" | "micro-vm" | "vm" => Ok(IsolationLevel::MicroVm),
        other => Err(format!(
            "不支持的隔离级别 '{other}'。提示：可选值为 auto、os、wasm、microvm；推荐使用 auto 自动选择最优后端"
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
    format!("sandbox {sandbox_id} 不存在。提示：使用 list_sandboxes 查看活跃的 sandbox 列表")
}

fn sandbox_quota_exceeded() -> String {
    format!(
        "sandbox 配额已满：最多允许 {} 个实例。提示：先使用 destroy_sandbox 释放不需要的实例",
        MAX_SANDBOXES
    )
}

#[cfg(not(feature = "vm"))]
fn vm_feature_required(operation: &str) -> String {
    format!(
        "{operation} 需要 microVM 后端。提示：启用 vm feature 并使用 microvm 隔离级别，或改用 auto 自动选择最优后端"
    )
}

fn build_code_command(language: Option<&str>, code: &str) -> Result<String, String> {
    let escaped_code = shell_single_quote(code);
    match language.unwrap_or("bash").to_ascii_lowercase().as_str() {
        "python" | "python3" | "py" => Ok(format!("python3 -c {escaped_code}")),
        "javascript" | "js" | "node" | "nodejs" => Ok(format!("node -e {escaped_code}")),
        "bash" => Ok(format!("bash -c {escaped_code}")),
        "sh" | "shell" => Ok(format!("sh -c {escaped_code}")),
        other => Err(format!(
            "不支持的语言 '{other}'。提示：可选值为 python、node、bash、sh"
        )),
    }
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn format_execute_result(result: ExecuteResult) -> ExecuteResponse {
    ExecuteResponse {
        stdout: format_execute_output(&result.stdout),
        stderr: format_execute_output(&result.stderr),
        exit_code: result.exit_code,
        timed_out: result.timed_out,
        elapsed_ms: result.elapsed.as_millis(),
    }
}

fn format_execute_output(output: &[u8]) -> String {
    if output.len() <= MAX_EXECUTE_OUTPUT {
        return String::from_utf8_lossy(output).into_owned();
    }

    let marker = format!("... [truncated, {} bytes total]", output.len());
    let keep_len = MAX_EXECUTE_OUTPUT.saturating_sub(marker.len());
    let mut truncated = Vec::with_capacity(keep_len + marker.len());
    truncated.extend_from_slice(&output[..keep_len]);
    truncated.extend_from_slice(marker.as_bytes());
    String::from_utf8_lossy(&truncated).into_owned()
}

fn format_list_dir_entry(entry: DirEntry) -> ListDirEntry {
    ListDirEntry {
        name: entry.name,
        file_type: match entry.file_type {
            FileType::File => "file".to_string(),
            FileType::Dir => "dir".to_string(),
            FileType::Symlink => "symlink".to_string(),
            _ => "other".to_string(),
        },
        size: entry.size,
        is_symlink: entry.is_symlink,
    }
}

fn truncate_list_dir_entries<T>(entries: &mut Vec<T>) {
    if entries.len() > MAX_LIST_DIR_ENTRIES {
        tracing::warn!(
            count = entries.len(),
            limit = MAX_LIST_DIR_ENTRIES,
            "list_dir result truncated"
        );
        entries.truncate(MAX_LIST_DIR_ENTRIES);
    }
}

fn should_fallback_list_dir(error: &str) -> bool {
    error.contains("[unsupported_platform]") && error.contains("does not support list_dir")
}

fn build_list_dir_fallback_command(path: &str) -> String {
    format!(
        "sh -c 'dir=$1; if [ ! -d \"$dir\" ]; then echo \"not found: $dir\" >&2; exit 66; fi; cd \"$dir\" || exit 66; ls -1A' sh {}",
        shell_single_quote(path)
    )
}

// 已知限制：文件名包含换行符时，`.lines()` 分割可能导致解析不准确。
// 这是可接受的限制，因为该命令在沙箱内部执行，文件名由沙箱用户控制，
// 且包含换行符的文件名属于边缘情况。
fn format_list_dir_fallback_entries(stdout: &[u8]) -> Vec<ListDirEntry> {
    String::from_utf8_lossy(stdout)
        .lines()
        .take(MAX_LIST_DIR_ENTRIES + 1)
        .map(|name| ListDirEntry {
            name: name.to_string(),
            // OS fallback 只能在沙箱内安全读取名称，避免额外 stat 泄露宿主路径语义。
            file_type: "other".to_string(),
            size: 0,
            is_symlink: false,
        })
        .collect()
}

/// 脱敏错误消息中的宿主路径信息。
///
/// 将常见宿主路径前缀替换为占位符，防止通过 MCP 错误响应泄露
/// 宿主文件系统布局（如 /Users/alice/...、/home/...、rootfs 路径等）。
fn sanitize_error_message(message: &str) -> String {
    let mut result = message.to_string();
    // 替换绝对路径模式：/Users/<name>/..., /home/<name>/..., /tmp/mimobox-..., /var/folders/...
    // 使用简单的前缀匹配和路径段识别
    let path_prefixes = [
        "/Users/",
        "/home/",
        "/var/folders/",
        "/tmp/",
        "/private/tmp/",
        "/private/var/",
    ];
    for prefix in path_prefixes {
        redact_path_prefix(&mut result, prefix, &format!("{prefix}<redacted>"));
    }
    // 脱敏 rootfs 相关路径
    redact_path_prefix(&mut result, "/rootfs", "/rootfs<redacted>");
    // 脱敏 .snap 文件路径（可能包含宿主路径前缀）
    result
}

fn redact_path_prefix(result: &mut String, prefix: &str, replacement: &str) {
    let mut search_start = 0;
    while search_start < result.len() {
        let Some(relative_pos) = result[search_start..].find(prefix) else {
            break;
        };
        let pos = search_start + relative_pos;
        // 找到路径结束位置（空格、换行、右括号或字符串末尾）。
        let end = result[pos..]
            .find([' ', '\n', ')'])
            .map(|index| pos + index)
            .unwrap_or(result.len());
        result.replace_range(pos..end, replacement);
        search_start = pos + replacement.len();
    }
}

fn format_sdk_error(error: SdkError) -> String {
    let message = match error {
        SdkError::Sandbox {
            code,
            message,
            suggestion,
        } => match suggestion {
            Some(suggestion) => format!("[{}] {message}; suggestion: {suggestion}", code.as_str()),
            None => format!("[{}] {message}", code.as_str()),
        },
        SdkError::BackendUnavailable(message) => format!("backend unavailable: {message}"),
        SdkError::Config(message) => format!("config error: {message}"),
        SdkError::Io(error) => format!("I/O error: {error}"),
        error => format!("SDK error: {error}"),
    };

    sanitize_error_message(&message)
}

fn format_join_error(error: JoinError) -> String {
    sanitize_error_message(&format!("blocking task failed: {error}"))
}

fn to_error(error: impl Into<String>) -> Json<ErrorResponse> {
    Json(ErrorResponse {
        error: sanitize_error_message(&error.into()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mimobox_sdk::ErrorCode;
    use std::time::Duration;

    // ── parse_isolation_level ──────────────────────────────────────────

    #[test]
    fn test_parse_isolation_none_defaults_to_auto() {
        let result = parse_isolation_level(None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), IsolationLevel::Auto);
    }

    #[test]
    fn test_parse_isolation_explicit_values() {
        assert_eq!(
            parse_isolation_level(Some("os")).unwrap(),
            IsolationLevel::Os
        );
        assert_eq!(
            parse_isolation_level(Some("wasm")).unwrap(),
            IsolationLevel::Wasm
        );
        assert_eq!(
            parse_isolation_level(Some("microvm")).unwrap(),
            IsolationLevel::MicroVm
        );
    }

    #[test]
    fn test_parse_isolation_aliases() {
        let aliases = ["micro_vm", "micro-vm", "vm"];
        for alias in aliases {
            assert_eq!(
                parse_isolation_level(Some(alias)).unwrap(),
                IsolationLevel::MicroVm,
                "alias '{alias}' should resolve to MicroVm"
            );
        }
    }

    #[test]
    fn test_parse_isolation_case_insensitive() {
        assert_eq!(
            parse_isolation_level(Some("AUTO")).unwrap(),
            IsolationLevel::Auto
        );
        assert_eq!(
            parse_isolation_level(Some("Os")).unwrap(),
            IsolationLevel::Os
        );
        assert_eq!(
            parse_isolation_level(Some("WASM")).unwrap(),
            IsolationLevel::Wasm
        );
        assert_eq!(
            parse_isolation_level(Some("MICROVM")).unwrap(),
            IsolationLevel::MicroVm
        );
    }

    #[test]
    fn test_parse_isolation_invalid_values() {
        let invalid = ["invalid", "docker", ""];
        for val in invalid {
            assert!(
                parse_isolation_level(Some(val)).is_err(),
                "'{val}' should be invalid"
            );
        }
    }

    #[test]
    fn test_create_sandbox_rejects_memory_limit_above_global_max() {
        let result =
            create_sandbox_with_options(IsolationLevel::Auto, None, Some(MAX_MEMORY_LIMIT_MB + 1));

        assert!(
            matches!(result, Err(SdkError::Config(message)) if message.contains("create_sandbox memory_limit_mb"))
        );
    }

    #[test]
    fn test_create_sandbox_rejects_timeout_above_max() {
        let excessive_timeout_ms = (MAX_SANDBOX_TIMEOUT_SECS + 1) * 1000;
        let result =
            create_sandbox_with_options(IsolationLevel::Auto, Some(excessive_timeout_ms), None);

        assert!(matches!(result, Err(SdkError::Config(message)) if message.contains("timeout_ms")));
    }

    #[test]
    fn test_create_sandbox_accepts_timeout_at_max() {
        let max_timeout_ms = MAX_SANDBOX_TIMEOUT_SECS * 1000;
        let result = create_sandbox_with_options(IsolationLevel::Auto, Some(max_timeout_ms), None);

        // 可能因后端不可用失败，但不应因 timeout 校验失败
        if let Err(SdkError::Config(message)) = &result {
            assert!(
                !message.contains("timeout_ms"),
                "timeout exactly at max should pass validation: {message}"
            );
        }
    }

    #[test]
    fn test_validate_timeout_ms_accepts_none() {
        assert!(validate_timeout_ms(None).is_ok());
    }

    #[test]
    fn test_validate_timeout_ms_accepts_below_max() {
        assert!(validate_timeout_ms(Some(30_000)).is_ok());
    }

    #[test]
    fn test_validate_timeout_ms_rejects_above_max() {
        let excessive = (MAX_SANDBOX_TIMEOUT_SECS + 1) * 1000;
        let result = validate_timeout_ms(Some(excessive));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timeout_ms"));
    }

    #[test]
    fn test_parse_isolation_none_same_as_auto_string() {
        let from_none = parse_isolation_level(None).unwrap();
        let from_auto = parse_isolation_level(Some("auto")).unwrap();
        assert_eq!(from_none, from_auto);
    }

    // ── build_code_command ─────────────────────────────────────────────

    #[test]
    fn test_build_code_command_python_aliases() {
        for lang in ["python", "python3", "py"] {
            let cmd = build_code_command(Some(lang), "print(1)").unwrap();
            assert!(
                cmd.starts_with("python3 -c "),
                "language='{lang}' should generate python3 command, got: {cmd}"
            );
        }
    }

    #[test]
    fn test_build_code_command_node_aliases() {
        for lang in ["node", "javascript", "js", "nodejs"] {
            let cmd = build_code_command(Some(lang), "console.log(1)").unwrap();
            assert!(
                cmd.starts_with("node -e "),
                "language='{lang}' should generate node command, got: {cmd}"
            );
        }
    }

    #[test]
    fn test_build_code_command_bash_default() {
        let cmd = build_code_command(None, "hello").unwrap();
        assert_eq!(cmd, "bash -c 'hello'");
    }

    #[test]
    fn test_build_code_command_sh_and_shell() {
        let cmd_sh = build_code_command(Some("sh"), "echo hi").unwrap();
        assert!(cmd_sh.starts_with("sh -c "));

        let cmd_shell = build_code_command(Some("shell"), "echo hi").unwrap();
        assert!(cmd_shell.starts_with("sh -c "));
    }

    #[test]
    fn test_build_code_command_unsupported_language() {
        let result = build_code_command(Some("ruby"), "puts 1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ruby"));
    }

    // ── shell_single_quote ─────────────────────────────────────────────

    #[test]
    fn test_shell_single_quote_simple() {
        assert_eq!(shell_single_quote("hello"), "'hello'");
    }

    #[test]
    fn test_shell_single_quote_empty() {
        assert_eq!(shell_single_quote(""), "''");
    }

    #[test]
    fn test_shell_single_quote_with_single_quote() {
        // "it's" -> 'it'\''s'
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_single_quote_special_chars() {
        // Ensure double quotes and $ are preserved inside quotes
        let input = r#"hello "world" $var"#;
        let quoted = shell_single_quote(input);
        assert!(quoted.starts_with('\''));
        assert!(quoted.ends_with('\''));
        assert!(quoted.contains(r#"hello "world" $var"#));
    }

    // ── format_sdk_error ───────────────────────────────────────────────

    #[test]
    fn test_format_sdk_error_sandbox_with_suggestion() {
        let err = SdkError::sandbox(
            ErrorCode::CommandTimeout,
            "timed out",
            Some("increase timeout".to_string()),
        );
        let formatted = format_sdk_error(err);
        assert!(
            formatted.contains("[command_timeout]"),
            "should contain error code"
        );
        assert!(formatted.contains("timed out"), "should contain message");
        assert!(
            formatted.contains("suggestion: increase timeout"),
            "should contain suggestion"
        );
    }

    #[test]
    fn test_format_sdk_error_sandbox_without_suggestion() {
        let err = SdkError::sandbox(ErrorCode::FileNotFound, "file not found", None);
        let formatted = format_sdk_error(err);
        assert!(formatted.contains("[file_not_found]"));
        assert!(formatted.contains("file not found"));
        assert!(
            !formatted.contains("suggestion:"),
            "No suggestion should be output when absent"
        );
    }

    #[test]
    fn test_format_sdk_error_backend_unavailable() {
        let err = SdkError::BackendUnavailable("microvm");
        let formatted = format_sdk_error(err);
        assert!(formatted.contains("backend unavailable"));
        assert!(formatted.contains("microvm"));
    }

    #[test]
    fn test_format_sdk_error_config() {
        let err = SdkError::Config("invalid config".to_string());
        let formatted = format_sdk_error(err);
        assert!(formatted.contains("config error"));
        assert!(formatted.contains("invalid config"));
    }

    #[test]
    fn test_format_sdk_error_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = SdkError::Io(io_err);
        let formatted = format_sdk_error(err);
        assert!(formatted.contains("I/O error"));
        assert!(formatted.contains("file not found"));
    }

    #[test]
    fn test_format_sdk_error_sanitizes_host_paths() {
        let err =
            SdkError::Config("failed to open /Users/alice/dev/mimobox/rootfs/init".to_string());
        let formatted = format_sdk_error(err);

        assert!(
            !formatted.contains("/Users/alice/dev/mimobox"),
            "formatted SDK errors must not expose host paths"
        );
        assert!(formatted.contains("/Users/<redacted>"));
    }

    // ── format_isolation_level ─────────────────────────────────────────

    #[test]
    fn test_format_isolation_level_roundtrip() {
        assert_eq!(format_isolation_level(IsolationLevel::Auto), "auto");
        assert_eq!(format_isolation_level(IsolationLevel::Os), "os");
        assert_eq!(format_isolation_level(IsolationLevel::Wasm), "wasm");
        assert_eq!(format_isolation_level(IsolationLevel::MicroVm), "microvm");
    }

    // ── format_execute_result ──────────────────────────────────────────

    #[test]
    fn test_format_execute_result_fields() {
        let result = ExecuteResult::new(
            b"out".to_vec(),
            b"err".to_vec(),
            Some(0),
            false,
            Duration::from_millis(42),
        );
        let resp = format_execute_result(result);
        assert_eq!(resp.stdout, "out");
        assert_eq!(resp.stderr, "err");
        assert_eq!(resp.exit_code, Some(0));
        assert!(!resp.timed_out);
        assert_eq!(resp.elapsed_ms, 42);
    }

    #[test]
    fn test_format_execute_result_non_utf8() {
        let result = ExecuteResult::new(
            vec![0xff, 0xfe],
            vec![],
            None,
            true,
            Duration::from_millis(100),
        );
        let resp = format_execute_result(result);
        // String::from_utf8_lossy replaces invalid UTF-8 with replacement character
        assert!(!resp.stdout.is_empty());
        assert!(resp.stderr.is_empty());
        assert_eq!(resp.exit_code, None);
        assert!(resp.timed_out);
        assert_eq!(resp.elapsed_ms, 100);
    }

    #[test]
    fn test_format_execute_result_truncates_large_output() {
        let stdout_len = MAX_EXECUTE_OUTPUT + 1;
        let stderr_len = MAX_EXECUTE_OUTPUT + 2;
        let result = ExecuteResult::new(
            vec![b'a'; stdout_len],
            vec![b'b'; stderr_len],
            Some(0),
            false,
            Duration::from_millis(1),
        );

        let resp = format_execute_result(result);

        assert_eq!(resp.stdout.len(), MAX_EXECUTE_OUTPUT);
        assert_eq!(resp.stderr.len(), MAX_EXECUTE_OUTPUT);
        assert!(
            resp.stdout
                .ends_with(&format!("... [truncated, {stdout_len} bytes total]"))
        );
        assert!(
            resp.stderr
                .ends_with(&format!("... [truncated, {stderr_len} bytes total]"))
        );
    }

    // ── sandbox_not_found ──────────────────────────────────────────────

    #[test]
    fn test_sandbox_not_found_contains_id() {
        let msg = sandbox_not_found(42);
        assert!(msg.contains("42"), "should contain sandbox_id");
        assert!(msg.contains("not found"), "should contain hint");
    }

    // ── unix_timestamp_ms ──────────────────────────────────────────────

    #[test]
    fn test_unix_timestamp_ms_reasonable() {
        let ts = unix_timestamp_ms();
        // 2023-01-01 00:00:00 UTC ≈ 1_672_531_200_000
        assert!(
            ts > 1_672_531_200_000,
            "Timestamp should be after 2023, got: {ts}"
        );
        // Should not exceed the future upper bound (2100 ≈ 4_102_444_800_000)
        assert!(ts < 4_102_444_800_000, "Timestamp should not exceed 2100");
    }

    #[test]
    fn test_unix_timestamp_ms_monotonic() {
        let t1 = unix_timestamp_ms();
        let t2 = unix_timestamp_ms();
        assert!(
            t2 >= t1,
            "Consecutive calls should be monotonically non-decreasing"
        );
    }

    // ── to_error helper ────────────────────────────────────────────────

    #[test]
    fn test_to_error_contains_message() {
        let Json(err) = to_error("test error");
        assert_eq!(err.error, "test error");
    }

    // ── vm_feature_required (non-vm builds) ────────────────────────────

    #[cfg(not(feature = "vm"))]
    #[test]
    fn test_vm_feature_required_message() {
        let msg = vm_feature_required("snapshot");
        assert!(msg.contains("snapshot"), "should contain operation name");
        assert!(msg.contains("microVM") || msg.contains("vm feature"));
    }
}
