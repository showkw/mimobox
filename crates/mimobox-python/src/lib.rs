//! mimobox Python SDK bindings.
//!
//! Exposes `mimobox-sdk` as a Python-callable module via PyO3.
//! Provides sandboxed code execution for AI agents with support for
//! OS-level, Wasm, and microVM isolation.

use mimobox_sdk::{
    Config, DirEntry, ErrorCode, ExecuteResult, FileStat, FileType, IsolationLevel,
    Sandbox as RustSandbox, SandboxSnapshot as RustSnapshot, SdkError, StreamEvent,
};
use pyo3::create_exception;
use pyo3::exceptions::{
    PyConnectionError, PyFileNotFoundError, PyNotImplementedError, PyPermissionError,
    PyRuntimeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyType};
use std::sync::mpsc;

fn extract_bytes_data(data: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    use pyo3::types::PyBytes;
    if data.is_instance_of::<PyBytes>() {
        Ok(data.downcast::<PyBytes>()?.as_bytes().to_vec())
    } else if let Ok(s) = data.extract::<String>() {
        Ok(s.into_bytes())
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "data must be str or bytes",
        ))
    }
}

mod tracing {
    macro_rules! tracing_warn {
        ($message:literal, code = ?$code:expr) => {
            eprintln!("{} code={:?}", $message, $code);
        };
    }

    pub(crate) use tracing_warn as warn;
}

create_exception!(mimobox, SandboxError, pyo3::exceptions::PyException);
create_exception!(mimobox, SandboxTimeoutError, SandboxError);
create_exception!(mimobox, SandboxProcessError, SandboxError);
create_exception!(mimobox, SandboxHttpError, SandboxError);
create_exception!(mimobox, SandboxLifecycleError, SandboxError);

/// Result of a sandbox command execution.
///
/// Wraps the Rust SDK `ExecuteResult` with UTF-8 lossy decoded strings
/// for Python compatibility. Binary output is converted using lossy UTF-8
/// decoding to avoid encoding errors.
///
/// # Attributes
///
/// * `stdout` - Standard output as a UTF-8 string (lossy decoded).
/// * `stderr` - Standard error as a UTF-8 string (lossy decoded).
/// * `exit_code` - Process exit code. `-1` when unavailable (e.g., timeout).
/// * `timed_out` - Whether the command exceeded its time limit.
#[pyclass(name = "ExecuteResult")]
#[derive(Debug, Clone)]
struct PyExecuteResult {
    #[pyo3(get)]
    stdout: String,
    #[pyo3(get)]
    stderr: String,
    #[pyo3(get)]
    exit_code: i32,
    #[pyo3(get)]
    timed_out: bool,
    #[pyo3(get)]
    elapsed: Option<f64>,
}

impl From<ExecuteResult> for PyExecuteResult {
    fn from(result: ExecuteResult) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
            // 底层在超时等场景可能无退出码，这里统一映射为 -1，
            // 并通过 timed_out 字段让调用方区分超时与正常退出。
            exit_code: result.exit_code.unwrap_or(-1),
            timed_out: result.timed_out,
            elapsed: if result.elapsed.is_zero() {
                None
            } else {
                Some(result.elapsed.as_secs_f64())
            },
        }
    }
}

/// HTTP response from the host-side proxy.
///
/// Returned by `Sandbox.http_request()`. The body is exposed as raw bytes;
/// headers are exposed as a Python dict.
///
/// # Attributes
///
/// * `status` - HTTP status code (e.g., 200, 404).
/// * `headers` - Response headers as a Python dict.
/// * `body` - Response body as raw bytes.
#[pyclass(name = "HttpResponse")]
#[derive(Debug, Clone)]
struct PyHttpResponse {
    #[pyo3(get)]
    status: u16,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

#[pymethods]
impl PyHttpResponse {
    /// Returns response headers as a Python dictionary.
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (key, value) in &self.headers {
            dict.set_item(key, value)?;
        }
        Ok(dict)
    }

    /// Returns the response body as raw bytes.
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.body.as_slice())
    }
}

impl From<mimobox_sdk::HttpResponse> for PyHttpResponse {
    fn from(value: mimobox_sdk::HttpResponse) -> Self {
        Self {
            status: value.status,
            headers: value.headers,
            body: value.body,
        }
    }
}

/// A single directory entry returned by `Sandbox.list_dir()`.
///
/// # Attributes
///
/// * `name` - File or directory name.
/// * `file_type` - Type string: "file", "dir", "symlink", or "other".
/// * `size` - File size in bytes.
/// * `is_symlink` - Whether this entry is a symbolic link.
#[pyclass(name = "DirEntry")]
#[derive(Debug, Clone)]
struct PyDirEntry {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    file_type: String,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    is_symlink: bool,
}

impl From<DirEntry> for PyDirEntry {
    fn from(value: DirEntry) -> Self {
        Self {
            name: value.name,
            file_type: match value.file_type {
                FileType::File => "file",
                FileType::Dir => "dir",
                FileType::Symlink => "symlink",
                _ => "other",
            }
            .to_string(),
            size: value.size,
            is_symlink: value.is_symlink,
        }
    }
}

/// 文件元信息，由 Sandbox.stat() 返回。
#[pyclass(name = "FileStat")]
#[derive(Debug, Clone)]
struct PyFileStat {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    is_dir: bool,
    #[pyo3(get)]
    is_file: bool,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    mode: u32,
    #[pyo3(get)]
    modified_ms: Option<u64>,
}

impl From<FileStat> for PyFileStat {
    fn from(value: FileStat) -> Self {
        Self {
            path: value.path,
            is_dir: value.is_dir,
            is_file: value.is_file,
            size: value.size,
            mode: value.mode,
            modified_ms: value.modified_ms,
        }
    }
}

/// An immutable sandbox snapshot that can be serialized and restored.
///
/// Snapshots capture the complete sandbox state and can be used to create
/// new sandbox instances via `Sandbox.from_snapshot()` or saved to disk
/// for later restoration.
#[pyclass(name = "Snapshot")]
#[derive(Debug, Clone)]
struct PySnapshot {
    inner: RustSnapshot,
}

#[pymethods]
impl PySnapshot {
    /// Reconstruct a snapshot from its serialized byte representation.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes previously obtained via `to_bytes()`.
    ///
    /// # Returns
    ///
    /// A restored `Snapshot` instance.
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, PyType>, data: &[u8]) -> PyResult<Self> {
        let snapshot = RustSnapshot::from_bytes(data).map_err(map_sdk_error)?;
        Ok(Self { inner: snapshot })
    }

    /// 从文件化快照创建 Snapshot 实例。
    ///
    /// 直接从磁盘文件路径构造快照引用，无需将整个文件读入内存。
    /// 适用于之前通过 `to_bytes()` 保存到磁盘的大快照文件。
    ///
    /// # Arguments
    ///
    /// * `path` - 快照文件的磁盘路径（如之前 `to_bytes()` 保存的 `.bin` 文件）。
    ///
    /// # Returns
    ///
    /// A restored `Snapshot` instance.
    ///
    /// # Raises
    ///
    /// * `FileNotFoundError` - If the file does not exist.
    /// * `SandboxError` - If the snapshot file is invalid.
    #[classmethod]
    fn from_file(_cls: &Bound<'_, PyType>, path: &str) -> PyResult<Self> {
        let snapshot =
            RustSnapshot::from_file(std::path::PathBuf::from(path)).map_err(map_sdk_error)?;
        Ok(Self { inner: snapshot })
    }

    /// Serialize the snapshot to raw bytes.
    ///
    /// # Returns
    ///
    /// The snapshot data as a bytes object.
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.to_bytes().map_err(map_sdk_error)?;
        Ok(PyBytes::new(py, bytes.as_slice()))
    }

    /// Returns the size of the snapshot data in bytes.
    #[getter]
    fn size(&self) -> usize {
        self.inner.size()
    }
}

/// A secure sandbox for executing commands.
///
/// Wraps the Rust SDK `Sandbox` and provides a Pythonic interface.
/// Supports context manager protocol (`with` statement) for automatic
/// resource cleanup.
///
/// # Example
///
/// ```python
/// with Sandbox(isolation="os") as sb:
///     result = sb.execute("echo hello", timeout=5.0)
///     print(result.stdout)
/// ```
///
/// # Arguments
///
/// * `isolation` - Isolation level: `"auto"`, `"os"`, `"wasm"`, or `"microvm"`.
/// * `allowed_http_domains` - List of domains allowed for HTTP proxy requests.
///   Supports glob patterns like `"*.openai.com"`.
#[pyclass(name = "Sandbox", unsendable)]
struct PySandbox {
    inner: Option<RustSandbox>,
}

/// A single event from a streaming sandbox execution.
///
/// Each event carries at most one type of data: a stdout chunk, a stderr chunk,
/// an exit code, or a timeout notification.
///
/// # Attributes
///
/// * `stdout` - Stdout bytes chunk, or `None` if this event carries no stdout data.
/// * `stderr` - Stderr bytes chunk, or `None` if this event carries no stderr data.
/// * `exit_code` - Process exit code, or `None` if the process has not exited yet.
/// * `timed_out` - `True` if the command exceeded its time limit.
#[pyclass(name = "StreamEvent")]
#[derive(Debug, Clone)]
struct PyStreamEvent {
    event_type: String,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
    exit_code: Option<i32>,
    timed_out: bool,
}

#[pymethods]
impl PyStreamEvent {
    #[getter]
    fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Returns stdout bytes chunk, if present.
    #[getter]
    fn stdout<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.stdout
            .as_ref()
            .map(|data| PyBytes::new(py, data.as_slice()))
    }

    /// Returns stderr bytes chunk, if present.
    #[getter]
    fn stderr<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.stderr
            .as_ref()
            .map(|data| PyBytes::new(py, data.as_slice()))
    }

    /// Returns the process exit code, if available.
    #[getter]
    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Returns whether the command timed out.
    #[getter]
    fn timed_out(&self) -> bool {
        self.timed_out
    }
}

impl From<StreamEvent> for PyStreamEvent {
    fn from(event: StreamEvent) -> Self {
        match event {
            StreamEvent::Stdout(data) => Self {
                event_type: "stdout".to_string(),
                stdout: Some(data),
                stderr: None,
                exit_code: None,
                timed_out: false,
            },
            StreamEvent::Stderr(data) => Self {
                event_type: "stderr".to_string(),
                stdout: None,
                stderr: Some(data),
                exit_code: None,
                timed_out: false,
            },
            StreamEvent::Exit(code) => Self {
                event_type: "exit".to_string(),
                stdout: None,
                stderr: None,
                exit_code: Some(code),
                timed_out: false,
            },
            StreamEvent::TimedOut => Self {
                event_type: "timeout".to_string(),
                stdout: None,
                stderr: None,
                exit_code: None,
                timed_out: true,
            },
            _ => Self {
                event_type: "unknown".to_string(),
                stdout: None,
                stderr: None,
                exit_code: None,
                timed_out: false,
            },
        }
    }
}

/// 文件系统子模块（sandbox.fs）。
///
/// 聚合文件操作 API，通过代理模式调用 PySandbox 的已有方法。
#[pyclass(name = "FileSystem")]
struct PyFileSystem {
    sandbox: Py<PyAny>,
}

#[pymethods]
impl PyFileSystem {
    /// 读取文件内容。
    fn read(&self, py: Python<'_>, path: &str) -> PyResult<Vec<u8>> {
        let result = self.sandbox.call_method1(py, "read_file", (path,))?;
        result.extract(py)
    }

    /// 写入文件。
    fn write(&self, py: Python<'_>, path: &str, data: &Bound<'_, PyAny>) -> PyResult<()> {
        let bytes = extract_bytes_data(data)?;
        self.sandbox.call_method1(py, "write_file", (path, bytes))?;
        Ok(())
    }

    /// 列出目录内容。
    fn list(&self, py: Python<'_>, path: &str) -> PyResult<Vec<PyDirEntry>> {
        let result = self.sandbox.call_method1(py, "list_dir", (path,))?;
        result.extract(py)
    }

    /// 检查文件是否存在。
    fn exists(&self, py: Python<'_>, path: &str) -> PyResult<bool> {
        let result = self.sandbox.call_method1(py, "file_exists", (path,))?;
        result.extract(py)
    }

    /// 删除文件。
    fn remove(&self, py: Python<'_>, path: &str) -> PyResult<()> {
        self.sandbox.call_method1(py, "remove_file", (path,))?;
        Ok(())
    }

    /// 重命名或移动文件。
    fn rename(&self, py: Python<'_>, from: &str, to: &str) -> PyResult<()> {
        self.sandbox.call_method1(py, "rename", (from, to))?;
        Ok(())
    }

    /// 返回文件元信息。
    fn stat(&self, py: Python<'_>, path: &str) -> PyResult<PyFileStat> {
        let result = self.sandbox.call_method1(py, "stat", (path,))?;
        result.extract(py)
    }
}

/// 进程子模块（sandbox.process）。
///
/// 聚合命令执行 API，通过代理模式调用 PySandbox 的已有方法。
#[pyclass(name = "Process")]
struct PyProcess {
    sandbox: Py<PyAny>,
}

#[pymethods]
impl PyProcess {
    /// 执行 shell 命令。
    #[pyo3(signature = (command, env=None, timeout=None, cwd=None))]
    fn run(
        &self,
        py: Python<'_>,
        command: &str,
        env: Option<std::collections::HashMap<String, String>>,
        timeout: Option<f64>,
        cwd: Option<&str>,
    ) -> PyResult<PyExecuteResult> {
        let result = self
            .sandbox
            .call_method1(py, "execute", (command, env, timeout, cwd))?;
        result.extract(py)
    }

    /// 执行代码片段。
    #[pyo3(signature = (language, code, *, env=None, timeout=None, cwd=None))]
    fn run_code(
        &self,
        py: Python<'_>,
        language: &str,
        code: &str,
        env: Option<std::collections::HashMap<String, String>>,
        timeout: Option<f64>,
        cwd: Option<&str>,
    ) -> PyResult<PyExecuteResult> {
        let kwargs = PyDict::new(py);
        if let Some(env) = env {
            kwargs.set_item("env", env)?;
        }
        if let Some(timeout) = timeout {
            kwargs.set_item("timeout", timeout)?;
        }
        if let Some(cwd) = cwd {
            kwargs.set_item("cwd", cwd)?;
        }

        let result =
            self.sandbox
                .call_method(py, "execute_code", (language, code), Some(&kwargs))?;
        result.extract(py)
    }

    /// 流式执行命令。
    fn stream(&self, py: Python<'_>, command: &str) -> PyResult<Py<PyAny>> {
        self.sandbox.call_method1(py, "stream_execute", (command,))
    }
}

/// 快照子模块（sandbox.snapshot）。
///
/// 聚合快照操作 API，通过代理模式调用 PySandbox 的已有方法。
#[pyclass(name = "SnapshotOps")]
struct PySnapshotOps {
    sandbox: Py<PyAny>,
}

#[pymethods]
impl PySnapshotOps {
    /// 兼容旧 API：允许 sandbox.snapshot() 继续捕获快照。
    fn __call__(&self, py: Python<'_>) -> PyResult<PySnapshot> {
        self.capture(py)
    }

    /// 捕获当前沙箱状态的快照。
    fn capture(&self, py: Python<'_>) -> PyResult<PySnapshot> {
        let result = self.sandbox.call_method0(py, "_capture_snapshot")?;
        result.extract(py)
    }

    /// 基于当前实例派生一个独立沙箱。
    fn fork(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.sandbox.call_method0(py, "fork")
    }
}

/// 网络子模块（sandbox.network）。
///
/// 聚合 HTTP 请求 API，通过代理模式调用 PySandbox 的已有方法。
#[pyclass(name = "Network")]
struct PyNetwork {
    sandbox: Py<PyAny>,
}

#[pymethods]
impl PyNetwork {
    /// 发起 HTTPS 请求（通过 host 代理）。
    #[pyo3(signature = (method, url, headers=None, body=None))]
    fn request(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Option<std::collections::HashMap<String, String>>,
        body: Option<Vec<u8>>,
    ) -> PyResult<PyHttpResponse> {
        let result = self
            .sandbox
            .call_method1(py, "http_request", (method, url, headers, body))?;
        result.extract(py)
    }
}

/// Python iterator over `StreamEvent` objects from a streaming execution.
///
/// Created by `Sandbox.stream_execute()`. Yields `StreamEvent` objects
/// until the stream is exhausted.
#[pyclass(name = "StreamIterator", unsendable)]
struct PyStreamIterator {
    receiver: Option<mpsc::Receiver<StreamEvent>>,
}

#[pymethods]
impl PyStreamIterator {
    /// Returns self as the iterator object.
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Returns the next `StreamEvent`, or `None` when the stream is exhausted.
    fn __next__(&mut self) -> PyResult<Option<PyStreamEvent>> {
        let Some(receiver) = self.receiver.as_ref() else {
            return Ok(None);
        };

        match receiver.recv() {
            Ok(event) => Ok(Some(event.into())),
            Err(_) => {
                self.receiver = None;
                Ok(None)
            }
        }
    }
}

#[pymethods]
impl PySandbox {
    /// Create a new sandbox instance.
    ///
    /// # Arguments
    ///
    /// * `isolation` - Isolation level: `"auto"`, `"os"`, `"wasm"`, or `"microvm"`.
    ///   Defaults to `"auto"` (smart routing) when `None`.
    /// * `allowed_http_domains` - List of domains allowed for HTTP proxy requests.
    ///   Supports glob patterns like `"*.openai.com"`. Defaults to empty when `None`.
    ///
    /// # Returns
    ///
    /// A new `Sandbox` instance ready for command execution.
    ///
    /// # Raises
    ///
    /// * `ValueError` - If `isolation` is not a recognized level.
    /// * `SandboxError` - If sandbox creation fails.
    #[new]
    #[pyo3(signature = (*, isolation=None, allowed_http_domains=None))]
    fn new(isolation: Option<&str>, allowed_http_domains: Option<Vec<String>>) -> PyResult<Self> {
        let config =
            build_python_config(isolation, allowed_http_domains).map_err(PyValueError::new_err)?;
        let sandbox = RustSandbox::with_config(config).map_err(map_sdk_error)?;
        Ok(Self {
            inner: Some(sandbox),
        })
    }

    /// 返回文件系统子模块。
    #[getter]
    fn fs(slf: PyRef<'_, Self>) -> PyFileSystem {
        PyFileSystem {
            sandbox: Py::<PySandbox>::from(slf).into_any(),
        }
    }

    /// 返回进程子模块。
    #[getter]
    fn process(slf: PyRef<'_, Self>) -> PyProcess {
        PyProcess {
            sandbox: Py::<PySandbox>::from(slf).into_any(),
        }
    }

    /// 返回快照子模块。
    #[getter]
    #[pyo3(name = "snapshot")]
    fn snapshot_ops(slf: PyRef<'_, Self>) -> PySnapshotOps {
        PySnapshotOps {
            sandbox: Py::<PySandbox>::from(slf).into_any(),
        }
    }

    /// 返回网络子模块。
    #[getter]
    fn network(slf: PyRef<'_, Self>) -> PyNetwork {
        PyNetwork {
            sandbox: Py::<PySandbox>::from(slf).into_any(),
        }
    }

    /// Execute a shell-style command inside the sandbox.
    ///
    /// # Arguments
    ///
    /// * `command` - Shell command to execute.
    /// * `env` - Optional environment variables to set for the command.
    /// * `timeout` - Optional timeout in seconds (float). Must be > 0 and finite.
    /// * `cwd` - Optional working directory for this command.
    ///
    /// # Returns
    ///
    /// An `ExecuteResult` with stdout, stderr, exit_code, and timed_out.
    ///
    /// # Raises
    ///
    /// * `SandboxError` - If the sandbox is destroyed or execution fails.
    /// * `SandboxProcessError` - If the command exits non-zero or is killed.
    /// * `TimeoutError` - If the command exceeds the specified timeout.
    #[pyo3(signature = (command, env=None, timeout=None, cwd=None))]
    fn execute(
        &mut self,
        command: &str,
        env: Option<std::collections::HashMap<String, String>>,
        timeout: Option<f64>,
        cwd: Option<&str>,
    ) -> PyResult<PyExecuteResult> {
        let sandbox = self.inner_mut()?;
        let effective_command = match cwd {
            Some(dir) => {
                if dir.contains("..") {
                    return Err(PyValueError::new_err(
                        "cwd must not contain '..' path traversal",
                    ));
                }
                let quoted = shlex::try_quote(dir).map_err(|_| {
                    PyValueError::new_err("cwd contains characters that cannot be shell-escaped")
                })?;
                format!("cd {quoted} && {command}")
            }
            None => command.to_string(),
        };
        let result = match (env, timeout) {
            (Some(env), Some(timeout)) => sandbox
                .execute_with_env_and_timeout(
                    &effective_command,
                    env,
                    parse_python_timeout(timeout)?,
                )
                .map_err(map_sdk_error)?,
            (Some(env), None) => sandbox
                .execute_with_env(&effective_command, env)
                .map_err(map_sdk_error)?,
            (None, Some(timeout)) => sandbox
                .execute_with_timeout(&effective_command, parse_python_timeout(timeout)?)
                .map_err(map_sdk_error)?,
            (None, None) => sandbox.execute(&effective_command).map_err(map_sdk_error)?,
        };
        Ok(result.into())
    }

    /// Execute code in the given language inside the sandbox.
    ///
    /// # Arguments
    ///
    /// * `language` - Programming language: "bash", "sh", "shell", "python", "python3", "py",
    ///   "javascript", "js", "node", "nodejs".
    /// * `code` - Source code to execute.
    /// * `env` - Optional environment variables to set for the command.
    /// * `timeout` - Optional timeout in seconds (float). Must be > 0 and finite.
    /// * `cwd` - Optional working directory for this command.
    ///
    /// # Returns
    ///
    /// An `ExecuteResult` with stdout, stderr, exit_code, and timed_out.
    ///
    /// # Raises
    ///
    /// * `SandboxError` - If the sandbox is destroyed or execution fails.
    /// * `ValueError` - If the language is not supported.
    #[pyo3(signature = (language, code, *, env=None, timeout=None, cwd=None))]
    fn execute_code(
        &mut self,
        language: &str,
        code: &str,
        env: Option<std::collections::HashMap<String, String>>,
        timeout: Option<f64>,
        cwd: Option<&str>,
    ) -> PyResult<PyExecuteResult> {
        let command = build_python_code_command(language, code)?;
        self.execute(&command, env, timeout, cwd)
    }

    /// Execute a command and return a streaming iterator of events.
    ///
    /// # Arguments
    ///
    /// * `command` - Shell command to execute.
    ///
    /// # Returns
    ///
    /// A `StreamIterator` yielding `StreamEvent` objects for stdout,
    /// stderr chunks and the final exit event.
    fn stream_execute(&mut self, command: &str) -> PyResult<PyStreamIterator> {
        let sandbox = self.inner_mut()?;
        let receiver = sandbox.stream_execute(command).map_err(map_sdk_error)?;
        Ok(PyStreamIterator {
            receiver: Some(receiver),
        })
    }

    /// Wait until the sandbox is ready to accept commands.
    #[pyo3(signature = (timeout_secs=None))]
    fn wait_ready(&mut self, timeout_secs: Option<f64>) -> PyResult<()> {
        let sandbox = self.inner_mut()?;
        let timeout = parse_python_timeout(timeout_secs.unwrap_or(30.0))?;
        sandbox.wait_ready(timeout).map_err(map_sdk_error)
    }

    /// Return whether the sandbox is currently ready.
    fn is_ready(&self) -> bool {
        self.inner.as_ref().is_some_and(|s| s.is_ready())
    }

    /// List directory entries inside the sandbox.
    ///
    /// # Arguments
    ///
    /// * `path` - Absolute path inside the sandbox filesystem.
    ///
    /// # Returns
    ///
    /// A list of `DirEntry` objects with name, file_type, size, and is_symlink.
    ///
    /// # Raises
    ///
    /// * `SandboxError` - If the directory cannot be read.
    fn list_dir(&mut self, path: &str) -> PyResult<Vec<PyDirEntry>> {
        let sandbox = self.inner_mut()?;
        let entries = sandbox.list_dir(path).map_err(map_sdk_error)?;
        Ok(entries.into_iter().map(PyDirEntry::from).collect())
    }

    /// 检查指定路径的文件是否存在。
    fn file_exists(&mut self, path: &str) -> PyResult<bool> {
        let sandbox = self.inner_mut()?;
        sandbox.file_exists(path).map_err(map_sdk_error)
    }

    /// 删除指定路径的文件或空目录。
    fn remove_file(&mut self, path: &str) -> PyResult<()> {
        let sandbox = self.inner_mut()?;
        sandbox.remove_file(path).map_err(map_sdk_error)
    }

    /// 重命名/移动文件。
    fn rename(&mut self, from: &str, to: &str) -> PyResult<()> {
        let sandbox = self.inner_mut()?;
        sandbox.rename(from, to).map_err(map_sdk_error)
    }

    /// 返回文件元信息。
    fn stat(&mut self, path: &str) -> PyResult<PyFileStat> {
        let sandbox = self.inner_mut()?;
        sandbox
            .stat(path)
            .map(PyFileStat::from)
            .map_err(map_sdk_error)
    }

    /// Read a file from inside the sandbox.
    ///
    /// # Arguments
    ///
    /// * `path` - Absolute path inside the sandbox filesystem.
    ///
    /// # Returns
    ///
    /// File contents as raw bytes.
    ///
    /// # Raises
    ///
    /// * `FileNotFoundError` - If the file does not exist.
    /// * `PermissionError` - If access is denied.
    /// * `SandboxError` - If the read operation fails.
    fn read_file(&mut self, path: &str) -> PyResult<Vec<u8>> {
        let sandbox = self.inner_mut()?;
        sandbox.read_file(path).map_err(map_sdk_error)
    }

    /// Write bytes to a file inside the sandbox.
    ///
    /// # Arguments
    ///
    /// * `path` - Absolute path inside the sandbox filesystem.
    /// * `data` - Raw bytes to write.
    ///
    /// # Raises
    ///
    /// * `SandboxError` - If the write operation fails.
    fn write_file(&mut self, path: &str, data: &Bound<'_, PyAny>) -> PyResult<()> {
        let bytes = extract_bytes_data(data)?;
        let sandbox = self.inner_mut()?;
        sandbox.write_file(path, &bytes).map_err(map_sdk_error)
    }

    /// Capture a snapshot of the current sandbox state.
    ///
    /// # Returns
    ///
    /// A `Snapshot` that can be used to restore or fork sandboxes.
    ///
    /// # Raises
    ///
    /// * `SandboxError` - If snapshotting fails.
    #[pyo3(name = "_capture_snapshot")]
    fn capture_snapshot(&mut self) -> PyResult<PySnapshot> {
        let sandbox = self.inner_mut()?;
        let snapshot = sandbox.snapshot().map_err(map_sdk_error)?;
        Ok(PySnapshot { inner: snapshot })
    }

    /// Create a new sandbox by restoring from a snapshot.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - A previously captured `Snapshot`.
    ///
    /// # Returns
    ///
    /// A new `Sandbox` instance with the restored state.
    ///
    /// # Raises
    ///
    /// * `SandboxError` - If restoration fails.
    #[classmethod]
    fn from_snapshot(_cls: &Bound<'_, PyType>, snapshot: PyRef<'_, PySnapshot>) -> PyResult<Self> {
        let sandbox = RustSandbox::from_snapshot(&snapshot.inner).map_err(map_sdk_error)?;
        Ok(Self {
            inner: Some(sandbox),
        })
    }

    /// Create an independent sandbox that inherits the current state.
    ///
    /// Uses copy-on-write (CoW) for efficient memory sharing.
    ///
    /// # Returns
    ///
    /// A new `Sandbox` instance with a copy of the current state.
    ///
    /// # Raises
    ///
    /// * `SandboxError` - If forking fails.
    fn fork(&mut self) -> PyResult<Self> {
        let sandbox = self.inner_mut()?;
        let forked = sandbox.fork().map_err(map_sdk_error)?;
        Ok(Self {
            inner: Some(forked),
        })
    }

    /// Perform an HTTPS request through the host-side proxy.
    ///
    /// The request is subject to the domain whitelist configured at sandbox creation.
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method (`"GET"`, `"POST"`, etc.).
    /// * `url` - Full HTTPS URL.
    /// * `headers` - Optional request headers.
    /// * `body` - Optional request body as raw bytes.
    ///
    /// # Returns
    ///
    /// An `HttpResponse` with status, headers, and body.
    ///
    /// # Raises
    ///
    /// * `SandboxHttpError` - If the domain is not whitelisted or the request fails.
    /// * `ConnectionError` - If the connection cannot be established.
    #[pyo3(signature = (method, url, headers=None, body=None))]
    fn http_request(
        &mut self,
        method: &str,
        url: &str,
        headers: Option<std::collections::HashMap<String, String>>,
        body: Option<Vec<u8>>,
    ) -> PyResult<PyHttpResponse> {
        let sandbox = self.inner_mut()?;
        let response = sandbox
            .http_request(method, url, headers.unwrap_or_default(), body.as_deref())
            .map_err(map_sdk_error)?;
        Ok(response.into())
    }

    /// Release sandbox resources.
    ///
    /// Safe to call multiple times; subsequent calls after the first are no-ops.
    /// Also called automatically by the context manager exit.
    fn close(&mut self) -> PyResult<()> {
        if let Some(sandbox) = self.inner.take() {
            sandbox.destroy().map_err(map_sdk_error)?;
        }

        Ok(())
    }

    /// Support `with Sandbox() as sandbox:` usage. Returns self.
    fn __enter__(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    /// Release sandbox resources on context manager exit.
    ///
    /// Does not suppress exceptions (always returns `False`).
    fn __exit__(
        &mut self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.close()?;
        Ok(false)
    }
}

impl PySandbox {
    fn inner_mut(&mut self) -> PyResult<&mut RustSandbox> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Sandbox has been closed"))
    }
}

fn build_python_config(
    isolation: Option<&str>,
    allowed_http_domains: Option<Vec<String>>,
) -> Result<Config, String> {
    let mut builder = Config::builder();

    if let Some(isolation) = isolation {
        builder = builder.isolation(parse_python_isolation(isolation)?);
    }

    if let Some(domains) = allowed_http_domains {
        builder = builder.allowed_http_domains(domains);
    }

    Ok(builder.build())
}

fn build_python_code_command(language: &str, code: &str) -> PyResult<String> {
    let quoted = shlex::try_quote(code).map_err(|_| {
        PyValueError::new_err("code contains characters that cannot be shell-escaped")
    })?;

    match language {
        "bash" => Ok(format!("bash -c {quoted}")),
        "sh" | "shell" => Ok(format!("sh -c {quoted}")),
        "python" | "python3" | "py" => Ok(format!("python3 -c {quoted}")),
        "javascript" | "js" | "node" | "nodejs" => Ok(format!("node -e {quoted}")),
        _ => Err(PyValueError::new_err(format!(
            "unsupported language: {language}. Supported: bash, sh, shell, python, python3, py, javascript, js, node, nodejs"
        ))),
    }
}

fn parse_python_isolation(value: &str) -> Result<IsolationLevel, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(IsolationLevel::Auto),
        "os" => Ok(IsolationLevel::Os),
        "wasm" => Ok(IsolationLevel::Wasm),
        "microvm" | "micro-vm" | "micro_vm" => Ok(IsolationLevel::MicroVm),
        other => Err(format!(
            "unknown isolation value: {other}. Valid values: auto, os, wasm, microvm"
        )),
    }
}

fn map_sdk_error(error: SdkError) -> PyErr {
    match error {
        SdkError::Config(message) => PyValueError::new_err(message),
        SdkError::BackendUnavailable(msg) => PyNotImplementedError::new_err(msg),
        SdkError::Io(err) => match err.kind() {
            std::io::ErrorKind::NotFound => PyFileNotFoundError::new_err(err.to_string()),
            std::io::ErrorKind::PermissionDenied => PyPermissionError::new_err(err.to_string()),
            _ => PyRuntimeError::new_err(err.to_string()),
        },
        SdkError::Sandbox {
            code,
            message,
            suggestion,
        } => {
            let detail = match suggestion {
                Some(suggestion) => format!("{message}. Suggestion: {suggestion}"),
                None => message,
            };

            match code {
                ErrorCode::CommandTimeout | ErrorCode::HttpTimeout => {
                    SandboxTimeoutError::new_err(detail)
                }
                ErrorCode::FileNotFound => PyFileNotFoundError::new_err(detail),
                ErrorCode::FilePermissionDenied => PyPermissionError::new_err(detail),
                ErrorCode::FileTooLarge => SandboxError::new_err(detail),
                ErrorCode::NotDirectory => SandboxError::new_err(detail),
                ErrorCode::HttpConnectFail | ErrorCode::HttpTlsFail => {
                    PyConnectionError::new_err(detail)
                }
                ErrorCode::InvalidConfig => PyValueError::new_err(detail),
                ErrorCode::UnsupportedPlatform => PyNotImplementedError::new_err(detail),
                ErrorCode::CommandExit(_) | ErrorCode::CommandKilled => {
                    SandboxProcessError::new_err(detail)
                }
                ErrorCode::HttpDeniedHost
                | ErrorCode::HttpBodyTooLarge
                | ErrorCode::HttpInvalidUrl => SandboxHttpError::new_err(detail),
                ErrorCode::SandboxNotReady
                | ErrorCode::SandboxDestroyed
                | ErrorCode::SandboxCreateFailed => SandboxLifecycleError::new_err(detail),
                _ => {
                    tracing::warn!("未识别的 ErrorCode 变体，降级为 SandboxError", code = ?code);
                    SandboxError::new_err(detail)
                }
            }
        }
        error => PyRuntimeError::new_err(error.to_string()),
    }
}

fn parse_python_timeout(timeout: f64) -> PyResult<std::time::Duration> {
    if !timeout.is_finite() || timeout <= 0.0 {
        return Err(PyValueError::new_err(
            "timeout must be a finite positive float",
        ));
    }

    Ok(std::time::Duration::from_secs_f64(timeout))
}

#[pymodule]
fn mimobox(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    module.add_class::<PySandbox>()?;
    module.add_class::<PySnapshot>()?;
    module.add_class::<PyExecuteResult>()?;
    module.add_class::<PyHttpResponse>()?;
    module.add_class::<PyDirEntry>()?;
    module.add_class::<PyFileStat>()?;
    module.add_class::<PyStreamEvent>()?;
    module.add_class::<PyStreamIterator>()?;
    module.add_class::<PyFileSystem>()?;
    module.add_class::<PyProcess>()?;
    module.add_class::<PySnapshotOps>()?;
    module.add_class::<PyNetwork>()?;
    module.add("SandboxError", py.get_type::<SandboxError>())?;
    module.add("SandboxTimeoutError", py.get_type::<SandboxTimeoutError>())?;
    module.add("SandboxProcessError", py.get_type::<SandboxProcessError>())?;
    module.add("SandboxHttpError", py.get_type::<SandboxHttpError>())?;
    module.add(
        "SandboxLifecycleError",
        py.get_type::<SandboxLifecycleError>(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn python_config_builder_accepts_microvm_and_http_domains() {
        let config = build_python_config(
            Some("microvm"),
            Some(vec![
                "api.github.com".to_string(),
                "example.com".to_string(),
            ]),
        )
        .expect("构造 Python 配置失败");

        assert_eq!(config.isolation, IsolationLevel::MicroVm);
        assert_eq!(
            config.allowed_http_domains,
            vec!["api.github.com".to_string(), "example.com".to_string()]
        );
    }

    #[test]
    fn python_isolation_parser_rejects_unknown_values() {
        let result = parse_python_isolation("unknown");

        assert!(result.is_err());
    }

    #[test]
    fn missing_exit_code_maps_to_negative_one() {
        let result = PyExecuteResult::from(ExecuteResult::new(
            Vec::new(),
            Vec::new(),
            None,
            true,
            Duration::ZERO,
        ));

        assert_eq!(result.exit_code, -1);
        assert!(result.timed_out);
        assert_eq!(result.elapsed, None);
    }

    #[test]
    fn invalid_utf8_output_is_lossily_decoded() {
        let result = PyExecuteResult::from(ExecuteResult::new(
            vec![0x66, 0x6f, 0x80, 0x6f],
            vec![0xff],
            Some(7),
            false,
            Duration::ZERO,
        ));

        assert_eq!(result.stdout, "fo\u{fffd}o");
        assert_eq!(result.stderr, "\u{fffd}");
        assert_eq!(result.exit_code, 7);
        assert!(!result.timed_out);
        assert_eq!(result.elapsed, None);
    }

    #[test]
    fn stream_event_maps_to_python_bytes_and_exit() {
        let stdout = PyStreamEvent::from(StreamEvent::Stdout(b"out".to_vec()));
        let timed_out = PyStreamEvent::from(StreamEvent::TimedOut);
        let exit = PyStreamEvent::from(StreamEvent::Exit(9));

        Python::with_gil(|py| {
            assert_eq!(
                stdout.stdout(py).expect("stdout bytes 必须存在").as_bytes(),
                b"out"
            );
        });
        assert!(timed_out.timed_out);
        assert_eq!(exit.exit_code(), Some(9));
    }

    #[cfg(all(feature = "os", not(target_os = "windows")))]
    #[test]
    fn python_sandbox_execute_end_to_end() {
        pyo3::prepare_freethreaded_python();

        Python::with_gil(|_py| {
            let config = build_python_config(None, None).expect("构建配置失败");
            let mut sandbox = RustSandbox::with_config(config).expect("创建 Rust 沙箱失败");
            let result = sandbox
                .execute("/bin/echo hello_from_python")
                .expect("执行命令失败");

            let py_result = PyExecuteResult::from(result);
            assert!(
                py_result.stdout.contains("hello_from_python"),
                "stdout 应包含预期输出，实际: {}",
                py_result.stdout
            );
            assert_eq!(py_result.exit_code, 0, "退出码应为 0");
            assert!(!py_result.timed_out, "不应超时");

            sandbox.destroy().expect("销毁沙箱失败");
        });
    }

    #[cfg(all(feature = "os", not(target_os = "windows")))]
    #[test]
    fn python_sandbox_operations_after_close_return_error() {
        pyo3::prepare_freethreaded_python();

        let mut py_sandbox = PySandbox::new(None, None).expect("创建 Python Sandbox 失败");
        py_sandbox.close().expect("关闭 Sandbox 失败");

        let result = py_sandbox.execute("/bin/echo should_fail", None, None);

        assert!(result.is_err(), "close 后 execute 应返回错误");
    }

    #[test]
    fn python_snapshot_round_trip_preserves_bytes() {
        let snapshot =
            RustSnapshot::from_bytes(b"snapshot-bytes").expect("从字节构造 Python 快照必须成功");
        let py_snapshot = PySnapshot { inner: snapshot };

        Python::with_gil(|py| {
            assert_eq!(
                py_snapshot
                    .to_bytes(py)
                    .expect("Python 快照导出字节必须成功")
                    .as_bytes(),
                b"snapshot-bytes"
            );
        });
        assert_eq!(py_snapshot.size(), "snapshot-bytes".len());
    }
}
