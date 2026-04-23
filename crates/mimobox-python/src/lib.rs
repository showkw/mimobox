//! mimobox Python SDK 绑定
//!
//! 通过 PyO3 将 `mimobox-sdk` 暴露为 Python 可调用模块。

use mimobox_sdk::{
    Config, ErrorCode, ExecuteResult, IsolationLevel, Sandbox as RustSandbox,
    SandboxSnapshot as RustSnapshot, SdkError, StreamEvent,
};
use pyo3::create_exception;
use pyo3::exceptions::{
    PyConnectionError, PyFileNotFoundError, PyNotImplementedError, PyPermissionError,
    PyRuntimeError, PyTimeoutError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyType};
use std::sync::mpsc;

create_exception!(mimobox, SandboxError, pyo3::exceptions::PyException);
create_exception!(mimobox, SandboxProcessError, SandboxError);
create_exception!(mimobox, SandboxHttpError, SandboxError);
create_exception!(mimobox, SandboxLifecycleError, SandboxError);

/// Python 侧执行结果对象。
///
/// 由于 Python API 约定 `stdout` / `stderr` 为 `str`，
/// 这里对底层字节流采用 UTF-8 lossy 解码，避免二进制输出直接报错。
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
        }
    }
}

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
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (key, value) in &self.headers {
            dict.set_item(key, value)?;
        }
        Ok(dict)
    }

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

#[pyclass(name = "Snapshot")]
#[derive(Debug, Clone)]
struct PySnapshot {
    inner: RustSnapshot,
}

#[pymethods]
impl PySnapshot {
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, PyType>, data: &[u8]) -> PyResult<Self> {
        let snapshot = RustSnapshot::from_bytes(data).map_err(map_sdk_error)?;
        Ok(Self { inner: snapshot })
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.to_bytes().map_err(map_sdk_error)?;
        Ok(PyBytes::new(py, bytes.as_slice()))
    }

    #[getter]
    fn size(&self) -> usize {
        self.inner.size()
    }
}

/// Python 侧沙箱对象。
///
/// 该类型直接包装 Rust SDK 的 `Sandbox`，默认保持零配置体验，
/// 同时只开放少量高频配置，避免把完整 ConfigBuilder 直接搬到 Python。
#[pyclass(name = "Sandbox", unsendable)]
struct PySandbox {
    inner: Option<RustSandbox>,
}

#[pyclass(name = "StreamEvent")]
#[derive(Debug, Clone)]
struct PyStreamEvent {
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
    exit_code: Option<i32>,
    timed_out: bool,
}

#[pymethods]
impl PyStreamEvent {
    #[getter]
    fn stdout<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.stdout
            .as_ref()
            .map(|data| PyBytes::new(py, data.as_slice()))
    }

    #[getter]
    fn stderr<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.stderr
            .as_ref()
            .map(|data| PyBytes::new(py, data.as_slice()))
    }

    #[getter]
    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    #[getter]
    fn timed_out(&self) -> bool {
        self.timed_out
    }
}

impl From<StreamEvent> for PyStreamEvent {
    fn from(event: StreamEvent) -> Self {
        match event {
            StreamEvent::Stdout(data) => Self {
                stdout: Some(data),
                stderr: None,
                exit_code: None,
                timed_out: false,
            },
            StreamEvent::Stderr(data) => Self {
                stdout: None,
                stderr: Some(data),
                exit_code: None,
                timed_out: false,
            },
            StreamEvent::Exit(code) => Self {
                stdout: None,
                stderr: None,
                exit_code: Some(code),
                timed_out: false,
            },
            StreamEvent::TimedOut => Self {
                stdout: None,
                stderr: None,
                exit_code: None,
                timed_out: true,
            },
        }
    }
}

#[pyclass(name = "StreamIterator", unsendable)]
struct PyStreamIterator {
    receiver: Option<mpsc::Receiver<StreamEvent>>,
}

#[pymethods]
impl PyStreamIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

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

    /// 在沙箱中执行一条 shell 风格命令。
    #[pyo3(signature = (command, env=None, timeout=None))]
    fn execute(
        &mut self,
        command: &str,
        env: Option<std::collections::HashMap<String, String>>,
        timeout: Option<f64>,
    ) -> PyResult<PyExecuteResult> {
        let sandbox = self.inner_mut()?;
        let result = match (env, timeout) {
            (Some(env), Some(timeout)) => sandbox
                .execute_with_env_and_timeout(command, env, parse_python_timeout(timeout)?)
                .map_err(map_sdk_error)?,
            (Some(env), None) => sandbox
                .execute_with_env(command, env)
                .map_err(map_sdk_error)?,
            (None, Some(timeout)) => sandbox
                .execute_with_timeout(command, parse_python_timeout(timeout)?)
                .map_err(map_sdk_error)?,
            (None, None) => sandbox.execute(command).map_err(map_sdk_error)?,
        };
        Ok(result.into())
    }

    /// 以 Python 迭代器形式返回流式执行事件。
    fn stream_execute(&mut self, command: &str) -> PyResult<PyStreamIterator> {
        let sandbox = self.inner_mut()?;
        let receiver = sandbox.stream_execute(command).map_err(map_sdk_error)?;
        Ok(PyStreamIterator {
            receiver: Some(receiver),
        })
    }

    /// 从沙箱内读取文件内容，返回 Python `bytes`。
    fn read_file(&mut self, path: &str) -> PyResult<Vec<u8>> {
        let sandbox = self.inner_mut()?;
        sandbox.read_file(path).map_err(map_sdk_error)
    }

    /// 将 Python `bytes` 写入沙箱内指定路径。
    fn write_file(&mut self, path: &str, data: Vec<u8>) -> PyResult<()> {
        let sandbox = self.inner_mut()?;
        sandbox.write_file(path, &data).map_err(map_sdk_error)
    }

    /// 拍摄当前沙箱快照。
    fn snapshot(&mut self) -> PyResult<PySnapshot> {
        let sandbox = self.inner_mut()?;
        let snapshot = sandbox.snapshot().map_err(map_sdk_error)?;
        Ok(PySnapshot { inner: snapshot })
    }

    /// 从快照恢复一个新的沙箱实例。
    #[classmethod]
    fn from_snapshot(_cls: &Bound<'_, PyType>, snapshot: PyRef<'_, PySnapshot>) -> PyResult<Self> {
        let sandbox = RustSandbox::from_snapshot(&snapshot.inner).map_err(map_sdk_error)?;
        Ok(Self {
            inner: Some(sandbox),
        })
    }

    /// 基于当前状态创建一个独立的新沙箱。
    fn fork(&mut self) -> PyResult<Self> {
        let sandbox = self.inner_mut()?;
        let forked = sandbox.fork().map_err(map_sdk_error)?;
        Ok(Self {
            inner: Some(forked),
        })
    }

    /// 通过 host HTTP 代理执行 HTTPS 请求。
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

    /// 支持 `with Sandbox() as sandbox:` 用法。
    fn __enter__(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    /// 退出上下文时主动释放底层资源，但不吞掉 Python 异常。
    fn __exit__(
        &mut self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        self.close().map_err(map_sdk_error)?;
        Ok(false)
    }
}

impl PySandbox {
    fn inner_mut(&mut self) -> PyResult<&mut RustSandbox> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Sandbox 已关闭"))
    }

    fn close(&mut self) -> Result<(), SdkError> {
        if let Some(sandbox) = self.inner.take() {
            sandbox.destroy()?;
        }

        Ok(())
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

fn parse_python_isolation(value: &str) -> Result<IsolationLevel, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(IsolationLevel::Auto),
        "os" => Ok(IsolationLevel::Os),
        "wasm" => Ok(IsolationLevel::Wasm),
        "microvm" | "micro-vm" | "micro_vm" => Ok(IsolationLevel::MicroVm),
        other => Err(format!(
            "未知 isolation 值: {other}。可选值: auto, os, wasm, microvm"
        )),
    }
}

fn map_sdk_error(error: SdkError) -> PyErr {
    match error {
        SdkError::Config(message) => PyValueError::new_err(message),
        SdkError::BackendUnavailable(msg) => PyNotImplementedError::new_err(msg),
        SdkError::Io(err) => PyRuntimeError::new_err(err.to_string()),
        SdkError::Sandbox {
            code,
            message,
            suggestion,
        } => {
            let detail = match suggestion {
                Some(suggestion) => format!("{message}。建议: {suggestion}"),
                None => message,
            };

            match code {
                ErrorCode::CommandTimeout | ErrorCode::HttpTimeout => {
                    PyTimeoutError::new_err(detail)
                }
                ErrorCode::FileNotFound => PyFileNotFoundError::new_err(detail),
                ErrorCode::FilePermissionDenied => PyPermissionError::new_err(detail),
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
                ErrorCode::FileTooLarge => SandboxError::new_err(detail),
            }
        }
    }
}

fn parse_python_timeout(timeout: f64) -> PyResult<std::time::Duration> {
    if !timeout.is_finite() || timeout <= 0.0 {
        return Err(PyValueError::new_err("timeout 必须是大于 0 的有限浮点数"));
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
    module.add_class::<PyStreamEvent>()?;
    module.add_class::<PyStreamIterator>()?;
    module.add("SandboxError", py.get_type::<SandboxError>())?;
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
        let result = PyExecuteResult::from(ExecuteResult {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
            timed_out: true,
            elapsed: Duration::ZERO,
        });

        assert_eq!(result.exit_code, -1);
        assert!(result.timed_out);
    }

    #[test]
    fn invalid_utf8_output_is_lossily_decoded() {
        let result = PyExecuteResult::from(ExecuteResult {
            stdout: vec![0x66, 0x6f, 0x80, 0x6f],
            stderr: vec![0xff],
            exit_code: Some(7),
            timed_out: false,
            elapsed: Duration::ZERO,
        });

        assert_eq!(result.stdout, "fo\u{fffd}o");
        assert_eq!(result.stderr, "\u{fffd}");
        assert_eq!(result.exit_code, 7);
        assert!(!result.timed_out);
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
