//! mimobox Python SDK 绑定
//!
//! 通过 PyO3 将 `mimobox-sdk` 暴露为 Python 可调用模块。

use mimobox_sdk::{ExecuteResult, Sandbox as RustSandbox, SdkError};
use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;

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

/// Python 侧沙箱对象。
///
/// 该类型直接包装 Rust SDK 的 `Sandbox`，不额外引入配置分支，
/// 保持 Python 首版 API 简洁稳定。
#[pyclass(name = "Sandbox", unsendable)]
struct PySandbox {
    inner: Option<RustSandbox>,
}

#[pymethods]
impl PySandbox {
    #[new]
    fn new() -> PyResult<Self> {
        let sandbox = RustSandbox::new().map_err(map_sdk_error)?;
        Ok(Self {
            inner: Some(sandbox),
        })
    }

    /// 在沙箱中执行一条 shell 风格命令。
    fn execute(&mut self, command: &str) -> PyResult<PyExecuteResult> {
        let sandbox = self.inner_mut()?;
        let result = sandbox.execute(command).map_err(map_sdk_error)?;
        Ok(result.into())
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

fn map_sdk_error(error: SdkError) -> PyErr {
    match error {
        SdkError::Config(message) => PyValueError::new_err(message),
        SdkError::BackendUnavailable(backend) => {
            PyNotImplementedError::new_err(format!("后端不可用: {backend}"))
        }
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

#[pymodule]
fn mimobox(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PySandbox>()?;
    module.add_class::<PyExecuteResult>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
}
