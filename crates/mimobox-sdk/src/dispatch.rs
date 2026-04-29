#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use crate::error::SdkError;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::types::HttpResponse;
#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use crate::types::{ExecuteResult, StreamEvent};
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::vm_helpers::{bridge_vm_stream, map_http_proxy_error, map_microvm_error};
#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use mimobox_core::Sandbox as CoreSandbox;
#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use std::sync::mpsc;

#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
pub(crate) trait ExecuteForSdk {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError>;
}

#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
pub(crate) trait StreamExecuteForSdk {
    fn stream_execute_for_sdk(
        &mut self,
        args: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, SdkError>;
}

#[cfg(all(feature = "vm", target_os = "linux"))]
pub(crate) trait HttpRequestForSdk {
    fn http_request_for_sdk(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError>;
}

// ── ExecuteForSdk: OS/Wasm backends using the CoreSandbox trait ──

#[cfg(all(feature = "os", target_os = "linux"))]
impl ExecuteForSdk for mimobox_os::LinuxSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

#[cfg(all(feature = "os", target_os = "macos"))]
impl ExecuteForSdk for mimobox_os::MacOsSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

#[cfg(feature = "wasm")]
impl ExecuteForSdk for mimobox_wasm::WasmSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos"))
))]
fn stream_from_execute_result(result: ExecuteResult) -> mpsc::Receiver<StreamEvent> {
    let (sender, receiver) = mpsc::sync_channel(32);

    if !result.stdout.is_empty() {
        let _ = sender.send(StreamEvent::Stdout(result.stdout));
    }
    if !result.stderr.is_empty() {
        let _ = sender.send(StreamEvent::Stderr(result.stderr));
    }
    if result.timed_out {
        let _ = sender.send(StreamEvent::TimedOut);
    } else {
        let _ = sender.send(StreamEvent::Exit(result.exit_code.unwrap_or(-1)));
    }

    receiver
}

#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos"))
))]
macro_rules! impl_stream_execute_for_core_backend {
    ($ty:ty) => {
        impl StreamExecuteForSdk for $ty {
            fn stream_execute_for_sdk(
                &mut self,
                args: &[String],
            ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
                tracing::debug!(backend = stringify!($ty), "dispatching stream_execute");
                CoreSandbox::execute(self, args)
                    .map(ExecuteResult::from)
                    .map(stream_from_execute_result)
                    .map_err(SdkError::from_sandbox_execute_error)
            }
        }
    };
}

#[cfg(all(feature = "os", target_os = "linux"))]
impl_stream_execute_for_core_backend!(mimobox_os::LinuxSandbox);
#[cfg(all(feature = "os", target_os = "macos"))]
impl_stream_execute_for_core_backend!(mimobox_os::MacOsSandbox);
#[cfg(feature = "wasm")]
impl_stream_execute_for_core_backend!(mimobox_wasm::WasmSandbox);

// ── ExecuteForSdk for VM backend MicrovmSandbox via CoreSandbox trait ──

#[cfg(all(feature = "vm", target_os = "linux"))]
impl ExecuteForSdk for mimobox_vm::MicrovmSandbox {
    fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
        CoreSandbox::execute(self, args)
            .map(ExecuteResult::from)
            .map_err(SdkError::from_sandbox_execute_error)
    }
}

// ── Trait implementations for VM pooled/restored types: macros remove duplication across types ──

/// Shared execute implementation for VM pooled/restored types, using start.elapsed() instead of backend timing.
#[cfg(all(feature = "vm", target_os = "linux"))]
macro_rules! impl_execute_for_sdk_pooled {
    ($ty:ty) => {
        impl ExecuteForSdk for $ty {
            fn execute_for_sdk(&mut self, args: &[String]) -> Result<ExecuteResult, SdkError> {
                let start = std::time::Instant::now();
                self.execute(args)
                    .map(|result| ExecuteResult {
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                        timed_out: result.timed_out,
                        elapsed: start.elapsed(),
                    })
                    .map_err(map_microvm_error)
            }
        }
    };
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl_execute_for_sdk_pooled!(mimobox_vm::PooledVm);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_execute_for_sdk_pooled!(mimobox_vm::PooledRestoreVm);

/// Shared VM type implementation for StreamExecuteForSdk.
#[cfg(all(feature = "vm", target_os = "linux"))]
macro_rules! impl_stream_execute_for_sdk {
    ($ty:ty) => {
        impl StreamExecuteForSdk for $ty {
            fn stream_execute_for_sdk(
                &mut self,
                args: &[String],
            ) -> Result<mpsc::Receiver<StreamEvent>, SdkError> {
                tracing::debug!(backend = stringify!($ty), "dispatching stream_execute");
                self.stream_execute(args)
                    .map(bridge_vm_stream)
                    .map_err(map_microvm_error)
            }
        }
    };
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl_stream_execute_for_sdk!(mimobox_vm::MicrovmSandbox);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_stream_execute_for_sdk!(mimobox_vm::PooledVm);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_stream_execute_for_sdk!(mimobox_vm::PooledRestoreVm);

/// Shared VM type implementation for HttpRequestForSdk.
#[cfg(all(feature = "vm", target_os = "linux"))]
macro_rules! impl_http_request_for_sdk {
    ($ty:ty) => {
        impl HttpRequestForSdk for $ty {
            fn http_request_for_sdk(
                &mut self,
                method: &str,
                url: &str,
                headers: std::collections::HashMap<String, String>,
                body: Option<&[u8]>,
            ) -> Result<HttpResponse, SdkError> {
                let request = mimobox_vm::HttpRequest::new(
                    method,
                    url,
                    headers,
                    body.map(|item| item.to_vec()),
                    None,
                    None,
                )
                .map_err(map_http_proxy_error)?;
                self.http_request(request)
                    .map(HttpResponse::from)
                    .map_err(map_microvm_error)
            }
        }
    };
}

#[cfg(all(feature = "vm", target_os = "linux"))]
impl_http_request_for_sdk!(mimobox_vm::MicrovmSandbox);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_http_request_for_sdk!(mimobox_vm::PooledVm);
#[cfg(all(feature = "vm", target_os = "linux"))]
impl_http_request_for_sdk!(mimobox_vm::PooledRestoreVm);
