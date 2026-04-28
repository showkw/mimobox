#[cfg(feature = "vm")]
use crate::error::SdkError;
#[cfg(feature = "vm")]
use crate::types::HttpResponse;

use super::Sandbox;
#[cfg(all(feature = "vm", target_os = "linux"))]
use super::SandboxInner;
#[cfg(feature = "vm")]
use super::dispatch_vm;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::dispatch::HttpRequestForSdk;

impl Sandbox {
    #[cfg(feature = "vm")]
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    /// Sends a request through the controlled HTTP proxy.
    pub fn http_request(
        &mut self,
        method: &str,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, SdkError> {
        self.ensure_backend_for_file_ops()?;
        let inner = self.require_inner()?;

        dispatch_vm!(
            inner,
            sandbox,
            sandbox.http_request_for_sdk(method, url, headers, body),
            Err(SdkError::sandbox(
                mimobox_core::ErrorCode::UnsupportedPlatform,
                "HTTP proxy only supports microVM backend",
                Some("set isolation to `MicroVm` and configure allowed_http_domains".to_string()),
            ))
        )
    }
}
