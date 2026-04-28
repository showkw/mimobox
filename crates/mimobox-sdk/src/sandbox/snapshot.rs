#[cfg(all(feature = "vm", target_os = "linux"))]
use super::SandboxInner;
#[cfg(all(feature = "vm", target_os = "linux"))]
use super::map_microvm_error;
#[cfg(all(feature = "vm", target_os = "linux"))]
use crate::config::{Config, IsolationLevel};
use crate::error::SdkError;
use crate::types::SandboxSnapshot;

use super::Sandbox;

impl Sandbox {
    /// Takes a snapshot of the current sandbox.
    ///
    /// This capability is currently only available on `Linux + vm feature + MicroVm` backends.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mimobox_sdk::{Config, IsolationLevel, Sandbox};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::builder()
    ///     .isolation(IsolationLevel::MicroVm)
    ///     .build()?;
    /// let mut sandbox = Sandbox::with_config(config)?;
    /// let snapshot = sandbox.snapshot()?;
    /// assert!(snapshot.size() > 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn snapshot(&mut self) -> Result<SandboxSnapshot, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        {
            self.ensure_backend_for_snapshot()?;
            let inner = self.require_inner()?;

            let snapshot = match inner {
                SandboxInner::MicroVm(sandbox) => sandbox.snapshot().map_err(map_microvm_error),
                SandboxInner::PooledMicroVm(sandbox) => {
                    sandbox.snapshot().map_err(map_microvm_error)
                }
                SandboxInner::RestoredPooledMicroVm(sandbox) => {
                    sandbox.snapshot().map_err(map_microvm_error)
                }
                _ => Err(SdkError::sandbox(
                    mimobox_core::ErrorCode::UnsupportedPlatform,
                    "current backend does not support snapshot",
                    Some(
                        "set isolation to `MicroVm` and run on Linux with vm feature enabled"
                            .to_string(),
                    ),
                )),
            }?;

            Ok(SandboxSnapshot::from_core(snapshot))
        }

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        {
            Err(SdkError::sandbox(
                mimobox_core::ErrorCode::UnsupportedPlatform,
                "snapshot not supported in current build",
                Some("use snapshot on Linux with vm feature enabled".to_string()),
            ))
        }
    }

    /// Restores a new sandbox from a snapshot.
    pub fn from_snapshot(snapshot: &SandboxSnapshot) -> Result<Self, SdkError> {
        #[cfg(all(feature = "vm", target_os = "linux"))]
        {
            let sandbox =
                mimobox_vm::MicrovmSandbox::restore(&snapshot.inner).map_err(map_microvm_error)?;
            Ok(Self::from_initialized_inner(
                SandboxInner::MicroVm(sandbox),
                Config::builder()
                    .isolation(IsolationLevel::MicroVm)
                    .build()?,
            ))
        }

        #[cfg(not(all(feature = "vm", target_os = "linux")))]
        {
            let _ = snapshot;
            Err(SdkError::sandbox(
                mimobox_core::ErrorCode::UnsupportedPlatform,
                "snapshot restore not supported in current build",
                Some("use snapshot restore on Linux with vm feature enabled".to_string()),
            ))
        }
    }

    /// Forks the current sandbox into an independent copy.
    ///
    /// Only the microVM backend supports this. The forked sandbox shares
    /// unmodified memory pages with the original sandbox (CoW), and each keeps
    /// private copies after writes.
    #[cfg(all(feature = "vm", target_os = "linux"))]
    pub fn fork(&mut self) -> Result<Self, SdkError> {
        self.ensure_backend_for_snapshot()?;
        let inner = self.require_inner()?;

        match inner {
            SandboxInner::MicroVm(sandbox) => {
                let forked = sandbox.fork().map_err(map_microvm_error)?;
                Ok(Self::from_initialized_inner(
                    SandboxInner::MicroVm(forked),
                    self.config.clone(),
                ))
            }
            _ => Err(SdkError::unsupported_backend("fork")),
        }
    }

    /// Fork stub for platforms without microVM support. Always returns `BackendUnavailable`.
    #[cfg(not(all(feature = "vm", target_os = "linux")))]
    pub fn fork(&mut self) -> Result<Self, SdkError> {
        Err(SdkError::unsupported_backend("fork"))
    }
}
