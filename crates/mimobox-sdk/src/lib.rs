//! mimobox-sdk: 统一 Agent Sandbox API
//!
//! 默认智能路由，高级用户完全可控。零配置即可安全执行代码，
//! 同时暴露完整三层配置供精细控制。

mod config;
mod error;
mod router;

pub use config::{Config, ConfigBuilder, IsolationLevel, NetworkPolicy, TrustLevel};
pub use error::SdkError;

use mimobox_core::{Sandbox as CoreSandbox, SandboxResult};
use router::resolve_isolation;

/// 沙箱执行结果
pub struct ExecuteResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub elapsed: std::time::Duration,
}

impl From<SandboxResult> for ExecuteResult {
    fn from(r: SandboxResult) -> Self {
        Self {
            stdout: r.stdout,
            stderr: r.stderr,
            exit_code: r.exit_code,
            timed_out: r.timed_out,
            elapsed: r.elapsed,
        }
    }
}

/// 后端实例枚举
enum SandboxInner {
    #[cfg(all(feature = "os", target_os = "linux"))]
    Os(mimobox_os::LinuxSandbox),
    #[cfg(all(feature = "os", target_os = "macos"))]
    OsMac(mimobox_os::MacOsSandbox),
    #[cfg(feature = "wasm")]
    Wasm(mimobox_wasm::WasmSandbox),
}

/// 统一沙箱入口
///
/// 支持零配置默认（智能路由）和完整配置两种模式。
pub struct Sandbox {
    inner: SandboxInner,
}

macro_rules! dispatch_execute {
    ($self:expr, $inner:pat, $s:expr) => {
        match &mut $self.inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os($inner) => $s,
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac($inner) => $s,
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm($inner) => $s,
        }
    };
}

impl Sandbox {
    /// 零配置创建沙箱，自动路由到最优隔离层级
    pub fn new() -> Result<Self, SdkError> {
        Self::with_config(Config::default())
    }

    /// 使用完整配置创建沙箱
    pub fn with_config(config: Config) -> Result<Self, SdkError> {
        let isolation = resolve_isolation(&config, "")?;
        let sandbox_config = config.to_sandbox_config();

        let inner = match isolation {
            IsolationLevel::Os => {
                #[cfg(all(feature = "os", target_os = "linux"))]
                {
                    SandboxInner::Os(mimobox_os::LinuxSandbox::new(sandbox_config)?)
                }
                #[cfg(all(feature = "os", target_os = "macos"))]
                {
                    SandboxInner::OsMac(mimobox_os::MacOsSandbox::new(sandbox_config)?)
                }
                #[cfg(not(any(
                    all(feature = "os", target_os = "linux"),
                    all(feature = "os", target_os = "macos")
                )))]
                {
                    return Err(SdkError::BackendUnavailable("os"));
                }
            }
            IsolationLevel::Wasm => {
                #[cfg(feature = "wasm")]
                {
                    SandboxInner::Wasm(mimobox_wasm::WasmSandbox::new(sandbox_config)?)
                }
                #[cfg(not(feature = "wasm"))]
                {
                    return Err(SdkError::BackendUnavailable("wasm"));
                }
            }
            _ => return Err(SdkError::BackendUnavailable("请求的后端")),
        };

        Ok(Sandbox { inner })
    }

    /// 在沙箱中执行命令
    pub fn execute(&mut self, command: &str) -> Result<ExecuteResult, SdkError> {
        let args = shlex::split(command).unwrap_or_else(|| vec![command.to_string()]);
        let result = dispatch_execute!(self, s, s.execute(&args))?;
        Ok(result.into())
    }

    /// 销毁沙箱，释放资源
    pub fn destroy(self) -> Result<(), SdkError> {
        match self.inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(s) => s.destroy().map_err(Into::into),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(s) => s.destroy().map_err(Into::into),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => s.destroy().map_err(Into::into),
        }
    }
}
