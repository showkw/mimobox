use crate::error::SdkError;
use mimobox_core::FileStat;
#[cfg(feature = "wasm")]
use mimobox_core::{Sandbox as CoreSandbox, SandboxError};

use super::Sandbox;
#[cfg(any(
    feature = "wasm",
    all(feature = "os", any(target_os = "linux", target_os = "macos")),
    all(feature = "vm", target_os = "linux")
))]
use super::SandboxInner;
#[cfg(feature = "wasm")]
use super::map_core_file_error;
#[cfg(all(feature = "vm", target_os = "linux"))]
use super::map_microvm_error;
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use super::os_file_operation_unsupported;
#[cfg(feature = "wasm")]
use super::{read_file_via_core, write_file_via_core};

impl Sandbox {
    /// Lists directory entries under the specified path.
    ///
    /// Returns each entry's name, type, size, and symlink flag.
    pub fn list_dir(&mut self, _path: &str) -> Result<Vec<mimobox_core::DirEntry>, SdkError> {
        self.ensure_backend("/bin/ls")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(_) => Err(os_file_operation_unsupported(
                "list_dir",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(_) => Err(os_file_operation_unsupported(
                "list_dir",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.list_dir(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.list_dir(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => s.list_dir(_path).map_err(map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => CoreSandbox::list_dir(s, _path).map_err(|err| match err {
                SandboxError::Io(io_err) => SdkError::Io(io_err),
                other => SdkError::from_sandbox_execute_error(other),
            }),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }

    /// 检查指定路径的文件是否存在。
    pub fn file_exists(&mut self, _path: &str) -> Result<bool, SdkError> {
        self.ensure_backend("/bin/test")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(_) => Err(os_file_operation_unsupported(
                "file_exists",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(_) => Err(os_file_operation_unsupported(
                "file_exists",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.file_exists(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.file_exists(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => {
                s.file_exists(_path).map_err(map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => CoreSandbox::file_exists(s, _path).map_err(|err| match err {
                SandboxError::Io(io_err) => SdkError::Io(io_err),
                other => SdkError::from_sandbox_execute_error(other),
            }),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }

    /// 删除指定路径的文件或空目录。
    pub fn remove_file(&mut self, _path: &str) -> Result<(), SdkError> {
        self.ensure_backend("/bin/test")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(_) => Err(os_file_operation_unsupported(
                "remove_file",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(_) => Err(os_file_operation_unsupported(
                "remove_file",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.remove_file(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.remove_file(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => {
                s.remove_file(_path).map_err(map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => CoreSandbox::remove_file(s, _path).map_err(|err| match err {
                SandboxError::Io(io_err) => SdkError::Io(io_err),
                other => SdkError::from_sandbox_execute_error(other),
            }),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }

    /// 重命名/移动文件。
    pub fn rename(&mut self, _from: &str, _to: &str) -> Result<(), SdkError> {
        self.ensure_backend("/bin/test")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(_) => Err(os_file_operation_unsupported(
                "rename",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(_) => Err(os_file_operation_unsupported(
                "rename",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.rename(_from, _to).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.rename(_from, _to).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => {
                s.rename(_from, _to).map_err(map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => CoreSandbox::rename(s, _from, _to).map_err(|err| match err {
                SandboxError::Io(io_err) => SdkError::Io(io_err),
                other => SdkError::from_sandbox_execute_error(other),
            }),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }

    /// 返回文件元信息。
    pub fn stat(&mut self, _path: &str) -> Result<FileStat, SdkError> {
        self.ensure_backend("/bin/test")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(_) => Err(os_file_operation_unsupported(
                "stat",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(_) => Err(os_file_operation_unsupported(
                "stat",
                "Use microVM backend for isolated file operations",
            )),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.stat(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.stat(_path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => s.stat(_path).map_err(map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => CoreSandbox::stat(s, _path).map_err(|err| match err {
                SandboxError::Io(io_err) => SdkError::Io(io_err),
                other => SdkError::from_sandbox_execute_error(other),
            }),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }

    /// Reads file contents from the active sandbox backend.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, SdkError> {
        let _ = path;
        self.ensure_backend("/bin/cat")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(_) => Err(os_file_operation_unsupported(
                "read_file",
                "Use microVM backend for isolated file operations, or execute commands inside the sandbox to access files",
            )),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(_) => Err(os_file_operation_unsupported(
                "read_file",
                "Use microVM backend for isolated file operations, or execute commands inside the sandbox to access files",
            )),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.read_file(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.read_file(path).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => s.read_file(path).map_err(map_microvm_error),
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => read_file_via_core(s, path).map_err(map_core_file_error),
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }

    /// Writes file contents into the active sandbox backend.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), SdkError> {
        let _ = (path, data);
        self.ensure_backend("/bin/sh")?;
        let inner = self.require_inner()?;

        match inner {
            #[cfg(all(feature = "os", target_os = "linux"))]
            SandboxInner::Os(_) => Err(os_file_operation_unsupported(
                "write_file",
                "Use microVM backend for isolated file operations, or execute commands inside the sandbox to access files",
            )),
            #[cfg(all(feature = "os", target_os = "macos"))]
            SandboxInner::OsMac(_) => Err(os_file_operation_unsupported(
                "write_file",
                "Use microVM backend for isolated file operations, or execute commands inside the sandbox to access files",
            )),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::MicroVm(s) => s.write_file(path, data).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::PooledMicroVm(s) => s.write_file(path, data).map_err(map_microvm_error),
            #[cfg(all(feature = "vm", target_os = "linux"))]
            SandboxInner::RestoredPooledMicroVm(s) => {
                s.write_file(path, data).map_err(map_microvm_error)
            }
            #[cfg(feature = "wasm")]
            SandboxInner::Wasm(s) => {
                write_file_via_core(s, path, data).map_err(map_core_file_error)
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("no backend variant matched"),
        }
    }
}
