//! 最小 `vmm-sys-util` 兼容层。
//!
//! 当前任务只需要该 crate 能在离线环境中被解析和编译，
//! 因此仅保留非常小的占位 API。

pub mod errno {
    /// 与 `vmm-sys-util` 类似的轻量错误包装。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Error(pub i32);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod eventfd;
