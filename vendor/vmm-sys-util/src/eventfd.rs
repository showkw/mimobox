//! 最小 `eventfd` 兼容实现。
//!
//! 该模块对齐 `vmm-sys-util::eventfd::EventFd` 的常用 API，
//! 满足 `mimobox-vm` 当前对事件通知原语的编译与运行需求。

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use libc::eventfd;

pub use libc::{EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};

/// Linux `eventfd` 的轻量封装。
#[derive(Debug)]
pub struct EventFd {
    eventfd: File,
}

impl EventFd {
    /// 创建新的 `eventfd`。
    pub fn new(flag: i32) -> Result<Self, io::Error> {
        // SAFETY: `eventfd` 不会解引用 Rust 指针；这里传入固定初始值 0，
        // 并在返回后校验文件描述符是否创建成功。
        let fd = unsafe { eventfd(0, flag) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            // SAFETY: `fd` 由内核成功返回，当前函数获得其唯一所有权。
            eventfd: unsafe { File::from_raw_fd(fd) },
        })
    }

    /// 向 `eventfd` 写入一个 64 位事件值。
    pub fn write(&self, value: u64) -> Result<(), io::Error> {
        (&self.eventfd).write_all(&value.to_ne_bytes())
    }

    /// 从 `eventfd` 读取一个 64 位事件值。
    pub fn read(&self) -> Result<u64, io::Error> {
        let mut buf = [0u8; std::mem::size_of::<u64>()];
        (&self.eventfd).read_exact(&mut buf)?;
        Ok(u64::from_ne_bytes(buf))
    }

    /// 克隆底层文件描述符，共享同一个内核计数器。
    pub fn try_clone(&self) -> Result<Self, io::Error> {
        Ok(Self {
            eventfd: self.eventfd.try_clone()?,
        })
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }
}

impl FromRawFd for EventFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            // SAFETY: 调用方保证 `fd` 有效且所有权已转移给当前对象。
            eventfd: unsafe { File::from_raw_fd(fd) },
        }
    }
}

impl IntoRawFd for EventFd {
    fn into_raw_fd(self) -> RawFd {
        self.eventfd.into_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::{EFD_NONBLOCK, EventFd};

    #[test]
    fn write_then_read_round_trip() {
        let event = EventFd::new(EFD_NONBLOCK).expect("创建 eventfd 必须成功");
        event.write(7).expect("写入 eventfd 必须成功");
        assert_eq!(event.read().expect("读取 eventfd 必须成功"), 7);
    }
}
