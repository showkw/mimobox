//! 最小 `vm-memory` 兼容层。
//!
//! 该实现使用 `Vec<u8>` 模拟 guest memory，满足本次骨架的离线编译需求。

use std::fmt;
use std::sync::{Arc, Mutex};

/// Guest 物理地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GuestAddress(pub u64);

impl GuestAddress {
    pub fn raw_value(self) -> u64 {
        self.0
    }
}

/// 兼容层错误类型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// 字节读写 trait。
pub trait Bytes {
    fn write_slice(&self, buf: &[u8], addr: GuestAddress) -> Result<(), Error>;
    fn read_slice(&self, buf: &mut [u8], addr: GuestAddress) -> Result<(), Error>;
}

/// 使用内存向量模拟的 guest memory。
#[derive(Debug, Clone)]
pub struct GuestMemoryMmap {
    base: GuestAddress,
    len: usize,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl GuestMemoryMmap {
    pub fn from_ranges(ranges: &[(GuestAddress, usize)]) -> Result<Self, Error> {
        let Some((base, _)) = ranges.first().copied() else {
            return Err(Error::new("guest memory 范围不能为空"));
        };

        let mut expected = base.raw_value();
        let mut total_len = 0usize;
        for (addr, len) in ranges.iter().copied() {
            if addr.raw_value() != expected {
                return Err(Error::new("当前 shim 仅支持连续的 guest memory 范围"));
            }
            total_len = total_len
                .checked_add(len)
                .ok_or_else(|| Error::new("guest memory 长度溢出"))?;
            expected = expected
                .checked_add(len as u64)
                .ok_or_else(|| Error::new("guest memory 地址溢出"))?;
        }

        Ok(Self {
            base,
            len: total_len,
            bytes: Arc::new(Mutex::new(vec![0; total_len])),
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn dump(&self) -> Result<Vec<u8>, Error> {
        let bytes = self
            .bytes
            .lock()
            .map_err(|_| Error::new("guest memory 锁已损坏"))?;
        Ok(bytes.clone())
    }

    pub fn restore(&self, data: &[u8]) -> Result<(), Error> {
        if data.len() != self.len {
            return Err(Error::new(format!(
                "快照内存大小不匹配: 期望 {}，实际 {}",
                self.len,
                data.len()
            )));
        }

        let mut bytes = self
            .bytes
            .lock()
            .map_err(|_| Error::new("guest memory 锁已损坏"))?;
        bytes.copy_from_slice(data);
        Ok(())
    }

    fn checked_bounds(&self, addr: GuestAddress, len: usize) -> Result<usize, Error> {
        let start = addr
            .raw_value()
            .checked_sub(self.base.raw_value())
            .ok_or_else(|| Error::new("guest memory 地址落在基地址之前"))?
            as usize;
        let end = start
            .checked_add(len)
            .ok_or_else(|| Error::new("guest memory 访问长度溢出"))?;
        if end > self.len {
            return Err(Error::new("guest memory 越界访问"));
        }
        Ok(start)
    }
}

impl Bytes for GuestMemoryMmap {
    fn write_slice(&self, buf: &[u8], addr: GuestAddress) -> Result<(), Error> {
        let start = self.checked_bounds(addr, buf.len())?;
        let mut bytes = self
            .bytes
            .lock()
            .map_err(|_| Error::new("guest memory 锁已损坏"))?;
        bytes[start..start + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn read_slice(&self, buf: &mut [u8], addr: GuestAddress) -> Result<(), Error> {
        let start = self.checked_bounds(addr, buf.len())?;
        let bytes = self
            .bytes
            .lock()
            .map_err(|_| Error::new("guest memory 锁已损坏"))?;
        buf.copy_from_slice(&bytes[start..start + buf.len()]);
        Ok(())
    }
}
