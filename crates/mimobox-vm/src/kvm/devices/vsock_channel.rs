#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::io::{Error, ErrorKind};
use std::mem;
use std::os::fd::RawFd;
use std::ptr;
use std::time::Duration;

use crate::{GuestCommandResult, MicrovmError};

/// Linux AF_VSOCK 地址族常量。
const AF_VSOCK: libc::c_int = 40;
/// host 侧固定 CID。
const VMADDR_CID_HOST: u32 = 2;
/// host 命令通道固定端口。
const COMMAND_PORT: u32 = 1024;
/// listener backlog 只需要容纳单个 guest 连接。
const LISTEN_BACKLOG: libc::c_int = 1;
/// 已建立的 vsock 流最多阻塞 30 秒，超时后由上层回退串口协议。
const STREAM_RECV_TIMEOUT_SECS: u64 = 30;
/// 使用 shell 内建 no-op 验证 vsock 数据面是否真正可收发。
const PROBE_COMMAND: &[u8] = b":";

#[repr(C)]
struct SockAddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: libc::c_ushort,
    svm_port: libc::c_uint,
    svm_cid: libc::c_uint,
    svm_zero: [libc::c_uchar; 4],
}

impl SockAddrVm {
    fn host_command_addr() -> Self {
        Self {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: COMMAND_PORT,
            svm_cid: VMADDR_CID_HOST,
            svm_zero: [0; 4],
        }
    }
}

#[derive(Debug)]
struct VsockFd {
    fd: RawFd,
}

impl VsockFd {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for VsockFd {
    fn drop(&mut self) {
        if self.fd < 0 {
            return;
        }

        // SAFETY: `self.fd` 是当前对象独占持有的有效文件描述符。
        // drop 时仅调用一次 `close` 释放内核资源，不会与其他所有者重复关闭。
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[derive(Debug)]
struct VsockStream {
    fd: VsockFd,
}

impl VsockStream {
    fn new(fd: RawFd) -> Self {
        Self {
            fd: VsockFd::new(fd),
        }
    }

    fn set_recv_timeout(&self, timeout: Duration) -> Result<(), MicrovmError> {
        let tv_sec = libc::time_t::try_from(timeout.as_secs())
            .map_err(|_| MicrovmError::Backend("vsock 接收超时秒数无法转换为 time_t".into()))?;
        let tv_usec = libc::suseconds_t::try_from(timeout.subsec_micros()).map_err(|_| {
            MicrovmError::Backend("vsock 接收超时微秒数无法转换为 suseconds_t".into())
        })?;
        let timeout_value = libc::timeval { tv_sec, tv_usec };
        let timeout_len = libc::socklen_t::try_from(mem::size_of::<libc::timeval>())
            .map_err(|_| MicrovmError::Backend("timeval 长度无法转换为 socklen_t".into()))?;

        // SAFETY: `timeout_value` 是当前栈上有效的 `timeval`，
        // `setsockopt` 只同步读取该结构体，不会越界或悬垂引用。
        let result = unsafe {
            libc::setsockopt(
                self.fd.raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                ptr::from_ref(&timeout_value).cast::<libc::c_void>(),
                timeout_len,
            )
        };
        if result != 0 {
            return Err(MicrovmError::Backend(format!(
                "设置 vsock 接收超时失败: {}",
                Error::last_os_error()
            )));
        }

        Ok(())
    }

    fn read_exact(&self, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let mut offset = 0usize;
        while offset < buf.len() {
            // SAFETY: `buf[offset..]` 是当前栈上可写切片，长度由 Rust 保证；
            // `read` 只会写入该切片边界内的数据。
            let read_bytes = unsafe {
                libc::read(
                    self.fd.raw_fd(),
                    buf[offset..].as_mut_ptr().cast::<libc::c_void>(),
                    buf.len() - offset,
                )
            };
            if read_bytes == 0 {
                return Err(MicrovmError::Io(Error::new(
                    ErrorKind::UnexpectedEof,
                    "vsock 对端提前关闭",
                )));
            }
            if read_bytes < 0 {
                let err = Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(MicrovmError::Io(err));
            }

            let chunk = usize::try_from(read_bytes)
                .map_err(|_| MicrovmError::Backend("vsock 读取长度无法转换为 usize".into()))?;
            offset += chunk;
        }

        Ok(())
    }

    fn write_all(&self, buf: &[u8]) -> Result<(), MicrovmError> {
        let mut offset = 0usize;
        while offset < buf.len() {
            // SAFETY: `buf[offset..]` 是当前切片的有效只读范围，
            // `write` 只会读取该范围内的数据，不会修改 Rust 内存。
            let written_bytes = unsafe {
                libc::write(
                    self.fd.raw_fd(),
                    buf[offset..].as_ptr().cast::<libc::c_void>(),
                    buf.len() - offset,
                )
            };
            if written_bytes == 0 {
                return Err(MicrovmError::Io(Error::new(
                    ErrorKind::WriteZero,
                    "vsock 写入返回 0",
                )));
            }
            if written_bytes < 0 {
                let err = Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(MicrovmError::Io(err));
            }

            let chunk = usize::try_from(written_bytes)
                .map_err(|_| MicrovmError::Backend("vsock 写入长度无法转换为 usize".into()))?;
            offset += chunk;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(in crate::kvm) struct VsockCommandChannel {
    listener: VsockFd,
    stream: Option<VsockStream>,
}

impl VsockCommandChannel {
    pub(in crate::kvm) fn new() -> Result<Self, MicrovmError> {
        // SAFETY: `socket` 仅向内核申请一个 AF_VSOCK stream fd，不直接操作 Rust 内存。
        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(MicrovmError::Backend(format!(
                "创建 AF_VSOCK socket 失败: {}",
                Error::last_os_error()
            )));
        }

        let listener = VsockFd::new(fd);
        let addr = SockAddrVm::host_command_addr();
        let addr_len = libc::socklen_t::try_from(mem::size_of::<SockAddrVm>())
            .map_err(|_| MicrovmError::Backend("sockaddr_vm 长度无法转换为 socklen_t".into()))?;

        // SAFETY: `addr` 是当前栈上的 `sockaddr_vm`，布局与内核 ABI 对齐；
        // `listener` 持有有效 fd，`bind` 仅同步读取地址结构体。
        let bind_result = unsafe {
            libc::bind(
                listener.raw_fd(),
                ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                addr_len,
            )
        };
        if bind_result != 0 {
            return Err(MicrovmError::Backend(format!(
                "绑定 host vsock 监听地址失败: {}",
                Error::last_os_error()
            )));
        }

        // SAFETY: `listener.raw_fd()` 是有效 socket fd，`listen` 不涉及 Rust 内存别名问题。
        let listen_result = unsafe { libc::listen(listener.raw_fd(), LISTEN_BACKLOG) };
        if listen_result != 0 {
            return Err(MicrovmError::Backend(format!(
                "监听 host vsock 端口失败: {}",
                Error::last_os_error()
            )));
        }

        Ok(Self {
            listener,
            stream: None,
        })
    }

    pub(in crate::kvm) fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub(in crate::kvm) fn accept_connection(
        &mut self,
        timeout: Duration,
    ) -> Result<(), MicrovmError> {
        if self.stream.is_some() {
            return Ok(());
        }

        let timeout_ms = duration_to_poll_timeout_ms(timeout);
        let mut poll_fd = libc::pollfd {
            fd: self.listener.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        loop {
            // SAFETY: `poll_fd` 指向当前栈上单元素数组，长度为 1，`poll` 只会读写该结构体。
            let ready = unsafe { libc::poll(ptr::from_mut(&mut poll_fd), 1, timeout_ms) };
            if ready == 0 {
                return Err(MicrovmError::Io(Error::new(
                    ErrorKind::TimedOut,
                    "等待 guest vsock 连接超时",
                )));
            }
            if ready < 0 {
                let err = Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(MicrovmError::Backend(format!(
                    "等待 guest vsock 连接失败: {err}"
                )));
            }
            break;
        }

        loop {
            // SAFETY: listener fd 有效；当前不关心 peer 地址，因此传空指针即可。
            let stream_fd =
                unsafe { libc::accept(self.listener.raw_fd(), ptr::null_mut(), ptr::null_mut()) };
            if stream_fd >= 0 {
                let stream = VsockStream::new(stream_fd);
                stream.set_recv_timeout(Duration::from_secs(STREAM_RECV_TIMEOUT_SECS))?;
                self.stream = Some(stream);
                return Ok(());
            }

            let err = Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(MicrovmError::Backend(format!(
                "accept guest vsock 连接失败: {err}"
            )));
        }
    }

    pub(in crate::kvm) fn send_command(&self, cmd: &[u8]) -> Result<(), MicrovmError> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| MicrovmError::Lifecycle("vsock 命令通道尚未建立连接".into()))?;
        let cmd_len = u32::try_from(cmd.len())
            .map_err(|_| MicrovmError::InvalidConfig("vsock 命令长度超过 u32 上限".into()))?;

        stream.write_all(&cmd_len.to_be_bytes())?;
        stream.write_all(cmd)?;
        Ok(())
    }

    pub(in crate::kvm) fn recv_result(&self) -> Result<GuestCommandResult, MicrovmError> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| MicrovmError::Lifecycle("vsock 命令通道尚未建立连接".into()))?;

        let stdout = read_length_prefixed_bytes(stream)?;
        let stderr = read_length_prefixed_bytes(stream)?;

        let mut exit_code = [0u8; 1];
        stream.read_exact(&mut exit_code)?;

        Ok(GuestCommandResult {
            stdout,
            stderr,
            exit_code: Some(i32::from(exit_code[0])),
            timed_out: false,
        })
    }

    pub(in crate::kvm) fn probe_round_trip(&self, timeout: Duration) -> Result<(), MicrovmError> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| MicrovmError::Lifecycle("vsock 命令通道尚未建立连接".into()))?;
        let default_timeout = Duration::from_secs(STREAM_RECV_TIMEOUT_SECS);

        stream.set_recv_timeout(timeout)?;

        let probe_result = self
            .send_command(PROBE_COMMAND)
            .and_then(|_| self.recv_result())
            .and_then(validate_probe_result);

        if let Err(err) = stream.set_recv_timeout(default_timeout) {
            if probe_result.is_ok() {
                return Err(err);
            }
        }

        probe_result
    }
}

fn read_length_prefixed_bytes(stream: &VsockStream) -> Result<Vec<u8>, MicrovmError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = usize::try_from(u32::from_be_bytes(len_buf))
        .map_err(|_| MicrovmError::Backend("vsock 帧长度无法转换为 usize".into()))?;

    let mut data = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut data)?;
    }
    Ok(data)
}

fn validate_probe_result(result: GuestCommandResult) -> Result<(), MicrovmError> {
    if result.exit_code != Some(0) {
        return Err(MicrovmError::Backend(format!(
            "vsock 探针返回了非零退出码: {:?}",
            result.exit_code
        )));
    }
    if !result.stdout.is_empty() || !result.stderr.is_empty() {
        return Err(MicrovmError::Backend(format!(
            "vsock 探针不应产生输出: stdout={}B stderr={}B",
            result.stdout.len(),
            result.stderr.len()
        )));
    }
    if result.timed_out {
        return Err(MicrovmError::Backend("vsock 探针被错误标记为超时".into()));
    }

    Ok(())
}

fn duration_to_poll_timeout_ms(timeout: Duration) -> libc::c_int {
    let timeout_ms = timeout.as_millis();
    let max_timeout = i32::MAX as u128;
    if timeout_ms > max_timeout {
        i32::MAX
    } else {
        timeout_ms as libc::c_int
    }
}
