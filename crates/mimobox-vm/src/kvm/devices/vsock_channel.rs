#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::io::{Error, ErrorKind};
use std::mem;
use std::os::fd::RawFd;
use std::ptr;
use std::time::Duration;

use crate::vm::LifecycleError;
use crate::{GuestCommandResult, MicrovmError};

/// Linux AF_VSOCK address family constant.
const AF_VSOCK: libc::c_int = 40;
/// Fixed host-side CID.
const VMADDR_CID_HOST: u32 = 2;
/// Fixed host command channel port.
const COMMAND_PORT: u32 = 1024;
/// Maximum accepted payload for a single vsock stdout/stderr frame.
const MAX_VSOCK_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Listener backlog only needs to hold one guest connection.
const LISTEN_BACKLOG: libc::c_int = 1;
/// Established vsock streams block for at most 30 seconds; after timeout the upper
/// layer falls back to the serial protocol.
const STREAM_RECV_TIMEOUT_SECS: u64 = 30;
/// Uses the shell built-in no-op to verify that the vsock data plane can actually send and receive.
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

        // SAFETY: `self.fd` is a valid file descriptor exclusively owned by this object.
        // `drop` calls `close` exactly once to release kernel resources, so it cannot be
        // closed twice by another owner.
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
        let tv_sec = libc::time_t::try_from(timeout.as_secs()).map_err(|_| {
            MicrovmError::Backend(
                "vsock receive timeout seconds cannot be converted to time_t".into(),
            )
        })?;
        let tv_usec = libc::suseconds_t::from(timeout.subsec_micros());
        let timeout_value = libc::timeval { tv_sec, tv_usec };
        let timeout_len =
            libc::socklen_t::try_from(mem::size_of::<libc::timeval>()).map_err(|_| {
                MicrovmError::Backend("timeval length cannot be converted to socklen_t".into())
            })?;

        // SAFETY: `timeout_value` is a valid `timeval` on the current stack.
        // `setsockopt` only reads this structure synchronously, so there is no out-of-bounds
        // access or dangling reference.
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
                "failed to set vsock receive timeout: {}",
                Error::last_os_error()
            )));
        }

        Ok(())
    }

    fn read_exact(&self, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let mut offset = 0usize;
        while offset < buf.len() {
            // SAFETY: `buf[offset..]` is a writable slice on the current stack and Rust
            // guarantees its length. `read` only writes within the slice bounds.
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
                    "vsock peer closed early",
                )));
            }
            if read_bytes < 0 {
                let err = Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(MicrovmError::Io(err));
            }

            let chunk = usize::try_from(read_bytes).map_err(|_| {
                MicrovmError::Backend("vsock read length cannot be converted to usize".into())
            })?;
            offset += chunk;
        }

        Ok(())
    }

    fn write_all(&self, buf: &[u8]) -> Result<(), MicrovmError> {
        let mut offset = 0usize;
        while offset < buf.len() {
            // SAFETY: `buf[offset..]` is a valid read-only range of the current slice.
            // `write` only reads data from this range and does not modify Rust memory.
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
                    "vsock write returned 0",
                )));
            }
            if written_bytes < 0 {
                let err = Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(MicrovmError::Io(err));
            }

            let chunk = usize::try_from(written_bytes).map_err(|_| {
                MicrovmError::Backend("vsock write length cannot be converted to usize".into())
            })?;
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
        // SAFETY: `socket` only asks the kernel for an AF_VSOCK stream fd and does not
        // directly operate on Rust memory.
        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(MicrovmError::Backend(format!(
                "failed to create AF_VSOCK socket: {}",
                Error::last_os_error()
            )));
        }

        let listener = VsockFd::new(fd);
        let addr = SockAddrVm::host_command_addr();
        let addr_len = libc::socklen_t::try_from(mem::size_of::<SockAddrVm>()).map_err(|_| {
            MicrovmError::Backend("sockaddr_vm length cannot be converted to socklen_t".into())
        })?;

        // SAFETY: `addr` is a `sockaddr_vm` on the current stack with a layout matching
        // the kernel ABI. `listener` holds a valid fd, and `bind` only reads the address
        // structure synchronously.
        let bind_result = unsafe {
            libc::bind(
                listener.raw_fd(),
                ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                addr_len,
            )
        };
        if bind_result != 0 {
            return Err(MicrovmError::Backend(format!(
                "failed to bind host vsock listener address: {}",
                Error::last_os_error()
            )));
        }

        // SAFETY: `listener.raw_fd()` is a valid socket fd, and `listen` does not involve
        // Rust memory aliasing.
        let listen_result = unsafe { libc::listen(listener.raw_fd(), LISTEN_BACKLOG) };
        if listen_result != 0 {
            return Err(MicrovmError::Backend(format!(
                "failed to listen on host vsock port: {}",
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
            // SAFETY: `poll_fd` points to a one-element array on the current stack, and
            // `poll` only reads and writes that structure.
            let ready = unsafe { libc::poll(ptr::from_mut(&mut poll_fd), 1, timeout_ms) };
            if ready == 0 {
                return Err(MicrovmError::Io(Error::new(
                    ErrorKind::TimedOut,
                    "timed out waiting for guest vsock connection",
                )));
            }
            if ready < 0 {
                let err = Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(MicrovmError::Backend(format!(
                    "failed waiting for guest vsock connection: {err}"
                )));
            }
            break;
        }

        loop {
            let stream_fd = {
                // SAFETY: listener fd is valid. The peer address is not needed here, so null
                // pointers are acceptable.
                unsafe { libc::accept(self.listener.raw_fd(), ptr::null_mut(), ptr::null_mut()) }
            };
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
                "failed to accept guest vsock connection: {err}"
            )));
        }
    }

    pub(in crate::kvm) fn send_command(&self, cmd: &[u8]) -> Result<(), MicrovmError> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| MicrovmError::Lifecycle(LifecycleError::VsockNotConnected))?;
        let cmd_len = u32::try_from(cmd.len()).map_err(|_| {
            MicrovmError::InvalidConfig("vsock command length exceeds u32 limit".into())
        })?;

        stream.write_all(&cmd_len.to_be_bytes())?;
        stream.write_all(cmd)?;
        Ok(())
    }

    pub(in crate::kvm) fn recv_result(&self) -> Result<GuestCommandResult, MicrovmError> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| MicrovmError::Lifecycle(LifecycleError::VsockNotConnected))?;

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
            .ok_or_else(|| MicrovmError::Lifecycle(LifecycleError::VsockNotConnected))?;
        let default_timeout = Duration::from_secs(STREAM_RECV_TIMEOUT_SECS);

        stream.set_recv_timeout(timeout)?;

        let probe_result = self
            .send_command(PROBE_COMMAND)
            .and_then(|_| self.recv_result())
            .and_then(validate_probe_result);

        if let Err(err) = stream.set_recv_timeout(default_timeout)
            && probe_result.is_ok()
        {
            return Err(err);
        }

        probe_result
    }
}

fn read_length_prefixed_bytes(stream: &VsockStream) -> Result<Vec<u8>, MicrovmError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = usize::try_from(u32::from_be_bytes(len_buf)).map_err(|_| {
        MicrovmError::Backend("vsock frame length cannot be converted to usize".into())
    })?;
    if len > MAX_VSOCK_FRAME_BYTES {
        return Err(MicrovmError::Backend(format!(
            "vsock frame length exceeds limit: len={len}, max={MAX_VSOCK_FRAME_BYTES}"
        )));
    }

    let mut data = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut data)?;
    }
    Ok(data)
}

fn validate_probe_result(result: GuestCommandResult) -> Result<(), MicrovmError> {
    if result.exit_code != Some(0) {
        return Err(MicrovmError::Backend(format!(
            "vsock probe returned non-zero exit code: {:?}",
            result.exit_code
        )));
    }
    if !result.stdout.is_empty() || !result.stderr.is_empty() {
        return Err(MicrovmError::Backend(format!(
            "vsock probe should not produce output: stdout={}B stderr={}B",
            result.stdout.len(),
            result.stderr.len()
        )));
    }
    if result.timed_out {
        return Err(MicrovmError::Backend(
            "vsock probe was incorrectly marked as timed out".into(),
        ));
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
