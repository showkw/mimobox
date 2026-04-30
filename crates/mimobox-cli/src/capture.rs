use std::cell::Cell;
use std::fs::File;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

use crate::commands::CliError;

thread_local! {
    /// Temporarily disable terminal logging when capturing process-level stderr, to avoid log output polluting fallback output.
    pub(crate) static STDERR_LOGGING_ENABLED: Cell<bool> = const { Cell::new(true) };
}
#[cfg(unix)]
/// Provides the capture benchmark output operation.
pub(crate) fn capture_benchmark_output<F>(run: F) -> Result<String, CliError>
where
    F: FnOnce() -> Result<(), CliError>,
{
    let (result, output) = capture_fd_output(libc::STDOUT_FILENO, run)?;
    result?;
    String::from_utf8(output).map_err(|error| {
        CliError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("captured stdout is not valid UTF-8: {error}"),
        ))
    })
}

#[cfg(not(unix))]
/// Provides the capture benchmark output operation.
pub(crate) fn capture_benchmark_output<F>(_run: F) -> Result<String, CliError>
where
    F: FnOnce() -> Result<(), CliError>,
{
    Err(CliError::BenchUnsupported)
}

#[cfg(unix)]
/// Provides the capture stderr bytes operation.
pub(crate) fn capture_stderr_bytes<F, T>(run: F) -> Result<(T, Vec<u8>), CliError>
where
    F: FnOnce() -> T,
{
    capture_fd_output(libc::STDERR_FILENO, run)
}

#[cfg(not(unix))]
/// Provides the capture stderr bytes operation.
pub(crate) fn capture_stderr_bytes<F, T>(run: F) -> Result<(T, Vec<u8>), CliError>
where
    F: FnOnce() -> T,
{
    Ok((run(), Vec::new()))
}

#[cfg(unix)]
/// Provides the capture fd output operation.
pub(crate) fn capture_fd_output<F, T>(
    target_fd: libc::c_int,
    run: F,
) -> Result<(T, Vec<u8>), CliError>
where
    F: FnOnce() -> T,
{
    let _capture_guard = fd_capture_lock()
        .lock()
        .map_err(|_| CliError::Io(io::Error::other("fd capture lock poisoned")))?;
    let mut capture = FdCapture::start(target_fd)?;
    let outcome = if target_fd == libc::STDERR_FILENO {
        let _guard = StderrLoggingGuard::suspend();
        run()
    } else {
        run()
    };
    let output = capture.finish()?;
    Ok((outcome, output))
}

#[cfg(unix)]
/// Provides the fd capture lock operation.
pub(crate) fn fd_capture_lock() -> &'static Mutex<()> {
    static FD_CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    FD_CAPTURE_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(unix)]
pub(crate) struct FdCapture {
    target_fd: libc::c_int,
    saved_fd: Option<OwnedFd>,
    read_file: Option<File>,
}

#[cfg(unix)]
impl FdCapture {
    fn start(target_fd: libc::c_int) -> Result<Self, CliError> {
        flush_standard_fd(target_fd)?;

        let mut pipe_fds = [-1; 2];
        // SAFETY: `pipe_fds` points to two valid `c_int` slots; `pipe` writes the read and write ends on success.
        let pipe_result = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        if pipe_result != 0 {
            return Err(CliError::Io(io::Error::last_os_error()));
        }

        // SAFETY: Ownership of fds returned by `pipe` is transferred to `File` / `OwnedFd` exactly once.
        let read_file = unsafe { File::from_raw_fd(pipe_fds[0]) };
        // SAFETY: Ownership of fds returned by `pipe` is transferred to `OwnedFd` exactly once.
        let write_fd = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        // SAFETY: `dup` duplicates the current target fd and returns a new independent fd.
        let saved_fd_raw = unsafe { libc::dup(target_fd) };
        if saved_fd_raw < 0 {
            return Err(CliError::Io(io::Error::last_os_error()));
        }
        // SAFETY: The fd returned by successful `dup` is transferred here to exclusive `OwnedFd` ownership.
        let saved_fd = unsafe { OwnedFd::from_raw_fd(saved_fd_raw) };

        // SAFETY: Redirects the target fd to the pipe write end. Both fds are valid open descriptors in this process.
        let dup_result = unsafe { libc::dup2(write_fd.as_raw_fd(), target_fd) };
        if dup_result < 0 {
            return Err(CliError::Io(io::Error::last_os_error()));
        }

        Ok(Self {
            target_fd,
            saved_fd: Some(saved_fd),
            read_file: Some(read_file),
        })
    }

    fn finish(&mut self) -> Result<Vec<u8>, CliError> {
        self.restore()?;

        let mut output = Vec::new();
        if let Some(read_file) = self.read_file.as_mut() {
            read_file.read_to_end(&mut output)?;
        }
        Ok(output)
    }

    fn restore(&mut self) -> Result<(), CliError> {
        flush_standard_fd(self.target_fd)?;

        if let Some(saved_fd) = self.saved_fd.as_ref() {
            // SAFETY: `saved_fd` is a valid fd duplicated earlier via `dup`, so it can safely restore the original standard stream.
            let restore_result = unsafe { libc::dup2(saved_fd.as_raw_fd(), self.target_fd) };
            if restore_result < 0 {
                return Err(CliError::Io(io::Error::last_os_error()));
            }
        }

        self.saved_fd = None;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for FdCapture {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(unix)]
/// Provides the flush standard fd operation.
pub(crate) fn flush_standard_fd(target_fd: libc::c_int) -> Result<(), CliError> {
    match target_fd {
        libc::STDOUT_FILENO => io::stdout().flush()?,
        libc::STDERR_FILENO => io::stderr().flush()?,
        _ => {}
    }
    Ok(())
}
pub(crate) struct StderrLoggingGuard {
    previous: bool,
}

impl StderrLoggingGuard {
    /// Provides the suspend operation.
    pub(crate) fn suspend() -> Self {
        let previous = STDERR_LOGGING_ENABLED.with(|flag| flag.replace(false));
        Self { previous }
    }
}

impl Drop for StderrLoggingGuard {
    fn drop(&mut self) {
        STDERR_LOGGING_ENABLED.with(|flag| flag.set(self.previous));
    }
}
