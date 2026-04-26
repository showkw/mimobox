//! Shared PTY helpers for OS-level sandbox backends.
//!
//! This module allocates native pseudo terminals and adapts them to the
//! `mimobox-core` [`PtySession`] trait used by Linux and macOS backends.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use mimobox_core::{PtyConfig, PtyEvent, PtySession, PtySize as CorePtySize, SandboxError};
use portable_pty::{MasterPty, NativePtySystem, PtySystem};

/// Allocated native pseudo terminal resources.
///
/// The platform backend owns this value until the sandbox child process is
/// spawned, then passes it to [`build_session`] to create a managed PTY session.
pub(crate) struct AllocatedPty {
    /// Master PTY handle used for resizing and lifecycle ownership.
    pub(crate) master: Box<dyn MasterPty + Send>,
    /// Reader cloned from the master PTY for output forwarding.
    pub(crate) reader: Box<dyn Read + Send>,
    /// Writer connected to the master PTY for input forwarding.
    pub(crate) writer: Box<dyn Write + Send>,
    /// Filesystem path of the slave PTY device opened by the child process.
    pub(crate) slave_path: PathBuf,
}

/// Allocates a native pseudo terminal with the requested terminal size.
pub(crate) fn allocate_pty(size: CorePtySize) -> Result<AllocatedPty, SandboxError> {
    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(to_portable_size(size))
        .map_err(|error| SandboxError::ExecutionFailed(format!("failed to create PTY: {error}")))?;

    let slave_path = pair.master.tty_name().ok_or_else(|| {
        SandboxError::ExecutionFailed("current platform cannot resolve PTY slave path".to_string())
    })?;
    let reader = pair.master.try_clone_reader().map_err(|error| {
        SandboxError::ExecutionFailed(format!("failed to clone PTY reader: {error}"))
    })?;
    let writer = pair.master.take_writer().map_err(|error| {
        SandboxError::ExecutionFailed(format!("failed to take PTY writer: {error}"))
    })?;

    drop(pair.slave);

    Ok(AllocatedPty {
        master: pair.master,
        reader,
        writer,
        slave_path,
    })
}

/// Builds a boxed PTY session around an allocated PTY and child process.
///
/// The returned session owns the PTY master side and starts background threads
/// for output forwarding, child exit observation, and optional timeout cleanup.
pub(crate) fn build_session(
    allocated: AllocatedPty,
    child_pid: libc::pid_t,
    timeout: Option<Duration>,
) -> Box<dyn PtySession> {
    Box::new(OsPtySession::new(allocated, child_pid, timeout))
}

/// Builds the sanitized child environment used for PTY-backed commands.
///
/// The result starts from a minimal allowlist and then overlays variables from
/// [`PtyConfig::env`]. The `PWD` value follows [`PtyConfig::cwd`] when present
/// and defaults to `/tmp` otherwise.
pub(crate) fn build_child_env(config: &PtyConfig) -> HashMap<String, String> {
    let mut env = HashMap::from([
        (
            "PATH".to_string(),
            "/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
        ),
        ("HOME".to_string(), "/tmp".to_string()),
        ("TERM".to_string(), "xterm-256color".to_string()),
        ("USER".to_string(), "sandbox".to_string()),
        ("LOGNAME".to_string(), "sandbox".to_string()),
        ("SHELL".to_string(), "/bin/sh".to_string()),
        ("LANG".to_string(), "C".to_string()),
        ("TMPDIR".to_string(), "/tmp".to_string()),
        (
            "PWD".to_string(),
            config.cwd.clone().unwrap_or_else(|| "/tmp".to_string()),
        ),
    ]);

    for (key, value) in &config.env {
        env.insert(key.clone(), value.clone());
    }

    env
}

struct OsPtySession {
    child_pid: libc::pid_t,
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    output_rx: Receiver<PtyEvent>,
    exit_rx: Receiver<i32>,
    cached_exit_code: Option<i32>,
    exited: Arc<AtomicBool>,
}

impl OsPtySession {
    fn new(allocated: AllocatedPty, child_pid: libc::pid_t, timeout: Option<Duration>) -> Self {
        let (output_tx, output_rx) = mpsc::channel();
        let (exit_tx, exit_rx) = mpsc::channel();
        let exited = Arc::new(AtomicBool::new(false));

        spawn_reader_thread(allocated.reader, output_tx.clone());
        spawn_wait_thread(child_pid, output_tx, exit_tx, Arc::clone(&exited));

        if let Some(timeout) = timeout {
            spawn_timeout_thread(child_pid, timeout, Arc::clone(&exited));
        }

        Self {
            child_pid,
            master: allocated.master,
            writer: allocated.writer,
            output_rx,
            exit_rx,
            cached_exit_code: None,
            exited,
        }
    }

    fn wait_internal(&mut self) -> Result<i32, SandboxError> {
        if let Some(code) = self.cached_exit_code {
            return Ok(code);
        }

        let code = self.exit_rx.recv().map_err(|_| {
            SandboxError::ExecutionFailed("PTY exit event channel closed".to_string())
        })?;
        self.cached_exit_code = Some(code);
        Ok(code)
    }
}

impl PtySession for OsPtySession {
    fn send_input(&mut self, data: &[u8]) -> Result<(), SandboxError> {
        self.writer
            .write_all(data)
            .and_then(|_| self.writer.flush())
            .map_err(SandboxError::Io)
    }

    fn resize(&mut self, size: CorePtySize) -> Result<(), SandboxError> {
        self.master.resize(to_portable_size(size)).map_err(|error| {
            SandboxError::ExecutionFailed(format!("failed to resize PTY: {error}"))
        })
    }

    fn output_rx(&self) -> &Receiver<PtyEvent> {
        &self.output_rx
    }

    fn kill(&mut self) -> Result<(), SandboxError> {
        terminate_process_group(self.child_pid, &self.exited)
    }

    fn wait(&mut self) -> Result<i32, SandboxError> {
        self.wait_internal()
    }
}

impl Drop for OsPtySession {
    fn drop(&mut self) {
        if !self.exited.load(Ordering::SeqCst) {
            let _ = terminate_process_group(self.child_pid, &self.exited);
        }
    }
}

fn to_portable_size(size: CorePtySize) -> portable_pty::PtySize {
    portable_pty::PtySize {
        rows: size.rows,
        cols: size.cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn spawn_reader_thread(mut reader: Box<dyn Read + Send>, output_tx: mpsc::Sender<PtyEvent>) {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if output_tx
                        .send(PtyEvent::Output(buffer[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    tracing::debug!("PTY reader 退出: {error}");
                    break;
                }
            }
        }
    });
}

fn spawn_wait_thread(
    child_pid: libc::pid_t,
    output_tx: mpsc::Sender<PtyEvent>,
    exit_tx: mpsc::Sender<i32>,
    exited: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let exit_code = wait_for_child(child_pid).unwrap_or_else(|error| {
            tracing::warn!("等待 PTY 子进程退出失败: {error}");
            -1
        });
        exited.store(true, Ordering::SeqCst);
        let _ = output_tx.send(PtyEvent::Exit(exit_code));
        let _ = exit_tx.send(exit_code);
    });
}

fn spawn_timeout_thread(child_pid: libc::pid_t, timeout: Duration, exited: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        if exited.load(Ordering::SeqCst) {
            return;
        }

        let _ = send_signal_to_group(child_pid, libc::SIGTERM);
        std::thread::sleep(Duration::from_millis(150));
        if !exited.load(Ordering::SeqCst) {
            let _ = send_signal_to_group(child_pid, libc::SIGKILL);
        }
    });
}

fn wait_for_child(child_pid: libc::pid_t) -> Result<i32, SandboxError> {
    loop {
        let mut status = 0;
        // SAFETY: `child_pid` 来自成功创建的子进程，`status` 指向当前线程栈上的有效内存。
        let result = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SandboxError::ExecutionFailed(format!(
                "waitpid failed while waiting for PTY child process: {error}"
            )));
        }

        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(-(libc::WTERMSIG(status) as i32));
        }
    }
}

fn terminate_process_group(
    child_pid: libc::pid_t,
    exited: &AtomicBool,
) -> Result<(), SandboxError> {
    if exited.load(Ordering::SeqCst) {
        return Ok(());
    }

    send_signal_to_group(child_pid, libc::SIGTERM)?;
    std::thread::sleep(Duration::from_millis(150));
    if !exited.load(Ordering::SeqCst) && process_group_exists(child_pid) {
        send_signal_to_group(child_pid, libc::SIGKILL)?;
    }

    Ok(())
}

fn send_signal_to_group(child_pid: libc::pid_t, signal: libc::c_int) -> Result<(), SandboxError> {
    // SAFETY: 传入负 pid 表示向该进程组发信号；pid 由父进程保存且仅用于同一子进程组。
    let result = unsafe { libc::kill(-child_pid, signal) };
    if result == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }

    Err(SandboxError::ExecutionFailed(format!(
        "failed to send signal {signal} to PTY process group: {error}"
    )))
}

fn process_group_exists(child_pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 仅做存在性探测，不会真正发送信号。
    let result = unsafe { libc::kill(-child_pid, 0) };
    if result == 0 {
        return true;
    }

    let error = std::io::Error::last_os_error();
    error.raw_os_error() != Some(libc::ESRCH)
}
