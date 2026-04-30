//! Shared PTY helpers for OS-level sandbox backends.
//!
//! This module allocates native pseudo terminals and adapts them to the
//! `mimobox-core` [`PtySession`] trait used by Linux and macOS backends.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
        .map_err(|error| SandboxError::new(format!("failed to create PTY: {error}")))?;

    let slave_path = pair
        .master
        .tty_name()
        .ok_or_else(|| SandboxError::new("current platform cannot resolve PTY slave path"))?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| SandboxError::new(format!("failed to clone PTY reader: {error}")))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|error| SandboxError::new(format!("failed to take PTY writer: {error}")))?;

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
    cleanup: Option<PtyCleanup>,
) -> Box<dyn PtySession> {
    Box::new(OsPtySession::new(allocated, child_pid, timeout, cleanup))
}

pub(crate) type PtyCleanup = Box<dyn FnOnce() + Send + 'static>;

/// 构建 PTY 子进程使用的净化环境变量集合。
///
/// 合并顺序为：内置最小环境、沙箱级持久环境变量、[`PtyConfig::env`]。
/// `PWD` 默认跟随 [`PtyConfig::cwd`]，未设置时回退到 `/tmp`。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn build_child_env_with_base(
    config: &PtyConfig,
    base_env: &HashMap<String, String>,
) -> HashMap<String, String> {
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

    for (key, value) in base_env {
        env.insert(key.clone(), value.clone());
    }

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
    exit_rx: Receiver<PtyExitStatus>,
    cached_exit_status: Option<PtyExitStatus>,
    exited: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
    started_at: Instant,
    timeout: Option<Duration>,
    cleanup: Mutex<Option<PtyCleanup>>,
}

#[derive(Clone, Copy)]
struct PtyExitStatus {
    code: i32,
    /// 等待线程观察到退出事件的耗时，用于关闭超时线程标记竞态窗口。
    elapsed: Duration,
}

impl OsPtySession {
    fn new(
        allocated: AllocatedPty,
        child_pid: libc::pid_t,
        timeout: Option<Duration>,
        cleanup: Option<PtyCleanup>,
    ) -> Self {
        let (output_tx, output_rx) = mpsc::channel();
        let (exit_tx, exit_rx) = mpsc::channel();
        let exited = Arc::new(AtomicBool::new(false));
        let timed_out = Arc::new(AtomicBool::new(false));
        let started_at = Instant::now();

        spawn_reader_thread(allocated.reader, output_tx.clone());
        spawn_wait_thread(
            child_pid,
            output_tx,
            exit_tx,
            Arc::clone(&exited),
            started_at,
        );

        if let Some(timeout) = timeout {
            spawn_timeout_thread(
                child_pid,
                timeout,
                Arc::clone(&exited),
                Arc::clone(&timed_out),
            );
        }

        Self {
            child_pid,
            master: allocated.master,
            writer: allocated.writer,
            output_rx,
            exit_rx,
            cached_exit_status: None,
            exited,
            timed_out,
            started_at,
            timeout,
            cleanup: Mutex::new(cleanup),
        }
    }

    fn wait_internal(&mut self) -> Result<i32, SandboxError> {
        if let Some(status) = self.cached_exit_status {
            if self.is_timeout_status(status) {
                self.run_cleanup();
                return Err(SandboxError::Timeout);
            }
            return Ok(status.code);
        }

        let status = match self.recv_exit_status() {
            Ok(status) => status,
            Err(error) => {
                self.run_cleanup();
                return Err(error);
            }
        };
        self.cached_exit_status = Some(status);
        self.run_cleanup();
        if self.is_timeout_status(status) {
            return Err(SandboxError::Timeout);
        }
        Ok(status.code)
    }

    fn recv_exit_status(&self) -> Result<PtyExitStatus, SandboxError> {
        let Some(timeout) = self.timeout else {
            return self
                .exit_rx
                .recv()
                .map_err(|_| SandboxError::new("PTY exit event channel closed"));
        };

        let elapsed = self.started_at.elapsed();
        let remaining = timeout.checked_sub(elapsed).unwrap_or(Duration::ZERO);
        match self.exit_rx.recv_timeout(remaining) {
            Ok(status) => Ok(status),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.mark_timed_out_and_terminate();
                self.exit_rx
                    .recv()
                    .map_err(|_| SandboxError::new("PTY exit event channel closed after timeout"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(SandboxError::new("PTY exit event channel closed"))
            }
        }
    }

    fn is_timeout_status(&self, status: PtyExitStatus) -> bool {
        if self.timed_out.load(Ordering::SeqCst) {
            return true;
        }

        if self
            .timeout
            .is_some_and(|timeout| status.elapsed >= timeout)
        {
            self.timed_out.store(true, Ordering::SeqCst);
            return true;
        }

        false
    }

    fn mark_timed_out_and_terminate(&self) {
        if self.timed_out.swap(true, Ordering::SeqCst) {
            return;
        }

        if let Err(error) = terminate_process_group(self.child_pid, &self.exited) {
            tracing::warn!("Failed to terminate PTY process group after timeout: {error}");
        }
    }

    fn run_cleanup(&self) {
        let Ok(mut cleanup) = self.cleanup.lock() else {
            tracing::warn!("PTY cleanup mutex poisoned; skipping cleanup callback");
            return;
        };
        if let Some(cleanup) = cleanup.take() {
            cleanup();
        }
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
        self.master
            .resize(to_portable_size(size))
            .map_err(|error| SandboxError::new(format!("failed to resize PTY: {error}")))
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
        self.run_cleanup();
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

const PTY_OUTPUT_SIZE_LIMIT: usize = 4 * 1024 * 1024;

fn spawn_reader_thread(mut reader: Box<dyn Read + Send>, output_tx: mpsc::Sender<PtyEvent>) {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        let mut total_bytes: usize = 0;
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
                    total_bytes += n;
                    if total_bytes >= PTY_OUTPUT_SIZE_LIMIT {
                        let _ = output_tx.send(PtyEvent::Output(
                            b"\n[mimobox] PTY output exceeded 4MB limit, truncated\n".to_vec(),
                        ));
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    tracing::debug!("PTY reader exited: {error}");
                    break;
                }
            }
        }
    });
}

fn spawn_wait_thread(
    child_pid: libc::pid_t,
    output_tx: mpsc::Sender<PtyEvent>,
    exit_tx: mpsc::Sender<PtyExitStatus>,
    exited: Arc<AtomicBool>,
    started_at: Instant,
) {
    std::thread::spawn(move || {
        let exit_code = wait_for_child(child_pid).unwrap_or_else(|error| {
            tracing::warn!("Failed to wait for PTY child process: {error}");
            -1
        });
        let status = PtyExitStatus {
            code: exit_code,
            elapsed: started_at.elapsed(),
        };
        exited.store(true, Ordering::SeqCst);
        let _ = output_tx.send(PtyEvent::Exit(exit_code));
        let _ = exit_tx.send(status);
    });
}

fn spawn_timeout_thread(
    child_pid: libc::pid_t,
    timeout: Duration,
    exited: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        if exited.load(Ordering::SeqCst) {
            return;
        }

        timed_out.store(true, Ordering::SeqCst);
        let _ = send_signal_to_child_tree(child_pid, libc::SIGTERM);
        std::thread::sleep(Duration::from_millis(150));
        if !exited.load(Ordering::SeqCst) {
            let _ = send_signal_to_child_tree(child_pid, libc::SIGKILL);
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
            return Err(SandboxError::new(format!(
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

    send_signal_to_child_tree(child_pid, libc::SIGTERM)?;
    std::thread::sleep(Duration::from_millis(150));
    if !exited.load(Ordering::SeqCst) {
        send_signal_to_child_tree(child_pid, libc::SIGKILL)?;
    }

    Ok(())
}

fn send_signal_to_child_tree(
    child_pid: libc::pid_t,
    signal: libc::c_int,
) -> Result<(), SandboxError> {
    // SAFETY: 传入负 pid 表示向该进程组发信号；pid 由父进程保存且仅用于同一子进程组。
    let result = unsafe { libc::kill(-child_pid, signal) };
    if result == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return send_signal_to_process(child_pid, signal);
    }

    Err(SandboxError::new(format!(
        "failed to send signal {signal} to PTY process group: {error}"
    )))
}

fn send_signal_to_process(child_pid: libc::pid_t, signal: libc::c_int) -> Result<(), SandboxError> {
    // SAFETY: child_pid 来自成功 spawn/fork 的子进程；ESRCH 表示进程已退出，按幂等清理处理。
    let result = unsafe { libc::kill(child_pid, signal) };
    if result == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }

    Err(SandboxError::new(format!(
        "failed to send signal {signal} to PTY process: {error}"
    )))
}
