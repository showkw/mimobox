#[cfg(unix)]
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::time::Duration;

use mimobox_sdk::{
    Config as SdkConfig, IsolationLevel as SdkIsolationLevel, PtyConfig as SdkPtyConfig,
    PtyEvent as SdkPtyEvent, PtySize as SdkPtySize, Sandbox as SdkSandbox,
};
use tracing::{info, warn};

use super::*;

#[cfg(unix)]
pub(crate) static SHELL_SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
pub(crate) static SHELL_SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

pub(crate) fn handle_shell(args: ShellArgs) -> Result<i32, CliError> {
    #[cfg(not(unix))]
    {
        let _ = args;
        return Err(CliError::Sdk(
            "shell subcommand only supports Unix terminal environments".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        let deny_network = resolve_shell_deny_network(&args);
        let sdk_config = build_shell_sdk_config(&args, deny_network);
        let pty_config = SdkPtyConfig {
            command: parse_command(&args.command)?,
            size: current_terminal_size().unwrap_or_default(),
            env: std::collections::HashMap::new(),
            cwd: None,
            timeout: sdk_config.timeout,
        };

        info!(
            backend = ?args.backend,
            command = %args.command,
            timeout_secs = sdk_config.timeout.as_ref().map(Duration::as_secs),
            deny_network,
            "preparing to execute shell subcommand"
        );

        install_shell_signal_handlers();

        let mut sandbox = SdkSandbox::with_config(sdk_config).map_err(map_sdk_error)?;
        let mut session = match sandbox.create_pty_with_config(pty_config) {
            Ok(session) => session,
            Err(error) => {
                if let Err(destroy_error) = sandbox.destroy() {
                    warn!(message = %destroy_error, "failed to destroy sandbox after shell initialization failure");
                }
                return Err(map_sdk_error(error));
            }
        };

        let shell_result = run_shell_session(&mut session);
        drop(session);

        if let Err(destroy_error) = sandbox.destroy() {
            warn!(message = %destroy_error, "failed to destroy sandbox after shell session");
        }

        shell_result
    }
}

pub(crate) fn build_shell_sdk_config(args: &ShellArgs, deny_network: bool) -> SdkConfig {
    let mut config = build_sdk_config(args.memory, args.timeout, deny_network, true);
    config.isolation = backend_to_sdk_isolation(args.backend);
    config
}

fn backend_to_sdk_isolation(backend: Backend) -> SdkIsolationLevel {
    match backend {
        Backend::Auto => SdkIsolationLevel::Auto,
        Backend::Os => SdkIsolationLevel::Os,
        Backend::Wasm => SdkIsolationLevel::Wasm,
        Backend::Kvm => SdkIsolationLevel::MicroVm,
    }
}

fn resolve_shell_deny_network(args: &ShellArgs) -> bool {
    !args.allow_network
}

#[cfg(unix)]
pub(crate) fn run_shell_session(session: &mut mimobox_sdk::PtySession) -> Result<i32, CliError> {
    let (input_tx, input_rx) = mpsc::channel();
    spawn_stdin_forwarder(input_tx);

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut exit_code = None;

    loop {
        while let Ok(data) = input_rx.try_recv() {
            session.send_input(&data).map_err(map_sdk_error)?;
        }

        if shell_sigint_received() {
            session.kill().map_err(map_sdk_error)?;
        }

        if shell_sigwinch_received()
            && let Some(size) = current_terminal_size()
        {
            session
                .resize(size.cols, size.rows)
                .map_err(map_sdk_error)?;
        }

        match session.output().recv_timeout(Duration::from_millis(50)) {
            Ok(SdkPtyEvent::Output(data)) => {
                stdout.write_all(&data)?;
                stdout.flush()?;
            }
            Ok(SdkPtyEvent::Exit(code)) => {
                exit_code = Some(code);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    match exit_code {
        Some(code) => session.wait().map_err(map_sdk_error).or(Ok(code)),
        None => session.wait().map_err(map_sdk_error),
    }
}

#[cfg(unix)]
pub(crate) fn spawn_stdin_forwarder(input_tx: mpsc::Sender<Vec<u8>>) {
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let mut buffer = [0_u8; 1024];

        loop {
            match stdin.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if input_tx.send(buffer[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    warn!(message = %error, "failed to read local stdin, stopping input forwarding");
                    break;
                }
            }
        }
    });
}

#[cfg(unix)]
pub(crate) fn current_terminal_size() -> Option<SdkPtySize> {
    // SAFETY: `winsize` is allocated on this stack frame, and `ioctl` only writes to this struct.
    let mut winsize = unsafe { std::mem::zeroed::<libc::winsize>() };
    // SAFETY: `STDOUT_FILENO` is the current process stdout fd; `ioctl` returns an error if it is not a terminal.
    let result = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut winsize) };
    if result != 0 || winsize.ws_col == 0 || winsize.ws_row == 0 {
        return None;
    }

    Some(SdkPtySize {
        cols: winsize.ws_col,
        rows: winsize.ws_row,
    })
}

#[cfg(unix)]
pub(crate) fn install_shell_signal_handlers() {
    SHELL_SIGINT_RECEIVED.store(false, Ordering::SeqCst);
    SHELL_SIGWINCH_RECEIVED.store(false, Ordering::SeqCst);

    // SAFETY: Installs a simple signal handler for the current CLI process; it only writes an atomic flag and performs no async-signal-unsafe operations.
    unsafe {
        libc::signal(
            libc::SIGINT,
            shell_sigint_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGWINCH,
            shell_sigwinch_handler as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(unix)]
pub(crate) fn shell_sigint_received() -> bool {
    SHELL_SIGINT_RECEIVED.swap(false, Ordering::SeqCst)
}

#[cfg(unix)]
pub(crate) fn shell_sigwinch_received() -> bool {
    SHELL_SIGWINCH_RECEIVED.swap(false, Ordering::SeqCst)
}

#[cfg(unix)]
pub(crate) extern "C" fn shell_sigint_handler(_: libc::c_int) {
    SHELL_SIGINT_RECEIVED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
pub(crate) extern "C" fn shell_sigwinch_handler(_: libc::c_int) {
    SHELL_SIGWINCH_RECEIVED.store(true, Ordering::SeqCst);
}
