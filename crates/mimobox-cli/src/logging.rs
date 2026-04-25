use std::fs::{self, File};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing_subscriber::{fmt::writer::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::capture::STDERR_LOGGING_ENABLED;
use crate::commands::CliError;

#[derive(Clone)]
pub(crate) struct SharedFileWriter {
    pub(crate) file: Arc<Mutex<File>>,
}

pub(crate) fn init_tracing() -> Result<(), CliError> {
    let log_dir = "logs";
    fs::create_dir_all(log_dir).map_err(|error| CliError::Logging(error.to_string()))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CliError::Logging(error.to_string()))?
        .as_secs();
    let log_path = format!("{log_dir}/mimobox-cli-{timestamp}.log");
    let file = File::options()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| CliError::Logging(error.to_string()))?;
    let file_writer = SharedFileWriter {
        file: Arc::new(Mutex::new(file)),
    };

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(ConditionalStderrWriter)
        .with_target(true);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(file_writer)
        .with_target(true);

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .try_init()
        .map_err(|error| CliError::Logging(error.to_string()))?;

    Ok(())
}

pub(crate) struct SharedFileGuard {
    pub(crate) file: Arc<Mutex<File>>,
}

#[derive(Clone, Copy)]
pub(crate) struct ConditionalStderrWriter;

pub(crate) struct ConditionalStderrGuard {
    muted: bool,
}

impl<'a> MakeWriter<'a> for SharedFileWriter {
    type Writer = SharedFileGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedFileGuard {
            file: Arc::clone(&self.file),
        }
    }
}

impl<'a> MakeWriter<'a> for ConditionalStderrWriter {
    type Writer = ConditionalStderrGuard;

    fn make_writer(&'a self) -> Self::Writer {
        let muted = STDERR_LOGGING_ENABLED.with(|flag| !flag.get());
        ConditionalStderrGuard { muted }
    }
}

impl Write for SharedFileGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;
        file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;
        file.flush()
    }
}

impl Write for ConditionalStderrGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.muted {
            Ok(buf.len())
        } else {
            io::stderr().write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.muted {
            Ok(())
        } else {
            io::stderr().flush()
        }
    }
}
