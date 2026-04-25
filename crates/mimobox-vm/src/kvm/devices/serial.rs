#![cfg(all(target_os = "linux", feature = "kvm"))]

use super::*;
use crate::http_proxy::HttpRequest;
use serde::Serialize;
use std::collections::HashMap;

pub(super) const SERIAL_PORT_COM1: u16 = 0x3f8;
pub(super) const SERIAL_PORT_LAST: u16 = SERIAL_PORT_COM1 + 7;
pub(super) const PIC_MASTER_COMMAND_REG: u16 = 0x20;
pub(super) const PIC_MASTER_DATA_REG: u16 = 0x21;
pub(super) const PIT_CHANNEL0_DATA_REG: u16 = 0x40;
pub(super) const PIT_MODE_COMMAND_REG: u16 = 0x43;
pub(in crate::kvm) const I8042_PORT_B_REG: u16 = 0x61;
pub(in crate::kvm) const I8042_COMMAND_REG: u16 = 0x64;
pub(in crate::kvm) const I8042_PORT_B_PIT_TICK: u8 = 0x20;
pub(in crate::kvm) const I8042_RESET_CMD: u8 = 0xfe;
pub(super) const RTC_INDEX_REG: u16 = 0x70;
pub(super) const RTC_DATA_REG: u16 = 0x71;
pub(super) const PIC_SLAVE_COMMAND_REG: u16 = 0xa0;
pub(super) const PIC_SLAVE_DATA_REG: u16 = 0xa1;
pub(in crate::kvm) const PCI_CONFIG_ADDRESS_REG: u16 = 0xcf8;
pub(in crate::kvm) const PCI_CONFIG_DATA_REG_START: u16 = 0xcfc;
pub(in crate::kvm) const PCI_CONFIG_DATA_REG_END: u16 = 0xcff;
pub(super) const UART_REG_DATA: u16 = 0;
pub(super) const UART_REG_INTERRUPT_ENABLE: u16 = 1;
pub(super) const UART_REG_INTERRUPT_IDENT: u16 = 2;
pub(super) const UART_REG_LINE_CONTROL: u16 = 3;
pub(super) const UART_REG_MODEM_CONTROL: u16 = 4;
pub(super) const UART_REG_LINE_STATUS: u16 = 5;
pub(super) const UART_REG_MODEM_STATUS: u16 = 6;
pub(super) const UART_REG_SCRATCH: u16 = 7;
pub(super) const UART_LCR_DLAB: u8 = 0x80;
pub(super) const UART_LSR_DATA_READY: u8 = 0x01;
pub(super) const UART_LSR_THR_EMPTY: u8 = 0x20;
pub(super) const UART_LSR_TRANSMITTER_EMPTY: u8 = 0x40;
pub(in crate::kvm) const SERIAL_READY_LINE: &str = "READY";
pub(in crate::kvm) const SERIAL_PING_PREFIX: &str = "PING";
pub(in crate::kvm) const SERIAL_PONG_LINE: &str = "PONG";
pub(in crate::kvm) const SERIAL_EXEC_PREFIX: &str = "EXEC:";
#[allow(dead_code)] // Phase A 先落常量与解析，Phase B 再接 host 发送路径。
pub(in crate::kvm) const SERIAL_EXECS_PREFIX: &str = "EXECS:";
#[allow(dead_code)] // 当前仅预留 kill 协议帧，后续再接 host 主动信号发送。
pub(in crate::kvm) const SERIAL_SIGNAL_KILL_PREFIX: &str = "SIGNAL:KILL:";
pub(in crate::kvm) const SERIAL_FS_READ_PREFIX: &str = "FS:READ:";
pub(in crate::kvm) const SERIAL_FS_WRITE_PREFIX: &str = "FS:WRITE:";
const SERIAL_OUTPUT_PREFIX: &str = "OUTPUT:";
const SERIAL_EXIT_PREFIX: &str = "EXIT:";
const SERIAL_EXIT_TIMEOUT: &str = "EXIT:TIMEOUT";
const SERIAL_FSRESULT_PREFIX: &str = "FSRESULT:";
pub(in crate::kvm) const SERIAL_HTTP_REQUEST_PREFIX: &str = "HTTP:REQUEST:";
pub(in crate::kvm) const SERIAL_HTTPRESP_HEADERS_PREFIX: &str = "HTTPRESP:HEADERS:";
pub(in crate::kvm) const SERIAL_HTTPRESP_BODY_PREFIX: &str = "HTTPRESP:BODY:";
pub(in crate::kvm) const SERIAL_HTTPRESP_END_PREFIX: &str = "HTTPRESP:END:";
pub(in crate::kvm) const SERIAL_HTTPRESP_ERROR_PREFIX: &str = "HTTPRESP:ERROR:";
pub(in crate::kvm) const SERIAL_STREAM_START_PREFIX: &str = "STREAM:START:";
pub(in crate::kvm) const SERIAL_STREAM_STDOUT_PREFIX: &str = "STREAM:STDOUT:";
pub(in crate::kvm) const SERIAL_STREAM_STDERR_PREFIX: &str = "STREAM:STDERR:";
pub(in crate::kvm) const SERIAL_STREAM_END_PREFIX: &str = "STREAM:END:";
pub(in crate::kvm) const SERIAL_STREAM_TIMEOUT_PREFIX: &str = "STREAM:TIMEOUT:";
pub(in crate::kvm) const MAX_FS_TRANSFER_BYTES: usize = 10 * 1024 * 1024;
#[cfg(any(debug_assertions, feature = "boot-profile"))]
pub(in crate::kvm) const SERIAL_BOOT_TIME_PREFIX: &str = "BOOT_TIME:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::kvm) struct SerialDevice {
    pub(in crate::kvm) rx_fifo: VecDeque<u8>,
    interrupt_enable: u8,
    line_control: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    divisor_latch_low: u8,
    divisor_latch_high: u8,
}

impl Default for SerialDevice {
    fn default() -> Self {
        Self {
            rx_fifo: VecDeque::new(),
            interrupt_enable: 0,
            line_control: 0x03,
            modem_control: 0x03,
            modem_status: 0xb0,
            scratch: 0,
            divisor_latch_low: 0,
            divisor_latch_high: 0,
        }
    }
}

impl SerialDevice {
    pub(in crate::kvm) fn queue_input(&mut self, bytes: &[u8]) {
        self.rx_fifo.extend(bytes.iter().copied());
    }

    pub(in crate::kvm) fn read(&mut self, port: u16) -> Result<u8, MicrovmError> {
        let register = port
            .checked_sub(SERIAL_PORT_COM1)
            .ok_or_else(|| MicrovmError::Backend(format!("invalid serial read port: {port:#x}")))?;

        let value = match register {
            UART_REG_DATA => {
                if self.dlab_enabled() {
                    self.divisor_latch_low
                } else {
                    self.rx_fifo.pop_front().unwrap_or_default()
                }
            }
            UART_REG_INTERRUPT_ENABLE => {
                if self.dlab_enabled() {
                    self.divisor_latch_high
                } else {
                    self.interrupt_enable
                }
            }
            UART_REG_INTERRUPT_IDENT => {
                if self.rx_fifo.is_empty() {
                    0x01
                } else {
                    0x04
                }
            }
            UART_REG_LINE_CONTROL => self.line_control,
            UART_REG_MODEM_CONTROL => self.modem_control,
            UART_REG_LINE_STATUS => self.line_status(),
            UART_REG_MODEM_STATUS => self.modem_status,
            UART_REG_SCRATCH => self.scratch,
            other => Err(MicrovmError::Backend(format!(
                "未实现的串口读寄存器: {other:#x}"
            )))?,
        };

        Ok(value)
    }

    pub(in crate::kvm) fn write(
        &mut self,
        port: u16,
        value: u8,
    ) -> Result<Option<u8>, MicrovmError> {
        let register = port.checked_sub(SERIAL_PORT_COM1).ok_or_else(|| {
            MicrovmError::Backend(format!("invalid serial write port: {port:#x}"))
        })?;

        match register {
            UART_REG_DATA => {
                if self.dlab_enabled() {
                    self.divisor_latch_low = value;
                    Ok(None)
                } else {
                    Ok(Some(value))
                }
            }
            UART_REG_INTERRUPT_ENABLE => {
                if self.dlab_enabled() {
                    self.divisor_latch_high = value;
                } else {
                    self.interrupt_enable = value;
                }
                Ok(None)
            }
            UART_REG_INTERRUPT_IDENT => Ok(None),
            UART_REG_LINE_CONTROL => {
                self.line_control = value;
                Ok(None)
            }
            UART_REG_MODEM_CONTROL => {
                self.modem_control = value;
                Ok(None)
            }
            UART_REG_LINE_STATUS | UART_REG_MODEM_STATUS => Ok(None),
            UART_REG_SCRATCH => {
                self.scratch = value;
                Ok(None)
            }
            other => Err(MicrovmError::Backend(format!(
                "未实现的串口写寄存器: {other:#x}"
            ))),
        }
    }

    pub(in crate::kvm) fn restore(&mut self, fifo: Vec<u8>, registers: [u8; 7]) {
        self.rx_fifo = fifo.into_iter().collect();
        self.interrupt_enable = registers[0];
        self.line_control = registers[1];
        self.modem_control = registers[2];
        self.modem_status = registers[3];
        self.scratch = registers[4];
        self.divisor_latch_low = registers[5];
        self.divisor_latch_high = registers[6];
    }

    pub(in crate::kvm) fn snapshot_registers(&self) -> [u8; 7] {
        [
            self.interrupt_enable,
            self.line_control,
            self.modem_control,
            self.modem_status,
            self.scratch,
            self.divisor_latch_low,
            self.divisor_latch_high,
        ]
    }

    fn dlab_enabled(&self) -> bool {
        (self.line_control & UART_LCR_DLAB) != 0
    }

    fn line_status(&self) -> u8 {
        let mut status = UART_LSR_THR_EMPTY | UART_LSR_TRANSMITTER_EMPTY;
        if !self.rx_fifo.is_empty() {
            status |= UART_LSR_DATA_READY;
        }
        status
    }
}

#[derive(Debug, Default)]
pub(in crate::kvm) struct CommandResponse {
    pub(in crate::kvm) stdout: Vec<u8>,
    pub(in crate::kvm) stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::kvm) struct FsResult {
    pub(in crate::kvm) status: u8,
    pub(in crate::kvm) data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::kvm) struct HttpRequestFrame {
    pub(in crate::kvm) id: u32,
    pub(in crate::kvm) request: HttpRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::kvm) enum SerialProtocolResult {
    PingPong,
    Command(GuestCommandResult),
    Fs(FsResult),
    HttpRequest(HttpRequestFrame),
    StreamStart(u32),
    StreamStdout(u32, Vec<u8>),
    StreamStderr(u32, Vec<u8>),
    StreamEnd(u32, i32),
    StreamTimeout(u32),
}

#[derive(Debug)]
pub(in crate::kvm) enum SerialResponseCollector {
    Command(CommandResponse),
    Fs,
    #[allow(dead_code)] // 预留给后续 host 主动 HTTP 帧收发路径。
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::kvm) enum SerialFrame {
    Line(String),
    FsResult(FsResult),
    Stream(SerialProtocolResult),
}

pub(in crate::kvm) fn encode_command_payload(
    cmd: &[String],
    env: &HashMap<String, String>,
    timeout_secs: Option<u64>,
) -> Result<Vec<u8>, MicrovmError> {
    let payload = build_guest_exec_payload(cmd, env, timeout_secs)?;
    encode_text_frame(SERIAL_EXEC_PREFIX, payload.as_bytes())
}

pub(in crate::kvm) fn encode_ping_payload() -> Vec<u8> {
    format!("{SERIAL_PING_PREFIX}\n").into_bytes()
}

pub(in crate::kvm) fn encode_fs_read_payload(path: &str) -> Result<Vec<u8>, MicrovmError> {
    encode_text_frame(SERIAL_FS_READ_PREFIX, path.as_bytes())
}

#[allow(dead_code)] // 预留给后续 host 主动 kill 当前命令的控制面。
pub(in crate::kvm) fn encode_signal_kill_payload(pid: u32) -> Vec<u8> {
    format!("{SERIAL_SIGNAL_KILL_PREFIX}{pid}\n").into_bytes()
}

pub(in crate::kvm) fn encode_fs_write_payload(
    path: &str,
    data: &[u8],
) -> Result<Vec<u8>, MicrovmError> {
    if data.len() > MAX_FS_TRANSFER_BYTES {
        Err(MicrovmError::InvalidConfig(format!(
            "FS:WRITE 数据超过 10MB 限制: {} bytes",
            data.len()
        )))?
    }

    let mut frame = encode_text_frame(SERIAL_FS_WRITE_PREFIX, path.as_bytes())?;
    frame.extend_from_slice(format!("{}:", data.len()).as_bytes());
    frame.extend_from_slice(data);
    frame.push(b'\n');
    Ok(frame)
}

pub(in crate::kvm) fn build_guest_command(cmd: &[String]) -> Result<String, MicrovmError> {
    if cmd.is_empty() {
        Err(MicrovmError::InvalidConfig(
            "command must not be empty".into(),
        ))?
    }

    Ok(join_shell_command(cmd))
}

pub(in crate::kvm) fn build_guest_exec_payload(
    cmd: &[String],
    env: &HashMap<String, String>,
    timeout_secs: Option<u64>,
) -> Result<String, MicrovmError> {
    if let Some(timeout_secs) = timeout_secs
        && timeout_secs == 0
    {
        Err(MicrovmError::InvalidConfig(
            "timeout_secs must not be zero".into(),
        ))?
    }

    let command = build_guest_command(cmd)?;
    let payload = GuestExecPayload {
        cmd: &command,
        env,
        timeout: timeout_secs,
    };
    serde_json::to_string(&payload).map_err(|err| {
        MicrovmError::Backend(format!("failed to serialize guest EXEC payload: {err}"))
    })
}

#[derive(Debug, Serialize)]
struct GuestExecPayload<'a> {
    cmd: &'a str,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    env: &'a HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
}

fn encode_text_frame(prefix: &str, payload: &[u8]) -> Result<Vec<u8>, MicrovmError> {
    let payload_len = payload.len();
    let mut frame = format!("{prefix}{payload_len}:").into_bytes();
    frame.extend_from_slice(payload);
    frame.push(b'\n');
    Ok(frame)
}

pub(in crate::kvm) fn parse_serial_line(
    line: &str,
    response: &mut CommandResponse,
) -> Result<Option<GuestCommandResult>, MicrovmError> {
    if line == SERIAL_PONG_LINE {
        Ok(None)
    } else if line == SERIAL_EXIT_TIMEOUT {
        Ok(Some(GuestCommandResult {
            stdout: std::mem::take(&mut response.stdout),
            stderr: std::mem::take(&mut response.stderr),
            exit_code: None,
            timed_out: true,
        }))
    } else if let Some(payload) = line.strip_prefix(SERIAL_OUTPUT_PREFIX) {
        let (stream, encoded) = parse_output_payload(payload);
        let decoded = decode_guest_output(encoded)?;
        match stream {
            OutputStream::Stdout => response.stdout.extend(decoded),
            OutputStream::Stderr => response.stderr.extend(decoded),
        }
        Ok(None)
    } else if let Some(payload) = line.strip_prefix(SERIAL_EXIT_PREFIX) {
        let exit_code = payload.parse::<i32>().map_err(|err| {
            MicrovmError::Backend(format!(
                "guest EXIT frame is not a valid integer: {payload}: {err}"
            ))
        })?;
        Ok(Some(GuestCommandResult {
            stdout: std::mem::take(&mut response.stdout),
            stderr: std::mem::take(&mut response.stderr),
            exit_code: Some(exit_code),
            timed_out: false,
        }))
    } else {
        Ok(None)
    }
}

pub(in crate::kvm) fn preview_serial_output(serial: &[u8]) -> String {
    if serial.is_empty() {
        "<empty>".to_string()
    } else {
        let max_len = 4096usize;
        let start = serial.len().saturating_sub(max_len);
        let snippet = String::from_utf8_lossy(&serial[start..]).replace('\n', "\\n");
        if start == 0 {
            snippet
        } else {
            format!("...{snippet}")
        }
    }
}

pub(in crate::kvm) fn take_serial_frame(
    frame_buffer: &mut Vec<u8>,
) -> Result<Option<SerialFrame>, MicrovmError> {
    if frame_buffer.is_empty() {
        Ok(None)
    } else if frame_buffer.starts_with(SERIAL_FSRESULT_PREFIX.as_bytes()) {
        try_take_fs_result_frame(frame_buffer)
    } else if frame_buffer.starts_with(SERIAL_HTTP_REQUEST_PREFIX.as_bytes()) {
        if is_partial_http_prefix(frame_buffer) {
            Ok(None)
        } else {
            try_take_http_request_frame(frame_buffer)
        }
    } else if frame_buffer.starts_with(b"STREAM:") {
        if is_partial_stream_prefix(frame_buffer) {
            Ok(None)
        } else {
            try_take_stream_frame(frame_buffer)
        }
    } else {
        let Some(newline_index) = frame_buffer.iter().position(|&byte| byte == b'\n') else {
            return Ok(None);
        };
        let line = String::from_utf8_lossy(&frame_buffer[..newline_index]).into_owned();
        frame_buffer.drain(..=newline_index);
        Ok(Some(SerialFrame::Line(line)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputStream {
    Stdout,
    Stderr,
}

fn parse_output_payload(payload: &str) -> (OutputStream, &str) {
    if let Some(encoded) = payload.strip_prefix("1:") {
        (OutputStream::Stdout, encoded)
    } else if let Some(encoded) = payload.strip_prefix("2:") {
        (OutputStream::Stderr, encoded)
    } else {
        // Backward compatibility for old guests: without an fd marker, default to stdout.
        (OutputStream::Stdout, payload)
    }
}

fn decode_guest_output(payload: &str) -> Result<Vec<u8>, MicrovmError> {
    let bytes = payload.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte != b'\\' {
            decoded.push(byte);
            index += 1;
            continue;
        }

        index += 1;
        let escaped = *bytes.get(index).ok_or_else(|| {
            MicrovmError::Backend("guest OUTPUT frame ends with incomplete escape".into())
        })?;
        match escaped {
            b'\\' => decoded.push(b'\\'),
            b'n' => decoded.push(b'\n'),
            b'r' => decoded.push(b'\r'),
            b't' => decoded.push(b'\t'),
            b'x' => {
                let hi = *bytes.get(index + 1).ok_or_else(|| {
                    MicrovmError::Backend("guest OUTPUT frame missing high hex digit".into())
                })?;
                let lo = *bytes.get(index + 2).ok_or_else(|| {
                    MicrovmError::Backend("guest OUTPUT frame missing low hex digit".into())
                })?;
                decoded.push((parse_hex_digit(hi)? << 4) | parse_hex_digit(lo)?);
                index += 2;
            }
            other => {
                return Err(MicrovmError::Backend(format!(
                    "guest OUTPUT 帧包含未知转义: \\{}",
                    char::from(other)
                )));
            }
        }
        index += 1;
    }

    Ok(decoded)
}

fn parse_hex_digit(value: u8) -> Result<u8, MicrovmError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        other => Err(MicrovmError::Backend(format!(
            "guest OUTPUT 帧包含非法十六进制字符: {}",
            char::from(other)
        ))),
    }
}

fn try_take_fs_result_frame(
    frame_buffer: &mut Vec<u8>,
) -> Result<Option<SerialFrame>, MicrovmError> {
    let bytes = frame_buffer.as_slice();
    if bytes.is_empty() || !bytes.starts_with(SERIAL_FSRESULT_PREFIX.as_bytes()) {
        return Ok(None);
    }

    let prefix_len = SERIAL_FSRESULT_PREFIX.len();
    let Some((status, status_delim_index)) = parse_decimal_prefix(bytes, prefix_len)? else {
        return Ok(None);
    };
    let status = u8::try_from(status).map_err(|_| {
        MicrovmError::Backend(format!(
            "guest FSRESULT status code exceeds u8 range: {status}"
        ))
    })?;

    match bytes.get(status_delim_index) {
        Some(b'\n') => {
            frame_buffer.drain(..=status_delim_index);
            return Ok(Some(SerialFrame::FsResult(FsResult {
                status,
                data: Vec::new(),
            })));
        }
        Some(b':') => {}
        Some(other) => {
            return Err(MicrovmError::Backend(format!(
                "guest FSRESULT 状态字段后缺少分隔符: {}",
                char::from(*other)
            )));
        }
        None => return Ok(None),
    }

    let data_len_start = status_delim_index + 1;
    let Some((data_len, data_len_delim_index)) = parse_decimal_prefix(bytes, data_len_start)?
    else {
        return Ok(None);
    };
    match bytes.get(data_len_delim_index) {
        Some(b':') => {}
        Some(other) => {
            return Err(MicrovmError::Backend(format!(
                "guest FSRESULT 数据长度字段后缺少冒号: {}",
                char::from(*other)
            )));
        }
        None => return Ok(None),
    }

    let data_start = data_len_delim_index + 1;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or_else(|| MicrovmError::Backend("guest FSRESULT data length overflow".into()))?;
    if frame_buffer.len() < data_end + 1 {
        return Ok(None);
    }
    if bytes
        .get(data_end)
        .copied()
        .ok_or_else(|| MicrovmError::Backend("guest FSRESULT missing trailing newline".into()))?
        != b'\n'
    {
        return Err(MicrovmError::Backend(
            "guest FSRESULT frame does not end with newline".into(),
        ));
    }

    let data = frame_buffer[data_start..data_end].to_vec();
    frame_buffer.drain(..=data_end);
    Ok(Some(SerialFrame::FsResult(FsResult { status, data })))
}

fn try_take_stream_frame(frame_buffer: &mut Vec<u8>) -> Result<Option<SerialFrame>, MicrovmError> {
    let bytes = frame_buffer.as_slice();

    if bytes.starts_with(SERIAL_STREAM_START_PREFIX.as_bytes()) {
        let prefix_len = SERIAL_STREAM_START_PREFIX.len();
        let Some((stream_id, delimiter_index)) = parse_decimal_prefix(bytes, prefix_len)? else {
            return Ok(None);
        };
        let stream_id = u32::try_from(stream_id).map_err(|_| {
            MicrovmError::Backend(format!(
                "guest STREAM:START id exceeds u32 range: {stream_id}"
            ))
        })?;
        match bytes.get(delimiter_index) {
            Some(b'\n') => {
                frame_buffer.drain(..=delimiter_index);
                return Ok(Some(SerialFrame::Stream(
                    SerialProtocolResult::StreamStart(stream_id),
                )));
            }
            Some(other) => {
                return Err(MicrovmError::Backend(format!(
                    "guest STREAM:START id 字段后缺少换行: {}",
                    char::from(*other)
                )));
            }
            None => return Ok(None),
        }
    }

    if bytes.starts_with(SERIAL_STREAM_END_PREFIX.as_bytes()) {
        let prefix_len = SERIAL_STREAM_END_PREFIX.len();
        let Some((stream_id, stream_delimiter_index)) = parse_decimal_prefix(bytes, prefix_len)?
        else {
            return Ok(None);
        };
        let stream_id = u32::try_from(stream_id).map_err(|_| {
            MicrovmError::Backend(format!(
                "guest STREAM:END id exceeds u32 range: {stream_id}"
            ))
        })?;
        match bytes.get(stream_delimiter_index) {
            Some(b':') => {}
            Some(other) => {
                return Err(MicrovmError::Backend(format!(
                    "guest STREAM:END id 字段后缺少冒号: {}",
                    char::from(*other)
                )));
            }
            None => return Ok(None),
        }

        let exit_code_start = stream_delimiter_index + 1;
        let Some((exit_code, exit_delimiter_index)) =
            parse_signed_decimal_prefix(bytes, exit_code_start)?
        else {
            return Ok(None);
        };
        match bytes.get(exit_delimiter_index) {
            Some(b'\n') => {
                frame_buffer.drain(..=exit_delimiter_index);
                return Ok(Some(SerialFrame::Stream(SerialProtocolResult::StreamEnd(
                    stream_id, exit_code,
                ))));
            }
            Some(other) => {
                return Err(MicrovmError::Backend(format!(
                    "guest STREAM:END 退出码字段后缺少换行: {}",
                    char::from(*other)
                )));
            }
            None => return Ok(None),
        }
    }

    if bytes.starts_with(SERIAL_STREAM_TIMEOUT_PREFIX.as_bytes()) {
        let prefix_len = SERIAL_STREAM_TIMEOUT_PREFIX.len();
        let Some((stream_id, delimiter_index)) = parse_decimal_prefix(bytes, prefix_len)? else {
            return Ok(None);
        };
        let stream_id = u32::try_from(stream_id).map_err(|_| {
            MicrovmError::Backend(format!(
                "guest STREAM:TIMEOUT id 超出 u32 范围: {stream_id}"
            ))
        })?;
        match bytes.get(delimiter_index) {
            Some(b'\n') => {
                frame_buffer.drain(..=delimiter_index);
                return Ok(Some(SerialFrame::Stream(
                    SerialProtocolResult::StreamTimeout(stream_id),
                )));
            }
            Some(other) => {
                return Err(MicrovmError::Backend(format!(
                    "guest STREAM:TIMEOUT id 字段后缺少换行: {}",
                    char::from(*other)
                )));
            }
            None => return Ok(None),
        }
    }

    let (prefix, is_stdout) = if bytes.starts_with(SERIAL_STREAM_STDOUT_PREFIX.as_bytes()) {
        (SERIAL_STREAM_STDOUT_PREFIX, true)
    } else if bytes.starts_with(SERIAL_STREAM_STDERR_PREFIX.as_bytes()) {
        (SERIAL_STREAM_STDERR_PREFIX, false)
    } else {
        return Err(MicrovmError::Backend(
            "unknown guest STREAM frame type".into(),
        ));
    };

    let prefix_len = prefix.len();
    let Some((stream_id, stream_delimiter_index)) = parse_decimal_prefix(bytes, prefix_len)? else {
        return Ok(None);
    };
    let stream_id = u32::try_from(stream_id).map_err(|_| {
        MicrovmError::Backend(format!("guest STREAM id exceeds u32 range: {stream_id}"))
    })?;
    match bytes.get(stream_delimiter_index) {
        Some(b':') => {}
        Some(other) => {
            return Err(MicrovmError::Backend(format!(
                "guest STREAM id 字段后缺少冒号: {}",
                char::from(*other)
            )));
        }
        None => return Ok(None),
    }

    let data_len_start = stream_delimiter_index + 1;
    let Some((data_len, data_len_delimiter_index)) = parse_decimal_prefix(bytes, data_len_start)?
    else {
        return Ok(None);
    };
    match bytes.get(data_len_delimiter_index) {
        Some(b':') => {}
        Some(other) => {
            return Err(MicrovmError::Backend(format!(
                "guest STREAM 数据长度字段后缺少冒号: {}",
                char::from(*other)
            )));
        }
        None => return Ok(None),
    }

    let data_start = data_len_delimiter_index + 1;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or_else(|| MicrovmError::Backend("guest STREAM data length overflow".into()))?;
    if frame_buffer.len() < data_end + 1 {
        return Ok(None);
    }
    if bytes
        .get(data_end)
        .copied()
        .ok_or_else(|| MicrovmError::Backend("guest STREAM missing trailing newline".into()))?
        != b'\n'
    {
        return Err(MicrovmError::Backend(
            "guest STREAM frame does not end with newline".into(),
        ));
    }

    let data = frame_buffer[data_start..data_end].to_vec();
    frame_buffer.drain(..=data_end);
    if is_stdout {
        Ok(Some(SerialFrame::Stream(
            SerialProtocolResult::StreamStdout(stream_id, data),
        )))
    } else {
        Ok(Some(SerialFrame::Stream(
            SerialProtocolResult::StreamStderr(stream_id, data),
        )))
    }
}

fn try_take_http_request_frame(
    frame_buffer: &mut Vec<u8>,
) -> Result<Option<SerialFrame>, MicrovmError> {
    let bytes = frame_buffer.as_slice();
    let prefix_len = SERIAL_HTTP_REQUEST_PREFIX.len();
    let Some((request_id, id_delimiter_index)) = parse_decimal_prefix(bytes, prefix_len)? else {
        return Ok(None);
    };
    let request_id = u32::try_from(request_id).map_err(|_| {
        MicrovmError::Backend(format!(
            "guest HTTP:REQUEST id exceeds u32 range: {request_id}"
        ))
    })?;

    match bytes.get(id_delimiter_index) {
        Some(b':') => {}
        Some(other) => {
            return Err(MicrovmError::Backend(format!(
                "guest HTTP:REQUEST id 字段后缺少冒号: {}",
                char::from(*other)
            )));
        }
        None => return Ok(None),
    }

    let json_len_start = id_delimiter_index + 1;
    let Some((json_len, json_len_delimiter_index)) = parse_decimal_prefix(bytes, json_len_start)?
    else {
        return Ok(None);
    };
    match bytes.get(json_len_delimiter_index) {
        Some(b':') => {}
        Some(other) => {
            return Err(MicrovmError::Backend(format!(
                "guest HTTP:REQUEST 长度字段后缺少冒号: {}",
                char::from(*other)
            )));
        }
        None => return Ok(None),
    }

    let json_start = json_len_delimiter_index + 1;
    let json_end = json_start
        .checked_add(json_len)
        .ok_or_else(|| MicrovmError::Backend("guest HTTP:REQUEST JSON length overflow".into()))?;
    if frame_buffer.len() < json_end + 1 {
        return Ok(None);
    }
    if bytes.get(json_end).copied().ok_or_else(|| {
        MicrovmError::Backend("guest HTTP:REQUEST missing trailing newline".into())
    })? != b'\n'
    {
        return Err(MicrovmError::Backend(
            "guest HTTP:REQUEST frame does not end with newline".into(),
        ));
    }

    let json = String::from_utf8(frame_buffer[json_start..json_end].to_vec()).map_err(|err| {
        MicrovmError::Backend(format!("guest HTTP:REQUEST JSON is not valid UTF-8: {err}"))
    })?;
    let request = HttpRequest::from_json(&json)?;
    frame_buffer.drain(..=json_end);
    Ok(Some(SerialFrame::Stream(
        SerialProtocolResult::HttpRequest(HttpRequestFrame {
            id: request_id,
            request,
        }),
    )))
}

fn is_partial_http_prefix(bytes: &[u8]) -> bool {
    let prefix_bytes = SERIAL_HTTP_REQUEST_PREFIX.as_bytes();
    bytes.len() < prefix_bytes.len() && prefix_bytes.starts_with(bytes)
}

fn is_partial_stream_prefix(bytes: &[u8]) -> bool {
    for prefix in [
        SERIAL_STREAM_START_PREFIX,
        SERIAL_STREAM_STDOUT_PREFIX,
        SERIAL_STREAM_STDERR_PREFIX,
        SERIAL_STREAM_END_PREFIX,
    ] {
        let prefix_bytes = prefix.as_bytes();
        if bytes.len() < prefix_bytes.len() && prefix_bytes.starts_with(bytes) {
            return true;
        }
    }
    false
}

fn parse_decimal_prefix(
    bytes: &[u8],
    start: usize,
) -> Result<Option<(usize, usize)>, MicrovmError> {
    let mut value = 0usize;
    let mut index = start;
    let mut saw_digit = false;

    while let Some(byte) = bytes.get(index).copied() {
        if byte.is_ascii_digit() {
            saw_digit = true;
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(usize::from(byte - b'0')))
                .ok_or_else(|| {
                    MicrovmError::Backend("guest FSRESULT numeric field overflow".into())
                })?;
            index += 1;
            continue;
        }

        if !saw_digit {
            return Err(MicrovmError::Backend(
                "guest FSRESULT missing numeric field".into(),
            ));
        }
        return Ok(Some((value, index)));
    }

    Ok(None)
}

fn parse_signed_decimal_prefix(
    bytes: &[u8],
    start: usize,
) -> Result<Option<(i32, usize)>, MicrovmError> {
    let mut index = start;
    let mut negative = false;

    if matches!(bytes.get(index), Some(b'-')) {
        negative = true;
        index += 1;
    }

    let Some((value, delimiter_index)) = parse_decimal_prefix(bytes, index)? else {
        return Ok(None);
    };
    let value = i32::try_from(value).map_err(|_| {
        MicrovmError::Backend(format!(
            "guest STREAM numeric field exceeds i32 range: {value}"
        ))
    })?;
    let signed = if negative {
        value
            .checked_neg()
            .ok_or_else(|| MicrovmError::Backend("guest STREAM numeric field overflow".into()))?
    } else {
        value
    };
    Ok(Some((signed, delimiter_index)))
}

fn join_shell_command(cmd: &[String]) -> String {
    cmd.iter()
        .map(|arg| shell_escape(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_escape(input: &str) -> String {
    if input.is_empty() {
        return "''".to_string();
    }

    format!("'{}'", input.replace('\'', "'\"'\"'"))
}
