#![cfg(all(target_os = "linux", feature = "kvm"))]

use super::*;

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
pub(in crate::kvm) const SERIAL_EXEC_PREFIX: &str = "EXEC:";
const SERIAL_OUTPUT_PREFIX: &str = "OUTPUT:";
const SERIAL_EXIT_PREFIX: &str = "EXIT:";
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
            .ok_or_else(|| MicrovmError::Backend(format!("非法串口读端口: {port:#x}")))?;

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
            other => {
                return Err(MicrovmError::Backend(format!(
                    "未实现的串口读寄存器: {other:#x}"
                )));
            }
        };

        Ok(value)
    }

    pub(in crate::kvm) fn write(
        &mut self,
        port: u16,
        value: u8,
    ) -> Result<Option<u8>, MicrovmError> {
        let register = port
            .checked_sub(SERIAL_PORT_COM1)
            .ok_or_else(|| MicrovmError::Backend(format!("非法串口写端口: {port:#x}")))?;

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

pub(in crate::kvm) fn encode_command_payload(
    cmd: &[String],
    timeout_secs: Option<u64>,
) -> Result<Vec<u8>, MicrovmError> {
    let command = build_guest_command(cmd, timeout_secs)?;
    let mut frame = format!("{SERIAL_EXEC_PREFIX}{}:", command.len()).into_bytes();
    frame.extend_from_slice(command.as_bytes());
    frame.push(b'\n');
    Ok(frame)
}

pub(in crate::kvm) fn build_guest_command(
    cmd: &[String],
    timeout_secs: Option<u64>,
) -> Result<String, MicrovmError> {
    if cmd.is_empty() {
        return Err(MicrovmError::InvalidConfig("命令不能为空".into()));
    }

    if let Some(timeout_secs) = timeout_secs
        && timeout_secs == 0
    {
        return Err(MicrovmError::InvalidConfig("timeout_secs 不能为 0".into()));
    }

    Ok(join_shell_command(cmd))
}

pub(in crate::kvm) fn parse_serial_line(
    line: &str,
    response: &mut CommandResponse,
) -> Result<Option<GuestCommandResult>, MicrovmError> {
    if let Some(payload) = line.strip_prefix(SERIAL_OUTPUT_PREFIX) {
        let (stream, encoded) = parse_output_payload(payload);
        let decoded = decode_guest_output(encoded)?;
        match stream {
            OutputStream::Stdout => response.stdout.extend(decoded),
            OutputStream::Stderr => response.stderr.extend(decoded),
        }
        return Ok(None);
    }

    if let Some(payload) = line.strip_prefix(SERIAL_EXIT_PREFIX) {
        let exit_code = payload.parse::<i32>().map_err(|err| {
            MicrovmError::Backend(format!("guest EXIT 帧不是合法整数: {payload}: {err}"))
        })?;
        return Ok(Some(GuestCommandResult {
            stdout: std::mem::take(&mut response.stdout),
            stderr: std::mem::take(&mut response.stderr),
            exit_code: Some(exit_code),
            timed_out: false,
        }));
    }

    Ok(None)
}

pub(in crate::kvm) fn preview_serial_output(serial: &[u8]) -> String {
    if serial.is_empty() {
        return "<empty>".to_string();
    }

    let max_len = 4096usize;
    let start = serial.len().saturating_sub(max_len);
    let snippet = String::from_utf8_lossy(&serial[start..]).replace('\n', "\\n");
    if start == 0 {
        snippet
    } else {
        format!("...{snippet}")
    }
}

pub(super) fn take_serial_line(line_buffer: &mut Vec<u8>) -> String {
    let line = String::from_utf8_lossy(line_buffer).into_owned();
    line_buffer.clear();
    line
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputStream {
    Stdout,
    Stderr,
}

fn parse_output_payload(payload: &str) -> (OutputStream, &str) {
    if let Some(encoded) = payload.strip_prefix("1:") {
        return (OutputStream::Stdout, encoded);
    }
    if let Some(encoded) = payload.strip_prefix("2:") {
        return (OutputStream::Stderr, encoded);
    }

    // 兼容旧 guest：无 fd 标记时默认视为 stdout。
    (OutputStream::Stdout, payload)
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
        let escaped = *bytes
            .get(index)
            .ok_or_else(|| MicrovmError::Backend("guest OUTPUT 帧以不完整转义结尾".into()))?;
        match escaped {
            b'\\' => decoded.push(b'\\'),
            b'n' => decoded.push(b'\n'),
            b'r' => decoded.push(b'\r'),
            b't' => decoded.push(b'\t'),
            b'x' => {
                let hi = *bytes.get(index + 1).ok_or_else(|| {
                    MicrovmError::Backend("guest OUTPUT 帧缺少十六进制高位".into())
                })?;
                let lo = *bytes.get(index + 2).ok_or_else(|| {
                    MicrovmError::Backend("guest OUTPUT 帧缺少十六进制低位".into())
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
