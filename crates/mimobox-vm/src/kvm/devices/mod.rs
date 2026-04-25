#![cfg(all(target_os = "linux", feature = "kvm"))]

#[cfg(any(debug_assertions, feature = "boot-profile"))]
use super::profile::{BootProfile, parse_guest_boot_time_line};
use super::*;

mod serial;
mod vsock;
mod vsock_channel;

#[cfg(any(debug_assertions, feature = "boot-profile"))]
pub(in crate::kvm) use self::serial::SERIAL_BOOT_TIME_PREFIX;
#[allow(unused_imports)]
pub(in crate::kvm) use self::serial::{
    CommandResponse, FsResult, I8042_COMMAND_REG, I8042_PORT_B_PIT_TICK, I8042_PORT_B_REG,
    I8042_RESET_CMD, MAX_FS_TRANSFER_BYTES, PCI_CONFIG_ADDRESS_REG, PCI_CONFIG_DATA_REG_END,
    PCI_CONFIG_DATA_REG_START, SERIAL_EXEC_PREFIX, SERIAL_EXECS_PREFIX, SERIAL_FS_READ_PREFIX,
    SERIAL_FS_WRITE_PREFIX, SERIAL_HTTP_REQUEST_PREFIX, SERIAL_HTTPRESP_BODY_PREFIX,
    SERIAL_HTTPRESP_END_PREFIX, SERIAL_HTTPRESP_ERROR_PREFIX, SERIAL_HTTPRESP_HEADERS_PREFIX,
    SERIAL_PONG_LINE, SERIAL_READY_LINE, SerialDevice, SerialFrame, SerialProtocolResult,
    SerialResponseCollector, build_guest_command, build_guest_exec_payload, encode_command_payload,
    encode_fs_read_payload, encode_fs_write_payload, encode_ping_payload, parse_serial_line,
    preview_serial_output,
};
pub(in crate::kvm) use self::vsock::{VsockMmioAction, VsockMmioDevice, activate_vhost_backend};
pub(in crate::kvm) use self::vsock_channel::VsockCommandChannel;

pub(in crate::kvm) use self::serial::take_serial_frame;
use self::serial::{
    PIC_MASTER_COMMAND_REG, PIC_MASTER_DATA_REG, PIC_SLAVE_COMMAND_REG, PIC_SLAVE_DATA_REG,
    PIT_CHANNEL0_DATA_REG, PIT_MODE_COMMAND_REG, RTC_DATA_REG, RTC_INDEX_REG, SERIAL_PORT_COM1,
    SERIAL_PORT_LAST,
};

pub(super) fn is_serial_port(port: u16) -> bool {
    (SERIAL_PORT_COM1..=SERIAL_PORT_LAST).contains(&port)
}

pub(super) fn is_boot_legacy_pio_port(port: u16) -> bool {
    matches!(
        port,
        PIC_MASTER_COMMAND_REG | PIC_MASTER_DATA_REG | PIT_CHANNEL0_DATA_REG
            ..=PIT_MODE_COMMAND_REG
                | RTC_INDEX_REG
                | RTC_DATA_REG
                | PIC_SLAVE_COMMAND_REG
                | PIC_SLAVE_DATA_REG
    )
}

pub(super) fn emulate_boot_legacy_pio_read(port: u16, data: &mut [u8]) -> bool {
    if !is_boot_legacy_pio_port(port) {
        return false;
    }

    data.fill(0);
    true
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
pub(super) fn handle_serial_write(
    serial_device: &mut SerialDevice,
    serial_buffer: &mut Vec<u8>,
    guest_ready: &mut bool,
    boot_profile: &mut BootProfile,
    port: u16,
    data: &[u8],
    frame_buffer: &mut Vec<u8>,
    response: Option<&mut SerialResponseCollector>,
) -> Result<Option<SerialProtocolResult>, MicrovmError> {
    let mut response = response;

    for &value in data {
        if let Some(tx_byte) = serial_device.write(port, value)? {
            serial_buffer.push(tx_byte);
            if tx_byte != b'\r' {
                frame_buffer.push(tx_byte);
            }

            while let Some(frame) = take_serial_frame(frame_buffer)? {
                match frame {
                    SerialFrame::Line(line) => {
                        if boot_profile.should_parse_guest_line()
                            && parse_guest_boot_time_line(&line, boot_profile)
                        {
                            continue;
                        }
                        if line == SERIAL_READY_LINE {
                            *guest_ready = true;
                            boot_profile.mark_boot_ready();
                            continue;
                        }
                        if line == SERIAL_PONG_LINE {
                            return Ok(Some(SerialProtocolResult::PingPong));
                        }

                        if let Some(response) = response.as_deref_mut() {
                            match response {
                                SerialResponseCollector::Command(command_response) => {
                                    if let Some(result) =
                                        parse_serial_line(&line, command_response)?
                                    {
                                        return Ok(Some(SerialProtocolResult::Command(result)));
                                    }
                                }
                                SerialResponseCollector::Fs => {
                                    if line.starts_with("OUTPUT:") || line.starts_with("EXIT:") {
                                        return Err(MicrovmError::Backend(format!(
                                            "unexpected serial line while waiting for FSRESULT: {line}"
                                        )));
                                    }
                                }
                                SerialResponseCollector::Http => {
                                    if line.starts_with("OUTPUT:") || line.starts_with("EXIT:") {
                                        return Err(MicrovmError::Backend(format!(
                                            "unexpected serial line while waiting for HTTP response: {line}"
                                        )));
                                    }
                                }
                            }
                        }
                    }
                    SerialFrame::FsResult(fs_result) => {
                        if let Some(response) = response.as_deref_mut() {
                            match response {
                                SerialResponseCollector::Command(_) => {
                                    return Err(MicrovmError::Backend(
                                        "unexpected FSRESULT frame during command execution".into(),
                                    ));
                                }
                                SerialResponseCollector::Fs => {
                                    return Ok(Some(SerialProtocolResult::Fs(fs_result)));
                                }
                                SerialResponseCollector::Http => {
                                    return Err(MicrovmError::Backend(
                                        "unexpected FSRESULT frame while waiting for HTTP response".into(),
                                    ));
                                }
                            }
                        }
                    }
                    SerialFrame::Stream(stream_result) => {
                        if let Some(response) = response.as_deref_mut() {
                            match response {
                                SerialResponseCollector::Command(_) => {
                                    return Ok(Some(stream_result));
                                }
                                SerialResponseCollector::Fs => {
                                    return Err(MicrovmError::Backend(format!(
                                        "unexpected STREAM frame while waiting for FSRESULT: {stream_result:?}"
                                    )));
                                }
                                SerialResponseCollector::Http => {
                                    return Ok(Some(stream_result));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

#[cfg(not(any(debug_assertions, feature = "boot-profile")))]
pub(super) fn handle_serial_write(
    serial_device: &mut SerialDevice,
    serial_buffer: &mut Vec<u8>,
    guest_ready: &mut bool,
    port: u16,
    data: &[u8],
    frame_buffer: &mut Vec<u8>,
    response: Option<&mut SerialResponseCollector>,
) -> Result<Option<SerialProtocolResult>, MicrovmError> {
    let mut response = response;

    for &value in data {
        if let Some(tx_byte) = serial_device.write(port, value)? {
            serial_buffer.push(tx_byte);
            if tx_byte != b'\r' {
                frame_buffer.push(tx_byte);
            }

            while let Some(frame) = take_serial_frame(frame_buffer)? {
                match frame {
                    SerialFrame::Line(line) => {
                        if line == SERIAL_READY_LINE {
                            *guest_ready = true;
                            continue;
                        }
                        if line == SERIAL_PONG_LINE {
                            return Ok(Some(SerialProtocolResult::PingPong));
                        }

                        if let Some(response) = response.as_deref_mut() {
                            match response {
                                SerialResponseCollector::Command(command_response) => {
                                    if let Some(result) =
                                        parse_serial_line(&line, command_response)?
                                    {
                                        return Ok(Some(SerialProtocolResult::Command(result)));
                                    }
                                }
                                SerialResponseCollector::Fs => {
                                    if line.starts_with("OUTPUT:") || line.starts_with("EXIT:") {
                                        return Err(MicrovmError::Backend(format!(
                                            "unexpected serial line while waiting for FSRESULT: {line}"
                                        )));
                                    }
                                }
                                SerialResponseCollector::Http => {
                                    if line.starts_with("OUTPUT:") || line.starts_with("EXIT:") {
                                        return Err(MicrovmError::Backend(format!(
                                            "unexpected serial line while waiting for HTTP response: {line}"
                                        )));
                                    }
                                }
                            }
                        }
                    }
                    SerialFrame::FsResult(fs_result) => {
                        if let Some(response) = response.as_deref_mut() {
                            match response {
                                SerialResponseCollector::Command(_) => {
                                    return Err(MicrovmError::Backend(
                                        "unexpected FSRESULT frame during command execution".into(),
                                    ));
                                }
                                SerialResponseCollector::Fs => {
                                    return Ok(Some(SerialProtocolResult::Fs(fs_result)));
                                }
                                SerialResponseCollector::Http => {
                                    return Err(MicrovmError::Backend(
                                        "unexpected FSRESULT frame while waiting for HTTP response".into(),
                                    ));
                                }
                            }
                        }
                    }
                    SerialFrame::Stream(stream_result) => {
                        if let Some(response) = response.as_deref_mut() {
                            match response {
                                SerialResponseCollector::Command(_) => {
                                    return Ok(Some(stream_result));
                                }
                                SerialResponseCollector::Fs => {
                                    return Err(MicrovmError::Backend(format!(
                                        "unexpected STREAM frame while waiting for FSRESULT: {stream_result:?}"
                                    )));
                                }
                                SerialResponseCollector::Http => {
                                    return Ok(Some(stream_result));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

pub(super) fn handle_serial_read(
    serial_device: &mut SerialDevice,
    port: u16,
    data: &mut [u8],
) -> Result<(), MicrovmError> {
    for slot in data.iter_mut() {
        *slot = serial_device.read(port)?;
    }
    Ok(())
}
