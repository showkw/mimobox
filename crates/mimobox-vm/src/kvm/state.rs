#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::mem;

use super::*;

pub(super) const KVM_RUNTIME_STATE_MAGIC_V2: &[u8; 8] = b"KVMSNAP2";
pub(super) const KVM_RUNTIME_STATE_MAGIC_V3: &[u8; 8] = b"KVMSNAP3";

pub(super) fn encode_runtime_state(backend: &KvmBackend) -> Result<Vec<u8>, MicrovmError> {
    let mut state = Vec::new();
    let serial_fifo = backend
        .serial_device
        .rx_fifo
        .iter()
        .copied()
        .collect::<Vec<_>>();

    state.extend_from_slice(KVM_RUNTIME_STATE_MAGIC_V3);
    encode_vcpu_ids(&mut state, &backend.vcpus)?;
    encode_vm_state(&mut state, backend)?;
    encode_vcpu_states(&mut state, &backend.vcpus)?;
    state.push(u8::from(backend.guest_booted));
    state.push(u8::from(backend.guest_ready));
    state.push(exit_reason_to_u8(backend.last_exit_reason));
    append_bytes(&mut state, &backend.last_command_payload)?;
    append_bytes(&mut state, &backend.serial_buffer)?;
    append_bytes(&mut state, &serial_fifo)?;
    state.extend_from_slice(&backend.serial_device.snapshot_registers());
    state.extend_from_slice(&backend.loaded_kernel.entry_point.to_le_bytes());
    state.extend_from_slice(&backend.loaded_kernel.high_watermark.to_le_bytes());
    state.extend_from_slice(&backend.boot_params_addr.to_le_bytes());
    state.extend_from_slice(&backend.cmdline_addr.to_le_bytes());
    state.extend_from_slice(&backend.initrd_addr.to_le_bytes());
    Ok(state)
}

pub(super) fn restore_runtime_state_v2(
    backend: &mut KvmBackend,
    cursor: &mut ByteCursor<'_>,
) -> Result<RuntimeRestoreProfile, MicrovmError> {
    restore_vcpu_ids(&backend.vcpus, cursor)?;
    let device_state_started_at = Instant::now();
    restore_runtime_tail(backend, cursor)?;
    Ok(RuntimeRestoreProfile {
        vcpu_state_restore: Duration::ZERO,
        device_state_restore: device_state_started_at.elapsed(),
    })
}

pub(super) fn restore_runtime_tail(
    backend: &mut KvmBackend,
    cursor: &mut ByteCursor<'_>,
) -> Result<(), MicrovmError> {
    backend.guest_booted = cursor.read_u8()? != 0;
    backend.guest_ready = cursor.read_u8()? != 0;
    backend.last_exit_reason = exit_reason_from_u8(cursor.read_u8()?)?;
    backend.last_command_payload = cursor.read_bytes()?;
    backend.serial_buffer = cursor.read_bytes()?;
    let serial_fifo = cursor.read_bytes()?;
    let mut serial_registers = [0u8; 7];
    let serial_registers_len = serial_registers.len();
    serial_registers.copy_from_slice(cursor.read_exact(serial_registers_len)?);
    backend.serial_device.restore(serial_fifo, serial_registers);
    backend.loaded_kernel = LoadedKernel {
        entry_point: cursor.read_u64()?,
        high_watermark: cursor.read_u64()?,
    };
    backend.boot_params_addr = cursor.read_u64()?;
    backend.cmdline_addr = cursor.read_u64()?;
    backend.initrd_addr = cursor.read_u64()?;
    if !cursor.is_eof() {
        return Err(MicrovmError::SnapshotFormat(
            "unrecognized data at end of KVM runtime snapshot".into(),
        ));
    }
    Ok(())
}

pub(super) fn restore_runtime_state_v3(
    backend: &mut KvmBackend,
    cursor: &mut ByteCursor<'_>,
) -> Result<RuntimeRestoreProfile, MicrovmError> {
    restore_vcpu_ids(&backend.vcpus, cursor)?;
    let device_state_started_at = Instant::now();
    restore_vm_state(backend, cursor)?;
    let mut device_state_restore = device_state_started_at.elapsed();

    let vcpu_state_started_at = Instant::now();
    restore_vcpu_states(&backend.vcpus, cursor)?;
    let vcpu_state_restore = vcpu_state_started_at.elapsed();

    let runtime_tail_started_at = Instant::now();
    restore_runtime_tail(backend, cursor)?;
    device_state_restore += runtime_tail_started_at.elapsed();

    Ok(RuntimeRestoreProfile {
        vcpu_state_restore,
        device_state_restore,
    })
}

pub(super) fn encode_vcpu_ids(out: &mut Vec<u8>, vcpus: &[VcpuFd]) -> Result<(), MicrovmError> {
    let count = u32::try_from(vcpus.len())
        .map_err(|_| MicrovmError::Backend("vCPU count exceeds u32 limit".into()))?;
    out.extend_from_slice(&count.to_le_bytes());
    for (index, _) in vcpus.iter().enumerate() {
        out.extend_from_slice(&(index as u64).to_le_bytes());
    }
    Ok(())
}

pub(super) fn restore_vcpu_ids(
    vcpus: &[VcpuFd],
    cursor: &mut ByteCursor<'_>,
) -> Result<(), MicrovmError> {
    let count = usize::try_from(cursor.read_u32()?).map_err(|_| {
        MicrovmError::SnapshotFormat("vCPU count in snapshot cannot be converted to usize".into())
    })?;
    if count != vcpus.len() {
        return Err(MicrovmError::SnapshotFormat(format!(
            "vCPU count mismatch: snapshot has {count}, current backend has {}",
            vcpus.len()
        )));
    }

    for (index, _) in vcpus.iter().enumerate() {
        let encoded_id = cursor.read_u64()?;
        if encoded_id != index as u64 {
            return Err(MicrovmError::SnapshotFormat(format!(
                "vCPU ID mismatch: snapshot has {encoded_id}, current is {}",
                index
            )));
        }
    }
    Ok(())
}

pub(super) fn encode_vm_state(out: &mut Vec<u8>, backend: &KvmBackend) -> Result<(), MicrovmError> {
    let clock = backend.vm_fd.get_clock().map_err(to_backend_error)?;
    append_pod(out, &clock);

    let pit = backend.vm_fd.get_pit2().map_err(to_backend_error)?;
    append_pod(out, &pit);

    for chip_id in [
        KVM_IRQCHIP_PIC_MASTER,
        KVM_IRQCHIP_PIC_SLAVE,
        KVM_IRQCHIP_IOAPIC,
    ] {
        let mut irqchip = kvm_irqchip {
            chip_id,
            ..Default::default()
        };
        backend
            .vm_fd
            .get_irqchip(&mut irqchip)
            .map_err(to_backend_error)?;
        append_pod(out, &irqchip);
    }

    Ok(())
}

pub(super) fn restore_vm_state(
    backend: &mut KvmBackend,
    cursor: &mut ByteCursor<'_>,
) -> Result<(), MicrovmError> {
    let clock: kvm_clock_data = read_pod(cursor)?;
    backend
        .vm_fd
        .set_clock(&clock)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore KVM clock: {err}")))?;

    let pit_state: kvm_pit_state2 = read_pod(cursor)?;
    backend
        .vm_fd
        .set_pit2(&pit_state)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore PIT state: {err}")))?;

    for expected_chip_id in [
        KVM_IRQCHIP_PIC_MASTER,
        KVM_IRQCHIP_PIC_SLAVE,
        KVM_IRQCHIP_IOAPIC,
    ] {
        let irqchip: kvm_irqchip = read_pod(cursor)?;
        if irqchip.chip_id != expected_chip_id {
            return Err(MicrovmError::SnapshotFormat(format!(
                "irqchip ID mismatch: snapshot has {}, expected {expected_chip_id}",
                irqchip.chip_id
            )));
        }
        backend.vm_fd.set_irqchip(&irqchip).map_err(|err| {
            MicrovmError::Backend(format!(
                "failed to restore irqchip({expected_chip_id}) state: {err}"
            ))
        })?;
    }

    Ok(())
}

pub(super) fn encode_vcpu_states(out: &mut Vec<u8>, vcpus: &[VcpuFd]) -> Result<(), MicrovmError> {
    for vcpu in vcpus {
        encode_vcpu_state(out, vcpu)?;
    }
    Ok(())
}

pub(super) fn encode_vcpu_state(out: &mut Vec<u8>, vcpu: &VcpuFd) -> Result<(), MicrovmError> {
    append_pod(out, &vcpu.get_regs().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_sregs().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_fpu().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_lapic().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_mp_state().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_xsave().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_xcrs().map_err(to_backend_error)?);
    append_pod(out, &vcpu.get_vcpu_events().map_err(to_backend_error)?);
    append_msr_entries(out, &snapshot_vcpu_msrs(vcpu)?)?;
    Ok(())
}

pub(super) fn restore_vcpu_states(
    vcpus: &[VcpuFd],
    cursor: &mut ByteCursor<'_>,
) -> Result<(), MicrovmError> {
    for vcpu in vcpus {
        restore_vcpu_state(vcpu, cursor)?;
    }
    Ok(())
}

pub(super) fn restore_vcpu_state(
    vcpu: &VcpuFd,
    cursor: &mut ByteCursor<'_>,
) -> Result<(), MicrovmError> {
    let regs: kvm_regs = read_pod(cursor)?;
    let sregs: kvm_sregs = read_pod(cursor)?;
    let fpu: kvm_fpu = read_pod(cursor)?;
    let lapic: kvm_lapic_state = read_pod(cursor)?;
    let mp_state: kvm_mp_state = read_pod(cursor)?;
    let xsave: kvm_xsave = read_pod(cursor)?;
    let xcrs: kvm_xcrs = read_pod(cursor)?;
    let vcpu_events: kvm_vcpu_events = read_pod(cursor)?;
    let msr_entries = read_msr_entries(cursor)?;

    vcpu.set_sregs(&sregs)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore sregs: {err}")))?;
    vcpu.set_regs(&regs)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore regs: {err}")))?;
    vcpu.set_fpu(&fpu)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore fpu: {err}")))?;
    vcpu.set_lapic(&lapic)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore lapic: {err}")))?;
    vcpu.set_mp_state(mp_state)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore mp_state: {err}")))?;
    vcpu.set_xsave(&xsave)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore xsave: {err}")))?;
    vcpu.set_xcrs(&xcrs)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore xcrs: {err}")))?;
    vcpu.set_vcpu_events(&vcpu_events)
        .map_err(|err| MicrovmError::Backend(format!("failed to restore vcpu_events: {err}")))?;
    restore_vcpu_msrs(vcpu, &msr_entries)?;
    Ok(())
}

pub(super) fn snapshot_vcpu_msrs(vcpu: &VcpuFd) -> Result<Vec<kvm_msr_entry>, MicrovmError> {
    let template = tracked_msr_entries_template();
    let mut msrs = Msrs::from_entries(&template).map_err(to_backend_error)?;
    let read = vcpu.get_msrs(&mut msrs).map_err(to_backend_error)?;
    if read != template.len() {
        return Err(MicrovmError::Backend(format!(
            "snapshot MSR read only {read}/{} entries",
            template.len()
        )));
    }
    Ok(msrs.as_slice().to_vec())
}

pub(super) fn restore_vcpu_msrs(
    vcpu: &VcpuFd,
    entries: &[kvm_msr_entry],
) -> Result<(), MicrovmError> {
    let msrs = Msrs::from_entries(entries).map_err(to_backend_error)?;
    let written = vcpu.set_msrs(&msrs).map_err(to_backend_error)?;
    if written != entries.len() {
        return Err(MicrovmError::Backend(format!(
            "恢复 MSR 仅写入 {written}/{} 项",
            entries.len()
        )));
    }
    Ok(())
}

pub(super) fn tracked_msr_entries_template() -> [kvm_msr_entry; 12] {
    [
        kvm_msr_entry {
            index: MSR_IA32_SYSENTER_CS,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_SYSENTER_ESP,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_SYSENTER_EIP,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_STAR,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_CSTAR,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_KERNEL_GS_BASE,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_SYSCALL_MASK,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_LSTAR,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_TSC,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_APICBASE,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_MTRR_DEF_TYPE,
            data: 0,
            ..Default::default()
        },
    ]
}

pub(super) fn encode_e820_entry(
    dst: &mut [u8],
    addr: u64,
    size: u64,
    entry_type: u32,
) -> Result<(), MicrovmError> {
    if dst.len() != E820_ENTRY_SIZE {
        return Err(MicrovmError::Backend("invalid E820 entry length".into()));
    }
    dst[..8].copy_from_slice(&addr.to_le_bytes());
    dst[8..16].copy_from_slice(&size.to_le_bytes());
    dst[16..20].copy_from_slice(&entry_type.to_le_bytes());
    Ok(())
}

pub(super) fn append_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), MicrovmError> {
    let len = u32_from_len(bytes.len(), "字节块长度超过 u32 上限")?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn append_msr_entries(
    out: &mut Vec<u8>,
    entries: &[kvm_msr_entry],
) -> Result<(), MicrovmError> {
    let len = u32_from_len(entries.len(), "MSR 条目数量超过 u32 上限")?;
    out.extend_from_slice(&len.to_le_bytes());
    for entry in entries {
        append_pod(out, entry);
    }
    Ok(())
}

pub(super) fn read_msr_entries(
    cursor: &mut ByteCursor<'_>,
) -> Result<Vec<kvm_msr_entry>, MicrovmError> {
    let len = usize::try_from(cursor.read_u32()?).map_err(|_| {
        MicrovmError::SnapshotFormat("MSR entry count cannot be converted to usize".into())
    })?;
    let mut entries = Vec::with_capacity(len);
    for _ in 0..len {
        entries.push(read_pod(cursor)?);
    }
    Ok(entries)
}

pub(super) fn append_pod<T>(out: &mut Vec<u8>, value: &T) {
    // SAFETY: KVM binding structs are byte-copyable kernel ABI data. Current snapshots
    // are only restored on the same architecture and process version, so storing raw
    // bytes does not introduce aliasing or lifetime issues.
    let bytes = unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>())
    };
    out.extend_from_slice(bytes);
}

pub(super) fn read_pod<T: Default>(cursor: &mut ByteCursor<'_>) -> Result<T, MicrovmError> {
    let bytes = cursor.read_exact(mem::size_of::<T>())?;
    let mut value = T::default();
    // SAFETY: `value` is zero-initialized with `Default` and then overwritten with the
    // same number of bytes. The source bytes come from `append_pod` serialization for
    // the same ABI, so layout and size match.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut value as *mut T).cast::<u8>(),
            bytes.len(),
        );
    }
    Ok(value)
}

pub(super) fn exit_reason_to_u8(reason: Option<KvmExitReason>) -> u8 {
    match reason {
        None => 0,
        Some(KvmExitReason::Io) => 1,
        Some(KvmExitReason::Hlt) => 2,
        Some(KvmExitReason::Shutdown) => 3,
        Some(KvmExitReason::InternalError) => 4,
    }
}

pub(super) fn exit_reason_from_u8(value: u8) -> Result<Option<KvmExitReason>, MicrovmError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(KvmExitReason::Io)),
        2 => Ok(Some(KvmExitReason::Hlt)),
        3 => Ok(Some(KvmExitReason::Shutdown)),
        4 => Ok(Some(KvmExitReason::InternalError)),
        other => Err(MicrovmError::SnapshotFormat(format!(
            "未知 KVM 退出原因编码: {other}"
        ))),
    }
}

pub(super) fn checked_slice(
    bytes: &[u8],
    offset: usize,
    len: usize,
) -> Result<&[u8], MicrovmError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| MicrovmError::Backend("byte range length calculation overflow".into()))?;
    bytes.get(offset..end).ok_or_else(|| {
        MicrovmError::Backend(format!(
            "byte range out of bounds: offset={offset}, len={len}, total={}",
            bytes.len()
        ))
    })
}

pub(super) fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, MicrovmError> {
    let mut raw = [0u8; 2];
    raw.copy_from_slice(checked_slice(bytes, offset, 2)?);
    Ok(u16::from_le_bytes(raw))
}

pub(super) fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, MicrovmError> {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(checked_slice(bytes, offset, 4)?);
    Ok(u32::from_le_bytes(raw))
}

pub(super) fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64, MicrovmError> {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(checked_slice(bytes, offset, 8)?);
    Ok(u64::from_le_bytes(raw))
}

pub(super) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), MicrovmError> {
    let dst = bytes
        .get_mut(offset..offset + 2)
        .ok_or_else(|| MicrovmError::Backend("boot_params write out of bounds".into()))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(super) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), MicrovmError> {
    let dst = bytes
        .get_mut(offset..offset + 4)
        .ok_or_else(|| MicrovmError::Backend("boot_params write out of bounds".into()))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(super) fn align_up(value: u64, align: u64) -> Result<u64, MicrovmError> {
    if align == 0 {
        return Err(MicrovmError::Backend("alignment must not be zero".into()));
    }
    let adjusted = value
        .checked_add(align - 1)
        .ok_or_else(|| MicrovmError::Backend("address alignment calculation overflow".into()))?;
    Ok(adjusted / align * align)
}

pub(super) fn lower_u32(value: u64) -> Result<u32, MicrovmError> {
    Ok((value & 0xffff_ffff) as u32)
}

pub(super) fn upper_u32(value: u64) -> Result<u32, MicrovmError> {
    Ok((value >> 32) as u32)
}

pub(super) fn usize_from_u64(value: u64) -> Result<usize, MicrovmError> {
    usize::try_from(value)
        .map_err(|_| MicrovmError::Backend("u64 cannot be converted to usize".into()))
}

pub(super) fn u32_from_len(len: usize, message: &str) -> Result<u32, MicrovmError> {
    u32::try_from(len).map_err(|_| MicrovmError::Backend(message.into()))
}

pub(super) fn to_backend_error(err: impl std::fmt::Display) -> MicrovmError {
    MicrovmError::Backend(err.to_string())
}

pub(super) struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn read_exact(&mut self, len: usize) -> Result<&'a [u8], MicrovmError> {
        let slice = checked_slice(self.bytes, self.offset, len)
            .map_err(|err| MicrovmError::SnapshotFormat(err.to_string()))?;
        self.offset += len;
        Ok(slice)
    }

    pub(super) fn read_u8(&mut self) -> Result<u8, MicrovmError> {
        Ok(self.read_exact(1)?[0])
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, MicrovmError> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    pub(super) fn read_u64(&mut self) -> Result<u64, MicrovmError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    pub(super) fn read_bytes(&mut self) -> Result<Vec<u8>, MicrovmError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| {
            MicrovmError::SnapshotFormat(
                "byte block length in snapshot cannot be converted to usize".into(),
            )
        })?;
        Ok(self.read_exact(len)?.to_vec())
    }

    pub(super) fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
