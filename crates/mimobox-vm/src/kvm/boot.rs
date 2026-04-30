#![cfg(all(target_os = "linux", feature = "kvm"))]

use std::mem;

use super::*;

#[cfg(target_arch = "x86_64")]
const BOOT_STACK_POINTER: u64 = 0x8_000;
#[cfg(target_arch = "x86_64")]
const BOOT_GDT_OFFSET: u64 = 0x500;
#[cfg(target_arch = "x86_64")]
const BOOT_IDT_OFFSET: u64 = 0x520;
#[cfg(target_arch = "x86_64")]
const BOOT_PML4_START: u64 = 0x9000;
#[cfg(target_arch = "x86_64")]
const BOOT_PDPTE_START: u64 = 0xa000;
#[cfg(target_arch = "x86_64")]
const BOOT_PDE_START: u64 = 0xb000;
#[cfg(target_arch = "x86_64")]
const BOOT_GDT_MAX: usize = 4;
#[cfg(target_arch = "x86_64")]
const EFER_LME: u64 = 0x100;
#[cfg(target_arch = "x86_64")]
const EFER_LMA: u64 = 0x400;
#[cfg(target_arch = "x86_64")]
const X86_CR0_PE: u64 = 0x1;
#[cfg(target_arch = "x86_64")]
const X86_CR0_PG: u64 = 0x8000_0000;
#[cfg(target_arch = "x86_64")]
const X86_CR4_PAE: u64 = 0x20;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_IA32_SYSENTER_CS: u32 = 0x174;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_IA32_SYSENTER_EIP: u32 = 0x176;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_IA32_TSC: u32 = 0x10;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_IA32_APICBASE: u32 = 0x1b;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_IA32_MISC_ENABLE: u32 = 0x1a0;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_APICBASE_BSP: u64 = 1 << 8;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_APICBASE_ENABLE: u64 = 1 << 11;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_APICBASE_BASE: u64 = 0xfee0_0000;
#[cfg(target_arch = "x86_64")]
const MSR_IA32_MISC_ENABLE_FAST_STRING: u64 = 1;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_MTRR_DEF_TYPE: u32 = 0x2ff;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_STAR: u32 = 0xc000_0081;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_LSTAR: u32 = 0xc000_0082;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_CSTAR: u32 = 0xc000_0083;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_SYSCALL_MASK: u32 = 0xc000_0084;
#[cfg(target_arch = "x86_64")]
pub(super) const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;
#[cfg(target_arch = "x86_64")]
const APIC_SPIV_REG_OFFSET: usize = 0x0f0;
#[cfg(target_arch = "x86_64")]
const APIC_SPIV_VECTOR_MASK: i32 = 0x00ff;
#[cfg(target_arch = "x86_64")]
const APIC_SPIV_SW_ENABLE: i32 = 0x0100;
#[cfg(target_arch = "x86_64")]
const APIC_LVT0_REG_OFFSET: usize = 0x350;
#[cfg(target_arch = "x86_64")]
const APIC_LVT1_REG_OFFSET: usize = 0x360;
#[cfg(target_arch = "x86_64")]
const APIC_MODE_EXTINT: i32 = 0x7;
#[cfg(target_arch = "x86_64")]
const APIC_MODE_NMI: i32 = 0x4;
#[cfg(target_arch = "x86_64")]
pub(super) const CPUID_LEAF_KVM_SIGNATURE: u32 = 0x4000_0000;
#[cfg(target_arch = "x86_64")]
pub(super) const CPUID_LEAF_KVM_FEATURES: u32 = 0x4000_0001;
#[cfg(target_arch = "x86_64")]
pub(super) const CPUID_LEAF_TIMING_INFO: u32 = 0x4000_0010;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF1_FUNCTION: u32 = 0x1;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF1_EDX_APIC: u32 = 1 << 9;
#[cfg(target_arch = "x86_64")]
const CPUID_LEAF1_ECX_TSC_DEADLINE: u32 = 1 << 24;
pub(super) const ZERO_PAGE_LEN: usize = 4096;
pub(super) const PT_LOAD: u32 = 1;
pub(super) const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
pub(super) const SETUP_HDR_TYPE_OF_LOADER: usize = 0x210;
pub(super) const SETUP_HDR_LOADFLAGS: usize = 0x211;
pub(super) const SETUP_HDR_CODE32_START: usize = 0x214;
pub(super) const SETUP_HDR_RAMDISK_IMAGE: usize = 0x218;
pub(super) const SETUP_HDR_RAMDISK_SIZE: usize = 0x21c;
pub(super) const SETUP_HDR_CMD_LINE_PTR: usize = 0x228;
pub(super) const ZERO_PAGE_E820_ENTRIES: usize = 0x1e8;
pub(super) const ZERO_PAGE_SENTINEL: usize = 0x1ef;
pub(super) const SETUP_HDR_BOOT_FLAG: usize = 0x1fe;
pub(super) const SETUP_HDR_HEADER_MAGIC: usize = 0x202;
pub(super) const ZERO_PAGE_EXT_RAMDISK_IMAGE: usize = 0x0c0;
pub(super) const ZERO_PAGE_EXT_RAMDISK_SIZE: usize = 0x0c4;
pub(super) const ZERO_PAGE_EXT_CMD_LINE_PTR: usize = 0x0c8;
pub(super) const ZERO_PAGE_E820_TABLE: usize = 0x2d0;
pub(super) const SETUP_HDR_KERNEL_ALIGNMENT: usize = 0x230;
pub(super) const E820_ENTRY_SIZE: usize = 20;
pub(super) const E820_RAM: u32 = 1;
pub(super) const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
pub(super) const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
pub(super) const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;
pub(super) const EBDA_START: u64 = 0x0009_fc00;
pub(super) const HIMEM_START: u64 = 0x0010_0000;
#[cfg(target_arch = "x86_64")]
pub(crate) const KVM_IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;
#[cfg(target_arch = "x86_64")]
pub(crate) const KVM_TSS_ADDR: usize = 0xfffb_d000;

impl KvmBackend {
    #[cfg(target_arch = "x86_64")]
    fn build_boot_cpuid(&self) -> Result<kvm_bindings::CpuId, MicrovmError> {
        let supported_cpuid = self
            .kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(to_backend_error)?;
        let mut entries = supported_cpuid.as_slice().to_vec();
        apply_host_passthrough_cpuid(&self.kvm, &mut entries);

        if let Some(tsc_khz) = self.boot_tsc_khz() {
            // The stable value currently available is the TSC frequency. LAPIC frequency
            // lacks a single reliable host query interface, so keep it conservatively at
            // 0 and let the guest prefer the TSC fast path.
            if !inject_hypervisor_timing_cpuid(&mut entries, tsc_khz, 0) {
                debug!(
                    entry_count = entries.len(),
                    tsc_khz, "CPUID table is full, skipping timing leaf injection"
                );
            }
        }

        entries.sort_by_key(|entry| (entry.function, entry.index));
        kvm_bindings::CpuId::from_entries(&entries).map_err(to_backend_error)
    }

    #[cfg(target_arch = "x86_64")]
    fn boot_tsc_khz(&self) -> Option<u32> {
        if !self.kvm.check_extension(Cap::GetTscKhz) {
            return None;
        }

        let vcpu = self.vcpus.first()?;

        match vcpu.get_tsc_khz() {
            Ok(0) => None,
            Ok(tsc_khz) => Some(tsc_khz),
            Err(err) => {
                debug!(error = %err, "failed to read vCPU TSC frequency, skipping timing leaf");
                None
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn apply_boot_cpuid_to_vcpus(&self) -> Result<(), MicrovmError> {
        let supported_cpuid = self.build_boot_cpuid()?;
        for vcpu in &self.vcpus {
            vcpu.set_cpuid2(&supported_cpuid)
                .map_err(to_backend_error)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn configure_boot_vcpu_registers(&self) -> Result<(), MicrovmError> {
        for (vcpu_index, vcpu) in self.vcpus.iter().enumerate() {
            configure_linux_boot_sregs(&self.guest_memory, vcpu)?;
            configure_boot_fpu(vcpu)?;
            configure_boot_msrs(vcpu, vcpu_index == 0)?;
            configure_lapic(vcpu)?;

            let mut regs = vcpu.get_regs().map_err(to_backend_error)?;
            regs.rip = self.loaded_kernel.entry_point;
            regs.rsp = BOOT_STACK_POINTER;
            regs.rbp = BOOT_STACK_POINTER;
            regs.rsi = self.boot_params_addr;
            regs.rflags = 0x2;
            vcpu.set_regs(&regs).map_err(to_backend_error)?;
        }
        Ok(())
    }

    /// Provides the configure boot vcpus operation.
    pub(in crate::kvm) fn configure_boot_vcpus(&self) -> Result<VcpuSetupProfile, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            let cpuid_started_at = Instant::now();
            self.apply_boot_cpuid_to_vcpus()?;
            let cpuid_config = cpuid_started_at.elapsed();

            let register_started_at = Instant::now();
            self.configure_boot_vcpu_registers()?;
            let register_config = register_started_at.elapsed();

            return Ok(VcpuSetupProfile {
                cpuid_config,
                register_config,
            });
        }

        #[allow(unreachable_code)]
        Err(MicrovmError::Backend(
            "KVM bring-up only supports x86_64".into(),
        ))
    }

    /// Provides the prepare restored vcpus operation.
    pub(crate) fn prepare_restored_vcpus(&self) -> Result<Duration, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            let cpuid_started_at = Instant::now();
            self.apply_boot_cpuid_to_vcpus()?;
            return Ok(cpuid_started_at.elapsed());
        }

        #[allow(unreachable_code)]
        Err(MicrovmError::Backend(
            "KVM bring-up only supports x86_64".into(),
        ))
    }
}

#[cfg(target_arch = "x86_64")]
fn configure_linux_boot_sregs(
    guest_memory: &GuestMemoryMmap,
    vcpu: &VcpuFd,
) -> Result<(), MicrovmError> {
    let mut sregs = vcpu.get_sregs().map_err(to_backend_error)?;
    configure_segments_and_sregs(guest_memory, &mut sregs)?;
    setup_page_tables(guest_memory, &mut sregs)?;
    vcpu.set_sregs(&sregs).map_err(to_backend_error)
}

#[cfg(target_arch = "x86_64")]
fn configure_boot_fpu(vcpu: &VcpuFd) -> Result<(), MicrovmError> {
    let fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };
    vcpu.set_fpu(&fpu).map_err(to_backend_error)
}

#[cfg(target_arch = "x86_64")]
/// Provides the inject hypervisor timing cpuid operation.
pub(super) fn inject_hypervisor_timing_cpuid(
    entries: &mut Vec<kvm_cpuid_entry2>,
    tsc_khz: u32,
    lapic_khz: u32,
) -> bool {
    let has_signature = entries
        .iter()
        .any(|entry| entry.function == CPUID_LEAF_KVM_SIGNATURE && entry.index == 0);
    let has_timing = entries
        .iter()
        .any(|entry| entry.function == CPUID_LEAF_TIMING_INFO && entry.index == 0);
    let missing_entries = usize::from(!has_signature) + usize::from(!has_timing);
    if entries.len() + missing_entries > KVM_MAX_CPUID_ENTRIES {
        return false;
    }

    if let Some(signature) = entries
        .iter_mut()
        .find(|entry| entry.function == CPUID_LEAF_KVM_SIGNATURE && entry.index == 0)
    {
        signature.eax = signature.eax.max(CPUID_LEAF_TIMING_INFO);
    } else {
        entries.push(kvm_cpuid_entry2 {
            function: CPUID_LEAF_KVM_SIGNATURE,
            index: 0,
            eax: CPUID_LEAF_TIMING_INFO.max(CPUID_LEAF_KVM_FEATURES),
            ebx: 0x4b4d_564b,
            ecx: 0x564b_4d56,
            edx: 0x0000_004d,
            ..Default::default()
        });
    }

    let timing_leaf = kvm_cpuid_entry2 {
        function: CPUID_LEAF_TIMING_INFO,
        index: 0,
        eax: tsc_khz,
        ebx: lapic_khz,
        ..Default::default()
    };
    if let Some(entry) = entries
        .iter_mut()
        .find(|entry| entry.function == CPUID_LEAF_TIMING_INFO && entry.index == 0)
    {
        *entry = timing_leaf;
    } else {
        entries.push(timing_leaf);
    }

    true
}

#[cfg(target_arch = "x86_64")]
fn apply_host_passthrough_cpuid(kvm: &Kvm, entries: &mut [kvm_cpuid_entry2]) {
    let (host_leaf1_ecx, host_leaf1_edx) = host_passthrough_cpuid_bits(kvm);

    for entry in entries {
        if entry.function != CPUID_LEAF1_FUNCTION || entry.index != 0 {
            continue;
        }

        // Keep the KVM-filtered available feature set here and explicitly align only the
        // cold-start-critical TSC deadline/APIC bits with host capabilities, preventing
        // the guest from falling back to slower calibration paths.
        entry.ecx |= host_leaf1_ecx;
        entry.edx |= host_leaf1_edx;
        return;
    }
}

#[cfg(target_arch = "x86_64")]
fn host_passthrough_cpuid_bits(kvm: &Kvm) -> (u32, u32) {
    let host_leaf1 = __cpuid_count(CPUID_LEAF1_FUNCTION, 0);
    let tsc_deadline = if kvm.check_extension(Cap::TscDeadlineTimer) {
        host_leaf1.ecx & CPUID_LEAF1_ECX_TSC_DEADLINE
    } else {
        0
    };
    let apic = host_leaf1.edx & CPUID_LEAF1_EDX_APIC;
    (tsc_deadline, apic)
}

#[cfg(target_arch = "x86_64")]
fn configure_boot_msrs(vcpu: &VcpuFd, is_bootstrap_processor: bool) -> Result<(), MicrovmError> {
    let apicbase = MSR_IA32_APICBASE_BASE
        | MSR_IA32_APICBASE_ENABLE
        | if is_bootstrap_processor {
            MSR_IA32_APICBASE_BSP
        } else {
            0
        };
    let entries = [
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
            data: apicbase,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            data: MSR_IA32_MISC_ENABLE_FAST_STRING,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_MTRR_DEF_TYPE,
            data: (1u64 << 11) | 0x6,
            ..Default::default()
        },
    ];
    let msrs = Msrs::from_entries(&entries).map_err(to_backend_error)?;
    let written = vcpu.set_msrs(&msrs).map_err(to_backend_error)?;
    if written != entries.len() {
        return Err(MicrovmError::Backend(format!(
            "only wrote {written}/{} boot MSR entries",
            entries.len()
        )));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn configure_lapic(vcpu: &VcpuFd) -> Result<(), MicrovmError> {
    let mut klapic = vcpu.get_lapic().map_err(to_backend_error)?;
    let spiv = get_klapic_reg(&klapic, APIC_SPIV_REG_OFFSET)?;
    let vector = match spiv & APIC_SPIV_VECTOR_MASK {
        0 => APIC_SPIV_VECTOR_MASK,
        value => value,
    };
    set_klapic_reg(
        &mut klapic,
        APIC_SPIV_REG_OFFSET,
        (spiv & !(APIC_SPIV_VECTOR_MASK | APIC_SPIV_SW_ENABLE)) | vector | APIC_SPIV_SW_ENABLE,
    )?;
    set_klapic_delivery_mode(&mut klapic, APIC_LVT0_REG_OFFSET, APIC_MODE_EXTINT)?;
    set_klapic_delivery_mode(&mut klapic, APIC_LVT1_REG_OFFSET, APIC_MODE_NMI)?;
    vcpu.set_lapic(&klapic).map_err(to_backend_error)
}

#[cfg(target_arch = "x86_64")]
fn configure_segments_and_sregs(
    guest_memory: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
) -> Result<(), MicrovmError> {
    let gdt_table: [u64; BOOT_GDT_MAX] = [
        gdt_entry(0, 0, 0),
        gdt_entry(0xa09b, 0, 0xfffff),
        gdt_entry(0xc093, 0, 0xfffff),
        gdt_entry(0x808b, 0, 0xfffff),
    ];
    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

    write_gdt_table(guest_memory, &gdt_table)?;
    write_idt_value(guest_memory, 0)?;

    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = u16::try_from(mem::size_of_val(&gdt_table) - 1)
        .map_err(|_| MicrovmError::Backend("GDT length cannot be converted to u16".into()))?;
    sregs.idt.base = BOOT_IDT_OFFSET;
    sregs.idt.limit = u16::try_from(mem::size_of::<u64>() - 1)
        .map_err(|_| MicrovmError::Backend("IDT length cannot be converted to u16".into()))?;
    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;
    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn setup_page_tables(
    guest_memory: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
) -> Result<(), MicrovmError> {
    guest_memory
        .write_obj(BOOT_PDPTE_START | 0x03u64, GuestAddress(BOOT_PML4_START))
        .map_err(to_backend_error)?;
    guest_memory
        .write_obj(BOOT_PDE_START | 0x03u64, GuestAddress(BOOT_PDPTE_START))
        .map_err(to_backend_error)?;

    for index in 0..512u64 {
        guest_memory
            .write_obj(
                (index << 21) | 0x83u64,
                GuestAddress(BOOT_PDE_START + (index * 8)),
            )
            .map_err(to_backend_error)?;
    }

    sregs.cr3 = BOOT_PML4_START;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn write_gdt_table(guest_memory: &GuestMemoryMmap, table: &[u64]) -> Result<(), MicrovmError> {
    for (index, entry) in table.iter().enumerate() {
        let addr = BOOT_GDT_OFFSET
            .checked_add(
                u64::try_from(index)
                    .map_err(|_| {
                        MicrovmError::Backend("GDT index cannot be converted to u64".into())
                    })?
                    .checked_mul(u64::try_from(mem::size_of::<u64>()).map_err(|_| {
                        MicrovmError::Backend("u64 size cannot be converted to u64".into())
                    })?)
                    .ok_or_else(|| {
                        MicrovmError::Backend("GDT address calculation overflow".into())
                    })?,
            )
            .ok_or_else(|| MicrovmError::Backend("GDT address calculation overflow".into()))?;
        guest_memory
            .write_obj(*entry, GuestAddress(addr))
            .map_err(to_backend_error)?;
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn write_idt_value(guest_memory: &GuestMemoryMmap, value: u64) -> Result<(), MicrovmError> {
    guest_memory
        .write_obj(value, GuestAddress(BOOT_IDT_OFFSET))
        .map_err(to_backend_error)
}

#[cfg(target_arch = "x86_64")]
fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000) << 32)
        | ((u64::from(flags) & 0x0000_f0ff) << 40)
        | ((u64::from(limit) & 0x000f_0000) << 32)
        | ((u64::from(base) & 0x00ff_ffff) << 16)
        | (u64::from(limit) & 0x0000_ffff)
}

#[cfg(target_arch = "x86_64")]
fn kvm_segment_from_gdt(entry: u64, table_index: u8) -> kvm_segment {
    kvm_segment {
        base: gdt_base(entry),
        limit: gdt_limit(entry),
        selector: u16::from(table_index) * 8,
        type_: ((entry >> 40) & 0x0f) as u8,
        present: ((entry >> 47) & 0x01) as u8,
        dpl: ((entry >> 45) & 0x03) as u8,
        db: ((entry >> 54) & 0x01) as u8,
        s: ((entry >> 44) & 0x01) as u8,
        l: ((entry >> 53) & 0x01) as u8,
        g: ((entry >> 55) & 0x01) as u8,
        avl: ((entry >> 52) & 0x01) as u8,
        padding: 0,
        unusable: if ((entry >> 47) & 0x01) == 0 { 1 } else { 0 },
    }
}

#[cfg(target_arch = "x86_64")]
fn gdt_base(entry: u64) -> u64 {
    ((entry & 0xff00_0000_0000_0000) >> 32)
        | ((entry & 0x0000_00ff_0000_0000) >> 16)
        | ((entry & 0x0000_0000_ffff_0000) >> 16)
}

#[cfg(target_arch = "x86_64")]
fn gdt_limit(entry: u64) -> u32 {
    let limit = (((entry & 0x000f_0000_0000_0000) >> 32) | (entry & 0x0000_0000_0000_ffff)) as u32;
    if ((entry >> 55) & 0x01) == 0 {
        limit
    } else {
        (limit << 12) | 0x0fff
    }
}

#[cfg(target_arch = "x86_64")]
fn get_klapic_reg(klapic: &kvm_lapic_state, reg_offset: usize) -> Result<i32, MicrovmError> {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic.regs.get(range).ok_or_else(|| {
        MicrovmError::Backend(format!("invalid LAPIC register offset: {reg_offset:#x}"))
    })?;
    Ok(read_le_i32(reg))
}

#[cfg(target_arch = "x86_64")]
fn set_klapic_reg(
    klapic: &mut kvm_lapic_state,
    reg_offset: usize,
    value: i32,
) -> Result<(), MicrovmError> {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic.regs.get_mut(range).ok_or_else(|| {
        MicrovmError::Backend(format!("invalid LAPIC register offset: {reg_offset:#x}"))
    })?;
    write_le_i32(reg, value);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn set_klapic_delivery_mode(
    klapic: &mut kvm_lapic_state,
    reg_offset: usize,
    mode: i32,
) -> Result<(), MicrovmError> {
    let reg_value = get_klapic_reg(klapic, reg_offset)?;
    set_klapic_reg(klapic, reg_offset, (reg_value & !0x700) | (mode << 8))
}

#[cfg(target_arch = "x86_64")]
fn read_le_i32(input: &[i8]) -> i32 {
    let mut array = [0u8; 4];
    for (byte, read) in array.iter_mut().zip(input.iter().copied()) {
        *byte = read as u8;
    }
    i32::from_le_bytes(array)
}

#[cfg(target_arch = "x86_64")]
fn write_le_i32(output: &mut [i8], value: i32) {
    for (byte, written) in output.iter_mut().zip(value.to_le_bytes().iter().copied()) {
        *byte = written as i8;
    }
}
