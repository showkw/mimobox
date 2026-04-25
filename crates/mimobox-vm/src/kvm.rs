#![cfg(all(target_os = "linux", feature = "kvm"))]

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid_count;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, Once, OnceLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_bindings::{
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, KVM_PIT_SPEAKER_DUMMY, Msrs,
    kvm_clock_data, kvm_cpuid_entry2, kvm_fpu, kvm_irqchip, kvm_lapic_state, kvm_mp_state,
    kvm_msr_entry, kvm_pit_config, kvm_pit_state2, kvm_regs, kvm_segment, kvm_sregs,
    kvm_userspace_memory_region, kvm_vcpu_events, kvm_xcrs, kvm_xsave,
};
#[cfg(target_arch = "x86_64")]
use kvm_ioctls::Cap;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use mimobox_core::SandboxConfig;
use tracing::{debug, info, warn};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::http_proxy::{HttpProxyError, HttpRequest, HttpResponse, execute_http_request};
use crate::snapshot::MicrovmSnapshot;
use crate::vm::GuestExecOptions;
use crate::vm::{GuestCommandResult, MicrovmConfig, MicrovmError, StreamEvent};

mod boot;
mod devices;
mod profile;
mod state;

#[cfg(all(target_arch = "x86_64", test))]
use self::boot::{
    CPUID_LEAF_KVM_FEATURES, CPUID_LEAF_KVM_SIGNATURE, CPUID_LEAF_TIMING_INFO,
    inject_hypervisor_timing_cpuid,
};
use self::boot::{
    E820_ENTRY_SIZE, E820_RAM, EBDA_START, GZIP_MAGIC, HIMEM_START, KERNEL_BOOT_FLAG_MAGIC,
    KERNEL_HDR_MAGIC, KERNEL_MIN_ALIGNMENT_BYTES, PT_LOAD, SETUP_HDR_BOOT_FLAG,
    SETUP_HDR_CMD_LINE_PTR, SETUP_HDR_CODE32_START, SETUP_HDR_HEADER_MAGIC,
    SETUP_HDR_KERNEL_ALIGNMENT, SETUP_HDR_LOADFLAGS, SETUP_HDR_RAMDISK_IMAGE,
    SETUP_HDR_RAMDISK_SIZE, SETUP_HDR_TYPE_OF_LOADER, ZERO_PAGE_E820_ENTRIES, ZERO_PAGE_E820_TABLE,
    ZERO_PAGE_EXT_CMD_LINE_PTR, ZERO_PAGE_EXT_RAMDISK_IMAGE, ZERO_PAGE_EXT_RAMDISK_SIZE,
    ZERO_PAGE_LEN, ZERO_PAGE_SENTINEL,
};
#[cfg(target_arch = "x86_64")]
pub(crate) use self::boot::{KVM_IDENTITY_MAP_ADDR, KVM_TSS_ADDR};
#[cfg(target_arch = "x86_64")]
use self::boot::{
    MSR_CSTAR, MSR_IA32_APICBASE, MSR_IA32_MISC_ENABLE, MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_EIP, MSR_IA32_SYSENTER_ESP, MSR_IA32_TSC, MSR_KERNEL_GS_BASE, MSR_LSTAR,
    MSR_MTRR_DEF_TYPE, MSR_STAR, MSR_SYSCALL_MASK,
};
#[cfg(any(debug_assertions, feature = "boot-profile"))]
use self::devices::SERIAL_BOOT_TIME_PREFIX;
use self::devices::{
    CommandResponse, FsResult, I8042_COMMAND_REG, I8042_PORT_B_PIT_TICK, I8042_PORT_B_REG,
    I8042_RESET_CMD, PCI_CONFIG_ADDRESS_REG, PCI_CONFIG_DATA_REG_END, PCI_CONFIG_DATA_REG_START,
    SERIAL_EXECS_PREFIX, SERIAL_HTTPRESP_BODY_PREFIX, SERIAL_HTTPRESP_END_PREFIX,
    SERIAL_HTTPRESP_ERROR_PREFIX, SERIAL_HTTPRESP_HEADERS_PREFIX, SerialDevice,
    SerialProtocolResult, SerialResponseCollector, VsockCommandChannel, VsockMmioAction,
    VsockMmioDevice, activate_vhost_backend, build_guest_command, emulate_boot_legacy_pio_read,
    encode_command_payload, encode_fs_read_payload, encode_fs_write_payload, encode_ping_payload,
    handle_serial_read, handle_serial_write, is_boot_legacy_pio_port, is_serial_port,
    preview_serial_output,
};
#[cfg(test)]
use self::devices::{SerialFrame, parse_serial_line, take_serial_frame};
pub(crate) use self::profile::RestoreProfile;
#[cfg(all(any(debug_assertions, feature = "boot-profile"), test))]
use self::profile::parse_guest_boot_time_line;
#[cfg(any(debug_assertions, feature = "boot-profile"))]
use self::profile::{BootProfile, log_boot_profile, log_guest_boot_profile_extension};
use self::profile::{CreateVmProfile, RuntimeRestoreProfile, VcpuSetupProfile};
use self::state::*;

pub(crate) const ZERO_PAGE_ADDR: u64 = 0x7_000;
pub(crate) const CMDLINE_ADDR: u64 = 0x20_000;
#[cfg(test)]
const ROOTFS_METADATA_ADDR: u64 = 0x30_000;
const BOOT_READY_TIMEOUT_SECS: u64 = 30;
const READINESS_PROBE_TIMEOUT_SECS: u64 = 5;
const VSOCK_ACCEPT_TIMEOUT_SECS: u64 = 10;
const VSOCK_PROBE_TIMEOUT_MILLIS: u64 = 500;
/// The `guest-vsock` feature is disabled by default. When disabled, the host does
/// not expose a virtio-vsock device.
#[cfg(feature = "guest-vsock")]
const VSOCK_TRANSPORT_ENABLED: bool = true;
#[cfg(not(feature = "guest-vsock"))]
const VSOCK_TRANSPORT_ENABLED: bool = false;
static ASSET_CACHE: OnceLock<Mutex<AssetCache>> = OnceLock::new();
const DEFAULT_CMDLINE: &str = "console=ttyS0 8250.nr_uarts=1 i8042.nokbd no_timer_check fastboot quiet rcupdate.rcu_expedited=1 mitigations=off tsc=reliable nokaslr nomodule reboot=t panic=1 pci=off rdinit=/init";
const VSOCK_CMDLINE_FRAGMENT: &str = " virtio_mmio.device=512@0xd0000000:5";
/// Base address of the vsock MMIO device in the guest physical address space.
const VSOCK_MMIO_BASE: u64 = 0xd000_0000;
/// Address space size of the vsock MMIO device.
const VSOCK_MMIO_SIZE: u64 = 0x200;
/// Interrupt GSI used by the vsock MMIO device.
const VSOCK_GSI: u32 = 5;
const WATCHDOG_SIGNAL: libc::c_int = libc::SIGUSR1;

/// Caches kernel and rootfs bytes reused during cold start, avoiding disk access for
/// every VM creation.
#[derive(Debug, Default)]
struct AssetCache {
    kernel: Option<(PathBuf, u64, Arc<[u8]>)>,
    rootfs: Option<(PathBuf, u64, Arc<[u8]>)>,
}

impl AssetCache {
    fn global() -> &'static Mutex<AssetCache> {
        ASSET_CACHE.get_or_init(|| Mutex::new(AssetCache::default()))
    }

    fn load(
        path: &Path,
        slot: &mut Option<(PathBuf, u64, Arc<[u8]>)>,
    ) -> Result<Arc<[u8]>, MicrovmError> {
        let metadata = fs::metadata(path).map_err(|err| {
            MicrovmError::Backend(format!(
                "failed to read asset metadata: {}: {err}",
                path.display()
            ))
        })?;
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        if let Some((cached_path, cached_mtime, cached_bytes)) = slot
            && cached_path.as_path() == path
            && *cached_mtime == mtime
        {
            return Ok(Arc::clone(cached_bytes));
        }

        let bytes: Arc<[u8]> = fs::read(path)
            .map_err(|err| {
                MicrovmError::Backend(format!(
                    "failed to read asset file: {}: {err}",
                    path.display()
                ))
            })?
            .into();
        *slot = Some((path.to_path_buf(), mtime, Arc::clone(&bytes)));
        Ok(bytes)
    }

    fn get_kernel(path: &Path) -> Result<Arc<[u8]>, MicrovmError> {
        let mut cache = match Self::global().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::load(path, &mut cache.kernel)
    }

    fn get_rootfs(path: &Path) -> Result<Arc<[u8]>, MicrovmError> {
        let mut cache = match Self::global().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::load(path, &mut cache.rootfs)
    }
}

/// Command channel type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmTransport {
    Serial,
    Vsock,
}

/// KVM backend lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmLifecycle {
    Created,
    Ready,
    Running,
    Destroyed,
}

/// Exit reason after the `KVM_RUN` loop is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmExitReason {
    Io,
    Hlt,
    Shutdown,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedKernel {
    pub(crate) entry_point: u64,
    pub(crate) high_watermark: u64,
}

#[derive(Debug)]
enum RunLoopOutcome {
    Exit(KvmExitReason),
    ResponseDone(SerialProtocolResult),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamCommandOutcome {
    Completed,
    RetryBlocking,
}

static WATCHDOG_SIGNAL_HANDLER_INIT: Once = Once::new();

extern "C" fn handle_watchdog_signal(_: libc::c_int) {}

#[derive(Debug)]
struct VcpuRunWatchdog {
    cancel: Option<mpsc::Sender<()>>,
    fired: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl VcpuRunWatchdog {
    fn start(vcpu: &mut VcpuFd, timeout: Duration) -> Self {
        install_watchdog_signal_handler();

        let immediate_exit_ptr = (&mut vcpu.get_kvm_run().immediate_exit as *mut u8) as usize;
        // SAFETY: `pthread_self` only returns the current thread identifier and does not
        // touch the Rust memory model.
        let target_thread = unsafe { libc::pthread_self() };
        vcpu.set_kvm_immediate_exit(0);

        let (tx, rx) = mpsc::channel();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        let handle = thread::spawn(move || {
            if rx.recv_timeout(timeout).is_err() {
                fired_clone.store(true, Ordering::SeqCst);

                // SAFETY: `immediate_exit_ptr` points to the `immediate_exit` field in
                // the `kvm_run` mapping for the current vCPU. The watchdog lifetime
                // strictly wraps one run loop, and `drop` notifies the thread to stop
                // before joining it, ensuring the pointer is not accessed after the
                // mapping becomes invalid.
                unsafe {
                    std::ptr::write_volatile(immediate_exit_ptr as *mut u8, 1);
                    libc::pthread_kill(target_thread, WATCHDOG_SIGNAL);
                }
            }
        });

        Self {
            cancel: Some(tx),
            fired,
            handle: Some(handle),
        }
    }

    fn timed_out(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl Drop for VcpuRunWatchdog {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Basic Linux KVM backend implementation.
pub struct KvmBackend {
    base_config: SandboxConfig,
    config: MicrovmConfig,
    kvm: Kvm,
    vm_fd: VmFd,
    vcpus: Vec<VcpuFd>,
    guest_memory: GuestMemoryMmap,
    kernel_bytes: Arc<[u8]>,
    rootfs_bytes: Arc<[u8]>,
    transport: KvmTransport,
    lifecycle: KvmLifecycle,
    last_command_payload: Vec<u8>,
    loaded_kernel: LoadedKernel,
    boot_params_addr: u64,
    cmdline_addr: u64,
    initrd_addr: u64,
    guest_booted: bool,
    guest_ready: bool,
    serial_device: SerialDevice,
    /// vsock virtio MMIO device emulator (`None` means vsock is disabled).
    vsock_device: Option<VsockMmioDevice>,
    /// Host-side vsock command channel, established only when guest-vsock is explicitly enabled.
    vsock_channel: Option<VsockCommandChannel>,
    serial_buffer: Vec<u8>,
    last_exit_reason: Option<KvmExitReason>,
    last_io_detail: Option<String>,
    recent_io_details: VecDeque<String>,
    create_vm_profile: Option<CreateVmProfile>,
    pending_restore_profile: Option<RestoreProfile>,
    #[cfg(any(debug_assertions, feature = "boot-profile"))]
    boot_profile: BootProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendCreateMode {
    ColdStart,
    SnapshotRestore,
}

impl KvmBackend {
    fn default_cmdline() -> String {
        let mut cmdline = String::from(DEFAULT_CMDLINE);
        if VSOCK_TRANSPORT_ENABLED {
            cmdline.push_str(VSOCK_CMDLINE_FRAGMENT);
        }
        cmdline
    }

    /// Executes `KVM_CREATE_VM`, allocates guest memory, and creates vCPUs.
    pub fn create_vm(
        base_config: SandboxConfig,
        config: MicrovmConfig,
    ) -> Result<Self, MicrovmError> {
        let _span = tracing::info_span!("vm_create").entered();
        Self::create_vm_with_mode(base_config, config, BackendCreateMode::ColdStart)
    }

    pub fn create_vm_for_restore(
        base_config: SandboxConfig,
        config: MicrovmConfig,
    ) -> Result<Self, MicrovmError> {
        Self::create_vm_with_mode(base_config, config, BackendCreateMode::SnapshotRestore)
    }

    /// Builds a backend from raw components of an externally pre-created slot without
    /// repeating the VM creation flow.
    pub(crate) fn from_slot_components(
        kvm: Kvm,
        vm_fd: VmFd,
        vcpus: Vec<VcpuFd>,
        guest_memory: GuestMemoryMmap,
        base_config: SandboxConfig,
        config: MicrovmConfig,
    ) -> Self {
        Self {
            base_config,
            config,
            kvm,
            vm_fd,
            vcpus,
            guest_memory,
            kernel_bytes: Arc::<[u8]>::from(Vec::<u8>::new()),
            rootfs_bytes: Arc::<[u8]>::from(Vec::<u8>::new()),
            transport: KvmTransport::Serial,
            lifecycle: KvmLifecycle::Created,
            last_command_payload: Vec::new(),
            loaded_kernel: LoadedKernel {
                entry_point: 0,
                high_watermark: 0,
            },
            boot_params_addr: ZERO_PAGE_ADDR,
            cmdline_addr: CMDLINE_ADDR,
            initrd_addr: 0,
            guest_booted: false,
            guest_ready: false,
            serial_device: SerialDevice::default(),
            vsock_device: None,
            vsock_channel: None,
            serial_buffer: Vec::new(),
            last_exit_reason: None,
            last_io_detail: None,
            recent_io_details: VecDeque::with_capacity(16),
            create_vm_profile: None,
            pending_restore_profile: None,
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            boot_profile: BootProfile::default(),
        }
    }

    pub(crate) fn set_lifecycle_ready(&mut self) {
        self.lifecycle = KvmLifecycle::Ready;
    }

    pub(crate) fn set_pending_restore_profile(&mut self, profile: RestoreProfile) {
        self.pending_restore_profile = Some(profile);
    }

    /// Hints the kernel to enable 2MB huge pages for guest memory to improve snapshot
    /// restore throughput.
    pub(crate) fn try_enable_huge_pages(guest_memory: &GuestMemoryMmap) {
        for (region_index, region) in guest_memory.iter().enumerate() {
            let ptr = region.as_ptr().cast::<libc::c_void>();
            let len = region.size();

            // SAFETY: `ptr` and `len` come directly from a valid mmap region currently
            // owned by `GuestMemoryMmap`. The mapping remains alive for the call, and
            // `madvise` only provides usage hints to the kernel without accessing user
            // memory out of bounds.
            let result = unsafe { libc::madvise(ptr, len, libc::MADV_HUGEPAGE) };
            if result != 0 {
                let err = std::io::Error::last_os_error();
                debug!(
                    region_index,
                    len,
                    error = %err,
                    "guest memory huge page 提示失败，继续使用默认页"
                );
            }
        }
    }

    fn create_vm_with_mode(
        base_config: SandboxConfig,
        config: MicrovmConfig,
        mode: BackendCreateMode,
    ) -> Result<Self, MicrovmError> {
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        let mut boot_profile = BootProfile::start();
        let create_started_at = Instant::now();
        let mut create_vm_profile = CreateVmProfile::default();
        let mut restore_profile = RestoreProfile::default();

        config.validate()?;
        info!(
            vcpu_count = config.vcpu_count,
            memory_mb = config.memory_mb,
            "创建 KVM microVM"
        );

        let kvm_open_started_at = Instant::now();
        let kvm = Kvm::new().map_err(to_backend_error)?;
        let kvm_open_elapsed = kvm_open_started_at.elapsed();
        create_vm_profile.kvm_fd_open = kvm_open_elapsed;
        restore_profile.kvm_fd_open = kvm_open_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        boot_profile.mark_kvm_open();

        let vm_create_started_at = Instant::now();
        let vm_fd = kvm.create_vm().map_err(to_backend_error)?;
        let vm_create_elapsed = vm_create_started_at.elapsed();
        create_vm_profile.kvm_create_vm = vm_create_elapsed;
        restore_profile.kvm_create_vm = vm_create_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        boot_profile.mark_vm_create();

        let vm_arch_setup_started_at = Instant::now();
        #[cfg(target_arch = "x86_64")]
        {
            vm_fd.create_irq_chip().map_err(to_backend_error)?;
            let pit_config = kvm_pit_config {
                flags: KVM_PIT_SPEAKER_DUMMY,
                ..Default::default()
            };
            vm_fd.create_pit2(pit_config).map_err(to_backend_error)?;
            vm_fd
                .set_identity_map_address(KVM_IDENTITY_MAP_ADDR)
                .map_err(to_backend_error)?;
            vm_fd
                .set_tss_address(KVM_TSS_ADDR)
                .map_err(to_backend_error)?;
        }
        let vm_arch_setup_elapsed = vm_arch_setup_started_at.elapsed();
        create_vm_profile.vm_arch_setup = vm_arch_setup_elapsed;
        restore_profile.vm_arch_setup = vm_arch_setup_elapsed;

        let memory_alloc_started_at = Instant::now();
        let guest_memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), config.memory_bytes()?)])
                .map_err(to_backend_error)?;
        let guest_memory_mmap_elapsed = memory_alloc_started_at.elapsed();
        create_vm_profile.guest_memory_mmap = guest_memory_mmap_elapsed;
        restore_profile.guest_memory_mmap = guest_memory_mmap_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        boot_profile.add_memory_alloc_duration(memory_alloc_started_at);
        Self::try_enable_huge_pages(&guest_memory);

        let (kernel_bytes, rootfs_bytes) = match mode {
            BackendCreateMode::ColdStart => {
                let kernel_asset_started_at = Instant::now();
                let kernel_bytes = AssetCache::get_kernel(config.kernel_path.as_path())?;
                let kernel_asset_elapsed = kernel_asset_started_at.elapsed();
                create_vm_profile.kernel_asset_read = kernel_asset_elapsed;
                #[cfg(any(debug_assertions, feature = "boot-profile"))]
                boot_profile.add_kernel_load_duration(kernel_asset_started_at);

                let rootfs_asset_started_at = Instant::now();
                let rootfs_bytes = AssetCache::get_rootfs(config.rootfs_path.as_path())?;
                validate_initrd_image(&rootfs_bytes)?;
                let rootfs_asset_elapsed = rootfs_asset_started_at.elapsed();
                create_vm_profile.rootfs_asset_read = rootfs_asset_elapsed;
                #[cfg(any(debug_assertions, feature = "boot-profile"))]
                boot_profile.add_rootfs_load_duration(rootfs_asset_started_at);
                (kernel_bytes, rootfs_bytes)
            }
            BackendCreateMode::SnapshotRestore => (
                Arc::<[u8]>::from(Vec::<u8>::new()),
                Arc::<[u8]>::from(Vec::<u8>::new()),
            ),
        };
        let mut vcpus = Vec::with_capacity(usize::from(config.vcpu_count));
        let vcpu_create_started_at = Instant::now();
        for vcpu_index in 0..u64::from(config.vcpu_count) {
            let vcpu = vm_fd.create_vcpu(vcpu_index).map_err(to_backend_error)?;
            vcpus.push(vcpu);
        }
        let vcpu_creation_elapsed = vcpu_create_started_at.elapsed();
        create_vm_profile.vcpu_creation = vcpu_creation_elapsed;
        restore_profile.vcpu_creation = vcpu_creation_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        boot_profile.add_vcpu_create_duration(vcpu_create_started_at);

        let mut backend = Self {
            base_config,
            config,
            kvm,
            vm_fd,
            vcpus,
            guest_memory,
            kernel_bytes,
            rootfs_bytes,
            transport: KvmTransport::Serial,
            lifecycle: KvmLifecycle::Created,
            last_command_payload: Vec::new(),
            loaded_kernel: LoadedKernel {
                entry_point: 0,
                high_watermark: 0,
            },
            boot_params_addr: ZERO_PAGE_ADDR,
            cmdline_addr: CMDLINE_ADDR,
            initrd_addr: 0,
            guest_booted: false,
            guest_ready: false,
            serial_device: SerialDevice::default(),
            vsock_device: if VSOCK_TRANSPORT_ENABLED {
                Some(VsockMmioDevice::new(3, VSOCK_MMIO_BASE, VSOCK_GSI))
            } else {
                None
            },
            vsock_channel: None,
            serial_buffer: Vec::new(),
            last_exit_reason: None,
            last_io_detail: None,
            recent_io_details: VecDeque::with_capacity(16),
            create_vm_profile: None,
            pending_restore_profile: None,
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            boot_profile,
        };
        let memory_register_started_at = Instant::now();
        backend.register_guest_memory()?;
        let memory_register_elapsed = memory_register_started_at.elapsed();
        create_vm_profile.kvm_set_user_memory_region = memory_register_elapsed;
        restore_profile.kvm_set_user_memory_region = memory_register_elapsed;
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        {
            backend
                .boot_profile
                .add_memory_register_duration(memory_register_started_at);
            backend.boot_profile.mark_memory_setup();
        }

        if mode == BackendCreateMode::ColdStart {
            let kernel_load_started_at = Instant::now();
            backend.load_kernel()?;
            create_vm_profile.kernel_elf_load = kernel_load_started_at.elapsed();
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            {
                backend
                    .boot_profile
                    .add_kernel_load_duration(kernel_load_started_at);
                backend.boot_profile.mark_kernel_load();
            }

            let rootfs_load_started_at = Instant::now();
            backend.load_initrd()?;
            create_vm_profile.rootfs_write = rootfs_load_started_at.elapsed();
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            {
                backend
                    .boot_profile
                    .add_rootfs_load_duration(rootfs_load_started_at);
                backend.boot_profile.mark_rootfs_load();
            }

            let boot_params_started_at = Instant::now();
            backend.write_boot_params()?;
            #[cfg(test)]
            backend.load_rootfs_metadata()?;
            create_vm_profile.boot_params = boot_params_started_at.elapsed();
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            backend
                .boot_profile
                .add_boot_params_duration(boot_params_started_at);

            create_vm_profile.create_vm_total = create_started_at.elapsed();
            backend.create_vm_profile = Some(create_vm_profile);
        } else {
            backend.pending_restore_profile = Some(restore_profile);
        }

        backend.lifecycle = KvmLifecycle::Ready;
        Ok(backend)
    }

    fn register_guest_memory(&self) -> Result<(), MicrovmError> {
        let host_addr = self
            .guest_memory
            .get_host_address(GuestAddress(0))
            .map_err(to_backend_error)? as u64;
        let memory_size = u64::try_from(self.config.memory_bytes()?).map_err(|_| {
            MicrovmError::Backend("guest memory size cannot be converted to u64".into())
        })?;
        let memory_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size,
            userspace_addr: host_addr,
            flags: 0,
        };

        // SAFETY: `userspace_addr` comes from the contiguous mapping currently owned by
        // `GuestMemoryMmap`. `guest_memory` lives for the entire `KvmBackend`, and this
        // only registers one non-overlapping slot 0.
        unsafe {
            self.vm_fd
                .set_user_memory_region(memory_region)
                .map_err(to_backend_error)?;
        }
        Ok(())
    }

    /// Returns accumulated serial output.
    pub fn serial_output(&self) -> &[u8] {
        &self.serial_buffer
    }

    /// Returns whether the guest has reached the READY state.
    pub fn is_guest_ready(&self) -> bool {
        self.lifecycle == KvmLifecycle::Ready && self.guest_ready
    }

    /// Probes through serial `PING\n`/`PONG\n` to check whether the guest command loop is responsive.
    pub fn ping(&mut self) -> Result<Duration, MicrovmError> {
        self.ping_with_timeout(Duration::from_secs(READINESS_PROBE_TIMEOUT_SECS))
    }

    pub(crate) fn ping_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Duration, MicrovmError> {
        let span = tracing::info_span!("vm_ping");
        let _entered = span.enter();

        if timeout.is_zero() {
            return Err(MicrovmError::InvalidConfig(
                "ping timeout must not be zero".into(),
            ));
        }
        self.ensure_guest_ready()?;
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle(
                "KVM backend is not in Ready state".into(),
            ));
        }

        let started_at = Instant::now();
        let payload = encode_ping_payload();
        self.serial_device.queue_input(&payload);
        self.lifecycle = KvmLifecycle::Running;

        let result = self.run_until_pong(timeout);
        if self.lifecycle != KvmLifecycle::Destroyed {
            self.lifecycle = KvmLifecycle::Ready;
        }

        result.map(|()| {
            let duration = started_at.elapsed();
            info!(elapsed = ?duration, "readiness probe 完成");
            duration
        })
    }

    /// Clears host-side state that must not leak into the next pooled checkout.
    pub fn clear_pool_artifacts(&mut self) {
        self.serial_buffer.clear();
        self.last_command_payload.clear();
        self.last_exit_reason = None;
        self.last_io_detail = None;
        self.recent_io_details.clear();
    }

    fn drop_vsock_channel(&mut self) {
        self.vsock_channel = None;
        self.transport = KvmTransport::Serial;
    }

    fn emit_create_vm_profile(&mut self) {
        let Some(profile) = self.create_vm_profile.take() else {
            return;
        };

        info!(
            total = ?profile.create_vm_total,
            cold_start_total = ?profile.cold_start_total(),
            boot_wait = ?profile.boot_wait,
            "[create_vm] 性能概览"
        );
        info!(
            kvm_fd_open = ?profile.kvm_fd_open,
            kvm_create_vm = ?profile.kvm_create_vm,
            arch_setup = ?profile.vm_arch_setup,
            "[create_vm] KVM 初始化耗时"
        );
        info!(
            guest_memory_mmap = ?profile.guest_memory_mmap,
            kernel_elf_load = ?profile.kernel_elf_load,
            rootfs_write = ?profile.rootfs_write,
            "[create_vm] guest 资源加载耗时"
        );
        info!(
            kvm_set_user_memory_region = ?profile.kvm_set_user_memory_region,
            vcpu_creation = ?profile.vcpu_creation,
            "[create_vm] 内存注册与 vCPU 创建耗时"
        );
        info!(
            vcpu_register_config = ?profile.vcpu_register_config,
            cpuid_config = ?profile.cpuid_config,
            boot_params = ?profile.boot_params,
            "[create_vm] vCPU 与启动参数配置耗时"
        );
        info!(
            kernel = ?profile.kernel_asset_read,
            rootfs = ?profile.rootfs_asset_read,
            create_vm_misc = ?profile.create_vm_misc(),
            "[create_vm] 资产读取与其他耗时"
        );
    }

    pub(crate) fn take_or_seed_restore_profile(&mut self) -> RestoreProfile {
        if let Some(profile) = self.pending_restore_profile.take() {
            return profile;
        }

        let mut profile = RestoreProfile::default();
        if let Some(create_vm_profile) = self.create_vm_profile.take() {
            profile.kvm_fd_open = create_vm_profile.kvm_fd_open;
            profile.kvm_create_vm = create_vm_profile.kvm_create_vm;
            profile.vm_arch_setup = create_vm_profile.vm_arch_setup;
            profile.guest_memory_mmap = create_vm_profile.guest_memory_mmap;
            profile.kvm_set_user_memory_region = create_vm_profile.kvm_set_user_memory_region;
            profile.vcpu_creation = create_vm_profile.vcpu_creation;
        }
        profile
    }

    pub(crate) fn emit_restore_profile_without_resume(&self, profile: &RestoreProfile) {
        info!(
            total_without_resume = ?profile.total_without_resume(),
            "[snapshot-restore] 恢复性能概览"
        );
        info!(
            kvm_fd_open = ?profile.kvm_fd_open,
            kvm_create_vm = ?profile.kvm_create_vm,
            arch_setup = ?profile.vm_arch_setup,
            "[snapshot-restore] KVM 初始化耗时"
        );
        info!(
            guest_memory_mmap = ?profile.guest_memory_mmap,
            kvm_set_user_memory_region = ?profile.kvm_set_user_memory_region,
            vcpu_creation = ?profile.vcpu_creation,
            "[snapshot-restore] 内存注册与 vCPU 创建耗时"
        );
        info!(
            memory_state_write = ?profile.memory_state_write,
            cpuid_config = ?profile.cpuid_config,
            "[snapshot-restore] 内存状态与 CPUID 恢复耗时"
        );
        info!(
            vcpu_state_restore = ?profile.vcpu_state_restore,
            device_state_restore = ?profile.device_state_restore,
            "[snapshot-restore] vCPU 与设备状态恢复耗时"
        );
        info!(
            resume_kvm_run = "待首个 KVM_RUN 实测",
            "[snapshot-restore] KVM_RUN 恢复耗时待测"
        );
    }

    fn finish_restore_resume_profile(&mut self, resume_kvm_run: Duration) {
        let Some(mut profile) = self.pending_restore_profile.take() else {
            return;
        };
        if profile.resume_kvm_run.is_some() {
            self.pending_restore_profile = Some(profile);
            return;
        }
        profile.resume_kvm_run = Some(resume_kvm_run);
        info!(
            resume_kvm_run = ?resume_kvm_run,
            total_with_resume = ?profile.total_with_resume(),
            "[snapshot-restore] KVM_RUN 恢复完成"
        );
    }

    /// Initializes vCPU boot registers and enters the real `KVM_RUN` loop.
    pub fn boot(&mut self) -> Result<KvmExitReason, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle(
                "KVM backend is not in Ready state".into(),
            ));
        }
        if self.guest_ready {
            return Ok(KvmExitReason::Io);
        }

        self.lifecycle = KvmLifecycle::Running;
        let exit_reason: Result<KvmExitReason, MicrovmError> = (|| {
            if !self.guest_booted {
                #[cfg(any(debug_assertions, feature = "boot-profile"))]
                let vcpu_config_started_at = Instant::now();
                let vcpu_setup = self.configure_boot_vcpus()?;
                if let Some(profile) = self.create_vm_profile.as_mut() {
                    profile.vcpu_register_config = vcpu_setup.register_config;
                    profile.cpuid_config = vcpu_setup.cpuid_config;
                }
                #[cfg(any(debug_assertions, feature = "boot-profile"))]
                {
                    self.boot_profile
                        .add_vcpu_config_duration(vcpu_config_started_at);
                    self.boot_profile.mark_vcpu_setup();
                }
            }
            let boot_wait_started_at = Instant::now();
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            self.boot_profile.mark_boot_start();
            let exit_reason = self.run_until_boot_ready()?;
            if let Some(profile) = self.create_vm_profile.as_mut() {
                profile.boot_wait = boot_wait_started_at.elapsed();
            }
            Ok(exit_reason)
        })();
        self.lifecycle = KvmLifecycle::Ready;
        let exit_reason = exit_reason?;
        self.guest_booted = true;
        self.guest_ready = exit_reason == KvmExitReason::Io;
        if self.guest_ready {
            self.emit_create_vm_profile();
        }
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        if self.guest_ready {
            log_boot_profile(&mut self.boot_profile);
        }
        Ok(exit_reason)
    }

    /// Loads the kernel image into guest memory according to ELF `PT_LOAD` segments.
    pub fn load_kernel(&mut self) -> Result<(), MicrovmError> {
        debug!(
            bytes = self.kernel_bytes.len(),
            "按 ELF 装载 guest 内核镜像"
        );

        let entry_point = read_u64_at(&self.kernel_bytes, 24)?;
        let phoff = usize_from_u64(read_u64_at(&self.kernel_bytes, 32)?)?;
        let phentsize = usize::from(read_u16_at(&self.kernel_bytes, 54)?);
        let phnum = usize::from(read_u16_at(&self.kernel_bytes, 56)?);

        validate_elf_header(&self.kernel_bytes, phoff, phentsize, phnum)?;

        let mut loaded_segment = false;
        let mut high_watermark = 0u64;
        for index in 0..phnum {
            let ph_start = phoff
                .checked_add(index.checked_mul(phentsize).ok_or_else(|| {
                    MicrovmError::Backend("ELF program header offset calculation overflow".into())
                })?)
                .ok_or_else(|| {
                    MicrovmError::Backend("ELF program header offset calculation overflow".into())
                })?;
            let ph = checked_slice(&self.kernel_bytes, ph_start, phentsize)?;
            let program_type = read_u32_at(ph, 0)?;
            if program_type != PT_LOAD {
                continue;
            }

            let file_offset = usize_from_u64(read_u64_at(ph, 8)?)?;
            let guest_addr = {
                let physical = read_u64_at(ph, 24)?;
                if physical == 0 {
                    read_u64_at(ph, 16)?
                } else {
                    physical
                }
            };
            let file_size = usize_from_u64(read_u64_at(ph, 32)?)?;
            let mem_size = usize_from_u64(read_u64_at(ph, 40)?)?;
            if mem_size < file_size {
                return Err(MicrovmError::Backend(format!(
                    "ELF segment memsz is smaller than filesz: memsz={mem_size}, filesz={file_size}"
                )));
            }

            let segment_bytes = checked_slice(&self.kernel_bytes, file_offset, file_size)?;
            self.write_guest_bytes(guest_addr, segment_bytes)?;
            self.zero_guest_range(
                guest_addr
                    .checked_add(u64::try_from(file_size).map_err(|_| {
                        MicrovmError::Backend(
                            "ELF segment file size cannot be converted to u64".into(),
                        )
                    })?)
                    .ok_or_else(|| {
                        MicrovmError::Backend("ELF segment address calculation overflow".into())
                    })?,
                mem_size - file_size,
            )?;
            loaded_segment = true;
            high_watermark = high_watermark.max(
                guest_addr
                    .checked_add(u64::try_from(mem_size).map_err(|_| {
                        MicrovmError::Backend(
                            "ELF segment memory size cannot be converted to u64".into(),
                        )
                    })?)
                    .ok_or_else(|| {
                        MicrovmError::Backend("ELF segment address calculation overflow".into())
                    })?,
            );
        }

        if !loaded_segment {
            return Err(MicrovmError::Backend(
                "ELF image contains no loadable PT_LOAD segment".into(),
            ));
        }

        self.loaded_kernel = LoadedKernel {
            entry_point,
            high_watermark,
        };
        Ok(())
    }

    /// Loads the rootfs (initrd) into guest memory.
    fn load_initrd(&mut self) -> Result<(), MicrovmError> {
        let proposed = align_up(
            self.loaded_kernel
                .high_watermark
                .checked_add(0x20_0000)
                .ok_or_else(|| {
                    MicrovmError::Backend("initrd load address calculation overflow".into())
                })?,
            0x1000,
        )?;
        self.write_guest_bytes(proposed, &self.rootfs_bytes)?;
        self.initrd_addr = proposed;
        Ok(())
    }

    /// Builds the zero page / `boot_params` and writes command line and initrd metadata.
    fn write_boot_params(&mut self) -> Result<(), MicrovmError> {
        let mut cmdline = Self::default_cmdline().into_bytes();
        cmdline.push(0);
        self.write_guest_bytes(self.cmdline_addr, &cmdline)?;

        let mut zero_page = vec![0u8; ZERO_PAGE_LEN];
        zero_page[ZERO_PAGE_SENTINEL] = 0xff;
        zero_page[ZERO_PAGE_E820_ENTRIES] = 0;
        write_u16(&mut zero_page, SETUP_HDR_BOOT_FLAG, KERNEL_BOOT_FLAG_MAGIC)?;
        write_u32(&mut zero_page, SETUP_HDR_HEADER_MAGIC, KERNEL_HDR_MAGIC)?;
        zero_page[SETUP_HDR_TYPE_OF_LOADER] = 0xff;
        zero_page[SETUP_HDR_LOADFLAGS] = 0x80;
        write_u32(
            &mut zero_page,
            SETUP_HDR_KERNEL_ALIGNMENT,
            KERNEL_MIN_ALIGNMENT_BYTES,
        )?;
        write_u32(
            &mut zero_page,
            SETUP_HDR_CODE32_START,
            lower_u32(self.loaded_kernel.entry_point)?,
        )?;
        write_u32(
            &mut zero_page,
            SETUP_HDR_RAMDISK_IMAGE,
            lower_u32(self.initrd_addr)?,
        )?;
        write_u32(
            &mut zero_page,
            SETUP_HDR_RAMDISK_SIZE,
            u32_from_len(self.rootfs_bytes.len(), "initrd size exceeds u32 limit")?,
        )?;
        write_u32(
            &mut zero_page,
            SETUP_HDR_CMD_LINE_PTR,
            lower_u32(self.cmdline_addr)?,
        )?;
        write_u32(
            &mut zero_page,
            ZERO_PAGE_EXT_RAMDISK_IMAGE,
            upper_u32(self.initrd_addr)?,
        )?;
        write_u32(
            &mut zero_page,
            ZERO_PAGE_EXT_RAMDISK_SIZE,
            upper_u32(u64::try_from(self.rootfs_bytes.len()).map_err(|_| {
                MicrovmError::Backend("initrd size cannot be converted to u64".into())
            })?)?,
        )?;
        write_u32(
            &mut zero_page,
            ZERO_PAGE_EXT_CMD_LINE_PTR,
            upper_u32(self.cmdline_addr)?,
        )?;
        let memory_end = u64::try_from(self.config.memory_bytes()?).map_err(|_| {
            MicrovmError::Backend("guest memory size cannot be converted to u64".into())
        })?;
        let mut e820_entries = 0usize;

        if memory_end > 0 {
            let lowmem_size = memory_end.min(EBDA_START);
            if lowmem_size > 0 {
                encode_e820_entry(
                    &mut zero_page[ZERO_PAGE_E820_TABLE..ZERO_PAGE_E820_TABLE + E820_ENTRY_SIZE],
                    0,
                    lowmem_size,
                    E820_RAM,
                )?;
                e820_entries += 1;
            }
        }

        if memory_end > HIMEM_START {
            let start = ZERO_PAGE_E820_TABLE
                .checked_add(e820_entries.checked_mul(E820_ENTRY_SIZE).ok_or_else(|| {
                    MicrovmError::Backend("E820 offset calculation overflow".into())
                })?)
                .ok_or_else(|| MicrovmError::Backend("E820 offset calculation overflow".into()))?;
            encode_e820_entry(
                &mut zero_page[start..start + E820_ENTRY_SIZE],
                HIMEM_START,
                memory_end - HIMEM_START,
                E820_RAM,
            )?;
            e820_entries += 1;
        }

        zero_page[ZERO_PAGE_E820_ENTRIES] = u8::try_from(e820_entries)
            .map_err(|_| MicrovmError::Backend("E820 entry count exceeds u8 limit".into()))?;

        self.write_guest_bytes(self.boot_params_addr, &zero_page)
    }

    /// Writes rootfs metadata into guest memory so tests can verify the guest layout.
    #[cfg(test)]
    fn load_rootfs_metadata(&mut self) -> Result<(), MicrovmError> {
        let metadata = format!(
            "rootfs={};size={};initrd={:#x};cmdline={:#x};transport={:?}",
            self.config.rootfs_path.display(),
            self.rootfs_bytes.len(),
            self.initrd_addr,
            self.cmdline_addr,
            self.transport
        );
        self.write_guest_bytes(ROOTFS_METADATA_ADDR, metadata.as_bytes())
    }

    /// Prefers vsock when guest-vsock is explicitly enabled; otherwise defaults to the serial protocol.
    pub fn run_command(&mut self, cmd: &[String]) -> Result<GuestCommandResult, MicrovmError> {
        self.run_command_with_options(cmd, &GuestExecOptions::default())
    }

    /// Allows per-command environment and timeout overrides.
    pub fn run_command_with_options(
        &mut self,
        cmd: &[String],
        options: &GuestExecOptions,
    ) -> Result<GuestCommandResult, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle(
                "KVM backend is not in Ready state".into(),
            ));
        }
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig(
                "command must not be empty".into(),
            ));
        }

        self.ensure_guest_ready()?;
        self.ensure_vsock_channel_connected()?;

        let effective_timeout_secs = self.effective_command_timeout_secs(options.timeout)?;
        let guest_command = build_guest_command(cmd)?;
        self.last_command_payload = guest_command.as_bytes().to_vec();

        self.lifecycle = KvmLifecycle::Running;
        let use_vsock =
            self.vsock_channel.is_some() && options.env.is_empty() && options.timeout.is_none();
        let result = if use_vsock {
            match self.run_command_over_vsock(guest_command.as_bytes()) {
                Ok(result) => Ok(result),
                Err(err) => {
                    warn!(error = %err, "vsock 命令通道执行失败，回退串口协议");
                    self.drop_vsock_channel();
                    self.run_command_over_serial(cmd, &options.env, effective_timeout_secs)
                }
            }
        } else {
            self.run_command_over_serial(cmd, &options.env, effective_timeout_secs)
        };
        // A watchdog timeout marks the instance as Destroyed, so later code must not
        // accidentally write it back to Ready.
        if self.lifecycle != KvmLifecycle::Destroyed {
            self.lifecycle = KvmLifecycle::Ready;
        }
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        if self.boot_profile.host_logged && !self.boot_profile.guest_extension_logged {
            self.boot_profile.close_guest_capture();
        }
        result
    }

    /// Phase B streaming execution always uses the serial protocol to avoid semantic
    /// conflicts with the current vsock command channel.
    pub fn run_command_streaming(
        &mut self,
        cmd: &[String],
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        self.run_command_streaming_with_options(cmd, &GuestExecOptions::default())
    }

    pub fn run_command_streaming_with_options(
        &mut self,
        cmd: &[String],
        options: &GuestExecOptions,
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle(
                "KVM backend is not in Ready state".into(),
            ));
        }
        if cmd.is_empty() {
            return Err(MicrovmError::InvalidConfig(
                "command must not be empty".into(),
            ));
        }

        self.ensure_guest_ready()?;

        self.lifecycle = KvmLifecycle::Running;
        let effective_timeout_secs = self.effective_command_timeout_secs(options.timeout)?;
        let result =
            self.run_command_streaming_over_serial(cmd, &options.env, effective_timeout_secs);
        if self.lifecycle != KvmLifecycle::Destroyed {
            self.lifecycle = KvmLifecycle::Ready;
        }
        #[cfg(any(debug_assertions, feature = "boot-profile"))]
        if self.boot_profile.host_logged && !self.boot_profile.guest_extension_logged {
            self.boot_profile.close_guest_capture();
        }
        result
    }

    pub fn lifecycle(&self) -> KvmLifecycle {
        self.lifecycle
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle(
                "KVM backend is not in Ready state".into(),
            ));
        }

        self.ensure_guest_ready()?;
        if self
            .vsock_channel
            .as_ref()
            .is_some_and(|channel| channel.is_connected())
        {
            return Err(MicrovmError::Backend(
                "FS serial protocol does not support an established guest-vsock connection yet"
                    .into(),
            ));
        }

        let payload = encode_fs_read_payload(path)?;
        self.lifecycle = KvmLifecycle::Running;
        let result =
            self.run_fs_operation_over_serial(payload)
                .and_then(|fs_result| match fs_result.status {
                    0 => Ok(fs_result.data),
                    status => Err(fs_result_to_error(status, path)),
                });
        if self.lifecycle != KvmLifecycle::Destroyed {
            self.lifecycle = KvmLifecycle::Ready;
        }
        result
    }

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle(
                "KVM backend is not in Ready state".into(),
            ));
        }

        self.ensure_guest_ready()?;
        if self
            .vsock_channel
            .as_ref()
            .is_some_and(|channel| channel.is_connected())
        {
            return Err(MicrovmError::Backend(
                "FS serial protocol does not support an established guest-vsock connection yet"
                    .into(),
            ));
        }

        let payload = encode_fs_write_payload(path, data)?;
        self.lifecycle = KvmLifecycle::Running;
        let result =
            self.run_fs_operation_over_serial(payload)
                .and_then(|fs_result| match fs_result.status {
                    0 => Ok(()),
                    status => Err(fs_result_to_error(status, path)),
                });
        if self.lifecycle != KvmLifecycle::Destroyed {
            self.lifecycle = KvmLifecycle::Ready;
        }
        result
    }

    pub fn http_request(&mut self, request: HttpRequest) -> Result<HttpResponse, MicrovmError> {
        if self.lifecycle != KvmLifecycle::Ready {
            return Err(MicrovmError::Lifecycle(
                "KVM backend is not in Ready state".into(),
            ));
        }

        execute_http_request(&self.base_config, &request).map_err(Into::into)
    }

    fn run_command_over_vsock(&mut self, cmd: &[u8]) -> Result<GuestCommandResult, MicrovmError> {
        let channel = self
            .vsock_channel
            .as_ref()
            .ok_or_else(|| MicrovmError::Lifecycle("vsock command channel unavailable".into()))?;
        channel.send_command(cmd)?;
        let result = channel.recv_result()?;
        self.transport = KvmTransport::Vsock;
        Ok(result)
    }

    fn run_command_over_serial(
        &mut self,
        cmd: &[String],
        env: &HashMap<String, String>,
        timeout_secs: Option<u64>,
    ) -> Result<GuestCommandResult, MicrovmError> {
        let payload = encode_command_payload(cmd, env, timeout_secs)?;
        self.serial_device.queue_input(&payload);
        self.last_command_payload = payload;
        self.transport = KvmTransport::Serial;
        self.run_until_command_result(timeout_secs)
    }

    fn run_command_streaming_over_serial(
        &mut self,
        cmd: &[String],
        env: &HashMap<String, String>,
        timeout_secs: Option<u64>,
    ) -> Result<mpsc::Receiver<StreamEvent>, MicrovmError> {
        let guest_command = build_guest_command(cmd)?;
        let payload = encode_streaming_command_payload(&guest_command);
        let (stream_tx, stream_rx) = spawn_stream_event_forwarder();
        self.serial_device.queue_input(&payload);
        self.last_command_payload = payload;
        self.transport = KvmTransport::Serial;
        match self.run_until_command_stream(stream_tx.clone(), timeout_secs)? {
            StreamCommandOutcome::Completed => {}
            StreamCommandOutcome::RetryBlocking => {
                // Old guests may reject EXECS without consuming the full payload, so
                // clear any leftover serial input before falling back.
                self.serial_device.rx_fifo.clear();
                let payload = encode_command_payload(cmd, env, timeout_secs)?;
                self.serial_device.queue_input(&payload);
                self.last_command_payload = payload;
                let result = self.run_until_command_result(timeout_secs)?;
                emit_command_result_as_stream(&stream_tx, result);
            }
        }
        Ok(stream_rx)
    }

    fn effective_command_timeout_secs(
        &self,
        timeout_override: Option<Duration>,
    ) -> Result<Option<u64>, MicrovmError> {
        match timeout_override {
            Some(timeout) => {
                if timeout.is_zero() {
                    return Err(MicrovmError::InvalidConfig(
                        "per-command timeout must not be zero".into(),
                    ));
                }
                let millis = timeout.as_millis();
                let secs = millis.div_ceil(1000);
                let secs = u64::try_from(secs).map_err(|_| {
                    MicrovmError::InvalidConfig("per-command timeout exceeds u64 range".into())
                })?;
                Ok(Some(secs.max(1)))
            }
            None => Ok(self.base_config.timeout_secs),
        }
    }

    fn run_http_proxy_request(
        &mut self,
        request_id: u32,
        request: HttpRequest,
    ) -> Result<(), MicrovmError> {
        match execute_http_request(&self.base_config, &request) {
            Ok(response) => {
                self.queue_http_response_headers(request_id, &response)?;
                self.queue_http_response_body(request_id, &response.body)?;
                self.queue_http_response_end(request_id);
                Ok(())
            }
            Err(error) => {
                self.queue_http_response_error(request_id, &error);
                match error {
                    HttpProxyError::DeniedHost(_) => Ok(()),
                    other => {
                        warn!(
                            request_id,
                            method = request.method,
                            url = request.url,
                            error = %other,
                            "处理 guest HTTP 代理请求失败"
                        );
                        Ok(())
                    }
                }
            }
        }
    }

    fn queue_http_response_headers(
        &mut self,
        request_id: u32,
        response: &HttpResponse,
    ) -> Result<(), MicrovmError> {
        let payload = serde_json::json!({
            "status": response.status,
            "headers": response.headers,
            "body_len": response.body.len(),
            "truncated": false,
        });
        let payload = serde_json::to_vec(&payload).map_err(|err| {
            MicrovmError::Backend(format!("failed to serialize HTTP response headers: {err}"))
        })?;
        let mut frame = format!(
            "{SERIAL_HTTPRESP_HEADERS_PREFIX}{request_id}:{}:",
            payload.len()
        )
        .into_bytes();
        frame.extend_from_slice(&payload);
        frame.push(b'\n');
        self.serial_device.queue_input(&frame);
        Ok(())
    }

    fn queue_http_response_body(
        &mut self,
        request_id: u32,
        body: &[u8],
    ) -> Result<(), MicrovmError> {
        const HTTP_BODY_FRAME_BYTES: usize = 16 * 1024;

        for chunk in body.chunks(HTTP_BODY_FRAME_BYTES) {
            let mut frame =
                format!("{SERIAL_HTTPRESP_BODY_PREFIX}{request_id}:{}:", chunk.len()).into_bytes();
            frame.extend_from_slice(chunk);
            frame.push(b'\n');
            self.serial_device.queue_input(&frame);
        }
        Ok(())
    }

    fn queue_http_response_end(&mut self, request_id: u32) {
        let frame = format!("{SERIAL_HTTPRESP_END_PREFIX}{request_id}\n");
        self.serial_device.queue_input(frame.as_bytes());
    }

    fn queue_http_response_error(&mut self, request_id: u32, error: &HttpProxyError) {
        let message = error.to_string();
        let mut frame = format!(
            "{SERIAL_HTTPRESP_ERROR_PREFIX}{request_id}:{}:{}:",
            error.code(),
            message.len()
        )
        .into_bytes();
        frame.extend_from_slice(message.as_bytes());
        frame.push(b'\n');
        self.serial_device.queue_input(&frame);
    }

    fn run_fs_operation_over_serial(&mut self, payload: Vec<u8>) -> Result<FsResult, MicrovmError> {
        self.serial_device.queue_input(&payload);
        self.last_command_payload = payload;
        self.transport = KvmTransport::Serial;
        self.run_until_fs_result()
    }

    /// Exports the memory and vCPU state required for a snapshot.
    pub fn snapshot_state(&self) -> Result<(Vec<u8>, Vec<u8>), MicrovmError> {
        let memory = self.dump_guest_memory()?;
        let vcpu_state = encode_runtime_state(self)?;
        Ok((memory, vcpu_state))
    }

    pub(crate) fn snapshot_bytes(&self) -> Result<Vec<u8>, MicrovmError> {
        let (memory, vcpu_state) = self.snapshot_state()?;
        MicrovmSnapshot::new(
            self.base_config.clone(),
            self.config.clone(),
            memory,
            vcpu_state,
        )
        .snapshot()
    }

    pub(crate) fn snapshot_to_file(&self) -> Result<mimobox_core::SandboxSnapshot, MicrovmError> {
        let (memory, vcpu_state) = self.snapshot_state()?;
        MicrovmSnapshot::new(
            self.base_config.clone(),
            self.config.clone(),
            memory,
            vcpu_state,
        )
        .persist_to_files()
    }

    /// Restores guest memory and vCPU state from a snapshot.
    pub fn restore_state(&mut self, memory: &[u8], vcpu_state: &[u8]) -> Result<(), MicrovmError> {
        let _span = tracing::info_span!("vm_restore").entered();
        let mut restore_profile = self.take_or_seed_restore_profile();

        let restore_memory_started_at = Instant::now();
        self.restore_guest_memory(memory)?;
        restore_profile.memory_state_write = restore_memory_started_at.elapsed();

        restore_profile.cpuid_config = self.prepare_restored_vcpus()?;

        let runtime_restore_profile = restore_runtime_state(self, vcpu_state)?;
        restore_profile.vcpu_state_restore = runtime_restore_profile.vcpu_state_restore;
        restore_profile.device_state_restore = runtime_restore_profile.device_state_restore;
        self.lifecycle = KvmLifecycle::Ready;
        self.emit_restore_profile_without_resume(&restore_profile);
        self.pending_restore_profile = Some(restore_profile);
        Ok(())
    }

    /// Shuts down the VM and releases lifecycle state.
    pub fn shutdown(&mut self) -> Result<(), MicrovmError> {
        self.last_command_payload.clear();
        self.serial_device = SerialDevice::default();
        self.vsock_channel = None;
        self.guest_booted = false;
        self.guest_ready = false;
        self.transport = KvmTransport::Serial;
        self.lifecycle = KvmLifecycle::Destroyed;
        Ok(())
    }

    fn ensure_guest_ready(&mut self) -> Result<(), MicrovmError> {
        if self.lifecycle == KvmLifecycle::Destroyed {
            return Err(MicrovmError::Lifecycle(
                "KVM backend destroyed, cannot reuse guest state".into(),
            ));
        }
        if self.guest_ready {
            return Ok(());
        }

        let exit_reason = self.boot()?;
        if exit_reason != KvmExitReason::Io {
            return Err(MicrovmError::Backend(format!(
                "guest exited before entering command loop: {exit_reason:?}"
            )));
        }
        Ok(())
    }

    fn ensure_vsock_channel_connected(&mut self) -> Result<(), MicrovmError> {
        if !VSOCK_TRANSPORT_ENABLED {
            return Ok(());
        }

        let Some(channel) = self.vsock_channel.as_ref() else {
            return Ok(());
        };
        if channel.is_connected() {
            self.transport = KvmTransport::Vsock;
            return Ok(());
        }

        let mut line_buffer = Vec::new();
        let watchdog = self.start_watchdog(Duration::from_secs(VSOCK_ACCEPT_TIMEOUT_SECS))?;

        loop {
            let accept_result = match self.vsock_channel.as_mut() {
                Some(channel) => channel.accept_connection(Duration::ZERO),
                None => return Ok(()),
            };
            match accept_result {
                Ok(()) => {
                    let probe_result = match self.vsock_channel.as_ref() {
                        Some(channel) => channel
                            .probe_round_trip(Duration::from_millis(VSOCK_PROBE_TIMEOUT_MILLIS)),
                        None => Ok(()),
                    };
                    if let Err(err) = probe_result {
                        warn!(
                            error = %err,
                            timeout_ms = VSOCK_PROBE_TIMEOUT_MILLIS,
                            "guest vsock 已连接但数据面探针失败，回退串口协议"
                        );
                        self.drop_vsock_channel();
                        return Ok(());
                    }
                    self.transport = KvmTransport::Vsock;
                    return Ok(());
                }
                Err(MicrovmError::Io(err)) if err.kind() == std::io::ErrorKind::TimedOut => {}
                Err(err) => {
                    warn!(error = %err, "建立 guest vsock 连接失败，回退串口协议");
                    self.drop_vsock_channel();
                    return Ok(());
                }
            }

            match self.run_vcpu_step(&mut line_buffer, None, &watchdog) {
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io | KvmExitReason::Hlt)) => {}
                Ok(RunLoopOutcome::Exit(exit_reason)) => {
                    return Err(MicrovmError::Backend(format!(
                        "guest exited unexpectedly while waiting for vsock connection: {exit_reason:?}"
                    )));
                }
                Ok(RunLoopOutcome::ResponseDone(_)) => {
                    return Err(MicrovmError::Backend(
                        "protocol completion event received unexpectedly during vsock handshake"
                            .into(),
                    ));
                }
                Err(err) if watchdog.timed_out() => {
                    warn!(error = %err, "等待 guest vsock 连接超时，回退串口协议");
                    self.drop_vsock_channel();
                    return Ok(());
                }
                Err(err) => {
                    warn!(error = %err, "推进 guest 进入 vsock 命令循环失败，回退串口协议");
                    self.drop_vsock_channel();
                    return Ok(());
                }
            }
        }
    }

    fn start_watchdog(&mut self, timeout: Duration) -> Result<VcpuRunWatchdog, MicrovmError> {
        let vcpu = self
            .vcpus
            .first_mut()
            .ok_or_else(|| MicrovmError::Backend("at least one vCPU is required".into()))?;
        Ok(VcpuRunWatchdog::start(vcpu, timeout))
    }

    fn run_until_boot_ready(&mut self) -> Result<KvmExitReason, MicrovmError> {
        let mut line_buffer = Vec::new();
        let boot_timeout_secs = self
            .base_config
            .timeout_secs
            .unwrap_or(BOOT_READY_TIMEOUT_SECS)
            .max(BOOT_READY_TIMEOUT_SECS);
        let watchdog = self.start_watchdog(Duration::from_secs(boot_timeout_secs))?;

        loop {
            match self.run_vcpu_step(&mut line_buffer, None, &watchdog) {
                Ok(RunLoopOutcome::Exit(exit_reason)) => {
                    if exit_reason != KvmExitReason::Io {
                        return Ok(exit_reason);
                    }
                    if self.guest_ready {
                        return Ok(KvmExitReason::Io);
                    }
                }
                Ok(RunLoopOutcome::ResponseDone(_)) => {
                    return Err(MicrovmError::Backend(
                        "protocol completion event received unexpectedly during boot".into(),
                    ));
                }
                Err(err) if watchdog.timed_out() => {
                    return Err(MicrovmError::Backend(format!(
                        "guest boot timed out: {err}; last_exit={:?}; last_io={:?}; io_history={:?}; serial={}",
                        self.last_exit_reason,
                        self.last_io_detail,
                        self.recent_io_details,
                        preview_serial_output(&self.serial_buffer),
                    )));
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn run_until_command_result(
        &mut self,
        timeout_secs: Option<u64>,
    ) -> Result<GuestCommandResult, MicrovmError> {
        let mut line_buffer = Vec::new();
        let mut response = SerialResponseCollector::Command(CommandResponse::default());
        let watchdog = self.start_watchdog(Duration::from_secs(timeout_secs.unwrap_or(30)))?;

        loop {
            match self.run_vcpu_step(&mut line_buffer, Some(&mut response), &watchdog) {
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::Command(result))) => {
                    return Ok(result);
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::Fs(_))) => {
                    return Err(MicrovmError::Backend(
                        "unexpected FSRESULT frame during command execution".into(),
                    ));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::HttpRequest(frame))) => {
                    self.run_http_proxy_request(frame.id, frame.request)?;
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::PingPong)) => {
                    return Err(MicrovmError::Backend(
                        "unexpected PONG frame during command execution".into(),
                    ));
                }
                Ok(RunLoopOutcome::ResponseDone(
                    SerialProtocolResult::StreamStart(_)
                    | SerialProtocolResult::StreamStdout(_, _)
                    | SerialProtocolResult::StreamStderr(_, _)
                    | SerialProtocolResult::StreamEnd(_, _)
                    | SerialProtocolResult::StreamTimeout(_),
                )) => {
                    return Err(MicrovmError::Backend(
                        "STREAM frame received before streaming command execution path is enabled"
                            .into(),
                    ));
                }
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io)) => {}
                Ok(RunLoopOutcome::Exit(exit_reason)) => {
                    return Err(MicrovmError::Backend(format!(
                        "guest exited unexpectedly before returning EXIT frame: {exit_reason:?}"
                    )));
                }
                Err(_) if watchdog.timed_out() => {
                    self.guest_ready = false;
                    self.lifecycle = KvmLifecycle::Destroyed;
                    let SerialResponseCollector::Command(response) = &mut response else {
                        unreachable!("命令等待阶段必须使用命令响应收集器");
                    };
                    return Ok(GuestCommandResult {
                        stdout: std::mem::take(&mut response.stdout),
                        stderr: std::mem::take(&mut response.stderr),
                        exit_code: None,
                        timed_out: true,
                    });
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn run_until_pong(&mut self, timeout: Duration) -> Result<(), MicrovmError> {
        let mut line_buffer = Vec::new();
        let mut response = SerialResponseCollector::Command(CommandResponse::default());
        let watchdog = self.start_watchdog(timeout)?;

        loop {
            match self.run_vcpu_step(&mut line_buffer, Some(&mut response), &watchdog) {
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::PingPong)) => return Ok(()),
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::HttpRequest(frame))) => {
                    self.run_http_proxy_request(frame.id, frame.request)?;
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::Command(result))) => {
                    return Err(MicrovmError::Backend(format!(
                        "guest does not support PING readiness probe: exit_code={:?}, stdout={}",
                        result.exit_code,
                        String::from_utf8_lossy(&result.stdout),
                    )));
                }
                Ok(RunLoopOutcome::ResponseDone(
                    SerialProtocolResult::Fs(_)
                    | SerialProtocolResult::StreamStart(_)
                    | SerialProtocolResult::StreamStdout(_, _)
                    | SerialProtocolResult::StreamStderr(_, _)
                    | SerialProtocolResult::StreamEnd(_, _)
                    | SerialProtocolResult::StreamTimeout(_),
                )) => {
                    return Err(MicrovmError::Backend(
                        "unexpected protocol frame during readiness probe".into(),
                    ));
                }
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io | KvmExitReason::Hlt)) => {}
                Ok(RunLoopOutcome::Exit(exit_reason)) => {
                    return Err(MicrovmError::Backend(format!(
                        "guest exited unexpectedly before returning PONG: {exit_reason:?}"
                    )));
                }
                Err(err) if watchdog.timed_out() => {
                    self.guest_ready = false;
                    self.lifecycle = KvmLifecycle::Destroyed;
                    return Err(MicrovmError::Backend(format!(
                        "guest readiness probe timed out: {err}; serial={}",
                        preview_serial_output(&self.serial_buffer),
                    )));
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn run_until_command_stream(
        &mut self,
        stream_tx: mpsc::Sender<StreamEvent>,
        timeout_secs: Option<u64>,
    ) -> Result<StreamCommandOutcome, MicrovmError> {
        let mut line_buffer = Vec::new();
        let mut response = SerialResponseCollector::Command(CommandResponse::default());
        let watchdog = self.start_watchdog(Duration::from_secs(timeout_secs.unwrap_or(30)))?;
        let mut started = false;

        loop {
            match self.run_vcpu_step(&mut line_buffer, Some(&mut response), &watchdog) {
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamStart(0))) => {
                    started = true;
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamStart(stream_id))) => {
                    return Err(MicrovmError::Backend(format!(
                        "unexpected STREAM:START id, expected 0, got {stream_id}"
                    )));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamStdout(0, data))) => {
                    if !started {
                        return Err(MicrovmError::Backend(
                            "missing STREAM:START before STREAM:STDOUT".into(),
                        ));
                    }
                    let _ = stream_tx.send(StreamEvent::Stdout(data));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamStdout(
                    stream_id,
                    _,
                ))) => {
                    return Err(MicrovmError::Backend(format!(
                        "unexpected STREAM:STDOUT id, expected 0, got {stream_id}"
                    )));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamStderr(0, data))) => {
                    if !started {
                        return Err(MicrovmError::Backend(
                            "missing STREAM:START before STREAM:STDERR".into(),
                        ));
                    }
                    let _ = stream_tx.send(StreamEvent::Stderr(data));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamStderr(
                    stream_id,
                    _,
                ))) => {
                    return Err(MicrovmError::Backend(format!(
                        "unexpected STREAM:STDERR id, expected 0, got {stream_id}"
                    )));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamEnd(0, exit_code))) => {
                    if !started {
                        return Err(MicrovmError::Backend(
                            "missing STREAM:START before STREAM:END".into(),
                        ));
                    }
                    let _ = stream_tx.send(StreamEvent::Exit(exit_code));
                    return Ok(StreamCommandOutcome::Completed);
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamEnd(stream_id, _))) => {
                    return Err(MicrovmError::Backend(format!(
                        "unexpected STREAM:END id, expected 0, got {stream_id}"
                    )));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamTimeout(0))) => {
                    if !started {
                        return Err(MicrovmError::Backend(
                            "missing STREAM:START before STREAM:TIMEOUT".into(),
                        ));
                    }
                    let _ = stream_tx.send(StreamEvent::TimedOut);
                    return Ok(StreamCommandOutcome::Completed);
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::StreamTimeout(
                    stream_id,
                ))) => {
                    return Err(MicrovmError::Backend(format!(
                        "unexpected STREAM:TIMEOUT id, expected 0, got {stream_id}"
                    )));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::Command(result))) => {
                    if should_retry_stream_with_blocking_command(&result) {
                        return Ok(StreamCommandOutcome::RetryBlocking);
                    }
                    emit_command_result_as_stream(&stream_tx, result);
                    return Ok(StreamCommandOutcome::Completed);
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::HttpRequest(frame))) => {
                    self.run_http_proxy_request(frame.id, frame.request)?;
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::Fs(_))) => {
                    return Err(MicrovmError::Backend(
                        "unexpected FSRESULT frame during streaming execution".into(),
                    ));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::PingPong)) => {
                    return Err(MicrovmError::Backend(
                        "unexpected PONG frame during streaming execution".into(),
                    ));
                }
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io)) => {}
                Ok(RunLoopOutcome::Exit(exit_reason)) => {
                    return Err(MicrovmError::Backend(format!(
                        "guest exited unexpectedly before returning STREAM:END: {exit_reason:?}"
                    )));
                }
                Err(_) if watchdog.timed_out() => {
                    self.guest_ready = false;
                    self.lifecycle = KvmLifecycle::Destroyed;
                    let _ = stream_tx.send(StreamEvent::TimedOut);
                    return Ok(StreamCommandOutcome::Completed);
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn run_until_fs_result(&mut self) -> Result<FsResult, MicrovmError> {
        let mut line_buffer = Vec::new();
        let mut response = SerialResponseCollector::Fs;
        let watchdog = self.start_watchdog(Duration::from_secs(
            self.base_config.timeout_secs.unwrap_or(30),
        ))?;

        loop {
            match self.run_vcpu_step(&mut line_buffer, Some(&mut response), &watchdog) {
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::Fs(result))) => {
                    return Ok(result);
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::Command(_))) => {
                    return Err(MicrovmError::Backend(
                        "unexpected command result frame during file operation".into(),
                    ));
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::HttpRequest(frame))) => {
                    self.run_http_proxy_request(frame.id, frame.request)?;
                }
                Ok(RunLoopOutcome::ResponseDone(SerialProtocolResult::PingPong)) => {
                    return Err(MicrovmError::Backend(
                        "unexpected PONG frame during file operation".into(),
                    ));
                }
                Ok(RunLoopOutcome::ResponseDone(
                    SerialProtocolResult::StreamStart(_)
                    | SerialProtocolResult::StreamStdout(_, _)
                    | SerialProtocolResult::StreamStderr(_, _)
                    | SerialProtocolResult::StreamEnd(_, _)
                    | SerialProtocolResult::StreamTimeout(_),
                )) => {
                    return Err(MicrovmError::Backend(
                        "unexpected STREAM frame during file operation".into(),
                    ));
                }
                Ok(RunLoopOutcome::Exit(KvmExitReason::Io)) => {}
                Ok(RunLoopOutcome::Exit(exit_reason)) => {
                    return Err(MicrovmError::Backend(format!(
                        "guest exited unexpectedly before returning FSRESULT frame: {exit_reason:?}"
                    )));
                }
                Err(err) if watchdog.timed_out() => {
                    self.guest_ready = false;
                    self.lifecycle = KvmLifecycle::Destroyed;
                    return Err(MicrovmError::Backend(format!(
                        "guest file operation timed out: {err}; serial={}",
                        preview_serial_output(&self.serial_buffer),
                    )));
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn run_vcpu_step(
        &mut self,
        line_buffer: &mut Vec<u8>,
        response: Option<&mut SerialResponseCollector>,
        watchdog: &VcpuRunWatchdog,
    ) -> Result<RunLoopOutcome, MicrovmError> {
        let should_track_io_detail = response.is_some();
        let measure_restore_resume = self.pending_restore_profile.is_some();
        let restore_resume_started_at = measure_restore_resume.then(Instant::now);
        let run_result = {
            let vcpu = self
                .vcpus
                .first_mut()
                .ok_or_else(|| MicrovmError::Backend("at least one vCPU is required".into()))?;
            vcpu.run()
        };
        let outcome = (|| -> Result<RunLoopOutcome, MicrovmError> {
            let exit = match run_result {
                Ok(exit) => exit,
                Err(err) if watchdog.timed_out() => {
                    return Err(MicrovmError::Backend(format!(
                        "KVM_RUN interrupted by watchdog: {err}"
                    )));
                }
                Err(err) => return Err(to_backend_error(err)),
            };

            let serial_device = &mut self.serial_device;
            let serial_buffer = &mut self.serial_buffer;
            let guest_ready = &mut self.guest_ready;
            let last_exit_reason = &mut self.last_exit_reason;
            let last_io_detail = &mut self.last_io_detail;
            let recent_io_details = &mut self.recent_io_details;
            let vsock_device = &mut self.vsock_device;
            let vsock_channel = &mut self.vsock_channel;
            let guest_memory = &self.guest_memory;
            #[cfg(any(debug_assertions, feature = "boot-profile"))]
            let boot_profile = &mut self.boot_profile;

            match exit {
                VcpuExit::IoOut(port, data) if is_serial_port(port) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("serial out port={port:#x} size={}", data.len()),
                        );
                    }
                    #[cfg(any(debug_assertions, feature = "boot-profile"))]
                    let action = handle_serial_write(
                        serial_device,
                        serial_buffer,
                        guest_ready,
                        boot_profile,
                        port,
                        data,
                        line_buffer,
                        response,
                    )?;
                    #[cfg(not(any(debug_assertions, feature = "boot-profile")))]
                    let action = handle_serial_write(
                        serial_device,
                        serial_buffer,
                        guest_ready,
                        port,
                        data,
                        line_buffer,
                        response,
                    )?;
                    if let Some(result) = action {
                        return Ok(RunLoopOutcome::ResponseDone(result));
                    }
                    #[cfg(any(debug_assertions, feature = "boot-profile"))]
                    if boot_profile.host_logged
                        && !boot_profile.guest_extension_logged
                        && boot_profile.guest_command_loop_recorded()
                    {
                        log_guest_boot_profile_extension(boot_profile);
                    }
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::IoIn(port, data) if is_serial_port(port) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("serial in port={port:#x} size={}", data.len()),
                        );
                    }
                    handle_serial_read(serial_device, port, data)?;
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::MmioRead(addr, data) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("mmio read addr={addr:#x} size={}", data.len()),
                        );
                    }
                    // Check whether the access hits the vsock MMIO address range.
                    if let Some(ref vsock) = *vsock_device {
                        let base = vsock.mmio_base();
                        let size = vsock.mmio_size();
                        if addr >= base && addr < base.saturating_add(size) {
                            let offset = addr - base;
                            vsock.mmio_read(offset, data);
                            *last_exit_reason = Some(KvmExitReason::Io);
                            return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                        }
                    }
                    data.fill(0);
                    debug!(addr, size = data.len(), "guest 触发 MMIO 读退出");
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("mmio write addr={addr:#x} size={}", data.len()),
                        );
                    }
                    // Check whether the access hits the vsock MMIO address range.
                    if let Some(vsock) = vsock_device {
                        let base = vsock.mmio_base();
                        let size = vsock.mmio_size();
                        if addr >= base && addr < base.saturating_add(size) {
                            let offset = addr - base;
                            let action = vsock.mmio_write(offset, data);
                            if action == VsockMmioAction::Activated {
                                debug!(
                                    addr,
                                    "vsock 设备已激活（guest driver 设置 DRIVER_OK），开始激活 vhost 后端"
                                );
                                let queues = vsock.queues();
                                let cid = vsock.guest_cid();
                                let features = vsock.acked_features();
                                match activate_vhost_backend(queues, cid, features, guest_memory) {
                                    Ok(()) => {
                                        info!(guest_cid = cid, "vhost-vsock 后端激活成功");
                                        if vsock_channel.is_none() {
                                            match VsockCommandChannel::new() {
                                                Ok(channel) => {
                                                    *vsock_channel = Some(channel);
                                                }
                                                Err(err) => {
                                                    warn!(
                                                        guest_cid = cid,
                                                        error = %err,
                                                        "创建 host vsock 命令通道失败，继续回退串口"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        // A vhost activation failure must not block the guest;
                                        // degrade to MMIO data-plane emulation.
                                        tracing::warn!(
                                            guest_cid = cid,
                                            error = %err,
                                            "vhost-vsock 后端激活失败，降级为 MMIO 模拟"
                                        );
                                    }
                                }
                            }
                            *last_exit_reason = Some(KvmExitReason::Io);
                            return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                        }
                    }
                    debug!(addr, size = data.len(), "guest 触发 MMIO 写退出");
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::Hlt => {
                    *last_exit_reason = Some(KvmExitReason::Hlt);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Hlt))
                }
                VcpuExit::Shutdown => {
                    *last_exit_reason = Some(KvmExitReason::Shutdown);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Shutdown))
                }
                VcpuExit::InternalError => {
                    *last_exit_reason = Some(KvmExitReason::InternalError);
                    Err(MicrovmError::Backend(
                        "vCPU entered KVM_EXIT_INTERNAL_ERROR".into(),
                    ))
                }
                VcpuExit::IoOut(port, data) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("pio out port={port:#x} size={}", data.len()),
                        );
                    }
                    if !*guest_ready && is_boot_legacy_pio_port(port) {
                        *last_exit_reason = Some(KvmExitReason::Io);
                        return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                    }
                    if port == PCI_CONFIG_ADDRESS_REG {
                        debug!(port, size = data.len(), "忽略 PCI 配置地址写");
                        *last_exit_reason = Some(KvmExitReason::Io);
                        return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                    }
                    if port == I8042_COMMAND_REG && data.len() == 1 && data[0] == I8042_RESET_CMD {
                        *last_exit_reason = Some(KvmExitReason::Shutdown);
                        return Ok(RunLoopOutcome::Exit(KvmExitReason::Shutdown));
                    }
                    debug!(port, size = data.len(), "忽略非串口 PIO 写退出");
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                VcpuExit::IoIn(port, data) => {
                    if should_track_io_detail {
                        push_io_detail(
                            last_io_detail,
                            recent_io_details,
                            format!("pio in port={port:#x} size={}", data.len()),
                        );
                    }
                    if !*guest_ready && emulate_boot_legacy_pio_read(port, data) {
                        *last_exit_reason = Some(KvmExitReason::Io);
                        return Ok(RunLoopOutcome::Exit(KvmExitReason::Io));
                    }
                    match port {
                        I8042_PORT_B_REG if data.len() == 1 => data[0] = I8042_PORT_B_PIT_TICK,
                        I8042_COMMAND_REG if data.len() == 1 => data[0] = 0,
                        PCI_CONFIG_DATA_REG_START..=PCI_CONFIG_DATA_REG_END => data.fill(0xff),
                        _ => data.fill(0),
                    }
                    debug!(port, size = data.len(), "响应非串口 PIO 读退出");
                    *last_exit_reason = Some(KvmExitReason::Io);
                    Ok(RunLoopOutcome::Exit(KvmExitReason::Io))
                }
                other => {
                    *last_exit_reason = Some(KvmExitReason::InternalError);
                    Err(MicrovmError::Backend(format!(
                        "unhandled vCPU exit: {other:?}"
                    )))
                }
            }
        })();
        if let Some(started_at) = restore_resume_started_at {
            self.finish_restore_resume_profile(started_at.elapsed());
        }
        outcome
    }

    fn dump_guest_memory(&self) -> Result<Vec<u8>, MicrovmError> {
        let mut memory = vec![0u8; self.config.memory_bytes()?];
        self.guest_memory
            .read_slice(&mut memory, GuestAddress(0))
            .map_err(to_backend_error)?;
        Ok(memory)
    }

    /// Exports vCPU state while cloning shared guest memory for zero-copy fork.
    ///
    /// `GuestMemoryMmap` uses `Arc` internally, so cloning only increments the
    /// reference count without copying data. When the two KVM VM fds each register
    /// their own `KVM_SET_USER_MEMORY_REGION` pointing at the same mmap region,
    /// MAP_PRIVATE lets the kernel apply CoW to written pages, keeping memory changes
    /// isolated between the two VMs.
    #[cfg(feature = "zerocopy-fork")]
    pub(crate) fn snapshot_for_fork(&self) -> Result<(GuestMemoryMmap, Vec<u8>), MicrovmError> {
        let _span = tracing::info_span!("vm_fork").entered();
        let vcpu_state = encode_runtime_state(self)?;
        Ok((self.guest_memory.clone(), vcpu_state))
    }

    /// Zero-copy fork restore: registers the shared `GuestMemoryMmap` in the current
    /// VM's KVM slot.
    ///
    /// This replaces `restore_from_file_zerocopy`, skips file mmap, and directly
    /// reuses the existing mmap region. The new VM's `vm_fd` registers its own
    /// `KVM_SET_USER_MEMORY_REGION`, with `userspace_addr` pointing to the shared
    /// mapping. MAP_PRIVATE lets the kernel provide CoW isolation automatically.
    #[cfg(feature = "zerocopy-fork")]
    pub(crate) fn restore_from_shared_memory(
        &mut self,
        shared_memory: GuestMemoryMmap,
        vcpu_state: &[u8],
    ) -> Result<(), MicrovmError> {
        let _span = tracing::info_span!("vm_restore").entered();
        let old_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };
        // SAFETY: KVM defines `memory_size = 0` as unregistering the specified slot.
        // Slot 0 is the only guest memory region registered by this backend, and an
        // equally sized new mapping is registered immediately after unregistering it.
        unsafe {
            self.vm_fd
                .set_user_memory_region(old_region)
                .map_err(to_backend_error)?;
        }

        let host_addr = shared_memory
            .get_host_address(GuestAddress(0))
            .map_err(to_backend_error)? as u64;
        let memory_size = u64::try_from(self.config.memory_bytes()?)
            .map_err(|_| MicrovmError::Backend("memory size cannot be converted to u64".into()))?;

        let new_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size,
            userspace_addr: host_addr,
            flags: 0,
        };
        // SAFETY: `userspace_addr` comes from the shared `GuestMemoryMmap` mapping,
        // whose length matches `memory_size`. Old slot 0 was unregistered before
        // replacement, so there is no overlap. MAP_PRIVATE ensures KVM writes from
        // the two VMs trigger CoW and remain isolated.
        unsafe {
            self.vm_fd
                .set_user_memory_region(new_region)
                .map_err(to_backend_error)?;
        }

        self.guest_memory = shared_memory;

        let mut restore_profile = self.take_or_seed_restore_profile();
        let restore_memory_started_at = Instant::now();
        // Attach shared memory directly with no data copy.
        restore_profile.memory_state_write = restore_memory_started_at.elapsed();

        restore_profile.cpuid_config = self.prepare_restored_vcpus()?;
        let runtime_restore_profile = restore_runtime_state(self, vcpu_state)?;
        restore_profile.vcpu_state_restore = runtime_restore_profile.vcpu_state_restore;
        restore_profile.device_state_restore = runtime_restore_profile.device_state_restore;

        self.lifecycle = KvmLifecycle::Ready;
        self.emit_restore_profile_without_resume(&restore_profile);
        self.set_pending_restore_profile(restore_profile);
        Ok(())
    }

    pub(crate) fn restore_guest_memory(&self, memory: &[u8]) -> Result<(), MicrovmError> {
        let expected_len = self.config.memory_bytes()?;
        if memory.len() != expected_len {
            return Err(MicrovmError::SnapshotFormat(format!(
                "guest memory size mismatch: snapshot has {}, current has {}",
                memory.len(),
                expected_len
            )));
        }

        self.guest_memory
            .write_slice(memory, GuestAddress(0))
            .map_err(to_backend_error)
    }

    /// Zero-copy restore: maps the snapshot file directly as guest memory, replaces
    /// the current KVM memory region, and skips `write_slice` data copying.
    #[cfg(feature = "zerocopy-fork")]
    pub(crate) fn restore_from_file_zerocopy(
        &mut self,
        memory_path: &Path,
    ) -> Result<(), MicrovmError> {
        use std::fs::File;
        use vm_memory::{FileOffset, GuestRegionMmap, MmapRegion};

        let file = File::open(memory_path)?;
        let metadata = file.metadata()?;
        let file_size = usize::try_from(metadata.len()).map_err(|_| {
            MicrovmError::SnapshotFormat("snapshot file size exceeds usize range".into())
        })?;

        let expected_len = self.config.memory_bytes()?;
        if file_size != expected_len {
            return Err(MicrovmError::SnapshotFormat(format!(
                "guest memory file size mismatch: file has {}, expected {}",
                file_size, expected_len
            )));
        }

        let old_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };
        // SAFETY: KVM defines `memory_size = 0` as unregistering the specified slot.
        // Slot 0 is the only guest memory region registered by this backend, and an
        // equally sized new mapping is registered immediately after unregistering it.
        unsafe {
            self.vm_fd
                .set_user_memory_region(old_region)
                .map_err(to_backend_error)?;
        }

        let file_offset = FileOffset::new(file, 0);
        let region = MmapRegion::<()>::build(
            Some(file_offset),
            file_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_NORESERVE,
        )
        .map_err(|error| MicrovmError::Backend(format!("zero-copy mmap failed: {error}")))?;

        let guest_region = GuestRegionMmap::new(region, GuestAddress(0)).map_err(|error| {
            MicrovmError::Backend(format!("failed to create GuestRegionMmap: {error}"))
        })?;
        let new_guest_memory =
            GuestMemoryMmap::from_regions(vec![guest_region]).map_err(|error| {
                MicrovmError::Backend(format!("failed to create GuestMemoryMmap: {error}"))
            })?;

        let host_addr = new_guest_memory
            .get_host_address(GuestAddress(0))
            .map_err(to_backend_error)? as u64;
        let memory_size = u64::try_from(file_size)
            .map_err(|_| MicrovmError::Backend("memory size cannot be converted to u64".into()))?;

        let new_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size,
            userspace_addr: host_addr,
            flags: 0,
        };
        // SAFETY: `userspace_addr` comes from the new `GuestMemoryMmap` mapping, whose
        // length matches `memory_size`. Old slot 0 was unregistered before replacement,
        // so there is no overlapping region.
        unsafe {
            self.vm_fd
                .set_user_memory_region(new_region)
                .map_err(to_backend_error)?;
        }

        self.guest_memory = new_guest_memory;
        Ok(())
    }

    /// Restores guest memory from a snapshot file using mmap(MAP_PRIVATE).
    ///
    /// Compared with `restore_guest_memory`, which accepts `&[u8]`, this method maps
    /// the file directly and avoids allocating a `Vec<u8>` for the full snapshot file.
    #[cfg(all(target_os = "linux", not(feature = "zerocopy-fork")))]
    pub(crate) fn restore_from_file(&self, memory_path: &Path) -> Result<(), MicrovmError> {
        use std::fs::File;
        use std::os::unix::io::AsRawFd;

        let file = File::open(memory_path)?;
        let metadata = file.metadata()?;
        let file_size = usize::try_from(metadata.len()).map_err(|_| {
            MicrovmError::SnapshotFormat("snapshot file size exceeds usize range".into())
        })?;

        let expected_len = self.config.memory_bytes()?;
        if file_size != expected_len {
            return Err(MicrovmError::SnapshotFormat(format!(
                "guest memory file size mismatch: file has {}, expected {}",
                file_size, expected_len
            )));
        }

        // SAFETY: mmap(MAP_PRIVATE) maps the file into the process address space.
        // MAP_PRIVATE ensures writes do not affect the original file. File size has
        // been validated, and the mapping is released by the explicit munmap below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                file_size,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(MicrovmError::Io(std::io::Error::last_os_error()));
        }

        // SAFETY: mmap succeeded and returned a valid pointer, and `file_size` matches
        // the mapping length.
        let memory_slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, file_size) };

        let result = self
            .guest_memory
            .write_slice(memory_slice, GuestAddress(0))
            .map_err(to_backend_error);

        // SAFETY: `ptr` comes from mmap, and `file_size` is the length of that mapping.
        unsafe {
            libc::munmap(ptr, file_size);
        }

        result
    }

    fn write_guest_bytes(&self, guest_addr: u64, bytes: &[u8]) -> Result<(), MicrovmError> {
        self.guest_memory
            .write_slice(bytes, GuestAddress(guest_addr))
            .map_err(to_backend_error)
    }

    fn zero_guest_range(&self, guest_addr: u64, len: usize) -> Result<(), MicrovmError> {
        const ZEROES: [u8; 65536] = [0; 65536];
        let mut written = 0usize;
        while written < len {
            let chunk = ZEROES.len().min(len - written);
            let chunk_addr = guest_addr
                .checked_add(u64::try_from(written).map_err(|_| {
                    MicrovmError::Backend(
                        "guest memory zero offset cannot be converted to u64".into(),
                    )
                })?)
                .ok_or_else(|| {
                    MicrovmError::Backend("guest memory zero address calculation overflow".into())
                })?;
            self.write_guest_bytes(chunk_addr, &ZEROES[..chunk])?;
            written += chunk;
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn read_guest_bytes(&self, guest_addr: u64, len: usize) -> Result<Vec<u8>, MicrovmError> {
        let mut bytes = vec![0u8; len];
        self.guest_memory
            .read_slice(&mut bytes, GuestAddress(guest_addr))
            .map_err(to_backend_error)?;
        Ok(bytes)
    }

    #[allow(dead_code)]
    fn vcpu_count(&self) -> usize {
        self.vcpus.len()
    }

    #[allow(dead_code)]
    fn _vm_fd(&self) -> &VmFd {
        &self.vm_fd
    }

    #[allow(dead_code)]
    fn _kvm(&self) -> &Kvm {
        &self.kvm
    }
}

pub(crate) fn restore_runtime_state(
    backend: &mut KvmBackend,
    state: &[u8],
) -> Result<RuntimeRestoreProfile, MicrovmError> {
    let mut cursor = ByteCursor::new(state);
    let magic = cursor.read_exact(8)?;
    if magic == KVM_RUNTIME_STATE_MAGIC_V2 {
        return restore_runtime_state_v2(backend, &mut cursor);
    }
    if magic == KVM_RUNTIME_STATE_MAGIC_V3 {
        return restore_runtime_state_v3(backend, &mut cursor);
    }
    Err(MicrovmError::SnapshotFormat(
        "KVM runtime snapshot magic mismatch".into(),
    ))
}

fn fs_result_to_error(status: u8, path: &str) -> MicrovmError {
    match status {
        1 => MicrovmError::Backend(format!("guest file path error: {path}")),
        2 => MicrovmError::Backend(format!("guest file I/O error: {path}")),
        3 => MicrovmError::Backend(format!("guest file permission error: {path}")),
        4 => MicrovmError::Backend(format!("guest file out of space: {path}")),
        other => MicrovmError::Backend(format!(
            "guest returned unknown file status code {other}: {path}"
        )),
    }
}

fn encode_streaming_command_payload(command: &str) -> Vec<u8> {
    let mut frame = format!("{}0:{}:", SERIAL_EXECS_PREFIX, command.len()).into_bytes();
    frame.extend_from_slice(command.as_bytes());
    frame.push(b'\n');
    frame
}

fn spawn_stream_event_forwarder() -> (mpsc::Sender<StreamEvent>, mpsc::Receiver<StreamEvent>) {
    let (forward_tx, forward_rx) = mpsc::channel();
    let (stream_tx, stream_rx) = mpsc::sync_channel(32);
    thread::spawn(move || {
        while let Ok(event) = forward_rx.recv() {
            if stream_tx.send(event).is_err() {
                break;
            }
        }
    });
    (forward_tx, stream_rx)
}

fn emit_command_result_as_stream(
    stream_tx: &mpsc::Sender<StreamEvent>,
    result: GuestCommandResult,
) {
    if !result.stdout.is_empty() {
        let _ = stream_tx.send(StreamEvent::Stdout(result.stdout));
    }
    if !result.stderr.is_empty() {
        let _ = stream_tx.send(StreamEvent::Stderr(result.stderr));
    }
    if result.timed_out {
        let _ = stream_tx.send(StreamEvent::TimedOut);
    } else if let Some(exit_code) = result.exit_code {
        let _ = stream_tx.send(StreamEvent::Exit(exit_code));
    }
}

fn should_retry_stream_with_blocking_command(result: &GuestCommandResult) -> bool {
    if result.timed_out || !result.stderr.is_empty() {
        return false;
    }

    let stdout = result.stdout.as_slice();
    stdout == b"invalid command frame"
        || stdout == b"invalid EXECS frame"
        || stdout == b"invalid EXECS id"
        || stdout == b"unsupported command prefix"
}

fn validate_initrd_image(bytes: &[u8]) -> Result<(), MicrovmError> {
    if bytes.len() < GZIP_MAGIC.len() || bytes[..2] != GZIP_MAGIC {
        return Err(MicrovmError::Backend(
            "rootfs must be a gzip-compressed cpio initrd".into(),
        ));
    }
    Ok(())
}

fn validate_elf_header(
    bytes: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
) -> Result<(), MicrovmError> {
    if bytes.len() < 64 {
        return Err(MicrovmError::Backend(
            "kernel image too short to parse ELF header".into(),
        ));
    }
    if &bytes[..4] != b"\x7fELF" {
        return Err(MicrovmError::Backend(
            "kernel image is not ELF format".into(),
        ));
    }
    if bytes[4] != 2 {
        return Err(MicrovmError::Backend(
            "only 64-bit ELF vmlinux images are supported".into(),
        ));
    }
    if bytes[5] != 1 {
        return Err(MicrovmError::Backend(
            "only little-endian ELF vmlinux images are supported".into(),
        ));
    }

    let table_len = phentsize
        .checked_mul(phnum)
        .ok_or_else(|| MicrovmError::Backend("ELF program header table length overflow".into()))?;
    let _ = checked_slice(bytes, phoff, table_len)?;
    Ok(())
}

fn push_io_detail(
    last_io_detail: &mut Option<String>,
    recent_io_details: &mut VecDeque<String>,
    detail: String,
) {
    *last_io_detail = Some(detail.clone());
    if recent_io_details.len() == 16 {
        let _ = recent_io_details.pop_front();
    }
    recent_io_details.push_back(detail);
}

fn install_watchdog_signal_handler() {
    WATCHDOG_SIGNAL_HANDLER_INIT.call_once(|| {
        // SAFETY: This only registers a no-op signal handler to interrupt a blocking
        // `KVM_RUN`. The handler itself does not access shared state, allocate, or
        // interact with Rust stack objects.
        unsafe {
            libc::signal(
                WATCHDOG_SIGNAL,
                handle_watchdog_signal as *const () as libc::sighandler_t,
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::devices::CommandResponse;
    use super::devices::SERIAL_HTTP_REQUEST_PREFIX;
    #[cfg(any(debug_assertions, feature = "boot-profile"))]
    use super::{BootProfile, parse_guest_boot_time_line};
    #[cfg(target_arch = "x86_64")]
    use super::{
        CPUID_LEAF_KVM_FEATURES, CPUID_LEAF_KVM_SIGNATURE, CPUID_LEAF_TIMING_INFO,
        MSR_IA32_APICBASE, inject_hypervisor_timing_cpuid, tracked_msr_entries_template,
    };
    use super::{
        DEFAULT_CMDLINE, SerialFrame, SerialProtocolResult, devices::build_guest_exec_payload,
        encode_command_payload, encode_fs_read_payload, encode_fs_write_payload,
        encode_ping_payload, parse_serial_line, take_serial_frame,
    };
    #[cfg(target_arch = "x86_64")]
    use kvm_bindings::kvm_cpuid_entry2;
    use std::collections::HashMap;

    #[test]
    fn test_encode_command_payload_uses_length_prefixed_frame() {
        let command = vec!["/bin/echo".to_string(), "test".to_string()];

        let payload =
            encode_command_payload(&command, &HashMap::new(), None).expect("编码命令帧必须成功");

        assert!(payload.starts_with(b"EXEC:"));
        assert!(payload.ends_with(b"\n"));
        let payload_str = String::from_utf8(payload).expect("payload 必须是合法 UTF-8");
        // JSON format: {"cmd":"/bin/echo test"}
        assert!(
            payload_str.contains(r#""cmd""#),
            "payload 必须包含 cmd 字段: {payload_str}"
        );
        assert!(
            payload_str.contains("echo"),
            "payload 必须包含命令: {payload_str}"
        );
    }

    #[test]
    fn test_parse_ping_response() {
        let payload = encode_ping_payload();
        assert_eq!(payload, b"PING\n");

        let mut buffer = b"PONG\n".to_vec();
        let frame = take_serial_frame(&mut buffer)
            .expect("解析 PONG 行必须成功")
            .expect("PONG 行必须被识别");
        assert_eq!(frame, SerialFrame::Line("PONG".to_string()));
        assert!(buffer.is_empty(), "PONG 行被取出后缓冲区应清空");
    }

    #[test]
    fn test_build_guest_exec_payload_contains_env_and_timeout() {
        let command = vec!["/bin/echo".to_string(), "hello".to_string()];
        let env = HashMap::from([("MY_VAR".to_string(), "value".to_string())]);

        let payload =
            build_guest_exec_payload(&command, &env, Some(10)).expect("构建 EXEC 负载必须成功");

        assert!(
            payload.contains(r#""cmd""#),
            "payload 必须包含 cmd: {payload}"
        );
        assert!(payload.contains("echo"), "payload 必须包含命令: {payload}");
        assert!(payload.contains(r#""MY_VAR":"value""#));
        assert!(payload.contains(r#""timeout":10"#));
    }

    #[test]
    fn test_encode_fs_write_payload_preserves_raw_bytes() {
        let path = "/sandbox/raw.bin";
        let data = b"hello\nworld\x00tail";

        let payload = encode_fs_write_payload(path, data).expect("编码 FS:WRITE 必须成功");
        let header = format!("FS:WRITE:{}:{path}\n{}:", path.len(), data.len()).into_bytes();

        assert!(payload.starts_with(&header));
        assert!(payload.ends_with(b"\n"));
        assert!(
            payload.windows(data.len()).any(|window| window == data),
            "FS:WRITE 必须保留原始数据字节"
        );
    }

    #[test]
    fn test_take_serial_frame_parses_fsresult_with_raw_newline_bytes() {
        let expected = b"hello\nworld\x00tail".to_vec();
        let mut buffer = format!("FSRESULT:0:{}:", expected.len()).into_bytes();
        buffer.extend_from_slice(&expected);
        buffer.push(b'\n');

        let frame = take_serial_frame(&mut buffer)
            .expect("解析 FSRESULT 帧必须成功")
            .expect("FSRESULT 帧必须被识别");

        assert!(
            matches!(frame, SerialFrame::FsResult(ref result) if result.status == 0 && result.data == expected)
        );
        assert!(buffer.is_empty(), "完整帧被取出后缓冲区应清空");
    }

    #[test]
    fn test_take_serial_frame_parses_stream_stdout_with_raw_newline_bytes() {
        let expected = b"hello\nworld\x00tail".to_vec();
        let mut buffer = format!("STREAM:STDOUT:0:{}:", expected.len()).into_bytes();
        buffer.extend_from_slice(&expected);
        buffer.push(b'\n');

        let frame = take_serial_frame(&mut buffer)
            .expect("解析 STREAM:STDOUT 帧必须成功")
            .expect("STREAM:STDOUT 帧必须被识别");

        assert!(matches!(
            frame,
            SerialFrame::Stream(SerialProtocolResult::StreamStdout(0, ref data))
                if data == &expected
        ));
        assert!(buffer.is_empty(), "完整 STREAM 帧被取出后缓冲区应清空");
    }

    #[test]
    fn test_take_serial_frame_parses_stream_start_and_end() {
        let mut start_buffer = b"STREAM:START:7\n".to_vec();
        let start_frame = take_serial_frame(&mut start_buffer)
            .expect("解析 STREAM:START 帧必须成功")
            .expect("STREAM:START 帧必须被识别");
        assert_eq!(
            start_frame,
            SerialFrame::Stream(SerialProtocolResult::StreamStart(7))
        );
        assert!(start_buffer.is_empty(), "START 帧被取出后缓冲区应清空");

        let mut end_buffer = b"STREAM:END:7:-9\n".to_vec();
        let end_frame = take_serial_frame(&mut end_buffer)
            .expect("解析 STREAM:END 帧必须成功")
            .expect("STREAM:END 帧必须被识别");
        assert_eq!(
            end_frame,
            SerialFrame::Stream(SerialProtocolResult::StreamEnd(7, -9))
        );
        assert!(end_buffer.is_empty(), "END 帧被取出后缓冲区应清空");
    }

    #[test]
    fn test_take_serial_frame_parses_http_request() {
        let json = r#"{"method":"GET","url":"https://api.openai.com/v1/models","headers":{"authorization":"Bearer test"},"timeout_ms":1000,"max_response_bytes":2048}"#;
        let mut buffer =
            format!("{SERIAL_HTTP_REQUEST_PREFIX}7:{}:{json}\n", json.len()).into_bytes();

        let frame = take_serial_frame(&mut buffer)
            .expect("解析 HTTP:REQUEST 帧必须成功")
            .expect("HTTP:REQUEST 帧必须被识别");

        assert!(matches!(
            frame,
            SerialFrame::Stream(SerialProtocolResult::HttpRequest(ref request))
                if request.id == 7
                    && request.request.method == "GET"
                    && request.request.url == "https://api.openai.com/v1/models"
        ));
        assert!(
            buffer.is_empty(),
            "完整 HTTP:REQUEST 帧被取出后缓冲区应清空"
        );
    }

    #[test]
    fn test_encode_fs_read_payload_uses_length_prefixed_frame() {
        let path = "/sandbox/example.txt";
        let payload = encode_fs_read_payload(path).expect("编码 FS:READ 必须成功");
        let expected = format!("FS:READ:{}:{path}\n", path.len()).into_bytes();

        assert_eq!(payload, expected);
    }

    #[test]
    fn test_exit_code_124_is_not_mapped_to_timeout() {
        let mut response = CommandResponse::default();

        let result = parse_serial_line("EXIT:124", &mut response)
            .expect("解析 EXIT 帧必须成功")
            .expect("EXIT 帧必须产生命令结果");

        assert_eq!(result.exit_code, Some(124));
        assert!(!result.timed_out, "退出码 124 只能表示用户命令退出码");
        assert!(result.stdout.is_empty(), "纯 EXIT 帧不应携带 stdout");
        assert!(result.stderr.is_empty(), "纯 EXIT 帧不应携带 stderr");
    }

    #[test]
    fn test_exit_timeout_maps_to_timed_out_result() {
        let mut response = CommandResponse::default();

        let result = parse_serial_line("EXIT:TIMEOUT", &mut response)
            .expect("解析 EXIT:TIMEOUT 帧必须成功")
            .expect("EXIT:TIMEOUT 帧必须产生命令结果");

        assert_eq!(result.exit_code, None);
        assert!(result.timed_out, "EXIT:TIMEOUT 必须映射为超时");
    }

    #[test]
    fn test_parse_serial_output_separates_stdout_and_stderr() {
        let mut response = CommandResponse::default();

        assert!(
            parse_serial_line("OUTPUT:1:hello\\n", &mut response)
                .expect("解析 stdout OUTPUT 帧必须成功")
                .is_none(),
            "stdout OUTPUT 帧不应直接结束命令"
        );
        assert!(
            parse_serial_line("OUTPUT:2:warn\\tline", &mut response)
                .expect("解析 stderr OUTPUT 帧必须成功")
                .is_none(),
            "stderr OUTPUT 帧不应直接结束命令"
        );

        let result = parse_serial_line("EXIT:7", &mut response)
            .expect("解析 EXIT 帧必须成功")
            .expect("EXIT 帧必须产生命令结果");

        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.stdout, b"hello\n");
        assert_eq!(result.stderr, b"warn\tline");
    }

    #[test]
    fn test_parse_serial_output_legacy_frame_defaults_to_stdout() {
        let mut response = CommandResponse::default();

        assert!(
            parse_serial_line("OUTPUT:legacy\\nframe", &mut response)
                .expect("解析旧格式 OUTPUT 帧必须成功")
                .is_none(),
            "旧格式 OUTPUT 帧不应直接结束命令"
        );

        let result = parse_serial_line("EXIT:0", &mut response)
            .expect("解析 EXIT 帧必须成功")
            .expect("EXIT 帧必须产生命令结果");

        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, b"legacy\nframe");
        assert!(
            result.stderr.is_empty(),
            "旧格式 OUTPUT 帧默认应落到 stdout"
        );
    }

    #[test]
    fn test_default_cmdline_contains_boot_latency_toggles() {
        for token in [
            "pci=off",
            "8250.nr_uarts=1",
            "no_timer_check",
            "fastboot",
            "quiet",
            "rcupdate.rcu_expedited=1",
            "mitigations=off",
            "tsc=reliable",
            "nokaslr",
            "nomodule",
        ] {
            assert!(
                DEFAULT_CMDLINE.split_whitespace().any(|item| item == token),
                "默认 cmdline 必须包含 {token}"
            );
        }
    }

    #[cfg(any(debug_assertions, feature = "boot-profile"))]
    #[test]
    fn test_parse_guest_boot_time_line_records_known_stage() {
        let mut boot_profile = BootProfile::start();

        let consumed = parse_guest_boot_time_line("BOOT_TIME:ready:12345", &mut boot_profile);

        assert!(consumed, "BOOT_TIME 行必须被 host 剖析逻辑消费");
        assert_eq!(boot_profile.guest.ready_ns, Some(12345));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_inject_hypervisor_timing_cpuid_updates_signature_and_adds_timing_leaf() {
        let mut entries = vec![
            kvm_cpuid_entry2 {
                function: CPUID_LEAF_KVM_SIGNATURE,
                index: 0,
                eax: CPUID_LEAF_KVM_FEATURES,
                ebx: 1,
                ecx: 2,
                edx: 3,
                ..Default::default()
            },
            kvm_cpuid_entry2 {
                function: 0x1,
                index: 0,
                ..Default::default()
            },
        ];

        assert!(inject_hypervisor_timing_cpuid(&mut entries, 2_900_000, 0));

        let signature = entries
            .iter()
            .find(|entry| entry.function == CPUID_LEAF_KVM_SIGNATURE && entry.index == 0)
            .expect("必须保留 hypervisor 签名叶");
        assert_eq!(signature.eax, CPUID_LEAF_TIMING_INFO);
        assert_eq!(signature.ebx, 1);
        assert_eq!(signature.ecx, 2);
        assert_eq!(signature.edx, 3);

        let timing = entries
            .iter()
            .find(|entry| entry.function == CPUID_LEAF_TIMING_INFO && entry.index == 0)
            .expect("必须注入 timing leaf");
        assert_eq!(timing.eax, 2_900_000);
        assert_eq!(timing.ebx, 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_inject_hypervisor_timing_cpuid_adds_missing_signature_leaf() {
        let mut entries = vec![kvm_cpuid_entry2 {
            function: 0x1,
            index: 0,
            ..Default::default()
        }];

        assert!(inject_hypervisor_timing_cpuid(&mut entries, 1_234_567, 0));

        let signature = entries
            .iter()
            .find(|entry| entry.function == CPUID_LEAF_KVM_SIGNATURE && entry.index == 0)
            .expect("缺失签名叶时必须自动补齐");
        assert_eq!(signature.eax, CPUID_LEAF_TIMING_INFO);
        assert_eq!(signature.ebx, 0x4b4d_564b);
        assert_eq!(signature.ecx, 0x564b_4d56);
        assert_eq!(signature.edx, 0x0000_004d);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_tracked_msrs_include_apicbase() {
        assert!(
            tracked_msr_entries_template()
                .iter()
                .any(|entry| entry.index == MSR_IA32_APICBASE),
            "快照/恢复需要跟踪 APICBASE MSR"
        );
    }
}
