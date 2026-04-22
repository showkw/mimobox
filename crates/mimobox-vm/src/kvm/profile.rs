#![cfg(all(target_os = "linux", feature = "kvm"))]

use super::*;

#[cfg(any(debug_assertions, feature = "boot-profile"))]
#[derive(Debug, Clone, Default)]
pub(in crate::kvm) struct GuestBootProfile {
    pub(in crate::kvm) init_entry_ns: Option<u64>,
    pub(in crate::kvm) mounts_done_ns: Option<u64>,
    pub(in crate::kvm) uart_access_done_ns: Option<u64>,
    pub(in crate::kvm) init_ok_ns: Option<u64>,
    pub(in crate::kvm) ready_ns: Option<u64>,
    pub(in crate::kvm) command_loop_ns: Option<u64>,
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
impl GuestBootProfile {
    fn record(&mut self, stage: &str, timestamp_ns: u64) {
        match stage {
            "init_entry" => self.init_entry_ns = Some(timestamp_ns),
            "mounts_done" => self.mounts_done_ns = Some(timestamp_ns),
            "uart_access_done" => self.uart_access_done_ns = Some(timestamp_ns),
            "init_ok" => self.init_ok_ns = Some(timestamp_ns),
            "ready" => self.ready_ns = Some(timestamp_ns),
            "command_loop" => self.command_loop_ns = Some(timestamp_ns),
            _ => {}
        }
    }

    fn command_loop_recorded(&self) -> bool {
        self.command_loop_ns.is_some()
    }
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
#[derive(Debug, Clone, Default)]
pub(in crate::kvm) struct BootProfile {
    t_total_start: Option<Instant>,
    t_kvm_open: Option<Instant>,
    t_vm_create: Option<Instant>,
    t_memory_setup: Option<Instant>,
    t_kernel_load: Option<Instant>,
    t_rootfs_load: Option<Instant>,
    t_vcpu_setup: Option<Instant>,
    t_boot_start: Option<Instant>,
    t_boot_ready: Option<Instant>,
    t_total_end: Option<Instant>,
    memory_alloc_duration: Duration,
    memory_register_duration: Duration,
    kernel_load_duration: Duration,
    rootfs_load_duration: Duration,
    vcpu_create_duration: Duration,
    vcpu_config_duration: Duration,
    boot_params_duration: Duration,
    pub(in crate::kvm) guest: GuestBootProfile,
    pub(in crate::kvm) host_logged: bool,
    pub(in crate::kvm) guest_extension_logged: bool,
    capture_guest_boot_lines: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub(in crate::kvm) struct CreateVmProfile {
    pub(in crate::kvm) kvm_fd_open: Duration,
    pub(in crate::kvm) kvm_create_vm: Duration,
    pub(in crate::kvm) vm_arch_setup: Duration,
    pub(in crate::kvm) guest_memory_mmap: Duration,
    pub(in crate::kvm) kernel_asset_read: Duration,
    pub(in crate::kvm) rootfs_asset_read: Duration,
    pub(in crate::kvm) kernel_elf_load: Duration,
    pub(in crate::kvm) rootfs_write: Duration,
    pub(in crate::kvm) kvm_set_user_memory_region: Duration,
    pub(in crate::kvm) vcpu_creation: Duration,
    pub(in crate::kvm) vcpu_register_config: Duration,
    pub(in crate::kvm) cpuid_config: Duration,
    pub(in crate::kvm) boot_params: Duration,
    pub(in crate::kvm) create_vm_total: Duration,
    pub(in crate::kvm) boot_wait: Duration,
}

impl CreateVmProfile {
    pub(in crate::kvm) fn profiled_create_vm_total(&self) -> Duration {
        self.kvm_fd_open
            + self.kvm_create_vm
            + self.vm_arch_setup
            + self.guest_memory_mmap
            + self.kernel_asset_read
            + self.rootfs_asset_read
            + self.kernel_elf_load
            + self.rootfs_write
            + self.kvm_set_user_memory_region
            + self.vcpu_creation
            + self.boot_params
    }

    pub(in crate::kvm) fn create_vm_misc(&self) -> Duration {
        self.create_vm_total
            .checked_sub(self.profiled_create_vm_total())
            .unwrap_or_default()
    }

    pub(in crate::kvm) fn cold_start_total(&self) -> Duration {
        self.create_vm_total + self.cpuid_config + self.vcpu_register_config + self.boot_wait
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RestoreProfile {
    pub(crate) kvm_fd_open: Duration,
    pub(crate) kvm_create_vm: Duration,
    pub(crate) vm_arch_setup: Duration,
    pub(crate) guest_memory_mmap: Duration,
    pub(crate) kvm_set_user_memory_region: Duration,
    pub(crate) vcpu_creation: Duration,
    pub(crate) cpuid_config: Duration,
    pub(crate) memory_state_write: Duration,
    pub(crate) vcpu_state_restore: Duration,
    pub(crate) device_state_restore: Duration,
    pub(crate) resume_kvm_run: Option<Duration>,
}

impl RestoreProfile {
    pub(in crate::kvm) fn total_without_resume(&self) -> Duration {
        self.kvm_fd_open
            + self.kvm_create_vm
            + self.vm_arch_setup
            + self.guest_memory_mmap
            + self.kvm_set_user_memory_region
            + self.vcpu_creation
            + self.cpuid_config
            + self.memory_state_write
            + self.vcpu_state_restore
            + self.device_state_restore
    }

    pub(in crate::kvm) fn total_with_resume(&self) -> Duration {
        self.total_without_resume() + self.resume_kvm_run.unwrap_or_default()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(in crate::kvm) struct VcpuSetupProfile {
    pub(in crate::kvm) cpuid_config: Duration,
    pub(in crate::kvm) register_config: Duration,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RuntimeRestoreProfile {
    pub(crate) vcpu_state_restore: Duration,
    pub(crate) device_state_restore: Duration,
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
impl BootProfile {
    pub(in crate::kvm) fn start() -> Self {
        Self {
            t_total_start: Some(Instant::now()),
            capture_guest_boot_lines: true,
            ..Default::default()
        }
    }

    pub(in crate::kvm) fn mark_kvm_open(&mut self) {
        self.t_kvm_open = Some(Instant::now());
    }

    pub(in crate::kvm) fn mark_vm_create(&mut self) {
        self.t_vm_create = Some(Instant::now());
    }

    pub(in crate::kvm) fn mark_memory_setup(&mut self) {
        self.t_memory_setup = Some(Instant::now());
    }

    pub(in crate::kvm) fn mark_kernel_load(&mut self) {
        self.t_kernel_load = Some(Instant::now());
    }

    pub(in crate::kvm) fn mark_rootfs_load(&mut self) {
        self.t_rootfs_load = Some(Instant::now());
    }

    pub(in crate::kvm) fn mark_vcpu_setup(&mut self) {
        self.t_vcpu_setup = Some(Instant::now());
    }

    pub(in crate::kvm) fn mark_boot_start(&mut self) {
        self.t_boot_start = Some(Instant::now());
    }

    pub(in crate::kvm) fn mark_boot_ready(&mut self) {
        let now = Instant::now();
        self.t_boot_ready = Some(now);
        self.t_total_end = Some(now);
    }

    pub(in crate::kvm) fn add_vcpu_create_duration(&mut self, started_at: Instant) {
        self.vcpu_create_duration += started_at.elapsed();
    }

    pub(in crate::kvm) fn add_memory_alloc_duration(&mut self, started_at: Instant) {
        self.memory_alloc_duration += started_at.elapsed();
    }

    pub(in crate::kvm) fn add_memory_register_duration(&mut self, started_at: Instant) {
        self.memory_register_duration += started_at.elapsed();
    }

    pub(in crate::kvm) fn add_kernel_load_duration(&mut self, started_at: Instant) {
        self.kernel_load_duration += started_at.elapsed();
    }

    pub(in crate::kvm) fn add_rootfs_load_duration(&mut self, started_at: Instant) {
        self.rootfs_load_duration += started_at.elapsed();
    }

    pub(in crate::kvm) fn add_vcpu_config_duration(&mut self, started_at: Instant) {
        self.vcpu_config_duration += started_at.elapsed();
    }

    pub(in crate::kvm) fn add_boot_params_duration(&mut self, started_at: Instant) {
        self.boot_params_duration += started_at.elapsed();
    }

    pub(in crate::kvm) fn should_parse_guest_line(&self) -> bool {
        self.capture_guest_boot_lines
    }

    pub(in crate::kvm) fn record_guest_time(&mut self, stage: &str, timestamp_ns: u64) {
        self.guest.record(stage, timestamp_ns);
    }

    pub(in crate::kvm) fn close_guest_capture(&mut self) {
        self.capture_guest_boot_lines = false;
    }

    pub(in crate::kvm) fn host_total_duration(&self) -> Option<Duration> {
        duration_between(self.t_total_start, self.t_total_end)
    }

    pub(in crate::kvm) fn host_step_duration(
        &self,
        start: Option<Instant>,
        end: Option<Instant>,
    ) -> Option<Duration> {
        duration_between(start, end)
    }

    pub(in crate::kvm) fn memory_step_duration(&self) -> Duration {
        self.memory_alloc_duration + self.memory_register_duration
    }

    pub(in crate::kvm) fn kernel_step_duration(&self) -> Duration {
        self.kernel_load_duration
    }

    pub(in crate::kvm) fn rootfs_step_duration(&self) -> Duration {
        self.rootfs_load_duration
    }

    pub(in crate::kvm) fn vcpu_step_duration(&self) -> Duration {
        self.vcpu_create_duration + self.vcpu_config_duration
    }

    pub(in crate::kvm) fn guest_command_loop_recorded(&self) -> bool {
        self.guest.command_loop_recorded()
    }
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn duration_between(start: Option<Instant>, end: Option<Instant>) -> Option<Duration> {
    let start = start?;
    let end = end?;
    Some(end.saturating_duration_since(start))
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn format_duration(duration: Duration) -> String {
    if duration.as_millis() > 0 {
        return format!("{}ms", duration.as_millis());
    }
    if duration.as_micros() > 0 {
        return format!("{}us", duration.as_micros());
    }
    format!("{}ns", duration.as_nanos())
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn format_share(duration: Duration, total: Duration) -> String {
    if total.is_zero() {
        return "0.0%".to_string();
    }

    format!(
        "{:.1}%",
        duration.as_secs_f64() / total.as_secs_f64() * 100.0
    )
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn log_host_boot_profile_line(label: &str, duration: Duration, total: Duration) {
    info!(
        "[boot-profile] {:<12} {:>8} ({})",
        format!("{label}:"),
        format_duration(duration),
        format_share(duration, total)
    );
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
fn log_guest_boot_profile_line(label: &str, delta_ns: u64, total_ns: u64) {
    let delta = Duration::from_nanos(delta_ns);
    let total = Duration::from_nanos(total_ns);
    info!(
        "[boot-profile][guest] {:<16} +{:>8} (total {})",
        format!("{label}:"),
        format_duration(delta),
        format_duration(total)
    );
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
pub(in crate::kvm) fn parse_guest_boot_time_line(
    line: &str,
    boot_profile: &mut BootProfile,
) -> bool {
    let Some(payload) = line.strip_prefix(SERIAL_BOOT_TIME_PREFIX) else {
        return false;
    };
    let Some((stage, raw_ns)) = payload.split_once(':') else {
        debug!(line, "忽略格式非法的 guest BOOT_TIME 行");
        return true;
    };
    let Ok(timestamp_ns) = raw_ns.parse::<u64>() else {
        debug!(line, "忽略时间戳非法的 guest BOOT_TIME 行");
        return true;
    };

    boot_profile.record_guest_time(stage, timestamp_ns);
    true
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
pub(in crate::kvm) fn log_guest_boot_profile(boot_profile: &BootProfile) {
    let Some(init_entry_ns) = boot_profile.guest.init_entry_ns else {
        return;
    };

    let mut previous_ns = init_entry_ns;
    for (label, maybe_ns) in [
        ("init_entry", boot_profile.guest.init_entry_ns),
        ("mounts_done", boot_profile.guest.mounts_done_ns),
        ("uart_access", boot_profile.guest.uart_access_done_ns),
        ("init_ok", boot_profile.guest.init_ok_ns),
        ("ready", boot_profile.guest.ready_ns),
    ] {
        let Some(timestamp_ns) = maybe_ns else {
            continue;
        };
        let delta_ns = timestamp_ns.saturating_sub(previous_ns);
        let total_ns = timestamp_ns.saturating_sub(init_entry_ns);
        log_guest_boot_profile_line(label, delta_ns, total_ns);
        previous_ns = timestamp_ns;
    }
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
pub(in crate::kvm) fn log_guest_boot_profile_extension(boot_profile: &mut BootProfile) {
    let Some(init_entry_ns) = boot_profile.guest.init_entry_ns else {
        return;
    };
    let Some(command_loop_ns) = boot_profile.guest.command_loop_ns else {
        return;
    };
    let previous_ns = boot_profile
        .guest
        .ready_ns
        .or(boot_profile.guest.init_ok_ns)
        .or(boot_profile.guest.uart_access_done_ns)
        .or(boot_profile.guest.mounts_done_ns)
        .unwrap_or(init_entry_ns);
    let delta_ns = command_loop_ns.saturating_sub(previous_ns);
    let total_ns = command_loop_ns.saturating_sub(init_entry_ns);
    log_guest_boot_profile_line("command_loop", delta_ns, total_ns);
    boot_profile.guest_extension_logged = true;
    boot_profile.close_guest_capture();
}

#[cfg(any(debug_assertions, feature = "boot-profile"))]
pub(in crate::kvm) fn log_boot_profile(boot_profile: &mut BootProfile) {
    if boot_profile.host_logged {
        return;
    }

    let Some(total) = boot_profile.host_total_duration() else {
        return;
    };
    info!("[boot-profile] total:        {}", format_duration(total));

    let kvm_open = boot_profile
        .host_step_duration(boot_profile.t_total_start, boot_profile.t_kvm_open)
        .unwrap_or_default();
    let vm_create = boot_profile
        .host_step_duration(boot_profile.t_kvm_open, boot_profile.t_vm_create)
        .unwrap_or_default();
    let memory = boot_profile.memory_step_duration();
    let kernel_load = boot_profile.kernel_step_duration();
    let rootfs_load = boot_profile.rootfs_step_duration();
    let boot_params = boot_profile.boot_params_duration;
    let vcpu_setup = boot_profile.vcpu_step_duration();
    let boot_wait = boot_profile
        .host_step_duration(boot_profile.t_boot_start, boot_profile.t_boot_ready)
        .unwrap_or_default();
    let accounted = kvm_open
        + vm_create
        + memory
        + kernel_load
        + rootfs_load
        + boot_params
        + vcpu_setup
        + boot_wait;
    let host_misc = total.saturating_sub(accounted);

    log_host_boot_profile_line("kvm_open", kvm_open, total);
    log_host_boot_profile_line("vm_create", vm_create, total);
    log_host_boot_profile_line("memory", memory, total);
    log_host_boot_profile_line("kernel_load", kernel_load, total);
    log_host_boot_profile_line("rootfs_load", rootfs_load, total);
    log_host_boot_profile_line("boot_params", boot_params, total);
    log_host_boot_profile_line("vcpu_setup", vcpu_setup, total);
    log_host_boot_profile_line("boot_wait", boot_wait, total);
    if !host_misc.is_zero() {
        log_host_boot_profile_line("host_misc", host_misc, total);
    }

    log_guest_boot_profile(boot_profile);
    if boot_profile.guest_command_loop_recorded() {
        log_guest_boot_profile_extension(boot_profile);
    }

    boot_profile.host_logged = true;
}
