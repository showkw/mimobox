#![cfg(all(target_os = "linux", feature = "kvm"))]

//! vsock virtio MMIO device emulator.
//!
//! Implements register-level emulation for virtio MMIO spec v2 and bridges the guest
//! Linux virtio_mmio driver to the host vhost-vsock backend.
//!
//! Phase 1 only implements register emulation and state tracking without directly
//! operating the vhost backend. Phase 2 integrates the vhost-vsock backend: after the
//! guest driver sets DRIVER_OK, `activate_vhost_backend()` passes virtqueue
//! configuration to the kernel vhost subsystem, whose kernel thread handles the data plane.

use tracing::debug;
use vhost::vhost_kern::vsock::Vsock as VhostKernVsock;
use vhost::vsock::VhostVsock;
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{GuestMemory, GuestMemoryMmap};

// ============================================================================
// virtio MMIO register offsets (virtio MMIO spec v2)
// ============================================================================

/// 0x00: MagicValue, always returns "virt" (0x74726976).
const VIRTIO_MMIO_MAGIC_VALUE: u64 = 0x00;
/// 0x04: Version, returns 2 (virtio MMIO v2).
const VIRTIO_MMIO_VERSION: u64 = 0x04;
/// 0x08: DeviceID, returns 19 (VIRTIO_ID_VSOCK).
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x08;
/// 0x0c: VendorID, returns 0.
const VIRTIO_MMIO_VENDOR_ID: u64 = 0x0c;
/// 0x10: DeviceFeatures, returns the low/high 32 bits based on `features_select`.
const VIRTIO_MMIO_DEVICE_FEATURES: u64 = 0x10;
/// 0x14: DeviceFeaturesSel, writes the low/high 32-bit selector.
const VIRTIO_MMIO_DEVICE_FEATURES_SEL: u64 = 0x14;
/// 0x20: DriverFeatures
const VIRTIO_MMIO_DRIVER_FEATURES: u64 = 0x20;
/// 0x24: DriverFeaturesSel
const VIRTIO_MMIO_DRIVER_FEATURES_SEL: u64 = 0x24;
/// 0x30: QueueSel, selects queue 0-2.
const VIRTIO_MMIO_QUEUE_SEL: u64 = 0x30;
/// 0x34: QueueNumMax → 256
const VIRTIO_MMIO_QUEUE_NUM_MAX: u64 = 0x34;
/// 0x38: QueueNum
const VIRTIO_MMIO_QUEUE_NUM: u64 = 0x38;
/// 0x44: QueueReady
const VIRTIO_MMIO_QUEUE_READY: u64 = 0x44;
/// 0x50: QueueNotify, kicks the queue and triggers ioeventfd.
const VIRTIO_MMIO_QUEUE_NOTIFY: u64 = 0x50;
/// 0x60: InterruptStatus
const VIRTIO_MMIO_INTERRUPT_STATUS: u64 = 0x60;
/// 0x64: InterruptACK
const VIRTIO_MMIO_INTERRUPT_ACK: u64 = 0x64;
/// 0x70: Status, device status bits.
const VIRTIO_MMIO_STATUS: u64 = 0x70;
/// 0x80: QueueDescLow
const VIRTIO_MMIO_QUEUE_DESC_LOW: u64 = 0x80;
/// 0x84: QueueDescHigh
const VIRTIO_MMIO_QUEUE_DESC_HIGH: u64 = 0x84;
/// 0x90: QueueAvailLow
const VIRTIO_MMIO_QUEUE_AVAIL_LOW: u64 = 0x90;
/// 0x94: QueueAvailHigh
const VIRTIO_MMIO_QUEUE_AVAIL_HIGH: u64 = 0x94;
/// 0xa0: QueueUsedLow
const VIRTIO_MMIO_QUEUE_USED_LOW: u64 = 0xa0;
/// 0xa4: QueueUsedHigh
const VIRTIO_MMIO_QUEUE_USED_HIGH: u64 = 0xa4;
/// 0xfc: ConfigGeneration
const VIRTIO_MMIO_CONFIG_GENERATION: u64 = 0xfc;
/// 0x100: start of config space, stores guest_cid (u64).
const VIRTIO_MMIO_CONFIG: u64 = 0x100;

// ============================================================================
// virtio constants
// ============================================================================

/// virtio MMIO magic number: "virt" in little-endian ASCII
const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
/// virtio MMIO version 2.
const VIRTIO_MMIO_VERSION_V2: u32 = 2;
/// VIRTIO_ID_VSOCK = 19
const VIRTIO_ID_VSOCK: u32 = 19;
/// VIRTIO_F_VERSION_1: bit 32, indicates support for the virtio 1.0+ specification.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// DRIVER_OK status bit, set after the guest driver finishes initialization.
const VSOCK_DRIVER_OK: u8 = 0x4;
/// Maximum queue size.
const QUEUE_SIZE_MAX: u16 = 256;
/// vsock uses 3 virtqueues: rx=0, tx=1, event=2.
const NUM_QUEUES: usize = 3;
/// MMIO device address space size.
const VSOCK_MMIO_SIZE: u64 = 0x200;

// ============================================================================
// Helper functions for slice reads and writes
// ============================================================================

/// Reads a u32 from a byte slice in little-endian order.
/// Returns 0 if the slice has fewer than 4 bytes.
fn read_u32_from_slice(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Writes a u32 value into a byte slice in little-endian order.
/// Writes only min(4, data.len()) bytes.
fn write_u32_to_slice(val: u32, data: &mut [u8]) {
    let bytes = val.to_le_bytes();
    let len = 4.min(data.len());
    data[..len].copy_from_slice(&bytes[..len]);
}

/// Writes a u64 value into a byte slice in little-endian order.
/// Writes only min(8, data.len()) bytes.
fn write_u64_to_slice(val: u64, data: &mut [u8]) {
    let bytes = val.to_le_bytes();
    let len = 8.min(data.len());
    data[..len].copy_from_slice(&bytes[..len]);
}

// ============================================================================
// Public types
// ============================================================================

/// Action produced by a virtio MMIO write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::kvm) enum VsockMmioAction {
    /// No additional handling is required.
    None,
    /// The guest driver set DRIVER_OK and the vhost backend needs activation.
    Activated,
    /// An interrupt needs to be injected.
    Interrupt,
}

// ============================================================================
// Internal types
// ============================================================================

/// virtio queue configuration (descriptor table, available ring, and used ring addresses).
#[derive(Debug, Clone, Copy, Default)]
pub(in crate::kvm) struct VirtQueueConfig {
    /// Descriptor table address.
    desc_addr: u64,
    /// Available ring address.
    avail_addr: u64,
    /// Used ring address.
    used_addr: u64,
    /// Queue size, as the number of descriptors.
    size: u16,
    /// Whether the queue is ready.
    ready: bool,
}

// ============================================================================
// VsockMmioDevice
// ============================================================================

/// vsock MMIO device emulator.
///
/// Implements register-level emulation for virtio MMIO spec v2 and bridges the guest
/// Linux virtio_mmio driver to the host vhost-vsock backend.
///
/// Phase 1 only implements register emulation; Phase 2 integrates the vhost backend.
#[derive(Debug, Clone)]
pub(in crate::kvm) struct VsockMmioDevice {
    // virtio MMIO device state
    /// Device status byte, including ACKNOWLEDGE, DRIVER, DRIVER_OK, FAILED, and related bits.
    device_status: u8,
    /// Config generation, incremented on each configuration change.
    config_generation: u8,
    // feature negotiation
    /// Currently selected 32-bit half of device features (0=low 32 bits, 1=high 32 bits).
    features_select: u32,
    /// Feature bitmap acknowledged by the guest.
    acked_features: u64,
    /// Currently selected 32-bit half of driver features.
    driver_features_select: u32,
    /// Driver features write buffer used for feature negotiation.
    driver_features: u64,
    // queue management
    /// Currently selected queue index (0-2).
    queue_select: u16,
    /// Configuration for three virtqueues: rx=0, tx=1, event=2.
    queues: [VirtQueueConfig; NUM_QUEUES],
    // vsock device configuration
    /// Guest Context ID.
    guest_cid: u64,
    /// Whether the device has been activated by the guest driver.
    activated: bool,
    // MMIO mapping metadata
    /// Base address of the MMIO device in the guest physical address space.
    mmio_base: u64,
    /// Interrupt GSI assigned to this device.
    #[allow(dead_code)] // 通过 gsi() API 暴露，字段需要保留用于运行时设备元数据。
    gsi: u32,
}

impl VsockMmioDevice {
    /// Creates a new vsock MMIO device emulator.
    ///
    /// # Parameters
    /// - `guest_cid`: guest Context ID (vsock address), typically allocated starting at 3.
    /// - `mmio_base`: base address of the MMIO device in the guest physical address space.
    /// - `gsi`: interrupt GSI assigned to this device.
    pub(in crate::kvm) fn new(guest_cid: u64, mmio_base: u64, gsi: u32) -> Self {
        Self {
            device_status: 0,
            config_generation: 0,
            features_select: 0,
            acked_features: 0,
            driver_features_select: 0,
            driver_features: 0,
            queue_select: 0,
            queues: [VirtQueueConfig::default(); NUM_QUEUES],
            guest_cid,
            activated: false,
            mmio_base,
            gsi,
        }
    }

    /// Returns the base address of the MMIO device in the guest physical address space.
    pub(in crate::kvm) fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// Returns the MMIO device address space size.
    pub(in crate::kvm) fn mmio_size(&self) -> u64 {
        VSOCK_MMIO_SIZE
    }

    /// Returns the interrupt GSI assigned to this device.
    #[allow(dead_code)] // 作为设备完整 API 保留，当前仅测试路径直接使用。
    pub(in crate::kvm) fn gsi(&self) -> u32 {
        self.gsi
    }

    /// Returns whether the device has been activated by the guest driver by setting DRIVER_OK.
    #[allow(dead_code)] // 作为设备完整 API 保留，当前仅测试路径直接使用。
    pub(in crate::kvm) fn is_activated(&self) -> bool {
        self.activated
    }

    /// Returns the guest Context ID.
    pub(in crate::kvm) fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Returns a reference to all queue configurations.
    pub(in crate::kvm) fn queues(&self) -> &[VirtQueueConfig; NUM_QUEUES] {
        &self.queues
    }

    /// Returns the feature bitmap acknowledged by the guest.
    pub(in crate::kvm) fn acked_features(&self) -> u64 {
        self.acked_features
    }

    /// Handles a guest read from a vsock MMIO register.
    ///
    /// # Parameters
    /// - `offset`: offset relative to `mmio_base`.
    /// - `data`: output buffer receiving the read register value.
    pub(in crate::kvm) fn mmio_read(&self, offset: u64, data: &mut [u8]) {
        data.fill(0);

        let val = match offset {
            VIRTIO_MMIO_MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            VIRTIO_MMIO_VERSION => VIRTIO_MMIO_VERSION_V2,
            VIRTIO_MMIO_DEVICE_ID => VIRTIO_ID_VSOCK,
            VIRTIO_MMIO_VENDOR_ID => 0,
            VIRTIO_MMIO_DEVICE_FEATURES => {
                // Return the low or high 32 bits based on `features_select`.
                let features = self.device_features();
                match self.features_select {
                    0 => features as u32,
                    1 => (features >> 32) as u32,
                    _ => 0,
                }
            }
            VIRTIO_MMIO_QUEUE_NUM_MAX => QUEUE_SIZE_MAX as u32,
            VIRTIO_MMIO_QUEUE_READY => {
                let queue = self.selected_queue();
                if queue.ready { 1 } else { 0 }
            }
            VIRTIO_MMIO_INTERRUPT_STATUS => 0,
            VIRTIO_MMIO_STATUS => self.device_status as u32,
            VIRTIO_MMIO_QUEUE_DESC_LOW => {
                let queue = self.selected_queue();
                queue.desc_addr as u32
            }
            VIRTIO_MMIO_QUEUE_DESC_HIGH => {
                let queue = self.selected_queue();
                (queue.desc_addr >> 32) as u32
            }
            VIRTIO_MMIO_QUEUE_AVAIL_LOW => {
                let queue = self.selected_queue();
                queue.avail_addr as u32
            }
            VIRTIO_MMIO_QUEUE_AVAIL_HIGH => {
                let queue = self.selected_queue();
                (queue.avail_addr >> 32) as u32
            }
            VIRTIO_MMIO_QUEUE_USED_LOW => {
                let queue = self.selected_queue();
                queue.used_addr as u32
            }
            VIRTIO_MMIO_QUEUE_USED_HIGH => {
                let queue = self.selected_queue();
                (queue.used_addr >> 32) as u32
            }
            VIRTIO_MMIO_CONFIG_GENERATION => self.config_generation as u32,
            VIRTIO_MMIO_CONFIG.. => {
                // Config space: guest_cid (u64), starting at offset 0x100.
                let config_offset = offset - VIRTIO_MMIO_CONFIG;
                if config_offset < 8 {
                    write_u64_to_slice(self.guest_cid, data);
                    debug!(
                        offset,
                        guest_cid = self.guest_cid,
                        "vsock MMIO config read: guest_cid"
                    );
                    return;
                }
                debug!(offset, "vsock MMIO read: config-space offset out of range");
                return;
            }
            _ => {
                debug!(offset, "vsock MMIO read: unknown offset");
                return;
            }
        };

        write_u32_to_slice(val, data);
    }

    /// Handles a guest write to a vsock MMIO register.
    ///
    /// # Parameters
    /// - `offset`: offset relative to `mmio_base`.
    /// - `data`: data being written.
    ///
    /// # Returns
    /// The action triggered by the write.
    pub(in crate::kvm) fn mmio_write(&mut self, offset: u64, data: &[u8]) -> VsockMmioAction {
        match offset {
            VIRTIO_MMIO_DEVICE_FEATURES_SEL => {
                self.features_select = read_u32_from_slice(data);
                debug!(select = self.features_select, "vsock feature select write");
                VsockMmioAction::None
            }
            VIRTIO_MMIO_DRIVER_FEATURES => {
                let val = read_u32_from_slice(data) as u64;
                match self.driver_features_select {
                    0 => self.driver_features = (self.driver_features & !0xFFFF_FFFF) | val,
                    1 => self.driver_features = (self.driver_features & 0xFFFF_FFFF) | (val << 32),
                    _ => {}
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_DRIVER_FEATURES_SEL => {
                self.driver_features_select = read_u32_from_slice(data);
                debug!(
                    select = self.driver_features_select,
                    "vsock driver feature select write"
                );
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_SEL => {
                let val = read_u32_from_slice(data) as u16;
                if (val as usize) < NUM_QUEUES {
                    self.queue_select = val;
                    debug!(queue = val, "vsock queue select write");
                } else {
                    debug!(queue = val, "vsock queue select out of range, ignoring");
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_NUM => {
                let val = read_u32_from_slice(data) as u16;
                let qi = self.queue_select;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.size = val;
                    debug!(queue_index = qi, size = val, "vsock queue size write");
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_READY => {
                let val = read_u32_from_slice(data);
                let qi = self.queue_select;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.ready = val != 0;
                    debug!(
                        queue_index = qi,
                        ready = queue.ready,
                        "vsock queue ready write"
                    );
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_NOTIFY => {
                let val = read_u32_from_slice(data);
                debug!(queue = val, "vsock queue notify (kick)");
                // Phase 1: simplify notification handling and return an Interrupt action.
                VsockMmioAction::Interrupt
            }
            VIRTIO_MMIO_INTERRUPT_ACK => {
                debug!(val = read_u32_from_slice(data), "vsock interrupt ACK");
                VsockMmioAction::None
            }
            VIRTIO_MMIO_STATUS => {
                let val = read_u32_from_slice(data) as u8;
                let was_activated = self.activated;
                self.device_status = val;

                // Detect DRIVER_OK being set, indicating that the guest driver finished initialization.
                if !was_activated && (val & VSOCK_DRIVER_OK) != 0 {
                    self.activated = true;
                    self.acked_features = self.driver_features;
                    debug!(
                        status = val,
                        guest_cid = self.guest_cid,
                        acked_features = self.acked_features,
                        "vsock device activated: guest driver set DRIVER_OK"
                    );
                    return VsockMmioAction::Activated;
                }

                // Guest reset the device (status = 0).
                if val == 0 {
                    self.activated = false;
                    self.device_status = 0;
                    self.config_generation = self.config_generation.wrapping_add(1);
                    debug!("vsock device reset");
                }

                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_DESC_LOW => {
                let val = read_u32_from_slice(data) as u64;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.desc_addr = (queue.desc_addr & 0xFFFF_FFFF_0000_0000) | val;
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_DESC_HIGH => {
                let val = read_u32_from_slice(data) as u64;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.desc_addr = (queue.desc_addr & 0x0000_0000_FFFF_FFFF) | (val << 32);
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_AVAIL_LOW => {
                let val = read_u32_from_slice(data) as u64;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.avail_addr = (queue.avail_addr & 0xFFFF_FFFF_0000_0000) | val;
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_AVAIL_HIGH => {
                let val = read_u32_from_slice(data) as u64;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.avail_addr = (queue.avail_addr & 0x0000_0000_FFFF_FFFF) | (val << 32);
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_USED_LOW => {
                let val = read_u32_from_slice(data) as u64;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.used_addr = (queue.used_addr & 0xFFFF_FFFF_0000_0000) | val;
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_USED_HIGH => {
                let val = read_u32_from_slice(data) as u64;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.used_addr = (queue.used_addr & 0x0000_0000_FFFF_FFFF) | (val << 32);
                }
                VsockMmioAction::None
            }
            _ => {
                debug!(offset, "vsock MMIO write: unknown offset");
                VsockMmioAction::None
            }
        }
    }

    /// Returns the feature bitmap supported by the device.
    ///
    /// Currently only VIRTIO_F_VERSION_1 (bit 32) is supported.
    /// VIRTIO_VSOCK_F_SEQ_PACKET is not enabled yet; only stream mode is used.
    fn device_features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    /// Returns an immutable reference to the currently selected queue.
    fn selected_queue(&self) -> &VirtQueueConfig {
        &self.queues[self.queue_select as usize]
    }

    /// Returns a mutable reference to the currently selected queue.
    fn selected_queue_mut(&mut self) -> Option<&mut VirtQueueConfig> {
        self.queues.get_mut(self.queue_select as usize)
    }
}

// ============================================================================
// vhost-vsock backend activation
// ============================================================================

/// Activates the vhost-vsock backend.
///
/// Called after the guest driver sets DRIVER_OK. This passes virtqueue configuration
/// to the kernel vhost subsystem. After activation, the data plane is handled directly
/// by a kernel thread and the VMM no longer participates.
///
/// # Parameters
/// - `queues`: configuration for three virtqueues (rx=0, tx=1, event=2).
/// - `guest_cid`: guest Context ID.
/// - `acked_features`: feature bitmap acknowledged by the guest.
/// - `guest_memory`: guest memory layout.
///
/// # Errors
/// - `/dev/vhost-vsock` does not exist or lacks permission.
/// - An ioctl call failed, such as feature negotiation, memory table setup, or virtqueue configuration.
pub(in crate::kvm) fn activate_vhost_backend(
    queues: &[VirtQueueConfig; NUM_QUEUES],
    guest_cid: u64,
    acked_features: u64,
    guest_memory: &GuestMemoryMmap,
) -> Result<(), String> {
    // 1. Open /dev/vhost-vsock and create the vhost backend handle.
    let vsock = VhostKernVsock::new(guest_memory)
        .map_err(|e| format!("failed to open /dev/vhost-vsock: {e}"))?;

    // 2. Set owner, which must be called first.
    vsock
        .set_owner()
        .map_err(|e| format!("VHOST_SET_OWNER failed: {e}"))?;

    // 3. Set guest CID.
    vsock
        .set_guest_cid(guest_cid)
        .map_err(|e| format!("VHOST_VSOCK_SET_GUEST_CID({guest_cid}) failed: {e}"))?;

    // 4. Set negotiated features.
    vsock
        .set_features(acked_features)
        .map_err(|e| format!("VHOST_SET_FEATURES({acked_features:#x}) failed: {e}"))?;

    // 5. Set the guest memory layout.
    // Iterate all regions through the GuestMemory trait and convert them into the
    // memory table required by vhost.
    let mem_regions: Vec<VhostUserMemoryRegionInfo> = guest_memory
        .iter()
        .map(|region| {
            VhostUserMemoryRegionInfo::from_guest_region(region)
                .map_err(|e| format!("failed to convert guest memory region: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    vsock
        .set_mem_table(&mem_regions)
        .map_err(|e| format!("VHOST_SET_MEM_TABLE failed: {e}"))?;

    // 6. Configure each virtqueue (rx=0, tx=1, event=2).
    for (queue_index, queue) in queues.iter().enumerate() {
        if !queue.ready {
            return Err(format!(
                "queue {queue_index} is not ready, cannot activate vhost backend"
            ));
        }
        if queue.size == 0 {
            return Err(format!(
                "queue {queue_index} size is 0, cannot activate vhost backend"
            ));
        }

        // VHOST_SET_VRING_NUM: set the number of queue descriptors.
        vsock
            .set_vring_num(queue_index, queue.size)
            .map_err(|e| format!("VHOST_SET_VRING_NUM(queue={queue_index}) failed: {e}"))?;

        // VHOST_SET_VRING_ADDR: set descriptor table, available ring, and used ring addresses.
        let config = VringConfigData {
            queue_max_size: QUEUE_SIZE_MAX,
            queue_size: queue.size,
            flags: 0,
            desc_table_addr: queue.desc_addr,
            used_ring_addr: queue.used_addr,
            avail_ring_addr: queue.avail_addr,
            log_addr: None,
        };
        vsock
            .set_vring_addr(queue_index, &config)
            .map_err(|e| format!("VHOST_SET_VRING_ADDR(queue={queue_index}) failed: {e}"))?;

        // VHOST_SET_VRING_BASE: set the available ring starting index.
        vsock
            .set_vring_base(queue_index, 0)
            .map_err(|e| format!("VHOST_SET_VRING_BASE(queue={queue_index}) failed: {e}"))?;
    }

    // 7. Start the vhost data plane.
    vsock
        .start()
        .map_err(|e| format!("VHOST_VSOCK_SET_RUNNING(true) failed: {e}"))?;

    debug!(
        guest_cid,
        acked_features,
        ?queues,
        "vhost-vsock backend activated successfully"
    );
    Ok(())
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests device initialization: magic, version, and device_id must match the virtio MMIO spec.
    #[test]
    fn test_mmio_read_magic_version_device_id() {
        let device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        let mut data = [0u8; 4];

        device.mmio_read(VIRTIO_MMIO_MAGIC_VALUE, &mut data);
        assert_eq!(u32::from_le_bytes(data), VIRTIO_MMIO_MAGIC);

        device.mmio_read(VIRTIO_MMIO_VERSION, &mut data);
        assert_eq!(u32::from_le_bytes(data), VIRTIO_MMIO_VERSION_V2);

        device.mmio_read(VIRTIO_MMIO_DEVICE_ID, &mut data);
        assert_eq!(u32::from_le_bytes(data), VIRTIO_ID_VSOCK);

        device.mmio_read(VIRTIO_MMIO_VENDOR_ID, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0);
    }

    /// Tests feature reads: low 32 bits are 0, high 32 bits include VIRTIO_F_VERSION_1.
    #[test]
    fn test_mmio_read_features() {
        let device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        let mut data = [0u8; 4];

        // features_select = 0: returns the low 32 bits, expected to be 0.
        device.mmio_read(VIRTIO_MMIO_DEVICE_FEATURES, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0);

        // Use mmio_write to set features_select = 1.
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        device.mmio_write(VIRTIO_MMIO_DEVICE_FEATURES_SEL, &[1, 0, 0, 0]);
        device.mmio_read(VIRTIO_MMIO_DEVICE_FEATURES, &mut data);
        assert_eq!(u32::from_le_bytes(data), 1); // High 32 bits of bit 32 = 1.
    }

    /// Tests reading guest_cid from config space.
    #[test]
    fn test_mmio_read_guest_cid() {
        let device = VsockMmioDevice::new(42, 0xd000_0000, 5);
        let mut data = [0u8; 8];

        device.mmio_read(VIRTIO_MMIO_CONFIG, &mut data);
        assert_eq!(u64::from_le_bytes(data), 42);
    }

    /// Tests queue selection and configuration.
    #[test]
    fn test_queue_select_and_size() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);

        // Select queue 1.
        device.mmio_write(VIRTIO_MMIO_QUEUE_SEL, &[1, 0, 0, 0]);
        assert_eq!(device.queue_select, 1);

        // Set queue 1 size.
        device.mmio_write(VIRTIO_MMIO_QUEUE_NUM, &[64, 0, 0, 0]);
        assert_eq!(device.queues[1].size, 64);

        // Verify queue 0 is unaffected.
        assert_eq!(device.queues[0].size, 0);
    }

    /// Tests queue address register writes for descriptor table, available ring, and used ring.
    #[test]
    fn test_queue_address_registers() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);

        // Select queue 0.
        device.mmio_write(VIRTIO_MMIO_QUEUE_SEL, &[0, 0, 0, 0]);

        // Write descriptor table address low = 0x1000, high = 0.
        device.mmio_write(VIRTIO_MMIO_QUEUE_DESC_LOW, &[0x00, 0x10, 0, 0]);
        device.mmio_write(VIRTIO_MMIO_QUEUE_DESC_HIGH, &[0, 0, 0, 0]);
        assert_eq!(device.queues[0].desc_addr, 0x1000);

        // Write available ring address.
        device.mmio_write(VIRTIO_MMIO_QUEUE_AVAIL_LOW, &[0x00, 0x20, 0, 0]);
        device.mmio_write(VIRTIO_MMIO_QUEUE_AVAIL_HIGH, &[0, 0, 0, 0]);
        assert_eq!(device.queues[0].avail_addr, 0x2000);

        // Write used ring address.
        device.mmio_write(VIRTIO_MMIO_QUEUE_USED_LOW, &[0x00, 0x30, 0, 0]);
        device.mmio_write(VIRTIO_MMIO_QUEUE_USED_HIGH, &[0, 0, 0, 0]);
        assert_eq!(device.queues[0].used_addr, 0x3000);
    }

    /// Tests the DRIVER_OK activation flow.
    #[test]
    fn test_driver_ok_activation() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        assert!(!device.is_activated());

        // Write the DRIVER_OK status bit.
        let action = device.mmio_write(VIRTIO_MMIO_STATUS, &[VSOCK_DRIVER_OK, 0, 0, 0]);
        assert_eq!(action, VsockMmioAction::Activated);
        assert!(device.is_activated());

        // Repeated writes should not trigger Activated again.
        let action = device.mmio_write(VIRTIO_MMIO_STATUS, &[VSOCK_DRIVER_OK, 0, 0, 0]);
        assert_eq!(action, VsockMmioAction::None);
    }

    /// Tests device reset.
    #[test]
    fn test_device_reset() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);

        // Activate first.
        device.mmio_write(VIRTIO_MMIO_STATUS, &[VSOCK_DRIVER_OK, 0, 0, 0]);
        assert!(device.is_activated());

        // Reset.
        device.mmio_write(VIRTIO_MMIO_STATUS, &[0, 0, 0, 0]);
        assert!(!device.is_activated());
        assert_eq!(device.device_status, 0);
    }

    /// Tests QueueNumMax returns 256.
    #[test]
    fn test_queue_num_max() {
        let device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        let mut data = [0u8; 4];
        device.mmio_read(VIRTIO_MMIO_QUEUE_NUM_MAX, &mut data);
        assert_eq!(u32::from_le_bytes(data), 256);
    }

    /// Tests QueueNotify returns an Interrupt action.
    #[test]
    fn test_queue_notify_returns_interrupt() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        let action = device.mmio_write(VIRTIO_MMIO_QUEUE_NOTIFY, &[0, 0, 0, 0]);
        assert_eq!(action, VsockMmioAction::Interrupt);
    }

    /// Tests QueueReady reads and writes.
    #[test]
    fn test_queue_ready() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);

        // Select queue 2 (event).
        device.mmio_write(VIRTIO_MMIO_QUEUE_SEL, &[2, 0, 0, 0]);

        // Initial state: not ready.
        let mut data = [0u8; 4];
        device.mmio_read(VIRTIO_MMIO_QUEUE_READY, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0);

        // Set ready.
        device.mmio_write(VIRTIO_MMIO_QUEUE_READY, &[1, 0, 0, 0]);
        assert!(device.queues[2].ready);

        // Read back.
        device.mmio_read(VIRTIO_MMIO_QUEUE_READY, &mut data);
        assert_eq!(u32::from_le_bytes(data), 1);
    }

    /// Tests helper functions.
    #[test]
    fn test_helper_functions() {
        // read_u32_from_slice
        assert_eq!(read_u32_from_slice(&[1, 0, 0, 0]), 1);
        assert_eq!(read_u32_from_slice(&[0xff, 0xff, 0xff, 0xff]), u32::MAX);
        assert_eq!(read_u32_from_slice(&[1, 2]), 0); // Fewer than 4 bytes.

        // write_u32_to_slice
        let mut buf = [0u8; 4];
        write_u32_to_slice(0x1234_5678, &mut buf);
        assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);

        // write_u32_to_slice with a short slice.
        let mut short = [0u8; 2];
        write_u32_to_slice(0x1234_5678, &mut short);
        assert_eq!(short, [0x78, 0x56]);

        // write_u64_to_slice
        let mut buf8 = [0u8; 8];
        write_u64_to_slice(0x0100_0000_0000_0003, &mut buf8);
        assert_eq!(buf8, [3, 0, 0, 0, 0, 0, 0, 1]);
    }

    /// Tests mmio_base / mmio_size / gsi / guest_cid accessors.
    #[test]
    fn test_accessors() {
        let device = VsockMmioDevice::new(7, 0xd000_0000, 5);
        assert_eq!(device.mmio_base(), 0xd000_0000);
        assert_eq!(device.mmio_size(), 0x200);
        assert_eq!(device.gsi(), 5);
        assert_eq!(device.guest_cid(), 7);
    }
}
