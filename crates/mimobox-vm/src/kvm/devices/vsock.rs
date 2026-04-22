#![cfg(all(target_os = "linux", feature = "kvm"))]

//! vsock virtio MMIO 设备模拟器
//!
//! 实现 virtio MMIO spec v2 寄存器级模拟，用于 guest Linux virtio_mmio 驱动
//! 与 host vhost-vsock 后端之间的桥接。
//!
//! Phase 1 只实现寄存器模拟和状态跟踪，不直接操作 vhost 后端。
//! Phase 2 将集成 vhost-vsock 完成数据面通信。

use tracing::debug;

// ============================================================================
// virtio MMIO 寄存器偏移（virtio MMIO spec v2）
// ============================================================================

/// 0x00: MagicValue，固定返回 "virt" (0x74726976)
const VIRTIO_MMIO_MAGIC_VALUE: u64 = 0x00;
/// 0x04: Version，返回 2（virtio MMIO v2）
const VIRTIO_MMIO_VERSION: u64 = 0x04;
/// 0x08: DeviceID，返回 19 (VIRTIO_ID_VSOCK)
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x08;
/// 0x0c: VendorID，返回 0
const VIRTIO_MMIO_VENDOR_ID: u64 = 0x0c;
/// 0x10: DeviceFeatures（根据 features_select 返回低32/高32位）
const VIRTIO_MMIO_DEVICE_FEATURES: u64 = 0x10;
/// 0x14: DeviceFeaturesSel（写入选择低/高32位）
const VIRTIO_MMIO_DEVICE_FEATURES_SEL: u64 = 0x14;
/// 0x20: DriverFeatures
const VIRTIO_MMIO_DRIVER_FEATURES: u64 = 0x20;
/// 0x24: DriverFeaturesSel
const VIRTIO_MMIO_DRIVER_FEATURES_SEL: u64 = 0x24;
/// 0x30: QueueSel（选择 queue 0-2）
const VIRTIO_MMIO_QUEUE_SEL: u64 = 0x30;
/// 0x34: QueueNumMax → 256
const VIRTIO_MMIO_QUEUE_NUM_MAX: u64 = 0x34;
/// 0x38: QueueNum
const VIRTIO_MMIO_QUEUE_NUM: u64 = 0x38;
/// 0x44: QueueReady
const VIRTIO_MMIO_QUEUE_READY: u64 = 0x44;
/// 0x50: QueueNotify（kick，触发 ioeventfd）
const VIRTIO_MMIO_QUEUE_NOTIFY: u64 = 0x50;
/// 0x60: InterruptStatus
const VIRTIO_MMIO_INTERRUPT_STATUS: u64 = 0x60;
/// 0x64: InterruptACK
const VIRTIO_MMIO_INTERRUPT_ACK: u64 = 0x64;
/// 0x70: Status（设备状态位）
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
/// 0x100: config 空间起始，存放 guest_cid (u64)
const VIRTIO_MMIO_CONFIG: u64 = 0x100;

// ============================================================================
// virtio 常量
// ============================================================================

/// virtio MMIO magic number: "virt" in little-endian ASCII
const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
/// virtio MMIO 版本 2
const VIRTIO_MMIO_VERSION_V2: u32 = 2;
/// VIRTIO_ID_VSOCK = 19
const VIRTIO_ID_VSOCK: u32 = 19;
/// VIRTIO_F_VERSION_1: bit 32，表示支持 virtio 1.0+ 规范
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// DRIVER_OK 状态位：guest 驱动完成初始化后设置
const VSOCK_DRIVER_OK: u8 = 0x4;
/// 最大队列大小
const QUEUE_SIZE_MAX: u16 = 256;
/// vsock 使用 3 个 virtqueue：rx=0, tx=1, event=2
const NUM_QUEUES: usize = 3;
/// MMIO 设备地址空间大小
const VSOCK_MMIO_SIZE: u64 = 0x200;

// ============================================================================
// 辅助函数：切片读写
// ============================================================================

/// 从字节切片中读取 u32（小端序）。
/// 切片不足 4 字节时返回 0。
fn read_u32_from_slice(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// 将 u32 值写入字节切片（小端序）。
/// 只写入 min(4, data.len()) 个字节。
fn write_u32_to_slice(val: u32, data: &mut [u8]) {
    let bytes = val.to_le_bytes();
    let len = 4.min(data.len());
    data[..len].copy_from_slice(&bytes[..len]);
}

/// 将 u64 值写入字节切片（小端序）。
/// 只写入 min(8, data.len()) 个字节。
fn write_u64_to_slice(val: u64, data: &mut [u8]) {
    let bytes = val.to_le_bytes();
    let len = 8.min(data.len());
    data[..len].copy_from_slice(&bytes[..len]);
}

// ============================================================================
// 公共类型
// ============================================================================

/// virtio MMIO 写操作产生的动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::kvm) enum VsockMmioAction {
    /// 无需额外处理
    None,
    /// guest driver 设置了 DRIVER_OK，需要激活 vhost 后端
    Activated,
    /// 需要注入中断
    Interrupt,
}

// ============================================================================
// 内部类型
// ============================================================================

/// virtio 队列配置（描述符表、可用环、已用环地址）
#[derive(Debug, Clone, Copy, Default)]
struct VirtQueueConfig {
    /// 描述符表地址
    desc_addr: u64,
    /// 可用环地址
    avail_addr: u64,
    /// 已用环地址
    used_addr: u64,
    /// 队列大小（描述符数量）
    size: u16,
    /// 队列是否已就绪
    ready: bool,
}

// ============================================================================
// VsockMmioDevice
// ============================================================================

/// vsock MMIO 设备模拟器
///
/// 实现 virtio MMIO spec v2 寄存器级模拟，用于 guest Linux virtio_mmio 驱动
/// 与 host vhost-vsock 后端之间的桥接。
///
/// Phase 1 只实现寄存器模拟，Phase 2 再集成 vhost 后端。
#[derive(Debug, Clone)]
pub(in crate::kvm) struct VsockMmioDevice {
    // virtio MMIO 设备状态
    /// 设备状态字节（包含 ACKNOWLEDGE、DRIVER、DRIVER_OK、FAILED 等位）
    device_status: u8,
    /// 配置空间代数，每次配置变更递增
    config_generation: u8,
    // feature 协商
    /// 当前选择的 device features 高低 32 位（0=低32位，1=高32位）
    features_select: u32,
    /// guest 已确认的 features 位图
    acked_features: u64,
    /// 当前选择的 driver features 高低 32 位
    driver_features_select: u32,
    /// driver features 写入缓冲（用于 feature 协商）
    driver_features: u64,
    // 队列管理
    /// 当前选中的队列索引（0-2）
    queue_select: u16,
    /// 三个 virtqueue 的配置：rx=0, tx=1, event=2
    queues: [VirtQueueConfig; NUM_QUEUES],
    // vsock 设备配置
    /// guest 的 Context ID
    guest_cid: u64,
    /// 设备是否已被 guest driver 激活
    activated: bool,
    // MMIO 映射信息
    /// MMIO 设备在 guest 物理地址空间中的基地址
    mmio_base: u64,
    /// 分配给该设备的中断 GSI 号
    gsi: u32,
}

impl VsockMmioDevice {
    /// 创建新的 vsock MMIO 设备模拟器
    ///
    /// # 参数
    /// - `guest_cid`: guest 的 Context ID（vsock 地址），通常从 3 开始分配
    /// - `mmio_base`: MMIO 设备在 guest 物理地址空间中的基地址
    /// - `gsi`: 分配给该设备的中断 GSI 号
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

    /// 返回 MMIO 设备在 guest 物理地址空间中的基地址
    pub(in crate::kvm) fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// 返回 MMIO 设备地址空间大小
    pub(in crate::kvm) fn mmio_size(&self) -> u64 {
        VSOCK_MMIO_SIZE
    }

    /// 返回分配给该设备的中断 GSI 号
    pub(in crate::kvm) fn gsi(&self) -> u32 {
        self.gsi
    }

    /// 返回设备是否已被 guest driver 激活（设置了 DRIVER_OK）
    pub(in crate::kvm) fn is_activated(&self) -> bool {
        self.activated
    }

    /// 返回 guest 的 Context ID
    pub(in crate::kvm) fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// 处理 guest 对 vsock MMIO 寄存器的读操作
    ///
    /// # 参数
    /// - `offset`: 相对于 mmio_base 的偏移量
    /// - `data`: 输出缓冲区，写入读取的寄存器值
    pub(in crate::kvm) fn mmio_read(&self, offset: u64, data: &mut [u8]) {
        data.fill(0);

        let val = match offset {
            VIRTIO_MMIO_MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            VIRTIO_MMIO_VERSION => VIRTIO_MMIO_VERSION_V2,
            VIRTIO_MMIO_DEVICE_ID => VIRTIO_ID_VSOCK,
            VIRTIO_MMIO_VENDOR_ID => 0,
            VIRTIO_MMIO_DEVICE_FEATURES => {
                // 根据 features_select 返回低32位或高32位
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
                // config 空间：guest_cid (u64)，从 0x100 偏移开始
                let config_offset = offset - VIRTIO_MMIO_CONFIG;
                if config_offset < 8 {
                    write_u64_to_slice(self.guest_cid, data);
                    debug!(
                        offset,
                        guest_cid = self.guest_cid,
                        "vsock MMIO config 读: guest_cid"
                    );
                    return;
                }
                debug!(offset, "vsock MMIO 读: config 空间越界偏移");
                return;
            }
            _ => {
                debug!(offset, "vsock MMIO 读: 未识别偏移量");
                return;
            }
        };

        write_u32_to_slice(val, data);
    }

    /// 处理 guest 对 vsock MMIO 寄存器的写操作
    ///
    /// # 参数
    /// - `offset`: 相对于 mmio_base 的偏移量
    /// - `data`: 写入的数据
    ///
    /// # 返回
    /// 写操作触发的动作枚举
    pub(in crate::kvm) fn mmio_write(&mut self, offset: u64, data: &[u8]) -> VsockMmioAction {
        match offset {
            VIRTIO_MMIO_DEVICE_FEATURES_SEL => {
                self.features_select = read_u32_from_slice(data);
                debug!(select = self.features_select, "vsock feature select 写入");
                VsockMmioAction::None
            }
            VIRTIO_MMIO_DRIVER_FEATURES => {
                let val = read_u32_from_slice(data) as u64;
                match self.driver_features_select {
                    0 => self.driver_features = (self.driver_features & !0xFFFF_FFFF) | val,
                    1 => {
                        self.driver_features =
                            (self.driver_features & 0xFFFF_FFFF) | (val << 32)
                    }
                    _ => {}
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_DRIVER_FEATURES_SEL => {
                self.driver_features_select = read_u32_from_slice(data);
                debug!(
                    select = self.driver_features_select,
                    "vsock driver feature select 写入"
                );
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_SEL => {
                let val = read_u32_from_slice(data) as u16;
                if (val as usize) < NUM_QUEUES {
                    self.queue_select = val;
                    debug!(queue = val, "vsock queue select 写入");
                } else {
                    debug!(queue = val, "vsock queue select 越界，忽略");
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_NUM => {
                let val = read_u32_from_slice(data) as u16;
                let qi = self.queue_select;
                if let Some(queue) = self.selected_queue_mut() {
                    queue.size = val;
                    debug!(queue_index = qi, size = val, "vsock queue size 写入");
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
                        "vsock queue ready 写入"
                    );
                }
                VsockMmioAction::None
            }
            VIRTIO_MMIO_QUEUE_NOTIFY => {
                let val = read_u32_from_slice(data);
                debug!(queue = val, "vsock queue notify (kick)");
                // Phase 1: 通知事件简化处理，返回 Interrupt 动作
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

                // 检测 DRIVER_OK 位设置（表示 guest driver 完成初始化）
                if !was_activated && (val & VSOCK_DRIVER_OK) != 0 {
                    self.activated = true;
                    self.acked_features = self.driver_features;
                    debug!(
                        status = val,
                        guest_cid = self.guest_cid,
                        acked_features = self.acked_features,
                        "vsock 设备已激活: guest driver 设置 DRIVER_OK"
                    );
                    return VsockMmioAction::Activated;
                }

                // guest 重置设备（status = 0）
                if val == 0 {
                    self.activated = false;
                    self.device_status = 0;
                    self.config_generation = self.config_generation.wrapping_add(1);
                    debug!("vsock 设备已重置");
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
                debug!(offset, "vsock MMIO 写: 未识别偏移量");
                VsockMmioAction::None
            }
        }
    }

    /// 返回设备支持的 features 位图
    ///
    /// 当前仅支持 VIRTIO_F_VERSION_1 (bit 32)，
    /// 暂不启用 VIRTIO_VSOCK_F_SEQ_PACKET（只用 stream 模式）。
    fn device_features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    /// 获取当前选中队列的不可变引用
    fn selected_queue(&self) -> &VirtQueueConfig {
        &self.queues[self.queue_select as usize]
    }

    /// 获取当前选中队列的可变引用
    fn selected_queue_mut(&mut self) -> Option<&mut VirtQueueConfig> {
        self.queues.get_mut(self.queue_select as usize)
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试设备初始化：magic、version、device_id 必须符合 virtio MMIO spec
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

    /// 测试 features 读取：低 32 位为 0，高 32 位包含 VIRTIO_F_VERSION_1
    #[test]
    fn test_mmio_read_features() {
        let device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        let mut data = [0u8; 4];

        // features_select = 0：返回低 32 位（应为 0）
        device.mmio_read(VIRTIO_MMIO_DEVICE_FEATURES, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0);

        // 需要 mmio_write 设置 features_select = 1
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        device.mmio_write(VIRTIO_MMIO_DEVICE_FEATURES_SEL, &[1, 0, 0, 0]);
        device.mmio_read(VIRTIO_MMIO_DEVICE_FEATURES, &mut data);
        assert_eq!(u32::from_le_bytes(data), 1); // bit 32 的高 32 位 = 1
    }

    /// 测试 guest_cid 从 config 空间读取
    #[test]
    fn test_mmio_read_guest_cid() {
        let device = VsockMmioDevice::new(42, 0xd000_0000, 5);
        let mut data = [0u8; 8];

        device.mmio_read(VIRTIO_MMIO_CONFIG, &mut data);
        assert_eq!(u64::from_le_bytes(data), 42);
    }

    /// 测试 queue 选择和配置
    #[test]
    fn test_queue_select_and_size() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);

        // 选择 queue 1
        device.mmio_write(VIRTIO_MMIO_QUEUE_SEL, &[1, 0, 0, 0]);
        assert_eq!(device.queue_select, 1);

        // 设置 queue 1 的大小
        device.mmio_write(VIRTIO_MMIO_QUEUE_NUM, &[64, 0, 0, 0]);
        assert_eq!(device.queues[1].size, 64);

        // 验证 queue 0 未受影响
        assert_eq!(device.queues[0].size, 0);
    }

    /// 测试 queue 地址寄存器写入（描述符表、可用环、已用环）
    #[test]
    fn test_queue_address_registers() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);

        // 选择 queue 0
        device.mmio_write(VIRTIO_MMIO_QUEUE_SEL, &[0, 0, 0, 0]);

        // 写入描述符表地址 low = 0x1000, high = 0
        device.mmio_write(VIRTIO_MMIO_QUEUE_DESC_LOW, &[0x00, 0x10, 0, 0]);
        device.mmio_write(VIRTIO_MMIO_QUEUE_DESC_HIGH, &[0, 0, 0, 0]);
        assert_eq!(device.queues[0].desc_addr, 0x1000);

        // 写入可用环地址
        device.mmio_write(VIRTIO_MMIO_QUEUE_AVAIL_LOW, &[0x00, 0x20, 0, 0]);
        device.mmio_write(VIRTIO_MMIO_QUEUE_AVAIL_HIGH, &[0, 0, 0, 0]);
        assert_eq!(device.queues[0].avail_addr, 0x2000);

        // 写入已用环地址
        device.mmio_write(VIRTIO_MMIO_QUEUE_USED_LOW, &[0x00, 0x30, 0, 0]);
        device.mmio_write(VIRTIO_MMIO_QUEUE_USED_HIGH, &[0, 0, 0, 0]);
        assert_eq!(device.queues[0].used_addr, 0x3000);
    }

    /// 测试 DRIVER_OK 激活流程
    #[test]
    fn test_driver_ok_activation() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        assert!(!device.is_activated());

        // 写入 DRIVER_OK 状态位
        let action = device.mmio_write(VIRTIO_MMIO_STATUS, &[VSOCK_DRIVER_OK, 0, 0, 0]);
        assert_eq!(action, VsockMmioAction::Activated);
        assert!(device.is_activated());

        // 重复写入不应再触发 Activated
        let action = device.mmio_write(VIRTIO_MMIO_STATUS, &[VSOCK_DRIVER_OK, 0, 0, 0]);
        assert_eq!(action, VsockMmioAction::None);
    }

    /// 测试设备重置
    #[test]
    fn test_device_reset() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);

        // 先激活
        device.mmio_write(VIRTIO_MMIO_STATUS, &[VSOCK_DRIVER_OK, 0, 0, 0]);
        assert!(device.is_activated());

        // 重置
        device.mmio_write(VIRTIO_MMIO_STATUS, &[0, 0, 0, 0]);
        assert!(!device.is_activated());
        assert_eq!(device.device_status, 0);
    }

    /// 测试 QueueNumMax 返回 256
    #[test]
    fn test_queue_num_max() {
        let device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        let mut data = [0u8; 4];
        device.mmio_read(VIRTIO_MMIO_QUEUE_NUM_MAX, &mut data);
        assert_eq!(u32::from_le_bytes(data), 256);
    }

    /// 测试 QueueNotify 返回 Interrupt 动作
    #[test]
    fn test_queue_notify_returns_interrupt() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);
        let action = device.mmio_write(VIRTIO_MMIO_QUEUE_NOTIFY, &[0, 0, 0, 0]);
        assert_eq!(action, VsockMmioAction::Interrupt);
    }

    /// 测试 QueueReady 读写
    #[test]
    fn test_queue_ready() {
        let mut device = VsockMmioDevice::new(3, 0xd000_0000, 5);

        // 选择 queue 2 (event)
        device.mmio_write(VIRTIO_MMIO_QUEUE_SEL, &[2, 0, 0, 0]);

        // 初始状态: not ready
        let mut data = [0u8; 4];
        device.mmio_read(VIRTIO_MMIO_QUEUE_READY, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0);

        // 设置 ready
        device.mmio_write(VIRTIO_MMIO_QUEUE_READY, &[1, 0, 0, 0]);
        assert!(device.queues[2].ready);

        // 读回
        device.mmio_read(VIRTIO_MMIO_QUEUE_READY, &mut data);
        assert_eq!(u32::from_le_bytes(data), 1);
    }

    /// 测试辅助函数
    #[test]
    fn test_helper_functions() {
        // read_u32_from_slice
        assert_eq!(read_u32_from_slice(&[1, 0, 0, 0]), 1);
        assert_eq!(read_u32_from_slice(&[0xff, 0xff, 0xff, 0xff]), u32::MAX);
        assert_eq!(read_u32_from_slice(&[1, 2]), 0); // 不足 4 字节

        // write_u32_to_slice
        let mut buf = [0u8; 4];
        write_u32_to_slice(0x1234_5678, &mut buf);
        assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);

        // write_u32_to_slice 短切片
        let mut short = [0u8; 2];
        write_u32_to_slice(0x1234_5678, &mut short);
        assert_eq!(short, [0x78, 0x56]);

        // write_u64_to_slice
        let mut buf8 = [0u8; 8];
        write_u64_to_slice(0x0100_0000_0000_0003, &mut buf8);
        assert_eq!(buf8, [3, 0, 0, 0, 0, 0, 0, 1]);
    }

    /// 测试 mmio_base / mmio_size / gsi / guest_cid 访问器
    #[test]
    fn test_accessors() {
        let device = VsockMmioDevice::new(7, 0xd000_0000, 5);
        assert_eq!(device.mmio_base(), 0xd000_0000);
        assert_eq!(device.mmio_size(), 0x200);
        assert_eq!(device.gsi(), 5);
        assert_eq!(device.guest_cid(), 7);
    }
}
