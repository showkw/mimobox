use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use mimobox_core::{SandboxConfig, SandboxError, SandboxSnapshot, SeccompProfile};
use serde::{Deserialize, Serialize};

use crate::vm::{MicrovmConfig, MicrovmError};

const SNAPSHOT_MAGIC: [u8; 8] = *b"MMBXVM01";
const SNAPSHOT_VERSION: u16 = 1;
pub(crate) const FILE_SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_MEMORY_FILE_NAME: &str = "memory.bin";
const SNAPSHOT_STATE_FILE_NAME: &str = "state.json";
static SNAPSHOT_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SnapshotStateFile {
    pub(crate) version: u16,
    pub(crate) sandbox_config: SandboxConfig,
    pub(crate) microvm_config: MicrovmConfig,
    pub(crate) vcpu_state_base64: String,
}

/// microVM 自描述快照。
#[derive(Clone)]
pub struct MicrovmSnapshot {
    pub(crate) sandbox_config: SandboxConfig,
    pub(crate) microvm_config: MicrovmConfig,
    pub(crate) memory: Vec<u8>,
    pub(crate) vcpu_state: Vec<u8>,
}

impl MicrovmSnapshot {
    /// 创建快照对象。
    pub fn new(
        sandbox_config: SandboxConfig,
        microvm_config: MicrovmConfig,
        memory: Vec<u8>,
        vcpu_state: Vec<u8>,
    ) -> Self {
        Self {
            sandbox_config,
            microvm_config,
            memory,
            vcpu_state,
        }
    }

    /// 序列化为 `magic + version + config + memory + vcpu state`。
    pub fn snapshot(&self) -> Result<Vec<u8>, MicrovmError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        encode_sandbox_config(&mut bytes, &self.sandbox_config)?;
        encode_microvm_config(&mut bytes, &self.microvm_config)?;
        encode_bytes(&mut bytes, &self.memory)?;
        encode_bytes(&mut bytes, &self.vcpu_state)?;
        Ok(bytes)
    }

    /// 从字节流恢复快照对象。
    pub fn restore(data: &[u8]) -> Result<Self, MicrovmError> {
        let mut cursor = SnapshotCursor::new(data);
        let magic = cursor.read_exact(SNAPSHOT_MAGIC.len())?;
        if magic != SNAPSHOT_MAGIC {
            return Err(MicrovmError::SnapshotFormat("快照 magic 不匹配".into()));
        }

        let version = cursor.read_u16()?;
        if version != SNAPSHOT_VERSION {
            return Err(MicrovmError::SnapshotFormat(format!(
                "不支持的快照版本: {version}"
            )));
        }

        let sandbox_config = decode_sandbox_config(&mut cursor)?;
        let microvm_config = decode_microvm_config(&mut cursor)?;
        let memory = cursor.read_bytes()?;
        let vcpu_state = cursor.read_bytes()?;

        if !cursor.is_eof() {
            return Err(MicrovmError::SnapshotFormat(
                "快照尾部存在未识别数据".into(),
            ));
        }

        Ok(Self {
            sandbox_config,
            microvm_config,
            memory,
            vcpu_state,
        })
    }

    /// 将快照持久化到 `~/.mimobox/snapshots/<id>/memory.bin + state.json`。
    pub(crate) fn persist_to_files(&self) -> Result<SandboxSnapshot, MicrovmError> {
        let snapshot_dir = create_snapshot_dir()?;
        let memory_path = snapshot_dir.join(SNAPSHOT_MEMORY_FILE_NAME);
        let state_path = snapshot_dir.join(SNAPSHOT_STATE_FILE_NAME);

        let write_result = (|| {
            fs::write(&memory_path, &self.memory)?;

            let state = SnapshotStateFile {
                version: FILE_SNAPSHOT_VERSION,
                sandbox_config: self.sandbox_config.clone(),
                microvm_config: self.microvm_config.clone(),
                vcpu_state_base64: BASE64_STANDARD.encode(&self.vcpu_state),
            };
            let state_bytes = serde_json::to_vec_pretty(&state).map_err(|error| {
                MicrovmError::SnapshotFormat(format!("序列化 state.json 失败: {error}"))
            })?;
            fs::write(&state_path, state_bytes)?;

            SandboxSnapshot::from_file(memory_path).map_err(map_snapshot_error)
        })();

        if write_result.is_err() {
            let _ = fs::remove_dir_all(snapshot_dir);
        }

        write_result
    }

    /// 从文件化快照的 `memory.bin` 恢复完整快照对象。
    pub fn from_memory_file(memory_path: &Path) -> Result<Self, MicrovmError> {
        let state_path = state_file_path(memory_path)?;
        let state_bytes = fs::read(&state_path)?;
        let state: SnapshotStateFile = serde_json::from_slice(&state_bytes).map_err(|error| {
            MicrovmError::SnapshotFormat(format!(
                "解析 state.json 失败 ({}): {error}",
                state_path.display()
            ))
        })?;

        if state.version != FILE_SNAPSHOT_VERSION {
            return Err(MicrovmError::SnapshotFormat(format!(
                "不支持的文件快照版本: {}",
                state.version
            )));
        }

        let vcpu_state = BASE64_STANDARD
            .decode(state.vcpu_state_base64.as_bytes())
            .map_err(|error| {
                MicrovmError::SnapshotFormat(format!("解码 vCPU state 失败: {error}"))
            })?;
        let memory = fs::read(memory_path)?;

        Ok(Self {
            sandbox_config: state.sandbox_config,
            microvm_config: state.microvm_config,
            memory,
            vcpu_state,
        })
    }

    pub(crate) fn into_parts(self) -> (SandboxConfig, MicrovmConfig, Vec<u8>, Vec<u8>) {
        (
            self.sandbox_config,
            self.microvm_config,
            self.memory,
            self.vcpu_state,
        )
    }
}

fn map_snapshot_error(error: SandboxError) -> MicrovmError {
    match error {
        SandboxError::Io(error) => MicrovmError::Io(error),
        SandboxError::InvalidSnapshot => MicrovmError::SnapshotFormat("文件快照无效".into()),
        other => MicrovmError::SnapshotFormat(other.to_string()),
    }
}

fn snapshot_root_dir() -> Result<PathBuf, MicrovmError> {
    let home_dir = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        MicrovmError::SnapshotFormat("HOME 环境变量缺失，无法定位快照目录".into())
    })?;
    Ok(home_dir.join(".mimobox").join("snapshots"))
}

pub(crate) fn create_snapshot_dir() -> Result<PathBuf, MicrovmError> {
    let root_dir = snapshot_root_dir()?;
    fs::create_dir_all(&root_dir)?;

    for _ in 0..32 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| MicrovmError::SnapshotFormat(format!("系统时间异常: {error}")))?;
        let sequence = SNAPSHOT_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let snapshot_dir = root_dir.join(format!(
            "{:x}-{:x}-{:x}",
            timestamp.as_nanos(),
            std::process::id(),
            sequence
        ));

        match fs::create_dir(&snapshot_dir) {
            Ok(()) => return Ok(snapshot_dir),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(MicrovmError::Io(error)),
        }
    }

    Err(MicrovmError::SnapshotFormat("生成唯一快照目录失败".into()))
}

fn state_file_path(memory_path: &Path) -> Result<PathBuf, MicrovmError> {
    let snapshot_dir = memory_path.parent().ok_or_else(|| {
        MicrovmError::SnapshotFormat(format!("快照文件路径缺少父目录: {}", memory_path.display()))
    })?;
    Ok(snapshot_dir.join(SNAPSHOT_STATE_FILE_NAME))
}

fn encode_sandbox_config(out: &mut Vec<u8>, config: &SandboxConfig) -> Result<(), MicrovmError> {
    encode_paths(out, &config.fs_readonly)?;
    encode_paths(out, &config.fs_readwrite)?;
    out.push(u8::from(config.deny_network));
    encode_opt_u64(out, config.memory_limit_mb);
    encode_opt_u64(out, config.timeout_secs);
    out.push(seccomp_to_u8(config.seccomp_profile));
    out.push(u8::from(config.allow_fork));
    encode_strings(out, &config.allowed_http_domains)?;
    Ok(())
}

fn decode_sandbox_config(cursor: &mut SnapshotCursor<'_>) -> Result<SandboxConfig, MicrovmError> {
    Ok(SandboxConfig {
        fs_readonly: decode_paths(cursor)?,
        fs_readwrite: decode_paths(cursor)?,
        deny_network: cursor.read_bool()?,
        memory_limit_mb: cursor.read_opt_u64()?,
        timeout_secs: cursor.read_opt_u64()?,
        seccomp_profile: u8_to_seccomp(cursor.read_u8()?)?,
        allow_fork: cursor.read_bool()?,
        allowed_http_domains: decode_strings(cursor)?,
    })
}

fn encode_microvm_config(out: &mut Vec<u8>, config: &MicrovmConfig) -> Result<(), MicrovmError> {
    out.push(config.vcpu_count);
    out.extend_from_slice(&config.memory_mb.to_le_bytes());
    encode_path(out, &config.kernel_path)?;
    encode_path(out, &config.rootfs_path)?;
    Ok(())
}

fn decode_microvm_config(cursor: &mut SnapshotCursor<'_>) -> Result<MicrovmConfig, MicrovmError> {
    Ok(MicrovmConfig {
        vcpu_count: cursor.read_u8()?,
        memory_mb: cursor.read_u32()?,
        kernel_path: decode_path(cursor)?,
        rootfs_path: decode_path(cursor)?,
    })
}

fn encode_paths(out: &mut Vec<u8>, paths: &[PathBuf]) -> Result<(), MicrovmError> {
    let len = u32::try_from(paths.len())
        .map_err(|_| MicrovmError::SnapshotFormat("路径数量超过 u32 上限".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    for path in paths {
        encode_path(out, path)?;
    }
    Ok(())
}

fn decode_paths(cursor: &mut SnapshotCursor<'_>) -> Result<Vec<PathBuf>, MicrovmError> {
    let len = cursor.read_u32()? as usize;
    let mut paths = Vec::with_capacity(len);
    for _ in 0..len {
        paths.push(decode_path(cursor)?);
    }
    Ok(paths)
}

fn encode_strings(out: &mut Vec<u8>, strings: &[String]) -> Result<(), MicrovmError> {
    let len = u32::try_from(strings.len())
        .map_err(|_| MicrovmError::SnapshotFormat("字符串数量超过 u32 上限".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    for s in strings {
        encode_bytes(out, s.as_bytes())?;
    }
    Ok(())
}

fn decode_strings(cursor: &mut SnapshotCursor<'_>) -> Result<Vec<String>, MicrovmError> {
    let len = cursor.read_u32()? as usize;
    let mut strings = Vec::with_capacity(len);
    for _ in 0..len {
        let bytes = cursor.read_bytes()?;
        String::from_utf8(bytes)
            .map_err(|e| MicrovmError::SnapshotFormat(format!("字符串 UTF-8 解码失败: {e}")))
            .map(|s| strings.push(s))?;
    }
    Ok(strings)
}

fn encode_path(out: &mut Vec<u8>, path: &std::path::Path) -> Result<(), MicrovmError> {
    let value = path.to_string_lossy();
    encode_bytes(out, value.as_bytes())
}

fn decode_path(cursor: &mut SnapshotCursor<'_>) -> Result<PathBuf, MicrovmError> {
    let bytes = cursor.read_bytes()?;
    let value = String::from_utf8(bytes)
        .map_err(|err| MicrovmError::SnapshotFormat(format!("路径不是合法 UTF-8: {err}")))?;
    Ok(PathBuf::from(value))
}

fn encode_bytes(out: &mut Vec<u8>, data: &[u8]) -> Result<(), MicrovmError> {
    let len = u64::try_from(data.len())
        .map_err(|_| MicrovmError::SnapshotFormat("数据块长度超过 u64 上限".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn encode_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn seccomp_to_u8(profile: SeccompProfile) -> u8 {
    match profile {
        SeccompProfile::Essential => 0,
        SeccompProfile::Network => 1,
        SeccompProfile::EssentialWithFork => 2,
        SeccompProfile::NetworkWithFork => 3,
    }
}

fn u8_to_seccomp(value: u8) -> Result<SeccompProfile, MicrovmError> {
    match value {
        0 => Ok(SeccompProfile::Essential),
        1 => Ok(SeccompProfile::Network),
        2 => Ok(SeccompProfile::EssentialWithFork),
        3 => Ok(SeccompProfile::NetworkWithFork),
        other => Err(MicrovmError::SnapshotFormat(format!(
            "非法 seccomp profile 编码: {other}"
        ))),
    }
}

struct SnapshotCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_exact<const N: usize>(&mut self, len: usize) -> Result<[u8; N], MicrovmError> {
        debug_assert_eq!(N, len);
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| MicrovmError::SnapshotFormat("快照偏移溢出".into()))?;
        let bytes = self.data.get(self.offset..end).ok_or_else(|| {
            MicrovmError::SnapshotFormat("快照数据在读取固定长度字段时提前结束".into())
        })?;
        self.offset = end;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn read_u8(&mut self) -> Result<u8, MicrovmError> {
        Ok(self.read_exact::<1>(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, MicrovmError> {
        Ok(u16::from_le_bytes(self.read_exact::<2>(2)?))
    }

    fn read_u32(&mut self) -> Result<u32, MicrovmError> {
        Ok(u32::from_le_bytes(self.read_exact::<4>(4)?))
    }

    fn read_u64(&mut self) -> Result<u64, MicrovmError> {
        Ok(u64::from_le_bytes(self.read_exact::<8>(8)?))
    }

    fn read_bool(&mut self) -> Result<bool, MicrovmError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(MicrovmError::SnapshotFormat(format!(
                "非法布尔编码: {other}"
            ))),
        }
    }

    fn read_opt_u64(&mut self) -> Result<Option<u64>, MicrovmError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u64()?)),
            other => Err(MicrovmError::SnapshotFormat(format!(
                "非法 Option<u64> 编码: {other}"
            ))),
        }
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, MicrovmError> {
        let len = usize::try_from(self.read_u64()?)
            .map_err(|_| MicrovmError::SnapshotFormat("数据块长度无法转换为 usize".into()))?;
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| MicrovmError::SnapshotFormat("快照偏移溢出".into()))?;
        let bytes = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| MicrovmError::SnapshotFormat("快照数据在读取字节块时提前结束".into()))?;
        self.offset = end;
        Ok(bytes.to_vec())
    }

    fn is_eof(&self) -> bool {
        self.offset == self.data.len()
    }
}
