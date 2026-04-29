use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use mimobox_core::{SandboxConfig, SandboxError, SandboxSnapshot, SeccompProfile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vm::{MicrovmConfig, MicrovmError, VmSecurityProfile, sanitize_path_display};

const SNAPSHOT_MAGIC: [u8; 8] = *b"MMBXVM01";
const SNAPSHOT_VERSION: u16 = 3;
const MIN_SUPPORTED_SNAPSHOT_VERSION: u16 = 2;
/// Version of the sidecar `state.json` file used by file-backed snapshots.
pub(crate) const FILE_SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_MEMORY_FILE_NAME: &str = "memory.bin";
const SNAPSHOT_STATE_FILE_NAME: &str = "state.json";
static SNAPSHOT_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Sidecar metadata stored next to a file-backed guest memory snapshot.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SnapshotStateFile {
    /// File snapshot metadata format version.
    pub(crate) version: u16,
    /// Sandbox policy captured when the snapshot was created.
    pub(crate) sandbox_config: SandboxConfig,
    /// microVM configuration captured when the snapshot was created.
    pub(crate) microvm_config: MicrovmConfig,
    /// Base64-encoded vCPU and device runtime state.
    pub(crate) vcpu_state_base64: String,
    /// `memory.bin` 的 SHA-256 摘要，使用小写十六进制编码。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) memory_hash: Option<String>,
}

/// Self-describing microVM snapshot.
///
/// A snapshot captures the base sandbox policy, microVM configuration, complete
/// guest memory image, and serialized vCPU/device runtime state required to
/// restore an equivalent guest.
#[derive(Clone)]
pub struct MicrovmSnapshot {
    pub(crate) sandbox_config: SandboxConfig,
    pub(crate) microvm_config: MicrovmConfig,
    pub(crate) memory: Vec<u8>,
    pub(crate) vcpu_state: Vec<u8>,
}

impl MicrovmSnapshot {
    /// Creates an in-memory snapshot object from already captured state parts.
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

    /// Serializes this snapshot into the stable in-memory byte format.
    ///
    /// The format is `magic + version + sandbox config + microVM config + guest
    /// memory + vCPU state`, with all variable-length sections length-prefixed.
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

    /// Restores a snapshot object from the self-describing byte format.
    ///
    /// The decoder validates the magic bytes, version, and end-of-input boundary
    /// before returning the reconstructed snapshot.
    pub fn restore(data: &[u8]) -> Result<Self, MicrovmError> {
        let mut cursor = SnapshotCursor::new(data);
        let magic = cursor.read_exact(SNAPSHOT_MAGIC.len())?;
        if magic != SNAPSHOT_MAGIC {
            return Err(MicrovmError::SnapshotFormat(
                "snapshot magic mismatch".into(),
            ));
        }

        let version = cursor.read_u16()?;
        if !(MIN_SUPPORTED_SNAPSHOT_VERSION..=SNAPSHOT_VERSION).contains(&version) {
            return Err(MicrovmError::SnapshotFormat(format!(
                "unsupported snapshot version: {version}"
            )));
        }

        let sandbox_config = decode_sandbox_config(&mut cursor)?;
        let microvm_config = decode_microvm_config(&mut cursor, version)?;
        let memory = cursor.read_bytes()?;
        let vcpu_state = cursor.read_bytes()?;

        if !cursor.is_eof() {
            return Err(MicrovmError::SnapshotFormat(
                "unrecognized data at end of snapshot".into(),
            ));
        }

        Ok(Self {
            sandbox_config,
            microvm_config,
            memory,
            vcpu_state,
        })
    }

    /// Persists the snapshot to `~/.mimobox/snapshots/<id>/memory.bin` and `state.json`.
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
                memory_hash: Some(memory_sha256_hex(&self.memory)),
            };
            let state_bytes = serde_json::to_vec_pretty(&state).map_err(|error| {
                MicrovmError::SnapshotFormat(format!("failed to serialize state.json: {error}"))
            })?;
            fs::write(&state_path, state_bytes)?;

            SandboxSnapshot::from_file(memory_path).map_err(map_snapshot_error)
        })();

        if write_result.is_err() {
            let _ = fs::remove_dir_all(snapshot_dir);
        }

        write_result
    }

    /// Restores a full snapshot object from a file-backed `memory.bin` snapshot.
    ///
    /// The method reads sibling `state.json` metadata and then loads the guest
    /// memory file into memory.
    pub fn from_memory_file(memory_path: &Path) -> Result<Self, MicrovmError> {
        let state = load_snapshot_state_from_memory_file(memory_path)?;
        let memory = fs::read(memory_path)?;
        verify_memory_hash_bytes(memory_path, &memory, state.memory_hash.as_deref())?;

        Ok(Self {
            sandbox_config: state.sandbox_config,
            microvm_config: state.microvm_config,
            memory,
            vcpu_state: state.vcpu_state,
        })
    }

    /// Splits the snapshot into the state parts required by restore paths.
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
        SandboxError::InvalidSnapshot => {
            MicrovmError::SnapshotFormat("invalid file snapshot".into())
        }
        other => MicrovmError::SnapshotFormat(other.to_string()),
    }
}

pub(crate) fn memory_sha256_hex(memory: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(memory);
    digest_to_hex(hasher.finalize())
}

#[allow(dead_code)]
fn memory_file_sha256_hex(memory_path: &Path) -> Result<String, MicrovmError> {
    let mut file = fs::File::open(memory_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read_len = file.read(&mut buffer)?;
        if read_len == 0 {
            break;
        }
        hasher.update(&buffer[..read_len]);
    }

    Ok(digest_to_hex(hasher.finalize()))
}

fn digest_to_hex(digest: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = digest.as_ref();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(HEX[(byte >> 4) as usize]));
        hex.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    hex
}

fn verify_memory_hash(
    memory_path: &Path,
    actual_hash: &str,
    expected_hash: Option<&str>,
) -> Result<(), MicrovmError> {
    let expected_hash = expected_hash.ok_or_else(|| {
        MicrovmError::SnapshotFormat(format!(
            "文件快照缺少 memory_hash，拒绝 restore: {}",
            sanitize_path_display(memory_path)
        ))
    })?;

    if actual_hash.eq_ignore_ascii_case(expected_hash) {
        return Ok(());
    }

    Err(MicrovmError::SnapshotFormat(format!(
        "memory.bin hash mismatch ({}): expected {expected_hash}, actual {actual_hash}",
        sanitize_path_display(memory_path)
    )))
}

fn verify_memory_hash_bytes(
    memory_path: &Path,
    memory: &[u8],
    expected_hash: Option<&str>,
) -> Result<(), MicrovmError> {
    verify_memory_hash(memory_path, &memory_sha256_hex(memory), expected_hash)
}

#[allow(dead_code)]
fn verify_memory_hash_file(
    memory_path: &Path,
    expected_hash: Option<&str>,
) -> Result<(), MicrovmError> {
    let actual_hash = memory_file_sha256_hex(memory_path)?;
    verify_memory_hash(memory_path, &actual_hash, expected_hash)
}

pub(crate) fn snapshot_root_dir() -> Result<PathBuf, MicrovmError> {
    let home_dir = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        MicrovmError::SnapshotFormat(
            "HOME environment variable missing, cannot locate snapshot directory".into(),
        )
    })?;
    let root_dir = home_dir.join(".mimobox").join("snapshots");
    fs::create_dir_all(&root_dir)?;
    // 快照根目录仅限当前用户访问，防止其他用户读取 guest 内存映像
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root_dir, fs::Permissions::from_mode(0o700))
            .map_err(MicrovmError::Io)?;
    }
    Ok(root_dir)
}

/// Creates a unique directory under the per-user microVM snapshot root.
pub(crate) fn create_snapshot_dir() -> Result<PathBuf, MicrovmError> {
    let root_dir = snapshot_root_dir()?;

    for _ in 0..32 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| MicrovmError::SnapshotFormat(format!("system time error: {error}")))?;
        let sequence = SNAPSHOT_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let snapshot_dir = root_dir.join(format!(
            "{:x}-{:x}-{:x}",
            timestamp.as_nanos(),
            std::process::id(),
            sequence
        ));

        match fs::create_dir(&snapshot_dir) {
            Ok(()) => {
                // 每个快照目录同样限制为当前用户独占访问
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&snapshot_dir, fs::Permissions::from_mode(0o700))
                        .map_err(MicrovmError::Io)?;
                }
                return Ok(snapshot_dir);
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(MicrovmError::Io(error)),
        }
    }

    Err(MicrovmError::SnapshotFormat(
        "failed to generate unique snapshot directory".into(),
    ))
}

fn state_file_path(memory_path: &Path) -> Result<PathBuf, MicrovmError> {
    let snapshot_dir = memory_path.parent().ok_or_else(|| {
        MicrovmError::SnapshotFormat(format!(
            "snapshot file path missing parent directory: {}",
            sanitize_path_display(memory_path)
        ))
    })?;
    Ok(snapshot_dir.join(SNAPSHOT_STATE_FILE_NAME))
}

struct LoadedSnapshotState {
    sandbox_config: SandboxConfig,
    microvm_config: MicrovmConfig,
    vcpu_state: Vec<u8>,
    memory_hash: Option<String>,
}

/// 读取文件快照元数据并校验 `memory.bin` 完整性，但不在内存中保留 guest memory。
#[allow(dead_code)]
pub(crate) fn load_state_from_memory_file(
    memory_path: &Path,
) -> Result<(SandboxConfig, MicrovmConfig, Vec<u8>), MicrovmError> {
    let state = load_snapshot_state_from_memory_file(memory_path)?;
    verify_memory_hash_file(memory_path, state.memory_hash.as_deref())?;

    Ok((state.sandbox_config, state.microvm_config, state.vcpu_state))
}

fn load_snapshot_state_from_memory_file(
    memory_path: &Path,
) -> Result<LoadedSnapshotState, MicrovmError> {
    let state_path = state_file_path(memory_path)?;
    let state_bytes = fs::read(&state_path)?;
    let state: SnapshotStateFile = serde_json::from_slice(&state_bytes).map_err(|error| {
        MicrovmError::SnapshotFormat(format!(
            "failed to parse state.json ({}): {error}",
            sanitize_path_display(&state_path)
        ))
    })?;

    if state.version != FILE_SNAPSHOT_VERSION {
        return Err(MicrovmError::SnapshotFormat(format!(
            "unsupported file snapshot version: {}",
            state.version
        )));
    }

    let vcpu_state = BASE64_STANDARD
        .decode(state.vcpu_state_base64.as_bytes())
        .map_err(|error| {
            MicrovmError::SnapshotFormat(format!("failed to decode vCPU state: {error}"))
        })?;

    Ok(LoadedSnapshotState {
        sandbox_config: state.sandbox_config,
        microvm_config: state.microvm_config,
        vcpu_state,
        memory_hash: state.memory_hash,
    })
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
    let mut config = SandboxConfig::default();
    config.fs_readonly = decode_paths(cursor)?;
    config.fs_readwrite = decode_paths(cursor)?;
    config.deny_network = cursor.read_bool()?;
    config.memory_limit_mb = cursor.read_opt_u64()?;
    config.timeout_secs = cursor.read_opt_u64()?;
    config.seccomp_profile = u8_to_seccomp(cursor.read_u8()?)?;
    config.allow_fork = cursor.read_bool()?;
    config.allowed_http_domains = decode_strings(cursor)?;
    Ok(config)
}

fn encode_microvm_config(out: &mut Vec<u8>, config: &MicrovmConfig) -> Result<(), MicrovmError> {
    out.push(config.vcpu_count);
    out.extend_from_slice(&config.memory_mb.to_le_bytes());
    encode_opt_u64(out, config.cpu_quota_us);
    out.push(vm_security_profile_to_u8(config.security_profile));
    encode_path(out, &config.kernel_path)?;
    encode_path(out, &config.rootfs_path)?;
    Ok(())
}

fn decode_microvm_config(
    cursor: &mut SnapshotCursor<'_>,
    version: u16,
) -> Result<MicrovmConfig, MicrovmError> {
    Ok(MicrovmConfig {
        vcpu_count: cursor.read_u8()?,
        memory_mb: cursor.read_u32()?,
        cpu_quota_us: if version >= 2 {
            cursor.read_opt_u64()?
        } else {
            None
        },
        security_profile: if version >= 3 {
            u8_to_vm_security_profile(cursor.read_u8()?)?
        } else {
            VmSecurityProfile::Secure
        },
        kernel_path: decode_path(cursor)?,
        rootfs_path: decode_path(cursor)?,
    })
}

fn vm_security_profile_to_u8(profile: VmSecurityProfile) -> u8 {
    match profile {
        VmSecurityProfile::Secure => 0,
        VmSecurityProfile::Performance => 1,
    }
}

fn u8_to_vm_security_profile(value: u8) -> Result<VmSecurityProfile, MicrovmError> {
    match value {
        0 => Ok(VmSecurityProfile::Secure),
        1 => Ok(VmSecurityProfile::Performance),
        other => Err(MicrovmError::SnapshotFormat(format!(
            "invalid VM security profile value: {other}"
        ))),
    }
}

fn encode_paths(out: &mut Vec<u8>, paths: &[PathBuf]) -> Result<(), MicrovmError> {
    let len = u32::try_from(paths.len())
        .map_err(|_| MicrovmError::SnapshotFormat("path count exceeds u32 limit".into()))?;
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
        .map_err(|_| MicrovmError::SnapshotFormat("string count exceeds u32 limit".into()))?;
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
            .map_err(|e| {
                MicrovmError::SnapshotFormat(format!("failed to decode UTF-8 string: {e}"))
            })
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
        .map_err(|err| MicrovmError::SnapshotFormat(format!("path is not valid UTF-8: {err}")))?;
    Ok(PathBuf::from(value))
}

fn encode_bytes(out: &mut Vec<u8>, data: &[u8]) -> Result<(), MicrovmError> {
    let len = u64::try_from(data.len())
        .map_err(|_| MicrovmError::SnapshotFormat("data block length exceeds u64 limit".into()))?;
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
            "invalid seccomp profile encoding: {other}"
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
            .ok_or_else(|| MicrovmError::SnapshotFormat("snapshot offset overflow".into()))?;
        let bytes = self.data.get(self.offset..end).ok_or_else(|| {
            MicrovmError::SnapshotFormat(
                "snapshot data ended early while reading fixed-length field".into(),
            )
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
                "invalid boolean encoding: {other}"
            ))),
        }
    }

    fn read_opt_u64(&mut self) -> Result<Option<u64>, MicrovmError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u64()?)),
            other => Err(MicrovmError::SnapshotFormat(format!(
                "invalid Option<u64> encoding: {other}"
            ))),
        }
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, MicrovmError> {
        let len = usize::try_from(self.read_u64()?).map_err(|_| {
            MicrovmError::SnapshotFormat("data block length cannot be converted to usize".into())
        })?;
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| MicrovmError::SnapshotFormat("snapshot offset overflow".into()))?;
        let bytes = self.data.get(self.offset..end).ok_or_else(|| {
            MicrovmError::SnapshotFormat(
                "snapshot data ended early while reading byte block".into(),
            )
        })?;
        self.offset = end;
        Ok(bytes.to_vec())
    }

    fn is_eof(&self) -> bool {
        self.offset == self.data.len()
    }
}
