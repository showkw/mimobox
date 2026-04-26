use mimobox_core::{DirEntry, FileStat, FileType};

use crate::vm::{GuestCommandResult, GuestFileErrorKind, MicrovmError};

const GUEST_SANDBOX_PREFIX: &str = "/sandbox/";
const EXIT_PATH_NOT_FOUND: i32 = 10;
const EXIT_NOT_DIRECTORY: i32 = 11;

const LIST_DIR_SCRIPT: &str = r#"
dir=$1
if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
    echo "path not found" >&2
    exit 10
fi
if [ ! -d "$dir" ]; then
    echo "path is not a directory" >&2
    exit 11
fi

for entry in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    name=${entry##*/}
    if [ -L "$entry" ]; then
        kind=symlink
        is_symlink=1
    elif [ -d "$entry" ]; then
        kind=dir
        is_symlink=0
    elif [ -f "$entry" ]; then
        kind=file
        is_symlink=0
    else
        kind=other
        is_symlink=0
    fi
    size=$(stat -c %s "$entry") || exit 12
    printf '%s\t%s\t%s\t%s\n' "$kind" "$size" "$is_symlink" "$name"
done
"#;

const FILE_EXISTS_SCRIPT: &str = r#"
if [ -e "$1" ] || [ -L "$1" ]; then
    echo yes
else
    echo no
fi
"#;

const STAT_SCRIPT: &str = r#"
path=$1
if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    echo "path not found" >&2
    exit 10
fi

if [ -L "$path" ]; then
    kind=symlink
elif [ -d "$path" ]; then
    kind=dir
elif [ -f "$path" ]; then
    kind=file
else
    kind=other
fi

size=$(stat -c %s "$path") || exit 12
mode=$(stat -c %f "$path") || exit 12
modified=$(stat -c %Y "$path") || exit 12
printf '%s\t%s\t%s\t%s\n' "$kind" "$size" "$mode" "$modified"
"#;

pub(crate) fn list_dir<F>(path: &str, mut execute: F) -> Result<Vec<DirEntry>, MicrovmError>
where
    F: FnMut(&[String]) -> Result<GuestCommandResult, MicrovmError>,
{
    validate_guest_path(path)?;
    let result = execute(&shell_script_command(LIST_DIR_SCRIPT, &[path.to_string()]))?;
    ensure_success(result.clone(), "list_dir", path)?;
    let stdout = command_stdout_utf8(result.stdout)?;
    parse_list_dir_output(&stdout)
}

pub(crate) fn file_exists<F>(path: &str, mut execute: F) -> Result<bool, MicrovmError>
where
    F: FnMut(&[String]) -> Result<GuestCommandResult, MicrovmError>,
{
    validate_guest_path(path)?;
    let result = execute(&shell_script_command(
        FILE_EXISTS_SCRIPT,
        &[path.to_string()],
    ))?;
    ensure_success(result.clone(), "file_exists", path)?;
    let stdout = command_stdout_utf8(result.stdout)?;
    match stdout.trim() {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(MicrovmError::Backend(format!(
            "guest file_exists returned unexpected output for {path}: {other}"
        ))),
    }
}

pub(crate) fn remove_file<F>(path: &str, mut execute: F) -> Result<(), MicrovmError>
where
    F: FnMut(&[String]) -> Result<GuestCommandResult, MicrovmError>,
{
    validate_guest_path(path)?;
    let cmd = vec!["/bin/rm".to_string(), "-f".to_string(), path.to_string()];
    let result = execute(&cmd)?;
    ensure_success(result, "remove_file", path)
}

pub(crate) fn rename<F>(from: &str, to: &str, mut execute: F) -> Result<(), MicrovmError>
where
    F: FnMut(&[String]) -> Result<GuestCommandResult, MicrovmError>,
{
    validate_guest_path(from)?;
    validate_guest_path(to)?;
    let cmd = vec!["/bin/mv".to_string(), from.to_string(), to.to_string()];
    let result = execute(&cmd)?;
    ensure_success(result, "rename", from)
}

pub(crate) fn stat<F>(path: &str, mut execute: F) -> Result<FileStat, MicrovmError>
where
    F: FnMut(&[String]) -> Result<GuestCommandResult, MicrovmError>,
{
    validate_guest_path(path)?;
    let result = execute(&shell_script_command(STAT_SCRIPT, &[path.to_string()]))?;
    ensure_success(result.clone(), "stat", path)?;
    let stdout = command_stdout_utf8(result.stdout)?;
    parse_stat_output(path, &stdout)
}

fn shell_script_command(script: &str, args: &[String]) -> Vec<String> {
    let mut cmd = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
    cmd.push("mimobox-file-op".to_string());
    cmd.extend(args.iter().cloned());
    cmd
}

fn validate_guest_path(path: &str) -> Result<(), MicrovmError> {
    if path.is_empty() {
        return Err(MicrovmError::InvalidConfig(
            "guest file path must not be empty".to_string(),
        ));
    }
    if path.as_bytes().contains(&0) {
        return Err(MicrovmError::InvalidConfig(
            "guest file path must not contain NUL bytes".to_string(),
        ));
    }
    if !path.starts_with(GUEST_SANDBOX_PREFIX) {
        return Err(MicrovmError::InvalidConfig(format!(
            "guest file path must start with {GUEST_SANDBOX_PREFIX}: {path}"
        )));
    }
    if path.split('/').any(|component| component == "..") {
        return Err(MicrovmError::InvalidConfig(format!(
            "guest file path must not contain '..' path traversal: {path}"
        )));
    }
    Ok(())
}

fn ensure_success(
    result: GuestCommandResult,
    operation: &str,
    path: &str,
) -> Result<(), MicrovmError> {
    if result.timed_out {
        return Err(MicrovmError::Backend(format!(
            "guest {operation} timed out for {path}"
        )));
    }

    match result.exit_code {
        Some(0) => Ok(()),
        Some(EXIT_PATH_NOT_FOUND) => Err(guest_file_error(GuestFileErrorKind::NotFound, path)),
        Some(EXIT_NOT_DIRECTORY) => Err(MicrovmError::Backend(format!(
            "guest {operation} target is not a directory: {path}"
        ))),
        Some(exit_code) => Err(MicrovmError::Backend(format!(
            "guest {operation} failed for {path}: exit_code={exit_code}, stderr={}",
            stderr_preview(&result.stderr)
        ))),
        None => Err(MicrovmError::Backend(format!(
            "guest {operation} did not return an exit code for {path}"
        ))),
    }
}

fn guest_file_error(kind: GuestFileErrorKind, path: &str) -> MicrovmError {
    MicrovmError::GuestFile {
        kind,
        path: path.to_string(),
    }
}

fn command_stdout_utf8(stdout: Vec<u8>) -> Result<String, MicrovmError> {
    String::from_utf8(stdout)
        .map_err(|error| MicrovmError::Backend(format!("guest output is not UTF-8: {error}")))
}

fn stderr_preview(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut preview = text.chars().take(512).collect::<String>();
    if text.chars().count() > 512 {
        preview.push_str("...");
    }
    preview
}

fn parse_list_dir_output(output: &str) -> Result<Vec<DirEntry>, MicrovmError> {
    output
        .lines()
        .filter(|line| !line.is_empty())
        .map(parse_list_dir_line)
        .collect()
}

fn parse_list_dir_line(line: &str) -> Result<DirEntry, MicrovmError> {
    let mut parts = line.splitn(4, '\t');
    let kind = parts
        .next()
        .ok_or_else(|| parse_error(line, "missing type"))?;
    let size = parts
        .next()
        .ok_or_else(|| parse_error(line, "missing size"))?
        .parse::<u64>()
        .map_err(|error| parse_error(line, &format!("invalid size: {error}")))?;
    let is_symlink = match parts
        .next()
        .ok_or_else(|| parse_error(line, "missing symlink flag"))?
    {
        "0" => false,
        "1" => true,
        value => return Err(parse_error(line, &format!("invalid symlink flag: {value}"))),
    };
    let name = parts
        .next()
        .ok_or_else(|| parse_error(line, "missing name"))?
        .to_string();

    Ok(DirEntry::new(
        name,
        parse_file_type(kind)?,
        size,
        is_symlink,
    ))
}

fn parse_stat_output(path: &str, output: &str) -> Result<FileStat, MicrovmError> {
    let line = output
        .lines()
        .find(|line| !line.is_empty())
        .ok_or_else(|| MicrovmError::Backend("guest stat returned empty output".to_string()))?;
    let mut parts = line.splitn(4, '\t');
    let kind = parts
        .next()
        .ok_or_else(|| parse_error(line, "missing type"))?;
    let size = parts
        .next()
        .ok_or_else(|| parse_error(line, "missing size"))?
        .parse::<u64>()
        .map_err(|error| parse_error(line, &format!("invalid size: {error}")))?;
    let mode = u32::from_str_radix(
        parts
            .next()
            .ok_or_else(|| parse_error(line, "missing mode"))?,
        16,
    )
    .map_err(|error| parse_error(line, &format!("invalid mode: {error}")))?;
    let modified_ms = parts
        .next()
        .ok_or_else(|| parse_error(line, "missing modified timestamp"))?
        .parse::<u64>()
        .map(|seconds| seconds.saturating_mul(1000))
        .map(Some)
        .map_err(|error| parse_error(line, &format!("invalid modified timestamp: {error}")))?;
    let file_type = parse_file_type(kind)?;

    Ok(FileStat::new(
        path.to_string(),
        matches!(file_type, FileType::Dir),
        matches!(file_type, FileType::File),
        size,
        mode,
        modified_ms,
    ))
}

fn parse_file_type(kind: &str) -> Result<FileType, MicrovmError> {
    match kind {
        "file" => Ok(FileType::File),
        "dir" => Ok(FileType::Dir),
        "symlink" => Ok(FileType::Symlink),
        "other" => Ok(FileType::Other),
        other => Err(MicrovmError::Backend(format!(
            "unknown guest file type: {other}"
        ))),
    }
}

fn parse_error(line: &str, detail: &str) -> MicrovmError {
    MicrovmError::Backend(format!(
        "failed to parse guest file operation output: {detail}; line={line}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_guest_path_rejects_paths_outside_sandbox() {
        assert!(validate_guest_path("/tmp/file").is_err());
        assert!(validate_guest_path("/sandbox/../etc/passwd").is_err());
        assert!(validate_guest_path("/sandbox/file").is_ok());
    }

    #[test]
    fn parse_list_dir_output_returns_core_entries() {
        let entries = parse_list_dir_output("file\t5\t0\ta.txt\ndir\t0\t0\td\nsymlink\t7\t1\tl\n")
            .expect("解析目录输出必须成功");

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].file_type, FileType::File);
        assert_eq!(entries[0].size, 5);
        assert!(!entries[0].is_symlink);
        assert_eq!(entries[2].file_type, FileType::Symlink);
        assert!(entries[2].is_symlink);
    }

    #[test]
    fn parse_stat_output_returns_file_stat() {
        let stat = parse_stat_output("/sandbox/a.txt", "file\t4\t81a4\t1700000000\n")
            .expect("解析 stat 输出必须成功");

        assert_eq!(stat.path, "/sandbox/a.txt");
        assert!(stat.is_file);
        assert!(!stat.is_dir);
        assert_eq!(stat.size, 4);
        assert_eq!(stat.mode, 0x81a4);
        assert_eq!(stat.modified_ms, Some(1_700_000_000_000));
    }
}
