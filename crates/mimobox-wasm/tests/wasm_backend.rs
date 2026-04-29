use std::error::Error;
use std::path::PathBuf;

use mimobox_core::{Sandbox, SandboxConfig, SeccompProfile};
use mimobox_wasm::WasmSandbox;
use tempfile::TempDir;

fn wasm_config() -> SandboxConfig {
    let mut config = SandboxConfig::default();
    config.timeout_secs = Some(5);
    config.memory_limit_mb = Some(64);
    config.fs_readonly = vec![];
    config.fs_readwrite = vec![];
    config.deny_network = true;
    config.seccomp_profile = SeccompProfile::Essential;
    config.allow_fork = false;
    config.allowed_http_domains = vec![];
    config
}

fn compile_wat_to_tempfile(
    file_name: &str,
    wat_source: &str,
) -> Result<(TempDir, PathBuf), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let wasm_path = temp_dir.path().join(file_name);
    let wasm_bytes = wat::parse_str(wat_source)?;
    std::fs::write(&wasm_path, wasm_bytes)?;
    Ok((temp_dir, wasm_path))
}

fn write_raw_module(file_name: &str, bytes: &[u8]) -> Result<(TempDir, PathBuf), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let wasm_path = temp_dir.path().join(file_name);
    std::fs::write(&wasm_path, bytes)?;
    Ok((temp_dir, wasm_path))
}

#[test]
fn wasm_module_loads_and_executes() -> Result<(), Box<dyn Error>> {
    let (_temp_dir, wasm_path) = compile_wat_to_tempfile(
        "noop.wasm",
        r#"
            (module
              (func (export "_start"))
            )
        "#,
    )?;
    let mut sandbox = WasmSandbox::new(wasm_config())?;
    let command = vec![wasm_path.to_string_lossy().into_owned()];
    let result = sandbox.execute(&command)?;

    assert_eq!(result.exit_code, Some(0));
    assert!(!result.timed_out);
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());

    Ok(())
}

#[test]
fn wasm_sandbox_captures_stdout_and_stderr() -> Result<(), Box<dyn Error>> {
    let (_temp_dir, wasm_path) = compile_wat_to_tempfile(
        "stdio.wasm",
        r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 32) "stdout line\n")
              (data (i32.const 64) "stderr line\n")
              (func $write (param $fd i32) (param $ptr i32) (param $len i32)
                i32.const 0
                local.get $ptr
                i32.store
                i32.const 4
                local.get $len
                i32.store
                local.get $fd
                i32.const 0
                i32.const 1
                i32.const 24
                call $fd_write
                drop)
              (func (export "_start")
                i32.const 1
                i32.const 32
                i32.const 12
                call $write
                i32.const 2
                i32.const 64
                i32.const 12
                call $write))
        "#,
    )?;
    let mut sandbox = WasmSandbox::new(wasm_config())?;
    let command = vec![wasm_path.to_string_lossy().into_owned()];
    let result = sandbox.execute(&command)?;
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    assert_eq!(result.exit_code, Some(0));
    assert!(!result.timed_out);
    assert!(stdout.contains("stdout line"));
    assert!(stderr.contains("stderr line"));

    Ok(())
}

#[test]
fn wasm_sandbox_times_out_infinite_loops() -> Result<(), Box<dyn Error>> {
    let (_temp_dir, wasm_path) = compile_wat_to_tempfile(
        "spin.wasm",
        r#"
            (module
              (func (export "_start")
                (loop $spin
                  br $spin)))
        "#,
    )?;
    let mut config = wasm_config();
    config.timeout_secs = Some(1);
    let mut sandbox = WasmSandbox::new(config)?;
    let command = vec![wasm_path.to_string_lossy().into_owned()];
    let result = sandbox.execute(&command)?;

    assert!(result.timed_out);
    assert_eq!(result.exit_code, None);

    Ok(())
}

#[test]
fn wasm_sandbox_enforces_memory_limits() -> Result<(), Box<dyn Error>> {
    let (_temp_dir, wasm_path) = compile_wat_to_tempfile(
        "grow.wasm",
        r#"
            (module
              (memory (export "memory") 1)
              (func (export "_start")
                i32.const 1024
                memory.grow
                drop))
        "#,
    )?;
    let mut config = wasm_config();
    config.memory_limit_mb = Some(1);
    let mut sandbox = WasmSandbox::new(config)?;
    let command = vec![wasm_path.to_string_lossy().into_owned()];
    let result = sandbox.execute(&command);

    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("memory limit exceeded") || msg.contains("oom"),
                "expected OOM error, got: {e}"
            );
        }
        Ok(r) => {
            // Some runtimes may return exit_code=1 instead of an error
            assert_eq!(r.exit_code, Some(1));
            assert!(!r.timed_out);
        }
    }

    Ok(())
}

#[test]
fn wasm_sandbox_rejects_invalid_modules() -> Result<(), Box<dyn Error>> {
    let (_temp_dir, wasm_path) = write_raw_module("invalid.wasm", b"not-a-valid-wasm-module")?;
    let mut sandbox = WasmSandbox::new(wasm_config())?;
    let command = vec![wasm_path.to_string_lossy().into_owned()];
    let result = sandbox.execute(&command);

    assert!(result.is_err());

    Ok(())
}
