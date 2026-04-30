// 基本命令执行示例：创建沙箱并执行一条简单命令。
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use mimobox_sdk::Sandbox;

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello mimobox")?;
    println!("exit: {:?}", result.exit_code);
    println!("stdout: {}", String::from_utf8_lossy(&result.stdout));
    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(all(feature = "os", any(target_os = "linux", target_os = "macos"))))]
fn main() {
    eprintln!("此示例需要 Linux/macOS + mimobox-sdk 的 os feature。");
}
