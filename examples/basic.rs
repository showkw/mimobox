// 基本命令执行示例：创建沙箱并执行一条简单命令。
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello mimobox")?;
    println!("exit: {:?}", result.exit_code);
    println!("stdout: {}", String::from_utf8_lossy(&result.stdout));
    sandbox.destroy()?;
    Ok(())
}
