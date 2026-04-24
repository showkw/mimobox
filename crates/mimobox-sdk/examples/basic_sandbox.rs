// 最简沙箱示例：创建沙箱、执行命令并打印核心结果。
use mimobox_sdk::Sandbox;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Sandbox::new()?;
    let result = sandbox.execute("/bin/echo hello mimobox")?;
    println!("exit code: {:?}", result.exit_code);
    println!("stdout: {}", String::from_utf8_lossy(&result.stdout));
    sandbox.destroy()?;
    Ok(())
}
