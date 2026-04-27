// 文件系统隔离示例：显式声明只读路径和可写路径。
use mimobox_sdk::{Config, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .fs_readonly(["/usr", "/bin", "/lib", "/etc"])
        .fs_readwrite(["/tmp"])
        .build()?;

    let mut sandbox = Sandbox::with_config(config)?;
    let result = sandbox
        .execute("/bin/sh -c 'echo writable > /tmp/mimobox-fs.txt && cat /tmp/mimobox-fs.txt'")?;

    println!("exit code: {:?}", result.exit_code);
    println!("stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&result.stderr));

    sandbox.destroy()?;
    Ok(())
}
