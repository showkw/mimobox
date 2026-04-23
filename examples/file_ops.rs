// 文件操作示例：写入、读回并验证沙箱内文件内容一致。
#[cfg(all(feature = "vm", target_os = "linux"))]
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

#[cfg(all(feature = "vm", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder().isolation(IsolationLevel::MicroVm).build();

    let mut sandbox = Sandbox::with_config(config)?;
    let path = "/tmp/mimobox-example.txt";
    let expected = b"hello from mimobox\n";

    sandbox.write_file(path, expected)?;
    let actual = sandbox.read_file(path)?;

    assert_eq!(actual, expected);
    println!("read back: {}", String::from_utf8_lossy(&actual));

    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
fn main() {
    eprintln!("此示例需要 Linux + mimobox-sdk 的 vm feature。");
}
