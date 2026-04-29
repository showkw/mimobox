// CoW Fork 示例：从同一 microVM 派生副本，并分别执行不同命令。
#[cfg(all(feature = "vm", target_os = "linux"))]
use mimobox_sdk::{Config, IsolationLevel, Sandbox};

#[cfg(all(feature = "vm", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .allow_fork(true)
        .build()?;

    let mut parent = Sandbox::with_config(config)?;
    parent.execute("/bin/echo parent initialized")?;
    let mut child = parent.fork()?;

    let parent_result = parent.execute("/bin/echo parent path")?;
    let child_result = child.execute("/bin/echo child path")?;

    println!("parent: {}", String::from_utf8_lossy(&parent_result.stdout));
    println!("child: {}", String::from_utf8_lossy(&child_result.stdout));

    child.destroy()?;
    parent.destroy()?;
    Ok(())
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
fn main() {
    eprintln!("The fork_demo example requires Linux + the mimobox-sdk vm feature.");
}
