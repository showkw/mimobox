// 预热池示例：从快照恢复沙箱，减少重复启动 microVM 的开销。
#[cfg(all(feature = "vm", target_os = "linux"))]
use mimobox_sdk::{Config, IsolationLevel, RestorePool, RestorePoolConfig, Sandbox};
#[cfg(all(feature = "vm", target_os = "linux"))]
use std::time::Instant;

#[cfg(all(feature = "vm", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build()?;
    let mut sandbox = Sandbox::with_config(config.clone())?;
    let snapshot = sandbox.snapshot()?;

    let pool = RestorePool::new(RestorePoolConfig {
        pool_size: 2,
        base_config: config,
    })?;

    let start = Instant::now();
    let mut restored = pool.restore(&snapshot)?;
    let result = restored.execute("/bin/echo restored from pool")?;

    println!("pool idle: {}", pool.idle_count());
    println!("restore + execute: {:?}", start.elapsed());
    println!("stdout: {}", String::from_utf8_lossy(&result.stdout));

    restored.destroy()?;
    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
fn main() {
    eprintln!("sandbox_pool 示例需要 Linux + mimobox-sdk 的 vm feature。");
}
