// 资源限制示例：配置执行超时和内存上限，并观察超时结果。
use mimobox_sdk::{Config, Sandbox};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .timeout(Duration::from_secs(2))
        .memory_limit_mb(128)
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let result = sandbox.execute("/bin/sleep 10")?;

    println!("timed out: {}", result.timed_out);
    println!("exit code: {:?}", result.exit_code);
    println!("elapsed: {:?}", result.elapsed);
    assert!(result.timed_out);

    sandbox.destroy()?;
    Ok(())
}
