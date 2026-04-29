// 环境变量注入示例：通过 execute_with_env 注入变量并验证输出。
#[cfg(all(feature = "vm", target_os = "linux"))]
use mimobox_sdk::{Config, IsolationLevel, Sandbox};
#[cfg(all(feature = "vm", target_os = "linux"))]
use std::collections::HashMap;

#[cfg(all(feature = "vm", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build()?;

    let mut sandbox = Sandbox::with_config(config)?;
    let mut env = HashMap::new();
    env.insert("MY_VAR".to_string(), "hello".to_string());

    let result = sandbox.execute_with_env("/bin/sh -c 'echo $MY_VAR'", env)?;
    let stdout = String::from_utf8_lossy(&result.stdout);

    assert!(stdout.contains("hello"));
    println!("stdout: {stdout}");

    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
fn main() {
    eprintln!("This example requires Linux + the mimobox-sdk vm feature.");
}
