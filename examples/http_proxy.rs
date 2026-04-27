// HTTP 代理示例：配置域名白名单并通过 host 代理发起 GET 请求。
#[cfg(all(feature = "vm", target_os = "linux"))]
use mimobox_sdk::{Config, IsolationLevel, Sandbox};
#[cfg(all(feature = "vm", target_os = "linux"))]
use std::collections::HashMap;

#[cfg(all(feature = "vm", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .allowed_http_domains(["api.github.com"])
        .build()?;

    let mut sandbox = Sandbox::with_config(config)?;
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "mimobox-example".to_string());
    headers.insert(
        "Accept".to_string(),
        "application/vnd.github+json".to_string(),
    );

    let response = sandbox.http_request("GET", "https://api.github.com/zen", headers, None)?;

    println!("status: {}", response.status);
    println!("body: {}", String::from_utf8_lossy(&response.body));

    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
fn main() {
    eprintln!("此示例需要 Linux + mimobox-sdk 的 vm feature。");
}
