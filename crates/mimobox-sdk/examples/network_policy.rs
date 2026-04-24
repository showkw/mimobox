// 网络策略示例：通过域名白名单和受控 HTTP 代理访问指定站点。
#[cfg(all(feature = "vm", target_os = "linux"))]
use mimobox_sdk::{Config, IsolationLevel, NetworkPolicy, Sandbox};
#[cfg(all(feature = "vm", target_os = "linux"))]
use std::collections::HashMap;

#[cfg(all(feature = "vm", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .network(NetworkPolicy::AllowDomains(vec!["example.com".to_string()]))
        .allowed_http_domains(["example.com"])
        .build();

    let mut sandbox = Sandbox::with_config(config)?;
    let response = sandbox.http_request("GET", "https://example.com", HashMap::new(), None)?;

    println!("status: {}", response.status);
    println!("body bytes: {}", response.body.len());

    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
fn main() {
    eprintln!("network_policy 示例需要 Linux + mimobox-sdk 的 vm feature。");
}
