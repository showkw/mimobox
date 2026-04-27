// 流式输出示例：实时接收 Stdout/Stderr/Exit 事件并打印。
#[cfg(all(feature = "vm", target_os = "linux"))]
use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};
#[cfg(all(feature = "vm", target_os = "linux"))]
use std::io::{self, Write};

#[cfg(all(feature = "vm", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder().isolation(IsolationLevel::MicroVm).build()?;

    let mut sandbox = Sandbox::with_config(config)?;
    let receiver =
        sandbox.stream_execute("/bin/sh -c 'echo stdout-line; echo stderr-line >&2; echo done'")?;

    for event in receiver {
        match event {
            StreamEvent::Stdout(chunk) => {
                print!("{}", String::from_utf8_lossy(&chunk));
                io::stdout().flush()?;
            }
            StreamEvent::Stderr(chunk) => {
                eprint!("{}", String::from_utf8_lossy(&chunk));
                io::stderr().flush()?;
            }
            StreamEvent::Exit(code) => {
                println!("exit: {code}");
            }
            StreamEvent::TimedOut => {
                println!("command timed out");
            }
            _ => {}
        }
    }

    sandbox.destroy()?;
    Ok(())
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
fn main() {
    eprintln!("此示例需要 Linux + mimobox-sdk 的 vm feature。");
}
