// Agent 流式执行示例：实时接收沙箱输出并反馈给上层 Agent。
#[cfg(all(feature = "vm", target_os = "linux"))]
use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};
#[cfg(all(feature = "vm", target_os = "linux"))]
use std::io::{self, Write};

#[cfg(all(feature = "vm", target_os = "linux"))]
struct AgentStep {
    description: &'static str,
    command: &'static str,
}

#[cfg(all(feature = "vm", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .isolation(IsolationLevel::MicroVm)
        .build()?;

    let mut sandbox = Sandbox::with_config(config)?;
    let steps = [
        AgentStep {
            description: "Confirm the microVM Agent runtime",
            command: "/bin/sh -c 'echo agent-stream-ready'",
        },
        AgentStep {
            description: "Simulate step-by-step task progress output",
            command: "/bin/sh -c 'echo step-1; echo step-2; echo done'",
        },
        AgentStep {
            description: "Simulate error channel output",
            command: "/bin/sh -c 'echo stderr-from-agent >&2; echo recovered'",
        },
    ];

    for step in steps {
        println!("\nagent step: {}", step.description);
        println!("command: {}", step.command);
        stream_step(&mut sandbox, step.command)?;
    }

    sandbox.destroy()?;
    Ok(())
}

#[cfg(all(feature = "vm", target_os = "linux"))]
fn stream_step(sandbox: &mut Sandbox, command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let receiver = sandbox.stream_execute(command)?;

    for event in receiver {
        match event {
            StreamEvent::Stdout(chunk) => {
                print!("stdout: {}", String::from_utf8_lossy(&chunk));
                io::stdout().flush()?;
            }
            StreamEvent::Stderr(chunk) => {
                eprint!("stderr: {}", String::from_utf8_lossy(&chunk));
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

    Ok(())
}

#[cfg(not(all(feature = "vm", target_os = "linux")))]
fn main() {
    eprintln!("This example requires Linux + the mimobox-sdk vm feature.");
}
