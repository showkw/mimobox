// Agent 集成示例：模拟 AI Agent 通过 mimobox SDK 安全执行用户请求。
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use mimobox_sdk::{Config, IsolationLevel, Sandbox, StreamEvent};
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use std::io::{self, Write};

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
struct AgentRequest {
    user_text: &'static str,
    command: &'static str,
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder().isolation(IsolationLevel::Os).build()?;
    let mut sandbox = Sandbox::with_config(config)?;

    println!("agent sandbox isolation: {:?}", sandbox.active_isolation());
    println!(
        "stream event type: {}",
        std::any::type_name::<StreamEvent>()
    );

    run_preset_tasks(&mut sandbox)?;

    if std::env::args().any(|arg| arg == "--interactive") {
        run_interactive_loop(&mut sandbox)?;
    } else {
        println!("Tip: add --interactive to enter interactive mode; type quit to exit.");
    }

    sandbox.destroy()?;
    Ok(())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn run_preset_tasks(sandbox: &mut Sandbox) -> Result<(), Box<dyn std::error::Error>> {
    let requests = [
        AgentRequest {
            user_text: "Please confirm the sandbox can run basic commands",
            command: "/bin/echo agent-ready",
        },
        AgentRequest {
            user_text: "Please generate a short task summary",
            command: "/bin/sh -c 'printf \"task=%s\\nstatus=%s\\n\" demo safe'",
        },
        AgentRequest {
            user_text: "Please demonstrate stderr and exit code handling",
            command: "/bin/sh -c 'echo warning-from-agent >&2; exit 0'",
        },
    ];

    for request in requests {
        println!("\nuser: {}", request.user_text);
        println!("agent command: {}", request.command);
        execute_and_print(sandbox, request.command)?;
    }

    Ok(())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn run_interactive_loop(sandbox: &mut Sandbox) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nInteractive mode. Commands are executed by the sandbox; type quit to exit. Example: /bin/echo hello");

    loop {
        print!("agent> ");
        io::stdout().flush()?;

        let mut input = String::new();
        let bytes_read = io::stdin().read_line(&mut input)?;
        if bytes_read == 0 {
            break;
        }

        let command = input.trim();
        if command == "quit" {
            break;
        }
        if command.is_empty() {
            continue;
        }

        execute_and_print(sandbox, command)?;
    }

    Ok(())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn execute_and_print(
    sandbox: &mut Sandbox,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match sandbox.execute(command) {
        Ok(result) => {
            println!("exit: {:?}", result.exit_code);
            println!("timed_out: {}", result.timed_out);
            println!("elapsed: {:?}", result.elapsed);
            if !result.stdout.is_empty() {
                println!("stdout:\n{}", String::from_utf8_lossy(&result.stdout));
            }
            if !result.stderr.is_empty() {
                eprintln!("stderr:\n{}", String::from_utf8_lossy(&result.stderr));
            }
        }
        Err(error) => {
            eprintln!("sandbox error: {error}");
        }
    }

    Ok(())
}

#[cfg(not(all(feature = "os", any(target_os = "linux", target_os = "macos"))))]
fn main() {
    eprintln!("This example requires Linux/macOS + the mimobox-sdk os feature.");
}
