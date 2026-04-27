// 注意：Python SDK 提供了更简洁的 execute_code() API，可一行代码执行多语言代码。
// 参见 examples/python/multi_language.py 和 examples/python/fork_isolation.py。
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
        println!("提示：添加 --interactive 可进入交互模式，输入 quit 退出。");
    }

    sandbox.destroy()?;
    Ok(())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn run_preset_tasks(sandbox: &mut Sandbox) -> Result<(), Box<dyn std::error::Error>> {
    let requests = [
        AgentRequest {
            user_text: "请确认沙箱是否能执行基础命令",
            command: "/bin/echo agent-ready",
        },
        AgentRequest {
            user_text: "请生成一个简短的任务摘要",
            command: "/bin/sh -c 'printf \"task=%s\\nstatus=%s\\n\" demo safe'",
        },
        AgentRequest {
            user_text: "请演示 stderr 和退出码处理",
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
    println!("\n进入交互模式。输入命令后由沙箱执行，输入 quit 退出。比如：/bin/echo hello");

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
    eprintln!("此示例需要 Linux/macOS + mimobox-sdk 的 os feature。");
}
