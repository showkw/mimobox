// LLM Agent 集成示例：自然语言请求 -> LLM 生成命令 -> mimobox 沙箱执行 -> LLM 总结结果。
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use mimobox_sdk::{Config, IsolationLevel, Sandbox};
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use serde_json::json;
#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
use std::io::{self, Write};

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder().isolation(IsolationLevel::Os).build();
    let mut sandbox = Sandbox::with_config(config)?;

    println!("LLM Agent + mimobox sandbox demo");
    println!("输入自然语言请求，LLM 会生成 shell 命令并交给沙箱执行。输入 quit 退出。\n");

    run_agent_loop(&mut sandbox)?;

    sandbox.destroy()?;
    Ok(())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn run_agent_loop(sandbox: &mut Sandbox) -> Result<(), Box<dyn std::error::Error>> {
    let llm = LlmBackend::from_env()?;

    loop {
        print!("user> ");
        io::stdout().flush()?;

        let mut request = String::new();
        let bytes_read = io::stdin().read_line(&mut request)?;
        if bytes_read == 0 {
            break;
        }

        let request = request.trim();
        if request == "quit" {
            break;
        }
        if request.is_empty() {
            continue;
        }

        let command = ask_llm_for_command(&llm, request)?;
        println!("\nagent command: {command}");

        let result = sandbox.execute(&command)?;
        let summary = ask_llm_for_summary(&llm, request, &command, &result)?;

        println!("\nassistant> {summary}\n");
    }

    Ok(())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn ask_llm_for_command(
    llm: &LlmBackend,
    request: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        r#"你是一个将用户请求转换为安全 shell 命令的 Agent。

要求：
1. 只输出一条 shell 命令，不要解释，不要使用 Markdown。
2. 优先使用只读、低风险命令。
3. 不要输出会删除文件、修改系统配置、联网访问或泄露凭据的命令。
4. 如果请求不适合执行命令，输出：/bin/echo '无法安全执行该请求'

用户请求：{request}"#
    );

    let command = llm.call(&prompt)?;
    Ok(normalize_command(&command))
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn ask_llm_for_summary(
    llm: &LlmBackend,
    request: &str,
    command: &str,
    result: &mimobox_sdk::ExecuteResult,
) -> Result<String, Box<dyn std::error::Error>> {
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    let exit_code = result
        .exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "无退出码".to_string());

    let prompt = format!(
        r#"你是一个命令执行结果总结助手。请用简体中文回答用户。

用户请求：{request}
执行命令：{command}
退出码：{exit_code}
是否超时：{timed_out}
耗时：{elapsed:?}

stdout：
{stdout}

stderr：
{stderr}

请基于以上信息给出简洁总结。如果命令失败，说明失败原因和可行下一步。"#,
        timed_out = result.timed_out,
        elapsed = result.elapsed,
    );

    llm.call(&prompt)
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
enum LlmBackend {
    OpenAI {
        api_key: String,
        base_url: String,
        model: String,
    },
    Anthropic {
        api_key: String,
        base_url: String,
        model: String,
    },
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
impl LlmBackend {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
            let model = std::env::var("ANTHROPIC_MODEL")?;
            let base_url = std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com".into());
            return Ok(Self::Anthropic { api_key, base_url, model });
        }

        Ok(Self::OpenAI {
            api_key: std::env::var("OPENAI_API_KEY")?,
            base_url: std::env::var("OPENAI_BASE_URL")?,
            model: std::env::var("OPENAI_MODEL")?,
        })
    }

    fn call(&self, prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        match self {
            Self::OpenAI {
                api_key,
                base_url,
                model,
            } => call_openai(base_url, model, api_key, prompt),
            Self::Anthropic { api_key, base_url, model } => {
                call_anthropic(base_url, api_key, model, prompt)
            }
        }
    }
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn call_openai(
    base_url: &str,
    model: &str,
    api_key: &str,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let endpoint = format!("{}/responses", base_url.trim_end_matches('/'));
    let body = json!({
        "model": model,
        "input": prompt,
    });

    let response = post_json(&endpoint, body, |request| request.bearer_auth(api_key))?;
    let content = response["output"][0]["content"][0]["text"]
        .as_str()
        .ok_or("OpenAI 响应缺少 output[0].content[0].text")?;

    Ok(content.trim().to_string())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn call_anthropic(
    base_url: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let endpoint = format!("{}/v1/messages", base_url.trim_end_matches('/'));
    let body = json!({
        "model": model,
        "max_tokens": 1024,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
    });

    let response = post_json(&endpoint, body, |request| {
        request
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
    })?;
    let content = response["content"][0]["text"]
        .as_str()
        .ok_or("Anthropic 响应缺少 content[0].text")?;

    Ok(content.trim().to_string())
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn post_json<F>(
    endpoint: &str,
    body: serde_json::Value,
    apply_auth: F,
) -> Result<serde_json::Value, Box<dyn std::error::Error>>
where
    F: FnOnce(reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder,
{
    let request = reqwest::blocking::Client::new()
        .post(endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string());

    let response_text = apply_auth(request).send()?.error_for_status()?.text()?;
    Ok(serde_json::from_str(&response_text)?)
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn normalize_command(command: &str) -> String {
    // 兼容模型偶尔输出的 Markdown fenced code block，最终只保留命令文本。
    let command = command.trim();
    let command = command.strip_prefix("```sh").unwrap_or(command);
    let command = command.strip_prefix("```bash").unwrap_or(command);
    let command = command.strip_prefix("```").unwrap_or(command);
    let command = command.strip_suffix("```").unwrap_or(command);

    command.trim().lines().next().unwrap_or_default().trim().to_string()
}

#[cfg(not(all(feature = "os", any(target_os = "linux", target_os = "macos"))))]
fn main() {
    eprintln!("此示例需要 Linux/macOS + mimobox-sdk 的 os feature。");
}
