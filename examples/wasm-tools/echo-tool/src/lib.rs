use mimobox_tool_api::{ToolDescription, ToolError, ToolResult, ExecutionContext, ParamSchema, Value, Guest};

/// 示例 echo 工具：将输入原样返回
struct EchoTool;

impl Guest for EchoTool {
    fn describe() -> ToolDescription {
        ToolDescription {
            name: "echo".to_string(),
            description: "将输入文本原样返回。用于测试 mimobox 工具链。".to_string(),
            parameters: vec![ParamSchema {
                name: "message".to_string(),
                type_: "string".to_string(),
                required: true,
                description: "要回显的消息".to_string(),
                default_value: None,
            }],
            version: "0.1.0".to_string(),
        }
    }

    fn execute(
        input: Vec<(String, Value)>,
        _context: ExecutionContext,
    ) -> Result<ToolResult, ToolError> {
        let message = input
            .iter()
            .find(|(k, _)| k == "message")
            .and_then(|(_, v)| match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| ToolError::InvalidArguments("缺少 message 参数".to_string()))?;

        Ok(ToolResult {
            output: Value::String(message),
            success: true,
            summary: None,
            elapsed_us: 0,
        })
    }
}
