//! Linux legacy operation adapter; metadata is shared.
use serde_json::Value;
use crate::file_access::FileAccess;
pub(crate) use mcp_gateway::core::tools::{Tool, tool_text};

pub(crate) fn read_file(files: &FileAccess, args: Option<&Value>) -> Value {
    let Some(args) = args.and_then(Value::as_object) else {
        return tool_text(true, "Expected read_file arguments");
    };
    let Some(path) = args.get("path").and_then(Value::as_str) else {
        return tool_text(true, "Missing string argument: path");
    };
    if args.len() != 1 {
        return tool_text(true, "Unexpected read_file argument");
    }
    match files.read_file(path) {
        Ok(text) => tool_text(false, &text),
        Err(problem) => tool_text(true, problem),
    }
}
