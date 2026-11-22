//! MCP tool names, schemas and audited mutation dispatch.

use serde_json::{Value, json};

use mcp_gateway::security::policy::Action;

use crate::file_access::FileAccess;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tool {
    ReadFile,
    WriteFile,
    ApplyPatch,
}

impl Tool {
    pub(crate) const ALL: [Self; 3] = [Self::ReadFile, Self::WriteFile, Self::ApplyPatch];

    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "read_file" => Some(Self::ReadFile),
            "write_file" => Some(Self::WriteFile),
            "apply_patch" => Some(Self::ApplyPatch),
            _ => None,
        }
    }

    pub(crate) fn action(self) -> Action {
        match self {
            Self::ReadFile => Action::ReadFile,
            Self::WriteFile => Action::WriteFile,
            Self::ApplyPatch => Action::ApplyPatch,
        }
    }

    pub(crate) fn schema(self) -> Value {
        match self {
            Self::ReadFile => json!({
                "name": "read_file",
                "description": "Read a UTF-8 text file relative to the configured allowed root (max 65536 bytes)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Relative file path inside the configured root"
                        }
                    },
                    "required": ["path"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            }),
            Self::WriteFile => json!({
                "name": "write_file",
                "description": "Atomically write up to 65536 bytes of UTF-8 within the allowed root",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                        "overwrite": {"type": "boolean", "default": false}
                    },
                    "required": ["path", "content"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::ApplyPatch => json!({
                "name": "apply_patch",
                "description": "Replace one exact text occurrence in a UTF-8 file guarded by its SHA-256",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "expected_sha256": {"type": "string", "pattern": "^[a-fA-F0-9]{64}$"},
                        "old": {"type": "string", "minLength": 1},
                        "new": {"type": "string"}
                    },
                    "required": ["path", "expected_sha256", "old", "new"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
        }
    }
}

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

pub(crate) fn tool_text(is_error: bool, text: &str) -> Value {
    json!({ "content": [{"type": "text", "text": text}], "isError": is_error })
}
