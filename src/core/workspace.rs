//! Portable private-workspace tool contract. Native adapters enforce path and mutation safety.
use super::tools::Tool;
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum WorkspaceTool {
    PlatformInfo,
    ReadFile,
    ListDirectory,
    FileInfo,
    WriteFile,
    ApplyPatch,
}
impl WorkspaceTool {
    pub const ALL: [Self; 6] = [
        Self::PlatformInfo,
        Self::ReadFile,
        Self::ListDirectory,
        Self::FileInfo,
        Self::WriteFile,
        Self::ApplyPatch,
    ];
    pub const READ_ONLY: [Self; 4] = [
        Self::PlatformInfo,
        Self::ReadFile,
        Self::ListDirectory,
        Self::FileInfo,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::PlatformInfo => "platform_info",
            Self::ReadFile => Tool::ReadFile.name(),
            Self::ListDirectory => Tool::ListDirectory.name(),
            Self::FileInfo => Tool::FileInfo.name(),
            Self::WriteFile => Tool::WriteFile.name(),
            Self::ApplyPatch => Tool::ApplyPatch.name(),
        }
    }
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }
    pub fn is_mutation(self) -> bool {
        matches!(self, Self::WriteFile | Self::ApplyPatch)
    }
    pub fn schema(self) -> Value {
        match self {
            Self::PlatformInfo => {
                json!({"name":"platform_info","description":"Report compiled platform capabilities and unsupported operations.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"destructiveHint":false}})
            }
            Self::ReadFile => Tool::ReadFile.schema(),
            Self::ListDirectory => {
                json!({"name":"list_directory","description":"List up to 256 scanned entries in one private workspace directory. Hidden, unsafe and non-UTF8 entries omitted.",
            "inputSchema":{"type":"object","properties":{"path":{"type":"string","default":"."}},"additionalProperties":false},
            "annotations":{"readOnlyHint":true,"destructiveHint":false}})
            }
            Self::FileInfo => {
                json!({"name":"file_info","description":"Read bounded private workspace metadata (type, size, mode and modification time; no hash).",
            "inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false},
            "annotations":{"readOnlyHint":true,"destructiveHint":false}})
            }
            Self::WriteFile => {
                json!({"name":"write_file","description":"Create an absent private text file, or replace a file with matching SHA-256. Requires durable audit.",
                "inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"},"expected_sha256":{"type":["string","null"]}},"required":["path","content","expected_sha256"],"additionalProperties":false},
                "annotations":{"readOnlyHint":false,"destructiveHint":true}})
            }
            Self::ApplyPatch => {
                json!({"name":"apply_patch","description":"Replace one unique literal occurrence in a private text file, guarded by SHA-256 and durable audit.",
                "inputSchema":{"type":"object","properties":{"path":{"type":"string"},"old":{"type":"string"},"new":{"type":"string"},"expected_sha256":{"type":"string"}},"required":["path","old","new","expected_sha256"],"additionalProperties":false},
                "annotations":{"readOnlyHint":false,"destructiveHint":true}})
            }
        }
    }
    pub fn path(self, args: Option<&Value>) -> Result<&str, &'static str> {
        if !matches!(self, Self::ReadFile | Self::FileInfo | Self::ListDirectory) {
            return Err("Not a read-path operation");
        }
        match args {
            None if self == Self::ListDirectory => Ok("."),
            Some(Value::Object(m)) if m.is_empty() && self == Self::ListDirectory => Ok("."),
            Some(Value::Object(m)) if m.len() == 1 => {
                m.get("path").and_then(Value::as_str).ok_or("Expected path")
            }
            _ => Err("Expected path"),
        }
    }
}
/// Explicit grant set; only recognized capabilities, no default grants.
pub struct WorkspaceGrants(BTreeSet<WorkspaceTool>);
impl WorkspaceGrants {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let arr = value.as_array().ok_or("Expected explicit tool array")?;
        let mut set = BTreeSet::new();
        for v in arr {
            let tool = v
                .as_str()
                .and_then(WorkspaceTool::parse)
                .ok_or("Unknown tool grant")?;
            if !set.insert(tool) {
                return Err("Empty or duplicate grant".into());
            }
        }
        if set.is_empty() {
            return Err("Empty or duplicate grant".into());
        }
        Ok(Self(set))
    }
    pub fn allows(&self, tool: WorkspaceTool) -> bool {
        self.0.contains(&tool)
    }
    pub fn names(&self) -> BTreeSet<&'static str> {
        self.0.iter().map(|t| t.name()).collect()
    }
    pub fn has_mutation(&self) -> bool {
        self.0.iter().any(|t| t.is_mutation())
    }
    pub fn schemas(&self) -> Vec<Value> {
        WorkspaceTool::ALL
            .into_iter()
            .filter(|t| self.allows(*t))
            .map(WorkspaceTool::schema)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_grants_never_imply_extra_authority() {
        let g = WorkspaceGrants::parse(&json!(["read_file", "list_directory"])).unwrap();
        assert!(g.allows(WorkspaceTool::ReadFile));
        assert!(!g.allows(WorkspaceTool::WriteFile));
        assert!(!g.has_mutation());
        assert_eq!(
            g.schemas()
                .iter()
                .map(|v| v["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["read_file", "list_directory"]
        );
        assert_eq!(g.schemas()[0], Tool::ReadFile.schema());
        for bad in [
            json!([]),
            json!(["read_file", "read_file"]),
            json!(["exec_command"]),
            json!(["root"]),
            json!(null),
        ] {
            assert!(WorkspaceGrants::parse(&bad).is_err());
        }
    }
    #[test]
    fn read_argument_contract_is_bounded_and_typed() {
        let tool = WorkspaceTool::ListDirectory;
        assert_eq!(tool.path(None), Ok("."));
        assert_eq!(tool.path(Some(&json!({}))), Ok("."));
        assert_eq!(
            WorkspaceTool::ReadFile.path(Some(&json!({"path":"x"}))),
            Ok("x")
        );
        assert!(WorkspaceTool::ReadFile.path(None).is_err());
        assert!(
            tool.path(Some(&json!({"path":"x","recursive":true})))
                .is_err()
        );
        assert!(
            WorkspaceTool::FileInfo
                .path(Some(&json!({"path":7})))
                .is_err()
        );
    }
}
