//! MCP tool names, schemas and audited mutation dispatch.

use serde_json::{Value, json};

use mcp_gateway::security::policy::Action;

use crate::file_access::FileAccess;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) enum Tool {
    ReadFile,
    SearchFiles,
    GitInspect,
    SystemInfo,
    ServiceStatus,
    WriteFile,
    ApplyPatch,
    RunCommand,
    StartJob,
    JobStart,
    JobStatus,
    JobLogs,
    CancelJob,
    JobCancel,
    ListJobs,
    SkillsList,
    SkillsRead,
    UpstreamsList,
    UpstreamsCall,
}

impl Tool {
    pub(crate) const ALL: [Self; 19] = [
        Self::ReadFile,
        Self::SearchFiles,
        Self::GitInspect,
        Self::SystemInfo,
        Self::ServiceStatus,
        Self::WriteFile,
        Self::ApplyPatch,
        Self::RunCommand,
        Self::StartJob,
        Self::JobStart,
        Self::JobStatus,
        Self::JobLogs,
        Self::CancelJob,
        Self::JobCancel,
        Self::ListJobs,
        Self::SkillsList,
        Self::SkillsRead,
        Self::UpstreamsList,
        Self::UpstreamsCall,
    ];

    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "read_file" => Some(Self::ReadFile),
            "search_files" => Some(Self::SearchFiles),
            "git_inspect" => Some(Self::GitInspect),
            "system_info" => Some(Self::SystemInfo),
            "service_status" => Some(Self::ServiceStatus),
            "write_file" => Some(Self::WriteFile),
            "apply_patch" => Some(Self::ApplyPatch),
            "run_command" => Some(Self::RunCommand),
            "start_job" => Some(Self::StartJob),
            "job_start" => Some(Self::JobStart),
            "job_status" => Some(Self::JobStatus),
            "job_logs" => Some(Self::JobLogs),
            "cancel_job" => Some(Self::CancelJob),
            "job_cancel" => Some(Self::JobCancel),
            "list_jobs" => Some(Self::ListJobs),
            "skills_list" => Some(Self::SkillsList),
            "skills_read" => Some(Self::SkillsRead),
            "mcp_servers_list" => Some(Self::UpstreamsList),
            "mcp_servers_call" => Some(Self::UpstreamsCall),
            _ => None,
        }
    }

    pub(crate) fn action(self) -> Action {
        match self {
            Self::ReadFile => Action::ReadFile,
            Self::SearchFiles => Action::SearchFiles,
            Self::GitInspect => Action::GitInspect,
            Self::SystemInfo => Action::SystemInfo,
            Self::ServiceStatus => Action::ServiceStatus,
            Self::WriteFile => Action::WriteFile,
            Self::ApplyPatch => Action::ApplyPatch,
            Self::RunCommand => Action::RunShortJob,
            Self::StartJob | Self::JobStart => Action::StartJob,
            Self::JobStatus => Action::JobStatus,
            Self::JobLogs => Action::JobLogs,
            Self::CancelJob | Self::JobCancel => Action::CancelJob,
            Self::ListJobs => Action::ListJobs,
            Self::SkillsList => Action::ListSkills,
            Self::SkillsRead => Action::ReadSkill,
            Self::UpstreamsList => Action::ListUpstreams,
            Self::UpstreamsCall => Action::CallUpstream,
        }
    }

    pub(crate) fn inspection(self) -> bool {
        matches!(
            self,
            Self::SearchFiles | Self::GitInspect | Self::SystemInfo | Self::ServiceStatus
        )
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
            Self::SkillsList => json!({
                "name": "skills_list",
                "description": "List authorized, enabled instruction packages",
                "inputSchema": {"type": "object", "additionalProperties": false},
                "annotations": {"readOnlyHint": true, "destructiveHint": false}
            }),
            Self::SkillsRead => json!({
                "name": "skills_read",
                "description": "Read an authorized instruction package without executing it",
                "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}},
                    "required": ["name"], "additionalProperties": false},
                "annotations": {"readOnlyHint": true, "destructiveHint": false}
            }),
            Self::UpstreamsList => json!({
                "name": "mcp_servers_list",
                "description": "List granted upstream MCP servers",
                "inputSchema": {"type":"object","additionalProperties":false}
            }),
            Self::UpstreamsCall => json!({
                "name": "mcp_servers_call",
                "description": "Invoke a discovered and granted namespaced upstream tool",
                "inputSchema": {"type":"object","properties":{"name":{"type":"string"},"arguments":{"type":"object"}},
                    "required":["name"],"additionalProperties":false}
            }),
            Self::SearchFiles => {
                json!({"name":"search_files","description":"Bounded literal path or UTF-8 content search in the configured workspace","inputSchema":{"type":"object","required":["query"],"additionalProperties":false,"properties":{"path":{"type":"string"},"query":{"type":"string"},"content":{"type":"boolean"}}}})
            }
            Self::GitInspect => {
                json!({"name":"git_inspect","description":"Inspect a Git checkout in a bounded read-only offline snapshot","inputSchema":{"type":"object","required":["operation"],"additionalProperties":false,"properties":{"path":{"type":"string"},"operation":{"enum":["info","status","diff","history"]}}}})
            }
            Self::SystemInfo => {
                json!({"name":"system_info","description":"Read Linux resource totals and workspace filesystem capacity","inputSchema":{"type":"object","additionalProperties":false}})
            }
            Self::ServiceStatus => {
                json!({"name":"service_status","description":"Inspect the Veyl systemd user unit","inputSchema":{"type":"object","additionalProperties":false}})
            }
            _ => self.job_schema(),
        }
    }

    fn job_schema(self) -> Value {
        let id = json!({"type":"string","pattern":"^[0-9a-f]{32}$"});
        let profile = json!({"type":"string"});
        let (name, description, properties, required, read_only) = match self {
            Self::StartJob | Self::JobStart => (
                if self == Self::StartJob {
                    "start_job"
                } else {
                    "job_start"
                },
                "Start a configured job profile in the client's root",
                json!({"profile": profile}),
                json!(["profile"]),
                false,
            ),
            Self::RunCommand => (
                "run_command",
                "Run a configured command for up to two seconds and return its outcome",
                json!({"profile":profile,"argv":{"type":"array","minItems":1,"maxItems":33,"items":{"type":"string","maxLength":1024}}}),
                json!([]),
                false,
            ),
            Self::JobStatus => (
                "job_status",
                "Get the current receipt for an owned job",
                json!({"job_id":id}),
                json!(["job_id"]),
                true,
            ),
            Self::JobLogs => (
                "job_logs",
                "Read bounded excerpts from an owned job",
                json!({"job_id":id}),
                json!(["job_id"]),
                true,
            ),
            Self::CancelJob | Self::JobCancel => (
                if self == Self::CancelJob {
                    "cancel_job"
                } else {
                    "job_cancel"
                },
                "Request cancellation of an owned job",
                json!({"job_id":id}),
                json!(["job_id"]),
                false,
            ),
            Self::ListJobs => (
                "list_jobs",
                "List owned jobs with an optional continuation cursor",
                json!({"cursor":id}),
                json!([]),
                true,
            ),
            _ => unreachable!("only job tools use the job schema"),
        };
        let mut schema = json!({
            "type":"object", "properties":properties, "required":required, "additionalProperties":false
        });
        if self == Self::RunCommand {
            schema["oneOf"] = json!([{"required":["profile"]},{"required":["argv"]}]);
        }
        json!({"name":name,"description":description,"inputSchema":schema,
            "annotations":{"readOnlyHint":read_only,"destructiveHint":!read_only}})
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
