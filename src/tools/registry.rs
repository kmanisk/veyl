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
    ListDirectory,
    DirectoryTree,
    FileInfo,
    EditFile,
    CreateDirectory,
    ExecCommand,
    JobWait,
    TaskRun,
}

impl Tool {
    pub(crate) const ALL: [Self; 27] = [
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
        Self::ListDirectory,
        Self::DirectoryTree,
        Self::FileInfo,
        Self::EditFile,
        Self::CreateDirectory,
        Self::ExecCommand,
        Self::JobWait,
        Self::TaskRun,
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
            "list_directory" => Some(Self::ListDirectory),
            "directory_tree" => Some(Self::DirectoryTree),
            "file_info" => Some(Self::FileInfo),
            "edit_file" => Some(Self::EditFile),
            "create_directory" => Some(Self::CreateDirectory),
            "exec_command" => Some(Self::ExecCommand),
            "job_wait" => Some(Self::JobWait),
            "task_run" => Some(Self::TaskRun),
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
            Self::ListDirectory | Self::DirectoryTree => Action::SearchFiles,
            Self::FileInfo => Action::ReadFile,
            Self::EditFile => Action::ApplyPatch,
            Self::CreateDirectory => Action::WriteFile,
            Self::ExecCommand => Action::RunShortJob,
            Self::JobWait => Action::JobStatus,
            Self::TaskRun => Action::StartJob,
        }
    }

    pub(crate) fn inspection(self) -> bool {
        matches!(
            self,
            Self::SearchFiles
                | Self::GitInspect
                | Self::SystemInfo
                | Self::ServiceStatus
                | Self::ListDirectory
                | Self::DirectoryTree
                | Self::FileInfo
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
            Self::ListDirectory => json!({
                "name": "list_directory",
                "description": "List files and subdirectories with type, size, and modification timestamps",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative directory path (default: current workspace)"},
                        "recursive": {"type": "boolean", "default": false},
                        "show_hidden": {"type": "boolean", "default": false},
                        "max_items": {"type": "integer", "default": 200}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            }),
            Self::DirectoryTree => json!({
                "name": "directory_tree",
                "description": "Get recursive directory structure as a nested JSON tree",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative directory path (default: current workspace)"},
                        "max_depth": {"type": "integer", "default": 4, "maximum": 10}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            }),
            Self::FileInfo => json!({
                "name": "file_info",
                "description": "Get detailed metadata for a file or directory (size, permissions, mtime, sha256)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative file or directory path"}
                    },
                    "required": ["path"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            }),
            Self::EditFile => json!({
                "name": "edit_file",
                "description": "Apply exact string replacement to a file without requiring precomputed SHA-256",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative file path"},
                        "target": {"type": "string", "description": "Exact text to find and replace", "minLength": 1},
                        "replacement": {"type": "string", "description": "New replacement text"},
                        "replace_all": {"type": "boolean", "default": false}
                    },
                    "required": ["path", "target", "replacement"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::CreateDirectory => json!({
                "name": "create_directory",
                "description": "Create a directory and any necessary parent directories",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Directory path to create"}
                    },
                    "required": ["path"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
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
                json!({
                    "profile": profile,
                    "request_id": {"type": "string", "description": "Optional client-assigned deduplication key"}
                }),
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
            Self::ExecCommand => (
                "exec_command",
                "Execute a supervised command with bounded timeout and return status and output",
                json!({
                    "command": {"type": "string", "description": "Shell command line to execute"},
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string", "description": "Working directory relative to root"},
                    "timeout_seconds": {"type": "integer", "default": 30, "maximum": 300}
                }),
                json!([]),
                false,
            ),
            Self::JobWait => (
                "job_wait",
                "Wait for a job to reach completion without busy-polling",
                json!({
                    "job_id": id,
                    "timeout_seconds": {"type": "integer", "default": 10, "maximum": 60}
                }),
                json!(["job_id"]),
                true,
            ),
            Self::TaskRun => (
                "task_run",
                "Execute a durable Nightshift task with optional deduplicating request_id, ephemeral worktree, and bounded wait",
                json!({
                    "command": {"type": "string", "description": "Command line to execute"},
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "request_id": {"type": "string", "description": "Client-assigned deduplication key"},
                    "cwd": {"type": "string", "description": "Working directory relative to root"},
                    "ephemeral_worktree": {"type": "boolean", "default": false},
                    "wait_seconds": {"type": "integer", "default": 15, "maximum": 60},
                    "timeout_seconds": {"type": "integer", "default": 120, "maximum": 600}
                }),
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
                "Read bounded excerpts or incremental offset-based stream from an owned job",
                json!({
                    "job_id": id,
                    "offset": {"type": "integer", "default": 0, "minimum": 0},
                    "max_bytes": {"type": "integer", "default": 4096, "maximum": 65536}
                }),
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
