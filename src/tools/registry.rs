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
    SystemInspect,
    ProjectContext,
    SystemContext,
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
    ProcessStart,
    ProcessInput,
    ShellReset,
}

impl Tool {
    pub(crate) const ALL: [Self; 33] = [
        Self::ReadFile,
        Self::SearchFiles,
        Self::GitInspect,
        Self::SystemInfo,
        Self::SystemInspect,
        Self::ProjectContext,
        Self::SystemContext,
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
        Self::ProcessStart,
        Self::ProcessInput,
        Self::ShellReset,
    ];

    pub(crate) fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ReadFile => "read_file",
            Self::SearchFiles => "search_files",
            Self::GitInspect => "git_inspect",
            Self::SystemInfo => "system_info",
            Self::SystemInspect => "system_inspect",
            Self::ProjectContext => "project_context",
            Self::SystemContext => "system_context",
            Self::ServiceStatus => "service_status",
            Self::WriteFile => "write_file",
            Self::ApplyPatch => "apply_patch",
            Self::RunCommand => "run_command",
            Self::StartJob => "start_job",
            Self::JobStart => "job_start",
            Self::JobStatus => "job_status",
            Self::JobLogs => "job_logs",
            Self::CancelJob => "cancel_job",
            Self::JobCancel => "job_cancel",
            Self::ListJobs => "list_jobs",
            Self::SkillsList => "skills_list",
            Self::SkillsRead => "skills_read",
            Self::UpstreamsList => "mcp_servers_list",
            Self::UpstreamsCall => "mcp_servers_call",
            Self::ListDirectory => "list_directory",
            Self::DirectoryTree => "directory_tree",
            Self::FileInfo => "file_info",
            Self::EditFile => "edit_file",
            Self::CreateDirectory => "create_directory",
            Self::ExecCommand => "exec_command",
            Self::JobWait => "job_wait",
            Self::TaskRun => "task_run",
            Self::ProcessStart => "process_start",
            Self::ProcessInput => "process_input",
            Self::ShellReset => "shell_reset",
        }
    }

    pub(crate) fn action(self) -> Action {
        match self {
            Self::ReadFile => Action::ReadFile,
            Self::SearchFiles => Action::SearchFiles,
            Self::GitInspect => Action::GitInspect,
            Self::SystemInfo => Action::SystemInfo,
            Self::SystemInspect => Action::SystemInspect,
            Self::ProjectContext => Action::ProjectContext,
            Self::SystemContext => Action::SystemContext,
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
            Self::ProcessStart => Action::ProcessStart,
            Self::ProcessInput => Action::ProcessInput,
            Self::ShellReset => Action::ShellReset,
        }
    }

    pub(crate) fn inspection(self) -> bool {
        matches!(
            self,
            Self::SearchFiles
                | Self::GitInspect
                | Self::SystemInfo
                | Self::SystemInspect
                | Self::ProjectContext
                | Self::SystemContext
                | Self::ServiceStatus
                | Self::ListDirectory
                | Self::DirectoryTree
                | Self::FileInfo
        )
    }

    pub(crate) fn process_control(self) -> bool {
        matches!(self, Self::ProcessStart | Self::ProcessInput | Self::ShellReset)
    }

    pub(crate) fn in_yolo_preset(self, jobs: bool, skills: bool) -> bool {
        match self.action() {
            Action::ReadFile
            | Action::SearchFiles
            | Action::GitInspect
            | Action::SystemInfo
            | Action::SystemInspect
            | Action::ProjectContext
            | Action::SystemContext
            | Action::ServiceStatus
            | Action::WriteFile
            | Action::ApplyPatch => true,
            Action::ListSkills | Action::ReadSkill => skills,
            action if action.is_job() => jobs && !self.process_control(),
            _ => false,
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
            Self::SystemInspect => json!({
                "name":"system_inspect",
                "description":"Read structured Linux subsystem status with bounded fixed read-only probes, including Sway outputs/workspaces, audio devices and failed systemd units. Missing components report unavailable.",
                "inputSchema":{"type":"object","additionalProperties":false,"properties":{"sections":{"type":"array","minItems":1,"maxItems":9,"uniqueItems":true,"items":{"enum":["resources","gpu","storage","network","audio","bluetooth","desktop","sway","services"]}}}},
                "annotations":{"readOnlyHint":true,"destructiveHint":false}
            }),
            Self::ProjectContext => json!({
                "name":"project_context","description":"Read bounded AGENTS.md, CLAUDE.md, README.md and project handoff documents within the granted workspace. No agent configuration or credential scanning.",
                "inputSchema":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"},"max_depth":{"type":"integer","minimum":0,"maximum":3},"max_bytes_per_file":{"type":"integer","minimum":1,"maximum":16000}}},
                "annotations":{"readOnlyHint":true,"destructiveHint":false}
            }),
            Self::SystemContext => json!({
                "name":"system_context","description":"Read explicitly named system documentation from a granted workspace containing the host configuration repository. No host context token or permission elevation.",
                "inputSchema":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string"},"docs":{"type":"array","minItems":1,"maxItems":4,"uniqueItems":true,"items":{"enum":["agents","current_state","philosophy","subsystem_map"]}},"max_bytes_per_file":{"type":"integer","minimum":1,"maximum":16000},"max_bytes_each":{"type":"integer","minimum":1,"maximum":16000}}},
                "annotations":{"readOnlyHint":true,"destructiveHint":false}
            }),
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
                "Start a mode-confined supervised command; return status and bounded output, or a durable job ID for continued polling",
                json!({
                    "command": {"type": "string", "description": "Shell command line to execute"},
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "request_id": {"type": "string", "description": "Optional client-scoped deduplication key"},
                    "cwd": {"type": "string", "description": "Working directory relative to root"},
                    "timeout_seconds": {"type": "integer", "default": 30, "minimum": 1, "maximum": 300}
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
                "Start a mode-confined durable task with an optional deduplication key; use job_status, job_wait, job_logs or job_cancel to continue",
                json!({
                    "command": {"type": "string", "description": "Command line to execute"},
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "request_id": {"type": "string", "description": "Client-assigned deduplication key"},
                    "cwd": {"type": "string", "description": "Working directory relative to root"},
                    "ephemeral_worktree": {"type": "boolean", "default": false, "description": "Reserved; true is currently unsupported"},
                    "wait_seconds": {"type": "integer", "default": 15, "minimum": 0, "maximum": 20},
                    "timeout_seconds": {"type": "integer", "default": 120, "minimum": 1, "maximum": 300}
                }),
                json!([]),
                false,
            ),
            Self::ProcessStart => (
                self.name(),
                "Start an explicitly approved persistent pipe or PTY session. Use process_input, job_status, job_logs and job_cancel with the returned job_id.",
                json!({
                    "profile": {"type": "string"},
                    "request_id": {"type": "string"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300}
                }),
                json!(["profile"]),
                false,
            ),
            Self::ProcessInput => (
                self.name(),
                "Send up to 4096 UTF-8 bytes or EOF (PTY hangup) with the current sequence. Supply job_id alone to query the sequence after reconnect or uncertain delivery.",
                json!({
                    "job_id": id,
                    "sequence": {"type": "integer", "minimum": 0},
                    "data": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "eof": {"type": "boolean", "const": true}
                }),
                json!(["job_id"]),
                false,
            ),
            Self::ShellReset => (
                self.name(),
                "Cancel an owned persistent process session and start one fresh instance of its original profile.",
                json!({"job_id": id}),
                json!(["job_id"]),
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
                "Read bounded logs for an owned job. For incremental reads, advance stdout_offset and stderr_offset independently using next_stdout_offset and next_stderr_offset.",
                json!({
                    "job_id": id,
                    "offset": {"type": "integer", "minimum": 0, "description": "Legacy shared byte offset; do not combine with independent offsets"},
                    "stdout_offset": {"type": "integer", "minimum": 0, "description": "Stdout byte offset; defaults to zero"},
                    "stderr_offset": {"type": "integer", "minimum": 0, "description": "Stderr byte offset; defaults to zero"},
                    "max_bytes": {"type": "integer", "default": 4096, "minimum": 0, "maximum": 65536}
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
