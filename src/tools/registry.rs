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
    LoadPathRules,
    Remember,
    ChezmoiInspect,
    ProjectSkillsList,
    ProjectSkillLoad,
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
    SkillsValidate,
    ExtensionsList,
    ExtensionsInfo,
    ExtensionsSearch,
    ExtensionsProposeAdd,
    ExtensionsProposeRemove,
    McpList,
    McpInfo,
    McpStatus,
    McpTest,
    McpProposeAdd,
    McpProposeUpdate,
    McpProposeRemove,
    McpProposeDisable,
    SkillsProposeAdd,
    SkillsProposeRemove,
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
    ProcessResize,
    ShellStatus,
    ShellReset,
    GitStatus,
    GitDiff,
    GitLog,
    GitAdd,
    GitCommit,
    GitBranch,
    GitCheckout,
    GitRestore,
    GitStash,
    GitReset,
    GitPull,
    GitPush,
}

impl Tool {
    pub(crate) const ALL: [Self; 68] = [
        Self::ReadFile,
        Self::SearchFiles,
        Self::GitInspect,
        Self::SystemInfo,
        Self::SystemInspect,
        Self::ProjectContext,
        Self::SystemContext,
        Self::LoadPathRules,
        Self::Remember,
        Self::ChezmoiInspect,
        Self::ProjectSkillsList,
        Self::ProjectSkillLoad,
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
        Self::SkillsValidate,
        Self::ExtensionsList,
        Self::ExtensionsInfo,
        Self::ExtensionsSearch,
        Self::ExtensionsProposeAdd,
        Self::ExtensionsProposeRemove,
        Self::McpList,
        Self::McpInfo,
        Self::McpStatus,
        Self::McpTest,
        Self::McpProposeAdd,
        Self::McpProposeUpdate,
        Self::McpProposeRemove,
        Self::McpProposeDisable,
        Self::SkillsProposeAdd,
        Self::SkillsProposeRemove,
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
        Self::ProcessResize,
        Self::ShellStatus,
        Self::ShellReset,
        Self::GitStatus,
        Self::GitDiff,
        Self::GitLog,
        Self::GitAdd,
        Self::GitCommit,
        Self::GitBranch,
        Self::GitCheckout,
        Self::GitRestore,
        Self::GitStash,
        Self::GitReset,
        Self::GitPull,
        Self::GitPush,
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
            Self::LoadPathRules => "load_path_rules",
            Self::Remember => "remember",
            Self::ChezmoiInspect => "chezmoi_inspect",
            Self::ProjectSkillsList => "list_skills",
            Self::ProjectSkillLoad => "load_skill",
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
            Self::SkillsValidate => "skills_validate",
            Self::ExtensionsList => "extensions_list",
            Self::ExtensionsInfo => "extensions_info",
            Self::ExtensionsSearch => "extensions_search",
            Self::ExtensionsProposeAdd => "extensions_propose_add",
            Self::ExtensionsProposeRemove => "extensions_propose_remove",
            Self::McpList => "mcp_list",
            Self::McpInfo => "mcp_info",
            Self::McpStatus => "mcp_status",
            Self::McpTest => "mcp_test",
            Self::McpProposeAdd => "mcp_propose_add",
            Self::McpProposeUpdate => "mcp_propose_update",
            Self::McpProposeRemove => "mcp_propose_remove",
            Self::McpProposeDisable => "mcp_propose_disable",
            Self::SkillsProposeAdd => "skills_propose_add",
            Self::SkillsProposeRemove => "skills_propose_remove",
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
            Self::ProcessResize => "process_resize",
            Self::ShellStatus => "shell_status",
            Self::ShellReset => "shell_reset",
            Self::GitStatus => "git_status",
            Self::GitDiff => "git_diff",
            Self::GitLog => "git_log",
            Self::GitAdd => "git_add",
            Self::GitCommit => "git_commit",
            Self::GitBranch => "git_branch",
            Self::GitCheckout => "git_checkout",
            Self::GitRestore => "git_restore",
            Self::GitStash => "git_stash",
            Self::GitReset => "git_reset",
            Self::GitPull => "git_pull",
            Self::GitPush => "git_push",
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
            Self::LoadPathRules => Action::LoadPathRules,
            Self::Remember => Action::Remember,
            Self::ChezmoiInspect => Action::ChezmoiInspect,
            Self::ProjectSkillsList => Action::ListProjectSkills,
            Self::ProjectSkillLoad => Action::LoadProjectSkill,
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
            Self::SkillsValidate => Action::SkillsValidate,
            Self::ExtensionsList | Self::ExtensionsInfo | Self::ExtensionsSearch => {
                Action::ExtensionsInspect
            }
            Self::McpList | Self::McpStatus | Self::McpInfo => Action::McpInspect,
            Self::McpTest => Action::McpTest,
            Self::ExtensionsProposeAdd
            | Self::ExtensionsProposeRemove
            | Self::McpProposeAdd
            | Self::McpProposeUpdate
            | Self::McpProposeRemove
            | Self::McpProposeDisable
            | Self::SkillsProposeAdd
            | Self::SkillsProposeRemove => Action::ProposeExtension,
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
            Self::ProcessResize => Action::ProcessResize,
            Self::ShellStatus => Action::ShellStatus,
            Self::ShellReset => Action::ShellReset,
            Self::GitStatus => Action::GitStatus,
            Self::GitDiff => Action::GitDiff,
            Self::GitLog => Action::GitLog,
            Self::GitAdd => Action::GitAdd,
            Self::GitCommit => Action::GitCommit,
            Self::GitBranch => Action::GitBranch,
            Self::GitCheckout => Action::GitCheckout,
            Self::GitRestore => Action::GitRestore,
            Self::GitStash => Action::GitStash,
            Self::GitReset => Action::GitReset,
            Self::GitPull => Action::GitPull,
            Self::GitPush => Action::GitPush,
        }
    }

    pub(crate) fn is_git(self) -> bool {
        matches!(
            self,
            Self::GitStatus
                | Self::GitDiff
                | Self::GitLog
                | Self::GitAdd
                | Self::GitCommit
                | Self::GitBranch
                | Self::GitCheckout
                | Self::GitRestore
                | Self::GitStash
                | Self::GitReset
                | Self::GitPull
                | Self::GitPush
        )
    }

    pub(crate) fn is_extension(self) -> bool {
        matches!(
            self,
            Self::SkillsValidate
                | Self::ExtensionsList
                | Self::ExtensionsInfo
                | Self::ExtensionsSearch
                | Self::ExtensionsProposeAdd
                | Self::ExtensionsProposeRemove
                | Self::McpList
                | Self::McpInfo
                | Self::McpStatus
                | Self::McpTest
                | Self::McpProposeAdd
                | Self::McpProposeUpdate
                | Self::McpProposeRemove
                | Self::McpProposeDisable
                | Self::SkillsProposeAdd
                | Self::SkillsProposeRemove
        )
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
                | Self::LoadPathRules
                | Self::ChezmoiInspect
                | Self::ProjectSkillsList
                | Self::ProjectSkillLoad
                | Self::ServiceStatus
                | Self::ListDirectory
                | Self::DirectoryTree
                | Self::FileInfo
        )
    }

    pub(crate) fn process_control(self) -> bool {
        matches!(
            self,
            Self::ProcessStart | Self::ProcessInput | Self::ProcessResize | Self::ShellStatus | Self::ShellReset
        )
    }

    pub(crate) fn in_yolo_preset(self, jobs: bool, skills: bool) -> bool {
        match self.action() {
            Action::ReadFile
            | Action::SearchFiles
            | Action::GitInspect
            | Action::GitStatus
            | Action::GitDiff
            | Action::GitLog
            | Action::SystemInfo
            | Action::SystemInspect
            | Action::ProjectContext
            | Action::SystemContext
            | Action::LoadPathRules
            | Action::Remember
            | Action::ChezmoiInspect
            | Action::ListProjectSkills
            | Action::LoadProjectSkill
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
            Self::SkillsValidate => json!({
                "name": "skills_validate",
                "description": "Validate granted operator skills and workspace project skills without executing anything",
                "inputSchema": {"type": "object", "additionalProperties": false},
                "annotations": {"readOnlyHint": true, "destructiveHint": false}
            }),
            Self::ExtensionsList | Self::ExtensionsInfo => json!({
                "name": self.name(),
                "description": "Inspect granted extensions, skills, and upstream server metadata without executing providers",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "maxLength": 128},
                        "query": {"type": "string", "maxLength": 128},
                        "scope": {"type": "string", "enum": ["user", "project"]}
                    },
                    "additionalProperties": false
                },
                "annotations": {"readOnlyHint": true, "destructiveHint": false}
            }),
            Self::ExtensionsSearch => json!({
                "name": "extensions_search",
                "description": "Search the bundled, metadata-verified integration catalog offline without executing providers",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "maxLength": 128},
                        "category": {"type": "string", "maxLength": 80},
                        "type": {"type": "string", "enum": ["mcp", "skill", "tool"]},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20}
                    },
                    "additionalProperties": false
                },
                "annotations": {"readOnlyHint": true, "destructiveHint": false}
            }),
            Self::McpList | Self::McpStatus => json!({
                "name": self.name(),
                "description": "Passively list granted upstream MCP server configuration metadata without connecting",
                "inputSchema": {"type": "object", "additionalProperties": false},
                "annotations": {"readOnlyHint": true, "destructiveHint": false}
            }),
            Self::McpInfo => json!({
                "name": "mcp_info",
                "description": "Inspect redacted configuration summary and SHA-256 provider_fingerprint for a granted upstream server",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string", "maxLength": 128}},
                    "required": ["name"],
                    "additionalProperties": false
                },
                "annotations": {"readOnlyHint": true, "destructiveHint": false}
            }),
            Self::McpTest => json!({
                "name": "mcp_test",
                "description": "Probe a granted upstream MCP server cleanly, bound to provider_fingerprint from mcp_info",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "maxLength": 128},
                        "provider_fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"}
                    },
                    "required": ["name", "provider_fingerprint"],
                    "additionalProperties": false
                },
                "annotations": {"readOnlyHint": false, "destructiveHint": false}
            }),
            Self::ExtensionsProposeAdd
            | Self::ExtensionsProposeRemove
            | Self::McpProposeAdd
            | Self::McpProposeUpdate
            | Self::McpProposeRemove
            | Self::McpProposeDisable
            | Self::SkillsProposeAdd
            | Self::SkillsProposeRemove => {
                let is_add = matches!(
                    self,
                    Self::ExtensionsProposeAdd | Self::McpProposeAdd | Self::SkillsProposeAdd
                );
                let required = if is_add { json!(["source"]) } else { json!(["name"]) };
                json!({
                    "name": self.name(),
                    "description": "Create an inert operator-review request. Does not download, install, approve, sign, enable, or execute code.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "maxLength": 128},
                            "source": {"type": "string", "maxLength": 2048},
                            "selection": {"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 128}},
                            "scope": {"type": "string", "enum": ["user", "project"], "default": "project"},
                            "provider_fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"}
                        },
                        "required": required,
                        "additionalProperties": false
                    },
                    "annotations": {"readOnlyHint": true, "destructiveHint": false}
                })
            }
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
                "description":"Read structured Linux subsystem status with bounded fixed read-only probes, including processes, network rates, GPU telemetry (without waking suspended hardware), Sway outputs/workspaces, audio devices and failed systemd units.",
                "inputSchema":{"type":"object","additionalProperties":false,"properties":{"sections":{"type":"array","minItems":1,"maxItems":10,"uniqueItems":true,"items":{"enum":["resources","processes","gpu","storage","network","audio","bluetooth","desktop","sway","services"]}}}},
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
            Self::LoadPathRules => json!({
                "name":"load_path_rules","description":"Match .claude/rules/*.md YAML paths frontmatter globs against a target path inside the approved workspace",
                "inputSchema":{"type":"object","required":["path"],"additionalProperties":false,"properties":{"path":{"type":"string"}}},
                "annotations":{"readOnlyHint":true,"destructiveHint":false}
            }),
            Self::Remember => json!({
                "name":"remember","description":"Append a bounded note to workspace cross-session auto memory (.veyl-memory/MEMORY.md)",
                "inputSchema":{"type":"object","required":["note"],"additionalProperties":false,"properties":{"note":{"type":"string","minLength":1,"maxLength":2000}}},
                "annotations":{"readOnlyHint":false,"destructiveHint":false}
            }),
            Self::ChezmoiInspect => json!({
                "name":"chezmoi_inspect","description":"Read-only chezmoi ownership and generated-header check for an approved path. Never runs chezmoi apply or edits files.",
                "inputSchema":{"type":"object","required":["path"],"additionalProperties":false,"properties":{"path":{"type":"string"}}},
                "annotations":{"readOnlyHint":true,"destructiveHint":false}
            }),
            Self::ProjectSkillsList => json!({
                "name":"list_skills","description":"List project skills discovered under .agents/skills, .claude/skills, or .veyl/skills in the granted workspace",
                "inputSchema":{"type":"object","additionalProperties":false},
                "annotations":{"readOnlyHint":true,"destructiveHint":false}
            }),
            Self::ProjectSkillLoad => json!({
                "name":"load_skill","description":"Load instructions for one workspace skill listed by list_skills without executing it",
                "inputSchema":{"type":"object","required":["name"],"additionalProperties":false,"properties":{"name":{"type":"string"},"max_bytes":{"type":"integer","minimum":1,"maximum":200000,"default":65536}}},
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
            Self::GitStatus => json!({
                "name": "git_status",
                "description": "Show structured git working tree status within an approved workspace",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            }),
            Self::GitDiff => json!({
                "name": "git_diff",
                "description": "Show unstaged or staged git diff within an approved workspace",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "staged": {"type": "boolean", "default": false},
                        "file": {"type": "string"}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            }),
            Self::GitLog => json!({
                "name": "git_log",
                "description": "Show recent git commit history within an approved workspace",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "count": {"type": "integer", "default": 10, "minimum": 1, "maximum": 500}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            }),
            Self::GitAdd => json!({
                "name": "git_add",
                "description": "Stage files for commit inside an approved repository",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "files": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
                        "all": {"type": "boolean", "default": true}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::GitCommit => json!({
                "name": "git_commit",
                "description": "Create a local commit inside an approved repository",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string", "minLength": 1, "maxLength": 8192},
                        "path": {"type": "string"},
                        "stage_all": {"type": "boolean", "default": true}
                    },
                    "required": ["message"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::GitBranch => json!({
                "name": "git_branch",
                "description": "List, create, or switch local git branches",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "action": {"type": "string", "enum": ["list", "create", "switch", "create-and-switch"], "default": "list"},
                        "name": {"type": "string"}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::GitCheckout => json!({
                "name": "git_checkout",
                "description": "Switch the local repository to an existing branch",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "branch": {"type": "string"}
                    },
                    "required": ["branch"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::GitRestore => json!({
                "name": "git_restore",
                "description": "Restore tracked files to HEAD or a revision (requires confirm=true)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "files": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 64},
                        "source": {"type": "string", "default": "HEAD"},
                        "confirm": {"type": "boolean"}
                    },
                    "required": ["files"],
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::GitStash => json!({
                "name": "git_stash",
                "description": "List, push, pop, or apply git stash entries",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "action": {"type": "string", "enum": ["list", "push", "pop", "apply"], "default": "list"},
                        "message": {"type": "string"}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::GitReset => json!({
                "name": "git_reset",
                "description": "Move HEAD cleanly (hard mode discards working changes and requires confirm=true)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "mode": {"type": "string", "enum": ["soft", "mixed", "hard"], "default": "mixed"},
                        "ref": {"type": "string", "default": "HEAD"},
                        "confirm": {"type": "boolean"}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::GitPull => json!({
                "name": "git_pull",
                "description": "Pull updates from a configured remote (requires YOLO or FULL mode and confirm=true)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "remote": {"type": "string", "default": "origin"},
                        "branch": {"type": "string"},
                        "confirm": {"type": "boolean"}
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": false, "destructiveHint": true }
            }),
            Self::GitPush => json!({
                "name": "git_push",
                "description": "Push local commits to a configured remote (requires YOLO or FULL mode and confirm=true)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "remote": {"type": "string", "default": "origin"},
                        "branch": {"type": "string"},
                        "set_upstream": {"type": "boolean", "default": false},
                        "confirm": {"type": "boolean"}
                    },
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
                    "ephemeral_worktree": {"type": "boolean", "default": false, "description": "Run the task in a disposable isolated Git worktree"},
                    "cpu_percent": {"type": "integer", "minimum": 10, "maximum": 1600},
                    "memory_bytes": {"type": "integer", "minimum": 16777216, "maximum": 17179869184_u64},
                    "max_output_bytes": {"type": "integer", "minimum": 1, "maximum": 16777216},
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
            Self::ProcessResize => (
                self.name(), "Resize an owned PTY session.",
                json!({"job_id": id, "rows": {"type":"integer", "minimum":1, "maximum":512}, "cols": {"type":"integer", "minimum":1, "maximum":512}}),
                json!(["job_id", "rows", "cols"]), false,
            ),
            Self::ShellStatus => (
                self.name(), "Inspect owned persistent process sessions.",
                json!({"job_id": id}), json!([]), true,
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
                    "max_bytes": {"type": "integer", "default": 4096, "minimum": 0, "maximum": 65536},
                    "encoding": {"type": "string", "enum": ["utf8", "base64"], "default": "utf8"}
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
