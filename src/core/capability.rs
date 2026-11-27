//! Portable capability and execution-mode identities. No native enforcement.
/// Capabilities requiring a separate, independently verified operator lease
/// remain unavailable in this milestone even when a grant lists them.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Action {
    ListTools,
    ReadFile,
    SearchFiles,
    GitInspect,
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
    SystemInfo,
    SystemInspect,
    ProjectContext,
    SystemContext,
    LoadPathRules,
    Remember,
    ChezmoiInspect,
    ListProjectSkills,
    LoadProjectSkill,
    ServiceStatus,
    WriteFile,
    ApplyPatch,
    Rewind,
    RewindRestore,
    RewindClear,
    ListSkills,
    ReadSkill,
    SkillsValidate,
    ExtensionsInspect,
    McpInspect,
    McpTest,
    ProposeExtension,
    ListUpstreams,
    CallUpstream,
    RunCommand,
    RunShortJob,
    StartJob,
    ProcessStart,
    ProcessInput,
    ProcessResize,
    ShellStatus,
    ShellReset,
    JobStatus,
    JobLogs,
    CancelJob,
    ListJobs,
    GoalRead,
    GoalWrite,
    PrivilegedCommand,
    ServiceControl,
}

impl Action {
    pub fn is_job(self) -> bool {
        matches!(
            self,
            Self::RunShortJob
                | Self::StartJob
                | Self::ProcessStart
                | Self::ProcessInput
                | Self::ProcessResize
                | Self::ShellStatus
                | Self::ShellReset
                | Self::JobStatus
                | Self::JobLogs
                | Self::CancelJob
                | Self::ListJobs
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExecutionMode {
    Standard,
    PersistentYolo,
    Yolo,
    BroadYolo,
    Disabled,
    /// Merely expressing intent is never evidence of an authorized YOLO lease.
    YoloRequested,
}

impl ExecutionMode {
    /// Public mode names. Older scoped authorizations use Standard's
    /// workspace scope and explicit grants until the operator migrates them.
    pub fn public_label(self) -> &'static str {
        match self {
            Self::BroadYolo => "yolo",
            Self::Yolo => "yolo",
            _ => "standard",
        }
    }

    pub fn audit_mode(self) -> Option<&'static str> {
        match self {
            Self::PersistentYolo => Some("yolo"),
            Self::Yolo => Some("native_yolo"),
            Self::BroadYolo => Some("broad_yolo"),
            _ => None,
        }
    }
}
