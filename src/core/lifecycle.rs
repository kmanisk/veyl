//! Shared audit, job and operator activity identities. Native adapters own
//! authorization, durable storage, supervision and enforcement.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAction {
    WriteFile,
    ApplyPatch,
    JobStart,
    JobCancel,
    StageCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditPhase {
    Intent,
    Success,
    Failure,
    Uncertain,
}

impl AuditPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Uncertain => "uncertain",
        }
    }

    // Android's existing private journal spells a definite failure "rejected".
    pub fn android_outcome(self) -> Option<&'static str> {
        match self {
            Self::Intent => None,
            Self::Success => Some("success"),
            Self::Failure => Some("rejected"),
            Self::Uncertain => Some("uncertain"),
        }
    }
    pub fn parse_android_outcome(value: &str) -> Option<Self> {
        match value {
            "success" => Some(Self::Success),
            "rejected" => Some(Self::Failure),
            "uncertain" => Some(Self::Uncertain),
            _ => None,
        }
    }
    pub fn is_definite(self) -> bool {
        matches!(self, Self::Success | Self::Failure)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(target_os = "linux", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(target_os = "linux", serde(rename_all = "snake_case"))]
pub enum JobState {
    Starting,
    Running,
    #[cfg_attr(target_os = "linux", serde(rename = "completed"))]
    Exited,
    Failed,
    #[cfg_attr(target_os = "linux", serde(rename = "canceled"))]
    Cancelled,
    TimedOut,
    Interrupted,
    Lost,
    Uncertain,
}

impl JobState {
    pub fn active(self) -> bool {
        matches!(self, Self::Starting | Self::Running)
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Exited => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "canceled",
            Self::TimedOut => "timed_out",
            Self::Interrupted => "interrupted",
            Self::Lost => "lost",
            Self::Uncertain => "uncertain",
        }
    }
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Starting | Self::Running => None,
            Self::Exited => Some("exit"),
            Self::Failed => Some("spawn_failed"),
            Self::Cancelled => Some("cancelled"),
            Self::TimedOut => Some("timeout"),
            Self::Interrupted => Some("interrupted"),
            Self::Lost => Some("lost"),
            Self::Uncertain => Some("uncertain"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(target_os = "linux", derive(serde::Serialize))]
#[cfg_attr(target_os = "linux", serde(rename_all = "snake_case"))]
pub enum ActivityStatus {
    Running,
    Success,
    Failure,
    TimedOut,
    Canceled,
}

/// Metadata only. Adapters must supply fixed server-owned labels, never raw
/// command arguments, path contents, or credentials.
#[derive(Clone)]
#[cfg_attr(target_os = "linux", derive(serde::Serialize))]
pub struct ActivityRecord {
    pub kind: &'static str,
    pub call_id: Option<String>,
    pub time: u64,
    pub client: Option<String>,
    pub tool: &'static str,
    pub status: ActivityStatus,
    pub duration_ms: Option<u64>,
    pub target_summary: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_outcome_vocabulary_is_adapter_specific() {
        assert_eq!(AuditPhase::Failure.label(), "failure");
        assert_eq!(AuditPhase::Failure.android_outcome(), Some("rejected"));
        assert_eq!(
            AuditPhase::parse_android_outcome("rejected"),
            Some(AuditPhase::Failure)
        );
        assert_eq!(AuditPhase::parse_android_outcome("failure"), None);
        assert!(!AuditPhase::Uncertain.is_definite());
        assert!(!AuditPhase::Intent.is_definite());
        assert!(AuditPhase::Success.is_definite());
    }

    #[test]
    fn job_states_distinguish_active_and_uncertain() {
        use JobState::*;
        assert!(Starting.active() && Running.active());
        assert!(!Uncertain.active());
        assert_eq!(Exited.label(), "completed");
        assert_eq!(Cancelled.label(), "canceled");
        assert_eq!(Cancelled.reason(), Some("cancelled"));
        #[cfg(target_os = "linux")]
        for state in [
            Starting,
            Running,
            Exited,
            Failed,
            Cancelled,
            TimedOut,
            Interrupted,
            Lost,
            Uncertain,
        ] {
            let encoded = serde_json::to_value(state).unwrap();
            assert_eq!(encoded, state.label());
            assert_eq!(serde_json::from_value::<JobState>(encoded).unwrap(), state);
        }
    }
}
