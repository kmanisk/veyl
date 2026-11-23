//! Typed durable state and the bounded, redacted representation returned over MCP.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::process::Identity;

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Starting,
    Running,
    #[serde(rename = "completed")]
    Exited,
    Failed,
    #[serde(rename = "canceled")]
    Cancelled,
    TimedOut,
    Interrupted,
    Lost,
    Uncertain,
}

impl State {
    pub fn active(self) -> bool {
        matches!(self, Self::Starting | Self::Running)
    }

    pub(super) fn label(self) -> &'static str {
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

    fn reason(self) -> Option<&'static str> {
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

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Receipt {
    pub job_id: String,
    pub client_id: String,
    pub profile: String,
    pub argv_sha256: String,
    pub root: std::path::PathBuf,
    pub cwd: std::path::PathBuf,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    pub state: State,
    pub created_at: u64,
    pub launch_nonce: String,
    pub runner: Option<Identity>,
    pub child: Option<Identity>,
    pub cancel_requested: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    #[serde(default)]
    pub stdout_bytes: usize,
    #[serde(default)]
    pub stderr_bytes: usize,
    pub resource_ceilings_enforced: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub yolo: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub full: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub isolated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broad: Option<super::broad::Broad>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sandbox_roots: Vec<super::config::RootIdentity>,
}

impl Receipt {
    pub fn status(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "state": self.state,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "exit_reason": self.state.reason(),
            "cancel_requested": self.cancel_requested,
            "stdout_log": format!("{}/stdout.log", self.job_id),
            "stderr_log": format!("{}/stderr.log", self.job_id),
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "output_truncated": self.stdout_truncated || self.stderr_truncated,
            "resource_ceilings": super::resources::status(self.resource_ceilings_enforced)
        })
    }
}
