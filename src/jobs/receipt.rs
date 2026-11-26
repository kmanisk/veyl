//! Typed durable state and the bounded, redacted representation returned over MCP.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::process::Identity;

pub(super) use mcp_gateway::core::lifecycle::JobState as State;

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Receipt {
    pub job_id: String,
    pub client_id: String,
    pub profile: String,
    pub argv_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral_worktree: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_repo: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_path: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_cleaned: Option<bool>,
    pub root: std::path::PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<super::session::Binding>,
    pub cwd: std::path::PathBuf,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    #[serde(default = "super::config::default_cpu")]
    pub cpu_percent: u64,
    #[serde(default = "super::config::default_memory")]
    pub memory_bytes: u64,
    pub state: State,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_clock: Option<super::process::ElapsedClock>,
    pub launch_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_key: Option<String>,
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
        let mut status = json!({
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
            "resource_ceilings": super::resources::status(self.resource_ceilings_enforced, self.cpu_percent, self.memory_bytes)
        });
        status["ephemeral_worktree"] = json!(self.ephemeral_worktree);
        if self.ephemeral_worktree {
            status["worktree_cleaned"] = json!(self.worktree_cleaned);
        }
        if let Some(session) = &self.session {
            status["transport"] = json!(session.transport());
        }
        if self.session.is_some() || self.timeout_seconds > super::config::SHORT_RUNTIME_MAX {
            status["timeout_seconds"] = json!(self.timeout_seconds);
        }
        if let Some(duration) = self.execution_duration_ms {
            status["execution_duration_ms"] = json!(duration);
        } else if self.state == State::Running
            && self
                .runner
                .as_ref()
                .is_some_and(|r| r.presence() == super::process::Presence::Present)
            && let Some(elapsed) = self
                .elapsed_clock
                .as_ref()
                .and_then(|clock| clock.elapsed_ms())
        {
            status["live_elapsed_ms"] = json!(elapsed);
        }
        status
    }
}
