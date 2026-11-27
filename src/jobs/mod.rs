//! Authenticated Linux job service and runner entry points.

mod api;
pub(crate) mod broad;
mod config;
mod launch;
mod logs;
mod process;
mod receipt;
mod recovery;
mod resources;
mod runner;
mod sandbox;
mod session;
pub(crate) mod store;
mod upstream_workspace;
mod worktree;

use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::{AuditAction, AuditLimits, AuditPhase, AuditSink, JobAuditInfo};

pub(crate) use config::{
    EXTENDED_RUNTIME_MAX, JobRoot, Profiles, SHORT_RUNTIME_MAX, parse_settings, oauth_profiles,
};
pub(crate) use resources::verify as verify_scope;
pub(crate) use runner::run_worker;
pub(crate) use sandbox::{
    GitToolRequest, git_tool_worker, git_worker,
    probe_worker as probe_sandbox_worker, upstream_worker,
};
pub(crate) use session::{
    Authorization as SessionAuthorization, OAuthAuthorization as OAuthSessionAuthorization,
};
pub(crate) use store::{has_active_jobs, has_unconfined_jobs};

use receipt::Receipt;
use resources::Scopes;
use store::Store;

const SHORT_TIMEOUT: u64 = 2;

// Reserved only inside the separate onboarded OAuth job store. The suffix
// is a domain-separated digest, not an access token or code verifier.
pub(crate) fn oauth_owner(value:&str)->bool {
    value.strip_prefix("oauth-job-v1-").is_some_and(|s|s.len()==64 && s.bytes().all(|b|matches!(b,b'a'..=b'f'|b'0'..=b'9')))
}

#[derive(Clone, Copy)]
pub(crate) struct JobPolicy<'a> {
    pub oauth_family: bool,
    pub oauth_bounded_workspace: bool,
    pub yolo: bool,
    pub session: Option<SessionAuthorization<'a>>,
    pub native_authority: Option<(&'a Path, &'a str)>,
    pub oauth: Option<OAuthSessionAuthorization<'a>>,
    pub full: bool,
    pub job_runtime_limit_seconds: u64,
    pub native_default_timeout: Option<u64>,
    pub job_cpu_percent_limit: u64,
    pub job_memory_bytes_limit: u64,
    pub job_output_limit_bytes: usize,
    pub job_retention_count: Option<usize>,
    pub broad: Option<&'a broad::Broad>,
    /// Some (including an empty slice) requires kernel isolation.
    pub workspace_mounts: Option<&'a [JobRoot]>,
}

pub(crate) struct Jobs {
    store: Store,
    profiles: Profiles,
    audit_path: PathBuf,
    audit_limits: AuditLimits,
    audit: Mutex<AuditSink>,
    scopes: Option<Scopes>,
    /// Jobs that existed before this HTTP instance began. Their runner may
    /// remain active, but this instance did not observe their spawn.
    recovered: HashSet<String>,
}

impl Jobs {
    pub(crate) fn open(
        state: &Path,
        profiles: Profiles,
        audit_path: &Path,
        audit_limits: AuditLimits,
    ) -> Result<Self, String> {
        if rustix::process::geteuid().is_root() {
            return Err("Jobs require an unprivileged gateway user".into());
        }
        let store = Store::open(state, true).map_err(|_| "Private job state unavailable")?;
        let recovered = store
            .jobs()
            .map_err(|_| "Cannot inspect existing private job receipts")?
            .into_iter()
            .collect();
        let audit = AuditSink::open_with_limits(audit_path, audit_limits)
            .map_err(|_| "Job grants require a private audit log")?;
        let jobs = Self {
            store,
            profiles,
            audit_path: audit_path.to_owned(),
            audit_limits,
            audit: Mutex::new(audit),
            scopes: Scopes::detect(),
            recovered,
        };
        jobs.recover()
            .map_err(|_| "Job state could not be reconciled")?;
        Ok(jobs)
    }

    pub(crate) fn available(&self) -> bool {
        self.audit
            .lock()
            .is_ok_and(|sink| sink.check_binding().is_ok())
    }
    pub(crate) fn oauth_launch_available(&self)->bool {
        self.scopes.is_some() && self.available()
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_hex() -> io::Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| invalid())?;
    Ok(store::hex(&bytes))
}

fn record(
    sink: &mut AuditSink,
    receipt: &Receipt,
    action: AuditAction,
    phase: AuditPhase,
) -> io::Result<()> {
    sink.record_job(
        &receipt.client_id,
        action,
        phase,
        now(),
        JobAuditInfo {
            job_id: &receipt.job_id,
            argv_sha256: &receipt.argv_sha256,
            cwd: &receipt.cwd,
            timeout_seconds: receipt.timeout_seconds,
            max_output_bytes: receipt.max_output_bytes,
            state: receipt.state.label(),
            stdout_bytes: receipt.stdout_bytes,
            stderr_bytes: receipt.stderr_bytes,
            yolo: receipt.yolo,
            effective_mode: if receipt.broad.is_some() {
                "broad_yolo"
            } else if receipt.full {
                "full"
            } else if receipt.yolo {
                "legacy_scoped_yolo"
            } else if receipt.isolated {
                "standard"
            } else {
                "legacy_unversioned"
            },
        },
    )
}

fn invalid() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "invalid or changed job state")
}

pub(crate) fn owns_job(state: &Path, owner: &str, id: &str) -> bool {
    Store::open(state, false).is_ok_and(|store| {
        store.job(id).and_then(|job| job.read()).is_ok_and(|receipt| receipt.client_id == owner)
    })
}
