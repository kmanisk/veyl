//! Authenticated Linux job service and runner entry points.

mod api;
mod config;
mod launch;
mod logs;
mod process;
mod receipt;
mod recovery;
mod resources;
mod runner;
mod store;

use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::{AuditAction, AuditLimits, AuditPhase, AuditSink, JobAuditInfo};

pub(crate) use config::{JobRoot, Profiles, parse_settings};
pub(crate) use resources::verify as verify_scope;
pub(crate) use runner::run_worker;

use receipt::Receipt;
use resources::Scopes;
use store::Store;

const SHORT_TIMEOUT: u64 = 2;

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
        },
    )
}

fn invalid() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "invalid or changed job state")
}
