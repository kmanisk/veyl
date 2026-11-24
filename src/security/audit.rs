//! Typed events for the durable, tamper-evident Linux audit ledger.

mod anchor;
mod chain;
mod ledger;

use std::io;
use std::path::{Path, PathBuf};

use rustix::fd::AsFd;
use rustix::fs::{FileType, Stat, fstat};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use ledger::Ledger;

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

/// Typed, bounded job metadata. Raw command arguments, environment values,
/// stdout, stderr and bearer credentials never enter the audit ledger.
pub struct JobAuditInfo<'a> {
    pub job_id: &'a str,
    pub argv_sha256: &'a str,
    pub cwd: &'a Path,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    pub state: &'a str,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub yolo: bool,
    pub effective_mode: &'static str,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLimits {
    segment_bytes: u64,
    total_bytes: u64,
}

impl Default for AuditLimits {
    fn default() -> Self {
        Self {
            segment_bytes: 4 * 1024 * 1024,
            total_bytes: 32 * 1024 * 1024,
        }
    }
}

impl AuditLimits {
    pub fn from_config(document: &Value) -> io::Result<Self> {
        let defaults = Self::default();
        let field = |name: &str, default, minimum, maximum| {
            document.get(name).map_or(Ok(default), |value| {
                value
                    .as_u64()
                    .filter(|value| (minimum..=maximum).contains(value))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "Invalid audit capacity")
                    })
            })
        };
        let total_bytes = field(
            "max_audit_dir_bytes",
            defaults.total_bytes,
            512,
            256 * 1024 * 1024,
        )?;
        let segment_bytes = field(
            "max_audit_file_bytes",
            defaults.segment_bytes,
            512,
            64 * 1024 * 1024,
        )?;
        Ok(Self {
            segment_bytes: segment_bytes.min(total_bytes),
            total_bytes,
        })
    }
}

/// Identity and location recorded by the writer after staging and syncing a file.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageProof {
    pub root: PathBuf,
    pub parent: PathBuf,
    pub directory: [u64; 2],
    pub name: String,
    pub file: [u64; 2],
    pub size: u64,
    pub modified: [i64; 2],
    pub created: [i64; 2],
    pub uid: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_parent: bool,
}

enum EventDetails<'a> {
    File {
        proof: Option<&'a StageProof>,
        yolo: bool,
    },
    Job(JobAuditInfo<'a>),
}

#[derive(Debug)]
pub struct AuditSink(Ledger);

impl AuditSink {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_limits(path, AuditLimits::default())
    }

    pub fn open_with_limits(path: &Path, limits: AuditLimits) -> io::Result<Self> {
        Ledger::open(path, limits).map(Self)
    }

    pub fn check_binding(&self) -> io::Result<()> {
        self.0.check_binding()
    }

    pub fn identity(&self) -> io::Result<[u64; 4]> {
        self.0.identity()
    }

    pub fn record(
        &self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
    ) -> io::Result<()> {
        self.record_event(
            principal,
            action,
            phase,
            unix_seconds,
            EventDetails::File {
                proof: None,
                yolo: false,
            },
        )
    }

    pub fn record_stage(
        &self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
        proof: &StageProof,
    ) -> io::Result<()> {
        self.record_event(
            principal,
            action,
            phase,
            unix_seconds,
            EventDetails::File {
                proof: Some(proof),
                yolo: false,
            },
        )
    }

    pub fn record_yolo_mutation(
        &self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
        proof: Option<&StageProof>,
    ) -> io::Result<()> {
        self.record_event(
            principal,
            action,
            phase,
            unix_seconds,
            EventDetails::File { proof, yolo: true },
        )
    }

    pub fn verify_read_only_active(path: &Path) -> io::Result<()> {
        Ledger::verify_read_only_active(path)
    }

    pub fn record_runtime_mode(
        &self,
        principal: &str,
        tool: &str,
        mode: &str,
        phase: AuditPhase,
        unix_seconds: u64,
    ) -> io::Result<()> {
        validate_principal(principal)?;
        self.0.append(json!({
            "principal": principal,
            "tool": tool,
            "phase": phase.label(),
            "unix_seconds": unix_seconds,
            "yolo": matches!(mode, "yolo" | "broad_yolo"),
            "effective_mode": if mode == "yolo" { "legacy_scoped_yolo" } else { mode },
        }))
    }

    pub fn verify_mode_approvals(path: &Path, expected: &[(&str, &str, &str)]) -> io::Result<()> {
        let mut approvals: std::collections::HashMap<_, _> = expected
            .iter()
            .map(|&(principal, revision, mode)| (principal, (revision, mode, false)))
            .collect();
        Ledger::inspect_transitions(path, |record| {
            if record["tool"] == "yolo_transition"
                && record["phase"] == "success"
                && let Some((revision, mode, matched)) = record["principal"]
                    .as_str()
                    .and_then(|principal| approvals.get_mut(principal))
            {
                *matched = record["requested_mode"].as_str() == Some(*mode)
                    && record["policy_revision"].as_str() == Some(*revision);
            }
        })?;
        if approvals.values().any(|(_, _, matched)| !matched) {
            return Err(io::Error::other(
                "Execution mode has no matching successful audit transition",
            ));
        }
        Ok(())
    }

    pub fn record_mode(
        &self,
        principal: &str,
        previous: &str,
        requested: &str,
        revision: &str,
        phase: AuditPhase,
        unix_seconds: u64,
    ) -> io::Result<()> {
        validate_principal(principal)?;
        self.0.append(json!({
            "principal": principal,
            "tool": "yolo_transition",
            "phase": phase.label(),
            "unix_seconds": unix_seconds,
            "actor_uid": rustix::process::geteuid().as_raw(),
            "previous_mode": previous,
            "requested_mode": requested,
            "policy_revision": revision,
            "yolo": matches!(requested, "yolo" | "broad_yolo"),
        }))
    }

    pub fn record_protected_paths(
        &self,
        operation: &str,
        rule: &str,
        path_hash: &str,
        phase: AuditPhase,
        unix_seconds: u64,
    ) -> io::Result<()> {
        self.0.append(json!({
            "principal": "local_operator",
            "tool": "protected_paths",
            "phase": phase.label(),
            "unix_seconds": unix_seconds,
            "actor_uid": rustix::process::geteuid().as_raw(),
            "operation": operation,
            "rule": rule,
            "path_sha256": path_hash,
        }))
    }

    pub fn record_skill_change(
        &self,
        operation: &str,
        name: &str,
        phase: AuditPhase,
        unix_seconds: u64,
    ) -> io::Result<()> {
        self.record_skill_change_for(operation, name, None, phase, unix_seconds)
    }

    pub fn record_skill_change_for(
        &self,
        operation: &str,
        name: &str,
        client: Option<&str>,
        phase: AuditPhase,
        unix_seconds: u64,
    ) -> io::Result<()> {
        self.0.append(json!({
            "principal": "local_operator", "tool": "skills_admin", "target_client": client,
            "phase": phase.label(), "unix_seconds": unix_seconds,
            "operation": operation, "skill": name,
        }))
    }

    pub fn record_upstream_change(
        &self,
        operation: &str,
        server: &str,
        client: Option<&str>,
        tool: Option<&str>,
        phase: AuditPhase,
        unix_seconds: u64,
    ) -> io::Result<()> {
        self.0.append(json!({
            "principal":"local_operator", "tool":"upstream_admin",
            "phase":phase.label(), "unix_seconds":unix_seconds, "operation":operation,
            "server":server, "target_client":client, "target_tool":tool,
        }))
    }

    pub fn pending_stages(&self) -> io::Result<Vec<(String, StageProof)>> {
        Ok(self.0.inspection(true)?.stages)
    }

    pub fn export_head(path: &Path, out: &Path) -> io::Result<()> {
        Ledger::export_anchor(path)?.write(out)
    }

    pub fn verify_anchor(path: &Path, anchor_path: &Path) -> io::Result<Value> {
        let anchor = anchor::Anchor::read(anchor_path)?;
        let inspection = Ledger::verify_anchor(path, &anchor)?;
        Self::inspection_json(inspection)
    }

    pub fn inspect(path: &Path, include_records: bool) -> io::Result<Value> {
        Self::inspection_json(Ledger::inspect_path(path, include_records)?)
    }

    /// Keep only a fixed number of verified events for local inspection.
    pub fn recent(path: &Path) -> io::Result<Vec<Value>> {
        let mut events = std::collections::VecDeque::with_capacity(40);
        Ledger::inspect_transitions(path, |event| {
            if events.len() == 40 {
                events.pop_front();
            }
            let mut view = json!({
                "time": event["unix_seconds"],
                "client": event["principal"],
                "tool": event["tool"],
                "phase": event["phase"],
                "mode": event["effective_mode"],
            });
            // Only verified, already-recorded metadata. Never return raw
            // credential, argument, environment or file-content fields.
            for key in [
                "sequence",
                "job_id",
                "argv_sha256",
                "cwd",
                "timeout_seconds",
                "max_output_bytes",
                "state",
                "stdout_bytes",
                "stderr_bytes",
            ] {
                if let Some(value) = event.get(key) {
                    view[key] = value.clone();
                }
            }
            events.push_back(view);
        })?;
        Ok(events.into())
    }

    fn inspection_json(result: ledger::Inspection) -> io::Result<Value> {
        Ok(json!({
            "schema_version": 1,
            "status": "verified",
            "sequence": result.sequence,
            "hash": result.hash,
            "segments": result.segments,
            "bytes": result.bytes,
            "records": result.records,
        }))
    }

    pub fn rotate(path: &Path, limits: AuditLimits) -> io::Result<()> {
        Ledger::open(path, limits)?.rotate()
    }

    pub fn record_job(
        &mut self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
        details: JobAuditInfo<'_>,
    ) -> io::Result<()> {
        if details.job_id.len() != 32
            || !details
                .job_id
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            || details.argv_sha256.len() != 64
            || !details.argv_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || !details.cwd.is_absolute()
            || details.cwd.as_os_str().as_encoded_bytes().len() > 4096
            || details.max_output_bytes > 65_536
            || details.stdout_bytes > details.max_output_bytes
            || details.stderr_bytes > details.max_output_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid audit job metadata",
            ));
        }
        self.record_event(
            principal,
            action,
            phase,
            unix_seconds,
            EventDetails::Job(details),
        )
    }

    fn record_event(
        &self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
        details: EventDetails<'_>,
    ) -> io::Result<()> {
        validate_principal(principal)?;

        let tool = match action {
            AuditAction::WriteFile => "write_file",
            AuditAction::ApplyPatch => "apply_patch",
            AuditAction::JobStart => "job_start",
            AuditAction::JobCancel => "job_cancel",
            AuditAction::StageCleanup => "stage_cleanup",
        };
        let mut event = serde_json::json!({
            "principal": principal,
            "tool": tool,
            "phase": phase.label(),
            "unix_seconds": unix_seconds,
        });
        match details {
            EventDetails::File { proof, yolo } => {
                if yolo {
                    event["yolo"] = true.into();
                }
                if let Some(proof) = proof {
                    event["staging"] = serde_json::to_value(proof)?;
                }
            }
            EventDetails::Job(details) => {
                event["effective_mode"] = details.effective_mode.into();
                if details.yolo {
                    event["yolo"] = true.into();
                }
                event["job_id"] = details.job_id.into();
                event["argv_sha256"] = details.argv_sha256.into();
                event["cwd"] = details.cwd.to_string_lossy().into_owned().into();
                event["timeout_seconds"] = details.timeout_seconds.into();
                event["max_output_bytes"] = details.max_output_bytes.into();
                event["state"] = details.state.into();
                event["stdout_bytes"] = details.stdout_bytes.into();
                event["stderr_bytes"] = details.stderr_bytes.into();
            }
        }
        self.0.append(event)
    }
}

impl AuditPhase {
    fn label(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Uncertain => "uncertain",
        }
    }
}

fn validate_principal(principal: &str) -> io::Result<()> {
    if principal.is_empty() || principal.len() > 128 || principal.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid audit principal",
        ));
    }
    Ok(())
}

fn invalid_audit() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "invalid or changed audit location",
    )
}

fn same_inode(first: &Stat, second: &Stat) -> bool {
    (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
}

fn check_directory(directory: impl AsFd) -> io::Result<()> {
    let metadata = fstat(directory)?;
    if metadata.st_mode & 0o7777 != 0o700 || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(invalid_audit());
    }
    Ok(())
}

fn check_file(metadata: &Stat) -> io::Result<()> {
    check_file_mode(metadata, 0o600)
}

fn check_file_mode(metadata: &Stat, mode: u32) -> io::Result<()> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_mode & 0o7777 != mode
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
    {
        return Err(invalid_audit());
    }
    Ok(())
}
