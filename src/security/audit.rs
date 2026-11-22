//! Typed events for the durable, tamper-evident Linux audit ledger.

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
        self.record_event(principal, action, phase, unix_seconds, None, None)
    }

    pub fn record_stage(
        &self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
        proof: &StageProof,
    ) -> io::Result<()> {
        self.record_event(principal, action, phase, unix_seconds, None, Some(proof))
    }

    pub fn pending_stages(&self) -> io::Result<Vec<(String, StageProof)>> {
        Ok(self.0.inspection(true)?.stages)
    }

    pub fn inspect(path: &Path, include_records: bool) -> io::Result<Value> {
        let result = Ledger::inspect_path(path, include_records)?;
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
        self.record_event(principal, action, phase, unix_seconds, Some(details), None)
    }

    fn record_event(
        &self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
        details: Option<JobAuditInfo<'_>>,
        stage: Option<&StageProof>,
    ) -> io::Result<()> {
        if principal.is_empty() || principal.len() > 128 || principal.chars().any(char::is_control)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid audit principal",
            ));
        }

        let tool = match action {
            AuditAction::WriteFile => "write_file",
            AuditAction::ApplyPatch => "apply_patch",
            AuditAction::JobStart => "job_start",
            AuditAction::JobCancel => "job_cancel",
            AuditAction::StageCleanup => "stage_cleanup",
        };
        let phase = match phase {
            AuditPhase::Intent => "intent",
            AuditPhase::Success => "success",
            AuditPhase::Failure => "failure",
            AuditPhase::Uncertain => "uncertain",
        };
        let mut event = serde_json::json!({
            "principal": principal,
            "tool": tool,
            "phase": phase,
            "unix_seconds": unix_seconds,
        });
        if let Some(details) = details {
            event["job_id"] = details.job_id.into();
            event["argv_sha256"] = details.argv_sha256.into();
            event["cwd"] = details.cwd.to_string_lossy().into_owned().into();
            event["timeout_seconds"] = details.timeout_seconds.into();
            event["max_output_bytes"] = details.max_output_bytes.into();
            event["state"] = details.state.into();
            event["stdout_bytes"] = details.stdout_bytes.into();
            event["stderr_bytes"] = details.stderr_bytes.into();
        }
        if let Some(proof) = stage {
            event["staging"] = serde_json::to_value(proof)?;
        }
        self.0.append(event)
    }
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
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
    {
        return Err(invalid_audit());
    }
    Ok(())
}
