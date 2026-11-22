//! Standalone append-only audit sink for a trusted local directory.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat, fstat};
use rustix::io::Errno;

use super::linux_fs::{open_operator_dir, reopen_regular};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAction {
    WriteFile,
    ApplyPatch,
    JobStart,
    JobCancel,
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

#[derive(Debug)]
pub struct AuditSink {
    file: File,
    directory: OwnedFd,
    parent: PathBuf,
    name: OsString,
}

impl AuditSink {
    /// Bind audit writes to one private log and its already-open parent.
    pub fn open(path: &Path) -> io::Result<Self> {
        let bytes = path.as_os_str().as_encoded_bytes();
        if !path.is_absolute()
            || bytes.ends_with(b"/")
            || bytes
                .split(|&byte| byte == b'/')
                .any(|part| part == b"." || part == b"..")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid audit path",
            ));
        }

        let parent = path.parent().ok_or_else(invalid_audit)?.to_path_buf();
        let name = path.file_name().ok_or_else(invalid_audit)?.to_os_string();
        let directory = open_operator_dir(&parent)?;
        check_directory(&directory)?;

        let flags =
            OFlags::APPEND | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let file = match fs::statat(&directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(expected) => {
                check_file(&expected)?;
                let handle = fs::openat(
                    &directory,
                    &name,
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                if !same_inode(&expected, &fstat(&handle)?) {
                    return Err(invalid_audit());
                }
                reopen_regular(&handle, OFlags::APPEND | OFlags::WRONLY | OFlags::NONBLOCK)?
            }
            Err(Errno::NOENT) => {
                let file = fs::openat(
                    &directory,
                    &name,
                    flags | OFlags::CREATE | OFlags::EXCL,
                    Mode::RUSR | Mode::WUSR,
                )?;
                fs::fchmod(&file, Mode::RUSR | Mode::WUSR)?;
                file
            }
            Err(error) => return Err(error.into()),
        };
        let sink = Self {
            file: file.into(),
            directory,
            parent,
            name,
        };
        sink.check_binding()?;
        sink.file.sync_all()?;
        fs::fsync(&sink.directory)?;
        sink.check_binding()?;
        Ok(sink)
    }

    /// Verify the configured name still designates the same owned log and directory.
    pub fn check_binding(&self) -> io::Result<()> {
        let current_dir = open_operator_dir(&self.parent)?;
        check_directory(&current_dir)?;
        if !same_inode(&fstat(&self.directory)?, &fstat(&current_dir)?) {
            return Err(invalid_audit());
        }
        let current_file = fs::statat(&current_dir, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        let opened_file = fstat(&self.file)?;
        check_file(&current_file)?;
        check_file(&opened_file)?;
        if !same_inode(&opened_file, &current_file) {
            return Err(invalid_audit());
        }
        Ok(())
    }

    pub fn record(
        &mut self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
    ) -> io::Result<()> {
        self.record_event(principal, action, phase, unix_seconds, None)
    }

    pub fn identity(&self) -> io::Result<[u64; 4]> {
        self.check_binding()?;
        let directory = fstat(&self.directory)?;
        let file = fstat(&self.file)?;
        Ok([
            directory.st_dev as u64,
            directory.st_ino as u64,
            file.st_dev as u64,
            file.st_ino as u64,
        ])
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
        self.record_event(principal, action, phase, unix_seconds, Some(details))
    }

    fn record_event(
        &mut self,
        principal: &str,
        action: AuditAction,
        phase: AuditPhase,
        unix_seconds: u64,
        details: Option<JobAuditInfo<'_>>,
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
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        fs::flock(&self.file, FlockOperation::LockExclusive)?;
        let written = self.append(&line);
        let unlocked = fs::flock(&self.file, FlockOperation::Unlock);
        written.and(unlocked.map_err(io::Error::from))
    }

    fn append(&mut self, line: &[u8]) -> io::Result<()> {
        self.check_binding()?;
        self.file.write_all(line)?;
        self.file.flush()?;
        self.file.sync_data()?;
        self.check_binding()
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
