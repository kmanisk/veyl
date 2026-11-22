//! Standalone append-only audit sink for a trusted local directory.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat, fstat};
use rustix::io::Errno;

use super::linux_fs::{open_absolute_dir, reopen_regular};

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
        let directory = open_absolute_dir(&parent)?;
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
        let current_dir = open_absolute_dir(&self.parent)?;
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
        let mut line = serde_json::to_vec(&serde_json::json!({
            "principal": principal,
            "tool": tool,
            "phase": phase,
            "unix_seconds": unix_seconds,
        }))?;
        line.push(b'\n');
        self.check_binding()?;
        self.file.write_all(&line)?;
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
