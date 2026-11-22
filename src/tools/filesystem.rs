//! Handle-relative mutation paths and file snapshots.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use mcp_gateway::security::audit::{AuditPhase, StageProof};
use mcp_gateway::security::linux_fs::{open_absolute_dir, open_beneath_dir, reopen_regular};
use rustix::fd::OwnedFd;
use rustix::fs::{
    self, AtFlags, FileType, FlockOperation, Mode, OFlags, ResolveFlags, Stat, StatxFlags,
};
use rustix::io::Errno;

pub(super) const MAX_TEXT_BYTES: usize = 65_536;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum MutationError {
    Rejected(&'static str),
    Uncertain,
}

use MutationError::Rejected;

pub(crate) struct MutationRoot {
    path: PathBuf,
    directory: OwnedFd,
}

impl MutationRoot {
    pub(crate) fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            directory: open_absolute_dir(path)?,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn recover_stage(
        &self,
        proof: &StageProof,
        audit: impl Fn(AuditPhase) -> io::Result<()>,
    ) -> io::Result<()> {
        let hex = proof.name.strip_prefix(".mcp-stage-");
        if proof.root != self.path
            || proof
                .parent
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || !hex
                .is_some_and(|name| name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Ok(());
        }
        let relative = proof.parent.join(&proof.name);
        let Some(relative) = relative.to_str() else {
            return Ok(());
        };
        let Ok(target) = self.target(relative) else {
            // A live writer owns the parent lock. Never sweep its stage.
            return Ok(());
        };
        let directory = fs::fstat(&target.directory)?;
        if directory_identity(&directory) != proof.directory || !target.matches_stage(proof) {
            return Ok(());
        }
        audit(AuditPhase::Intent)?;
        target
            .check_directory()
            .map_err(|_| io::Error::other("Stage directory changed"))?;
        if !target.matches_stage(proof) {
            return Err(io::Error::other("Stage identity changed before cleanup"));
        }
        fs::unlinkat(&target.directory, target.name, AtFlags::empty())?;
        fs::fsync(&target.directory)?;
        audit(AuditPhase::Success)
    }

    pub(super) fn target<'a>(&'a self, path: &'a str) -> Result<Target<'a>, MutationError> {
        let raw = path.as_bytes();
        let leaf = raw.rsplit(|&byte| byte == b'/').next().unwrap_or_default();
        let path = Path::new(path);
        if leaf.is_empty()
            || leaf == b"."
            || leaf == b".."
            || raw.contains(&0)
            || path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(Rejected(
                "Expected a relative file path within the allowed root",
            ));
        }

        let relative_parent = path.parent().ok_or(Rejected("Invalid file path"))?;
        let directory = open_beneath_dir(&self.directory, relative_parent)
            .map_err(|_| Rejected("File directory is unavailable or outside the allowed root"))?;
        fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Rejected("File directory is busy or cannot be locked"))?;
        let target = Target {
            root: self,
            relative_parent,
            directory,
            name: path.file_name().ok_or(Rejected("Invalid file path"))?,
        };
        target.check_directory()?;
        Ok(target)
    }
}

pub(super) struct Target<'a> {
    root: &'a MutationRoot,
    relative_parent: &'a Path,
    pub(super) directory: OwnedFd,
    pub(super) name: &'a OsStr,
}

impl Target<'_> {
    pub(super) fn stage_proof(&self, name: &str, file: &File) -> Result<StageProof, MutationError> {
        let directory =
            fs::fstat(&self.directory).map_err(|_| Rejected("Cannot identify stage directory"))?;
        let created = birth_time(file, "", AtFlags::EMPTY_PATH)
            .map_err(|_| Rejected("Cannot verify staging birth time"))?;
        let file = fs::fstat(file).map_err(|_| Rejected("Cannot identify stage file"))?;
        Ok(StageProof {
            root: self.root.path.clone(),
            parent: self.relative_parent.to_owned(),
            directory: directory_identity(&directory),
            name: name.to_owned(),
            file: directory_identity(&file),
            size: file.st_size as u64,
            modified: [file.st_mtime, file.st_mtime_nsec as i64],
            created,
            uid: file.st_uid,
        })
    }

    pub(super) fn matches_stage(&self, proof: &StageProof) -> bool {
        let name = proof.name.as_str();
        fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|stat| {
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && matches_proof(&stat, proof)
        }) && birth_time(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|created| created == proof.created)
    }

    pub(super) fn check_directory(&self) -> Result<(), MutationError> {
        let changed = || Rejected("File directory changed during the operation");
        let root = open_absolute_dir(&self.root.path).map_err(|_| changed())?;
        let root_now = fs::fstat(&root).map_err(|_| changed())?;
        let root_original = fs::fstat(&self.root.directory).map_err(|_| changed())?;
        if !same_inode(&root_now, &root_original) {
            return Err(changed());
        }
        let current = open_beneath_dir(&root, self.relative_parent).map_err(|_| changed())?;
        let current = fs::fstat(current).map_err(|_| changed())?;
        let opened = fs::fstat(&self.directory).map_err(|_| changed())?;
        if !same_inode(&current, &opened) {
            return Err(changed());
        }
        Ok(())
    }

    pub(super) fn metadata(&self) -> Result<Option<Stat>, MutationError> {
        match fs::statat(&self.directory, self.name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => {
                Ok(Some(stat))
            }
            Ok(_) => Err(Rejected("Target must be a regular file")),
            Err(Errno::NOENT) => Ok(None),
            Err(_) => Err(Rejected("Cannot inspect target file")),
        }
    }

    pub(super) fn open_existing(&self, expected: &Stat) -> Result<File, MutationError> {
        let file = fs::openat2(
            &self.directory,
            self.name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(|_| Rejected("Cannot safely open target file"))?;
        let actual = fs::fstat(&file).map_err(|_| Rejected("Cannot inspect target file"))?;
        if !same_snapshot(expected, &actual) {
            return Err(Rejected("Target changed during the operation"));
        }
        let file = reopen_regular(&file, OFlags::RDONLY | OFlags::NONBLOCK)
            .map_err(|_| Rejected("Cannot safely read target file"))?;
        Ok(file.into())
    }

    pub(super) fn check_target(&self, expected: Option<&Stat>) -> Result<(), MutationError> {
        match (expected, self.metadata()?.as_ref()) {
            (None, None) => Ok(()),
            (Some(original), Some(current)) if same_snapshot(original, current) => Ok(()),
            _ => Err(Rejected("Target changed during the operation")),
        }
    }
}

pub(super) fn read_text(file: &File, expected: &Stat) -> Result<String, MutationError> {
    if expected.st_size > MAX_TEXT_BYTES as i64 {
        return Err(Rejected("Target exceeds the 65536-byte limit"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Rejected("Cannot read target file"))?;
    let actual = fs::fstat(file).map_err(|_| Rejected("Cannot inspect target file"))?;
    if !same_snapshot(expected, &actual) {
        return Err(Rejected("Target changed during the operation"));
    }
    if bytes.len() > MAX_TEXT_BYTES {
        return Err(Rejected("Target exceeds the 65536-byte limit"));
    }
    String::from_utf8(bytes).map_err(|_| Rejected("Target is not valid UTF-8"))
}

pub(super) fn same_inode(first: &Stat, second: &Stat) -> bool {
    (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
}

fn same_snapshot(first: &Stat, second: &Stat) -> bool {
    same_inode(first, second)
        && first.st_mode == second.st_mode
        && first.st_uid == second.st_uid
        && first.st_gid == second.st_gid
        && first.st_size == second.st_size
        && (first.st_mtime, first.st_mtime_nsec) == (second.st_mtime, second.st_mtime_nsec)
        && (first.st_ctime, first.st_ctime_nsec) == (second.st_ctime, second.st_ctime_nsec)
}

fn directory_identity(stat: &Stat) -> [u64; 2] {
    [stat.st_dev, stat.st_ino]
}

fn matches_proof(stat: &Stat, proof: &StageProof) -> bool {
    directory_identity(stat) == proof.file
        && stat.st_uid == proof.uid
        && stat.st_nlink == 1
        && stat.st_size as u64 == proof.size
        && [stat.st_mtime, stat.st_mtime_nsec as i64] == proof.modified
}

fn birth_time(
    directory: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
    flags: AtFlags,
) -> io::Result<[i64; 2]> {
    let stat = fs::statx(directory, name, flags, StatxFlags::BTIME)?;
    if stat.stx_mask & StatxFlags::BTIME.bits() == 0 {
        return Err(io::Error::other(
            "Staging filesystem has no file birth time",
        ));
    }
    Ok([stat.stx_btime.tv_sec, i64::from(stat.stx_btime.tv_nsec)])
}
