//! Handle-relative mutation paths and file snapshots.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use mcp_gateway::security::audit::{AuditPhase, StageProof};
use mcp_gateway::security::durable_id::DurableFs;
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
    host_parent: bool,
    protected: Option<BTreeSet<[u64; 2]>>,
}

impl MutationRoot {
    pub(crate) fn directory(&self) -> &OwnedFd {
        &self.directory
    }

    pub(crate) fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            directory: open_absolute_dir(path)?,
            host_parent: false,
            protected: None,
        })
    }

    pub(crate) fn open_owned(path: &Path) -> io::Result<Self> {
        let root = Self::open(path)?;
        let metadata = fs::fstat(&root.directory)?;
        if metadata.st_uid != rustix::process::geteuid().as_raw() || metadata.st_mode & 0o7022 != 0
        {
            return Err(io::Error::other("Expected an operator-owned directory"));
        }
        Ok(root)
    }

    /// OAuth scoped mutations reject multiply-linked targets, including
    /// atomic detach of an alias. Preserve legacy native semantics.
    pub(crate) fn strict_alias_scope(&self) -> io::Result<Self> {
        let mut root=Self::open(&self.path)?;
        if !same_inode(&fs::fstat(&root.directory)?, &fs::fstat(&self.directory)?) {
            return Err(io::Error::other("Workspace identity changed"));
        }
        root.protected=Some(self.protected.clone().unwrap_or_default());
        Ok(root)
    }

    pub(crate) fn open_host_parent(path: &Path) -> io::Result<Self> {
        if rustix::process::geteuid().is_root() {
            return Err(io::Error::other(
                "FULL file tools require a non-root gateway",
            ));
        }
        Ok(Self {
            host_parent: true,
            ..Self::open(path)?
        })
    }

    pub(crate) fn open_broad_parent(
        path: &Path,
        protected: BTreeSet<[u64; 2]>,
    ) -> io::Result<Self> {
        let root = Self {
            protected: Some(protected),
            ..Self::open_host_parent(path)?
        };
        let metadata = fs::fstat(&root.directory)?;
        if root.is_protected(&metadata) {
            return Err(io::Error::other("Protected directory identity"));
        }
        Ok(root)
    }

    fn is_protected(&self, metadata: &Stat) -> bool {
        self.protected
            .as_ref()
            .is_some_and(|entries| entries.contains(&directory_identity(metadata)))
    }

    pub(super) fn is_host_parent(&self) -> bool {
        self.host_parent
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn create_directory(&self, path: &str) -> Result<(), MutationError> {
        if path.is_empty()
            || path.starts_with('/')
            || path.as_bytes().contains(&0)
            || path.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(Rejected("Use a relative directory path"));
        }

        // Recursive creation can leave a prefix behind if a later step fails.
        let mut created = false;
        self.create_directory_components(path, &mut created)
            .map_err(|error| {
                if created {
                    MutationError::Uncertain
                } else {
                    error
                }
            })
    }

    fn create_directory_components(
        &self,
        path: &str,
        created: &mut bool,
    ) -> Result<(), MutationError> {
        let mut relative = PathBuf::new();
        let mut parent = open_directory_component(&self.directory, &relative)
            .map_err(|_| Rejected("Cannot open the directory root"))?;
        // Preserve redundant separators and a trailing slash.
        for name in path.split('/').filter(|part| !part.is_empty()) {
            self.check_creation_directory(&relative, &parent)?;
            let child = match open_directory_component(&parent, Path::new(name)) {
                Ok(child) => child,
                Err(Errno::NOENT) => {
                    self.check_creation_directory(&relative, &parent)?;
                    fs::mkdirat(&parent, name, Mode::from_raw_mode(0o777))
                        .map_err(|_| Rejected("Cannot create directory"))?;
                    *created = true;
                    open_directory_component(&parent, Path::new(name))
                        .map_err(|_| Rejected("Cannot open the new directory"))?
                }
                Err(_) => return Err(Rejected("Cannot open directory component")),
            };
            self.check_creation_directory(&relative, &parent)?;
            relative.push(name);
            self.check_creation_directory(&relative, &child)?;
            parent = child;
        }
        Ok(())
    }

    fn check_creation_directory(
        &self,
        relative: &Path,
        pinned: &OwnedFd,
    ) -> Result<(), MutationError> {
        const CHANGED: MutationError = Rejected("Directory changed during creation");
        let root = open_absolute_dir(&self.path).map_err(|_| CHANGED)?;
        if checked_directory_identity(&root).map_err(|_| CHANGED)?
            != checked_directory_identity(&self.directory).map_err(|_| CHANGED)?
        {
            return Err(CHANGED);
        }

        let current = open_directory_component(&self.directory, relative).map_err(|_| CHANGED)?;
        let opened = fs::fstat(pinned).map_err(|_| CHANGED)?;
        if self.is_protected(&opened)
            || !same_inode(&opened, &fs::fstat(current).map_err(|_| CHANGED)?)
        {
            return Err(CHANGED);
        }
        Ok(())
    }

    pub(crate) fn read(&self, path: &str) -> Result<String, &'static str> {
        const UNAVAILABLE: &str = "File unavailable or outside an approved root";
        let handle = fs::openat2(
            &self.directory,
            path,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_XDEV
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| UNAVAILABLE)?;
        let stat = fs::fstat(&handle).map_err(|_| UNAVAILABLE)?;
        if self.is_protected(&stat) {
            return Err("Protected file identity");
        }
        if stat.st_nlink != 1 || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err("Expected a singly-linked regular file");
        }
        let file = File::from(
            reopen_regular(handle, OFlags::RDONLY | OFlags::NONBLOCK).map_err(|_| UNAVAILABLE)?,
        );
        read_text(&file, &stat).map_err(|error| match error {
            Rejected(message) => message,
            MutationError::Uncertain => UNAVAILABLE,
        })
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
        if file.st_dev != directory.st_dev {
            return Err(Rejected("Cannot verify staging mount identity"));
        }
        let fs = DurableFs::probe(&self.directory, &directory)
            .map_err(|_| Rejected("Cannot identify stage filesystem"))?;
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
            host_parent: self.root.host_parent,
            fs: Some(fs),
        })
    }

    pub(super) fn matches_stage(&self, proof: &StageProof) -> bool {
        let name = proof.name.as_str();
        let Ok(dir_stat) = fs::fstat(&self.directory) else {
            return false;
        };
        let Ok(dir_fs) = DurableFs::probe(&self.directory, &dir_stat) else {
            return false;
        };
        fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|stat| {
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && stat.st_dev == dir_stat.st_dev
                && matches_proof(&dir_stat, &dir_fs, &stat, proof)
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
        if self.root.is_protected(&opened) || !same_inode(&current, &opened) {
            return Err(changed());
        }
        Ok(())
    }

    pub(super) fn metadata(&self) -> Result<Option<Stat>, MutationError> {
        match fs::statat(&self.directory, self.name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat)
                if self.root.is_protected(&stat)
                    || self.root.protected.is_some() && stat.st_nlink != 1 =>
            {
                Err(Rejected("Protected or multiply-linked file identity"))
            }
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
        if self.root.is_protected(&actual) || !same_snapshot(expected, &actual) {
            return Err(Rejected("Target changed during the operation"));
        }
        let file = reopen_regular(&file, OFlags::RDONLY | OFlags::NONBLOCK)
            .map_err(|_| Rejected("Cannot safely read target file"))?;
        Ok(file.into())
    }

    pub(super) fn check_write_access(&self, file: &File) -> Result<(), MutationError> {
        if self.root.host_parent {
            // A directory owner can replace a read-only file by rename.
            // FULL must have permission to write the original inode as well.
            reopen_regular(file, OFlags::WRONLY | OFlags::NONBLOCK)
                .map_err(|_| Rejected("Target is not writable"))?;
        }
        Ok(())
    }

    pub(super) fn check_target(&self, expected: Option<&Stat>) -> Result<(), MutationError> {
        match (expected, self.metadata()?.as_ref()) {
            (None, None) => Ok(()),
            (Some(original), Some(current)) if same_snapshot(original, current) => Ok(()),
            _ => Err(Rejected("Target changed during the operation")),
        }
    }
}

fn open_directory_component(directory: &OwnedFd, relative: &Path) -> Result<OwnedFd, Errno> {
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    fs::openat2(
        directory,
        relative,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_XDEV
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS,
    )
}

fn checked_directory_identity(directory: &OwnedFd) -> Result<([u64; 2], u64), Errno> {
    let stat = fs::fstat(directory)?;
    let mount = fs::statx(directory, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    if mount.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(Errno::OPNOTSUPP);
    }
    Ok((directory_identity(&stat), mount.stx_mnt_id))
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

fn matches_proof(dir_stat: &Stat, dir_fs: &DurableFs, stat: &Stat, proof: &StageProof) -> bool {
    let identity_ok = match &proof.fs {
        Some(expected_fs @ DurableFs::Persistent { .. }) => {
            expected_fs == dir_fs
                && dir_stat.st_ino == proof.directory[1]
                && stat.st_ino == proof.file[1]
                && stat.st_dev == dir_stat.st_dev
        }
        _ => directory_identity(dir_stat) == proof.directory && directory_identity(stat) == proof.file,
    };
    identity_ok
        && stat.st_uid == proof.uid
        && stat.st_nlink == 1
        && stat.st_size as u64 == proof.size
        && [stat.st_mtime, stat.st_mtime_nsec as i64] == proof.modified
}

pub(super) fn birth_time(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn create_directory_rejects_renamed_and_protected_directories() {
        struct Fixture(PathBuf);

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let base = std::env::temp_dir().join(format!(
            "mcp-mkdir-test-{:032x}",
            u128::from_ne_bytes(nonce)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .unwrap();
        let fixture = Fixture(base);
        let workspace = fixture.0.join("workspace");
        let parent = workspace.join("parent");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&parent).unwrap();

        let mut root = MutationRoot::open(&workspace).unwrap();
        let relative = Path::new("parent");
        let pinned = open_directory_component(&root.directory, relative).unwrap();
        assert_eq!(root.check_creation_directory(relative, &pinned), Ok(()));
        let stat = fs::fstat(&pinned).unwrap();
        root.protected = Some(BTreeSet::from([directory_identity(&stat)]));
        assert!(root.create_directory("parent").is_err());
        assert!(root.create_directory("parent/protected").is_err());
        root.protected = None;
        assert!(!parent.join("protected").exists());

        let moved_parent = fixture.0.join("moved-parent");
        std::fs::rename(&parent, &moved_parent).unwrap();
        std::fs::create_dir(&parent).unwrap();
        assert!(root.check_creation_directory(relative, &pinned).is_err());
        assert!(std::fs::read_dir(&moved_parent).unwrap().next().is_none());

        let moved_root = fixture.0.join("moved-root");
        std::fs::rename(&workspace, &moved_root).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        assert!(root.create_directory("escaped/child").is_err());
        assert!(!workspace.join("escaped").exists());
        assert!(!moved_root.join("escaped").exists());
    }
}
