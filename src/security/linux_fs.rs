//! Linux directory handles anchored with openat2.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Component, Path};

use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags};
use rustix::io::Errno;

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const SCOPED: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Open an operator path without following links in any component.
pub fn open_absolute_dir(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid directory path",
        ));
    }
    let root = fs::open("/", DIRECTORY, Mode::empty())?;
    let suffix = path.strip_prefix("/").expect("absolute Linux path");
    let relative = if suffix.as_os_str().is_empty() {
        Path::new(".")
    } else {
        suffix
    };
    Ok(fs::openat2(
        root,
        relative,
        DIRECTORY,
        Mode::empty(),
        SCOPED,
    )?)
}

/// Open a trusted absolute configuration path. On kernels without openat2,
/// walk one directory component per openat, with O_NOFOLLOW on each step.
/// User-selected mutation paths still require the stricter openat2 resolver.
pub fn open_operator_dir(path: &Path) -> io::Result<OwnedFd> {
    match open_absolute_dir(path) {
        Err(error) if error.raw_os_error() == Some(Errno::NOSYS.raw_os_error()) => {
            let mut directory = fs::open("/", DIRECTORY, Mode::empty())?;
            for component in path.components() {
                if let Component::Normal(name) = component {
                    directory = fs::openat(
                        &directory,
                        name,
                        DIRECTORY | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )?;
                }
            }
            Ok(directory)
        }
        result => result,
    }
}

/// Public writable OAuth previews require a small dedicated filesystem, not
/// a subdirectory on an unbounded host disk. tmpfs is the first supported
/// bounded backend; both allocated bytes and inode counts are kernel limited.
pub const OAUTH_WORKSPACE_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const OAUTH_WORKSPACE_MAX_INODES: u64 = 16384;

fn workspace_capacity_ok(bytes: u64, inodes: u64) -> bool {
    (1..=OAUTH_WORKSPACE_MAX_BYTES).contains(&bytes)
        && (1..=OAUTH_WORKSPACE_MAX_INODES).contains(&inodes)
}

pub fn bounded_oauth_workspace(path: &Path) -> io::Result<()> {
    let denied = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Public writable OAuth requires a private dedicated tmpfs mount (max 256 MiB, 16384 inodes, nosuid,nodev)",
        )
    };
    let root = open_absolute_dir(path)?;
    let stat = fs::fstat(&root)?;
    let parent = open_absolute_dir(path.parent().ok_or_else(denied)?)?;
    let stats = fs::fstatvfs(&root)?;
    // TMPFS_MAGIC from Linux magic.h; no dependency on mount utility output.
    if fs::fstatfs(&root)?.f_type != 0x01021994
        || stat.st_dev == fs::fstat(&parent)?.st_dev
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o700
        || !workspace_capacity_ok(
            stats
                .f_blocks
                .checked_mul(stats.f_frsize)
                .ok_or_else(denied)?,
            stats.f_files,
        )
    {
        return Err(denied());
    }
    // Require the exact filesystem root, never a nested/bind-mounted subtree,
    // and reject nested mount points which could expose a different disk.
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mut found = 0;
    for line in mountinfo.lines() {
        let (before, after) = line.split_once(" - ").ok_or_else(denied)?;
        let fields: Vec<_> = before.split_ascii_whitespace().collect();
        if fields.len() < 6 {
            return Err(denied());
        }
        let decoded = fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        let mount = Path::new(&decoded);
        if mount == path {
            let options = fields[5].split(',').collect::<Vec<_>>();
            if fields[3] != "/"
                || after.split_ascii_whitespace().next() != Some("tmpfs")
                || !options.contains(&"nosuid")
                || !options.contains(&"nodev")
            {
                return Err(denied());
            }
            found += 1;
        } else if mount.starts_with(path) {
            return Err(denied());
        }
    }
    if found != 1 {
        return Err(denied());
    }
    Ok(())
}

/// Open a directory inside a previously validated root without crossing mounts.
pub fn open_beneath_dir(root: impl AsFd, relative: &Path) -> io::Result<OwnedFd> {
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    Ok(fs::openat2(
        root,
        relative,
        DIRECTORY,
        Mode::empty(),
        SCOPED | ResolveFlags::NO_XDEV,
    )?)
}

/// Reopen a pinned regular inode for I/O through the Linux procfs fd directory.
/// Type validation on the path-only handle precedes any I/O-capable open.
pub fn reopen_regular(handle: impl AsFd, flags: OFlags) -> io::Result<OwnedFd> {
    let handle = handle.as_fd();
    let pinned = fs::fstat(handle)?;
    if FileType::from_raw_mode(pinned.st_mode) != FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected regular file",
        ));
    }

    let proc = fs::open("/proc/self/fd", DIRECTORY, Mode::empty())?;
    if fs::fstatfs(&proc)?.f_type != fs::PROC_SUPER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "procfs fd directory unavailable",
        ));
    }
    let name = handle.as_raw_fd().to_string();
    let file = fs::openat(&proc, name.as_str(), flags | OFlags::CLOEXEC, Mode::empty())?;
    let actual = fs::fstat(&file)?;
    if (pinned.st_dev, pinned.st_ino) != (actual.st_dev, actual.st_ino) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file identity changed",
        ));
    }
    Ok(file)
}

/// Publish a private regular file durably without replacing an existing name.
pub fn publish_new(parent: impl AsFd, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| io::Error::other("secure randomness unavailable"))?;
    let temporary = format!(".mcp-publish-{:032x}", u128::from_le_bytes(nonce));
    let private = Mode::RUSR | Mode::WUSR;
    let mut file = File::from(fs::openat(
        &parent,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        private,
    )?);
    let result = (|| {
        fs::fchmod(&file, private)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::renameat_with(
            &parent,
            temporary.as_str(),
            &parent,
            name,
            RenameFlags::NOREPLACE,
        )?;
        fs::fsync(&parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::unlinkat(&parent, temporary.as_str(), AtFlags::empty());
    }
    result
}

#[cfg(test)]
mod oauth_workspace_capacity_tests {
    use super::*;
    #[test]
    fn capacity_and_inode_limits_must_both_be_finite() {
        assert!(workspace_capacity_ok(
            OAUTH_WORKSPACE_MAX_BYTES,
            OAUTH_WORKSPACE_MAX_INODES
        ));
        for (bytes, inodes) in [
            (0, 100),
            (100, 0),
            (OAUTH_WORKSPACE_MAX_BYTES + 1, 100),
            (100, OAUTH_WORKSPACE_MAX_INODES + 1),
        ] {
            assert!(!workspace_capacity_ok(bytes, inodes));
        }
    }
    #[test]
    fn shared_host_root_is_not_a_bounded_workspace() {
        assert!(bounded_oauth_workspace(Path::new("/")).is_err());
        assert!(bounded_oauth_workspace(Path::new("/tmp")).is_err());
    }
}
