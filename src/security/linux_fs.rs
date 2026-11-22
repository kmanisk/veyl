//! Linux directory handles anchored with openat2.

use std::io;
use std::path::{Component, Path};

use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};

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
