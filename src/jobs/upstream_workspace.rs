//! Descriptor-pinned, bounded, per-call projection; no host directory bind.
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use mcp_gateway::security::linux_fs::{open_absolute_dir, open_beneath_dir};
use rustix::fd::OwnedFd;
use rustix::fs::{self, Dir, FileType, Mode, OFlags, ResolveFlags};

use super::sandbox::{Sandbox, unsupported};

const MAX_FILES: usize = 256;
const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DEPTH: usize = 32;

fn valid_relative(path: &Path) -> bool {
    path.components().all(|component| match component {
        Component::Normal(name) => name
            .to_str()
            .is_some_and(|name| !name.starts_with('.') && !name.chars().any(char::is_control)),
        _ => false,
    })
}

fn open_item(parent: &OwnedFd, relative: &Path) -> io::Result<OwnedFd> {
    Ok(fs::openat2(
        parent,
        relative,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_XDEV
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS,
    )?)
}

#[derive(Default)]
struct Budget {
    files: usize,
    entries: usize,
    bytes: u64,
}

impl Budget {
    fn project_file(
        &mut self,
        sandbox: &mut Sandbox,
        file: &OwnedFd,
        destination: &Path,
    ) -> io::Result<()> {
        let st = fs::fstat(file)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            || st.st_nlink != 1
            || st.st_mode & 0o6000 != 0
            || st.st_uid != rustix::process::geteuid().as_raw()
        {
            return Err(unsupported());
        }
        self.files += 1;
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(st.st_size).map_err(|_| unsupported())?)
            .ok_or_else(unsupported)?;
        if self.files > MAX_FILES || self.bytes > MAX_BYTES {
            return Err(unsupported());
        }
        sandbox.pass("--ro-bind-fd", file)?;
        sandbox.command.arg(destination);
        Ok(())
    }

    fn project_tree(
        &mut self,
        sandbox: &mut Sandbox,
        directory: &OwnedFd,
        destination: &Path,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(unsupported());
        }
        sandbox.command.arg("--dir").arg(destination);
        for entry in Dir::read_from(directory)? {
            let entry = entry?;
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(unsupported());
            }
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            let relative = Path::new(name);
            if !valid_relative(relative)
                || relative.as_os_str().is_empty()
                || matches!(
                    name.to_str(),
                    Some("target" | "node_modules" | "__pycache__")
                )
            {
                continue;
            }
            let file = open_item(directory, relative)?;
            let st = fs::fstat(&file)?;
            let destination = destination.join(name);
            match FileType::from_raw_mode(st.st_mode) {
                FileType::Directory => {
                    let child = open_beneath_dir(&file, Path::new("."))?;
                    self.project_tree(sandbox, &child, &destination, depth + 1)?;
                }
                FileType::RegularFile => self.project_file(sandbox, &file, &destination)?,
                // No symlinks, sockets, devices or other special files enter
                // the projection, even when present in an approved directory.
                _ => {}
            }
        }
        Ok(())
    }
}

pub(super) fn mount(sandbox: &mut Sandbox, args: &[OsString]) -> io::Result<()> {
    let [root, dev, ino, relative, kind] = args else {
        return Err(unsupported());
    };
    let root = Path::new(root);
    let relative = Path::new(relative);
    if !root.is_absolute() || !valid_relative(relative) {
        return Err(unsupported());
    }
    let number = |value: &OsString| {
        value
            .to_str()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(unsupported)
    };
    let expected = [number(dev)?, number(ino)?];
    super::broad::check_workspace_mount(root)?;
    let root = open_absolute_dir(root)?;
    let st = fs::fstat(&root)?;
    if [st.st_dev, st.st_ino] != expected || st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(unsupported());
    }
    let destination = Path::new("/workspace").join(relative);
    let mut budget = Budget::default();
    sandbox.command.args(["--dir", "/workspace"]);
    match kind.to_str() {
        Some("tree") => {
            let directory = open_beneath_dir(&root, relative)?;
            budget.project_tree(sandbox, &directory, &destination, 0)
        }
        Some("file") if !relative.as_os_str().is_empty() => {
            let file = open_item(&root, relative)?;
            budget.project_file(sandbox, &file, &destination)
        }
        _ => Err(unsupported()),
    }
}
