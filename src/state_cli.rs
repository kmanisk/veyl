//! Read-only inventory of a candidate broad execution state directory.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};

use mcp_gateway::security::linux_fs::open_absolute_dir;
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, Dir, FileType, Mode, OFlags, ResolveFlags, Stat};

use crate::http::admission::{Configuration, parse_clients, read_config};
use crate::http::operator::verify_approvals;
use crate::protected_paths::validate_path;

const HELP: &str = "usage: veyl state check [--state-root PATH] [--config PATH]";
const LOCAL: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_XDEV)
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const MAX_ENTRIES: usize = 131_072;
const MAX_DEPTH: usize = 16;

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] || args == ["check", "--help"] {
        println!("{HELP}");
        return Ok(());
    }
    if args.first().is_none_or(|arg| arg != "check") {
        return Err(HELP.into());
    }
    let (mut root, mut config) = (None, None);
    let mut options = args[1..].iter();
    while let Some(option) = options.next() {
        let destination = match option.to_str() {
            Some("--state-root") if root.is_none() => &mut root,
            Some("--config") if config.is_none() => &mut config,
            _ => return Err(HELP.into()),
        };
        *destination = Some(PathBuf::from(options.next().ok_or(HELP)?));
    }
    let root = root
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".local/state/mcp-gateway"))
        })
        .ok_or("Set HOME or give an explicit --state-root")?;
    let config = config.unwrap_or_else(|| root.join("clients.json"));
    validate_path(&root)?;
    validate_path(&config)?;
    let result = check(&root, &config);
    match result {
        Ok(()) => {
            println!("layout=valid broad_yolo=requires_sandbox_preflight");
            Ok(())
        }
        Err(reason) => {
            println!("layout=invalid broad_yolo=denied");
            Err(reason)
        }
    }
}

fn check(root: &Path, config: &Path) -> Result<(), String> {
    let layout = Layout::inspect(root)?;
    let metadata = fs::fstat(&layout.root).map_err(|_| "Cannot inspect state root")?;
    println!(
        "state_root={} owner_uid={} mode={:04o} device={} inode={}",
        root.display(),
        metadata.st_uid,
        metadata.st_mode & 0o7777,
        metadata.st_dev,
        metadata.st_ino
    );
    println!(
        "regular_files={} hardlink_violations={}",
        layout.inventory.files, layout.inventory.hardlinks
    );
    layout.validate_links()?;
    let settings = parse_clients(config, &read_config(config)?)?;
    layout.verify_settings(config, &settings)?;
    verify_approvals(&settings)?;
    println!("credentials=contained audit=contained jobs=contained");
    Ok(())
}

/// A descriptor-pinned inventory of the entire dedicated state directory.
pub(crate) struct Layout {
    root: OwnedFd,
    path: PathBuf,
    inventory: Inventory,
}

impl Layout {
    pub(crate) fn inspect(path: &Path) -> Result<Self, String> {
        Self::inspect_mode(path, false)
    }

    pub(crate) fn inspect_bundle(path: &Path) -> Result<Self, String> {
        Self::inspect_mode(path, true)
    }

    fn inspect_mode(path: &Path, bundle_root: bool) -> Result<Self, String> {
        validate_path(path)?;
        let uid = rustix::process::geteuid();
        if uid.is_root() {
            return Err("State verification requires the unprivileged gateway owner".into());
        }
        let root = open_absolute_dir(path).map_err(|_| "State root is missing or unsafe")?;
        // Job receipts and audit rotation can change directory entries during
        // an otherwise valid scan. Retry only that specific transient failure,
        // on the same pinned directory, and require a complete stable scan.
        for attempt in 0..4 {
            let mut inventory = Inventory {
                uid: Some(uid.as_raw()),
                masked: false,
                bundle_root,
                remaining: MAX_ENTRIES,
                files: 0,
                hardlinks: 0,
                objects: None,
            };
            match inventory.directory(&root, 0, &[]) {
                Ok(()) => {
                    let current = open_absolute_dir(path)
                        .map_err(|_| "State root changed during inspection")?;
                    if !same_identity(&root, current)
                        .map_err(|_| "Cannot verify state root identity")?
                    {
                        return Err("State root changed during inspection".into());
                    }
                    return Ok(Self {
                        root,
                        path: path.to_owned(),
                        inventory,
                    });
                }
                Err(error)
                    if error == "State directory changed during inspection" && attempt < 3 =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10 * (attempt + 1)));
                }
                Err(error) => return Err(error),
            }
        }
        Err("State directory changed during inspection".into())
    }

    pub(crate) fn admission(config: &Path, settings: &Configuration) -> Result<Self, String> {
        let root = config.parent().ok_or("Missing dedicated state root")?;
        let layout = Self::inspect(root)?;
        layout.validate_links()?;
        layout.verify_settings(config, settings)?;
        Ok(layout)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn into_root(self) -> OwnedFd {
        self.root
    }

    pub(crate) fn validate_links(&self) -> Result<(), String> {
        if self.inventory.hardlinks != 0 {
            return Err("Protected regular files must have exactly one hardlink".into());
        }
        Ok(())
    }

    fn verify_settings(&self, config: &Path, settings: &Configuration) -> Result<(), String> {
        let root = &self.path;
        let ledger = settings.audit_log.as_deref().ok_or("Missing audit_log")?;
        let jobs = settings.job_state_path().ok_or("Missing job_state_dir")?;
        required(&self.root, root, config, FileType::RegularFile)?;
        required(&self.root, root, ledger, FileType::RegularFile)?;
        required(&self.root, root, jobs, FileType::Directory)?;
        if settings.clients.iter().any(|client| {
            root.starts_with(&client.root)
                || client.root.starts_with(root)
                || client
                    .extra_roots
                    .iter()
                    .any(|scope| root.starts_with(scope.path()) || scope.path().starts_with(root))
        }) {
            return Err("State root must be separate from all approved workspace scopes".into());
        }
        let now = open_absolute_dir(root).map_err(|_| "State root changed during verification")?;
        if !same_identity(&self.root, now).map_err(|_| "Cannot verify state root identity")? {
            return Err("State root changed during verification".into());
        }
        Ok(())
    }
}

fn required(
    root_fd: &OwnedFd,
    root: &Path,
    path: &Path,
    kind: FileType,
) -> Result<OwnedFd, String> {
    validate_path(path)?;
    let relative = path
        .strip_prefix(root)
        .ok()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or("Configuration, audit and jobs must be under the dedicated state root")?;
    let fd = fs::openat2(
        root_fd,
        relative,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        LOCAL,
    )
    .map_err(|_| "Required state entry is missing, a symlink, or crosses a mount")?;
    let metadata = fs::fstat(&fd).map_err(|_| "Cannot inspect required state entry")?;
    if FileType::from_raw_mode(metadata.st_mode) != kind {
        return Err("Required state entry has an unexpected file type".into());
    }
    Ok(fd)
}

fn same_identity(first: impl AsFd, second: impl AsFd) -> io::Result<bool> {
    let first = fs::fstat(first)?;
    let second = fs::fstat(second)?;
    Ok((first.st_dev, first.st_ino) == (second.st_dev, second.st_ino))
}

struct Inventory {
    uid: Option<u32>,
    masked: bool,
    bundle_root: bool,
    remaining: usize,
    files: usize,
    hardlinks: usize,
    objects: Option<BTreeSet<[u64; 2]>>,
}

impl Inventory {
    fn directory(&mut self, dir: &OwnedFd, depth: usize, path: &[OsString]) -> Result<(), String> {
        let invalid = |_| "Cannot inspect state without following links or crossing mountpoints";
        let before = fs::fstat(dir).map_err(invalid)?;
        if self
            .uid
            .is_some_and(|uid| before.st_uid != uid || before.st_mode & 0o7777 != 0o700)
        {
            return Err("State directories must be owned by the gateway user and mode 0700".into());
        }
        if let Some(objects) = &mut self.objects {
            objects.insert([before.st_dev, before.st_ino]);
        }
        if depth >= MAX_DEPTH {
            return Err("State directory exceeds inspection depth".into());
        }
        let mut child_flags = OFlags::PATH | OFlags::CLOEXEC;
        if self.uid.is_none() {
            // Open the desktop link itself. NO_SYMLINKS still prohibits traversal.
            child_flags |= OFlags::NOFOLLOW;
        }
        for entry in Dir::read_from(dir).map_err(invalid)? {
            let entry = entry.map_err(invalid)?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            self.remaining = self
                .remaining
                .checked_sub(1)
                .ok_or("State directory exceeds inspection entry limit")?;
            let child =
                fs::openat2(dir, name, child_flags, Mode::empty(), LOCAL).map_err(|error| {
                    if self.uid.is_some() && error == rustix::io::Errno::NOENT {
                        "State directory changed during inspection"
                    } else {
                        invalid(error)
                    }
                })?;
            let metadata = fs::fstat(&child).map_err(invalid)?;
            if self.uid.is_some_and(|uid| metadata.st_uid != uid) {
                return Err("State entries must be owned by the gateway user".into());
            }
            match FileType::from_raw_mode(metadata.st_mode) {
                FileType::Directory => {
                    let child = fs::openat(
                        child,
                        ".",
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(invalid)?;
                    let mut child_path = path.to_vec();
                    child_path.push(OsString::from(name.to_string_lossy().into_owned()));
                    self.directory(&child, depth + 1, &child_path)?;
                }
                FileType::RegularFile
                    if self.uid.is_none()
                        || metadata.st_mode & 0o7177 == 0
                        || (((self.bundle_root && path.len() == 1 && path[0] == "bin")
                            || (!self.bundle_root
                                && path.len() == 3
                                && path[0] == "upstream-bundles"
                                && path[2] == "bin"))
                            && metadata.st_mode & 0o7077 == 0
                            && metadata.st_nlink == 1
                            && verified_elf(dir, name, &child)) =>
                {
                    if let Some(objects) = &mut self.objects {
                        objects.insert([metadata.st_dev, metadata.st_ino]);
                    }
                    self.files += 1;
                    self.hardlinks += usize::from(metadata.st_nlink != 1);
                }
                // The link's referent is governed by its own path and inode.
                FileType::Symlink if self.uid.is_none() && metadata.st_nlink == 1 => {}
                // A live desktop socket disappears with the containing mount.
                FileType::Socket if self.masked && metadata.st_nlink == 1 => {}
                _ => return Err("State contains an unsafe file type or permission mode".into()),
            }
        }
        let after = fs::fstat(dir).map_err(invalid)?;
        if changed(&before) != changed(&after) {
            return Err("State directory changed during inspection".into());
        }
        Ok(())
    }
}

fn protected_inventory(
    path: &Path,
    masked: bool,
    collect_objects: bool,
) -> io::Result<BTreeSet<[u64; 2]>> {
    let parent = open_absolute_dir(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
    let file = fs::openat2(
        parent,
        path.file_name().ok_or(io::ErrorKind::InvalidInput)?,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        LOCAL,
    )?;
    let stat = fs::fstat(&file)?;
    let kind = FileType::from_raw_mode(stat.st_mode);
    if kind == FileType::RegularFile && !masked {
        if stat.st_nlink != 1 {
            return Err(io::Error::other("Protected file has a hardlink alias"));
        }
        return Ok(if collect_objects {
            BTreeSet::from([[stat.st_dev, stat.st_ino]])
        } else {
            BTreeSet::new()
        });
    }
    if kind != FileType::Directory {
        return Err(io::Error::other("Unsupported protected path"));
    }
    let root = fs::openat(
        file,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut inventory = Inventory {
        uid: None,
        masked,
        bundle_root: false,
        remaining: MAX_ENTRIES,
        files: 0,
        hardlinks: 0,
        objects: collect_objects.then(BTreeSet::new),
    };
    inventory
        .directory(&root, 0, &[])
        .map_err(io::Error::other)?;
    if !same_identity(&root, open_absolute_dir(path)?)? {
        return Err(io::Error::other(
            "Protected directory changed during admission",
        ));
    }
    if inventory.hardlinks != 0 {
        return Err(io::Error::other("Protected directory has a hardlink alias"));
    }
    Ok(inventory.objects.unwrap_or_default())
}

pub(crate) fn verify_private_aliases(path: &Path, masked: bool) -> io::Result<()> {
    protected_inventory(path, masked, false).map(|_| ())
}

pub(crate) fn protected_objects(path: &Path, masked: bool) -> io::Result<BTreeSet<[u64; 2]>> {
    protected_inventory(path, masked, true)
}

fn changed(stat: &Stat) -> (i64, i64) {
    (stat.st_ctime, stat.st_ctime_nsec as i64)
}

fn verified_elf(dir: &OwnedFd, name: &std::ffi::CStr, expected: &OwnedFd) -> bool {
    let Ok(fd) = fs::openat2(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        LOCAL,
    ) else {
        return false;
    };
    if !same_identity(expected, &fd).unwrap_or(false) {
        return false;
    }
    let mut magic = [0; 4];
    std::fs::File::from(fd).read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn executable_files_are_confined_to_bundle_bin() {
        let root = std::env::temp_dir().join(format!("veyl-state-test-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bundles = root.join("upstream-bundles");
        let bin = bundles.join("demo/bin");
        std::fs::create_dir_all(&bin).unwrap();
        for dir in [&bundles, &bundles.join("demo"), &bin] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let inspect = || {
            let fd = open_absolute_dir(&root).unwrap();
            Inventory {
                uid: Some(rustix::process::geteuid().as_raw()),
                masked: false,
                bundle_root: false,
                remaining: MAX_ENTRIES,
                files: 0,
                hardlinks: 0,
                objects: None,
            }
            .directory(&fd, 0, &[])
        };
        for file in [root.join("bad.sh"), bundles.join("bad.sh")] {
            std::fs::write(&file, b"\x7fELF").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(inspect().is_err());
            std::fs::remove_file(file).unwrap();
        }
        let executable = bin.join("app");
        std::fs::write(&executable, b"\x7fELF").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(inspect().is_ok());
        std::fs::write(&executable, b"#!/bin/sh").unwrap();
        assert!(inspect().is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
