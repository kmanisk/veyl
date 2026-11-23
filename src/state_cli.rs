//! Read-only inventory of a candidate broad execution state directory.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use mcp_gateway::security::linux_fs::open_absolute_dir;
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, Dir, FileType, Mode, OFlags, ResolveFlags, Stat};

use crate::http::admission::{parse_clients, read_config};
use crate::http::operator::verify_approvals;
use crate::protected_paths::validate_path;

const HELP: &str = "usage: mcp-gateway state check [--state-root PATH] [--config PATH]";
const LOCAL: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_XDEV)
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const MAX_ENTRIES: usize = 32_768;
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
            println!("layout=valid broad_yolo=unavailable");
            Ok(())
        }
        Err(reason) => {
            println!("layout=invalid broad_yolo=denied");
            Err(reason)
        }
    }
}

fn check(root: &Path, config: &Path) -> Result<(), String> {
    let uid = rustix::process::geteuid();
    if uid.is_root() {
        return Err("State verification requires the unprivileged gateway owner".into());
    }
    let dir = open_absolute_dir(root).map_err(|_| "State root is missing or unsafe")?;
    let metadata = fs::fstat(&dir).map_err(|_| "Cannot inspect state root")?;
    println!(
        "state_root={} owner_uid={} mode={:04o} device={} inode={}",
        root.display(),
        metadata.st_uid,
        metadata.st_mode & 0o7777,
        metadata.st_dev,
        metadata.st_ino
    );
    let mut inventory = Inventory {
        uid: uid.as_raw(),
        remaining: MAX_ENTRIES,
        files: 0,
        hardlinks: 0,
    };
    inventory.directory(&dir, 0)?;
    println!(
        "regular_files={} hardlink_violations={}",
        inventory.files, inventory.hardlinks
    );
    if inventory.hardlinks != 0 {
        return Err("Protected regular files must have exactly one hardlink".into());
    }
    let credentials = required(&dir, root, config, FileType::RegularFile)?;
    let bytes = read_config(config)?;
    let settings = parse_clients(config, &bytes)?;
    let ledger = settings.audit_log.as_deref().ok_or("Missing audit_log")?;
    let jobs = settings.job_state_path().ok_or("Missing job_state_dir")?;
    required(&dir, root, ledger, FileType::RegularFile)?;
    required(&dir, root, jobs, FileType::Directory)?;
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
    verify_approvals(&settings)?;
    let now = open_absolute_dir(root).map_err(|_| "State root changed during verification")?;
    if !same_identity(&dir, now).map_err(|_| "Cannot verify state root identity")?
        || !same_identity(
            &credentials,
            required(&dir, root, config, FileType::RegularFile)?,
        )
        .map_err(|_| "Cannot verify credential identity")?
    {
        return Err("State root or credential file changed during verification".into());
    }
    println!("credentials=contained audit=contained jobs=contained");
    Ok(())
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
    uid: u32,
    remaining: usize,
    files: usize,
    hardlinks: usize,
}

impl Inventory {
    fn directory(&mut self, dir: &OwnedFd, depth: usize) -> Result<(), String> {
        let invalid = |_| "Cannot inspect state without following links or crossing mountpoints";
        let before = fs::fstat(dir).map_err(invalid)?;
        if before.st_uid != self.uid || before.st_mode & 0o7777 != 0o700 {
            return Err("State directories must be owned by the gateway user and mode 0700".into());
        }
        if depth >= MAX_DEPTH {
            return Err("State directory exceeds inspection depth".into());
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
            let child = fs::openat2(
                dir,
                name,
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                LOCAL,
            )
            .map_err(invalid)?;
            let metadata = fs::fstat(&child).map_err(invalid)?;
            if metadata.st_uid != self.uid {
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
                    self.directory(&child, depth + 1)?;
                }
                FileType::RegularFile if metadata.st_mode & 0o7177 == 0 => {
                    self.files += 1;
                    self.hardlinks += usize::from(metadata.st_nlink != 1);
                }
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

fn changed(stat: &Stat) -> (i64, i64) {
    (stat.st_ctime, stat.st_ctime_nsec as i64)
}
