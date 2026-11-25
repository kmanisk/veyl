//! Explicit, local-operator-only release and development-bundle updates.
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    path::Path,
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::Duration,
};

use mcp_gateway::security::linux_fs::open_operator_dir;
use rustix::fd::OwnedFd;
use rustix::fs::{self as at, AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const NAMES: [&str; 3] = ["veyl", "veyl-monitor", "mcp-gateway"];
const REMOTE_LIMIT: usize = 32 * 1024 * 1024;
const LOCAL_LIMIT: usize = 128 * 1024 * 1024;
const REPO: &str = "https://github.com/kmanisk/veyl/releases/download/";
const HELP: &str = "Usage: veyl update [--check | --reinstall | --from-dir DIR | --recover]\nUpdates the installed user binaries from the official GitHub release, or a trusted local bundle with SHA256SUMS. No automatic updates. Active jobs block installation. Requires curl for downloads and a standard Linux user installation.";

fn version_key(s: &str) -> Option<(u32, u32, u32, u8, u32)> {
    let (core, rank, sequence) = match s.split_once('-') {
        None => (s, 3, 0),
        Some((c, prerelease)) => {
            let (label, sequence) = match prerelease.split_once('.') {
                Some((label, n)) => (label, n.parse().ok()?),
                None => (prerelease, 0),
            };
            let rank = match label {
                "alpha" => 0,
                "beta" => 1,
                "rc" => 2,
                _ => return None,
            };
            (c, rank, sequence)
        }
    };
    let mut nums = core.split('.');
    let key = (
        nums.next()?.parse().ok()?,
        nums.next()?.parse().ok()?,
        nums.next()?.parse().ok()?,
        rank,
        sequence,
    );
    if nums.next().is_some()
        || s.len() > 48
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(key)
}

fn fetch(url: &str, limit: usize) -> Result<Vec<u8>, String> {
    let mut command = Command::new("/usr/bin/curl");
    command.env_clear().args([
        "-q",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "5",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "8",
        "--max-time",
        "60",
        "--user-agent",
        "Veyl-updater",
        "--url",
        url,
    ]);
    let (status, bytes) =
        crate::linux_command::capture(&mut command, limit, Duration::from_secs(65))
            .map_err(|_| "Release download failed or exceeded its bound (curl required)")?;
    if !status.success() {
        return Err("Official release download failed".into());
    }
    Ok(bytes)
}

fn choose_release(data: &serde_json::Value, prereleases: bool) -> Result<String, String> {
    data.as_array()
        .ok_or("Invalid release list")?
        .iter()
        .filter(|r| r["draft"] == false && (prereleases || r["prerelease"] == false))
        .filter_map(|r| {
            let v = r["tag_name"].as_str()?.strip_prefix('v')?;
            let key = version_key(v)?;
            if !prereleases && key.3 != 3 {
                return None;
            }
            Some((key, v))
        })
        .max_by_key(|(key, _)| *key)
        .map(|(_, v)| v.to_owned())
        .ok_or_else(|| "No supported published release".into())
}

fn latest() -> Result<String, String> {
    let bytes = fetch(
        "https://api.github.com/repos/kmanisk/veyl/releases?per_page=100",
        2 * 1024 * 1024,
    )?;
    let data: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid release metadata")?;
    choose_release(
        &data,
        version_key(env!("CARGO_PKG_VERSION")).is_some_and(|v| v.3 != 3),
    )
}

fn checksum(manifest: &[u8], name: &str) -> Result<String, String> {
    let manifest = std::str::from_utf8(manifest).map_err(|_| "Invalid SHA256SUMS")?;
    let mut found = None;
    for line in manifest.lines() {
        let Some((hash, file)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if file.trim_start().trim_start_matches('*') == name {
            if found.is_some() || hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("Invalid or duplicate binary checksum".into());
            }
            found = Some(hash.to_ascii_lowercase());
        }
    }
    found.ok_or_else(|| format!("Missing checksum for {name}"))
}

fn verify(bytes: &[u8], expected: &str, limit: usize) -> Result<(), String> {
    if bytes.len() < 64
        || bytes.len() > limit
        || !bytes.starts_with(b"\x7fELF\x02\x01")
        || bytes[18..20] != [62, 0]
        || format!("{:x}", Sha256::digest(bytes)) != expected
    {
        return Err("Binary checksum or Linux x86_64 format mismatch".into());
    }
    Ok(())
}

fn checked_dir(path: &Path) -> Result<(), String> {
    let handle = open_operator_dir(path)
        .map_err(|_| "Install or bundle directory must be real and absolute")?;
    let m = rustix::fs::fstat(&handle).map_err(|_| "Cannot inspect directory")?;
    if m.st_uid != rustix::process::geteuid().as_raw() || m.st_mode & 0o022 != 0 {
        return Err("Directory must be controlled by your user".into());
    }
    Ok(())
}

fn read_owned(path: &Path, limit: usize) -> Result<Option<(Vec<u8>, u32)>, String> {
    read_input(path, limit, false)
}

// Cargo's trusted source bundle may contain hardlinks to its own build cache.
// Installed destinations and rollback backups remain strictly single-linked.
fn read_input(path: &Path, limit: usize, source: bool) -> Result<Option<(Vec<u8>, u32)>, String> {
    // O_PATH before reading: never open a FIFO or device for I/O.
    let parent = open_operator_dir(path.parent().ok_or("Invalid file path")?)
        .map_err(|_| "Cannot open file directory")?;
    let handle = match rustix::fs::openat(
        &parent,
        path.file_name().ok_or("Invalid file name")?,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(f) => f,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err("Cannot inspect binary or checksum".into()),
    };
    let m = rustix::fs::fstat(&handle).map_err(|_| "Cannot inspect file")?;
    if rustix::fs::FileType::from_raw_mode(m.st_mode) != rustix::fs::FileType::RegularFile
        || m.st_uid != rustix::process::geteuid().as_raw()
        || (!source && m.st_nlink != 1)
        || m.st_mode & 0o7022 != 0
    {
        return Err("Refusing linked, unsafe or non-owned file".into());
    }
    let mut data = Vec::new();
    File::from(
        mcp_gateway::security::linux_fs::reopen_regular(handle, rustix::fs::OFlags::RDONLY)
            .map_err(|_| "Cannot read file")?,
    )
    .take(limit as u64 + 1)
    .read_to_end(&mut data)
    .map_err(|_| "Cannot read file")?;
    if data.len() > limit {
        return Err("File exceeds update bound".into());
    }
    Ok(Some((data, m.st_mode & 0o777)))
}

fn bundle(local: Option<&Path>, version: &str) -> Result<Vec<Vec<u8>>, String> {
    let get = |name: &str, limit: usize| -> Result<Vec<u8>, String> {
        if let Some(dir) = local {
            read_input(&dir.join(name), limit, true)?
                .map(|(bytes, _)| bytes)
                .ok_or_else(|| format!("Missing bundle file {name}"))
        } else {
            fetch(&format!("{REPO}v{version}/{name}"), limit)
        }
    };
    let manifest = get("SHA256SUMS", 32 * 1024)?;
    NAMES
        .iter()
        .map(|name| {
            let limit = if local.is_some() {
                LOCAL_LIMIT
            } else {
                REMOTE_LIMIT
            };
            let bytes = get(name, limit)?;
            verify(&bytes, &checksum(&manifest, name)?, limit)?;
            Ok(bytes)
        })
        .collect()
}

fn write_at(dir: &OwnedFd, name: &std::ffi::OsStr, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = File::from(
        at::openat(
            dir,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "Cannot create update stage")?,
    );
    file.write_all(bytes)
        .map_err(|_| "Cannot write update stage")?;
    at::fchmod(&file, Mode::from_raw_mode(mode)).map_err(|_| "Cannot set binary permissions")?;
    file.sync_all()
        .map_err(|_| "Cannot sync update stage".into())
}

#[cfg(test)]
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let dir = open_operator_dir(path.parent().ok_or("Invalid stage parent")?)
        .map_err(|_| "Cannot open stage parent")?;
    write_at(
        &dir,
        path.file_name().ok_or("Invalid stage name")?,
        bytes,
        mode,
    )
}

fn sync_dir(path: &Path) -> Result<(), String> {
    let fd = open_operator_dir(path).map_err(|_| "Cannot open install directory")?;
    at::fsync(fd).map_err(|_| "Cannot sync install directory".into())
}

/// A private directory containing only files created by this transaction.
/// Preflight failures and completed installs remove staging files. Backups
/// are retained separately once any replacement is attempted.
struct PrivateStage {
    path: PathBuf,
    parent: OwnedFd,
    directory: Arc<OwnedFd>,
    names: Vec<std::ffi::OsString>,
    retain: bool,
}
impl PrivateStage {
    fn create(path: PathBuf) -> Result<Self, String> {
        let parent = open_operator_dir(path.parent().ok_or("Invalid stage parent")?)
            .map_err(|_| "Cannot open stage parent")?;
        let name = path.file_name().ok_or("Invalid stage name")?;
        at::mkdirat(&parent, name, Mode::from_raw_mode(0o700))
            .map_err(|_| "Cannot create private update directory")?;
        let directory = match at::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(_) => {
                let _ = at::unlinkat(&parent, name, AtFlags::REMOVEDIR);
                return Err("Cannot open private update directory".into());
            }
        };
        let stage = Self {
            path,
            parent,
            directory: Arc::new(directory),
            names: Vec::new(),
            retain: false,
        };
        let m = at::fstat(&*stage.directory).map_err(|_| "Cannot inspect stage")?;
        if m.st_uid != rustix::process::geteuid().as_raw() || m.st_mode & 0o7777 != 0o700 {
            return Err("Unsafe update directory".into());
        }
        at::fsync(&stage.parent).map_err(|_| "Cannot sync update parent")?;
        Ok(stage)
    }
    fn write(&mut self, name: &str, bytes: &[u8], mode: u32) -> Result<PathBuf, String> {
        let name = std::ffi::OsString::from(name);
        // Register before writing so a partially written file is cleaned.
        self.names.push(name.clone());
        write_at(&self.directory, &name, bytes, mode)?;
        at::fsync(&*self.directory).map_err(|_| "Cannot sync update directory")?;
        Ok(self.path.join(name))
    }
}
impl Drop for PrivateStage {
    fn drop(&mut self) {
        if self.retain {
            return;
        }
        for name in &self.names {
            let _ = at::unlinkat(&*self.directory, name, AtFlags::empty());
        }
        let Some(name) = self.path.file_name() else {
            return;
        };
        let current = at::statat(&self.parent, name, AtFlags::SYMLINK_NOFOLLOW);
        let pinned = at::fstat(&*self.directory);
        if current
            .ok()
            .zip(pinned.ok())
            .is_some_and(|(a, b)| (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino))
        {
            if at::unlinkat(&self.parent, name, AtFlags::REMOVEDIR).is_err() {
                eprintln!("Update staging cleanup incomplete: {}", self.path.display());
            }
            let _ = at::fsync(&self.parent);
        }
    }
}

struct Change {
    dest: PathBuf,
    staged: PathBuf,
    backup: Option<PathBuf>,
    dest_dir: Arc<OwnedFd>,
    stage_dir: Arc<OwnedFd>,
    installed: bool,
}
impl Change {
    fn new(dest: PathBuf, staged: PathBuf, backup: Option<PathBuf>) -> Result<Self, String> {
        let dest_dir = Arc::new(
            open_operator_dir(dest.parent().ok_or("Invalid destination")?)
                .map_err(|_| "Cannot pin install directory")?,
        );
        let stage_dir = Arc::new(
            open_operator_dir(staged.parent().ok_or("Invalid stage")?)
                .map_err(|_| "Cannot pin stage directory")?,
        );
        Ok(Self {
            dest,
            staged,
            backup,
            dest_dir,
            stage_dir,
            installed: false,
        })
    }
    fn replace(&mut self) -> Result<(), String> {
        at::renameat(
            &*self.stage_dir,
            self.staged.file_name().unwrap(),
            &*self.dest_dir,
            self.dest.file_name().unwrap(),
        )
        .map_err(|_| "Cannot publish binary")?;
        self.installed = true;
        at::fsync(&*self.dest_dir).map_err(|_| "Cannot sync install directory".into())
    }
    fn restore(&mut self) -> Result<(), String> {
        if self.installed {
            let name = self.dest.file_name().unwrap();
            if let Some(backup) = &self.backup {
                let (bytes, mode) =
                    read_owned(backup, LOCAL_LIMIT)?.ok_or("Rollback backup missing")?;
                let temp = self.staged.with_extension("restore");
                let tmp_name = temp.file_name().unwrap();
                write_at(&self.stage_dir, tmp_name, &bytes, mode)?;
                if at::renameat(&*self.stage_dir, tmp_name, &*self.dest_dir, name).is_err() {
                    let _ = at::unlinkat(&*self.stage_dir, tmp_name, AtFlags::empty());
                    return Err("Cannot restore backup".into());
                }
            } else {
                at::unlinkat(&*self.dest_dir, name, AtFlags::empty())
                    .map_err(|_| "Cannot remove newly installed binary")?;
            }
            at::fsync(&*self.dest_dir).map_err(|_| "Cannot sync restored directory")?;
            self.installed = false;
        }
        Ok(())
    }
}

fn require_idle(policy: &crate::http::operator::PolicyFile) -> Result<(), String> {
    let settings = policy.snapshot()?;
    crate::http::operator::verify_approvals(&settings)?;
    if let Some(state) = settings.job_state_path()
        && crate::jobs::has_active_jobs(state).map_err(|_| "Cannot verify signed job state")?
    {
        return Err("Wait for active or uncertain jobs to finish before updating".into());
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    nonce: String,
    phase: String,
    dirs: Vec<PathBuf>,
    backup_dir: PathBuf,
    service_executable: Option<PathBuf>,
    service_active: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    destination: PathBuf,
    backup: Option<PathBuf>,
    original_mode: Option<u32>,
    original_sha256: Option<String>,
}

fn update_lock(home: &Path) -> Result<OwnedFd, String> {
    checked_dir(home)?;
    let parent = open_operator_dir(home).map_err(|_| "Cannot open update lock directory")?;
    let fd = at::openat(
        &parent,
        ".veyl-update.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| "Cannot open update lock")?;
    let m = at::fstat(&fd).map_err(|_| "Cannot inspect update lock")?;
    if at::FileType::from_raw_mode(m.st_mode) != at::FileType::RegularFile
        || m.st_nlink != 1
        || m.st_uid != rustix::process::geteuid().as_raw()
        || m.st_mode & 0o7777 != 0o600
    {
        return Err("Unsafe update lock".into());
    }
    at::flock(&fd, at::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| "Another update is in progress")?;
    Ok(fd)
}

fn rollback_root(home: &Path, create: bool) -> Result<Option<(PathBuf, OwnedFd)>, String> {
    let path = home.join(".veyl-update-backups");
    if create {
        let parent = open_operator_dir(home).map_err(|_| "Cannot open home")?;
        match at::mkdirat(&parent, ".veyl-update-backups", Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => (),
            Err(_) => return Err("Cannot create rollback directory".into()),
        }
        at::fsync(&parent).map_err(|_| "Cannot sync home")?;
    } else if !path
        .try_exists()
        .map_err(|_| "Cannot inspect rollback directory")?
    {
        return Ok(None);
    }
    checked_dir(&path)?;
    let fd = open_operator_dir(&path).map_err(|_| "Cannot open rollback directory")?;
    if at::fstat(&fd)
        .map_err(|_| "Cannot inspect rollback directory")?
        .st_mode
        & 0o7777
        != 0o700
    {
        return Err("Rollback directory must be private".into());
    }
    Ok(Some((path, fd)))
}

fn read_journal(home: &Path, root: &Path) -> Result<Option<Journal>, String> {
    let Some((data, mode)) = read_owned(&root.join("active.json"), 64 * 1024)? else {
        return Ok(None);
    };
    if mode != 0o600 {
        return Err("Unsafe update journal mode".into());
    }
    let j: Journal = serde_json::from_slice(&data).map_err(|_| "Invalid update journal")?;
    if j.nonce.is_empty()
        || !j.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        || j.backup_dir != root.join(&j.nonce)
        || !matches!(j.phase.as_str(), "staging" | "replacing" | "rolling_back")
        || j.dirs.is_empty()
        || j.dirs
            .iter()
            .any(|d| *d != home.join(".local/bin") && *d != home.join(".cargo/bin"))
        || (j.service_active
            && j.service_executable.as_ref().is_none_or(|e| {
                !j.dirs
                    .iter()
                    .any(|d| *e == d.join("veyl") || *e == d.join("mcp-gateway"))
            }))
    {
        return Err("Invalid update journal".into());
    }
    Ok(Some(j))
}

fn write_journal(fd: &OwnedFd, j: &Journal) -> Result<(), String> {
    let data = serde_json::to_vec(j).map_err(|_| "Cannot encode update journal")?;
    // A crash may leave the private temporary file. Refuse unsafe entries.
    match at::statat(fd, ".active.json.tmp", AtFlags::SYMLINK_NOFOLLOW) {
        Ok(m)
            if at::FileType::from_raw_mode(m.st_mode) == at::FileType::RegularFile
                && m.st_uid == rustix::process::geteuid().as_raw()
                && m.st_nlink == 1
                && m.st_mode & 0o7777 == 0o600 =>
        {
            at::unlinkat(fd, ".active.json.tmp", AtFlags::empty())
                .map_err(|_| "Cannot remove journal temporary file")?
        }
        Ok(_) => return Err("Unsafe journal temporary file".into()),
        Err(rustix::io::Errno::NOENT) => (),
        Err(_) => return Err("Cannot inspect journal temporary file".into()),
    }
    write_at(fd, std::ffi::OsStr::new(".active.json.tmp"), &data, 0o600)?;
    at::renameat(fd, ".active.json.tmp", fd, "active.json")
        .map_err(|_| "Cannot publish update journal")?;
    at::fsync(fd).map_err(|_| "Cannot sync update journal".into())
}
fn clear_journal(fd: &OwnedFd) -> Result<(), String> {
    at::unlinkat(fd, "active.json", AtFlags::empty())
        .map_err(|_| "Cannot remove update journal")?;
    at::fsync(fd).map_err(|_| "Cannot sync update journal removal".into())
}

// Only remove single-linked regular files owned by this user from a pinned directory.
fn clean_private_dir(parent_path: &Path, name: &std::ffi::OsStr) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let parent = open_operator_dir(parent_path).map_err(|_| "Cannot open cleanup parent")?;
    let dir = match at::openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(_) => return Err("Unsafe update cleanup directory".into()),
    };
    let m = at::fstat(&dir).map_err(|_| "Cannot inspect cleanup directory")?;
    if m.st_uid != rustix::process::geteuid().as_raw() || m.st_mode & 0o7777 != 0o700 {
        return Err("Unsafe update cleanup directory".into());
    }
    let entries = at::Dir::read_from(&dir).map_err(|_| "Cannot list cleanup directory")?;
    for entry in entries {
        let entry = entry.map_err(|_| "Cannot list cleanup directory")?;
        let name_c = entry.file_name();
        if matches!(name_c.to_bytes(), b"." | b"..") {
            continue;
        }
        let name = std::ffi::OsStr::from_bytes(name_c.to_bytes());
        let m = at::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "Cannot inspect cleanup file")?;
        if at::FileType::from_raw_mode(m.st_mode) != at::FileType::RegularFile
            || m.st_uid != rustix::process::geteuid().as_raw()
            || m.st_nlink != 1
        {
            return Err("Unsafe update cleanup file".into());
        }
        at::unlinkat(&dir, name, AtFlags::empty()).map_err(|_| "Cannot remove cleanup file")?;
    }
    at::fsync(&dir).map_err(|_| "Cannot sync cleanup directory")?;
    let current = at::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "Cannot inspect cleanup directory")?;
    if (current.st_dev, current.st_ino) != (m.st_dev, m.st_ino) {
        return Err("Cleanup directory changed".into());
    }
    at::unlinkat(&parent, name, AtFlags::REMOVEDIR)
        .map_err(|_| "Cannot remove cleanup directory")?;
    at::fsync(&parent).map_err(|_| "Cannot sync cleanup parent".into())
}
fn clean_staging(j: &Journal, root: &Path, remove_backup: bool) -> Result<(), String> {
    for dir in &j.dirs {
        clean_private_dir(
            dir,
            std::ffi::OsStr::new(&format!(".veyl-update-{}", j.nonce)),
        )?;
    }
    if remove_backup {
        clean_private_dir(root, std::ffi::OsStr::new(&j.nonce))?;
    }
    Ok(())
}
fn sweep(dirs: &[PathBuf]) -> Result<(), String> {
    for dir in dirs {
        checked_dir(dir)?;
        for e in std::fs::read_dir(dir).map_err(|_| "Cannot list install directory")? {
            let e = e.map_err(|_| "Cannot list install directory")?;
            let name = e.file_name();
            if name.to_string_lossy().starts_with(".veyl-update-") {
                let m = std::fs::symlink_metadata(e.path()).map_err(|_| "Cannot inspect orphan stage")?;
                if m.is_dir() {
                    clean_private_dir(dir, &name)?;
                }
            }
        }
    }
    Ok(())
}
fn config_path(home: &Path) -> Result<Option<PathBuf>, String> {
    let current = home.join(".local/state/veyl/clients.json");
    let legacy = home.join(".config/mcp-gateway/clients.json");
    match (current.try_exists(), legacy.try_exists()) {
        (Ok(true), Ok(false)) => Ok(Some(current)),
        (Ok(false), Ok(true)) => Ok(Some(legacy)),
        (Ok(false), Ok(false)) => Ok(None),
        _ => Err("Ambiguous or unreadable Veyl configuration".into()),
    }
}
fn existing_bins(home: &Path) -> Result<Vec<PathBuf>, String> {
    let mut dirs = Vec::new();
    for dir in [home.join(".local/bin"), home.join(".cargo/bin")] {
        match dir.symlink_metadata() {
            Ok(_) => {
                checked_dir(&dir)?;
                dirs.push(dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("Cannot inspect installation".into()),
        }
    }
    Ok(dirs)
}
fn recover(home: &Path) -> Result<(), String> {
    checked_dir(home)?;
    let dirs = existing_bins(home)?;
    let _lock = update_lock(home)?;
    let Some((root, fd)) = rollback_root(home, false)? else {
        sweep(&dirs)?;
        println!("No interrupted update transaction found.");
        return Ok(());
    };
    let Some(mut j) = read_journal(home, &root)? else {
        sweep(&dirs)?;
        println!("No interrupted update transaction found.");
        return Ok(());
    };
    if j.phase == "staging" {
        clean_staging(&j, &root, true)?;
        clear_journal(&fd)?;
        println!("Cleaned interrupted update staging ({}).", j.nonce);
        return Ok(());
    }
    let config = config_path(home)?;
    let policy = config
        .as_ref()
        .map(|p| crate::http::operator::PolicyFile::lock(p, true))
        .transpose()?;
    if let Some(policy) = &policy {
        require_idle(policy)?;
    }
    let (data, _) = read_owned(&j.backup_dir.join("manifest.json"), 64 * 1024)?
        .ok_or("Rollback manifest missing")?;
    let entries: Vec<ManifestEntry> =
        serde_json::from_slice(&data).map_err(|_| "Invalid rollback manifest")?;
    let mut prepared = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for e in entries {
        let dir = e
            .destination
            .parent()
            .ok_or("Invalid rollback destination")?;
        let name = e
            .destination
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid rollback destination")?;
        if !j.dirs.iter().any(|d| d == dir)
            || !NAMES.contains(&name)
            || e.destination != dir.join(name)
            || !seen.insert(e.destination.clone())
        {
            return Err("Invalid rollback destination".into());
        }
        let original = if let Some(path) = &e.backup {
            if path.parent() != Some(j.backup_dir.as_path()) || path.file_name().is_none() {
                return Err("Invalid rollback backup path".into());
            }
            let (data, mode) = read_owned(path, LOCAL_LIMIT)?.ok_or("Rollback backup missing")?;
            let expected_mode = e.original_mode.ok_or("Rollback mode missing")?;
            if mode != expected_mode
                || e.original_sha256.as_deref()
                    != Some(format!("{:x}", Sha256::digest(&data)).as_str())
            {
                return Err("Rollback backup checksum or mode mismatch".into());
            }
            Some((data, mode))
        } else {
            if e.original_mode.is_some() || e.original_sha256.is_some() {
                return Err("Invalid rollback manifest".into());
            }
            None
        };
        prepared.push((e.destination, original));
    }
    if seen.len() != j.dirs.len() * NAMES.len() {
        return Err("Incomplete rollback manifest".into());
    }
    j.phase = "rolling_back".into();
    write_journal(&fd, &j)?;
    if j.service_active {
        crate::service_cli::update_stop()?;
    }
    for dir in &j.dirs {
        clean_private_dir(dir, std::ffi::OsStr::new(&format!(".veyl-update-recover-{}", j.nonce)))?;
        let mut stage =
            PrivateStage::create(dir.join(format!(".veyl-update-recover-{}", j.nonce)))?;
        let dest_fd = open_operator_dir(dir).map_err(|_| "Cannot open install directory")?;
        for (dest, original) in prepared
            .iter()
            .filter(|(dest, _)| dest.parent() == Some(dir.as_path()))
        {
            let name = dest.file_name().unwrap();
            if let Some((data, mode)) = original {
                stage.write(name.to_str().unwrap(), data, *mode)?;
                at::renameat(&*stage.directory, name, &dest_fd, name)
                    .map_err(|_| "Cannot restore backup")?;
            } else {
                match at::unlinkat(&dest_fd, name, AtFlags::empty()) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => (),
                    Err(_) => return Err("Cannot remove installed binary".into()),
                }
            }
            at::fsync(&dest_fd).map_err(|_| "Cannot sync restored directory")?;
        }
    }
    clean_staging(&j, &root, false)?;
    drop(policy);
    if j.service_active {
        crate::service_cli::update_start(
            j.service_executable
                .as_deref()
                .ok_or("Missing service executable")?,
        )?;
    }
    clear_journal(&fd)?;
    println!("Recovered interrupted update ({}).", j.nonce);
    Ok(())
}

fn install(
    home: &Path,
    payloads: &[Vec<u8>],
    expected_version: Option<&str>,
) -> Result<(), String> {
    let mut dirs = Vec::new();
    for dir in [home.join(".local/bin"), home.join(".cargo/bin")] {
        let mut found = false;
        for name in NAMES {
            match dir.join(name).symlink_metadata() {
                Ok(_) => found = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err("Cannot inspect installation".into()),
            }
        }
        if found {
            checked_dir(&dir)?;
            dirs.push(dir);
        }
    }
    let running = std::env::current_exe().map_err(|_| "Cannot resolve updater executable")?;
    let installed = dirs
        .iter()
        .any(|dir| running == dir.join("veyl") || running == dir.join("mcp-gateway"));
    let bootstrap = expected_version.is_none()
        && read_input(&running, LOCAL_LIMIT, true)?.is_some_and(|(bytes, _)| bytes == payloads[0]);
    if dirs.is_empty() || !(installed || bootstrap) {
        return Err("Use the installed Veyl binary or the verified local bundle CLI; package-manager or custom installations need their own updater".into());
    }
    let _update_lock = update_lock(home)?;
    let (rollback_root, root_fd) = rollback_root(home, true)?.unwrap();
    if let Some(old) = read_journal(home, &rollback_root)? {
        if old.phase != "staging" {
            return Err(format!(
                "Interrupted update {}; run veyl update --recover",
                old.nonce
            ));
        }
        clean_staging(&old, &rollback_root, true)?;
        clear_journal(&root_fd)?;
    }
    sweep(&dirs)?;
    let executables: Vec<_> = dirs
        .iter()
        .flat_map(|d| [d.join("veyl"), d.join("mcp-gateway")])
        .collect();
    let config = config_path(home)?;
    let service = crate::service_cli::update_target(home, config.as_deref(), &executables)?;
    // All private staging directories are RAII-owned. A successful install
    // retains only one external rollback bundle, not staging in bin dirs.
    let nonce =
        crate::http::operator::revision().map_err(|_| "Cannot create update transaction")?;
    let mut journal = Journal {
        nonce: nonce.clone(),
        phase: "staging".into(),
        dirs: dirs.clone(),
        backup_dir: rollback_root.join(&nonce),
        service_executable: None,
        service_active: false,
    };
    write_journal(&root_fd, &journal)?;
    struct StagingJournalGuard<'a> {
        fd: &'a OwnedFd,
        clear_on_drop: bool,
    }
    impl Drop for StagingJournalGuard<'_> {
        fn drop(&mut self) {
            if self.clear_on_drop {
                let _ = clear_journal(self.fd);
            }
        }
    }
    let mut staging_guard = StagingJournalGuard {
        fd: &root_fd,
        clear_on_drop: true,
    };
    let mut backup = PrivateStage::create(rollback_root.join(&nonce))?;
    let mut stages = Vec::new();
    let mut changes = Vec::new();
    let mut manifest = Vec::new();
    for (index, dir) in dirs.iter().enumerate() {
        let mut stage = PrivateStage::create(dir.join(format!(".veyl-update-{nonce}")))?;
        for (name, bytes) in NAMES.iter().zip(payloads) {
            let dest = dir.join(name);
            let original = read_owned(&dest, LOCAL_LIMIT)?;
            let original_path = if let Some((data, mode)) = &original {
                Some(backup.write(&format!("{index}-{name}.old"), data, *mode)?)
            } else {
                None
            };
            manifest.push(serde_json::json!({"destination":dest,"backup":original_path,"original_mode":original.as_ref().map(|(_,mode)|*mode),"original_sha256":original.as_ref().map(|(data,_)|format!("{:x}",Sha256::digest(data)))}));
            let staged = stage.write(name, bytes, 0o755)?;
            stage.names.push(
                staged
                    .with_extension("restore")
                    .file_name()
                    .unwrap()
                    .to_owned(),
            );
            changes.push(Change::new(dest, staged, original_path)?);
        }
        sync_dir(dir)?;
        stages.push(stage);
    }
    backup.write(
        "manifest.json",
        &serde_json::to_vec_pretty(&manifest).map_err(|_| "Cannot encode rollback manifest")?,
        0o600,
    )?;
    let mut detected = None;
    for change in changes.iter().take(NAMES.len()) {
        let mut command = Command::new(&change.staged);
        command.env_clear().arg("--version");
        let (status, output) =
            crate::linux_command::capture(&mut command, 128, Duration::from_secs(5))
                .map_err(|_| "Staged binary version check failed")?;
        let output = std::str::from_utf8(&output).map_err(|_| "Invalid staged version")?;
        let mut words = output.split_whitespace();
        let binary = words.next().ok_or("Missing staged binary name")?;
        let version = words.next().ok_or("Missing staged version")?;
        let key = version_key(version).ok_or("Invalid staged version")?;
        if !status.success()
            || change.dest.file_name().and_then(|n| n.to_str()) != Some(binary)
            || words.next().is_some()
            || expected_version.is_some_and(|v| v != version)
            || detected.as_ref().is_some_and(|v| v != version)
            || key < version_key(env!("CARGO_PKG_VERSION")).unwrap()
        {
            return Err("Staged binary identity, version mismatch or downgrade refused".into());
        }
        detected = Some(version.to_owned());
    }
    let version = detected.ok_or("Empty update bundle")?;
    let policy = config
        .as_ref()
        .map(|p| crate::http::operator::PolicyFile::lock(p, true))
        .transpose()?;
    if let Some(policy) = &policy {
        require_idle(policy)?;
    }
    // Recheck staged data and the original files after draining admitted calls.
    // Never overwrite an installation that changed while the update was prepared.
    for (i, change) in changes.iter().enumerate() {
        if read_owned(&change.staged, LOCAL_LIMIT)?
            .is_none_or(|(data, _)| data != payloads[i % NAMES.len()])
        {
            return Err("Staged binary changed during update".into());
        }
        let original = change
            .backup
            .as_ref()
            .map(|p| read_owned(p, LOCAL_LIMIT))
            .transpose()?
            .flatten();
        if read_owned(&change.dest, LOCAL_LIMIT)? != original {
            return Err("Installed binary changed during staging".into());
        }
    }
    // No new admitted jobs can start while the exclusive policy lock is held.
    let service_now = crate::service_cli::update_target(home, config.as_deref(), &executables)?;
    if service_now != service {
        return Err("Service state changed during staging; retry when idle".into());
    }
    let restart = service
        .as_ref()
        .filter(|(_, active)| *active)
        .map(|(path, _)| path);
    journal.phase = "replacing".into();
    journal.service_active = restart.is_some();
    journal.service_executable = restart.cloned();
    write_journal(&root_fd, &journal)?;
    staging_guard.clear_on_drop = false;
    backup.retain = true;
    if restart.is_some() {
        crate::service_cli::update_stop()?;
    }
    backup.retain = true;
    println!("Update rollback bundle: {}", backup.path.display());
    let result = (|| {
        for change in &mut changes {
            change.replace()?;
        }
        Ok::<_, String>(())
    })();
    drop(policy); // New service startup needs the shared admission lock.
    let result = result.and_then(|()| {
        if let Some(exe) = restart {
            crate::service_cli::update_start(exe)
        } else {
            Ok(())
        }
    });
    if let Err(error) = result {
        journal.phase = "rolling_back".into();
        write_journal(&root_fd, &journal)?;
        let rollback_policy = config
            .as_ref()
            .map(|p| crate::http::operator::PolicyFile::lock(p, true))
            .transpose()?;
        if let Some(policy) = &rollback_policy {
            require_idle(policy).map_err(|e| {
                format!("{error}; automatic rollback refused: {e}; backups retained")
            })?;
        }
        if restart.is_some() {
            crate::service_cli::update_stop()
                .map_err(|e| format!("{error}; cannot stop service for rollback: {e}"))?;
        }
        let mut restore_errors = Vec::new();
        for change in changes.iter_mut().rev() {
            if let Err(e) = change.restore() {
                restore_errors.push(format!("{}: {e}", change.dest.display()));
            }
        }
        if !restore_errors.is_empty() {
            return Err(format!(
                "{error}; rollback incomplete: {}; restore from printed backup paths",
                restore_errors.join("; ")
            ));
        }
        drop(rollback_policy);
        if let Some(exe) = restart {
            crate::service_cli::update_start(exe)
                .map_err(|e| format!("{error}; restored binaries but restart failed: {e}"))?;
        }
        clear_journal(&root_fd)?;
        return Err(format!("{error}; previous binaries restored"));
    }
    clear_journal(&root_fd)?;
    println!(
        "Veyl {version} installed. Reopen existing TUI instances. Permissions and configuration unchanged."
    );
    Ok(())
}

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    if !cfg!(target_arch = "x86_64") || rustix::process::geteuid().is_root() {
        return Err("Updater requires an unprivileged Linux x86_64 user".into());
    }
    let local = match args {
        [a, b] if a == "--from-dir" => Some(PathBuf::from(b)),
        [] => None,
        [a] if a == "--check" || a == "--reinstall" || a == "--recover" => None,
        _ => return Err(HELP.into()),
    };
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or("HOME must be absolute")?;
    if args == ["--recover"] {
        return recover(&home);
    }
    if let Some(dir) = local {
        let dir = if dir.is_absolute() {
            dir
        } else {
            std::env::current_dir()
                .map_err(|_| "Cannot resolve current directory")?
                .join(dir)
        };
        checked_dir(&dir)?;
        return install(&home, &bundle(Some(&dir), "")?, None);
    }
    let version = latest()?;
    let current = env!("CARGO_PKG_VERSION");
    println!("Installed: {current} | Latest: {version}");
    if args == ["--check"] {
        return Ok(());
    }
    let wanted = version_key(&version).unwrap();
    let installed = version_key(current).unwrap();
    if wanted < installed {
        return Err("Refusing to downgrade to an older release".into());
    }
    if wanted == installed && args != ["--reinstall"] {
        println!("Already current. Use --reinstall to restore the published binaries.");
        return Ok(());
    }
    install(&home, &bundle(None, &version)?, Some(&version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt};
    fn fixture() -> (PathBuf, PathBuf, OwnedFd, Journal) {
        let home = std::env::temp_dir().join(format!("veyl-recovery-test-{}", crate::http::operator::revision().unwrap()));
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        let dir = home.join(".local/bin");
        let (root, fd) = rollback_root(&home, true).unwrap().unwrap();
        let j = Journal { nonce: "abcdef".into(), phase: "staging".into(), dirs: vec![dir], backup_dir: root.join("abcdef"), service_executable: None, service_active: false };
        (home, root, fd, j)
    }
    fn replacing_fixture() -> (PathBuf, PathBuf, OwnedFd, Journal) {
        let (home, root, fd, mut j) = fixture();
        let mut backup = PrivateStage::create(j.backup_dir.clone()).unwrap();
        let old = backup.write("old", b"original", 0o750).unwrap();
        let entries = serde_json::json!([
            {"destination": j.dirs[0].join("veyl"), "backup": old, "original_mode": 0o750, "original_sha256": format!("{:x}", Sha256::digest(b"original"))},
            {"destination": j.dirs[0].join("veyl-monitor"), "backup": null, "original_mode": null, "original_sha256": null},
            {"destination": j.dirs[0].join("mcp-gateway"), "backup": null, "original_mode": null, "original_sha256": null}
        ]);
        backup.write("manifest.json", &serde_json::to_vec(&entries).unwrap(), 0o600).unwrap();
        backup.retain = true;
        write_new(&j.dirs[0].join("veyl"), b"updated", 0o755).unwrap();
        write_new(&j.dirs[0].join("veyl-monitor"), b"new", 0o755).unwrap();
        let mut stage = PrivateStage::create(j.dirs[0].join(".veyl-update-abcdef")).unwrap();
        stage.write("mcp-gateway", b"staged", 0o755).unwrap();
        stage.retain = true;
        j.phase = "replacing".into();
        write_journal(&fd, &j).unwrap();
        (home, root, fd, j)
    }
    #[test]
    fn interrupted_staging_is_cleaned_before_next_transaction() {
        let (home, root, fd, j) = fixture();
        let mut backup = PrivateStage::create(j.backup_dir.clone()).unwrap();
        backup.write("partial", b"old", 0o600).unwrap(); backup.retain = true;
        let mut stage = PrivateStage::create(j.dirs[0].join(".veyl-update-abcdef")).unwrap();
        stage.write("partial", b"new", 0o600).unwrap(); stage.retain = true;
        write_journal(&fd, &j).unwrap();
        let old = read_journal(&home, &root).unwrap().unwrap();
        clean_staging(&old, &root, true).unwrap(); clear_journal(&fd).unwrap();
        assert!(!j.backup_dir.exists()); assert!(!j.dirs[0].join(".veyl-update-abcdef").exists()); assert!(!root.join("active.json").exists());
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn recover_restores_and_removes_new_files() {
        let (home, root, _fd, j) = replacing_fixture();
        recover(&home).unwrap();
        assert_eq!(read_owned(&j.dirs[0].join("veyl"), LOCAL_LIMIT).unwrap().unwrap(), (b"original".to_vec(), 0o750));
        assert!(!j.dirs[0].join("veyl-monitor").exists());
        assert!(!j.dirs[0].join(".veyl-update-abcdef").exists());
        assert!(!root.join("active.json").exists()); assert!(j.backup_dir.exists());
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn recover_rejects_tampered_manifest_and_backup() {
        let (home, root, _fd, j) = replacing_fixture();
        let path = j.backup_dir.join("manifest.json");
        let bytes = fs::read(&path).unwrap();
        let mut manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        manifest[0]["destination"] = serde_json::json!(home.join("outside"));
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(recover(&home).is_err());
        fs::write(&path, bytes).unwrap();
        fs::write(j.backup_dir.join("old"), b"tampered").unwrap();
        assert!(recover(&home).is_err());
        assert_eq!(fs::read(j.dirs[0].join("veyl")).unwrap(), b"updated");
        assert!(root.join("active.json").exists());
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn version_order() {
        assert!(version_key("0.2.5-beta") < version_key("0.2.5"));
        assert!(version_key("0.2.9") < version_key("0.2.10-beta"));
        assert!(version_key("../../evil").is_none());
        assert!(version_key("1.2.3-beta.2") < version_key("1.2.3-beta.10"));
    }
    #[test]
    fn selects_channel_and_skips_drafts() {
        let releases = serde_json::json!([
            {"draft":false,"prerelease":false,"tag_name":"v1.0.0"},
            {"draft":false,"prerelease":true,"tag_name":"v1.1.0-alpha"},
            {"draft":false,"prerelease":true,"tag_name":"v1.1.0-beta.2"},
            {"draft":false,"prerelease":true,"tag_name":"v1.1.0-rc.1"},
            {"draft":true,"prerelease":false,"tag_name":"v9.0.0"},
            {"draft":false,"prerelease":true,"tag_name":"v9.0.0-unsupported"}
        ]);
        assert_eq!(choose_release(&releases, false).unwrap(), "1.0.0");
        assert_eq!(choose_release(&releases, true).unwrap(), "1.1.0-rc.1");
    }
    #[test]
    fn checksum_rejects_duplicate_and_missing() {
        let h = "a".repeat(64);
        let line = format!("{h}  veyl\n");
        assert_eq!(checksum(line.as_bytes(), "veyl").unwrap(), h);
        assert!(checksum(format!("{line}{line}").as_bytes(), "veyl").is_err());
        assert!(checksum(line.as_bytes(), "mcp-gateway").is_err());
    }
    #[test]
    fn atomic_replacement_and_rollback_preserve_original() {
        let dir = std::env::temp_dir().join(format!(
            "veyl-update-test-{}",
            crate::http::operator::revision().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let dest = dir.join("veyl");
        let staged = dir.join("veyl.new");
        let backup = dir.join("veyl.old");
        write_new(&dest, b"old", 0o750).unwrap();
        write_new(&backup, b"old", 0o750).unwrap();
        write_new(&staged, b"new", 0o755).unwrap();
        let mut change = Change::new(dest.clone(), staged, Some(backup)).unwrap();
        change.replace().unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"new");
        change.restore().unwrap();
        assert_eq!(
            read_owned(&dest, LOCAL_LIMIT).unwrap().unwrap(),
            (b"old".to_vec(), 0o750)
        );
        std::os::unix::fs::symlink(&dest, dir.join("link")).unwrap();
        assert!(read_owned(&dir.join("link"), LOCAL_LIMIT).is_err());
        fs::hard_link(&dest, dir.join("alias")).unwrap();
        assert!(read_owned(&dest, LOCAL_LIMIT).is_err());
        assert_eq!(
            read_input(&dest, LOCAL_LIMIT, true).unwrap().unwrap().0,
            b"old"
        );
        assert!(read_input(&dir.join("link"), LOCAL_LIMIT, true).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn private_stage_removes_preflight_artifacts_and_preserves_backup() {
        let root = std::env::temp_dir().join(format!(
            "veyl-stage-test-{}",
            crate::http::operator::revision().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let stage_path = root.join("stage");
        {
            let mut stage = PrivateStage::create(stage_path.clone()).unwrap();
            stage.write("veyl", b"test", 0o755).unwrap();
            assert!(stage_path.join("veyl").is_file());
        }
        assert!(!stage_path.exists());
        let backup_path = root.join("backup");
        {
            let mut backup = PrivateStage::create(backup_path.clone()).unwrap();
            backup.write("veyl.old", b"old", 0o700).unwrap();
            backup.retain = true;
        }
        assert_eq!(fs::read(backup_path.join("veyl.old")).unwrap(), b"old");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn local_binary_limit_exceeds_remote_limit() {
        let mut elf = vec![0u8; REMOTE_LIMIT + 1];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18] = 62;
        let hash = format!("{:x}", Sha256::digest(&elf));
        assert!(verify(&elf, &hash, LOCAL_LIMIT).is_ok());
        assert!(verify(&elf, &hash, REMOTE_LIMIT).is_err());
    }

    #[test]
    fn binary_rejects_tamper() {
        let mut elf = vec![0u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18] = 62;
        let h = format!("{:x}", Sha256::digest(&elf));
        assert!(verify(&elf, &h, LOCAL_LIMIT).is_ok());
        elf[63] = 1;
        assert!(verify(&elf, &h, LOCAL_LIMIT).is_err());
    }
}
