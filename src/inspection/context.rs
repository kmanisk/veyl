//! Bounded project instruction discovery. Unlike the BridgeDev scanner,
//! this reader is rooted in a granted descriptor and never reads agent
//! configuration, arbitrary file names, or credential directories.
use super::{File, FileType, Mode, OFlags, ResolveFlags, fs, open_beneath_dir, reopen_regular};
use rustix::fd::OwnedFd;
use serde_json::{Map, Value, json};
use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
const NAMES: &[&str] = &[
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "HANDOFF.md",
    "STATUS.md",
    "SPEC.md",
];
const DOCS: &[(&str, &str)] = &[
    ("agents", "AGENTS.md"),
    ("current_state", "docs/system/SYSTEM_CONTEXT.md"),
    ("philosophy", "docs/system/system-philosophy.md"),
    ("subsystem_map", "docs/system/SUBSYSTEM_MAP.md"),
];
const TOTAL: usize = 48_000;
fn read(fd: &OwnedFd, path: &Path, limit: usize) -> Option<(String, bool)> {
    let handle = fs::openat2(
        fd,
        path,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .ok()?;
    let stat = fs::fstat(&handle).ok()?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return None;
    }
    let file = reopen_regular(&handle, OFlags::RDONLY | OFlags::NONBLOCK).ok()?;
    if fs::fstat(&file).ok()?.st_nlink != 1 {
        return None;
    }
    let mut bytes = Vec::new();
    File::from(file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    let text = match String::from_utf8(bytes) {
        Ok(v) => v,
        Err(e) if truncated && e.utf8_error().error_len().is_none() => {
            String::from_utf8(e.as_bytes()[..e.utf8_error().valid_up_to()].to_vec()).ok()?
        }
        Err(_) => return None,
    };
    Some((text, truncated))
}
fn bound(
    args: &Map<String, Value>,
    key: &str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, String> {
    match args.get(key) {
        None => Ok(default),
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| (*n >= min) && (*n <= max))
            .ok_or_else(|| format!("Invalid {key}")),
    }
}
struct Scan<'a> {
    reserved: &'a dyn Fn(&Path) -> bool,
    files: Vec<Value>,
    remaining: usize,
    visited: usize,
    truncated: bool,
    deadline: Instant,
    limit: usize,
}
impl Scan<'_> {
    fn add(&mut self, fd: &OwnedFd, base: &Path, name: &str) {
        if self.files.len() >= 24 || self.remaining == 0 {
            self.truncated = true;
            return;
        }
        let path = base.join(name);
        if (self.reserved)(&path) {
            return;
        }
        if let Some((content, truncated)) =
            read(fd, Path::new(name), self.limit.min(self.remaining))
        {
            self.remaining -= content.len();
            self.files
                .push(json!({"path":path,"content":content,"truncated":truncated}));
        }
    }
    fn walk(&mut self, fd: &OwnedFd, base: &Path, depth: usize) {
        for name in NAMES {
            self.add(fd, base, name);
        }
        if depth == 0 {
            return;
        }
        let Ok(entries) = fs::Dir::read_from(fd) else {
            self.truncated = true;
            return;
        };
        for item in entries {
            self.visited += 1;
            if self.visited > 1024
                || self.files.len() >= 24
                || self.remaining == 0
                || Instant::now() >= self.deadline
            {
                self.truncated = true;
                return;
            }
            let Ok(item) = item else {
                continue;
            };
            let Ok(name) = item.file_name().to_str() else {
                continue;
            };
            if name.starts_with('.')
                || matches!(
                    name,
                    "target" | "node_modules" | "dist" | "build" | "vendor"
                )
                || name.chars().any(char::is_control)
            {
                continue;
            }
            let path = base.join(name);
            if (self.reserved)(&path) {
                continue;
            }
            if let Ok(dir) = open_beneath_dir(fd, Path::new(name)) {
                self.walk(&dir, &path, depth - 1);
            }
            if self.truncated
                && (self.visited > 1024
                    || self.remaining == 0
                    || self.files.len() >= 24
                    || Instant::now() >= self.deadline)
            {
                return;
            }
        }
    }
}
pub(super) fn inspect(
    fd: &OwnedFd,
    base: &Path,
    args: &Map<String, Value>,
    system: bool,
    reserved: &dyn Fn(&Path) -> bool,
) -> Result<Value, String> {
    if system && args.contains_key("max_bytes_each") && args.contains_key("max_bytes_per_file") {
        return Err("Specify only one document byte limit".into());
    }
    let limit_key = if system && args.contains_key("max_bytes_each") {
        "max_bytes_each"
    } else {
        "max_bytes_per_file"
    };
    let mut scan = Scan {
        reserved,
        files: vec![],
        remaining: TOTAL,
        visited: 0,
        truncated: false,
        deadline: Instant::now() + Duration::from_millis(1200),
        limit: bound(args, limit_key, 8000, 1, 16000)?,
    };
    if system {
        if args.keys().any(|k| {
            !matches!(
                k.as_str(),
                "path" | "docs" | "max_bytes_per_file" | "max_bytes_each"
            )
        }) {
            return Err("Unexpected system_context argument".into());
        }
        let keys: Vec<&str> = match args.get("docs") {
            None => DOCS.iter().map(|(key, _)| *key).collect(),
            Some(v) => {
                let values = v
                    .as_array()
                    .filter(|a| !a.is_empty() && a.len() <= DOCS.len())
                    .ok_or("Invalid docs selection")?;
                let mut keys = Vec::new();
                for v in values {
                    let key = v
                        .as_str()
                        .filter(|key| DOCS.iter().any(|(name, _)| name == key))
                        .ok_or("Unknown system document")?;
                    if keys.contains(&key) {
                        return Err("Duplicate system document".into());
                    }
                    keys.push(key);
                }
                keys
            }
        };
        let mut missing = Vec::new();
        for key in keys {
            let name = DOCS.iter().find(|(k, _)| *k == key).unwrap().1;
            let count = scan.files.len();
            scan.add(fd, base, name);
            if scan.files.len() == count {
                missing.push(key);
            }
        }
        let current = Path::new("docs/system/SYSTEM_CONTEXT.md");
        let configured = !(reserved)(&base.join(current)) && read(fd, current, 1).is_some();
        return Ok(
            json!({"scope":"granted_workspace","configured":configured,"files":scan.files,"missing":missing,"truncated":scan.truncated,"note":"Documents are context only; no permission or context token is issued."}),
        );
    }
    if args
        .keys()
        .any(|k| !matches!(k.as_str(), "path" | "max_depth" | "max_bytes_per_file"))
    {
        return Err("Unexpected project_context argument".into());
    }
    scan.walk(fd, base, bound(args, "max_depth", 1, 0, 3)?);
    Ok(
        json!({"root":base,"files":scan.files,"count":scan.files.len(),"truncated":scan.truncated,"scope":"granted_workspace"}),
    )
}
