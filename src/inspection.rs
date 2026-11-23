//! Bounded read-only Linux inspection. All workspace data starts at a pinned directory.

use mcp_gateway::security::linux_fs::{open_beneath_dir, reopen_regular};
use rustix::fd::OwnedFd;
use rustix::fs::{self, Dir, FileType, Mode, OFlags, ResolveFlags};
use serde_json::{Value, json};
use std::{
    ffi::OsStr,
    fs::{self as host_fs, File},
    io::{self, Read},
    os::unix::{ffi::OsStrExt, fs::DirBuilderExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use crate::http::admission::{Client, Configuration};
use crate::protected_paths::{Kind, OPTIONAL_DEFAULTS};
use crate::tools::{
    MutationRoot,
    registry::{Tool, tool_text},
};

const MAX_ENTRIES: usize = 16_384;
const MAX_COPY: u64 = 64 * 1024 * 1024;
static GIT_WORKER: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn system(root: Option<&MutationRoot>) -> Value {
    fn read(path: &str) -> String {
        let mut text = String::new();
        if let Ok(file) = File::open(path) {
            let _ = file.take(16_384).read_to_string(&mut text);
        }
        text
    }
    let mem = read("/proc/meminfo");
    let kib = |name: &str| {
        mem.lines().find_map(|line| {
            line.strip_prefix(name)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
    };
    let disk = root
        .and_then(|root| fs::fstatvfs(root.directory()).ok())
        .map(|stats| {
            json!({"total_bytes":stats.f_blocks.saturating_mul(stats.f_frsize),
            "available_bytes":stats.f_bavail.saturating_mul(stats.f_frsize)})
        });
    let load = read("/proc/loadavg")
        .split_whitespace()
        .take(3)
        .filter_map(|v| v.parse::<f64>().ok())
        .collect::<Vec<_>>();
    json!({
        "platform":"linux","architecture":std::env::consts::ARCH,
        "logical_cpus":std::thread::available_parallelism().ok().map(usize::from),
        "load_average":load,"memory_total_kib":kib("MemTotal:"),"memory_available_kib":kib("MemAvailable:"),
        "workspace_filesystem":disk
    })
}

pub(crate) fn run(
    tool: Tool,
    args: Option<&Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
) -> Value {
    let result = inspect(tool, args, config, settings, client);
    match result {
        Ok(value) => tool_text(false, &value.to_string()),
        Err(err) => tool_text(true, &err),
    }
}

fn inspect(
    tool: Tool,
    args: Option<&Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    let empty = serde_json::Map::new();
    let args = match args {
        Some(value) => value.as_object().ok_or("Expected an arguments object")?,
        None => &empty,
    };
    if matches!(tool, Tool::SystemInfo | Tool::ServiceStatus) {
        if !args.is_empty() {
            return Err("This tool takes no arguments".into());
        }
        return Ok(if tool == Tool::SystemInfo {
            system(client.mutation_root.as_ref())
        } else {
            crate::service_cli::health()
        });
    }
    let root = client
        .mutation_root
        .as_ref()
        .ok_or("Workspace unavailable")?;
    let relative = match args.get("path") {
        None => Path::new(""),
        Some(value) => {
            let raw = value
                .as_str()
                .filter(|p| p.len() < 1024)
                .ok_or("Invalid directory path")?;
            if raw == "." {
                Path::new("")
            } else if raw.is_empty()
                || raw.as_bytes().contains(&0)
                || raw
                    .split('/')
                    .any(|p| p.is_empty() || matches!(p, "." | ".."))
            {
                return Err("Use a root-relative directory path".into());
            } else {
                Path::new(raw)
            }
        }
    };
    let directory = open_beneath_dir(root.directory(), relative)
        .map_err(|_| "Directory unavailable or outside workspace")?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let reserved = |path: &Path| {
        let full = root.path().join(path);
        crate::protected_paths::is_mandatory(config, settings, &full)
            || settings
                .skills
                .as_ref()
                .is_some_and(|skills| full.starts_with(skills.path()))
            || settings
                .protected_paths
                .selected(Kind::Optional)
                .iter()
                .any(|rule| full.starts_with(&rule.path))
            || home.as_ref().is_some_and(|home| {
                OPTIONAL_DEFAULTS
                    .iter()
                    .any(|dir| full.starts_with(home.join(dir)))
            })
    };
    if reserved(relative) {
        return Err("Protected inspection directory".into());
    }
    let mut walk = Walk {
        reserved: &reserved,
        seen: 0,
        truncated: false,
        deadline: Instant::now() + Duration::from_millis(1400),
    };
    if tool == Tool::SearchFiles {
        let query = args
            .get("query")
            .and_then(Value::as_str)
            .filter(|q| !q.is_empty() && q.len() <= 128)
            .ok_or("Expected a literal query of 1–128 bytes")?;
        let content = args
            .get("content")
            .map_or(Some(false), Value::as_bool)
            .ok_or("Invalid content flag")?;
        if args
            .keys()
            .any(|key| !matches!(key.as_str(), "path" | "query" | "content"))
        {
            return Err("Unexpected search argument".into());
        }
        let mut matches = Vec::new();
        let mut budget = 4_194_304;
        let complete = walk.visit(&directory, relative, false, 0, &mut |path, entry| {
            if matches.len() >= 100 || budget == 0 { return Ok(false); }
            if !content && path.file_name().is_some_and(|name| name.to_string_lossy().contains(query)) {
                matches.push(json!({"path":path}));
            }
            if content && let Entry::File(file, len) = entry && len <= 65_536 && len <= budget {
                budget -= len;
                let mut bytes = Vec::new();
                if file.take(len+1).read_to_end(&mut bytes).is_ok()
                    && bytes.len() as u64 == len
                    && let Ok(text) = std::str::from_utf8(&bytes)
                {
                    for (idx, line) in text.lines().enumerate().filter(|(_,l)|l.contains(query)) {
                        matches.push(json!({"path":path,"line":idx+1,"excerpt":line.chars().take(200).collect::<String>()}));
                        if matches.len() == 100 || serde_json::to_vec(&matches)?.len() >= 40_000 { return Ok(false); }
                    }
                }
            }
            Ok(serde_json::to_vec(&matches)?.len() < 40_000)
        }).map_err(|_| "Workspace changed or search could not be completed")?;
        return Ok(json!({"matches":matches,"truncated": !complete || walk.truncated}));
    }
    if args
        .keys()
        .any(|key| !matches!(key.as_str(), "path" | "operation"))
    {
        return Err("Unexpected Git argument".into());
    }
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "info" | "status" | "diff" | "history"))
        .ok_or("Expected info, status, diff or history")?;
    let _permit = GIT_WORKER
        .try_lock()
        .map_err(|_| "A Git inspection is already running")?;
    git_snapshot(directory, relative, operation, &mut walk)
}

enum Entry {
    Directory,
    File(File, u64),
    Other,
}

struct Walk<'a> {
    reserved: &'a dyn Fn(&Path) -> bool,
    seen: usize,
    truncated: bool,
    deadline: Instant,
}
impl Walk<'_> {
    fn visit(
        &mut self,
        fd: &OwnedFd,
        current: &Path,
        git: bool,
        depth: usize,
        visit: &mut dyn FnMut(&Path, Entry) -> io::Result<bool>,
    ) -> io::Result<bool> {
        if depth > 28 {
            self.truncated = true;
            return Ok(true);
        }
        for item in Dir::read_from(fd)? {
            let item = item?;
            let name = OsStr::from_bytes(item.file_name().to_bytes());
            if matches!(name.to_str(), Some("." | "..")) {
                continue;
            }
            self.seen += 1;
            if self.seen > MAX_ENTRIES || Instant::now() >= self.deadline {
                return Ok(false);
            }
            let path = current.join(name);
            if path
                .to_str()
                .is_none_or(|p| p.len() > 1024 || p.chars().any(char::is_control))
                || (self.reserved)(&path)
                || (!git && name == ".git")
            {
                continue;
            }
            let handle = match fs::openat2(
                fd,
                name,
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_XDEV
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_SYMLINKS,
            ) {
                Ok(handle) => handle,
                Err(_) => {
                    self.truncated = true;
                    continue;
                }
            };
            let stat = fs::fstat(&handle)?;
            let entry = match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => Entry::Directory,
                FileType::RegularFile if stat.st_nlink == 1 => {
                    let readable = reopen_regular(&handle, OFlags::RDONLY | OFlags::NONBLOCK)?;
                    if fs::fstat(&readable)?.st_nlink != 1 {
                        self.truncated = true;
                        continue;
                    }
                    Entry::File(File::from(readable), stat.st_size.max(0) as u64)
                }
                _ => Entry::Other,
            };
            let directory = matches!(entry, Entry::Directory);
            if !visit(&path, entry)? {
                return Ok(false);
            }
            if directory {
                let dir = open_beneath_dir(&handle, Path::new("."))?;
                if !self.visit(&dir, &path, git, depth + 1, visit)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

struct Snapshot(PathBuf);
impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = host_fs::remove_dir_all(&self.0);
    }
}

fn git_snapshot(
    directory: OwnedFd,
    base: &Path,
    operation: &str,
    walk: &mut Walk<'_>,
) -> Result<Value, String> {
    if open_beneath_dir(&directory, Path::new(".git")).is_err() {
        return Err("Expected a workspace checkout with an in-tree .git directory".into());
    }
    let path = Path::new("/tmp").join(format!(
        "veyl-git-{}",
        crate::http::operator::revision().map_err(|e| e.to_string())?
    ));
    host_fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| "Cannot create private Git snapshot")?;
    let snapshot = Snapshot(path);
    let mut bytes = 0_u64;
    let mut omitted = 0;
    let metadata_only = matches!(operation, "history" | "info");
    let complete = walk
        .visit(&directory, base, true, 0, &mut |path, entry| {
            let rel = path.strip_prefix(base).map_err(io::Error::other)?;
            let value = rel.to_str().unwrap_or_default();
            if value == ".git/config"
                || value == ".git/config.worktree"
                || value.starts_with(".git/hooks")
                || matches!(
                    value,
                    ".git/objects/info/alternates" | ".git/objects/info/http-alternates"
                )
                || (metadata_only && !rel.starts_with(".git"))
            {
                return Ok(true);
            }
            let target = snapshot.0.join(rel);
            match entry {
                Entry::Directory => {
                    host_fs::create_dir(&target)?;
                }
                Entry::File(file, size) => {
                    bytes = bytes.saturating_add(size);
                    if bytes > MAX_COPY {
                        return Ok(false);
                    }
                    let mode = fs::fstat(&file)?.st_mode;
                    let mut into = File::options().write(true).create_new(true).open(&target)?;
                    let wrote = io::copy(&mut (&file).take(size + 1), &mut into)?;
                    if wrote != size || fs::fstat(&file)?.st_nlink != 1 {
                        return Err(io::Error::other("File changed"));
                    }
                    use std::os::unix::fs::PermissionsExt;
                    into.set_permissions(host_fs::Permissions::from_mode(if mode & 0o100 != 0 {
                        0o700
                    } else {
                        0o600
                    }))?;
                }
                Entry::Other => omitted += 1,
            }
            Ok(true)
        })
        .map_err(|_| "Git snapshot could not be built safely")?;
    if !complete || walk.truncated {
        return Err("Git snapshot exceeded its time, entry, or byte budget".into());
    }
    host_fs::write(
        snapshot.0.join(".git/config"),
        "[core]\nrepositoryformatversion=0\nbare=false\n",
    )
    .map_err(|_| "Cannot initialize isolated Git configuration")?;
    let mut command =
        Command::new(std::env::current_exe().map_err(|_| "Gateway executable unavailable")?);
    command
        .env_clear()
        .args(["--git-inspect-worker", operation])
        .arg(&snapshot.0);
    let (status, output) =
        crate::linux_command::capture(&mut command, 65_536, Duration::from_secs(2))
            .map_err(|_| "Git inspection exceeded its deadline or output limit")?;
    if !status.success() {
        return Err("Git inspection failed in the required sandbox".into());
    }
    Ok(
        json!({"operation":operation,"output":String::from_utf8_lossy(&output),"omitted_special_entries":omitted}),
    )
}
