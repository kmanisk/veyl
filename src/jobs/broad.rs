//! Broad Linux execution mount plan and an in-namespace execution guard.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use mcp_gateway::security::linux_fs::open_absolute_dir;
use serde::{Deserialize, Serialize};

use crate::http::admission::Configuration;
use crate::protected_paths::{Kind, OPTIONAL_DEFAULTS, READONLY_DEFAULTS, validate_path};
use crate::state_cli::Layout;

use super::sandbox::{Sandbox, check_inherited_fds, unsupported, validate_executable};

const GUARD: &str = "/.veyl-exec";
const WRITABLE: &[&str] = &[
    "/home", "/tmp", "/srv", "/opt", "/mnt", "/media", "/var/tmp",
];
const SYSTEM: &[&str] = &["/usr", "/etc"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Broad {
    config: PathBuf,
    state: PathBuf,
    home: PathBuf,
    masked: BTreeSet<PathBuf>,
    readonly: BTreeSet<PathBuf>,
}

impl Broad {
    pub(crate) fn prepare(config: &Path, settings: &Configuration) -> Result<Self, String> {
        let layout = Layout::admission(config, settings)?;
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME unavailable")?;
        validate_path(&home)?;
        let mut plan = Self {
            config: config.to_owned(),
            state: layout.path().to_owned(),
            home,
            masked: BTreeSet::new(),
            readonly: BTreeSet::new(),
        };
        plan.masked.insert(plan.state.clone());
        if let Some(skills) = &settings.skills {
            plan.masked.insert(skills.path().to_owned());
        }
        for name in OPTIONAL_DEFAULTS {
            plan.masked.insert(plan.home.join(name));
        }
        for name in READONLY_DEFAULTS {
            plan.readonly.insert(plan.home.join(name));
        }
        for kind in [Kind::Optional, Kind::ReadOnly] {
            for rule in settings.protected_paths.selected(kind) {
                rule.check_identity(kind)?;
                match kind {
                    Kind::Optional => &mut plan.masked,
                    Kind::ReadOnly => &mut plan.readonly,
                }
                .insert(rule.path.clone());
            }
        }
        for client in &settings.clients {
            let hooks = client.root.join(".git/hooks");
            if metadata(&hooks)
                .map_err(|error| error.to_string())?
                .is_some()
            {
                plan.readonly.insert(hooks);
            }
        }
        plan.validate().map_err(|error| error.to_string())?;
        Ok(plan)
    }

    pub(crate) fn file_parent(
        &self,
        path: &Path,
        write: bool,
    ) -> io::Result<crate::tools::MutationRoot> {
        if !visible(path)
            || self.is_masked(path)
            || (write
                && (SYSTEM.iter().any(|root| path.starts_with(root))
                    || self
                        .readonly
                        .iter()
                        .any(|readonly| path.starts_with(readonly))))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Protected or unavailable path",
            ));
        }
        let mut protected = BTreeSet::new();
        for candidate in self
            .masked
            .iter()
            .chain(self.readonly.iter().filter(|_| write))
        {
            if !visible(candidate) || self.hidden_by_parent(candidate) {
                continue;
            }
            if metadata(candidate)?.is_some() {
                protected.extend(crate::state_cli::protected_objects(
                    candidate,
                    self.masked.contains(candidate),
                )?);
            }
        }
        crate::tools::MutationRoot::open_broad_parent(
            path.parent().ok_or_else(unsupported)?,
            protected,
        )
    }

    /// Runner-side validation uses the admitted paths and checks state aliases
    /// again immediately before the mount namespace is assembled.
    pub(super) fn validate(&self) -> io::Result<()> {
        if !visible(&self.state)
            || self.home == self.state
            || self.state.starts_with(&self.home) && !visible(&self.home)
        {
            return Err(unsupported());
        }
        if visible(&self.home) {
            open_absolute_dir(&self.home)?;
        }
        if self.readonly.iter().any(|readonly| {
            self.masked
                .iter()
                .any(|masked| masked != readonly && masked.starts_with(readonly))
        }) {
            return Err(io::Error::other(
                "A read-only mount would re-expose a masked directory",
            ));
        }
        Layout::inspect(&self.state)
            .and_then(|layout| layout.validate_links())
            .map_err(io::Error::other)?;
        let mounts = mounts()?;
        for mount in &mounts {
            if visible(&mount.at)
                && matches!(
                    mount.kind.as_str(),
                    "proc" | "sysfs" | "devtmpfs" | "cgroup" | "cgroup2"
                )
            {
                return Err(io::Error::other(
                    "Unexpected host kernel filesystem in broad workspace",
                ));
            }
        }
        for path in self.masked.iter().chain(&self.readonly) {
            if path != &self.state && path.starts_with(&self.state) {
                continue;
            }
            if let Some(meta) = metadata(path)? {
                if meta.file_type().is_symlink() || !(meta.is_file() || meta.is_dir()) {
                    return Err(io::Error::other("Unsupported protected path"));
                }
                if !visible(path) {
                    // Nothing outside the projection is reachable inside it.
                    continue;
                }
                let kind = if self.masked.contains(path) {
                    Kind::Optional
                } else {
                    Kind::ReadOnly
                };
                if path != &self.state {
                    crate::protected_paths::Rule::inspect(path, kind).map_err(io::Error::other)?;
                    crate::state_cli::verify_private_aliases(path, kind == Kind::Optional)?;
                }
                no_mount_alias(path, &mounts)?;
            } else if path == &self.state {
                return Err(unsupported());
            }
        }
        Ok(())
    }

    pub(super) fn command(
        &self,
        cwd: &Path,
        identity: [u64; 2],
        executable: &str,
        args: &[String],
        network: bool,
    ) -> io::Result<Sandbox> {
        self.validate()?;
        validate_executable(executable)?;
        if !visible(cwd) || self.is_masked(cwd) {
            return Err(unsupported());
        }
        let mut sandbox = Sandbox::broad(network)?;
        let mut entries = 0;
        for name in WRITABLE.iter().chain(SYSTEM) {
            let path = Path::new(name);
            if let Some(meta) = metadata(path)? {
                if !meta.is_dir() || meta.file_type().is_symlink() {
                    return Err(unsupported());
                }
                if self.needs_projection(path) {
                    if SYSTEM.contains(name) {
                        return Err(io::Error::other(
                            "Cannot project a protected subtree in a system mount",
                        ));
                    }
                    // None of the real ancestors of a hidden tree may be
                    // writable in the sandbox. Bind only safe sibling trees
                    // onto this private directory. Otherwise a second broad
                    // job could rename a state ancestor while we are mounting.
                    sandbox.command.arg("--tmpfs").arg(path);
                    self.project(path, &mut sandbox, &mut entries)?;
                } else {
                    sandbox.pass(
                        if SYSTEM.contains(name) {
                            "--ro-bind-fd"
                        } else {
                            "--bind-fd"
                        },
                        open_absolute_dir(path)?,
                    )?;
                    sandbox.command.arg(path);
                }
            }
        }
        if Path::new("/etc/resolv.conf").is_symlink() {
            let resolver = fs::canonicalize("/etc/resolv.conf")?;
            if resolver.starts_with("/run") && resolver.is_file() {
                // Bind only the regular resolver file. Never bind the runtime directory.
                sandbox.pass("--ro-bind-fd", fs::File::open(&resolver)?)?;
                sandbox.command.arg(&resolver);
            }
        }
        let mut guard = Guard {
            masked: BTreeSet::new(),
            readonly: BTreeSet::new(),
            cwd: identity,
            host_mount: fs::read_link("/proc/self/ns/mnt")?,
            host_pid: fs::read_link("/proc/self/ns/pid")?,
        };

        if visible(&self.home) && self.home.is_dir() {
            sandbox.command.args(["--setenv", "HOME"]).arg(&self.home);
        }
        for path in &self.masked {
            if !visible(path) || self.hidden_by_parent(path) {
                continue;
            }
            // A missing target needs no mount. The private HOME projection
            // also prevents accidental host creation of missing default paths.
            if metadata(path)?.is_some() || path.starts_with(&self.home) {
                sandbox.command.arg("--tmpfs").arg(path);
                guard.masked.insert(path.clone());
            }
        }
        for path in &self.readonly {
            if visible(path) && !self.is_masked(path) && metadata(path)?.is_some() {
                bind(&mut sandbox, path, true)?;
                guard.readonly.insert(path.clone());
            }
        }
        if !guard.masked.contains(&self.state) {
            return Err(unsupported());
        }
        // The wrapper is the running runner inode, never a pathname in the
        // user's writable tree. All subsequent workload exec happens inside.
        sandbox.pass("--ro-bind-fd", fs::File::open("/proc/self/exe")?)?;
        sandbox
            .command
            .arg(GUARD)
            .arg("--chdir")
            .arg(cwd)
            .args(["--", GUARD, "--broad-exec"])
            .arg(serde_json::to_string(&guard)?)
            .arg(executable)
            .args(args);
        Ok(sandbox)
    }

    pub(crate) fn probe(&self, cwd: &Path) -> io::Result<()> {
        let meta = fs::metadata(cwd)?;
        let status = self
            .command(cwd, [meta.dev(), meta.ino()], "/usr/bin/true", &[], false)?
            .command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(unsupported())
        }
    }

    fn project(&self, path: &Path, sandbox: &mut Sandbox, seen: &mut usize) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            *seen += 1;
            if *seen > 4096 {
                return Err(unsupported());
            }
            let entry = entry?;
            let child = entry.path();
            if self.is_masked(&child) || self.readonly.contains(&child) {
                continue;
            }
            let kind = entry.file_type()?;
            if self.needs_projection(&child) {
                if !kind.is_dir() {
                    return Err(io::Error::other(
                        "A protected ancestor must be a real directory",
                    ));
                }
                sandbox.command.arg("--dir").arg(&child);
                self.project(&child, sandbox, seen)?;
            } else if kind.is_symlink() {
                sandbox
                    .command
                    .arg("--symlink")
                    .arg(fs::read_link(&child)?)
                    .arg(&child);
            } else if kind.is_file() || kind.is_dir() {
                bind(sandbox, &child, false)?;
            }
        }
        for target in &self.masked {
            if target.starts_with(path)
                && !self.hidden_by_parent(target)
                && let Some(parent) = target.parent()
            {
                sandbox.command.arg("--dir").arg(parent);
            }
        }
        Ok(())
    }

    fn needs_projection(&self, path: &Path) -> bool {
        path == self.home
            || (self.home.starts_with(path) && visible(&self.home))
            || self
                .masked
                .iter()
                .any(|mask| mask.starts_with(path) && mask != path)
            || (path.starts_with(&self.home)
                && self
                    .readonly
                    .iter()
                    .any(|target| target.starts_with(path) && target != path))
    }

    fn is_masked(&self, path: &Path) -> bool {
        self.masked.iter().any(|mask| path.starts_with(mask))
    }

    fn hidden_by_parent(&self, path: &Path) -> bool {
        self.masked
            .iter()
            .any(|mask| path != mask && path.starts_with(mask))
    }
}

fn bind(sandbox: &mut Sandbox, path: &Path, readonly: bool) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    let parent = open_absolute_dir(path.parent().ok_or_else(unsupported)?)?;
    let fd = rustix::fs::openat2(
        parent,
        path.file_name().ok_or_else(unsupported)?,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    sandbox.pass(
        if readonly {
            "--ro-bind-fd"
        } else {
            "--bind-fd"
        },
        fd,
    )?;
    sandbox.command.arg(path);
    Ok(())
}

fn visible(path: &Path) -> bool {
    WRITABLE
        .iter()
        .chain(SYSTEM)
        .any(|parent| path.starts_with(parent))
}

fn metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[derive(Deserialize, Serialize)]
struct Guard {
    cwd: [u64; 2],
    masked: BTreeSet<PathBuf>,
    readonly: BTreeSet<PathBuf>,
    host_mount: PathBuf,
    host_pid: PathBuf,
}

pub(crate) fn exec(args: &[std::ffi::OsString]) -> io::Result<()> {
    let plan: Guard = serde_json::from_str(
        args.first()
            .and_then(|arg| arg.to_str())
            .ok_or_else(unsupported)?,
    )?;
    let executable = args
        .get(1)
        .and_then(|arg| arg.to_str())
        .ok_or_else(unsupported)?;
    validate_executable(executable)?;
    if rustix::process::geteuid().is_root()
        || fs::read_link("/proc/self/ns/mnt")? == plan.host_mount
        || fs::read_link("/proc/self/ns/pid")? == plan.host_pid
    {
        return Err(unsupported());
    }
    let cwd = fs::metadata(".")?;
    if [cwd.dev(), cwd.ino()] != plan.cwd {
        return Err(unsupported());
    }
    let status = fs::read_to_string("/proc/self/status")?;
    if !status.lines().any(|line| {
        line.strip_prefix("NoNewPrivs:")
            .is_some_and(|value| value.trim() == "1")
    }) || !status.lines().any(|line| {
        line.strip_prefix("CapEff:")
            .is_some_and(|value| value.trim() == "0000000000000000")
    }) {
        return Err(unsupported());
    }
    check_inherited_fds()?;
    let mounts = mounts()?;
    for path in &plan.masked {
        let parent = path.parent().ok_or_else(unsupported)?;
        if !mounts
            .iter()
            .any(|mount| mount.at == *path && mount.kind == "tmpfs")
            || fs::metadata(path)?.dev() == fs::metadata(parent)?.dev()
            || fs::read_dir(path)?.next().is_some()
        {
            return Err(unsupported());
        }
    }
    for path in &plan.readonly {
        if !rustix::fs::statvfs(path)?
            .f_flag
            .contains(rustix::fs::StatVfsMountFlags::RDONLY)
        {
            return Err(unsupported());
        }
    }
    Err(Command::new(executable).args(&args[2..]).exec())
}

#[derive(Debug)]
struct Mount {
    id: u64,
    device: String,
    root: PathBuf,
    at: PathBuf,
    kind: String,
}

fn mounts() -> io::Result<Vec<Mount>> {
    fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .map(|line| {
            let (before, after) = line.split_once(" - ").ok_or_else(unsupported)?;
            let mut items = before.split_ascii_whitespace();
            let id = items
                .next()
                .and_then(|id| id.parse().ok())
                .ok_or_else(unsupported)?;
            items.next().ok_or_else(unsupported)?;
            let device = items.next().ok_or_else(unsupported)?.to_owned();
            let root = path_field(items.next().ok_or_else(unsupported)?);
            let at = path_field(items.next().ok_or_else(unsupported)?);
            let kind = after
                .split_ascii_whitespace()
                .next()
                .ok_or_else(unsupported)?
                .to_owned();
            Ok(Mount {
                id,
                device,
                root,
                at,
                kind,
            })
        })
        .collect()
}

fn path_field(field: &str) -> PathBuf {
    PathBuf::from(
        field
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\"),
    )
}

fn no_mount_alias(path: &Path, mounts: &[Mount]) -> io::Result<()> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?;
    let id = info
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:")?.trim().parse::<u64>().ok())
        .ok_or_else(unsupported)?;
    let origin = mounts
        .iter()
        .find(|mount| mount.id == id)
        .ok_or_else(unsupported)?;
    let internal = origin
        .root
        .join(path.strip_prefix(&origin.at).map_err(io::Error::other)?);
    for candidate in mounts.iter().filter(|mount| mount.device == origin.device) {
        let alias = if let Ok(relative) = internal.strip_prefix(&candidate.root) {
            candidate.at.join(relative)
        } else if candidate.root.starts_with(&internal) {
            candidate.at.clone()
        } else {
            continue;
        };
        if alias != path && visible(&alias) {
            return Err(io::Error::other("A visible mount aliases protected state"));
        }
    }
    Ok(())
}
