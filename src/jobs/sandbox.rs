//! One-shot, unprivileged Linux job confinement using Bubblewrap.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Seek, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::dup;

use super::config::RootIdentity;

const BWRAP: &str = "/usr/bin/bwrap";
const BIN: &str = "/usr/bin";
const LIB: &str = "/usr/lib";

pub(super) struct Sandbox {
    pub command: Command,
    passed: Vec<OwnedFd>,
}

impl Sandbox {
    fn new() -> io::Result<Self> {
        Self::profile(false, false)
    }

    pub(super) fn broad(network: bool) -> io::Result<Self> {
        Self::profile(true, network)
    }

    fn profile(broad: bool, network: bool) -> io::Result<Self> {
        if !cfg!(target_arch = "x86_64") || rustix::process::geteuid().is_root() {
            return Err(unsupported());
        }
        let metadata = fs::symlink_metadata(BWRAP)?;
        if !metadata.is_file()
            || !trusted_owner(&metadata)?
            || metadata.permissions().mode() & 0o6022 != 0
        {
            return Err(unsupported());
        }

        let mut result = Self {
            command: Command::new(BWRAP),
            passed: Vec::new(),
        };
        result.command.env_clear().args([
            "--unshare-user",
            "--disable-userns",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LC_ALL",
            "C",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]);
        if !network {
            result.command.arg("--unshare-net");
        }
        if broad {
            result
                .command
                .arg("--new-session")
                .arg("--assert-userns-disabled");
        }
        if !broad {
            result.command.args([
                "--ro-bind",
                BIN,
                BIN,
                "--ro-bind",
                LIB,
                LIB,
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--dir",
                "/tmp",
            ]);
        }
        if broad {
            result.command.args([
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
            ]);
        }
        let lib64 = Path::new("/usr/lib64");
        if lib64.is_dir() && lib64.canonicalize()? != Path::new(LIB) {
            if !broad {
                result
                    .command
                    .args(["--ro-bind", "/usr/lib64", "/usr/lib64"]);
            }
            result.command.args(["--symlink", "usr/lib64", "/lib64"]);
        } else {
            result.command.args(["--symlink", "usr/lib", "/lib64"]);
        }
        let filter = filter(network)?;
        result.pass("--seccomp", &filter)?;
        Ok(result)
    }

    pub(super) fn pass(&mut self, option: &str, handle: impl AsFd) -> io::Result<()> {
        // The worker is single-threaded and performs one spawn. Only these
        // explicitly selected descriptors cross exec, and bwrap consumes them.
        let fd = dup(handle)?;
        self.command.arg(option).arg(fd.as_raw_fd().to_string());
        self.passed.push(fd);
        Ok(())
    }

    pub(super) fn for_job(
        root: &RootIdentity,
        cwd: &OwnedFd,
        others: &[RootIdentity],
        executable: &str,
        args: &[String],
    ) -> io::Result<Self> {
        validate_executable(executable)?;
        let mut sandbox = Self::new()?;
        sandbox.mount(root, cwd)?;
        for candidate in others {
            sandbox.mount(candidate, &candidate.handle()?)?;
        }
        sandbox.command.arg("--chdir").arg(root.path());
        sandbox
            .command
            .args([OsStr::new("--"), OsStr::new(executable)])
            .args(args);
        Ok(sandbox)
    }

    fn mount(&mut self, root: &RootIdentity, handle: &OwnedFd) -> io::Result<()> {
        let path = root.path();
        let reserved = [
            "/usr", "/lib", "/lib64", "/bin", "/proc", "/dev", "/etc", "/sys", "/run",
        ];
        if reserved
            .iter()
            .any(|reserved| path.starts_with(reserved) || Path::new(reserved).starts_with(path))
            || path == Path::new("/tmp")
        {
            return Err(unsupported());
        }
        no_nested_mount(path)?;
        self.pass("--bind-fd", handle)?;
        self.command.arg(path);
        Ok(())
    }
}

/// Every gateway-owned descriptor beyond stdio must be close-on-exec.
/// An inherited, unnamed descriptor cannot be made safe by a mount namespace.
pub(super) fn check_inherited_fds() -> io::Result<()> {
    let cloexec = u64::from(rustix::fs::OFlags::CLOEXEC.bits());
    for entry in fs::read_dir("/proc/self/fd")? {
        let fd = entry?.file_name();
        if fd
            .to_str()
            .and_then(|fd| fd.parse::<u32>().ok())
            .is_none_or(|fd| fd < 3)
        {
            continue;
        }
        let contents = match fs::read_to_string(Path::new("/proc/self/fdinfo").join(&fd)) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let flags = contents
            .lines()
            .find_map(|line| u64::from_str_radix(line.strip_prefix("flags:")?.trim(), 8).ok())
            .ok_or_else(unsupported)?;
        if flags & cloexec == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "inherited non-CLOEXEC file descriptor",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_executable(executable: &str) -> io::Result<()> {
    if !Path::new(executable).starts_with(BIN) {
        return Err(unsupported());
    }
    Ok(())
}

fn trusted_owner(metadata: &fs::Metadata) -> io::Result<bool> {
    if metadata.uid() == 0 {
        return Ok(true);
    }
    // A nested, unprivileged verifier sees host root as the overflow UID.
    // Permit that mapping only when the launcher is on a read-only mount.
    let overflow_uid: u32 = fs::read_to_string("/proc/sys/kernel/overflowuid")?
        .trim()
        .parse()
        .map_err(|_| unsupported())?;
    Ok(metadata.uid() == overflow_uid
        && rustix::fs::statvfs(BWRAP)?
            .f_flag
            .contains(rustix::fs::StatVfsMountFlags::RDONLY)
        && fs::read_to_string("/proc/self/uid_map")?
            .lines()
            .all(|range| {
                range
                    .split_ascii_whitespace()
                    .next()
                    .is_some_and(|start| start != "0")
            }))
}

/// Recursive bind mounts can expose nested host mounts. Only simple host
/// workspace trees are supported. Changing host mounts requires separate trust.
fn no_nested_mount(root: &Path) -> io::Result<()> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    for line in mountinfo.lines() {
        let mount = line
            .split_ascii_whitespace()
            .nth(4)
            .ok_or_else(unsupported)?;
        let mount = mount
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        let mount = Path::new(&mount);
        if mount != root && mount.starts_with(root) {
            return Err(unsupported());
        }
    }
    Ok(())
}

/// Check the whole workspace with descriptor-relative traversal. Existing
/// hardlinks and special files can otherwise bypass the mount boundary.
/// Outside concurrent same-UID mutations remain outside the threat model.
pub(super) fn verify_oauth_workspace(root:&OwnedFd)->io::Result<()> {
    use rustix::fs::{self,Dir,Mode,OFlags,ResolveFlags,FileType};
    use std::time::{Instant,Duration};
    fn walk(dir:&OwnedFd,depth:usize,remaining:&mut usize,deadline:Instant)->io::Result<()> {
        if depth>64{return Err(unsupported());}
        for entry in Dir::read_from(dir)? {
            let entry=entry?;
            let name=entry.file_name();
            if matches!(name.to_bytes(),b"."|b".."){continue;}
            if *remaining==0 || Instant::now()>=deadline{return Err(unsupported());}
            *remaining-=1;
            let fd=fs::openat2(dir,name,OFlags::PATH|OFlags::NOFOLLOW|OFlags::CLOEXEC,
                Mode::empty(),ResolveFlags::BENEATH|ResolveFlags::NO_XDEV|ResolveFlags::NO_MAGICLINKS)?;
            let stat=fs::fstat(&fd)?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::RegularFile if stat.st_nlink==1=>{},
                FileType::Symlink=>{},
                FileType::Directory=>{
                    let child=fs::openat2(dir,name,OFlags::RDONLY|OFlags::DIRECTORY|OFlags::NOFOLLOW|OFlags::CLOEXEC,
                        Mode::empty(),ResolveFlags::BENEATH|ResolveFlags::NO_XDEV|ResolveFlags::NO_SYMLINKS)?;
                    let current=fs::fstat(&child)?;
                    if (stat.st_dev,stat.st_ino)!=(current.st_dev,current.st_ino){return Err(unsupported());}
                    walk(&child,depth+1,remaining,deadline)?;
                }
                _=>return Err(unsupported())
            }
        }
        Ok(())
    }
    walk(root,0,&mut 16384,Instant::now()+Duration::from_secs(2))
}

/// Filter x86_64 syscall numbers, including the x32 ABI bit. A private network
/// namespace alone leaves filesystem Unix sockets available through bind mounts.
fn filter(network: bool) -> io::Result<File> {
    const ARCH_X86_64: u32 = 0xc000_003e;
    const KILL: u32 = 0x8000_0000;
    const DENY: u32 = 0x0005_0001; // EPERM
    const ALLOW: u32 = 0x7fff_0000;
    let mut file = File::from(memfd_create("mcp-job-seccomp", MemfdFlags::CLOEXEC)?);
    let mut emit = |code: u16, yes: u8, no: u8, operand: u32| -> io::Result<()> {
        file.write_all(&code.to_ne_bytes())?;
        file.write_all(&[yes, no])?;
        file.write_all(&operand.to_ne_bytes())
    };
    emit(0x20, 0, 0, 4)?; // seccomp_data.arch
    emit(0x15, 1, 0, ARCH_X86_64)?;
    emit(0x06, 0, 0, KILL)?;
    emit(0x20, 0, 0, 0)?; // seccomp_data.nr
    emit(0x35, 0, 1, 0x4000_0000)?;
    emit(0x06, 0, 0, KILL)?;
    if network {
        // TCP, UDP and DNS are permitted. AF_UNIX is kept isolated from
        // both pathname and abstract host sockets even on the host netns.
        emit(0x15, 0, 4, 41)?;
        emit(0x20, 0, 0, 16)?; // socket domain (argument 0)
        emit(0x15, 0, 1, 1)?; // AF_UNIX
        emit(0x06, 0, 0, DENY)?;
        emit(0x06, 0, 0, ALLOW)?;
    }
    for syscall in (if network {
        &[304, 425][..]
    } else {
        &[41, 304, 425][..]
    })
    .iter()
    .copied()
    {
        // socket, open_by_handle_at, io_uring_setup
        emit(0x15, 0, 1, syscall)?;
        emit(0x06, 0, 0, DENY)?;
    }
    emit(0x06, 0, 0, ALLOW)?;
    file.rewind()?;
    Ok(file)
}

pub(crate) fn probe() -> io::Result<()> {
    // Descriptor passing deliberately uses non-CLOEXEC duplicates. Never
    // create them in the concurrent HTTP gateway, even for a no-op probe.
    let mut command = Command::new("/proc/self/exe");
    command.env_clear().arg("--job-sandbox-probe");
    let (status, _) =
        crate::linux_command::capture(&mut command, 256, std::time::Duration::from_secs(3))?;
    if status.success() {
        Ok(())
    } else {
        Err(unsupported())
    }
}

pub(crate) fn probe_worker() -> io::Result<()> {
    check_inherited_fds()?;
    rustix::thread::set_no_new_privs(true)?;
    let mut sandbox = Sandbox::new()?;
    let root = super::config::JobRoot::open(&std::env::current_dir()?).map_err(io::Error::other)?;
    let root = root.identity();
    // The profile needs directory-fd binds in addition to namespaces and
    // seccomp. Bind a read-only runtime directory onto a disposable target.
    sandbox.pass("--ro-bind-fd", root.handle()?)?;
    sandbox.command.arg("/mnt").args(["--", "/usr/bin/true"]);
    let status = sandbox
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

pub(super) fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "required Linux execution isolation unavailable",
    )
}

/// The upstream worker is a separate single-threaded process. It can pass
/// selected read-only input descriptors without leaking them to other jobs.
pub(crate) fn upstream_worker(args: &[std::ffi::OsString]) -> io::Result<()> {
    use mcp_gateway::security::linux_fs::open_absolute_dir;
    use rustix::fs::{self as fd_fs, FileType, Mode, OFlags};
    use std::os::unix::process::CommandExt;

    fn open_source(path: &Path) -> io::Result<OwnedFd> {
        let dir = open_absolute_dir(path.parent().ok_or_else(unsupported)?)?;
        let file = fd_fs::openat(
            &dir,
            path.file_name().ok_or_else(unsupported)?,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let metadata = fd_fs::fstat(&file)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_nlink != 1
            || metadata.st_mode & 0o6022 != 0
            || ![0, rustix::process::geteuid().as_raw()].contains(&metadata.st_uid)
        {
            return Err(unsupported());
        }
        Ok(file)
    }

    let (bundle, args) = if args.first().is_some_and(|v| v == "--runtime-bundle") {
        let path = Path::new(args.get(1).ok_or_else(unsupported)?);
        let parent = path.parent().ok_or_else(unsupported)?;
        let id = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(unsupported)?;
        if parent.file_name() != Some(OsStr::new("upstream-bundles"))
            || !crate::upstream::server_name(id)
        {
            return Err(unsupported());
        }
        let state = open_absolute_dir(parent.parent().ok_or_else(unsupported)?)?;
        let anchored = mcp_gateway::security::linux_fs::open_beneath_dir(
            &state,
            &Path::new("upstream-bundles").join(id),
        )?;
        let layout = crate::state_cli::Layout::inspect_bundle(path).map_err(io::Error::other)?;
        layout.validate_links().map_err(io::Error::other)?;
        let handle = layout.into_root();
        let (a, b) = (fd_fs::fstat(&anchored)?, fd_fs::fstat(&handle)?);
        if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) {
            return Err(unsupported());
        }
        (Some(handle), &args[2..])
    } else {
        (None, args)
    };
    let (workspace, args) = if args.first().is_some_and(|v| v == "--workspace-input") {
        if bundle.is_none() || args.len() < 7 {
            return Err(unsupported());
        }
        (Some(&args[1..6]), &args[6..])
    } else {
        (None, args)
    };
    let (program, args) = args.split_first().ok_or_else(unsupported)?;
    let program = Path::new(program);
    let canonical = program.canonicalize()?;
    check_inherited_fds()?;
    rustix::thread::set_no_new_privs(true)?;
    let mut sandbox = Sandbox::new()?;
    sandbox.command.args([
        "--new-session",
        "--chdir",
        "/tmp",
        "--setenv",
        "HOME",
        "/tmp",
    ]);
    let has_bundle = bundle.is_some();
    if let Some(bundle) = bundle {
        sandbox.pass("--ro-bind-fd", bundle)?;
        sandbox.command.arg("/upstream/bundle");
    }
    if let Some(workspace) = workspace {
        super::upstream_workspace::mount(&mut sandbox, workspace)?;
    }
    let executable = if canonical.starts_with(BIN) {
        canonical.as_os_str()
    } else {
        if program != canonical {
            return Err(unsupported());
        }
        sandbox.pass("--ro-bind-fd", open_source(program)?)?;
        sandbox.command.arg("/upstream/server");
        OsStr::new("/upstream/server")
    };
    let mut args = args.to_vec();
    if canonical
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.starts_with("python"))
        && let Some(script) = args.first_mut()
        && Path::new(script).is_absolute()
        && Path::new(script).extension() == Some(OsStr::new("py"))
        && !(has_bundle && Path::new(script).starts_with("/upstream/bundle"))
    {
        sandbox.pass("--ro-bind-fd", open_source(Path::new(script))?)?;
        sandbox.command.arg("/upstream/server.py");
        *script = "/upstream/server.py".into();
    }
    sandbox.command.arg("--").arg(executable).args(args);
    Err(sandbox.command.exec())
}

pub(crate) fn git_worker(args: &[std::ffi::OsString]) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let [operation, path] = args else {
        return Err(unsupported());
    };
    let params: &[&str] = match operation.to_str() {
        Some("info") => &["rev-parse", "--is-inside-work-tree", "--abbrev-ref", "HEAD"],
        Some("status") => &[
            "status",
            "--porcelain=v1",
            "--branch",
            "--untracked-files=normal",
        ],
        Some("diff") => &["diff", "--no-ext-diff", "--no-textconv", "HEAD", "--"],
        Some("history") => &["log", "-n", "24", "--format=%H%x09%aI%x09%s", "--"],
        _ => return Err(unsupported()),
    };
    check_inherited_fds()?;
    rustix::thread::set_no_new_privs(true)?;
    let mut sandbox = Sandbox::new()?;
    let directory = mcp_gateway::security::linux_fs::open_absolute_dir(Path::new(path))?;
    sandbox.pass("--ro-bind-fd", directory)?;
    sandbox
        .command
        .args([
            "/repo",
            "--new-session",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--setenv",
            "GIT_CONFIG_GLOBAL",
            "/dev/null",
            "--",
            "/usr/bin/git",
            "--no-pager",
            "--no-optional-locks",
            "-C",
            "/repo",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(params);
    Err(sandbox.command.exec())
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct GitToolRequest {
    pub repo: std::path::PathBuf,
    pub argv: Vec<String>,
    pub readonly: bool,
    pub network: bool,
    pub native: bool,
}

pub(crate) fn git_tool_worker() -> io::Result<()> {
    use std::io::Read;
    use std::time::Duration;
    check_inherited_fds()?;
    rustix::thread::set_no_new_privs(true)?;
    let mut input = Vec::new();
    io::stdin().lock().take(32_769).read_to_end(&mut input)?;
    if input.len() > 32_768 {
        return Err(unsupported());
    }
    let request: GitToolRequest = serde_json::from_slice(&input).map_err(|_| unsupported())?;
    if request.argv.is_empty()
        || request.argv.len() > 128
        || request.argv.iter().any(|arg| arg.contains('\0'))
        || !request.repo.is_absolute()
    {
        return Err(unsupported());
    }
    let mut hardened: Vec<String> = [
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "submodule.recurse=false",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.fd.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "user.name=Veyl",
        "-c",
        "user.email=veyl@localhost",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    hardened.extend(request.argv);

    let (status, stdout, stderr) = if request.native {
        let mut cmd = Command::new("/usr/bin/git");
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", "/tmp")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "Veyl")
            .env("GIT_AUTHOR_EMAIL", "veyl@localhost")
            .env("GIT_COMMITTER_NAME", "Veyl")
            .env("GIT_COMMITTER_EMAIL", "veyl@localhost")
            .arg("-C")
            .arg(&request.repo)
            .args(&hardened);
        crate::linux_command::capture_with_input(&mut cmd, &[], 131_072, Duration::from_secs(15))?
    } else {
        let mut sandbox = Sandbox::new()?;
        let dir = mcp_gateway::security::linux_fs::open_absolute_dir(&request.repo)?;
        sandbox.pass(
            if request.readonly {
                "--ro-bind-fd"
            } else {
                "--bind-fd"
            },
            &dir,
        )?;
        sandbox.command.arg("/repo");
        if request.repo.join(".git/hooks").is_dir() {
            sandbox.command.args(["--tmpfs", "/repo/.git/hooks"]);
        }
        if request.readonly && request.repo.join(".git/config").is_file() {
            let mut empty = File::from(memfd_create("git-empty-cfg", MemfdFlags::CLOEXEC)?);
            empty.write_all(b"[core]\nrepositoryformatversion = 0\nbare = false\n")?;
            empty.rewind()?;
            sandbox.pass("--ro-bind-data", &empty)?;
            sandbox.command.arg("/repo/.git/config");
        }
        sandbox
            .command
            .args([
                "--new-session",
                "--setenv",
                "HOME",
                "/tmp",
                "--setenv",
                "GIT_CONFIG_NOSYSTEM",
                "1",
                "--setenv",
                "GIT_CONFIG_GLOBAL",
                "/dev/null",
                "--setenv",
                "GIT_ALLOW_PROTOCOL",
                "",
                "--setenv",
                "GIT_TERMINAL_PROMPT",
                "0",
                "--setenv",
                "GIT_AUTHOR_NAME",
                "Veyl",
                "--setenv",
                "GIT_AUTHOR_EMAIL",
                "veyl@localhost",
                "--setenv",
                "GIT_COMMITTER_NAME",
                "Veyl",
                "--setenv",
                "GIT_COMMITTER_EMAIL",
                "veyl@localhost",
                "--",
                "/usr/bin/git",
                "-C",
                "/repo",
            ])
            .args(&hardened);
        let (status, out, err) = crate::linux_command::capture_with_input(
            &mut sandbox.command,
            &[],
            131_072,
            Duration::from_secs(15),
        )?;
        drop(sandbox);
        (status, out, err)
    };
    let payload = serde_json::json!({
        "exit_code": status.code().unwrap_or(1),
        "stdout": String::from_utf8_lossy(&stdout),
        "stderr": String::from_utf8_lossy(&stderr),
    });
    println!("{payload}");
    Ok(())
}
