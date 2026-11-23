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
