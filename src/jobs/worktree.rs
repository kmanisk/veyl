//! Private, disposable Git worktrees for task execution.

use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use mcp_gateway::security::linux_fs::open_operator_dir;

use super::{invalid, process};

fn git(repo: &Path, args: &[&std::ffi::OsStr], output: bool) -> io::Result<Vec<u8>> {
    let mut child = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "submodule.recurse=false",
            "-c",
            "protocol.file.allow=never",
            "-C",
        ])
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .stdout(if output {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(invalid());
            }
            let mut bytes = Vec::new();
            if let Some(stdout) = child.stdout.take() {
                stdout.take(4097).read_to_end(&mut bytes)?;
            }
            if bytes.len() > 4096 {
                return Err(invalid());
            }
            return Ok(bytes);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "Git operation timed out",
            ));
        }
        thread::sleep(process::TICK);
    }
}

pub(super) fn repository(cwd: &Path) -> io::Result<PathBuf> {
    let bytes = git(
        cwd,
        &["rev-parse".as_ref(), "--show-toplevel".as_ref()],
        true,
    )
    .map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "Working directory is not a Git repository",
        )
    })?;
    let name = std::str::from_utf8(&bytes)
        .map_err(|_| invalid())?
        .trim_end_matches('\n');
    let path = fs::canonicalize(name).map_err(|_| invalid())?;
    git(
        &path,
        &[
            "rev-parse".as_ref(),
            "--verify".as_ref(),
            "HEAD^{commit}".as_ref(),
        ],
        false,
    )
    .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Git repository has no HEAD commit"))?;
    Ok(path)
}

fn base() -> io::Result<PathBuf> {
    let path = PathBuf::from(format!(
        "/tmp/veyl-worktrees-{}",
        rustix::process::geteuid().as_raw()
    ));
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => (),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let file = File::from(open_operator_dir(&path)?);
    let meta = file.metadata()?;
    if meta.uid() != rustix::process::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
        return Err(invalid());
    }
    Ok(path)
}

pub(super) struct Worktree {
    pub repo: PathBuf,
    pub path: PathBuf,
    armed: bool,
}
impl Worktree {
    pub fn create(repo: &Path, id: &str) -> io::Result<Self> {
        let path = base()?.join(id);
        if path.try_exists()? {
            return Err(io::Error::from(ErrorKind::AlreadyExists));
        }
        let worktree = Self {
            repo: repo.to_owned(),
            path,
            armed: true,
        };
        git(
            repo,
            &[
                "worktree".as_ref(),
                "add".as_ref(),
                "--detach".as_ref(),
                worktree.path.as_os_str(),
                "HEAD".as_ref(),
            ],
            false,
        )?;
        Ok(worktree)
    }
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for Worktree {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove(&self.repo, &self.path);
        }
    }
}
pub(super) fn remove(repo: &Path, path: &Path) -> io::Result<()> {
    let base = base()?;
    if path.parent() != Some(base.as_path())
        || !path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(super::store::valid_id)
    {
        return Err(invalid());
    }
    let _ = git(
        repo,
        &[
            "worktree".as_ref(),
            "remove".as_ref(),
            "--force".as_ref(),
            path.as_os_str(),
        ],
        false,
    );
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    git(repo, &["worktree".as_ref(), "prune".as_ref()], false)?;
    Ok(())
}
