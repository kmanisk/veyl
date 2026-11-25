//! Optional Linux cgroup ceilings using a transient user scope.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{invalid, random_hex};

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const CPU_PERCENT: u64 = 100;

pub(super) struct Scopes {
    executable: PathBuf,
    runtime: PathBuf,
}

impl Scopes {
    pub fn detect() -> Option<Self> {
        // Scope discovery uses only the current UID's local manager. The
        // gateway never passes an ambient D-Bus address to the helper.
        let uid = rustix::process::geteuid().as_raw();
        let runtime = PathBuf::from(format!("/run/user/{uid}"));
        if std::env::var_os("XDG_RUNTIME_DIR").as_deref() != Some(runtime.as_os_str()) {
            return None;
        }
        let manager = runtime.join("systemd/private");
        if !fs::symlink_metadata(&runtime)
            .is_ok_and(|meta| meta.is_dir() && meta.uid() == uid && meta.mode() & 0o777 == 0o700)
            || !fs::symlink_metadata(manager)
                .is_ok_and(|meta| meta.uid() == uid && meta.file_type().is_socket())
        {
            return None;
        }

        let scopes = Self {
            // Keep subsequent scope launches bound to the running gateway inode.
            executable: PathBuf::from(format!("/proc/{}/exe", std::process::id())),
            runtime,
        };
        let id = random_hex().ok()?;
        let mut probe = scopes
            .command(&id, "--job-scope-check", 2, CPU_PERCENT, MEMORY_BYTES)
            .arg(&id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let deadline = Instant::now() + Duration::from_millis(750);
        loop {
            match probe.try_wait() {
                Ok(Some(status)) => return status.success().then_some(scopes),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(15)),
                _ => {
                    let _ = probe.kill();
                    let _ = probe.wait();
                    return None;
                }
            }
        }
    }

    pub fn command(
        &self,
        id: &str,
        mode: &str,
        timeout_seconds: u64,
        cpu_percent: u64,
        memory_bytes: u64,
    ) -> Command {
        let mut command = Command::new(SYSTEMD_RUN);
        command
            .env_clear()
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .args(["--user", "--scope", "--collect", "--quiet"])
            .arg(format!("--unit={}", unit(id)))
            .arg(format!("--property=CPUQuota={cpu_percent}%"))
            .arg(format!("--property=MemoryMax={memory_bytes}"))
            // This manager-side backstop also ends the scope if its runner
            // dies. The runner normally times out and records the result first.
            .arg(format!(
                "--property=RuntimeMaxSec={}s",
                timeout_seconds + 10
            ))
            .arg("--property=TimeoutStopSec=1s")
            .arg("--")
            .arg(&self.executable)
            .arg(mode);
        command
    }
}

pub(crate) fn verify(id: &str, cpu_percent: u64, memory_bytes: u64) -> io::Result<()> {
    if !super::store::valid_id(id) {
        return Err(invalid());
    }
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let location = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .ok_or_else(invalid)?;
    let location = Path::new(location);
    if location
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
        || location.file_name().and_then(|name| name.to_str()) != Some(unit(id).as_str())
    {
        return Err(invalid());
    }
    let cgroup = Path::new("/sys/fs/cgroup").join(location);
    let memory = fs::read_to_string(cgroup.join("memory.max"))?;
    let memory: u64 = memory.trim().parse().map_err(|_| invalid())?;
    let cpu = fs::read_to_string(cgroup.join("cpu.max"))?;
    let (quota, period) = cpu.trim().split_once(' ').ok_or_else(invalid)?;
    let quota: u64 = quota.parse().map_err(|_| invalid())?;
    let period: u64 = period.parse().map_err(|_| invalid())?;
    if period == 0
        || u128::from(quota) * 100 != u128::from(period) * u128::from(cpu_percent)
        || memory != memory_bytes
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn status(enforced: bool, cpu_percent: u64, memory_bytes: u64) -> Value {
    if enforced {
        json!({"cpu_percent": cpu_percent, "memory_bytes": memory_bytes})
    } else {
        json!({"cpu": "unavailable", "memory": "unavailable"})
    }
}

fn unit(id: &str) -> String {
    format!("mcp-gateway-job-{id}.scope")
}
