//! Explicit, operator-configured Cloudflare Tunnel lifecycle support.
//! Never installs external packages, prompts for login, issues ephemeral
//! trycloudflare hostnames, or leaks credentials to stdout/stderr/audit.

use std::net::SocketAddrV4;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use rustix::fs::{FileType, OFlags};
use rustix::process::{Pid, Signal, kill_process};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::{Child, Command, Stdio};

use mcp_gateway::security::linux_fs::{open_operator_dir, reopen_regular};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub hostname: String,
    pub tunnel: String,
    pub credentials_file: PathBuf,
    #[serde(default)]
    pub config_file: Option<PathBuf>,
    #[serde(default)]
    pub binary: Option<PathBuf>,
}

fn valid_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with(".trycloudflare.com")
        && !host.ends_with(".ts.net")
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').count() >= 2
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn valid_tunnel_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn validate_private_file(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(format!("Cloudflare {label} must be an absolute normalized path"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("Cloudflare {label} missing parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| format!("Cloudflare {label} missing filename"))?;
    let dir = open_operator_dir(parent)
        .map_err(|_| format!("Cloudflare {label} parent directory is unsafe or unavailable"))?;
    let dir_meta = rustix::fs::fstat(&dir)
        .map_err(|_| format!("Cannot inspect Cloudflare {label} directory"))?;
    let uid = rustix::process::geteuid().as_raw();
    if dir_meta.st_uid != uid || dir_meta.st_mode & 0o022 != 0 {
        return Err(format!(
            "Cloudflare {label} directory must be owned by your user and not writable by others"
        ));
    }
    let handle = rustix::fs::openat(
        &dir,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| format!("Cloudflare {label} unavailable or is a symlink"))?;
    let stat = rustix::fs::fstat(&handle)
        .map_err(|_| format!("Cannot inspect Cloudflare {label}"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(format!(
            "Cloudflare {label} must be an owner-controlled private regular file"
        ));
    }
    drop(reopen_regular(handle, OFlags::RDONLY).map_err(|_| format!("Cloudflare {label} unreadable"))?);
    path.canonicalize()
        .map_err(|_| format!("Cloudflare {label} unavailable"))
}

fn resolve_binary(explicit: Option<&Path>) -> Result<PathBuf, String> {
    let uid = rustix::process::geteuid().as_raw();
    let check_exec = |candidate: &Path| -> Result<PathBuf, String> {
        if !candidate.is_absolute()
            || candidate
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err("Cloudflare binary path must be absolute".into());
        }
        let meta = std::fs::symlink_metadata(candidate)
            .map_err(|_| "Configured cloudflared executable does not exist".to_owned())?;
        if !meta.file_type().is_file() {
            return Err("Configured cloudflared executable must be a regular non-symlink binary".into());
        }
        if (meta.uid() != 0 && meta.uid() != uid) || meta.mode() & 0o022 != 0 || meta.permissions().mode() & 0o111 == 0 {
            return Err("Cloudflare binary permissions or ownership are unsafe".into());
        }
        Ok(candidate.to_path_buf())
    };
    if let Some(path) = explicit {
        return check_exec(path);
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for entry in std::env::split_paths(&path_var) {
        if !entry.is_absolute() {
            continue;
        }
        let candidate = entry.join("cloudflared");
        if candidate.exists() {
            return check_exec(&candidate);
        }
    }
    Err("Cloudflare tunnel requires an installed cloudflared executable or explicit binary path; no packages were installed".into())
}

impl Settings {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let mut parsed: Self = serde_json::from_value(value.clone())
            .map_err(|_| "Invalid cloudflare_tunnel configuration")?;
        if !valid_hostname(&parsed.hostname) {
            return Err(
                "Cloudflare tunnel requires a valid stable custom hostname (ephemeral trycloudflare.com hosts are refused)"
                    .into(),
            );
        }
        if !valid_tunnel_name(&parsed.tunnel) {
            return Err("Cloudflare tunnel name or ID is invalid".into());
        }
        parsed.hostname = parsed.hostname.trim_end_matches('.').to_ascii_lowercase();
        parsed.credentials_file =
            validate_private_file(&parsed.credentials_file, "credentials_file")?;
        if let Some(cfg) = &parsed.config_file {
            parsed.config_file = Some(validate_private_file(cfg, "config_file")?);
        }
        Ok(parsed)
    }

    pub fn origin(&self) -> String {
        format!("https://{}", self.hostname)
    }

    pub fn validate_ready(&self) -> Result<PathBuf, String> {
        validate_private_file(&self.credentials_file, "credentials_file")?;
        if let Some(cfg) = &self.config_file {
            validate_private_file(cfg, "config_file")?;
        }
        resolve_binary(self.binary.as_deref())
    }
}

pub(crate) struct OwnedTunnel {
    child: Child,
    config_file: Option<PathBuf>,
}

impl OwnedTunnel {
    pub async fn start(
        settings: &Settings,
        runtime_dir: &Path,
        target: SocketAddrV4,
    ) -> Result<Self, String> {
        let bin = settings.validate_ready()?;
        let runtime_config = if let Some(cfg) = &settings.config_file {
            cfg.clone()
        } else {
            let path = runtime_dir.join(".cloudflared-runtime.yml");
            let creds = settings
                .credentials_file
                .to_str()
                .ok_or("Invalid credentials file path")?;
            let rendered = format!(
                "tunnel: {}\ncredentials-file: {}\ningress:\n  - hostname: {}\n    service: http://{}\n  - service: http_status:404\n",
                settings.tunnel, creds, settings.hostname, target
            );
            std::fs::write(&path, rendered.as_bytes())
                .map_err(|_| "Cannot write Cloudflare runtime configuration")?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "Cannot secure Cloudflare runtime configuration")?;
            path
        };

        let mut command = Command::new(&bin);
        command
            .arg("tunnel")
            .arg("--no-autoupdate")
            .arg("--config")
            .arg(&runtime_config)
            .arg("run")
            .arg("--credentials-file")
            .arg(&settings.credentials_file)
            .arg(&settings.tunnel)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|_| "Failed to start configured cloudflared tunnel process")?;
        Ok(Self {
            child,
            config_file: settings.config_file.is_none().then_some(runtime_config),
        })
    }

    pub async fn exited(&mut self) -> Option<i32> {
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.code().or(Some(1)),
                Ok(None) => tokio::time::sleep(Duration::from_millis(250)).await,
                Err(_) => return Some(1),
            }
        }
    }

    pub async fn stop(mut self) -> Result<(), String> {
        if let Some(raw_pid) = Pid::from_raw(self.child.id() as i32) {
            let _ = kill_process(raw_pid, Signal::TERM);
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if std::time::Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    _ => {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        break;
                    }
                }
            }
        }
        if let Some(path) = self.config_file.take() {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }
}

impl Drop for OwnedTunnel {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(path) = self.config_file.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}
