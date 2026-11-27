//! Explicit, per-client upstream access to selected read-only workspace inputs.
use std::io;
use std::path::{Component, Path, PathBuf};

use mcp_gateway::security::durable_id::DurableObjectId;
use mcp_gateway::security::linux_fs::{open_absolute_dir, open_beneath_dir};
use rustix::fs;
use serde_json::Value;

use crate::http::admission::{Client, Configuration};
use crate::protected_paths::{self, Kind};
use mcp_gateway::security::policy::{Action, ExecutionMode};

pub(super) struct Grant {
    pub root: PathBuf,
    pub identity: [u64; 2],
    pub durable: Option<DurableObjectId>,
    pub provider_only: bool,
}

pub(super) struct Input {
    pub root: PathBuf,
    pub identity: [u64; 2],
    pub relative: PathBuf,
    pub tree: bool,
}

fn visible(path: &Path) -> bool {
    path.components().all(|c| match c {
        Component::RootDir => true,
        Component::Normal(name) => name
            .to_str()
            .is_some_and(|n| !n.starts_with('.') && !n.chars().any(char::is_control)),
        _ => false,
    })
}

fn identity(fd: &rustix::fd::OwnedFd) -> io::Result<[u64; 2]> {
    let st = fs::fstat(fd)?;
    Ok([st.st_dev, st.st_ino])
}

impl Grant {
    pub fn parse(raw: &Value) -> Result<Self, String> {
        let (path, pinned) = if let Some(path) = raw.as_str() {
            (path, None)
        } else {
            let object = raw
                .as_object()
                .ok_or("Expected an upstream workspace grant")?;
            if !matches!(object.len(), 3 | 4) {
                return Err("Invalid provider-only workspace grant".into());
            }
            let path = object
                .get("root")
                .and_then(Value::as_str)
                .ok_or("Missing workspace root")?;
            let device = object
                .get("device")
                .and_then(Value::as_u64)
                .ok_or("Missing workspace device")?;
            let inode = object
                .get("inode")
                .and_then(Value::as_u64)
                .filter(|i| *i != 0)
                .ok_or("Missing workspace inode")?;
            let durable = match object.get("durable") {
                Some(raw_durable) => {
                    let parsed: DurableObjectId = serde_json::from_value(raw_durable.clone())
                        .map_err(|_| "Invalid workspace durable identity")?;
                    if !parsed.is_valid() || parsed.inode != inode {
                        return Err("Invalid workspace durable identity".into());
                    }
                    Some(parsed)
                }
                None if object.len() == 3 => None,
                None => return Err("Invalid provider-only workspace grant".into()),
            };
            (path, Some(([device, inode], durable)))
        };
        let root = PathBuf::from(path);
        protected_paths::validate_path(&root)?;
        if !visible(&root) {
            return Err("Hidden upstream workspace roots are not supported".into());
        }
        // Explicit folder grants persist the approved inode. A moved or missing
        // folder must deny its calls, not make the entire policy unmanageable.
        if let Some((identity, durable)) = pinned {
            return Ok(Self {
                root,
                identity,
                durable,
                provider_only: true,
            });
        }
        crate::jobs::broad::check_workspace_mount(&root)
            .map_err(|_| "Upstream workspace mount is unsafe")?;
        let fd = open_absolute_dir(&root).map_err(|_| "Upstream workspace root unavailable")?;
        let st = fs::fstat(&fd).map_err(|_| "Upstream workspace identity unavailable")?;
        if st.st_uid != rustix::process::geteuid().as_raw() || st.st_mode & 0o7022 != 0 {
            return Err("Expected an operator-owned upstream workspace directory".into());
        }
        let identity = [st.st_dev, st.st_ino];
        let durable = DurableObjectId::probe(&fd, &st)
            .map_err(|_| "Upstream workspace identity unavailable")?;
        Ok(Self {
            root,
            identity,
            durable: Some(durable),
            provider_only: false,
        })
    }

    pub fn validate(
        &self,
        config: &Path,
        settings: &Configuration,
        client: &Client,
    ) -> Result<(), String> {
        let overlaps = |p: &Path| self.root.starts_with(p) || p.starts_with(&self.root);
        if !client.actions.contains(&Action::ReadFile)
            || protected_paths::is_mandatory(config, settings, &self.root)
            || (settings.managed && config.parent().is_some_and(overlaps))
            || config
                .parent()
                .is_some_and(|p| overlaps(&p.join("upstream-bundles")))
            || std::env::var_os("HOME").is_some_and(|home| Path::new(&home).starts_with(&self.root))
            || settings
                .runtime_settings
                .get("skills_dir")
                .and_then(Value::as_str)
                .is_some_and(|p| overlaps(Path::new(p)))
            || [Kind::Optional, Kind::ReadOnly].iter().any(|kind| {
                settings
                    .protected_paths
                    .selected(*kind)
                    .iter()
                    .any(|r| overlaps(&r.path))
            })
        {
            return Err(
                "Upstream workspace overlaps protected state or lacks a native read grant".into(),
            );
        }
        // Provider-only grants are explicit operator delegation, not native scope changes.
        // The operator-approved read-only scope is separate from execution mode.
        if self.provider_only {
            if !settings.managed
                || !client.actions.contains(&Action::CallUpstream)
                || settings.clients.iter().any(|other| {
                    other.id != client.id && other.root != client.root && overlaps(&other.root)
                })
            {
                return Err("Provider-only folders require managed policy and must not overlap another client's distinct workspace".into());
            }
            return Ok(());
        }
        // An explicit provider grant can only narrow an already approved client root.
        // No implicit broad-YOLO or FULL filesystem delegation to third-party code.
        let extra_allowed = client.explicit_extra_roots
            || client.mode == ExecutionMode::Yolo;
        let anchor = client
            .mutation_root
            .iter()
            .chain(client.extra_roots.iter().filter(|_| extra_allowed))
            .find(|anchor| self.root.starts_with(anchor.path()))
            .ok_or("Upstream workspace must be inside an explicitly approved client root")?;
        let relative = self
            .root
            .strip_prefix(anchor.path())
            .map_err(|_| "Invalid upstream workspace root")?;
        let fd = open_beneath_dir(anchor.directory(), relative)
            .map_err(|_| "Upstream workspace crosses a mount or symlink")?;
        if identity(&fd).map_err(|_| "Upstream workspace identity unavailable")? != self.identity {
            return Err("Upstream workspace identity changed".into());
        }
        Ok(())
    }

    // Translate only the reviewed read-only input fields. Other upstream
    // tools keep their previous bundle-only isolation.
    pub fn prepare(
        &self,
        provider: &str,
        tool: &str,
        args: &mut Value,
    ) -> Result<Option<Input>, &'static str> {
        let (field, tree) = match (provider, tool) {
            ("rust-anything", "analyze") => ("root", true),
            ("rea", "inspect_python_pyc" | "inspect_rust_binary") => ("path", false),
            _ => return Ok(None),
        };
        let value = args
            .get(field)
            .and_then(Value::as_str)
            .ok_or("Expected upstream input path")?;
        if value.is_empty() || value.len() > 4096 || value.contains('\0') {
            return Err("Invalid upstream input path");
        }
        let path = Path::new(value);
        // Existing explicit bundle-relative requests continue working.
        if path.starts_with("/upstream/bundle") && visible(path) {
            return Ok(None);
        }
        let relative = if path.is_absolute() {
            path.strip_prefix(&self.root)
                .or_else(|_| path.strip_prefix("/workspace"))
                .map_err(|_| "Upstream input outside granted workspace")?
        } else if value == "." {
            Path::new("")
        } else {
            path
        };
        if !visible(relative)
            || relative.is_absolute()
            || (!tree && relative.as_os_str().is_empty())
        {
            return Err("Invalid or hidden upstream workspace path");
        }
        let relative = relative.to_owned();
        args[field] = Value::String(
            Path::new("/workspace")
                .join(&relative)
                .to_string_lossy()
                .into_owned(),
        );
        let live_identity = if self.provider_only {
            let fd = open_absolute_dir(&self.root)
                .map_err(|_| "Upstream workspace root unavailable")?;
            let st = fs::fstat(&fd).map_err(|_| "Upstream workspace identity unavailable")?;
            let matches = match &self.durable {
                Some(expected) => DurableObjectId::probe(&fd, &st)
                    .is_ok_and(|actual| expected.matches_live(&actual)),
                None => [st.st_dev, st.st_ino] == self.identity,
            };
            if !matches {
                return Err("Upstream workspace identity changed");
            }
            [st.st_dev, st.st_ino]
        } else {
            self.identity
        };
        Ok(Some(Input {
            root: self.root.clone(),
            identity: live_identity,
            relative,
            tree,
        }))
    }
}
