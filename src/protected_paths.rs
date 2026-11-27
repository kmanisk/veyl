//! Validated operator rules for a future broad execution profile.

use std::path::{Path, PathBuf};

use mcp_gateway::security::durable_id::DurableObjectId;
use mcp_gateway::security::linux_fs::open_absolute_dir;
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::http::admission::Configuration;
use crate::http::operator::policy_path;

pub(crate) const OPTIONAL_DEFAULTS: &[&str] = &[".ssh", ".gnupg", ".codex"];
/// Managed and native gateway control-plane directories must remain isolated across modes.
pub(crate) const MANAGED_LOGIN_DIR: &str = ".veyl-login";
pub(crate) const CONTROL_PLANE_DIRS: &[&str] = &[
    MANAGED_LOGIN_DIR,
    ".local/state/veyl",
    ".local/state/mcp-gateway",
    ".config/mcp-gateway",
    ".veyl-update-backups",
];
pub(crate) const READONLY_DEFAULTS: &[&str] = &[
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".zshrc",
    ".config/systemd",
    ".config/autostart",
    ".local/bin",
    ".ssh/authorized_keys",
    ".veyl-update.lock",
];
const MAX_RULES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Optional,
    ReadOnly,
}

impl Kind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::ReadOnly => "readonly",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub(crate) path: PathBuf,
    device: u64,
    inode: u64,
    object: Object,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    durable: Option<DurableObjectId>,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Object {
    Directory,
    RegularFile,
}

impl Rule {
    pub(crate) fn inspect(path: &Path, kind: Kind) -> Result<Self, String> {
        validate_path(path)?;
        let parent = path.parent().ok_or("Missing protection parent")?;
        let name = path.file_name().ok_or("Missing protection name")?;
        let open = || {
            let parent_fd = open_absolute_dir(parent).map_err(|_| "Unsafe or unavailable parent")?;
            let parent_stat =
                fs::fstat(&parent_fd).map_err(|_| "Cannot identify protection parent")?;
            let handle = fs::openat2(
                &parent_fd,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )
            .map_err(|_| "Unsafe or unavailable protected path, including mount aliases")?;
            let stat = fs::fstat(handle).map_err(|_| "Cannot identify protected path")?;
            if stat.st_dev != parent_stat.st_dev {
                return Err("Unsafe or unavailable protected path, including mount aliases".into());
            }
            let durable = DurableObjectId::probe(&parent_fd, &stat)
                .map_err(|_| "Cannot identify protected filesystem")?;
            Ok::<_, String>((stat, durable))
        };
        let (stat, durable) = open()?;
        let object = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => Object::Directory,
            FileType::RegularFile if kind == Kind::ReadOnly && stat.st_nlink == 1 => {
                Object::RegularFile
            }
            _ => return Err("Use a directory for optional protection or a singly-linked regular file for read-only protection".into()),
        };
        let (again, again_durable) = open()?;
        if (stat.st_dev, stat.st_ino, stat.st_mode, stat.st_nlink)
            != (again.st_dev, again.st_ino, again.st_mode, again.st_nlink)
            || durable != again_durable
        {
            return Err("Protected path changed during validation".into());
        }
        Ok(Self {
            path: path.to_owned(),
            device: stat.st_dev,
            inode: stat.st_ino,
            object,
            durable: Some(durable),
        })
    }

    pub(crate) fn check_identity(&self, kind: Kind) -> Result<(), String> {
        let live = Self::inspect(&self.path, kind)?;
        if self.path != live.path || self.object != live.object {
            return Err("Protected path identity changed; review and re-add the rule".into());
        }
        let matches = match &self.durable {
            Some(expected) => live
                .durable
                .as_ref()
                .is_some_and(|actual| expected.matches_live(actual)),
            None => (self.device, self.inode) == (live.device, live.inode),
        };
        if !matches {
            return Err("Protected path identity changed; review and re-add the rule".into());
        }
        Ok(())
    }

    pub(crate) fn same_object(&self, other: &Self) -> bool {
        match (&self.durable, &other.durable) {
            (Some(a), Some(b)) => a.matches_live(b),
            _ => (self.device, self.inode) == (other.device, other.inode),
        }
    }

    pub(crate) fn migrate_legacy(&mut self, kind: Kind) -> Result<bool, String> {
        if self.durable.is_some() {
            self.check_identity(kind)?;
            return Ok(false);
        }
        let live = Self::inspect(&self.path, kind)?;
        let Some(durable) = &live.durable else {
            return Err("Protected filesystem identity unavailable".into());
        };
        if self.object != live.object
            || self.inode != live.inode
            || (!durable.fs.is_persistent() && self.device != live.device)
        {
            return Err("Legacy protected path identity changed; review and re-add the rule".into());
        }
        self.device = live.device;
        self.durable = live.durable;
        Ok(true)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rules {
    version: u8,
    optional: Vec<Rule>,
    readonly: Vec<Rule>,
}

impl Rules {
    pub(crate) fn parse(document: &Value) -> Result<Self, String> {
        let Some(raw) = document.get("protected_paths") else {
            return Ok(Self {
                version: 1,
                optional: Vec::new(),
                readonly: Vec::new(),
            });
        };
        let rules: Self =
            serde_json::from_value(raw.clone()).map_err(|_| "Invalid protected-path rules")?;
        let all: Vec<_> = rules.optional.iter().chain(&rules.readonly).collect();
        if rules.version != 1 || all.len() > MAX_RULES {
            return Err("Unsupported protected-path version or too many rules".into());
        }
        for (index, rule) in all.iter().enumerate() {
            validate_path(&rule.path)?;
            if let Some(durable) = &rule.durable
                && (!durable.is_valid() || durable.inode != rule.inode)
            {
                return Err("Conflicting or invalid protected-path rules".into());
            }
            if rule.inode == 0
                || (index < rules.optional.len() && rule.object != Object::Directory)
                || all[..index]
                    .iter()
                    .any(|other| overlaps(&rule.path, &other.path) || rule.same_object(other))
            {
                return Err("Conflicting or invalid protected-path rules".into());
            }
        }
        Ok(rules)
    }

    pub(crate) fn selected(&self, kind: Kind) -> &[Rule] {
        match kind {
            Kind::Optional => &self.optional,
            Kind::ReadOnly => &self.readonly,
        }
    }

    pub(crate) fn insert(&mut self, kind: Kind, rule: Rule) -> Result<bool, String> {
        let present = self.check_candidate(kind, &rule)?;
        if present {
            return Ok(false);
        }
        let rules = self.selected_mut(kind);
        rules.push(rule);
        rules.sort_by(|first, second| first.path.cmp(&second.path));
        Ok(true)
    }

    pub(crate) fn check_candidate(&self, kind: Kind, rule: &Rule) -> Result<bool, String> {
        let mut present = false;
        for (selected, rules) in [
            (Kind::Optional, &self.optional),
            (Kind::ReadOnly, &self.readonly),
        ] {
            for other in rules {
                if selected == kind && other == rule {
                    present = true;
                } else if overlaps(&other.path, &rule.path) || other.same_object(rule) {
                    return Err("Rule conflicts with an existing path or object identity".into());
                }
            }
        }
        if !present && self.optional.len() + self.readonly.len() >= MAX_RULES {
            return Err("Too many protected-path rules".into());
        }
        Ok(present)
    }

    pub(crate) fn remove(&mut self, kind: Kind, path: &Path) -> bool {
        let rules = self.selected_mut(kind);
        let before = rules.len();
        rules.retain(|rule| rule.path != path);
        rules.len() != before
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.optional.is_empty() && self.readonly.is_empty()
    }

    pub(crate) fn selected_mut(&mut self, kind: Kind) -> &mut Vec<Rule> {
        match kind {
            Kind::Optional => &mut self.optional,
            Kind::ReadOnly => &mut self.readonly,
        }
    }
}

pub(crate) fn validate_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        || path.to_str().is_none_or(|text| {
            text.len() > 4096
                || text.chars().any(char::is_control)
                || text.split('/').any(|segment| matches!(segment, "." | ".."))
        })
        || ["/proc", "/sys", "/dev", "/run"]
            .iter()
            .any(|location| path.starts_with(location))
    {
        return Err("Expected a canonical absolute path outside kernel and runtime trees".into());
    }
    Ok(())
}

fn is_mandatory_core(config: &Path, settings: &Configuration, path: &Path) -> bool {
    policy_path(config, path)
        || overlaps(config, path)
        || settings
            .audit_log
            .as_deref()
            .and_then(Path::parent)
            .is_some_and(|directory| overlaps(directory, path))
        || settings
            .job_state_path()
            .is_some_and(|directory| overlaps(directory, path))
}

pub(crate) fn is_mandatory(config: &Path, settings: &Configuration, path: &Path) -> bool {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .is_some_and(|home| {
            CONTROL_PLANE_DIRS
                .iter()
                .any(|dir| overlaps(&home.join(dir), path))
                || overlaps(&home.join(".veyl-update.lock"), path)
        })
        || is_mandatory_core(config, settings, path)
}

pub(crate) fn is_mandatory_for_skills(
    config: &Path,
    settings: &Configuration,
    path: &Path,
) -> bool {
    if is_mandatory_core(config, settings, path) {
        return true;
    }
    let Some(home) = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    else {
        return false;
    };
    let default_skills_dir = home.join(".local/state/veyl/skills");
    CONTROL_PLANE_DIRS.iter().any(|dir| {
        if *dir == ".local/state/veyl" && path == default_skills_dir {
            return false;
        }
        overlaps(&home.join(dir), path)
    }) || overlaps(&home.join(".veyl-update.lock"), path)
}

pub(crate) fn check_conflicts(
    config: &Path,
    settings: &Configuration,
    path: &Path,
    kind: Kind,
) -> Result<(), String> {
    if is_mandatory(config, settings, path) {
        return Err("Path overlaps mandatory gateway protection".into());
    }
    if kind == Kind::Optional
        && settings.clients.iter().any(|client| {
            client.root.starts_with(path)
                || client
                    .extra_roots
                    .iter()
                    .any(|root| root.path().starts_with(path))
        })
    {
        return Err("An optional mask cannot hide a configured client workspace".into());
    }
    Ok(())
}

fn overlaps(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::security::durable_id::DurableFs;

    #[test]
    fn protected_rule_uses_durable_identity_and_migrates_legacy() {
        let dir = std::env::temp_dir().join(format!("veyl-prot-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("secret");
        std::fs::create_dir(&target).unwrap();

        let rule = Rule::inspect(&target, Kind::Optional).unwrap();
        assert!(rule.durable.is_some());
        rule.check_identity(Kind::Optional).unwrap();

        // Simulate device renumbering on persistent FS: rule.device changed while durable stays identical.
        let persistent_rule = Rule {
            path: target.clone(),
            device: rule.device ^ 17,
            inode: rule.inode,
            object: Object::Directory,
            durable: Some(DurableObjectId {
                fs: DurableFs::Persistent {
                    fs_type: 0x9123_683e,
                    fsid: 0x1234_5678_9abc_def0,
                },
                inode: rule.inode,
            }),
        };
        if rule.durable.as_ref().unwrap().fs.is_persistent() {
            let mut renumbered = rule.clone();
            renumbered.device ^= 17;
            renumbered.check_identity(Kind::Optional).unwrap();
        }
        // Snapshot subvolume / mismatched fsid must fail closed.
        let mut wrong_subvol = rule.clone();
        if let Some(DurableObjectId {
            fs: DurableFs::Persistent { fsid, .. },
            ..
        }) = &mut wrong_subvol.durable
        {
            *fsid ^= 1;
            assert!(wrong_subvol.check_identity(Kind::Optional).is_err());
        }
        // Volatile rule with mismatched device fails closed.
        let volatile_rule = Rule {
            path: target.clone(),
            device: rule.device ^ 9,
            inode: rule.inode,
            object: Object::Directory,
            durable: Some(DurableObjectId {
                fs: DurableFs::Volatile {
                    fs_type: 0x0102_1994,
                    device: rule.device ^ 9,
                },
                inode: rule.inode,
            }),
        };
        assert!(volatile_rule.check_identity(Kind::Optional).is_err());

        // Legacy rule migration (v1 -> durable) preserves inode/object constraints.
        let mut legacy = Rule {
            path: target.clone(),
            device: rule.device,
            inode: rule.inode,
            object: Object::Directory,
            durable: None,
        };
        assert!(legacy.migrate_legacy(Kind::Optional).unwrap());
        assert!(legacy.durable.is_some());
        assert!(!legacy.migrate_legacy(Kind::Optional).unwrap());

        drop(persistent_rule);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
