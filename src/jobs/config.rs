//! Operator-approved profiles and validated working-directory handles.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fd::OwnedFd;
use rustix::thread::set_no_new_privs;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mcp_gateway::security::linux_fs::open_operator_dir;

use super::invalid;

const MAX_ARGS: usize = 32;
const MAX_ARG_BYTES: usize = 1024;
const MAX_ARGV_BYTES: usize = 8192;
pub(super) const MAX_OUTPUT: usize = 65_536;
pub(super) const MAX_PROFILE_OUTPUT: usize = 16 * 1024 * 1024;
pub(super) const fn default_cpu() -> u64 {
    100
}
pub(super) const fn default_memory() -> u64 {
    256 * 1024 * 1024
}
pub(crate) const SHORT_RUNTIME_MAX: u64 = 300;
pub(crate) const EXTENDED_RUNTIME_MAX: u64 = 86_400;
const DEFAULT_OUTPUT: usize = 4096;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub executable: String,
    pub args: Vec<String>,
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub interactive: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pty: bool,
    /// Explicit local operator opt-in; not accepted as an MCP argument.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub extended_runtime: bool,
    #[serde(default = "default_output_limit")]
    pub max_output_bytes: usize,
    #[serde(default = "default_cpu")]
    pub cpu_percent: u64,
    #[serde(default = "default_memory")]
    pub memory_bytes: u64,
}

fn default_output_limit() -> usize {
    DEFAULT_OUTPUT
}

impl Profile {
    pub(super) fn validate(&mut self, native: bool) -> io::Result<()> {
        self.check_limits(native)?;
        let path = fs::canonicalize(&self.executable)?;
        if !fs::metadata(&path).is_ok_and(|meta| meta.is_file() && meta.mode() & 0o111 != 0) {
            return Err(invalid());
        }
        self.executable = path.into_os_string().into_string().map_err(|_| invalid())?;
        Ok(())
    }

    pub fn check_limits(&self, native: bool) -> io::Result<()> {
        if (self.pty && !self.interactive)
            || !Path::new(&self.executable).is_absolute()
            || self.executable.len() > MAX_ARG_BYTES
            || self.executable.contains('\0')
            || self.args.len() > MAX_ARGS
            || self
                .args
                .iter()
                .any(|arg| arg.len() > MAX_ARG_BYTES || arg.contains('\0'))
            || self.args.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES
            || !(u64::from(!native)..=if self.extended_runtime {
                EXTENDED_RUNTIME_MAX
            } else {
                SHORT_RUNTIME_MAX
            })
                .contains(&self.timeout_seconds)
            || !(1..=MAX_PROFILE_OUTPUT).contains(&self.max_output_bytes)
            || !(native && self.cpu_percent == 0 || (10..=1600).contains(&self.cpu_percent))
            || !(native && self.memory_bytes == 0 || (16 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&self.memory_bytes))
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn argv_hash(&self) -> String {
        let mut hash = Sha256::new();
        for arg in std::iter::once(&self.executable).chain(&self.args) {
            hash.update((arg.len() as u64).to_be_bytes());
            hash.update(arg.as_bytes());
        }
        format!("{:x}", hash.finalize())
    }
}

#[derive(Clone)]
pub(crate) struct Profiles(BTreeMap<String, Profile>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobDocument {
    #[serde(rename = "clients")]
    _clients: Vec<JobClient>,
    #[serde(rename = "audit_log")]
    _audit_log: String,
    #[serde(default, rename = "policy_version")]
    _policy_version: Option<u64>,
    #[serde(default, rename = "max_audit_file_bytes")]
    _max_audit_file_bytes: Option<u64>,
    #[serde(default, rename = "max_audit_dir_bytes")]
    _max_audit_dir_bytes: Option<u64>,
    #[serde(default, rename = "protected_paths")]
    _protected_paths: Option<serde_json::Value>,
    #[serde(default, rename = "skills_dir")]
    _skills_dir: Option<PathBuf>,
    #[serde(default, rename = "skills_disabled")]
    _skills_disabled: Option<Vec<String>>,
    #[serde(default, rename = "admin_listen")]
    _admin_listen: Option<String>,
    #[serde(default, rename = "tailscale_serve")]
    _tailscale_serve: Option<serde_json::Value>,
    #[serde(default, rename = "cloudflare_tunnel")]
    _cloudflare_tunnel: Option<serde_json::Value>,
    #[serde(default, rename = "mcp_servers")]
    _mcp_servers: Option<serde_json::Value>,
    #[serde(default, rename = "default_mode")]
    _default_mode: Option<String>,
    #[serde(default, rename = "workspace")]
    _workspace: Option<PathBuf>,
    #[serde(default, rename = "oauth")]
    _oauth: Option<serde_json::Value>,
    #[serde(default, rename = "migrated_from")]
    _migrated_from: Option<serde_json::Value>,
    job_state_dir: PathBuf,
    #[serde(deserialize_with = "unique_profiles")]
    job_profiles: BTreeMap<String, Profile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobClient {
    #[serde(rename = "id")]
    _id: String,
    #[serde(rename = "token_sha256")]
    _token_sha256: String,
    #[serde(rename = "expires_at_unix_seconds")]
    _expires_at: u64,
    #[serde(rename = "root")]
    _root: String,
    #[serde(rename = "tools")]
    _tools: Vec<String>,
    #[serde(default, rename = "skills")]
    _skills: Option<Vec<String>>,
    #[serde(default, rename = "allowed_servers")]
    _allowed_servers: Option<Vec<String>>,
    #[serde(default, rename = "allowed_server_tools")]
    _allowed_server_tools: Option<serde_json::Value>,
    // Workspace delegation is validated by upstream admission, not job profiles.
    #[serde(default, rename = "upstream_workspace_roots")]
    _upstream_workspace_roots: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, rename = "mode")]
    _mode: Option<String>,
    #[serde(default, rename = "yolo_roots")]
    _yolo_roots: Option<Vec<PathBuf>>,
    #[serde(default, rename = "yolo_shared_roots")]
    _yolo_shared_roots: Option<Vec<PathBuf>>,
    #[serde(default, rename = "yolo_revision")]
    _yolo_revision: Option<String>,
    #[serde(default, rename = "extra_roots")]
    _extra_roots: Option<Vec<PathBuf>>,
    #[serde(default, rename = "deny_tools")]
    _deny_tools: Option<Vec<String>>,
    #[serde(default, rename = "native_tool_preset")]
    _native_tool_preset: Option<bool>,
    #[serde(default, rename = "disabled")]
    _disabled: Option<bool>,
    #[serde(default, rename = "job_runtime_limit_seconds")]
    _job_runtime_limit_seconds: Option<u64>,
    #[serde(default, rename = "job_cpu_percent_limit")]
    _job_cpu_percent_limit: Option<u64>,
    #[serde(default, rename = "job_memory_bytes_limit")]
    _job_memory_bytes_limit: Option<u64>,
    #[serde(default, rename = "job_output_limit_bytes")]
    _job_output_limit_bytes: Option<usize>,
    #[serde(default, rename = "job_retention_count")]
    _job_retention_count: Option<usize>,
    #[serde(default, rename = "timeshift_retention_count")]
    _timeshift_retention_count: Option<usize>,
}

pub(crate) fn parse_settings(bytes: &[u8]) -> Result<(PathBuf, Profiles), String> {
    let mut document: JobDocument = serde_json::from_slice(bytes)
        .map_err(|_| "Invalid job-enabled credential configuration")?;
    let state = document.job_state_dir;
    if !state.is_absolute()
        || state.file_name().is_none()
        || state
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err("Invalid job_state_dir".into());
    }
    let profiles = &mut document.job_profiles;
    if profiles.is_empty() || profiles.len() > 64 {
        return Err("Invalid job profile count".into());
    }
    for (name, profile) in profiles {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("Invalid job profile name".into());
        }
        profile.validate(false).map_err(|_| "Invalid job profile")?;
    }
    Ok((state, Profiles(document.job_profiles)))
}

fn unique_profiles<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Profile>, D::Error> {
    struct UniqueProfiles;

    impl<'de> Visitor<'de> for UniqueProfiles {
        type Value = BTreeMap<String, Profile>;

        fn expecting(&self, format: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            format.write_str("an object with unique job profile names")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<Self::Value, M::Error> {
            let mut profiles = BTreeMap::new();
            while let Some((name, profile)) = input.next_entry()? {
                if profiles.insert(name, profile).is_some() {
                    return Err(de::Error::custom("duplicate job profile"));
                }
            }
            Ok(profiles)
        }
    }
    deserializer.deserialize_map(UniqueProfiles)
}

impl Profiles {
    /// OAuth admits only operator-configured noninteractive profiles.
    /// The local consent UI displays the exact normalized profile set.
    pub(crate) fn oauth_summary(&self, allow_interactive: bool) -> Result<serde_json::Value,String> {
        if self.0.is_empty() || self.0.len()>16 {return Err("OAuth requires 1 to 16 named job profiles".into());}
        if allow_interactive && !self.has_interactive() {
            return Err("Interactive OAuth sessions require at least one interactive job profile".into());
        }
        for profile in self.0.values() {
            if (!allow_interactive && (profile.interactive || profile.pty))
                || profile.extended_runtime
                || profile.timeout_seconds>SHORT_RUNTIME_MAX
                || profile.max_output_bytes>MAX_OUTPUT
                || profile.cpu_percent>default_cpu() || profile.memory_bytes>default_memory()
                || !Path::new(&profile.executable).starts_with("/usr/bin")
                || !fs::metadata(&profile.executable).is_ok_and(|m|m.is_file() && m.uid()==0 && m.mode()&0o6022==0) {
                return Err(if allow_interactive {
                    "OAuth interactive jobs require bounded profiles with trusted system executables"
                } else {
                    "OAuth jobs require bounded noninteractive profiles with trusted system executables"
                }.into());
            }
        }
        serde_json::to_value(&self.0).map_err(|_|"Cannot represent OAuth job profiles".into())
    }
    pub(super) fn named(&self, name: &str) -> Option<Profile> {
        self.0.get(name).cloned()
    }

    pub(super) fn has_interactive(&self) -> bool {
        self.0.values().any(|profile| profile.interactive)
    }

    pub(super) fn matching(&self, args: &serde_json::Value) -> Option<(String, Profile)> {
        let args = args
            .as_array()
            .filter(|args| !args.is_empty() && args.len() <= MAX_ARGS + 1)?;
        let executable = args[0].as_str()?;
        if !Path::new(executable).is_absolute() || executable.len() > MAX_ARG_BYTES {
            return None;
        }
        self.0.iter().find_map(|(name, profile)| {
            (!profile.interactive
                && profile.executable == executable
                && profile.args.len() == args.len() - 1
                && profile
                    .args
                    .iter()
                    .zip(&args[1..])
                    .all(|(expected, actual)| actual.as_str() == Some(expected.as_str())))
            .then(|| (name.clone(), profile.clone()))
        })
    }

    pub(crate) fn reject_mutable_executables(&self, root: &Path) -> Result<(), String> {
        if self
            .0
            .values()
            .any(|profile| Path::new(&profile.executable).starts_with(root))
        {
            return Err("Job executables must be outside HTTP mutation roots".into());
        }
        Ok(())
    }
}

pub(crate) fn oauth_profiles(bytes:&[u8], allow_interactive: bool)->Result<serde_json::Value,String>{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        #[serde(deserialize_with="unique_profiles")]
        job_profiles:BTreeMap<String,Profile>,
    }
    let mut input:Input=serde_json::from_slice(bytes).map_err(|_|"Invalid job profiles file")?;
    if input.job_profiles.is_empty() || input.job_profiles.len()>16 {return Err("OAuth requires 1 to 16 job profiles".into());}
    for (name,profile) in &mut input.job_profiles {
        if name.is_empty() || name.len()>64 || !name.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'_'|b'-')) {
            return Err("Invalid OAuth job profile name".into());
        }
        profile.validate(false).map_err(|_|"Invalid OAuth job profile")?;
    }
    Profiles(input.job_profiles).oauth_summary(allow_interactive)
}

pub(crate) struct JobRoot {
    identity: RootIdentity,
    _directory: File,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct RootIdentity {
    path: PathBuf,
    id: [u64; 2],
}

impl JobRoot {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let (directory, id) = open_directory(path)
            .map_err(|_| "Job root must be an existing symlink-free directory")?;
        Ok(Self {
            identity: RootIdentity {
                path: path.to_path_buf(),
                id,
            },
            _directory: directory,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        self.identity.path()
    }

    pub(super) fn identity(&self) -> &RootIdentity {
        &self.identity
    }
}

impl RootIdentity {
    pub(super) fn handle(&self) -> io::Result<OwnedFd> {
        let (file, current) = open_directory(&self.path)?;
        if self.id != current {
            return Err(invalid());
        }
        Ok(file.into())
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

fn open_directory(path: &Path) -> io::Result<(File, [u64; 2])> {
    let file = File::from(open_operator_dir(path)?);
    let stat = file.metadata()?;
    Ok((file, [stat.dev(), stat.ino()]))
}

pub(super) fn restrict_child_privileges() -> io::Result<()> {
    set_no_new_privs(true).map_err(io::Error::from)
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    #[test]
    fn resource_budgets_validate_and_default() {
        let mut profile: Profile = serde_json::from_value(serde_json::json!({
            "executable": "/usr/bin/true", "args": [], "timeout_seconds": 1
        }))
        .unwrap();
        assert_eq!(profile.cpu_percent, 100);
        assert_eq!(profile.memory_bytes, 256 * 1024 * 1024);
        assert_eq!(profile.max_output_bytes, 4096);
        profile.cpu_percent = 9;
        assert!(profile.check_limits(false).is_err());
        profile.cpu_percent = 1600;
        profile.memory_bytes = 16 * 1024 * 1024 * 1024;
        profile.max_output_bytes = MAX_PROFILE_OUTPUT;
        assert!(profile.check_limits(false).is_ok());
        profile.memory_bytes += 1;
        assert!(profile.check_limits(false).is_err());
        profile.memory_bytes = 16 * 1024 * 1024;
        profile.max_output_bytes += 1;
        assert!(profile.check_limits(false).is_err());
    }

    #[test]
    fn long_budget_requires_explicit_operator_profile_opt_in() {
        let mut profile = Profile {
            interactive: false,
            pty: false,
            executable: "/usr/bin/true".into(),
            args: vec![],
            timeout_seconds: 300,
            extended_runtime: false,
            max_output_bytes: 4096,
            cpu_percent: default_cpu(),
            memory_bytes: default_memory(),
        };
        assert!(profile.check_limits(false).is_ok());
        profile.timeout_seconds = 301;
        assert!(profile.check_limits(false).is_err());
        profile.extended_runtime = true;
        assert!(profile.check_limits(false).is_ok());
        profile.timeout_seconds = EXTENDED_RUNTIME_MAX;
        assert!(profile.check_limits(false).is_ok());
        profile.timeout_seconds += 1;
        assert!(profile.check_limits(false).is_err());
        profile.timeout_seconds = 0;
        assert!(profile.check_limits(false).is_err());
        let old: Profile = serde_json::from_value(serde_json::json!({
            "executable": "/usr/bin/true", "args": [], "timeout_seconds": 300
        }))
        .unwrap();
        assert!(!old.extended_runtime);
        assert!(
            serde_json::to_value(old)
                .unwrap()
                .get("extended_runtime")
                .is_none()
        );
    }

    #[test]
    fn oauth_summary_enforces_explicit_interactive_boundary() {
        let mut map = BTreeMap::new();
        map.insert(
            "shell".to_owned(),
            Profile {
                executable: "/usr/bin/sh".into(),
                args: vec!["-s".into()],
                timeout_seconds: 60,
                interactive: true,
                pty: false,
                extended_runtime: false,
                max_output_bytes: MAX_OUTPUT,
                cpu_percent: 100,
                memory_bytes: default_memory(),
            },
        );
        let profiles = Profiles(map.clone());
        assert!(profiles.oauth_summary(false).is_err());
        assert!(profiles.oauth_summary(true).is_ok());

        let mut pty_map = BTreeMap::new();
        pty_map.insert(
            "pty".to_owned(),
            Profile {
                executable: "/usr/bin/sh".into(),
                args: vec!["-i".into()],
                timeout_seconds: 300,
                interactive: true,
                pty: true,
                extended_runtime: false,
                max_output_bytes: MAX_OUTPUT,
                cpu_percent: 100,
                memory_bytes: default_memory(),
            },
        );
        assert!(Profiles(pty_map.clone()).oauth_summary(false).is_err());
        assert!(Profiles(pty_map.clone()).oauth_summary(true).is_ok());

        // Interactive OAuth still forbids extended runtime or exceeded ceilings.
        let mut over = pty_map.clone();
        over.get_mut("pty").unwrap().extended_runtime = true;
        over.get_mut("pty").unwrap().timeout_seconds = 301;
        assert!(Profiles(over).oauth_summary(true).is_err());

        let mut over_mem = pty_map;
        over_mem.get_mut("pty").unwrap().memory_bytes = default_memory() + 1;
        assert!(Profiles(over_mem).oauth_summary(true).is_err());

        // Interactive mode requires at least one interactive profile.
        let mut non_interactive = BTreeMap::new();
        non_interactive.insert(
            "pwd".to_owned(),
            Profile {
                executable: "/usr/bin/pwd".into(),
                args: vec![],
                timeout_seconds: 10,
                interactive: false,
                pty: false,
                extended_runtime: false,
                max_output_bytes: DEFAULT_OUTPUT,
                cpu_percent: 100,
                memory_bytes: default_memory(),
            },
        );
        assert!(Profiles(non_interactive.clone()).oauth_summary(false).is_ok());
        assert!(Profiles(non_interactive).oauth_summary(true).is_err());
    }
}
