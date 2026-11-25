//! Extension/marketplace search, skill validation, upstream config inspection
//! and fingerprint-bound probing, plus inert operator-review proposals.

use mcp_gateway::security::linux_fs::{open_beneath_dir, reopen_regular};
use rustix::fd::OwnedFd;
use rustix::fs::{self, Dir, FileType, Mode, OFlags, ResolveFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::http::admission::{Client, Configuration};
use crate::tools::registry::Tool;

const MARKETPLACE_JSON: &str = include_str!("../http/dashboard/marketplace.json");
const MAX_PROPOSALS: usize = 64;
const MAX_PROPOSAL_BYTES: usize = 8192;

pub(crate) fn run(
    tool: Tool,
    args: Option<&Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    let empty = serde_json::Map::new();
    let args = match args {
        Some(value) => value.as_object().ok_or("Expected an arguments object")?,
        None => &empty,
    };
    match tool {
        Tool::ExtensionsSearch => search_marketplace(args, settings, client),
        Tool::ExtensionsList | Tool::ExtensionsInfo => {
            list_extensions(tool == Tool::ExtensionsInfo, args, config, settings, client)
        }
        Tool::SkillsValidate => skills_validate(args, settings, client),
        Tool::McpList | Tool::McpStatus => mcp_list(args, settings, client),
        Tool::McpInfo => mcp_info(args, settings, client),
        Tool::McpTest => mcp_test(args, config, settings, client),
        Tool::ExtensionsProposeAdd
        | Tool::ExtensionsProposeRemove
        | Tool::McpProposeAdd
        | Tool::McpProposeUpdate
        | Tool::McpProposeRemove
        | Tool::McpProposeDisable
        | Tool::SkillsProposeAdd
        | Tool::SkillsProposeRemove => create_proposal(tool, args, config, client),
        _ => Err("Unsupported extension or upstream tool".into()),
    }
}

fn check_no_control(value: &str, max_len: usize, field: &str) -> Result<String, String> {
    if value.len() > max_len
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(format!("Invalid {field}"));
    }
    Ok(value.to_owned())
}

fn search_marketplace(
    args: &serde_json::Map<String, Value>,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    if args
        .keys()
        .any(|k| !matches!(k.as_str(), "query" | "category" | "type" | "limit"))
    {
        return Err("Unexpected extensions_search argument".into());
    }
    let query = match args.get("query") {
        None => String::new(),
        Some(v) => check_no_control(v.as_str().ok_or("Invalid query")?, 128, "query")?
            .to_ascii_lowercase(),
    };
    let category = match args.get("category") {
        None => None,
        Some(v) => Some(
            check_no_control(v.as_str().ok_or("Invalid category")?, 80, "category")?
                .to_ascii_lowercase(),
        ),
    };
    let kind_filter = match args.get("type") {
        None => None,
        Some(v) => {
            let s = v.as_str().ok_or("Invalid type")?;
            if !matches!(s, "mcp" | "skill" | "tool") {
                return Err("Expected type in mcp, skill, tool".into());
            }
            Some(s)
        }
    };
    let limit = match args.get("limit") {
        None => 20usize,
        Some(v) => usize::try_from(v.as_u64().ok_or("Invalid limit")?)
            .ok()
            .filter(|n| (1..=50).contains(n))
            .ok_or("Invalid limit")?,
    };

    let doc: Value = serde_json::from_str(MARKETPLACE_JSON)
        .map_err(|_| "Marketplace catalog unavailable")?;
    let entries = doc["entries"]
        .as_array()
        .ok_or("Invalid marketplace catalog")?;

    let mut matched = Vec::new();
    for entry in entries {
        if let Some(kind) = kind_filter
            && entry["type"].as_str() != Some(kind)
        {
            continue;
        }
        if let Some(cat) = &category
            && entry["category"]
                .as_str()
                .is_none_or(|c| !c.to_ascii_lowercase().contains(cat))
        {
            continue;
        }
        if !query.is_empty() {
            let hay = [
                entry["id"].as_str(),
                entry["name"].as_str(),
                entry["description"].as_str(),
                entry["category"].as_str(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
            let cap_hit = entry["capabilities"]
                .as_array()
                .is_some_and(|arr| {
                    arr.iter().any(|c| {
                        c.as_str()
                            .is_some_and(|s| s.to_ascii_lowercase().contains(&query))
                    })
                });
            if !hay.contains(&query) && !cap_hit {
                continue;
            }
        }
        let id = entry["id"].as_str().unwrap_or_default();
        let installed = settings.upstreams.contains_server(id) || client.skills.contains(id);
        let mut item = entry.clone();
        if let Some(obj) = item.as_object_mut() {
            obj.insert("installed".into(), json!(installed));
        }
        matched.push(item);
        if matched.len() >= limit {
            break;
        }
    }

    Ok(json!({
        "entries": matched,
        "count": matched.len(),
        "total_catalog": entries.len(),
        "search_scope": "bundled metadata catalog; external registries are not contacted",
        "attribution": doc.get("attribution"),
    }))
}

fn list_extensions(
    info: bool,
    args: &serde_json::Map<String, Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    if args
        .keys()
        .any(|k| !matches!(k.as_str(), "name" | "query" | "scope"))
    {
        return Err("Unexpected extension inspection argument".into());
    }
    let name_filter = match args.get("name") {
        None => None,
        Some(v) => Some(check_no_control(
            v.as_str().ok_or("Invalid name")?,
            128,
            "name",
        )?),
    };
    let query_filter = match args.get("query") {
        None => None,
        Some(v) => Some(
            check_no_control(v.as_str().ok_or("Invalid query")?, 128, "query")?
                .to_ascii_lowercase(),
        ),
    };
    if let Some(scope) = args.get("scope")
        && !scope.as_str().is_some_and(|s| matches!(s, "user" | "project"))
    {
        return Err("Invalid scope".into());
    }

    let mut entries = Vec::new();
    if let Some(skills) = &settings.skills
        && let Ok(catalog) = skills.catalog()
    {
        for item in catalog {
            let Some(skill_id) = item["name"].as_str() else {
                continue;
            };
            if !client.skills.contains(skill_id) {
                continue;
            }
            entries.push(json!({
                "key": format!("skill:{skill_id}"),
                "scope": "user",
                "enabled": item["enabled"],
                "component": {
                    "id": skill_id,
                    "kind": "skill",
                    "name": skill_id,
                    "description": item["description"],
                    "version": item["version"],
                }
            }));
        }
    }
    if let Some(root) = &client.mutation_root {
        entries.extend(crate::inspection::extra_project_skill_summaries(root));
    }
    if let Value::Array(providers) = settings.upstreams.listing(Some(&client.upstreams)) {
        for p in providers {
            let Some(id) = p["id"].as_str() else {
                continue;
            };
            entries.push(json!({
                "key": format!("mcp:{id}"),
                "scope": "user",
                "enabled": p["enabled"],
                "component": {
                    "id": id,
                    "kind": "mcp",
                    "name": id,
                    "transport": p["transport"],
                    "credentials": p["credentials"],
                }
            }));
        }
    }

    if let Some(ref target) = name_filter {
        entries.retain(|e| {
            e["key"].as_str() == Some(target) || e["component"]["id"].as_str() == Some(target)
        });
    }
    if let Some(ref q) = query_filter {
        entries.retain(|e| e.to_string().to_ascii_lowercase().contains(q));
    }
    if let Some(scope) = args.get("scope").and_then(Value::as_str) {
        entries.retain(|e| e["scope"].as_str() == Some(scope));
    }

    let mut out = json!({
        "entries": entries,
        "count": entries.len(),
        "search_scope": "installed entries; external registries not configured",
    });
    if info {
        let pending = list_requests(config)
            .map(|list| {
                list.into_iter()
                    .filter(|req| req["client_id"].as_str() == Some(client.id.as_str()))
                    .count()
            })
            .unwrap_or(0);
        out["inventory_source"] = json!("user declarations; account inventory is unavailable");
        out["pending_proposals_count"] = json!(pending);
    }
    Ok(out)
}

fn skills_validate(
    args: &serde_json::Map<String, Value>,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    if !args.is_empty() {
        return Err("Unexpected skills_validate argument".into());
    }
    let mut results = Vec::new();
    if let Some(skills) = &settings.skills {
        for name in &client.skills {
            let key = format!("skill:{name}");
            match skills.read(name) {
                Ok(_) => results.push(json!({"key": key, "valid": true, "source": "skills_dir"})),
                Err(err) => {
                    results.push(json!({"key": key, "valid": false, "source": "skills_dir", "error": err}))
                }
            }
        }
    }
    if let Some(root) = &client.mutation_root {
        results.extend(crate::inspection::extra_validate_project_skills(root));
    }
    let ok = results.iter().all(|r| r["valid"] == true);
    Ok(json!({
        "results": results,
        "ok": ok,
        "count": results.len(),
    }))
}

fn mcp_list(
    args: &serde_json::Map<String, Value>,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    if !args.is_empty() {
        return Err("Unexpected mcp list argument".into());
    }
    let providers = settings.upstreams.listing(Some(&client.upstreams));
    let count = providers.as_array().map_or(0, Vec::len);
    Ok(json!({
        "providers": providers,
        "count": count,
        "mode": "passive_metadata_only",
    }))
}

fn mcp_info(
    args: &serde_json::Map<String, Value>,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    if args.keys().any(|k| k != "name") {
        return Err("Unexpected mcp_info argument".into());
    }
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing string argument: name")?;
    settings
        .upstreams
        .fingerprint_and_info(&client.upstreams, name)
        .map_err(str::to_owned)
}

fn mcp_test(
    args: &serde_json::Map<String, Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    if args
        .keys()
        .any(|k| !matches!(k.as_str(), "name" | "provider_fingerprint"))
    {
        return Err("Unexpected mcp_test argument".into());
    }
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .ok_or("Missing string argument: name")?;
    let expected_fp = args
        .get("provider_fingerprint")
        .and_then(Value::as_str)
        .filter(|s| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or("Expected 64-hex lowercase provider_fingerprint from mcp_info")?;

    let info = settings
        .upstreams
        .fingerprint_and_info(&client.upstreams, name)
        .map_err(str::to_owned)?;
    let actual_fp = info["provider_fingerprint"]
        .as_str()
        .ok_or("PROVIDER_NOT_FOUND")?;
    if actual_fp != expected_fp {
        return Err("PROVIDER_FINGERPRINT_CHANGED".into());
    }
    let mut result = settings.upstreams.probe(config, name)?;
    if let Some(obj) = result.as_object_mut() {
        obj.insert("provider_fingerprint".into(), json!(actual_fp));
    }
    Ok(result)
}

fn open_proposals_dir(config: &Path, create: bool) -> Result<OwnedFd, String> {
    let parent = config.parent().ok_or("Missing state directory")?;
    let parent_fd = mcp_gateway::security::linux_fs::open_absolute_dir(parent)
        .map_err(|_| "State directory unavailable")?;
    if create {
        match fs::mkdirat(&parent_fd, "proposals", Mode::from_bits_truncate(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err("Unable to initialize proposals directory".into()),
        }
    }
    open_beneath_dir(&parent_fd, Path::new("proposals"))
        .map_err(|_| "Proposals directory unavailable or unsafe".into())
}

fn create_proposal(
    tool: Tool,
    args: &serde_json::Map<String, Value>,
    config: &Path,
    client: &Client,
) -> Result<Value, String> {
    if args.keys().any(|k| {
        !matches!(
            k.as_str(),
            "name" | "source" | "selection" | "scope" | "provider_fingerprint"
        )
    }) {
        return Err("Unexpected proposal argument".into());
    }
    let (kind, action) = match tool {
        Tool::ExtensionsProposeAdd => ("extension", "add"),
        Tool::ExtensionsProposeRemove => ("extension", "remove"),
        Tool::McpProposeAdd => ("mcp", "add"),
        Tool::McpProposeUpdate => ("mcp", "update"),
        Tool::McpProposeRemove => ("mcp", "remove"),
        Tool::McpProposeDisable => ("mcp", "disable"),
        Tool::SkillsProposeAdd => ("skill", "add"),
        Tool::SkillsProposeRemove => ("skill", "remove"),
        _ => return Err("Unsupported proposal tool".into()),
    };

    let scope = match args.get("scope") {
        None => "project",
        Some(v) => v
            .as_str()
            .filter(|s| matches!(*s, "user" | "project"))
            .ok_or("Expected scope user or project")?,
    };
    let name = match args.get("name") {
        None => None,
        Some(v) => {
            let s = check_no_control(v.as_str().ok_or("Invalid name")?, 128, "name")?;
            if s.trim().is_empty() {
                return Err("name cannot be empty".into());
            }
            Some(s)
        }
    };
    let source = match args.get("source") {
        None => None,
        Some(v) => {
            let s = check_no_control(v.as_str().ok_or("Invalid source")?, 2048, "source")?;
            if s.trim().is_empty() {
                return Err("source cannot be empty".into());
            }
            Some(s)
        }
    };
    let selection = match args.get("selection") {
        None => None,
        Some(v) => {
            let arr = v
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 64)
                .ok_or("Invalid selection")?;
            let mut items = Vec::with_capacity(arr.len());
            for item in arr {
                let s = check_no_control(item.as_str().ok_or("Invalid selection entry")?, 128, "selection")?;
                items.push(s);
            }
            Some(items)
        }
    };
    let fingerprint = match args.get("provider_fingerprint") {
        None => None,
        Some(v) => {
            let s = v
                .as_str()
                .filter(|s| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                .ok_or("Invalid provider_fingerprint")?;
            Some(s.to_owned())
        }
    };

    if action == "add" && source.is_none() {
        return Err("source is required for add proposals".into());
    }
    if action != "add" && name.is_none() {
        return Err("name is required".into());
    }
    let key = name.as_ref().map(|n| {
        if n.contains(':') || kind == "extension" {
            n.clone()
        } else {
            format!("{kind}:{n}")
        }
    });

    let canonical = json!({
        "version": 1,
        "client_id": client.id,
        "tool": tool.name(),
        "kind": kind,
        "action": action,
        "scope": scope,
        "key": key,
        "source": source,
        "selection": selection,
        "provider_fingerprint": fingerprint,
    });
    let payload_str = canonical.to_string();
    if payload_str.len() > 4096 {
        return Err("Proposal payload exceeds size limit".into());
    }
    let id = format!("{:x}", Sha256::digest(payload_str.as_bytes()));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut stored = canonical;
    stored["id"] = json!(id);
    stored["created_at"] = json!(now);
    stored["status"] = json!("pending_operator_review");
    stored["operator_review_required"] = json!(true);
    stored["inert"] = json!(true);

    let dir = open_proposals_dir(config, true)?;
    let existing = list_proposal_filenames(&dir)?;
    let filename = format!("{id}.json");
    if existing.len() >= MAX_PROPOSALS && !existing.contains(&filename) {
        return Err("Pending operator review queue is full".into());
    }

    let tmp_name = format!(
        ".{id}.stage.{}",
        std::process::id()
    );
    let tmp_fd = fs::openat2(
        &dir,
        Path::new(&tmp_name),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| "Unable to create staged proposal")?;
    {
        let mut f = File::from(tmp_fd);
        let serialized = stored.to_string();
        if f.write_all(serialized.as_bytes()).is_err() || f.sync_all().is_err() {
            let _ = fs::unlinkat(&dir, Path::new(&tmp_name), fs::AtFlags::empty());
            return Err("Failed writing staged proposal".into());
        }
    }
    if fs::renameat(&dir, Path::new(&tmp_name), &dir, Path::new(&filename)).is_err() {
        let _ = fs::unlinkat(&dir, Path::new(&tmp_name), fs::AtFlags::empty());
        return Err("Failed publishing proposal".into());
    }
    let _ = fs::fsync(&dir);

    Ok(json!({
        "id": id,
        "kind": kind,
        "action": action,
        "scope": scope,
        "key": key,
        "status": "pending_operator_review",
        "operator_review_required": true,
        "inert": true,
        "note": "Inert review request stored only. Nothing was downloaded, installed, enabled, or executed.",
    }))
}

fn list_proposal_filenames(dir: &OwnedFd) -> Result<Vec<String>, String> {
    let entries = Dir::read_from(dir).map_err(|_| "Proposals directory unreadable")?;
    let mut names = Vec::new();
    for item in entries.flatten() {
        let os = OsStr::from_bytes(item.file_name().to_bytes());
        if let Some(s) = os.to_str()
            && let Some(hex) = s.strip_suffix(".json")
            && hex.len() == 64
            && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            names.push(s.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

pub(crate) fn list_requests(config: &Path) -> Result<Vec<Value>, String> {
    let dir = match open_proposals_dir(config, false) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };
    let files = list_proposal_filenames(&dir)?;
    let mut out = Vec::new();
    for filename in files.into_iter().take(MAX_PROPOSALS) {
        let Ok(handle) = fs::openat2(
            &dir,
            Path::new(&filename),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) else {
            continue;
        };
        let Ok(stat) = fs::fstat(&handle) else {
            continue;
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_nlink != 1
            || stat.st_size > MAX_PROPOSAL_BYTES as i64
        {
            continue;
        }
        let Ok(file) = reopen_regular(&handle, OFlags::RDONLY | OFlags::NONBLOCK) else {
            continue;
        };
        let mut bytes = Vec::new();
        if File::from(file)
            .take(MAX_PROPOSAL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .is_err()
        {
            continue;
        }
        if let Ok(parsed) = serde_json::from_slice::<Value>(&bytes) {
            out.push(parsed);
        }
    }
    out.sort_by_key(|v| std::cmp::Reverse(v["created_at"].as_u64().unwrap_or(0)));
    Ok(out)
}

pub(crate) fn dismiss_request(config: &Path, id: &str) -> Result<bool, String> {
    if id.len() != 64 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("Invalid proposal identifier".into());
    }
    let dir = open_proposals_dir(config, false)?;
    let filename = format!("{id}.json");
    match fs::unlinkat(&dir, Path::new(&filename), fs::AtFlags::empty()) {
        Ok(()) => {
            let _ = fs::fsync(&dir);
            Ok(true)
        }
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(_) => Err("Unable to dismiss proposal".into()),
    }
}
