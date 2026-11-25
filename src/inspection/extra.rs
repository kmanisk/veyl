//! Bounded workspace context helpers: path-scoped rules, project skills,
//! auto-memory notes, and read-only chezmoi ownership inspection.

use mcp_gateway::security::linux_fs::{open_beneath_dir, reopen_regular};
use rustix::fd::OwnedFd;
use rustix::fs::{self, Dir, FileType, Mode, OFlags, ResolveFlags};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::http::admission::{Client, Configuration};
use crate::http::operator;
use crate::skills::valid_name;
use crate::tools::MutationRoot;
use crate::tools::registry::Tool;

const MAX_RULE_BYTES: usize = 65_536;
const MAX_RULE_FILES: usize = 128;
const MAX_RULES_RETURNED: usize = 24;
const MAX_SKILL_BYTES: usize = 200_000;
const MAX_MEMORY_BYTES: usize = 25_000;
const MAX_MEMORY_LINES: usize = 200;

pub(crate) fn run(
    tool: Tool,
    args: Option<&Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
    reserved: &dyn Fn(&Path) -> bool,
) -> Result<Value, String> {
    let empty = serde_json::Map::new();
    let args = match args {
        Some(value) => value.as_object().ok_or("Expected an arguments object")?,
        None => &empty,
    };
    match tool {
        Tool::LoadPathRules => load_path_rules(args, config, settings, client, reserved),
        Tool::ProjectSkillsList => list_skills(args, client, reserved),
        Tool::ProjectSkillLoad => load_skill(args, client, reserved),
        Tool::Remember => remember(args, config, settings, client, reserved),
        Tool::ChezmoiInspect => chezmoi_inspect(args, config, settings, client, reserved),
        _ => Err("Unsupported workspace context tool".into()),
    }
}

fn validate_raw_path(raw: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw.len() >= 1024
        || raw.as_bytes().contains(&0)
        || raw.chars().any(char::is_control)
    {
        return Err("Invalid path argument".into());
    }
    if Path::new(raw)
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("Relative navigation components are not allowed".into());
    }
    Ok(())
}

fn read_regular_beneath(dir: &OwnedFd, rel: &Path, limit: usize) -> Result<(Vec<u8>, bool), String> {
    let handle = fs::openat2(
        dir,
        rel,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| "Target unavailable or outside approved directory")?;
    let stat = fs::fstat(&handle).map_err(|_| "Unable to inspect file")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return Err("Target must be an unaliased regular file".into());
    }
    let file = reopen_regular(&handle, OFlags::RDONLY | OFlags::NONBLOCK)
        .map_err(|_| "Unable to open regular file")?;
    let mut bytes = Vec::new();
    File::from(file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Unable to read file")?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((bytes, truncated))
}

fn load_path_rules(
    args: &serde_json::Map<String, Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
    reserved: &dyn Fn(&Path) -> bool,
) -> Result<Value, String> {
    if args.keys().any(|k| k != "path") {
        return Err("Unexpected load_path_rules argument".into());
    }
    let raw = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or("Missing string argument: path")?;
    validate_raw_path(raw)?;

    let req = Path::new(raw);
    let root = client
        .mutation_root
        .as_ref()
        .ok_or("Workspace unavailable")?;
    let rel_target = if req.is_absolute() {
        let abs = req;
        let mode = client.mode;
        if operator::policy_path(config, abs) && mode != mcp_gateway::security::policy::ExecutionMode::Full
        {
            return Err("Protected path cannot be inspected".into());
        }
        if matches!(
            mode,
            mcp_gateway::security::policy::ExecutionMode::BroadYolo
        ) {
            let broad = crate::jobs::broad::Broad::prepare(config, settings)?;
            broad
                .file_parent(abs, false)
                .map_err(|_| "Protected path cannot be inspected")?;
        } else if mode != mcp_gateway::security::policy::ExecutionMode::Full
            && !abs.starts_with(root.path())
            && !client
                .extra_roots
                .iter()
                .any(|extra| abs.starts_with(extra.path()))
        {
            return Err("Path outside approved workspace".into());
        }
        abs.strip_prefix(root.path())
            .unwrap_or(abs)
            .to_string_lossy()
            .into_owned()
    } else {
        let joined = root.path().join(req);
        if reserved(&joined) {
            return Err("Protected path cannot be inspected".into());
        }
        raw.to_owned()
    };

    let mut rule_files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    let mut truncated = false;
    if let Ok(rules_dir) = open_beneath_dir(root.directory(), Path::new(".claude/rules")) {
        walk_rules(
            &rules_dir,
            Path::new(".claude/rules"),
            0,
            &mut rule_files,
            &mut truncated,
        );
    }

    let full_target = if req.is_absolute() {
        raw.to_owned()
    } else {
        root.path().join(req).to_string_lossy().into_owned()
    };
    let mut matched = Vec::new();
    for (rel_rule, bytes) in rule_files {
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let Some((patterns, body)) = parse_rule_frontmatter(text) else {
            continue;
        };
        if body.is_empty() {
            continue;
        }
        if patterns
            .iter()
            .any(|pat| glob_matches_path(pat, &rel_target) || glob_matches_path(pat, &full_target))
        {
            if matched.len() >= MAX_RULES_RETURNED {
                truncated = true;
                break;
            }
            let excerpt: String = body.chars().take(4000).collect();
            matched.push(json!({
                "path": root.path().join(&rel_rule),
                "content": excerpt,
            }));
        }
    }

    Ok(json!({
        "path": full_target,
        "rules": matched,
        "count": matched.len(),
        "truncated": truncated,
    }))
}

fn walk_rules(
    dir: &OwnedFd,
    rel_base: &Path,
    depth: usize,
    out: &mut Vec<(PathBuf, Vec<u8>)>,
    truncated: &mut bool,
) {
    if depth > 3 || out.len() >= MAX_RULE_FILES {
        if out.len() >= MAX_RULE_FILES {
            *truncated = true;
        }
        return;
    }
    let Ok(entries) = Dir::read_from(dir) else {
        return;
    };
    let mut names = Vec::new();
    for item in entries.flatten() {
        let name = OsStr::from_bytes(item.file_name().to_bytes());
        if let Some(s) = name.to_str()
            && !matches!(s, "." | "..")
        {
            names.push(s.to_owned());
        }
    }
    names.sort();
    for name in names {
        if out.len() >= MAX_RULE_FILES {
            *truncated = true;
            return;
        }
        let rel = Path::new(&name);
        if let Ok(sub) = open_beneath_dir(dir, rel) {
            walk_rules(&sub, &rel_base.join(rel), depth + 1, out, truncated);
        } else if name.ends_with(".md")
            && let Ok((bytes, _)) = read_regular_beneath(dir, rel, MAX_RULE_BYTES)
        {
            out.push((rel_base.join(rel), bytes));
        }
    }
}

fn parse_rule_frontmatter(raw: &str) -> Option<(Vec<String>, String)> {
    let mut lines = raw.lines();
    if lines.next()?.trim_end_matches('\r') != "---" {
        return None;
    }
    let mut frontmatter = Vec::new();
    let mut closed = false;
    for line in lines.by_ref() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed == "---" {
            closed = true;
            break;
        }
        frontmatter.push(trimmed);
    }
    if !closed {
        return None;
    }
    let mut patterns = Vec::new();
    let mut in_paths = false;
    for line in frontmatter {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("paths:") {
            in_paths = true;
            let rest = rest.trim();
            if let Some(inline) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                for item in inline.split(',') {
                    let clean = item.trim().trim_matches(|c| c == '"' || c == '\'').trim();
                    if !clean.is_empty() {
                        patterns.push(clean.to_owned());
                    }
                }
                in_paths = false;
            }
            continue;
        }
        if in_paths {
            if let Some(item) = trimmed.strip_prefix('-') {
                let clean = item.trim().trim_matches(|c| c == '"' || c == '\'').trim();
                if !clean.is_empty() {
                    patterns.push(clean.to_owned());
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                in_paths = false;
            }
        }
    }
    if patterns.is_empty() {
        return None;
    }
    let body = lines.collect::<Vec<_>>().join("\n").trim().to_owned();
    Some((patterns, body))
}

fn expand_braces(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_owned()];
    };
    let Some(rel_close) = pattern[open + 1..].find('}') else {
        return vec![pattern.to_owned()];
    };
    let close = open + 1 + rel_close;
    let prefix = &pattern[..open];
    let suffix = &pattern[close + 1..];
    let mut expanded = Vec::new();
    for alt in pattern[open + 1..close].split(',').take(16) {
        let candidate = format!("{prefix}{}{suffix}", alt.trim());
        for tail in expand_braces(&candidate) {
            expanded.push(tail);
            if expanded.len() >= 32 {
                return expanded;
            }
        }
    }
    expanded
}

fn glob_match_bytes(pat: &[u8], text: &[u8]) -> bool {
    if pat.len() > 256 || text.len() > 1024 {
        return false;
    }
    #[derive(Clone, Copy)]
    enum Tok {
        GlobStar,     // "**" or "**/" (0+ chars including '/')
        GlobStarDir,  // "**/" (0+ dirs ending at '/' or empty)
        Star,         // "*" (0+ non-'/' chars)
        AnyNonSlash,  // "?"
        Lit(u8),
    }
    let mut toks = Vec::with_capacity(pat.len());
    let mut i = 0;
    while i < pat.len() {
        if i + 1 < pat.len() && pat[i] == b'*' && pat[i + 1] == b'*' {
            while i + 1 < pat.len() && pat[i + 1] == b'*' {
                i += 1;
            }
            if i + 1 < pat.len() && pat[i + 1] == b'/' {
                toks.push(Tok::GlobStarDir);
                i += 2;
            } else {
                toks.push(Tok::GlobStar);
                i += 1;
            }
        } else if pat[i] == b'*' {
            toks.push(Tok::Star);
            i += 1;
        } else if pat[i] == b'?' {
            toks.push(Tok::AnyNonSlash);
            i += 1;
        } else {
            toks.push(Tok::Lit(pat[i]));
            i += 1;
        }
    }
    let cols = text.len() + 1;
    let mut dp = vec![false; (toks.len() + 1) * cols];
    dp[0] = true;
    for (ti, tok) in toks.iter().enumerate() {
        for ci in 0..=text.len() {
            if !dp[ti * cols + ci] {
                continue;
            }
            match tok {
                Tok::GlobStar => {
                    for k in ci..=text.len() {
                        dp[(ti + 1) * cols + k] = true;
                    }
                }
                Tok::GlobStarDir => {
                    dp[(ti + 1) * cols + ci] = true;
                    for k in ci..text.len() {
                        if text[k] == b'/' {
                            dp[(ti + 1) * cols + k + 1] = true;
                        }
                    }
                }
                Tok::Star => {
                    dp[(ti + 1) * cols + ci] = true;
                    for k in ci..text.len() {
                        if text[k] == b'/' {
                            break;
                        }
                        dp[(ti + 1) * cols + k + 1] = true;
                    }
                }
                Tok::AnyNonSlash => {
                    if ci < text.len() && text[ci] != b'/' {
                        dp[(ti + 1) * cols + ci + 1] = true;
                    }
                }
                Tok::Lit(ch) => {
                    if ci < text.len() && ch.eq_ignore_ascii_case(&text[ci]) {
                        dp[(ti + 1) * cols + ci + 1] = true;
                    }
                }
            }
        }
    }
    dp[toks.len() * cols + text.len()]
}

fn glob_matches_path(pattern: &str, candidate: &str) -> bool {
    let norm = candidate.replace('\\', "/");
    let base = Path::new(&norm)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&norm);
    for pat in expand_braces(&pattern.replace('\\', "/")) {
        let p = pat.as_bytes();
        if glob_match_bytes(p, norm.as_bytes()) || glob_match_bytes(p, base.as_bytes()) {
            return true;
        }
    }
    false
}

struct ProjectSkillMeta {
    name: String,
    description: String,
    version: Option<String>,
}

fn parse_project_skill_meta(dir_name: &str, raw: &str) -> Option<ProjectSkillMeta> {
    let mut lines = raw.lines();
    if lines.next()?.trim_end_matches('\r') != "---" {
        return None;
    }
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut version: Option<String> = None;
    let mut closed = false;
    for line in lines.by_ref().take(48) {
        let trimmed = line.trim_end_matches('\r');
        if trimmed == "---" {
            closed = true;
            break;
        }
        let Some((key, val)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim().trim_matches(|c| c == '"' || c == '\'').trim();
        if val.is_empty() || val.chars().any(char::is_control) {
            continue;
        }
        match key {
            "name" => name = Some(val.to_owned()),
            "description" => description = Some(val.chars().take(512).collect()),
            "version" => version = Some(val.chars().take(40).collect()),
            _ => {}
        }
    }
    if !closed || !lines.any(|l| !l.trim().is_empty()) {
        return None;
    }
    let name = name.filter(|n| n == dir_name && valid_name(n))?;
    let description = description?;
    Some(ProjectSkillMeta {
        name,
        description,
        version,
    })
}

const PROJECT_SKILL_DIRS: &[&str] = &[".agents/skills", ".claude/skills", ".veyl/skills"];

fn scan_project_skills(
    root: &MutationRoot,
    reserved: &dyn Fn(&Path) -> bool,
) -> Vec<(String, ProjectSkillMeta, String, String)> {
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    for base_rel in PROJECT_SKILL_DIRS {
        if reserved(&root.path().join(base_rel)) {
            continue;
        }
        let Ok(base_fd) = open_beneath_dir(root.directory(), Path::new(base_rel)) else {
            continue;
        };
        let Ok(entries) = Dir::read_from(&base_fd) else {
            continue;
        };
        let mut names = Vec::new();
        for item in entries.flatten() {
            let name = OsStr::from_bytes(item.file_name().to_bytes());
            if let Some(s) = name.to_str()
                && valid_name(s)
            {
                names.push(s.to_owned());
            }
        }
        names.sort();
        for dir_name in names {
            if seen.contains(&dir_name) || found.len() >= 128 {
                continue;
            }
            let Ok(skill_dir) = open_beneath_dir(&base_fd, Path::new(&dir_name)) else {
                continue;
            };
            let Ok((bytes, _)) = read_regular_beneath(&skill_dir, Path::new("SKILL.md"), MAX_SKILL_BYTES)
            else {
                continue;
            };
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            let Some(meta) = parse_project_skill_meta(&dir_name, &text) else {
                continue;
            };
            seen.insert(dir_name);
            let rel_file = format!("{base_rel}/{}/SKILL.md", meta.name);
            found.push(((*base_rel).to_owned(), meta, rel_file, text));
        }
    }
    found
}

pub(crate) fn validate_project_skills(root: &MutationRoot) -> Vec<Value> {
    let mut results = Vec::new();
    for base_rel in PROJECT_SKILL_DIRS {
        let Ok(base_fd) = open_beneath_dir(root.directory(), Path::new(base_rel)) else {
            continue;
        };
        let Ok(entries) = Dir::read_from(&base_fd) else {
            continue;
        };
        let mut names = Vec::new();
        for item in entries.flatten() {
            let name = OsStr::from_bytes(item.file_name().to_bytes());
            if let Some(s) = name.to_str()
                && !matches!(s, "." | "..")
            {
                names.push(s.to_owned());
            }
        }
        names.sort();
        for dir_name in names {
            if results.len() >= 128 {
                break;
            }
            let key = format!("project_skill:{base_rel}/{dir_name}");
            if !valid_name(&dir_name) {
                results.push(json!({"key": key, "valid": false, "source": base_rel, "error": "Invalid skill directory name"}));
                continue;
            }
            let Ok(skill_dir) = open_beneath_dir(&base_fd, Path::new(&dir_name)) else {
                continue;
            };
            match read_regular_beneath(&skill_dir, Path::new("SKILL.md"), MAX_SKILL_BYTES) {
                Ok((bytes, truncated)) => {
                    if truncated {
                        results.push(json!({"key": format!("skill:{dir_name}"), "valid": false, "source": base_rel, "error": "SKILL.md exceeds 200000 byte limit"}));
                        continue;
                    }
                    match String::from_utf8(bytes) {
                        Ok(text) => {
                            if parse_project_skill_meta(&dir_name, &text).is_some() {
                                results.push(json!({"key": format!("skill:{dir_name}"), "valid": true, "source": base_rel}));
                            } else {
                                results.push(json!({"key": format!("skill:{dir_name}"), "valid": false, "source": base_rel, "error": "Invalid SKILL.md frontmatter or empty body"}));
                            }
                        }
                        Err(_) => results.push(json!({"key": format!("skill:{dir_name}"), "valid": false, "source": base_rel, "error": "SKILL.md must be valid UTF-8"})),
                    }
                }
                Err(err) => {
                    results.push(json!({"key": format!("skill:{dir_name}"), "valid": false, "source": base_rel, "error": err}));
                }
            }
        }
    }
    results
}

pub(crate) fn list_project_skill_summaries(root: &MutationRoot) -> Vec<Value> {
    scan_project_skills(root, &|_| false)
        .into_iter()
        .map(|(source_dir, meta, rel_file, _)| {
            json!({
                "key": format!("skill:{}", meta.name),
                "scope": "project",
                "enabled": true,
                "component": {
                    "id": meta.name,
                    "kind": "skill",
                    "name": meta.name,
                    "description": meta.description,
                    "version": meta.version,
                    "source_dir": source_dir,
                    "path": root.path().join(rel_file),
                }
            })
        })
        .collect()
}

fn list_skills(
    args: &serde_json::Map<String, Value>,
    client: &Client,
    reserved: &dyn Fn(&Path) -> bool,
) -> Result<Value, String> {
    if !args.is_empty() {
        return Err("Unexpected list_skills argument".into());
    }
    let root = client
        .mutation_root
        .as_ref()
        .ok_or("Workspace unavailable")?;
    let skills: Vec<Value> = scan_project_skills(root, reserved)
        .into_iter()
        .map(|(source_dir, meta, rel_file, _)| {
            json!({
                "name": meta.name,
                "description": meta.description,
                "version": meta.version,
                "source_dir": source_dir,
                "path": root.path().join(rel_file),
            })
        })
        .collect();
    Ok(json!({ "skills": skills, "count": skills.len() }))
}

fn load_skill(
    args: &serde_json::Map<String, Value>,
    client: &Client,
    reserved: &dyn Fn(&Path) -> bool,
) -> Result<Value, String> {
    if args.keys().any(|k| !matches!(k.as_str(), "name" | "max_bytes")) {
        return Err("Unexpected load_skill argument".into());
    }
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .filter(|n| valid_name(n))
        .ok_or("Invalid or missing skill name")?;
    let max_bytes = match args.get("max_bytes") {
        None => 65_536usize,
        Some(v) => usize::try_from(v.as_u64().ok_or("Invalid max_bytes")?)
            .ok()
            .filter(|n| (1..=MAX_SKILL_BYTES).contains(n))
            .ok_or("Invalid max_bytes")?,
    };
    let root = client
        .mutation_root
        .as_ref()
        .ok_or("Workspace unavailable")?;
    let Some((source_dir, meta, rel_file, text)) = scan_project_skills(root, reserved)
        .into_iter()
        .find(|(_, meta, _, _)| meta.name == name)
    else {
        return Err("Project skill not found".into());
    };
    let (content, truncated) = if text.len() > max_bytes {
        let mut end = max_bytes;
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        (text[..end].to_owned(), true)
    } else {
        (text, false)
    };
    Ok(json!({
        "skill": {
            "name": meta.name,
            "description": meta.description,
            "version": meta.version,
            "source_dir": source_dir,
            "path": root.path().join(rel_file),
        },
        "content": content,
        "truncated": truncated,
    }))
}

fn utc_date_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    // Civil date from Unix epoch days (Howard Hinnant algorithm).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn remember(
    args: &serde_json::Map<String, Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
    reserved: &dyn Fn(&Path) -> bool,
) -> Result<Value, String> {
    if args.keys().any(|k| k != "note") {
        return Err("Unexpected remember argument".into());
    }
    let raw_note = args
        .get("note")
        .and_then(Value::as_str)
        .ok_or("Missing string argument: note")?;
    let trimmed = raw_note.trim();
    if trimmed.is_empty()
        || trimmed.len() > 2000
        || trimmed.as_bytes().contains(&0)
        || trimmed
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("Memory note must be non-empty UTF-8 (<= 2000 bytes)".into());
    }
    let single_line = trimmed
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let root = client
        .mutation_root
        .as_ref()
        .ok_or("Workspace unavailable")?;
    let mem_dir_rel = Path::new(".veyl-memory");
    let mem_dir_abs = root.path().join(mem_dir_rel);
    if reserved(&mem_dir_abs) || operator::policy_path(config, &mem_dir_abs) {
        return Err("Memory path conflicts with protected state".into());
    }
    if settings.skills.as_ref().is_some_and(|s| mem_dir_abs.starts_with(s.path())) {
        return Err("Memory path conflicts with skills directory".into());
    }
    match fs::mkdirat(root.directory(), mem_dir_rel, Mode::from_bits_truncate(0o750)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err("Unable to initialize workspace memory directory".into()),
    }
    let mem_dir = open_beneath_dir(root.directory(), mem_dir_rel)
        .map_err(|_| "Memory directory must be an unaliased directory")?;

    let existing = match fs::openat2(
        &mem_dir,
        Path::new("MEMORY.md"),
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    ) {
        Ok(handle) => {
            let stat = fs::fstat(&handle).map_err(|_| "Unable to stat MEMORY.md")?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
                return Err("MEMORY.md must be a regular unaliased file".into());
            }
            let file = reopen_regular(&handle, OFlags::RDONLY | OFlags::NONBLOCK)
                .map_err(|_| "Unable to open MEMORY.md")?;
            let mut buf = Vec::new();
            File::from(file)
                .take(MAX_MEMORY_BYTES as u64 + 1)
                .read_to_end(&mut buf)
                .map_err(|_| "Unable to read MEMORY.md")?;
            if buf.len() > MAX_MEMORY_BYTES {
                return Err("Auto-memory capacity limit reached (25000 bytes)".into());
            }
            String::from_utf8(buf).map_err(|_| "Existing MEMORY.md is not valid UTF-8")?
        }
        Err(rustix::io::Errno::NOENT) => String::new(),
        Err(_) => return Err("Unable to access MEMORY.md".into()),
    };

    let prefix = if existing.is_empty() {
        "# Auto memory (cross-session notes)\n\n"
    } else if existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let line = format!("- {}: {single_line}\n", utc_date_string());
    let updated = format!("{existing}{prefix}{line}");
    let line_count = updated.lines().count();
    if updated.len() > MAX_MEMORY_BYTES || line_count > MAX_MEMORY_LINES {
        return Err("Auto-memory limit exceeded (max 200 lines / 25000 bytes)".into());
    }

    let tmp_name = format!(
        ".MEMORY.md.stage.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let tmp_fd = fs::openat2(
        &mem_dir,
        Path::new(&tmp_name),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|_| "Unable to create staged memory file")?;
    {
        let mut f = File::from(tmp_fd);
        if f.write_all(updated.as_bytes()).is_err() || f.sync_all().is_err() {
            let _ = fs::unlinkat(&mem_dir, Path::new(&tmp_name), fs::AtFlags::empty());
            return Err("Failed writing staged memory file".into());
        }
    }
    if fs::renameat(&mem_dir, Path::new(&tmp_name), &mem_dir, Path::new("MEMORY.md")).is_err() {
        let _ = fs::unlinkat(&mem_dir, Path::new(&tmp_name), fs::AtFlags::empty());
        return Err("Failed publishing MEMORY.md".into());
    }
    let _ = fs::fsync(&mem_dir);

    Ok(json!({
        "saved_to": mem_dir_abs.join("MEMORY.md"),
        "note": single_line,
        "bytes": updated.len(),
        "lines": line_count,
    }))
}

fn canonical_with_tail(input: &Path) -> Result<PathBuf, String> {
    match std::fs::canonicalize(input) {
        Ok(p) => Ok(p),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut missing = Vec::new();
            let mut cur = input;
            while let Some(name) = cur.file_name() {
                missing.push(name.to_owned());
                let Some(parent) = cur.parent() else {
                    return Err("Unable to canonicalize path".into());
                };
                if let Ok(resolved) = std::fs::canonicalize(parent) {
                    let mut out = resolved;
                    for seg in missing.into_iter().rev() {
                        out.push(seg);
                    }
                    return Ok(out);
                }
                cur = parent;
            }
            Err("Unable to canonicalize path".into())
        }
        Err(_) => Err("Unable to inspect target path".into()),
    }
}

fn generated_marker(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut buf = [0u8; 1024];
    let n = file.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    for line in text.lines().take(5) {
        let trimmed = line.trim();
        let comment = trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with(';')
            || trimmed.starts_with("/*");
        if !comment {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if (lower.contains("auto-generated")
            || lower.contains("autogenerated")
            || lower.contains("generated by"))
            && lower.contains("do not edit")
        {
            return Some(trimmed.chars().take(200).collect());
        }
    }
    None
}

fn run_readonly_cmd(bin: &str, args: &[&str], dest_home: &Path) -> Option<(Option<i32>, String, String)> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", dest_home)
        .current_dir("/");
    let (status, stdout, stderr) =
        crate::linux_command::capture_with_input(&mut cmd, &[], 16_384, Duration::from_secs(3)).ok()?;
    Some((
        status.code(),
        String::from_utf8_lossy(&stdout).trim().to_owned(),
        String::from_utf8_lossy(&stderr).trim().to_owned(),
    ))
}

fn chezmoi_inspect(
    args: &serde_json::Map<String, Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
    reserved: &dyn Fn(&Path) -> bool,
) -> Result<Value, String> {
    if args.keys().any(|k| k != "path") {
        return Err("Unexpected chezmoi_inspect argument".into());
    }
    let raw = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or("Missing string argument: path")?;
    validate_raw_path(raw)?;

    let root = client
        .mutation_root
        .as_ref()
        .ok_or("Workspace unavailable")?;
    let requested = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        root.path().join(raw)
    };
    let canonical = canonical_with_tail(&requested)?;
    let mode = client.mode;
    if mode != mcp_gateway::security::policy::ExecutionMode::Full
        && (operator::policy_path(config, &requested)
            || operator::policy_path(config, &canonical)
            || reserved(&requested)
            || reserved(&canonical))
    {
        return Err("Protected path cannot be inspected".into());
    }
    match mode {
        mcp_gateway::security::policy::ExecutionMode::Full => {}
        mcp_gateway::security::policy::ExecutionMode::BroadYolo => {
            let broad = crate::jobs::broad::Broad::prepare(config, settings)?;
            broad
                .file_parent(&canonical, false)
                .map_err(|_| "Protected path cannot be inspected")?;
        }
        _ => {
            let allowed = std::iter::once(root.path())
                .chain(client.extra_roots.iter().map(MutationRoot::path))
                .any(|allowed_root| {
                    canonical.starts_with(allowed_root) || requested.starts_with(allowed_root)
                });
            if !allowed {
                return Err("Path outside approved workspace".into());
            }
        }
    }

    let home_dir = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let source_raw = std::env::var_os("VEYL_CHEZMOI_SOURCE_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home_dir.join(".local/share/chezmoi"));
    let dest_raw = std::env::var_os("VEYL_CHEZMOI_DESTINATION_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or(home_dir);
    let source_dir = canonical_with_tail(&source_raw).unwrap_or(source_raw);
    let dest_dir = canonical_with_tail(&dest_raw).unwrap_or(dest_raw);

    if canonical.starts_with(&source_dir) && !requested.starts_with(&source_dir) {
        return Ok(json!({
            "requestedPath": requested,
            "canonicalPath": canonical,
            "kind": "managed_target",
            "sourcePath": canonical,
            "sourceIsTemplate": canonical.to_string_lossy().ends_with(".tmpl"),
            "explanation": "Symlink alias to chezmoi source; edit its canonical source path.",
        }));
    }
    if canonical.starts_with(&source_dir) {
        return Ok(json!({
            "requestedPath": requested,
            "canonicalPath": canonical,
            "kind": "source",
            "sourcePath": canonical,
            "sourceIsTemplate": canonical.to_string_lossy().ends_with(".tmpl"),
            "explanation": "Chezmoi source; edit explicitly and validate before applying.",
        }));
    }
    if !canonical.starts_with(&dest_dir) {
        return Ok(json!({
            "requestedPath": requested,
            "canonicalPath": canonical,
            "kind": "outside_destination",
            "explanation": "Not inside the chezmoi destination; normal filesystem policy applies.",
        }));
    }

    if let Some(marker) = generated_marker(&canonical) {
        return Ok(json!({
            "requestedPath": requested,
            "canonicalPath": canonical,
            "kind": "generated_target",
            "generatedMarker": marker,
            "explanation": "Generated output with a do-not-edit header. Use the owning generator/helper.",
        }));
    }

    let chezmoi_bin = "/usr/bin/chezmoi";
    if !Path::new(chezmoi_bin).is_file() || !source_dir.is_dir() {
        return Ok(json!({
            "requestedPath": requested,
            "canonicalPath": canonical,
            "kind": "unmanaged",
            "explanation": "Chezmoi integration is unavailable or not initialized on this host.",
        }));
    }

    let Some((code, stdout, stderr)) = run_readonly_cmd(
        chezmoi_bin,
        &[
            "--source",
            &source_dir.to_string_lossy(),
            "--destination",
            &dest_dir.to_string_lossy(),
            "source-path",
            &canonical.to_string_lossy(),
        ],
        &dest_dir,
    ) else {
        return Ok(json!({
            "requestedPath": requested,
            "canonicalPath": canonical,
            "kind": "unavailable",
            "explanation": "Cannot execute read-only chezmoi lookup.",
        }));
    };

    if code == Some(0) {
        let first_line = stdout.lines().next().unwrap_or("").trim();
        let resolved_source = PathBuf::from(first_line);
        if !resolved_source.starts_with(&source_dir) {
            return Ok(json!({
                "requestedPath": requested,
                "canonicalPath": canonical,
                "kind": "unavailable",
                "explanation": "Chezmoi returned an unexpected source outside its configured directory.",
            }));
        }
        let rel_source = resolved_source
            .strip_prefix(&source_dir)
            .unwrap_or(&resolved_source);
        let source_dirty = run_readonly_cmd(
            "/usr/bin/git",
            &[
                "-C",
                &source_dir.to_string_lossy(),
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "status",
                "--porcelain",
                "--",
                &rel_source.to_string_lossy(),
            ],
            &dest_dir,
        )
        .and_then(|(c, out, _)| (c == Some(0)).then_some(!out.is_empty()));
        let target_status = run_readonly_cmd(
            chezmoi_bin,
            &[
                "--source",
                &source_dir.to_string_lossy(),
                "--destination",
                &dest_dir.to_string_lossy(),
                "--no-pager",
                "status",
                &canonical.to_string_lossy(),
            ],
            &dest_dir,
        )
        .and_then(|(c, out, _)| {
            (c == Some(0)).then(|| if out.is_empty() { "in_sync".to_owned() } else { out })
        });
        return Ok(json!({
            "requestedPath": requested,
            "canonicalPath": canonical,
            "kind": "managed_target",
            "sourcePath": resolved_source,
            "sourceIsTemplate": resolved_source.to_string_lossy().ends_with(".tmpl"),
            "sourceDirty": source_dirty,
            "targetStatus": target_status,
            "explanation": "Managed target. Do not edit the live path; edit its chezmoi source and apply separately after validation.",
        }));
    }

    let combined = format!("{stderr} {stdout}").to_ascii_lowercase();
    if combined.contains("not managed") || combined.contains("not in source state") {
        return Ok(json!({
            "requestedPath": requested,
            "canonicalPath": canonical,
            "kind": "unmanaged",
            "explanation": "Unmanaged destination file. Do not auto-adopt it into chezmoi.",
        }));
    }
    Ok(json!({
        "requestedPath": requested,
        "canonicalPath": canonical,
        "kind": "unavailable",
        "explanation": if stderr.is_empty() { "Chezmoi lookup failed".to_owned() } else { format!("Chezmoi lookup failed: {stderr}") },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_recursive_and_brace_patterns() {
        assert!(glob_matches_path("src/**/*.rs", "src/inspection/extra.rs"));
        assert!(glob_matches_path("*.{ts,rs}", "src/lib/main.rs"));
        assert!(!glob_matches_path("docs/**/*.md", "src/main.rs"));
        assert!(glob_matches_path("Cargo.toml", "Cargo.toml"));
        assert!(glob_matches_path("docs/?.md", "docs/a.md"));
        assert!(!glob_matches_path("docs/?.md", "docs/ab.md"));
    }

    #[test]
    fn rule_frontmatter_parses_paths_and_body() {
        let doc = "---\npaths:\n  - \"src/**/*.rs\"\n  - '*.py'\n---\n# Rust rule\nAlways validate paths.\n";
        let (paths, body) = parse_rule_frontmatter(doc).expect("valid rule");
        assert_eq!(paths, vec!["src/**/*.rs", "*.py"]);
        assert!(body.contains("Always validate paths."));

        let inline = "---\npaths: [tests/*.py, docs/*.md]\n---\nTest body\n";
        let (paths, body) = parse_rule_frontmatter(inline).expect("inline paths");
        assert_eq!(paths, vec!["tests/*.py", "docs/*.md"]);
        assert_eq!(body, "Test body");
    }

    #[test]
    fn project_skill_frontmatter_requires_matching_name_and_description() {
        let valid = "---\nname: demo-skill\ndescription: Helps test workspace skills\nallowed-tools: read_file\n---\nInstructions here.\n";
        let meta = parse_project_skill_meta("demo-skill", valid).expect("valid skill");
        assert_eq!(meta.name, "demo-skill");
        assert_eq!(meta.description, "Helps test workspace skills");
        assert!(parse_project_skill_meta("other-skill", valid).is_none());
    }
}
