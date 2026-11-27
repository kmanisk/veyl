//! Confined, audited execution for the 12 structured Git tools.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use mcp_gateway::security::linux_fs::{open_absolute_dir, open_beneath_dir};
use mcp_gateway::security::policy::ExecutionMode;
use serde_json::{Map, Value, json};

use crate::http::admission::{Client, Configuration};
use crate::jobs::GitToolRequest;
use crate::protected_paths::{Kind, OPTIONAL_DEFAULTS, READONLY_DEFAULTS, is_mandatory};
use crate::tools::registry::{Tool, tool_text};

fn pathspec_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('-')
        && !value.starts_with('/')
        && !value.chars().any(char::is_control)
        && !value.split('/').any(|part| part == "..")
        && !value.starts_with(':')
}

fn ref_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && !value.starts_with('-')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || matches!(byte, b'~' | b'^' | b':' | b'*' | b'?' | b'[' | b'\\')
        })
}

fn remote_valid(value: &str) -> bool {
    ref_valid(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn confirmed(tool: &str, mode: Option<&str>, confirm: bool) -> bool {
    confirm
        || !(matches!(tool, "git_restore" | "git_pull" | "git_push")
            || tool == "git_reset" && mode == Some("hard"))
}

fn validate(tool: &str, value: &Value) -> Result<(), &'static str> {
    let args = value.as_object().ok_or("expected an object")?;
    let allowed: &[&str] = match tool {
        "git_status" => &["path"],
        "git_diff" => &["path", "staged", "file"],
        "git_log" => &["path", "count"],
        "git_add" => &["path", "files", "all"],
        "git_commit" => &["path", "message", "stage_all"],
        "git_branch" => &["path", "action", "name"],
        "git_checkout" => &["path", "branch"],
        "git_restore" => &["path", "files", "source", "confirm"],
        "git_stash" => &["path", "action", "message"],
        "git_reset" => &["path", "mode", "ref", "confirm"],
        "git_pull" => &["path", "remote", "branch", "confirm"],
        "git_push" => &["path", "remote", "branch", "set_upstream", "confirm"],
        _ => return Err("unknown tool"),
    };
    if args.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("unexpected field");
    }
    for key in ["path", "message"] {
        if let Some(value) = args.get(key) {
            let text = value.as_str().ok_or("expected string")?;
            if text.contains('\0')
                || (key == "path" && text.len() > 4096)
                || (key == "message" && (text.is_empty() || text.len() > 8192))
            {
                return Err("invalid string");
            }
        }
    }
    if tool == "git_commit" && !args.contains_key("message") {
        return Err("message required");
    }
    for key in ["staged", "all", "stage_all", "confirm", "set_upstream"] {
        if args.get(key).is_some_and(|v| !v.is_boolean()) {
            return Err("expected boolean");
        }
    }
    if let Some(value) = args.get("count")
        && !value.as_u64().is_some_and(|n| (1..=500).contains(&n))
    {
        return Err("invalid count");
    }
    if let Some(value) = args.get("file")
        && !value.as_str().is_some_and(pathspec_valid)
    {
        return Err("invalid file");
    }
    if let Some(value) = args.get("files") {
        let files = value.as_array().ok_or("expected files array")?;
        if files.len() > 64
            || (tool == "git_restore" && files.is_empty())
            || files
                .iter()
                .any(|v| !v.as_str().is_some_and(pathspec_valid))
        {
            return Err("invalid files");
        }
    } else if tool == "git_restore" {
        return Err("files required");
    }
    for key in ["name", "branch", "source", "ref"] {
        if args
            .get(key)
            .is_some_and(|v| !v.as_str().is_some_and(ref_valid))
        {
            return Err("invalid ref");
        }
    }
    if tool == "git_checkout" && !args.contains_key("branch") {
        return Err("branch required");
    }
    if args
        .get("remote")
        .is_some_and(|v| !v.as_str().is_some_and(remote_valid))
    {
        return Err("invalid remote");
    }
    if let Some(value) = args.get("action") {
        let action = value.as_str().ok_or("invalid action")?;
        let valid = match tool {
            "git_branch" => ["list", "create", "switch", "create-and-switch"].contains(&action),
            "git_stash" => ["list", "push", "pop", "apply"].contains(&action),
            _ => false,
        };
        if !valid || (tool == "git_branch" && action != "list" && !args.contains_key("name")) {
            return Err("invalid action");
        }
    }
    let mode = match args.get("mode") {
        Some(value) => {
            let mode = value.as_str().ok_or("invalid mode")?;
            if !["soft", "mixed", "hard"].contains(&mode) {
                return Err("invalid mode");
            }
            Some(mode)
        }
        None => None,
    };
    if !confirmed(
        tool,
        mode,
        args.get("confirm")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    ) {
        return Err("confirmation required");
    }
    Ok(())
}

pub(crate) fn run(
    tool: Tool,
    args: Option<&Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
) -> Value {
    match execute(tool, args, config, settings, client) {
        Ok(value) => tool_text(false, &value.to_string()),
        Err(msg) => tool_text(true, &msg),
    }
}

fn is_readonly_op(tool: Tool, args: &Map<String, Value>) -> bool {
    match tool {
        Tool::GitStatus | Tool::GitDiff | Tool::GitLog => true,
        Tool::GitBranch => args.get("action").and_then(Value::as_str).unwrap_or("list") == "list",
        Tool::GitStash => args.get("action").and_then(Value::as_str).unwrap_or("list") == "list",
        _ => false,
    }
}

fn is_protected(path: &Path, config: &Path, settings: &Configuration, readonly: bool) -> bool {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if is_mandatory(config, settings, path)
        || settings
            .skills
            .as_ref()
            .is_some_and(|skills| path.starts_with(skills.path()))
        || settings
            .protected_paths
            .selected(Kind::Optional)
            .iter()
            .any(|rule| path.starts_with(&rule.path))
        || home.as_ref().is_some_and(|home| {
            OPTIONAL_DEFAULTS
                .iter()
                .any(|dir| path.starts_with(home.join(dir)))
        })
    {
        return true;
    }
    if !readonly
        && (settings
            .protected_paths
            .selected(Kind::ReadOnly)
            .iter()
            .any(|rule| path.starts_with(&rule.path))
            || home.as_ref().is_some_and(|home| {
                READONLY_DEFAULTS
                    .iter()
                    .any(|dir| path.starts_with(home.join(dir)))
            }))
    {
        return true;
    }
    false
}



fn resolve_repo(
    requested: Option<&str>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
    readonly: bool,
) -> Result<PathBuf, String> {
    let base = match requested {
        None => client.root.clone(),
        Some(raw) => {
            let p = Path::new(raw);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                client.root.join(p)
            }
        }
    };
    let canonical = fs::canonicalize(&base).map_err(|_| "Repository directory unavailable")?;
    if !canonical.is_dir() || is_protected(&canonical, config, settings, readonly) {
        return Err("Protected or unavailable repository directory".into());
    }

    match client.mode {
        ExecutionMode::Yolo => {
            let repo = find_git_repo_bounded(&canonical, None)?;
            if is_protected(&repo, config, settings, readonly) {
                return Err("Protected repository root".into());
            }
            let _ = open_absolute_dir(&repo).map_err(|_| "Cannot open repository directory")?;
            Ok(repo)
        }
        _ => {
            let mut roots: Vec<&Path> = Vec::new();
            if let Some(root) = client.mutation_root.as_ref() {
                roots.push(root.path());
            }
            for extra in &client.extra_roots {
                roots.push(extra.path());
            }
            let matching_root = roots
                .into_iter()
                .find(|allowed| canonical.starts_with(allowed))
                .ok_or("Operation outside an approved scope")?;
            let rel = canonical
                .strip_prefix(matching_root)
                .map_err(|_| "Operation outside an approved scope")?;
            let root_fd =
                open_absolute_dir(matching_root).map_err(|_| "Approved workspace unavailable")?;
            let _ = open_beneath_dir(&root_fd, rel)
                .map_err(|_| "Operation outside an approved scope")?;
            let repo = find_git_repo_bounded(&canonical, Some(matching_root))?;
            if is_protected(&repo, config, settings, readonly) {
                return Err("Protected repository root".into());
            }
            Ok(repo)
        }
    }
}

fn find_git_repo_bounded(start: &Path, boundary: Option<&Path>) -> Result<PathBuf, String> {
    let mut cur = start;
    loop {
        let dot_git = cur.join(".git");
        if let Ok(meta) = fs::symlink_metadata(&dot_git)
            && !meta.file_type().is_symlink()
            && meta.is_dir()
        {
            return Ok(cur.to_path_buf());
        }
        if boundary.is_some_and(|b| cur == b) {
            break;
        }
        let Some(parent) = cur.parent() else {
            break;
        };
        if boundary.is_some_and(|b| !parent.starts_with(b)) {
            break;
        }
        cur = parent;
    }
    Err("Target directory is not inside an approved Git repository with in-tree .git".into())
}

fn execute(
    tool: Tool,
    args: Option<&Value>,
    config: &Path,
    settings: &Configuration,
    client: &Client,
) -> Result<Value, String> {
    let empty_obj = Value::Object(Map::new());
    let val = args.unwrap_or(&empty_obj);
    validate(tool.name(), val).map_err(|e| format!("Invalid {}: {e}", tool.name()))?;
    let args = val.as_object().ok_or("Expected arguments object")?;

    let network = matches!(tool, Tool::GitPull | Tool::GitPush);
    if network && client.mode != ExecutionMode::Yolo {
        return Err("Remote Git operations require YOLO mode".into());
    }

    let readonly = is_readonly_op(tool, args);
    let repo = resolve_repo(
        args.get("path").and_then(Value::as_str),
        config,
        settings,
        client,
        readonly,
    )?;

    let (argv, stage_all, meta) = build_argv(tool, args, &repo)?;
    if stage_all {
        let add_spec = GitToolRequest {
            repo: repo.clone(),
            argv: vec!["add".into(), "-A".into()],
            readonly: false,
            network: false,
            native: client.mode == ExecutionMode::Yolo,
        };
        let add_bytes =
            serde_json::to_vec(&add_spec).map_err(|_| "Cannot encode git add request")?;
        let exe = std::env::current_exe().map_err(|_| "Gateway executable unavailable")?;
        let mut add_cmd = Command::new(exe);
        add_cmd.env_clear().arg("--git-tool-worker");
        let (add_status, add_out, _) = crate::linux_command::capture_with_input(
            &mut add_cmd,
            &add_bytes,
            131_072,
            Duration::from_secs(16),
        )
        .map_err(|_| "Git staging failed or exceeded limit")?;
        if !add_status.success() {
            return Err("Git staging refused by confinement worker".into());
        }
        let add_reply: Value =
            serde_json::from_slice(&add_out).map_err(|_| "Invalid git worker reply")?;
        if add_reply["exit_code"].as_i64().unwrap_or(1) != 0 {
            let msg = add_reply["stderr"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    add_reply["stdout"]
                        .as_str()
                        .filter(|s| !s.trim().is_empty())
                })
                .unwrap_or("git add failed");
            return Err(msg.trim().to_owned());
        }
    }
    let spec = GitToolRequest {
        repo: repo.clone(),
        argv,
        readonly,
        network,
        native: client.mode == ExecutionMode::Yolo,
    };
    let spec_bytes = serde_json::to_vec(&spec).map_err(|_| "Cannot encode git worker request")?;
    let exe = std::env::current_exe().map_err(|_| "Gateway executable unavailable")?;
    let mut cmd = Command::new(exe);
    cmd.env_clear().arg("--git-tool-worker");
    let (status, stdout, _) = crate::linux_command::capture_with_input(
        &mut cmd,
        &spec_bytes,
        131_072,
        Duration::from_secs(16),
    )
    .map_err(|_| "Git operation failed or exceeded limit")?;
    if !status.success() {
        return Err("Git operation refused by confinement worker".into());
    }
    let reply: Value = serde_json::from_slice(&stdout).map_err(|_| "Invalid git worker reply")?;
    let exit_code = reply["exit_code"].as_i64().unwrap_or(1);
    let out = reply["stdout"].as_str().unwrap_or("").trim();
    let err = reply["stderr"].as_str().unwrap_or("").trim();
    if exit_code != 0 {
        let msg = if !err.is_empty() {
            err
        } else if !out.is_empty() {
            out
        } else {
            "git command failed"
        };
        return Err(msg.to_owned());
    }
    Ok(format_result(tool, meta, out, err))
}

enum Meta {
    Status(PathBuf),
    Diff {
        path: PathBuf,
        staged: bool,
        file: Option<String>,
    },
    Log {
        path: PathBuf,
        count: u64,
    },
    Add {
        path: PathBuf,
        files: Vec<String>,
    },
    Commit {
        path: PathBuf,
        message: String,
    },
    Branch {
        path: PathBuf,
        action: String,
        name: Option<String>,
    },
    Checkout {
        path: PathBuf,
        branch: String,
    },
    Restore {
        path: PathBuf,
        files: Vec<String>,
        source: String,
    },
    Stash {
        path: PathBuf,
        action: String,
    },
    Reset {
        path: PathBuf,
        mode: String,
        git_ref: String,
    },
    Pull {
        path: PathBuf,
        remote: String,
        branch: Option<String>,
    },
    Push {
        path: PathBuf,
        remote: String,
        branch: Option<String>,
        set_upstream: bool,
    },
}

fn build_argv(
    tool: Tool,
    args: &Map<String, Value>,
    repo: &Path,
) -> Result<(Vec<String>, bool, Meta), String> {
    match tool {
        Tool::GitStatus => Ok((
            vec![
                "status".into(),
                "--short".into(),
                "--branch".into(),
                "--untracked-files=normal".into(),
            ],
            false,
            Meta::Status(repo.to_path_buf()),
        )),
        Tool::GitDiff => {
            let staged = args.get("staged").and_then(Value::as_bool).unwrap_or(false);
            let file = args.get("file").and_then(Value::as_str).map(str::to_owned);
            let mut argv = vec![
                "diff".into(),
                "--no-ext-diff".into(),
                "--no-textconv".into(),
            ];
            if staged {
                argv.push("--staged".into());
            }
            if let Some(ref f) = file {
                argv.push("--".into());
                argv.push(f.clone());
            }
            Ok((
                argv,
                false,
                Meta::Diff {
                    path: repo.to_path_buf(),
                    staged,
                    file,
                },
            ))
        }
        Tool::GitLog => {
            let count = args.get("count").and_then(Value::as_u64).unwrap_or(10);
            Ok((
                vec![
                    "log".into(),
                    "--oneline".into(),
                    "-n".into(),
                    count.to_string(),
                ],
                false,
                Meta::Log {
                    path: repo.to_path_buf(),
                    count,
                },
            ))
        }
        Tool::GitAdd => {
            let all = args.get("all").and_then(Value::as_bool).unwrap_or(true);
            let files: Vec<String> = args
                .get("files")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let mut argv = vec!["add".into()];
            let label = if !files.is_empty() {
                argv.push("--".into());
                argv.extend(files.iter().cloned());
                files
            } else if all {
                argv.push("-A".into());
                vec!["-A".into()]
            } else {
                return Err("Specify files or set all=true".into());
            };
            Ok((
                argv,
                false,
                Meta::Add {
                    path: repo.to_path_buf(),
                    files: label,
                },
            ))
        }
        Tool::GitCommit => {
            let message = args["message"].as_str().unwrap().to_owned();
            let stage_all = args
                .get("stage_all")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let argv = vec!["commit".into(), "-m".into(), message.clone()];
            Ok((
                argv,
                stage_all,
                Meta::Commit {
                    path: repo.to_path_buf(),
                    message,
                },
            ))
        }
        Tool::GitBranch => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("list")
                .to_owned();
            let name = args.get("name").and_then(Value::as_str).map(str::to_owned);
            let argv = match action.as_str() {
                "list" => vec!["branch".into(), "--all".into()],
                "create" => vec!["branch".into(), name.clone().unwrap()],
                "switch" => vec!["switch".into(), name.clone().unwrap()],
                "create-and-switch" => vec!["switch".into(), "-c".into(), name.clone().unwrap()],
                _ => unreachable!(),
            };
            Ok((
                argv,
                false,
                Meta::Branch {
                    path: repo.to_path_buf(),
                    action,
                    name,
                },
            ))
        }
        Tool::GitCheckout => {
            let branch = args["branch"].as_str().unwrap().to_owned();
            Ok((
                vec!["switch".into(), branch.clone()],
                false,
                Meta::Checkout {
                    path: repo.to_path_buf(),
                    branch,
                },
            ))
        }
        Tool::GitRestore => {
            let files: Vec<String> = args["files"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let source = args
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("HEAD")
                .to_owned();
            let mut argv = vec![
                "restore".into(),
                "--source".into(),
                source.clone(),
                "--".into(),
            ];
            argv.extend(files.iter().cloned());
            Ok((
                argv,
                false,
                Meta::Restore {
                    path: repo.to_path_buf(),
                    files,
                    source,
                },
            ))
        }
        Tool::GitStash => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("list")
                .to_owned();
            let mut argv = vec!["stash".into(), action.clone()];
            if action == "push"
                && let Some(msg) = args.get("message").and_then(Value::as_str)
            {
                argv.push("-m".into());
                argv.push(msg.to_owned());
            }
            Ok((
                argv,
                false,
                Meta::Stash {
                    path: repo.to_path_buf(),
                    action,
                },
            ))
        }
        Tool::GitReset => {
            let mode = args
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("mixed")
                .to_owned();
            let git_ref = args
                .get("ref")
                .and_then(Value::as_str)
                .unwrap_or("HEAD")
                .to_owned();
            Ok((
                vec!["reset".into(), format!("--{mode}"), git_ref.clone()],
                false,
                Meta::Reset {
                    path: repo.to_path_buf(),
                    mode,
                    git_ref,
                },
            ))
        }
        Tool::GitPull => {
            let remote = args
                .get("remote")
                .and_then(Value::as_str)
                .unwrap_or("origin")
                .to_owned();
            let branch = args
                .get("branch")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let mut argv = vec!["pull".into(), remote.clone()];
            if let Some(ref b) = branch {
                argv.push(b.clone());
            }
            Ok((
                argv,
                false,
                Meta::Pull {
                    path: repo.to_path_buf(),
                    remote,
                    branch,
                },
            ))
        }
        Tool::GitPush => {
            let remote = args
                .get("remote")
                .and_then(Value::as_str)
                .unwrap_or("origin")
                .to_owned();
            let branch = args
                .get("branch")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let set_upstream = args
                .get("set_upstream")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let mut argv = vec!["push".into()];
            if set_upstream {
                argv.push("-u".into());
            }
            argv.push(remote.clone());
            if let Some(ref b) = branch {
                argv.push(b.clone());
            }
            Ok((
                argv,
                false,
                Meta::Push {
                    path: repo.to_path_buf(),
                    remote,
                    branch,
                    set_upstream,
                },
            ))
        }
        _ => Err("Unsupported git tool".into()),
    }
}

fn format_result(_tool: Tool, meta: Meta, out: &str, err: &str) -> Value {
    let text = if out.is_empty() { err } else { out };
    match meta {
        Meta::Status(path) => json!({
            "path": path,
            "output": if out.is_empty() { "Clean working tree" } else { out }
        }),
        Meta::Diff { path, staged, file } => json!({
            "path": path,
            "staged": staged,
            "file": file,
            "output": if out.is_empty() { "No changes" } else { out }
        }),
        Meta::Log { path, count } => {
            let commits: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
            json!({ "path": path, "count": count, "commits": commits })
        }
        Meta::Add { path, files } => json!({ "path": path, "files": files, "output": out }),
        Meta::Commit { path, message } => {
            json!({ "path": path, "message": message, "output": out })
        }
        Meta::Branch { path, action, name } => {
            json!({ "path": path, "action": action, "name": name, "output": text })
        }
        Meta::Checkout { path, branch } => {
            json!({ "path": path, "branch": branch, "output": text })
        }
        Meta::Restore {
            path,
            files,
            source,
        } => {
            json!({ "path": path, "files": files, "source": source, "output": if text.is_empty() { "Restored" } else { text } })
        }
        Meta::Stash { path, action } => json!({ "path": path, "action": action, "output": text }),
        Meta::Reset {
            path,
            mode,
            git_ref,
        } => {
            json!({ "path": path, "mode": mode, "ref": git_ref, "output": text })
        }
        Meta::Pull {
            path,
            remote,
            branch,
        } => {
            json!({ "path": path, "remote": remote, "branch": branch, "output": text })
        }
        Meta::Push {
            path,
            remote,
            branch,
            set_upstream,
        } => json!({
            "path": path, "remote": remote, "branch": branch, "set_upstream": set_upstream, "output": text
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_arguments_fail_closed() {
        assert!(validate("git_status", &json!({})).is_ok());
        assert!(validate("git_status", &json!({"extra": true})).is_err());
        assert!(validate("git_log", &json!({"count": 501})).is_err());
        assert!(validate("git_commit", &json!({"message": ""})).is_err());
        assert!(validate("git_restore", &json!({"files": ["x"]})).is_err());
        assert!(validate("git_restore", &json!({"files": ["x"], "confirm": true})).is_ok());
        assert!(validate("git_push", &json!({"remote": "ext::bad", "confirm": true})).is_err());
        assert!(validate("git_branch", &json!({"action": "create"})).is_err());
        assert!(validate("git_reset", &json!({"mode": "hard"})).is_err());
    }

    #[test]
    fn pathspec_rejects_traversal_and_option_injection() {
        for value in [
            "",
            "../a",
            "a/../b",
            "/tmp/x",
            "--all",
            ":(top)secret",
            "a\0b",
            "a\nb",
        ] {
            assert!(!pathspec_valid(value), "{value:?}");
        }
        assert!(!pathspec_valid(&"x".repeat(1025)));
        assert!(pathspec_valid("src/main.rs"));
    }

    #[test]
    fn refs_and_remotes_reject_injection() {
        for value in [
            "", "-x", "a..b", "a@{b", "a b", "a\0b", "a~b", "a^b", "a:b", "a*b", "a?b", "a[b",
            "a\\b", "é",
        ] {
            assert!(!ref_valid(value), "{value:?}");
        }
        assert!(!ref_valid(&"x".repeat(129)));
        assert!(ref_valid("feature/test"));
        assert!(remote_valid("origin-1"));
        for value in ["https://example.com/repo", "ext::command", "a/b", "-origin"] {
            assert!(!remote_valid(value), "{value:?}");
        }
    }

    #[test]
    fn destructive_confirmation_is_required() {
        for tool in ["git_restore", "git_pull", "git_push"] {
            assert!(!confirmed(tool, None, false));
            assert!(confirmed(tool, None, true));
        }
        assert!(!confirmed("git_reset", Some("hard"), false));
        assert!(confirmed("git_reset", Some("mixed"), false));
        assert!(confirmed("git_reset", Some("hard"), true));
    }
}
