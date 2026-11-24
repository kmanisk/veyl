//! Local convenience commands. Explicit configuration always takes precedence.
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("HOME must be absolute".into())
}

fn default_config(home: &Path) -> Result<PathBuf, String> {
    let current = home.join(".local/state/veyl/clients.json");
    let legacy = home.join(".config/mcp-gateway/clients.json");
    match (current.try_exists(), legacy.try_exists()) {
        (Ok(true), Ok(false)) => Ok(current),
        (Ok(false), Ok(true)) => Ok(legacy),
        (Ok(true), Ok(true)) => Err("Two Veyl policies found; specify --config PATH".into()),
        (Ok(false), Ok(false)) => {
            Err("No Veyl configuration found; specify --config PATH or follow README setup".into())
        }
        _ => Err("Cannot inspect default configuration paths".into()),
    }
}

pub(crate) fn normalize(mut args: Vec<OsString>) -> Result<Vec<OsString>, String> {
    if args == ["mode"] {
        args.push("list".into());
    }
    if args == ["dashboard"] {
        args.push("open".into());
    }
    if args.first().is_some_and(|arg| arg == "ui") {
        args[0] = "dashboard".into();
        args.insert(1, "open".into());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "run" || arg == "portable")
    {
        let portable = args[0] == "portable";
        if args.iter().any(|arg| arg == "--help") {
            println!(
                "usage: veyl run|portable [--config PATH] [--listen 127.0.0.1:PORT]\nRun in the foreground; portable first stops and disables the matching Veyl user service."
            );
            // Reuse the harmless top-level help path rather than launching.
            return Ok(vec!["--help".into()]);
        }
        if !portable {
            args[0] = "http".into();
        }
        if !args.iter().any(|arg| arg == "--listen") {
            args.extend(["--listen".into(), "127.0.0.1:7331".into()]);
        }
    } else if !matches!(
        args.first().and_then(|arg| arg.to_str()),
        Some(
            "mode"
                | "dashboard"
                | "serve"
                | "skills"
                | "mcp-servers"
                | "service"
                | "connect"
                | "diagnostics"
        )
    ) {
        return Ok(args);
    }
    if args.iter().any(|arg| arg == "--config" || arg == "--help")
        || (args.len() < 2 && args[0] != "connect")
        || (args[0] == "service" && matches!(args[1].to_str(), Some("status" | "diagnostics")))
    {
        return Ok(args);
    }
    let home = home()?;
    args.extend([
        OsString::from("--config"),
        default_config(&home)?.into_os_string(),
    ]);
    Ok(args)
}

/// Explicit local grant for the new read-only diagnostics capability.
pub(crate) fn diagnostics(args: &[OsString]) -> Result<(), String> {
    use crate::http::admission::{parse_clients, parse_document};
    use crate::http::operator::{PolicyFile, verify_approvals};
    use mcp_gateway::security::{audit::AuditSink, policy::Action};
    const HELP: &str = "usage: veyl diagnostics show|grant|revoke CLIENT [--config PATH]";
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let [action, client, option, config] = args else {
        return Err(HELP.into());
    };
    let action = action.to_str().ok_or(HELP)?;
    let client = client.to_str().ok_or(HELP)?;
    if !matches!(action, "show" | "grant" | "revoke")
        || option != "--config"
        || rustix::process::geteuid().is_root()
    {
        return Err(HELP.into());
    }
    let path = Path::new(config);
    let policy = PolicyFile::lock(path, action != "show")?;
    let marker = format!("diagnostics:{action}:{client}");
    let pending = policy.pending_client()?;
    if pending.as_deref().is_some_and(|value| value != marker) || marker.len() > 128 {
        return Err("Interrupted policy update requires local recovery".into());
    }
    let bytes = policy.bytes()?;
    let settings = parse_clients(path, &bytes)?;
    verify_approvals(&settings)?;
    let selected = settings
        .clients
        .iter()
        .find(|c| c.id == client)
        .ok_or("Unknown client")?;
    let granted = selected.actions.contains(&Action::SystemInspect);
    if action == "show" {
        println!("client={client} system_inspect={granted}");
        return Ok(());
    }
    let enable = action == "grant";
    if granted == enable && pending.is_none() {
        println!("client={client} system_inspect={enable}");
        return Ok(());
    }
    let mut document = parse_document(&bytes)?;
    let entry = document["clients"]
        .as_array_mut()
        .ok_or("Invalid clients")?
        .iter_mut()
        .find(|entry| entry["id"].as_str() == Some(client))
        .ok_or("Unknown client")?;
    let tools = entry["tools"].as_array_mut().ok_or("Invalid tool grants")?;
    tools.retain(|tool| tool.as_str() != Some("system_inspect"));
    if enable {
        tools.push("system_inspect".into());
    }
    let audit = AuditSink::open_with_limits(
        settings
            .audit_log
            .as_ref()
            .ok_or("Private audit ledger required")?,
        settings.audit_limits,
    )
    .map_err(|_| "Audit ledger unavailable")?;
    let operation = if enable {
        "diagnostics_grant"
    } else {
        "diagnostics_revoke"
    };
    policy.commit_edit(&document, &marker, |phase| {
        audit.record_runtime_mode(
            client,
            operation,
            selected.mode.audit_mode().unwrap_or("standard"),
            phase,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    })?;
    println!("client={client} system_inspect={enable}");
    Ok(())
}

/// Provision a fresh local installation. Existing directories and policies
/// are never adopted, overwritten or implicitly migrated.
pub(crate) fn init(args: &[OsString]) -> Result<(), String> {
    use mcp_gateway::security::linux_fs::{open_operator_dir, publish_new};
    use rustix::fs::{self, Mode, OFlags};
    use sha2::{Digest, Sha256};
    use std::ffi::OsStr;

    const HELP: &str = "usage: veyl init --root EXISTING_WORKSPACE [--tailscale | --tailscale-host HOST] [--yolo]";
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    if rustix::process::geteuid().is_root() {
        return Err("Run setup as your normal user, not root".into());
    }
    let mut root = None;
    let mut hostname = None;
    let mut tailscale = false;
    let mut public = false;
    let mut options = args.iter();
    while let Some(arg) = options.next() {
        match arg.to_str() {
            Some("--root") if root.is_none() => {
                root = Some(PathBuf::from(options.next().ok_or(HELP)?))
            }
            Some("--tailscale-host") if hostname.is_none() => {
                hostname = Some(
                    options
                        .next()
                        .and_then(|v| v.to_str())
                        .ok_or(HELP)?
                        .to_owned(),
                );
            }
            Some("--tailscale") if !tailscale => tailscale = true,
            Some("--yolo" | "--chatgpt-yolo") if !public => public = true,
            _ => return Err(HELP.into()),
        }
    }
    let root = root
        .ok_or(HELP)?
        .canonicalize()
        .map_err(|_| "Workspace does not exist")?;
    open_operator_dir(&root).map_err(|_| "Workspace must be an existing directory")?;
    let home = home()?;
    let state = home.join(".local/state/veyl");
    if state
        .try_exists()
        .map_err(|_| "Cannot inspect Veyl state")?
    {
        return Err("Veyl state already exists; use veyl connect or veyl ui".into());
    }
    if root.starts_with(&state) || state.starts_with(&root) {
        return Err("Choose a workspace separate from Veyl's private state".into());
    }
    if home
        .join(".config/mcp-gateway/clients.json")
        .try_exists()
        .map_err(|_| "Cannot inspect legacy configuration")?
    {
        return Err(
            "An existing legacy policy was found; use that configuration rather than init".into(),
        );
    }
    if tailscale && hostname.is_some() {
        return Err("Choose --tailscale or --tailscale-host, not both".into());
    }
    if (tailscale || public) && hostname.is_none() {
        hostname = Some(crate::tailnet::discover_hostname()?);
    }
    let tailnet = hostname
        .map(|host| {
            let value =
                serde_json::json!({"hostname":host,"mcp_https_port":8443,"admin_https_port":9443});
            crate::tailnet::Settings::parse(&value)?;
            Ok::<_, String>(value)
        })
        .transpose()?;
    let secret = credential()?;
    let digest = format!("{:x}", Sha256::digest(secret.as_bytes()));
    let mut document = serde_json::json!({
        "policy_version":3,
        "audit_log":state.join("audit/events.jsonl"),
        "job_state_dir":state.join("jobs"),
        "skills_dir":state.join("skills"),
        "admin_listen":"127.0.0.1:7332",
        "job_profiles":{"health":{"executable":"/usr/bin/true","args":[],"timeout_seconds":5}},
        "clients":[{
            "id":"dev","root":root,"token_sha256":digest,
            "expires_at_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| "System clock is before Unix epoch")?.as_secs().saturating_add(365*24*60*60),
            "mode":"standard","disabled":false,"extra_roots":[],
            "tools":["read_file","search_files","git_inspect","system_info","service_status",
                "system_inspect","write_file","apply_patch","start_job","job_status","job_logs","cancel_job",
                "list_jobs","skills_list","skills_read","list_directory","directory_tree",
                "file_info","edit_file","create_directory","exec_command","job_wait","task_run"]
        }]
    });
    let mut connector = None;
    let mut private_chatgpt = None;
    if let Some(mut tailnet) = tailnet {
        if public {
            let private = credential()?;
            let public_secret = credential()?;
            let mut client = document["clients"][0].clone();
            client["id"] = "chatgpt".into();
            client["token_sha256"] = format!("{:x}", Sha256::digest(private.as_bytes())).into();
            document["clients"].as_array_mut().unwrap().push(client);
            tailnet["funnel"] = serde_json::json!({"client":"chatgpt",
                "token_sha256":format!("{:x}",Sha256::digest(public_secret.as_bytes())),
                "allow_secret_path":true});
            tailnet["shared_funnel"] = true.into();
            tailnet["standalone_funnel"] = true.into();
            connector = Some(format!(
                "https://{}/veyl/mcp/{public_secret}",
                tailnet["hostname"].as_str().unwrap()
            ));
            private_chatgpt = Some(private);
        }
        document["tailscale_serve"] = tailnet;
    }
    let mut parent = open_operator_dir(&home).map_err(|_| "HOME must be a real directory")?;
    // Walk the standard state parents with descriptor-relative, no-follow
    // opens. A pre-existing symbolic link is never traversed or modified.
    for name in [".local", "state"] {
        let meta = fs::fstat(&parent).map_err(|_| "Cannot inspect state parent")?;
        if meta.st_uid != rustix::process::geteuid().as_raw() || meta.st_mode & 0o022 != 0 {
            return Err(
                "State parent must be owned by your user and not writable by others".into(),
            );
        }
        match fs::mkdirat(&parent, name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err("Cannot create the state parent".into()),
        }
        parent = fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "State parent must be a real directory")?;
    }
    let meta = fs::fstat(&parent).map_err(|_| "Cannot inspect state parent")?;
    if meta.st_uid != rustix::process::geteuid().as_raw() || meta.st_mode & 0o022 != 0 {
        return Err("State parent must be owned by your user and not writable by others".into());
    }
    fs::mkdirat(&parent, "veyl", Mode::from_raw_mode(0o700))
        .map_err(|_| "Veyl state already exists or cannot be created; no files overwritten")?;
    let dir = fs::openat(
        &parent,
        "veyl",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "Cannot open new state directory")?;
    for name in ["audit", "jobs", "skills"] {
        fs::mkdirat(&dir, name, Mode::from_raw_mode(0o700))
            .map_err(|_| "Cannot initialize state directories")?;
    }
    let mut bytes = serde_json::to_vec_pretty(&document).map_err(|_| "Cannot encode policy")?;
    bytes.push(b'\n');
    publish_new(&dir, OsStr::new("clients.json"), &bytes)
        .map_err(|_| "Cannot publish initial policy")?;
    publish_new(&dir, OsStr::new("dev.bearer"), secret.as_bytes())
        .map_err(|_| "Cannot store local client credential")?;
    if let (Some(connector), Some(private)) = (connector, private_chatgpt) {
        publish_new(&dir, OsStr::new("chatgpt.bearer"), private.as_bytes())
            .map_err(|_| "Cannot store private ChatGPT credential")?;
        publish_new(
            &dir,
            OsStr::new("chatgpt-connector-url.txt"),
            connector.as_bytes(),
        )
        .map_err(|_| "Cannot store the public connector URL")?;
    }
    let settings = crate::http::admission::parse_clients(&state.join("clients.json"), &bytes)?;
    // Create and verify the private ledger before any broad-mode preflight.
    let ledger = settings
        .audit_log
        .as_ref()
        .ok_or("Missing initial ledger")?;
    drop(
        mcp_gateway::security::audit::AuditSink::open_with_limits(ledger, settings.audit_limits)
            .map_err(|_| "Cannot initialize the audit ledger")?,
    );
    if public {
        crate::mode_cli::run(&[
            "set".into(),
            "chatgpt".into(),
            "yolo".into(),
            "--config".into(),
            state.join("clients.json").into_os_string(),
        ])?;
    }
    println!(
        "Initialized Veyl in {}\nClient: dev (Standard)\nRun: veyl run\nOpen the dashboard from another terminal: veyl ui",
        state.display()
    );
    println!("Local MCP bearer saved privately as dev.bearer in that state directory.");
    Ok(())
}

fn credential() -> Result<String, String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| "Secure randomness unavailable")?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Install the user service and, when configured, publish owned Tailscale
/// routes. This is an explicit local operation, never an MCP tool.
pub(crate) fn setup(args: &[OsString]) -> Result<(), String> {
    if args == ["--help"] {
        println!(
            "usage: veyl setup --root EXISTING_WORKSPACE [--tailscale] [--yolo]\nInitialize and start the user service. --yolo creates a public authenticated Funnel connector and copies its URL once."
        );
        return Ok(());
    }
    init(args)?;
    let path = default_config(&home()?)?;
    let settings = crate::http::operator::PolicyFile::preview(&path)?;
    let tailnet = settings.tailnet;
    crate::service_cli::run(&[
        "on".into(),
        "--config".into(),
        path.clone().into_os_string(),
    ])?;
    if tailnet.as_ref().is_some_and(|tail| tail.funnel.is_some()) {
        connect(&["--config".into(), path.clone().into_os_string()])?;
    } else if tailnet.is_some() {
        crate::tailnet::run(&[
            "apply".into(),
            "--confirm".into(),
            "--config".into(),
            path.clone().into_os_string(),
        ])?;
    }
    crate::http::dashboard::run(&["open".into(), "--config".into(), path.into_os_string()])
}

pub(crate) fn connect(args: &[OsString]) -> Result<(), String> {
    use mcp_gateway::security::linux_fs::{open_operator_dir, reopen_regular};
    use rustix::fs::{self, Mode, OFlags};
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::process::{Command, Stdio};

    if args == ["--help"] {
        println!(
            "usage: veyl connect [--config PATH]\nActivate the configured public connector and copy its URL."
        );
        return Ok(());
    }
    let [option, path] = args else {
        return Err("Expected --config PATH".into());
    };
    if option != "--config" || rustix::process::geteuid().is_root() {
        return Err("Connect requires the unprivileged local operator".into());
    }
    let path = Path::new(path);
    let settings = crate::http::operator::PolicyFile::preview(path)?;
    crate::http::operator::verify_approvals(&settings)?;
    let tail = settings
        .tailnet
        .as_ref()
        .ok_or("Configure Tailscale first with veyl init --chatgpt-yolo")?;
    let public = tail
        .funnel
        .as_ref()
        .ok_or("No public connector configured")?;
    let parent = open_operator_dir(path.parent().ok_or("Invalid policy path")?)
        .map_err(|_| "Private state unavailable")?;
    let handle = fs::openat(
        &parent,
        "chatgpt-connector-url.txt",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "Connector URL file is unavailable")?;
    let file = std::fs::File::from(
        reopen_regular(handle, OFlags::RDONLY).map_err(|_| "Unsafe connector URL file")?,
    );
    let meta = file
        .metadata()
        .map_err(|_| "Cannot inspect connector URL file")?;
    if meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 512
    {
        return Err("Unsafe connector URL file".into());
    }
    let mut url = String::new();
    file.take(513)
        .read_to_string(&mut url)
        .map_err(|_| "Cannot read connector URL file")?;
    let url = url.trim_end_matches('\n');
    let prefix = if tail.shared_funnel {
        format!("https://{}/veyl/mcp/", tail.hostname)
    } else {
        format!("https://{}/mcp/", tail.authority(false))
    };
    if !url
        .strip_prefix(&prefix)
        .is_some_and(|token| public.accepts_token(token))
    {
        return Err(
            "Saved connector URL no longer matches the configured credential or route".into(),
        );
    }
    let common = [
        "--confirm".into(),
        "--config".into(),
        path.as_os_str().to_owned(),
    ];
    let mut command = vec!["apply".into()];
    command.extend(common.clone());
    crate::tailnet::run(&command)?;
    command[0] = "funnel-apply".into();
    crate::tailnet::run(&command)?;
    let clipboard = Command::new("wl-copy")
        .arg("--trim-newline")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(mut child) = clipboard {
        child
            .stdin
            .take()
            .ok_or("Clipboard input unavailable")?
            .write_all(url.as_bytes())
            .map_err(|_| "Clipboard transfer failed")?;
        if !child.wait().map_err(|_| "Clipboard unavailable")?.success() {
            return Err("Clipboard transfer failed".into());
        }
        println!(
            "Connector URL copied. Paste it once into your AI client's private MCP connection form."
        );
    } else {
        println!(
            "Connector ready. Copy chatgpt-connector-url.txt privately from the configuration directory."
        );
    }
    Ok(())
}

pub(crate) fn monitor(exe: &Path, args: &[OsString]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    // Preserve the explicit listener/stdin contract for scripts.
    if args
        .iter()
        .any(|arg| arg == "--listen" || arg == "--help" || arg == "--version")
    {
        let error = Command::new(exe).args(args).exec();
        return Err(format!("Cannot launch monitor: {error}"));
    }
    let mut config = None;
    let mut forwarded = Vec::new();
    let mut options = args.iter();
    while let Some(arg) = options.next() {
        if arg == "--config" && config.is_none() {
            config = Some(PathBuf::from(
                options.next().ok_or("Missing --config path")?,
            ));
        } else {
            forwarded.push(arg.clone());
        }
    }
    let config = match config {
        Some(path) => path,
        None => default_config(&home()?)?,
    };
    let (token, listen) = {
        if rustix::process::geteuid().is_root() {
            return Err("Use the unprivileged Veyl operator".into());
        }
        let policy = crate::http::operator::PolicyFile::lock(&config, true)?;
        let settings = policy.snapshot()?;
        crate::http::operator::verify_approvals(&settings)?;
        let listen = settings
            .admin_listen
            .filter(|addr| addr.port() != 0)
            .ok_or("Configure a fixed admin listener")?;
        (crate::http::dashboard::issue_pairing(&policy)?, listen)
    };
    let mut child = Command::new(exe)
        .arg("--listen")
        .arg(listen.to_string())
        .args(forwarded)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| "Cannot launch monitor")?;
    writeln!(
        child.stdin.take().ok_or("Monitor input unavailable")?,
        "{token}"
    )
    .map_err(|_| "Cannot pair monitor")?;
    if !child
        .wait()
        .map_err(|_| "Monitor process unavailable")?
        .success()
    {
        return Err("Monitor exited unsuccessfully".into());
    }
    Ok(())
}
