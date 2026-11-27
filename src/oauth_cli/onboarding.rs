//! Explicit isolated onboarding. A fresh profile contains no plaintext
//! bearer credentials. The optional Funnel route is foreground-owned.
use mcp_gateway::{core::session::random_id, security::linux_fs::{open_operator_dir,publish_new}};
use rustix::fs::{self,Mode,OFlags};
use serde_json::{Value,json};
use std::io::Read;
use sha2::{Digest,Sha256};
use std::{ffi::{OsStr,OsString},path::{Path,PathBuf},time::{SystemTime,UNIX_EPOCH}};

pub(super) const HELP: &str = "Usage: veyl oauth setup --root ABSOLUTE_EXISTING_WORKSPACE --profile ABSOLUTE_NEW_DIRECTORY [--open-ui] [--workspace-edit | --workspace-tools] [--funnel [--funnel-port 8443|10000] [--funnel-advanced]] [--workspace-jobs --job-profiles ABSOLUTE_FILE [--workspace-commands] [--workspace-interactive]] [--workspace-upstreams --upstream-manifest ABSOLUTE_FILE]\n       veyl oauth run --profile ABSOLUTE_EXISTING_DIRECTORY [--open-ui] [--workspace-edit | --workspace-tools] [--funnel [--funnel-port 8443|10000] [--funnel-advanced]] [--workspace-jobs [--workspace-commands] [--workspace-interactive]] [--workspace-upstreams]\nExperimental OAuth candidate. --funnel explicitly enables public HTTPS through a dedicated foreground-owned Tailscale route; no installed service. Stop with Ctrl-C. Setup never overwrites an existing profile. --workspace-edit grants scoped write/patch/edit; --workspace-tools also grants bounded search/list/tree/metadata and mkdir. --workspace-jobs enables locally approved named commands with offline sandbox, writable workspace and systemd resource ceilings; public jobs require the separate experimental --funnel-advanced opt-in. --workspace-upstreams enables explicitly granted MCP providers; public upstream grants also require --funnel-advanced. Providers may share application state and have side effects. --workspace-commands adds arbitrary sandboxed commands with the same Standard job boundary and resource ceilings. --workspace-interactive grants persistent interactive pipe/PTY sessions (process_start, process_input, process_resize, shell_status, shell_reset) for approved interactive job profiles within the same Standard boundary and resource ceilings. --funnel-advanced does not itself grant tools; it requires --funnel and explicit jobs or upstreams. Review the public scope locally. Public workspace writes/jobs require a private dedicated bounded tmpfs mount; providers may have side effects. Public activation awaits independent acceptance. Repeat the selected profile flags on restart.";
const CLIENT: &str = "oauth-preview";

pub(super) fn private_directory(path:&Path, exact:bool)->Result<rustix::fd::OwnedFd,String> {
    let dir=open_operator_dir(path).map_err(|_|"Unsafe profile directory")?;
    let meta=fs::fstat(&dir).map_err(|_|"Cannot inspect directory")?;
    if meta.st_uid!=rustix::process::geteuid().as_raw()
        || if exact {meta.st_mode & 0o7777 != 0o700} else {meta.st_mode & 0o022 != 0}
    { return Err("Profile directories must be owned and private; parent must not be writable by others".into()); }
    Ok(dir)
}

struct ProfileScope {
    edit: bool,
    tools: bool,
    commands: bool,
    interactive: bool,
    managed_login: bool,
    job_profiles: Option<Value>,
    upstreams: Option<Value>,
}

fn create_profile(profile:&Path,root:&Path,scope:ProfileScope)->Result<(),String> {
    let ProfileScope { edit: workspace_edit, tools: workspace_tools, commands: workspace_commands, interactive: workspace_interactive, managed_login, job_profiles, upstreams } = scope;
    let parent=profile.parent().ok_or("Missing profile parent")?;
    let name=profile.file_name().ok_or("Missing profile name")?;
    if parent.canonicalize().map_err(|_|"Profile parent must exist")?.join(name)!=profile
        || root.canonicalize().map_err(|_|"Workspace must exist")?!=root
    {return Err("Use canonical absolute workspace and profile paths".into());}
    open_operator_dir(root).map_err(|_|"Unsafe workspace")?;
    if root.starts_with(profile)||profile.starts_with(root) {
        return Err("Workspace and private OAuth profile must be separate".into());
    }
    let parent=private_directory(parent,false)?;
    fs::mkdirat(&parent,name,Mode::from_raw_mode(0o700)).map_err(|_|"Profile already exists or cannot be created; no files overwritten")?;
    let dir=fs::openat(&parent,name,OFlags::RDONLY|OFlags::DIRECTORY|OFlags::NOFOLLOW|OFlags::CLOEXEC,Mode::empty())
        .map_err(|_|"Cannot open new profile")?;
    fs::fchmod(&dir,Mode::from_raw_mode(0o700)).map_err(|_|"Cannot secure profile")?;
    for name in ["audit","oauth"] {
        fs::mkdirat(&dir,name,Mode::from_raw_mode(0o700)).map_err(|_|"Cannot initialize private profile")?;
        let child=fs::openat(&dir,name,OFlags::RDONLY|OFlags::DIRECTORY|OFlags::NOFOLLOW|OFlags::CLOEXEC,Mode::empty())
            .map_err(|_|"Cannot open private profile directory")?;
        fs::fchmod(&child,Mode::from_raw_mode(0o700)).map_err(|_|"Cannot secure private profile directory")?;
        fs::fsync(&child).map_err(|_|"Cannot sync profile directory")?;
    }
    // A random native verifier is required by the established policy. The
    // corresponding bearer is deliberately not retained or printed.
    let native=random_id::<32>().map_err(|_|"Secure randomness unavailable")?;
    let expiry=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"Invalid system clock")?.as_secs()
        .checked_add(365*24*60*60).ok_or("Invalid expiry")?;
    let mut doc=json!({"policy_version":3,"audit_log":profile.join("audit/events.jsonl"),
        "admin_listen":"127.0.0.1:0","clients":[{"id":CLIENT,"root":root,
        "token_sha256":format!("{:x}",Sha256::digest(native.as_bytes())),
        "expires_at_unix_seconds":expiry,"mode":"standard","disabled":false,
        "extra_roots":[],"tools":if workspace_tools {vec!["read_file","write_file","apply_patch","edit_file","create_directory","list_directory","directory_tree","file_info","search_files"]} else if workspace_edit {vec!["read_file","write_file","apply_patch","edit_file"]} else {vec!["read_file"]}}]});
    if let Some(profiles)=job_profiles {
        doc["job_profiles"]=profiles;
        doc["job_state_dir"]=json!(profile.join("jobs"));
        doc["clients"][0]["tools"].as_array_mut().ok_or("Missing tools")?.extend(
            ["run_command","job_start","job_status","job_logs","job_cancel","list_jobs","job_wait"].into_iter().map(Value::from));
        doc["clients"][0]["job_runtime_limit_seconds"]=json!(300);
        doc["clients"][0]["job_retention_count"]=json!(32);
        if workspace_commands {
            doc["clients"][0]["tools"].as_array_mut().ok_or("Missing tools")?.extend(
                ["exec_command","task_run"].into_iter().map(Value::from));
        }
        if workspace_interactive {
            doc["clients"][0]["tools"].as_array_mut().ok_or("Missing tools")?.extend(
                ["process_start","process_input","process_resize","shell_status","shell_reset"].into_iter().map(Value::from));
        }
        if workspace_commands || workspace_interactive {
            doc["clients"][0]["job_cpu_percent_limit"]=json!(100);
            doc["clients"][0]["job_memory_bytes_limit"]=json!(268435456);
            doc["clients"][0]["job_output_limit_bytes"]=json!(65536);
        }
    } else if managed_login {
        fs::mkdirat(&dir, "jobs", Mode::from_raw_mode(0o700)).map_err(|_| "Cannot initialize private jobs directory")?;
        let jobs_dir = fs::openat(&dir, "jobs", OFlags::RDONLY|OFlags::DIRECTORY|OFlags::NOFOLLOW|OFlags::CLOEXEC, Mode::empty())
            .map_err(|_| "Cannot open private jobs directory")?;
        fs::fchmod(&jobs_dir, Mode::from_raw_mode(0o700)).map_err(|_| "Cannot secure private jobs directory")?;
        fs::fsync(&jobs_dir).map_err(|_| "Cannot sync private jobs directory")?;
        doc["job_profiles"]=json!({"status":{"executable":"/usr/bin/pwd","args":[],"timeout_seconds":10}});
        doc["job_state_dir"]=json!(profile.join("jobs"));
        doc["clients"][0]["job_runtime_limit_seconds"]=json!(300);
        doc["clients"][0]["job_cpu_percent_limit"]=json!(100);
        doc["clients"][0]["job_memory_bytes_limit"]=json!(268435456);
        doc["clients"][0]["job_output_limit_bytes"]=json!(65536);
        doc["clients"][0]["job_retention_count"]=json!(32);
    }
    if let Some(providers)=upstreams {
        doc["mcp_servers"]=providers["mcp_servers"].clone();
        doc["clients"][0]["allowed_servers"]=json!(providers["mcp_servers"].as_object().ok_or("Missing providers")?.keys().collect::<Vec<_>>());
        doc["clients"][0]["allowed_server_tools"]=providers["allowed_server_tools"].clone();
        doc["clients"][0]["tools"].as_array_mut().ok_or("Missing tools")?.extend(
            ["mcp_servers_list","mcp_servers_call"].into_iter().map(Value::from));
    }
    let bytes=serde_json::to_vec_pretty(&doc).map_err(|_|"Cannot serialize policy")?;
    let path=profile.join("clients.json");
    // The existing job parser requires the policy pathname to exist.
    // A failed initialization retains the new, private profile; it never
    // launches the gateway or overwrites prior state.
    publish_new(&dir,OsStr::new("clients.json"),&bytes).map_err(|_|"Cannot publish isolated policy")?;
    fs::fsync(&dir).and_then(|_|fs::fsync(&parent)).map_err(|_|"Profile publication uncertain")?;
    let settings=crate::http::admission::parse_clients(&path,&bytes)?;
    drop(mcp_gateway::security::audit::AuditSink::open_with_limits(
        settings.audit_log.as_deref().ok_or("Missing audit ledger")?,settings.audit_limits)
        .map_err(|_|"Cannot initialize private audit ledger")?);
    Ok(())
}

fn read_manifest(path:&Path)->Result<Vec<u8>,String>{
    if !path.is_absolute() || path.canonicalize().map_err(|_|"Manifest unavailable")?!=path {
        return Err("Use a canonical absolute manifest path".into());
    }
    let dir=open_operator_dir(path.parent().ok_or("Missing manifest parent")?).map_err(|_|"Unsafe manifest directory")?;
    let file=fs::openat(&dir,path.file_name().ok_or("Missing manifest name")?,OFlags::RDONLY|OFlags::NOFOLLOW|OFlags::NONBLOCK|OFlags::CLOEXEC,Mode::empty()).map_err(|_|"Cannot read manifest")?;
    let stat=fs::fstat(&file).map_err(|_|"Cannot inspect manifest")?;
    if fs::FileType::from_raw_mode(stat.st_mode)!=fs::FileType::RegularFile
        || stat.st_uid!=rustix::process::geteuid().as_raw() || stat.st_mode&0o022!=0 || stat.st_nlink!=1 {
        return Err("Manifest must be a trusted owner-controlled regular file".into());
    }
    let mut bytes=Vec::new();
    std::fs::File::from(file).take(32769).read_to_end(&mut bytes).map_err(|_|"Cannot read manifest")?;
    if bytes.len()>32768{return Err("Manifest file too large".into());}
    Ok(bytes)
}

pub(super) fn run(args:&[OsString])->Result<(),String> {
    run_with_control(args,None)
}

pub(super) fn run_with_control(args:&[OsString], control: Option<std::os::unix::net::UnixListener>)->Result<(),String> {
    if args==["--help"] || (args.len()==2 && args[1]=="--help") {
        println!("{HELP}");return Ok(());
    }
    if rustix::process::geteuid().is_root(){return Err("Run onboarding as your normal user".into());}
    let initialize=args.first().is_some_and(|v|v=="setup");
    let mut profile=None;
    let mut root=None;
    let mut open_ui=false;
    let mut workspace_edit=false;
    let mut workspace_tools=false;
    let mut workspace_jobs=false;
    let mut workspace_commands=false;
    let mut workspace_interactive=false;
    let mut job_profiles=None;
    let mut workspace_upstreams=false;
    let mut upstream_manifest=None;
    let mut funnel=false;
    let mut funnel_advanced=false;
    let mut funnel_port=None;
    let mut funnel_socket=None;
    let mut managed_login=false;
    let mut options=args[1..].iter();
    while let Some(arg)=options.next(){
        match arg.to_str(){
            Some("--profile") if profile.is_none()=>profile=Some(PathBuf::from(options.next().ok_or(HELP)?)),
            Some("--root") if initialize && root.is_none()=>root=Some(PathBuf::from(options.next().ok_or(HELP)?)),
            Some("--open-ui") if !open_ui=>open_ui=true,
            Some("--workspace-edit") if !workspace_edit=>workspace_edit=true,
            Some("--workspace-tools") if !workspace_edit=>{workspace_edit=true;workspace_tools=true;},
            Some("--workspace-jobs") if !workspace_jobs=>workspace_jobs=true,
            Some("--workspace-commands") if !workspace_commands=>workspace_commands=true,
            Some("--workspace-interactive") if !workspace_interactive=>workspace_interactive=true,
            Some("--job-profiles") if initialize && job_profiles.is_none()=>job_profiles=Some(PathBuf::from(options.next().ok_or(HELP)?)),
            Some("--workspace-upstreams") if !workspace_upstreams=>workspace_upstreams=true,
            Some("--upstream-manifest") if initialize && upstream_manifest.is_none()=>upstream_manifest=Some(PathBuf::from(options.next().ok_or(HELP)?)),
            Some("--funnel") if !funnel=>funnel=true,
            Some("--funnel-advanced") if !funnel_advanced=>funnel_advanced=true,
            Some("--funnel-port") if funnel_port.is_none()=>funnel_port=Some(options.next().and_then(|v|v.to_str()).and_then(|v|v.parse::<u16>().ok()).ok_or(HELP)?),
            Some("--funnel-socket") if funnel_socket.is_none()=>funnel_socket=Some(PathBuf::from(options.next().ok_or(HELP)?)),
            Some("--managed-login") if !managed_login && control.is_some()=>managed_login=true,
            _=>return Err(HELP.into()),
        }
    }
    let profile=profile.filter(|v|v.is_absolute()&&v.to_str().is_some()).ok_or(HELP)?;
    if managed_login && !funnel {return Err("Managed login requires --funnel".into());}
    if workspace_commands && !workspace_jobs {return Err("Workspace commands require explicit --workspace-jobs".into());}
    if workspace_interactive && !workspace_jobs {return Err("Interactive workspace sessions require explicit --workspace-jobs".into());}
    if funnel_advanced != (funnel && (workspace_jobs || workspace_upstreams)) {
        return Err("Advanced public capabilities require --funnel, --funnel-advanced and explicit workspace jobs or upstreams".into());
    }
    if initialize && workspace_upstreams!=upstream_manifest.is_some(){return Err("Fresh --workspace-upstreams requires --upstream-manifest ABSOLUTE_FILE".into());}
    let upstreams=upstream_manifest.map(|path|crate::upstream::oauth_manifest(&read_manifest(&path)?)).transpose()?;
    if initialize && workspace_jobs!=job_profiles.is_some(){return Err("Fresh --workspace-jobs requires --job-profiles ABSOLUTE_FILE".into());}
    let job_profiles=job_profiles.map(|path|crate::jobs::oauth_profiles(&read_manifest(&path)?,workspace_interactive)).transpose()?;
    if !funnel && (funnel_port.is_some()||funnel_socket.is_some()){return Err(HELP.into());}
    let saved_origin=if initialize {None} else {
        private_directory(&profile,true)?;
        Some(mcp_gateway::http_common::oauth_http::persisted_origin(&profile.join("oauth"))?)
    };
    if let Some(origin)=&saved_origin {
        if funnel {
            let uri:hyper::Uri=origin.parse().map_err(|_|"Invalid saved origin")?;
            let port=uri.port_u16().filter(|p|matches!(p,8443|10000)).ok_or("Existing profile is not a dedicated Funnel profile")?;
            if uri.host().is_none_or(|h|!h.ends_with(".ts.net")) || funnel_port.is_some_and(|p|p!=port){
                return Err("Existing profile is bound to a different OAuth origin".into());
            }
            funnel_port=Some(port);
        } else if origin!="https://veyl.example" {
            return Err("This profile requires explicit --funnel to resume public ingress".into());
        }
    }
    let plan=if funnel {Some(crate::tailnet::oauth_provider::Plan::detect(funnel_socket,funnel_port)?)} else {None};
    if saved_origin.as_deref().is_some_and(|old|plan.as_ref().is_some_and(|p|p.origin()!=old)){
        return Err("Tailscale hostname changed; use a new explicit OAuth profile".into());
    }
    if initialize {
        let root=root.filter(|v|v.is_absolute()&&v.to_str().is_some()).ok_or(HELP)?;
        if funnel && !managed_login && (workspace_edit || workspace_jobs) {
            mcp_gateway::security::linux_fs::bounded_oauth_workspace(&root).map_err(|e| e.to_string())?;
        }
        create_profile(&profile,&root,ProfileScope{edit:workspace_edit,tools:workspace_tools,commands:workspace_commands,interactive:workspace_interactive,managed_login,job_profiles,upstreams})?;
    }
    if profile.canonicalize().map_err(|_|"Profile unavailable")?!=profile{return Err("Use a canonical profile path".into());}
    private_directory(&profile,true)?;
    private_directory(&profile.join("audit"),true)?;
    private_directory(&profile.join("oauth"),true)?;
    let operator=random_id::<32>().map_err(|_|"Secure randomness unavailable")?;
    crate::http::run_onboarded(profile.join("clients.json"),
        json!({"operator_token":operator,"local_fixture_client":CLIENT,
            "state_dir":profile.join("oauth"),"initialize_state":initialize,"managed_login":managed_login,"workspace_edit":workspace_edit,"workspace_tools":workspace_tools,"workspace_jobs":workspace_jobs,"workspace_upstreams":workspace_upstreams,"workspace_commands":workspace_commands,"workspace_interactive":workspace_interactive,"funnel_advanced":funnel_advanced}),open_ui,plan,control)
}
