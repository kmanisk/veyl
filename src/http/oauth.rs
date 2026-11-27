//! Opt-in native OAuth integration, including an isolated foreground Funnel.
//! Pin a pre-existing scoped Standard client and require the live native
//! policy on every admission. No mode, client, root, or grant is created.
use super::{Client, Configuration, Reply, State, Tool, simple, unix_seconds};
use hyper::{Request, StatusCode, body::Incoming};
use mcp_gateway::{
    core::oauth::ConnectionMode,
    http_common::oauth_http::{self, Identity, Server},
    security::{
        durable_id::DurableObjectId,
        linux_fs::open_absolute_dir,
        policy::{Action, ExecutionMode},
    },
};
use std::{
    io::{Read, stdin},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use sha2::{Digest, Sha256};

pub(super) struct Native {
    pub server: Server,
    pub legacy_operator: bool,
    pub managed_login: bool,
    workspace_edit: bool,
    workspace_tools: bool,
    pub workspace_jobs: bool,
    workspace_upstreams: bool,
    workspace_commands: bool,
    pub workspace_interactive: bool,
    funnel_advanced: bool,
    pub(super) bounded_workspace: bool,
    verifier: [u8; 32],
    root: PathBuf,
    config_path: PathBuf,
    durable_policy: Option<[u8; 32]>,
    durable_root: Option<(u64, u64)>,
    pub durable_state_dir: Option<PathBuf>,
}

#[derive(Clone, Copy)]
struct Scope {
    edit: bool,
    tools: bool,
    jobs: bool,
    upstreams: bool,
    commands: bool,
    interactive: bool,
}

fn eligible_client(client: &Client, now: u64, scope: Scope) -> bool {
    !client.is_disabled()
        && client.mode == ExecutionMode::Standard
        && now < client.expires_at
        && client.extra_roots.is_empty()
        && client.job_extra_roots.is_empty()
        && (!(scope.commands || scope.interactive) || scope.jobs && client.job_runtime_limit_seconds<=300
            && client.job_cpu_percent_limit<=100 && client.job_memory_bytes_limit<=268435456
            && client.job_output_limit_bytes<=65536)
        && client.actions.iter().all(|a| matches!(a, Action::ListTools | Action::ReadFile)
            || scope.edit && matches!(a, Action::WriteFile | Action::ApplyPatch)
            || scope.tools && *a == Action::SearchFiles
            || scope.jobs && matches!(a,Action::RunShortJob|Action::StartJob|Action::JobStatus|Action::JobLogs|Action::CancelJob|Action::ListJobs)
            || scope.interactive && matches!(a,Action::ProcessStart|Action::ProcessInput|Action::ProcessResize|Action::ShellStatus|Action::ShellReset)
            || scope.upstreams && matches!(a,Action::ListUpstreams|Action::CallUpstream))
        && client.tools.iter().all(|t| *t == Tool::ReadFile
            || scope.edit && matches!(t, Tool::WriteFile | Tool::ApplyPatch | Tool::EditFile)
            || scope.tools && matches!(t, Tool::CreateDirectory | Tool::ListDirectory | Tool::DirectoryTree | Tool::FileInfo | Tool::SearchFiles)
            || scope.jobs && matches!(t,Tool::RunCommand|Tool::JobStart|Tool::JobStatus|Tool::JobLogs|Tool::JobCancel|Tool::ListJobs|Tool::JobWait)
            || scope.commands && matches!(t,Tool::ExecCommand|Tool::TaskRun)
            || scope.interactive && matches!(t,Tool::ProcessStart|Tool::ProcessInput|Tool::ProcessResize|Tool::ShellStatus|Tool::ShellReset)
            || scope.upstreams && matches!(t,Tool::UpstreamsList|Tool::UpstreamsCall))
}

pub(super) fn job_owner(identity:&Identity)->String{
    let digest=Sha256::digest(serde_json::json!(["veyl-oauth-job-owner-v1",identity.local_client,identity.oauth_client,identity.family]).to_string().as_bytes());
    format!("oauth-job-v1-{digest:x}")
}

impl Native {
    pub fn consent(&self, state: &State, bytes: &[u8]) -> Reply {
        // Keep the native shared policy lock through the actual approval
        // transaction. Failure to read policy must not block revocation.
        let current = state.policy.read().ok();
        let selected = current.as_ref().and_then(|(_,settings)|
            self.client_index(settings,unix_seconds()).map(|i|&settings.clients[i]));
        let profiles=current.as_ref().and_then(|(_,settings)|settings.jobs.as_ref()).and_then(|(_,profiles)|profiles.oauth_summary(self.workspace_interactive).ok());
        let providers=selected.and_then(|client|current.as_ref().and_then(|(_,settings)|settings.upstreams.oauth_summary(&client.upstreams).ok()));
        let eligible=selected.is_some() && state.mutations.available()
            && (!self.workspace_jobs || profiles.is_some() && state.jobs.as_ref().is_some_and(crate::jobs::Jobs::oauth_launch_available))
            && (!self.workspace_interactive || state.jobs.as_ref().is_some_and(crate::jobs::Jobs::sessions_available))
            && (!self.workspace_upstreams || providers.is_some());
        let tools=selected.map(|client| {
            let mut names:Vec<_>=client.tools.iter().map(|t|t.name()).collect();
            names.sort_unstable();
            names
        }).unwrap_or_default();
        let mut scope=serde_json::json!({
            "root":self.root,"mode":"standard","workspace_edit":self.workspace_edit,"tools":tools
        });
        if self.workspace_jobs {
            scope["workspace_jobs"]=serde_json::json!(true);
            scope["job_profiles"]=serde_json::json!(profiles);
            scope["jobs_may_write_workspace"]=serde_json::json!(true);
        }
        if self.workspace_upstreams {
            scope["workspace_upstreams"]=serde_json::json!(true);
            scope["upstream_providers"]=serde_json::json!(providers);
            scope["upstream_shared_state"]=serde_json::json!(true);
        }
        if self.workspace_commands {
            scope["workspace_commands"]=serde_json::json!(true);
            scope["dynamic_command_scope"]=serde_json::json!({"arbitrary_code":true,"offline":true,"workspace_writable":true,
                "cwd":"workspace_root_only","runtime_seconds_max":300,"cpu_percent_max":100,"memory_bytes_max":268435456,
                "output_bytes_per_stream_max":65536,"wait_seconds_max":2,"ephemeral_worktree":false,"interactive":false});
        }
        if self.workspace_interactive {
            scope["workspace_interactive"]=serde_json::json!(true);
            scope["interactive_session_scope"]=serde_json::json!({"stdin":true,"pty":true,"resize":true,"offline":true,
                "workspace_writable":true,"cwd":"workspace_root_only","runtime_seconds_max":300,"cpu_percent_max":100,
                "memory_bytes_max":268435456,"output_bytes_per_stream_max":65536});
        }
        if self.bounded_workspace {
            scope["bounded_workspace"]=serde_json::json!({
                "backend":"tmpfs","max_bytes":mcp_gateway::security::linux_fs::OAUTH_WORKSPACE_MAX_BYTES,
                "max_inodes":mcp_gateway::security::linux_fs::OAUTH_WORKSPACE_MAX_INODES,
                "volatile":true
            });
        }
        if self.funnel_advanced {
            scope["funnel_advanced"]=serde_json::json!(true);
            scope["public_capability_limits"]=serde_json::json!({"public_https":true,"local_approval_required":true,
                "workspace_disk_quota_enforced":self.bounded_workspace,"upstream_shared_state":self.workspace_upstreams});
        }
        let yolo_scope = if self.managed_login && eligible {
            current.as_ref().and_then(|(_, settings)| {
                let client = selected?;
                if !settings.managed
                    || settings.jobs.is_none()
                    || !state.jobs.as_ref().is_some_and(crate::jobs::Jobs::oauth_launch_available)
                {
                    return None;
                }
                let broad = crate::jobs::Broad::prepare(state.policy.path(), settings).ok()?;
                if broad.probe(&client.root).is_err() {
                    return None;
                }
                let jobs = settings.jobs.is_some();
                let skills = settings.skills.is_some();
                let mut yolo_tools: Vec<_> = Tool::ALL
                    .into_iter()
                    .filter(|tool| {
                        tool.in_yolo_preset(jobs, skills)
                            && !client.denied_actions.contains(&tool.action())
                    })
                    .map(|tool| tool.name())
                    .collect();
                yolo_tools.sort_unstable();
                let protected_summary = serde_json::json!({
                    "state_masked": state.policy.path().parent().map(|p| p.display().to_string()),
                    "control_plane_masked": crate::protected_paths::CONTROL_PLANE_DIRS,
                    "masked_home_defaults": crate::protected_paths::OPTIONAL_DEFAULTS,
                    "readonly_home_defaults": crate::protected_paths::READONLY_DEFAULTS,
                    "custom_masked": settings
                        .protected_paths
                        .selected(crate::protected_paths::Kind::Optional)
                        .iter()
                        .map(|r| r.path.display().to_string())
                        .collect::<Vec<_>>(),
                    "custom_readonly": settings
                        .protected_paths
                        .selected(crate::protected_paths::Kind::ReadOnly)
                        .iter()
                        .map(|r| r.path.display().to_string())
                        .collect::<Vec<_>>(),
                });
                Some(serde_json::json!({
                    "root": self.root,
                    "mode": "yolo",
                    "yolo": true,
                    "broad_host_access": true,
                    "network_enabled": true,
                    "tools": yolo_tools,
                    "protected_paths": protected_summary,
                    "resource_ceilings": {
                        "runtime_seconds_max": client.job_runtime_limit_seconds.min(300),
                        "cpu_percent_max": client.job_cpu_percent_limit.min(100),
                        "memory_bytes_max": client.job_memory_bytes_limit.min(268435456),
                        "output_bytes_per_stream_max": client.job_output_limit_bytes.min(65536),
                        "memory_swap_max": 0,
                        "tasks_max": 128
                    }
                }))
            })
        } else {
            None
        };
        self.server
            .local_consent_with_modes(bytes, eligible, scope, yolo_scope)
    }
    pub fn open(origin: &str, settings: &Configuration, config_path: &Path, automated: Option<serde_json::Value>, funnel:bool) -> Result<Self, String> {
        // Public ingress is selected only by automated onboarding after
        // provider preflight, never by the raw preview CLI.
        let uri: hyper::Uri = origin.parse().map_err(|_| "Invalid preview origin")?;
        if (if funnel {automated.is_none() || uri.host().is_none_or(|h|!h.ends_with(".ts.net")) || !matches!(uri.port_u16(),Some(8443|10000))}
            else {uri.host().is_none_or(|host| !host.ends_with(".example"))})
            || settings.tailnet.is_some()
            || settings.admin_listen.is_none_or(|addr| addr.port() != 0)
        {
            return Err("OAuth requires the selected isolated origin, no legacy tunnel and an ephemeral admin port".into());
        }
        let legacy_operator = automated.is_none();
        let mut config = if let Some(config) = automated { config } else {
            let mut bytes = Vec::new();
            stdin().take(16_385).read_to_end(&mut bytes).map_err(|_| "Cannot read preview config")?;
            if bytes.len() > 16_384 {
                return Err("Preview config too large".into());
            }
            serde_json::from_slice(&bytes).map_err(|_| "Invalid preview config")?
        };
        let object = config.as_object_mut().ok_or("Invalid preview config")?;
        let state_dir = object.remove("state_dir");
        let managed_login = object.remove("managed_login").map(|v|v.as_bool().ok_or("Invalid managed login option")).transpose()?.unwrap_or(false);
        let workspace_edit = object.remove("workspace_edit").map(|v|v.as_bool().ok_or("Invalid workspace edit option")).transpose()?.unwrap_or(false);
        let workspace_tools = object.remove("workspace_tools").map(|v|v.as_bool().ok_or("Invalid workspace tools option")).transpose()?.unwrap_or(false);
        let workspace_jobs = object.remove("workspace_jobs").map(|v|v.as_bool().ok_or("Invalid workspace jobs option")).transpose()?.unwrap_or(false);
        let workspace_commands=object.remove("workspace_commands").map(|v|v.as_bool().ok_or("Invalid workspace command option")).transpose()?.unwrap_or(false);
        let workspace_interactive=object.remove("workspace_interactive").map(|v|v.as_bool().ok_or("Invalid workspace interactive option")).transpose()?.unwrap_or(false);
        if managed_login && (legacy_operator || !funnel || state_dir.is_none() || !settings.managed) {
            return Err("Managed OAuth login requires explicit Funnel onboarding".into());
        }
        if workspace_commands && !workspace_jobs {return Err("Dynamic commands require explicit workspace jobs".into());}
        if workspace_interactive && !workspace_jobs {return Err("Interactive sessions require explicit workspace jobs".into());}
        let workspace_upstreams=object.remove("workspace_upstreams").map(|v|v.as_bool().ok_or("Invalid workspace upstream option")).transpose()?.unwrap_or(false);
        let funnel_advanced=object.remove("funnel_advanced").map(|v|v.as_bool().ok_or("Invalid advanced Funnel option")).transpose()?.unwrap_or(false);
        if funnel_advanced != (funnel && (workspace_jobs || workspace_upstreams)) || funnel_advanced && legacy_operator {
            return Err("Advanced public capabilities require explicit managed Funnel onboarding".into());
        }
        if workspace_upstreams && (legacy_operator || state_dir.is_none() || !settings.managed) {
            return Err("Workspace upstreams require explicit durable onboarding".into());
        }
        if workspace_upstreams==settings.upstreams.empty(){return Err("Resume with the exact configured workspace upstream option".into());}
        if (workspace_jobs || workspace_interactive) && (legacy_operator || state_dir.is_none() || !settings.managed) {
            return Err("Workspace jobs require explicit durable onboarding".into());
        }
        if !managed_login && workspace_jobs != settings.jobs.is_some() {return Err("Resume with the exact configured workspace jobs option".into());}
        if managed_login && settings.jobs.is_none() {return Err("Managed OAuth login requires private job configuration".into());}
        if let Some((path,profiles))=&settings.jobs {
            if path!=&config_path.parent().ok_or("Missing profile")?.join("jobs") {
                return Err("OAuth jobs require dedicated private job state".into());
            }
            profiles.oauth_summary(workspace_interactive)?;
        }
        if workspace_tools && !workspace_edit {return Err("Workspace tools requires explicit editing profile".into());}
        if workspace_edit && (legacy_operator || state_dir.is_none()) {
            return Err("Workspace editing requires explicit durable onboarding".into());
        }
        let initialize = object.remove("initialize_state").map(|v| v.as_bool().ok_or("Invalid initialization option")).transpose()?.unwrap_or(false);
        if initialize && state_dir.is_none() { return Err("State directory required for initialization".into()); }
        let operator = config["operator_token"].as_str().and_then(super::admission::token_digest).ok_or("Invalid operator credential")?;
        if settings.clients.iter().any(|c| c.has_digest(&operator)) {
            return Err("OAuth preview operator credential must be distinct from native client credentials".into());
        }
        let scope = Scope {
            edit: workspace_edit,
            tools: workspace_tools,
            jobs: workspace_jobs,
            upstreams: workspace_upstreams,
            commands: workspace_commands,
            interactive: workspace_interactive,
        };
        let client = settings.clients.iter().find(|c| Some(c.id.as_str()) == config["local_fixture_client"].as_str() && eligible_client(c, unix_seconds(), scope))
            .ok_or("OAuth preview requires an eligible scoped Standard client")?;
        if workspace_commands != (client.tools.contains(&Tool::ExecCommand) && client.tools.contains(&Tool::TaskRun)){
            return Err("Resume with the exact configured workspace command option".into());
        }
        if workspace_interactive != [Tool::ProcessStart,Tool::ProcessInput,Tool::ProcessResize,Tool::ShellStatus,Tool::ShellReset].iter().all(|t|client.tools.contains(t)) {
            return Err("Resume with the exact configured workspace interactive option".into());
        }
        let bounded_workspace = funnel && (workspace_edit || workspace_jobs);
        if bounded_workspace {
            mcp_gateway::security::linux_fs::bounded_oauth_workspace(&client.root).map_err(|e| e.to_string())?;
        }
        if workspace_upstreams {settings.upstreams.oauth_summary(&client.upstreams)?;}
        if !legacy_operator {
            let profile=config_path.parent().ok_or("Missing profile")?;
            if client.root.starts_with(profile)||profile.starts_with(&client.root)
                || settings.audit_log.as_deref()!=Some(profile.join("audit/events.jsonl").as_path())
            {return Err("Onboarded workspace and private profile must remain separate".into());}
        }
        let durable_policy = state_dir.as_ref().map(|_|settings.digest);
        let mut durable_root = None;
        let mut durable_state_dir = None;
        let server = if let Some(directory) = state_dir {
            let dir = Path::new(directory.as_str().ok_or("Invalid state directory")?);
            let canonical = dir.canonicalize().map_err(|_| "State directory unavailable")?;
            let overlaps = |a: &Path,b: &Path| a.starts_with(b) || b.starts_with(a);
            if dir != canonical || settings.clients.len()!=1
                || overlaps(dir,&client.root) || overlaps(dir,&config_path.canonicalize().map_err(|_|"Policy unavailable")?)
                || settings.audit_log.as_ref().and_then(|p|p.parent()).is_none_or(|p|overlaps(dir,p))
                || settings.job_state_path().is_some_and(|p|overlaps(dir,p))
            { return Err("Durable preview requires separate private state and one scoped client".into()); }
            durable_state_dir = Some(canonical);
            let root = std::fs::symlink_metadata(&client.root).map_err(|_| "Root unavailable")?;
            if !root.is_dir() { return Err("Root unavailable".into()); }
            let root_fd = open_absolute_dir(&client.root).map_err(|_| "Root unavailable")?;
            let root_stat = rustix::fs::fstat(&root_fd).map_err(|_| "Root unavailable")?;
            if (root_stat.st_dev, root_stat.st_ino) != (root.dev(), root.ino()) {
                return Err("Root unavailable".into());
            }
            let durable_id = DurableObjectId::probe(&root_fd, &root_stat)
                .map_err(|_| "Root filesystem identity unavailable")?;
            durable_root = Some((root.dev(),root.ino()));
            let config_canonical = config_path.canonicalize().map_err(|_|"Policy unavailable")?;
            // Bind recovered credentials to this exact policy and durable filesystem object;
            // policy replacement or snapshot/filesystem substitution requires fresh authorization.
            let binding = format!("{:x}", Sha256::digest(serde_json::json!([
                "veyl-native-oauth-v2",settings.digest,&config_canonical,
                client.id,client.root,&durable_id
            ]).to_string().as_bytes()));
            let legacy_binding = format!("{:x}", Sha256::digest(serde_json::json!([
                "veyl-native-oauth-v1",settings.digest,config_canonical,
                client.id,client.root,root.dev(),root.ino()
            ]).to_string().as_bytes()));
            oauth_http::open_durable_with_legacy(origin,config,dir,&binding,Some(&legacy_binding),initialize)?
        } else { oauth_http::open(origin, config, None)? };
        let server=if funnel {server.with_funnel_ingress()} else {server};
        Ok(Self {
            server,
            legacy_operator,
            managed_login,
            workspace_edit,
            workspace_tools,
            workspace_jobs,
            workspace_upstreams,
            workspace_commands,
            workspace_interactive,
            funnel_advanced,
            bounded_workspace,
            verifier: client.credential_digest(),
            root: client.root.clone(),
            config_path: config_path.to_owned(),
            durable_policy,
            durable_root,
            durable_state_dir,
        })
    }

    pub fn client_index(&self, settings: &Configuration, now: u64) -> Option<usize> {
        if settings.tailnet.is_some() || self.durable_policy.is_some_and(|digest| digest!=settings.digest) { return None; }
        if self.bounded_workspace && mcp_gateway::security::linux_fs::bounded_oauth_workspace(&self.root).is_err() { return None; }
        if let Some(expected) = self.durable_root {
            let metadata = std::fs::symlink_metadata(&self.root).ok()?;
            if !metadata.is_dir() || (metadata.dev(),metadata.ino()) != expected { return None; }
        }
        let scope = Scope {
            edit: self.workspace_edit,
            tools: self.workspace_tools,
            jobs: self.workspace_jobs,
            upstreams: self.workspace_upstreams,
            commands: self.workspace_commands,
            interactive: self.workspace_interactive,
        };
        settings.clients.iter().position(|c| c.id == self.server.local_client() && c.root == self.root
            && c.has_digest(&self.verifier) && eligible_client(c, now, scope)
            && (!self.workspace_jobs || settings.jobs.as_ref().is_some_and(|(_,p)|p.oauth_summary(self.workspace_interactive).is_ok()))
            && (!self.workspace_upstreams || settings.upstreams.oauth_summary(&c.upstreams).is_ok()))
    }

    pub fn admit(&self, settings: &Configuration, bearer: Option<&str>, now: u64) -> Option<(usize, Identity)> {
        let identity = self.server.authenticate(bearer)?;
        let index = self.client_index(settings, now)?;
        if identity.local_client != settings.clients[index].id { return None; }
        Some((index, identity))
    }

    pub fn resolve_client_override(
        &self,
        settings: &Configuration,
        index: usize,
        identity: Option<&Identity>,
    ) -> Result<Option<Client>, &'static str> {
        let base = &settings.clients[index];
        if identity.is_some_and(|id| id.mode == ConnectionMode::Yolo) {
            if !self.managed_login || self.durable_state_dir.is_none() {
                return Err("OAuth YOLO unavailable for this profile");
            }
            Ok(Some(base.oauth_yolo_override(settings, &self.config_path)?))
        } else {
            Ok(None)
        }
    }

    pub async fn operator(&self, req: Request<Incoming>, state: Arc<State>) -> Reply {
        let Some(admin) = &state.admin else { return simple(StatusCode::SERVICE_UNAVAILABLE, "Operator unavailable"); };
        // Never make revocation dependent on the native client's current
        // permission status. Approval/inspection still re-read live policy.
        if matches!(req.uri().path(), "/approve" | "/inspect")
            && mcp_gateway::http_common::one(req.headers(), "authorization")
                .and_then(mcp_gateway::http_common::bearer_text)
                .is_some_and(|digest| self.server.operator_matches(&digest))
        {
            let snapshot = state.clone();
            let eligible = self.server.admission_work(true,move || {
                let Ok((_lock, current)) = snapshot.policy.read() else { return false; };
                snapshot.oauth.as_ref().is_some_and(|o| o.client_index(&current,unix_seconds()).is_some())
                    && snapshot.mutations.available()
            }).await.unwrap_or(false);
            if !eligible { return simple(StatusCode::SERVICE_UNAVAILABLE, "Native authorization unavailable"); }
        }
        self.server.handle(req, Some(&admin.addr.to_string()), |_| async {
            simple(StatusCode::NOT_FOUND, "Not found")
        }).await
    }
}
