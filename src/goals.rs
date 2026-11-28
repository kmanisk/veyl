//! Operator and client access to durable development goals.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mcp_gateway::platform::private_store::Store;
use mcp_gateway::security::audit::AuditPhase;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::tools::registry::Tool;

mod runner;

const MAX_GOALS: usize = 128;
const MAX_LIST: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Pending,
    Running,
    Paused,
    Blocked,
    Completed,
    Failed,
    Cancelled,
}

impl State {
    fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Criterion {
    description: String,
    #[serde(default)]
    evidence: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Task {
    id: String,
    description: String,
    #[serde(default)]
    completed: bool,
    #[serde(default)]
    subtasks: Vec<Task>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    completed_work: String,
    outstanding_work: String,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    commits: Vec<String>,
    #[serde(default)]
    jobs: Vec<String>,
    test_results: String,
    next_action: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedCheckpoint {
    at: u64,
    handoff: Checkpoint,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Goal {
    id: String,
    owner: String,
    workspace: PathBuf,
    description: String,
    request_digest: String,
    state: State,
    revision: u64,
    acceptance_criteria: Vec<Criterion>,
    roadmap: Vec<Task>,
    active_task: Option<String>,
    progress: String,
    decisions: Vec<String>,
    findings: Vec<String>,
    blockers: Vec<String>,
    evidence: Vec<String>,
    jobs: Vec<String>,
    checkpoints: Vec<SavedCheckpoint>,
    created_at: u64,
    updated_at: u64,
    completed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "runner::Execution::is_empty")]
    execution: runner::Execution,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u8,
    goals: BTreeMap<String, Goal>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Create {
    description: String,
    request_id: String,
    acceptance_criteria: Vec<Criterion>,
    #[serde(default)]
    roadmap: Vec<Task>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    goal_id: String,
    revision: u64,
    #[serde(default)]
    state: Option<State>,
    #[serde(default)]
    acceptance_criteria: Option<Vec<Criterion>>,
    #[serde(default)]
    roadmap: Option<Vec<Task>>,
    #[serde(default)]
    active_task: Option<String>,
    #[serde(default)]
    progress: Option<String>,
    #[serde(default)]
    decisions: Option<Vec<String>>,
    #[serde(default)]
    findings: Option<Vec<String>>,
    #[serde(default)]
    blockers: Option<Vec<String>>,
    #[serde(default)]
    evidence: Option<Vec<String>>,
    #[serde(default)]
    jobs: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    goal_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    goal_id: String,
    revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Save {
    goal_id: String,
    revision: u64,
    handoff: Checkpoint,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    cursor: Option<String>,
}

pub(crate) struct Owner<'a> {
    pub id: &'a str,
    pub workspace: &'a Path,
}

impl Goal {
    fn owned_by(&self, owner: Option<&Owner<'_>>) -> bool {
        owner.is_none_or(|owner| self.owner == owner.id && self.workspace == owner.workspace)
    }

    fn validate(&self) -> Result<(), String> {
        if !is_id(&self.id)
            || self.owner.is_empty()
            || self.owner.len() > 128
            || !self.workspace.is_absolute()
            || self.request_digest.len() != 64
            || self.revision == 0
            || self.created_at > self.updated_at
            || self.state.terminal() != self.completed_at.is_some()
            || self
                .completed_at
                .is_some_and(|stamp| stamp != self.updated_at)
            || !text(&self.description, 4096)
            || self.progress.len() > 2048
            || self.acceptance_criteria.is_empty()
            || self.acceptance_criteria.len() > 32
            || self.acceptance_criteria.iter().any(|item| {
                !text(&item.description, 1024)
                    || item.evidence.as_ref().is_some_and(|e| !text(e, 1024))
            })
            || [
                &self.decisions,
                &self.findings,
                &self.blockers,
                &self.evidence,
            ]
            .into_iter()
            .any(|entries| !text_list(entries, 32, 1024))
            || !job_ids(&self.jobs)
            || self.checkpoints.len() > 12
            || self
                .checkpoints
                .iter()
                .any(|item| !item.handoff.valid() || item.at > self.updated_at)
            || self.state == State::Blocked && self.blockers.is_empty()
            || self.state == State::Completed && !self.verified()
        {
            return Err("Invalid goal state or goal exceeds storage limits".into());
        }

        self.execution.validate()?;
        let mut tasks = BTreeMap::new();
        validate_tasks(&self.roadmap, 0, &mut tasks)?;
        if self
            .active_task
            .as_ref()
            .is_some_and(|task| tasks.get(task.as_str()) != Some(&false))
        {
            return Err("Active task must be an incomplete roadmap item".into());
        }
        Ok(())
    }

    fn verified(&self) -> bool {
        self.acceptance_criteria
            .iter()
            .all(|item| item.evidence.is_some())
            && self.roadmap.iter().all(|task| task.completed)
            && self.blockers.is_empty()
    }

    fn summary(&self) -> Value {
        let done = self.roadmap.iter().filter(|task| task.completed).count();
        json!({"id":self.id,"owner":self.owner,"workspace":self.workspace,"state":self.state,
               "description":self.description.chars().take(256).collect::<String>(),"revision":self.revision,"active_task":self.active_task,
               "completed_milestones":done,"milestones":self.roadmap.len(),"updated_at":self.updated_at,
               "iterations":self.execution.count(),"stop_reason":self.execution.stop_reason()})
    }
}

impl Checkpoint {
    fn valid(&self) -> bool {
        [
            &self.completed_work,
            &self.outstanding_work,
            &self.test_results,
            &self.next_action,
        ]
        .into_iter()
        .all(|item| text(item, 4096))
            && text_list(&self.files, 32, 1024)
            && text_list(&self.commits, 16, 128)
            && job_ids(&self.jobs)
    }
}

fn text(value: &str, limit: usize) -> bool {
    !value.trim().is_empty() && value.len() <= limit
}

fn text_list(items: &[String], count: usize, limit: usize) -> bool {
    items.len() <= count && items.iter().all(|item| text(item, limit))
}

fn is_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn job_ids(items: &[String]) -> bool {
    items.len() <= 32 && items.iter().all(|item| is_id(item))
}

fn validate_tasks<'a>(
    tasks: &'a [Task],
    depth: usize,
    seen: &mut BTreeMap<&'a str, bool>,
) -> Result<(), String> {
    if !tasks.is_empty() && depth == 3 {
        return Err("Roadmap depth exceeds three levels".into());
    }
    for task in tasks {
        if !text(&task.id, 64)
            || !text(&task.description, 1024)
            || seen.insert(&task.id, task.completed).is_some()
            || seen.len() > 64
            || task.completed && task.subtasks.iter().any(|item| !item.completed)
        {
            return Err("Invalid roadmap. Check unique task IDs, completion and size".into());
        }
        validate_tasks(&task.subtasks, depth + 1, seen)?;
    }
    Ok(())
}

fn find_task<'a>(tasks: &'a [Task], id: &str) -> Option<&'a Task> {
    tasks.iter().find_map(|task| {
        if task.id == id {
            Some(task)
        } else {
            find_task(&task.subtasks, id)
        }
    })
}

fn next_task(tasks: &[Task]) -> Option<&Task> {
    let task = tasks.iter().find(|task| !task.completed)?;
    next_task(&task.subtasks).or(Some(task))
}

fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|error| format!("Invalid goal data: {error}"))
}

fn publish(
    store: &Store,
    registry: &Registry,
    id: &str,
    record: &impl Fn(&str, AuditPhase) -> bool,
) -> Result<Value, String> {
    let goal = registry.goals.get(id).ok_or("Goal unavailable")?;
    goal.validate()?;
    let response = json!(goal);
    if response.to_string().len() > 48_000 {
        return Err("Goal exceeds 48 KB. Condense the roadmap or handoff".into());
    }
    if !record(id, AuditPhase::Intent) {
        return Err("Goal audit intent unavailable".into());
    }
    if let Err(error) = store.write(&json!(registry), false) {
        record(id, AuditPhase::Uncertain);
        return Err(format!("Goal publication requires verification: {error}"));
    }
    if !record(id, AuditPhase::Success) {
        return Err(
            "Goal audit outcome unavailable. Read its current revision before retrying".into(),
        );
    }
    Ok(response)
}

fn get<'a>(
    registry: &'a Registry,
    id: &str,
    owner: Option<&Owner<'_>>,
) -> Result<&'a Goal, String> {
    registry
        .goals
        .get(id)
        .filter(|goal| goal.owned_by(owner))
        .ok_or("Goal unavailable".into())
}

fn load(store: &Store) -> Result<Registry, String> {
    let data = store.read_optional()?;
    let registry = data
        .map(decode::<Registry>)
        .transpose()?
        .unwrap_or_else(|| Registry {
            version: 1,
            goals: BTreeMap::new(),
        });
    if registry.version != 1 || registry.goals.len() > MAX_GOALS {
        return Err("Invalid goal registry".into());
    }
    for (id, goal) in &registry.goals {
        if id != &goal.id {
            return Err("Invalid goal index".into());
        }
        goal.validate()?;
    }
    Ok(registry)
}

pub(crate) fn execute(
    config: &Path,
    owner: Option<&Owner<'_>>,
    tool: Tool,
    args: Value,
    record: impl Fn(&str, AuditPhase) -> bool,
    owns_job: impl Fn(&str, &str) -> bool,
) -> Result<Value, String> {
    let store = Store::open_goals(config)?;
    let mut registry = load(&store)?;
    match tool {
        Tool::GoalList => {
            let list: List = decode(args)?;
            if list.cursor.as_deref().is_some_and(|id| !is_id(id)) {
                return Err("Invalid goal cursor".into());
            }
            let mut entries: Vec<_> = registry
                .goals
                .values()
                .filter(|goal| {
                    goal.owned_by(owner)
                        && list.cursor.as_ref().is_none_or(|cursor| goal.id > *cursor)
                })
                .take(MAX_LIST + 1)
                .collect();
            let next_cursor = if entries.len() > MAX_LIST {
                entries.pop();
                entries.last().map(|goal| &goal.id)
            } else {
                None
            };
            return Ok(
                json!({"goals":entries.into_iter().map(Goal::summary).collect::<Vec<_>>(),
                             "next_cursor":next_cursor}),
            );
        }
        Tool::GoalGet | Tool::GoalNext => {
            let id = decode::<Reference>(args)?.goal_id;
            let goal = get(&registry, &id, owner)?;
            return Ok(if tool == Tool::GoalGet {
                json!(goal)
            } else {
                let task = matches!(goal.state, State::Pending | State::Running)
                    .then(|| {
                        goal.active_task
                            .as_deref()
                            .and_then(|id| find_task(&goal.roadmap, id))
                            .or_else(|| next_task(&goal.roadmap))
                    })
                    .flatten();
                json!({"goal_id":goal.id,"objective":goal.description,"state":goal.state,
                    "revision":goal.revision,"task":task,"checkpoint":goal.checkpoints.last(),
                    "blockers":goal.blockers,"jobs":goal.jobs,"progress":goal.progress})
            });
        }
        Tool::GoalCreate => {
            let create: Create = decode(args)?;
            let owner = owner.ok_or("Choose a client and workspace for the new goal")?;
            if !text(&create.request_id, 128) {
                return Err("Goal creation requires a nonempty request ID".into());
            }
            let key = json!(["veyl-goal-v1", owner.id, owner.workspace, create.request_id]);
            let id = format!("{:x}", Sha256::digest(key.to_string().as_bytes()))[..32].to_owned();
            let digest = format!("{:x}", Sha256::digest(json!(create).to_string().as_bytes()));
            if let Some(goal) = registry.goals.get(&id) {
                return if goal.owned_by(Some(owner)) && goal.request_digest == digest {
                    Ok(json!(goal))
                } else {
                    Err("Request ID already used for another goal".into())
                };
            }
            if registry.goals.len() >= MAX_GOALS {
                return Err("Goal storage is full".into());
            }
            let now = crate::http::unix_seconds();
            registry.goals.insert(
                id.clone(),
                Goal {
                    id: id.clone(),
                    owner: owner.id.to_owned(),
                    workspace: owner.workspace.to_owned(),
                    description: create.description,
                    request_digest: digest,
                    state: State::Pending,
                    revision: 1,
                    acceptance_criteria: create.acceptance_criteria,
                    roadmap: create.roadmap,
                    active_task: None,
                    progress: String::new(),
                    decisions: Vec::new(),
                    findings: Vec::new(),
                    blockers: Vec::new(),
                    evidence: Vec::new(),
                    jobs: Vec::new(),
                    checkpoints: Vec::new(),
                    created_at: now,
                    updated_at: now,
                    completed_at: None,
                    execution: runner::Execution::default(),
                },
            );
            return publish(&store, &registry, &id, &record);
        }
        _ => {}
    }

    let (id, revision) = if tool == Tool::GoalUpdate {
        let update: Update = decode(args.clone())?;
        (update.goal_id, update.revision)
    } else if tool == Tool::GoalCheckpoint {
        let checkpoint: Save = decode(args.clone())?;
        (checkpoint.goal_id, checkpoint.revision)
    } else {
        let change: Change = decode(args.clone())?;
        (change.goal_id, change.revision)
    };
    let current = get(&registry, &id, owner)?;
    if current.revision != revision {
        return Err("Goal revision changed. Retrieve the current goal before retrying".into());
    }
    if current.state.terminal() {
        return Err("Goal is already terminal".into());
    }
    if current.execution.is_active() && !matches!(tool, Tool::GoalPause | Tool::GoalCancel) {
        return Err("An iteration owns this goal. Pause or cancel it before editing".into());
    }
    let goal = registry.goals.get_mut(&id).ok_or("Goal unavailable")?;
    goal.updated_at = crate::http::unix_seconds().max(goal.updated_at);
    goal.revision = goal
        .revision
        .checked_add(1)
        .ok_or("Invalid goal revision")?;
    match tool {
        Tool::GoalUpdate => {
            let update: Update = decode(args)?;
            apply_update(goal, update, &owns_job)?;
        }
        Tool::GoalCheckpoint => {
            let save: Save = decode(args)?;
            if !save.handoff.valid() || !save.handoff.jobs.iter().all(|job| goal.jobs.contains(job))
            {
                return Err("Invalid checkpoint. Link owned jobs to the goal first".into());
            }
            if goal.checkpoints.len() == 12 {
                goal.checkpoints.remove(0);
            }
            goal.checkpoints.push(SavedCheckpoint {
                at: goal.updated_at,
                handoff: save.handoff,
            });
        }
        Tool::GoalPause
            if matches!(goal.state, State::Pending | State::Running | State::Blocked) =>
        {
            goal.state = State::Paused;
        }
        Tool::GoalResume
            if matches!(goal.state, State::Pending | State::Paused | State::Blocked)
                && goal.blockers.is_empty() =>
        {
            goal.execution.resume_paused_iteration();
            goal.state = State::Running;
        }
        Tool::GoalComplete
            if matches!(goal.state, State::Pending | State::Running) && goal.verified() =>
        {
            goal.state = State::Completed;
        }
        Tool::GoalCancel => goal.state = State::Cancelled,
        _ => {
            return Err(
                "Goal cannot make this transition. Check its blockers and verification evidence"
                    .into(),
            );
        }
    }
    if goal.state.terminal() {
        goal.active_task = None;
        goal.completed_at = Some(goal.updated_at);
    }
    publish(&store, &registry, &id, &record)
}

fn apply_update(
    goal: &mut Goal,
    update: Update,
    owns_job: &impl Fn(&str, &str) -> bool,
) -> Result<(), String> {
    if let Some(state) = update.state {
        if !matches!(state, State::Running | State::Blocked | State::Failed)
            || goal.state == State::Paused && state != State::Failed
        {
            return Err("Use the explicit lifecycle command for this transition".into());
        }
        goal.state = state;
    }
    if let Some(criteria) = update.acceptance_criteria {
        goal.acceptance_criteria = criteria;
    }
    if let Some(roadmap) = update.roadmap {
        goal.roadmap = roadmap;
    }
    if let Some(task) = update.active_task {
        goal.active_task = (!task.is_empty()).then_some(task);
    }
    if let Some(progress) = update.progress {
        goal.progress = progress;
    }
    if let Some(decisions) = update.decisions {
        goal.decisions = decisions;
    }
    if let Some(findings) = update.findings {
        goal.findings = findings;
    }
    if let Some(blockers) = update.blockers {
        goal.blockers = blockers;
    }
    if let Some(evidence) = update.evidence {
        goal.evidence = evidence;
    }
    if let Some(jobs) = update.jobs {
        if !job_ids(&jobs)
            || !jobs
                .iter()
                .all(|job| goal.jobs.contains(job) || owns_job(&goal.owner, job))
        {
            return Err("Associated job unavailable to this goal owner".into());
        }
        goal.jobs = jobs;
    }
    Ok(())
}

pub(crate) fn stop_active_runner(
    jobs: &crate::jobs::Jobs,
    tool: Tool,
    goal: &Value,
) -> Result<(), String> {
    if matches!(tool, Tool::GoalPause | Tool::GoalCancel) {
        runner::cancel_active(jobs, goal)?;
    }
    Ok(())
}

pub(crate) fn operator_call(
    config: &Path,
    settings: &crate::http::admission::Configuration,
    client: Option<&str>,
    tool: Tool,
    args: Value,
) -> Result<Value, String> {
    use mcp_gateway::security::audit::AuditSink;
    let audit = settings
        .audit_log
        .as_ref()
        .ok_or("Goals require an audit ledger")?;
    let sink = AuditSink::open_with_limits(audit, settings.audit_limits)
        .map_err(|_| "Goal audit unavailable")?;
    let owner = client
        .map(|name| {
            settings
                .clients
                .iter()
                .find(|client| client.id == name && !client.is_disabled())
                .map(|client| Owner {
                    id: &client.id,
                    workspace: &client.root,
                })
                .ok_or("Enabled goal client unavailable")
        })
        .transpose()?;
    execute(
        config,
        owner.as_ref(),
        tool,
        args,
        |id, phase| {
            sink.record_runtime_mode(
                "local_operator",
                &format!("{}/{id}", tool.name()),
                "standard",
                phase,
                crate::http::unix_seconds(),
            )
            .is_ok()
        },
        |owner, job| {
            settings
                .job_state_path()
                .is_some_and(|state| crate::jobs::owns_job(state, owner, job))
        },
    )
}

pub(crate) fn cli(args: &[std::ffi::OsString]) -> Result<(), String> {
    use std::io::Read;
    if args
        .first()
        .is_some_and(|arg| arg == "run" || arg == "retry")
    {
        return runner::cli(args);
    }

    const USAGE: &str = "Usage: veyl goal list|get|next|create|update|checkpoint|pause|resume|complete|cancel [ID [REVISION]] [--client ID] [--config PATH]\nveyl goal run|retry ID --runner PATH --confirm-runner [--iterations N] [--seconds N] [--retries N]\nCreate, update and checkpoint accept JSON on stdin. Create can also take an objective, with --criterion TEXT and an optional --request-id ID.";
    if args.is_empty() || args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let name = format!("goal_{}", args[0].to_str().ok_or(USAGE)?);
    let tool = Tool::parse(&name)
        .filter(|tool| tool.is_goal())
        .ok_or(USAGE)?;
    let (mut config, mut client, mut positionals) = (None, None, Vec::new());
    let (mut criteria, mut request_id) = (Vec::new(), None);
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.to_str().ok_or(USAGE)? {
            "--config" if config.is_none() => {
                config = Some(PathBuf::from(rest.next().ok_or(USAGE)?))
            }
            "--client" if client.is_none() => {
                client = Some(rest.next().and_then(|arg| arg.to_str()).ok_or(USAGE)?)
            }
            "--criterion" if tool == Tool::GoalCreate => criteria.push(json!({
                "description":rest.next().and_then(|arg| arg.to_str()).ok_or(USAGE)?
            })),
            "--request-id" if tool == Tool::GoalCreate && request_id.is_none() => {
                request_id = Some(rest.next().and_then(|arg| arg.to_str()).ok_or(USAGE)?);
            }
            pos if !pos.starts_with('-') => positionals.push(pos),
            _ => return Err(USAGE.into()),
        }
    }
    let config = resolve_config(config)?;
    let policy = crate::http::operator::PolicyFile::lock(&config, false)?;
    let settings = policy.snapshot()?;
    crate::http::operator::verify_approvals(&settings)?;
    let client = if tool == Tool::GoalCreate && client.is_none() {
        let mut eligible = settings.clients.iter().filter(|client| {
            !client.is_disabled() && client.expires_at > crate::http::unix_seconds()
        });
        let only = eligible
            .next()
            .ok_or("Choose an enabled static client with --client ID")?;
        if eligible.next().is_some() {
            return Err("Several static clients are enabled. Choose one with --client ID".into());
        }
        Some(only.id.as_str())
    } else {
        client
    };
    let args = match (tool, positionals.as_slice()) {
        (Tool::GoalCreate, [description]) => {
            if criteria.is_empty() {
                return Err("Specify at least one --criterion".into());
            }
            let digest = format!(
                "{:x}",
                Sha256::digest(json!([description, criteria]).to_string().as_bytes())
            );
            json!({"description":description,"request_id":request_id.unwrap_or(&digest),
                "acceptance_criteria":criteria})
        }
        (Tool::GoalList, []) => json!({}),
        (Tool::GoalList, [cursor]) => json!({"cursor":cursor}),
        (Tool::GoalGet | Tool::GoalNext, [id]) => json!({"goal_id":id}),
        (Tool::GoalPause | Tool::GoalResume | Tool::GoalComplete | Tool::GoalCancel, [id]) => {
            let revision = operator_call(
                &config,
                &settings,
                client,
                Tool::GoalGet,
                json!({"goal_id":id}),
            )?["revision"]
                .clone();
            json!({"goal_id":id,"revision":revision})
        }
        (
            Tool::GoalPause | Tool::GoalResume | Tool::GoalComplete | Tool::GoalCancel,
            [id, revision],
        ) => {
            json!({"goal_id":id,"revision":revision.parse::<u64>().map_err(|_| USAGE)?})
        }
        (Tool::GoalCreate | Tool::GoalUpdate | Tool::GoalCheckpoint, []) => {
            let mut data = Vec::new();
            std::io::stdin()
                .take(64_001)
                .read_to_end(&mut data)
                .map_err(|_| "Cannot read goal input")?;
            if data.len() > 64_000 {
                return Err("Goal input exceeds 64 KB".into());
            }
            crate::http::operator::parse_unique_json(&data)?
        }
        _ => return Err(USAGE.into()),
    };
    let result = operator_call(&config, &settings, client, tool, args)?;
    if matches!(tool, Tool::GoalPause | Tool::GoalCancel)
        && result["execution"]["active"].is_object()
    {
        let (job_path, profiles) = settings
            .jobs
            .as_ref()
            .ok_or("Goal stop was saved. Jobs are unavailable")?;
        let audit = settings
            .audit_log
            .as_ref()
            .ok_or("Goal stop was saved. Job audit is unavailable")?;
        let jobs =
            crate::jobs::Jobs::open(job_path, profiles.clone(), audit, settings.audit_limits)?;
        stop_active_runner(&jobs, tool, &result)?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|_| "Cannot encode goal response")?
    );
    Ok(())
}

fn resolve_config(config: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(path) = config {
        return Ok(path);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("HOME must be absolute")?;
    let unified = home.join(".local/state/veyl/clients.json");
    if unified
        .try_exists()
        .map_err(|_| "Cannot inspect unified registry")?
    {
        return Ok(unified);
    }
    crate::local_cli::optional_default_config()?.ok_or("No Veyl policy found".into())
}
