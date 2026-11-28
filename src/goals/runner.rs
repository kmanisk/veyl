//! Explicit foreground controller. Each reasoning turn is a signed durable job.
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mcp_gateway::security::audit::AuditSink;
use mcp_gateway::security::policy::ExecutionMode;
use rustix::fd::OwnedFd;

use super::*;
use crate::http::operator::{PolicyFile, verify_approvals};
use crate::jobs::{JobPolicy, Jobs};

const USAGE: &str = "Usage: veyl goal run|retry ID --runner ABSOLUTE_PATH --confirm-runner [--iterations N] [--seconds N] [--retries N] [--config PATH]";
const MAX_ITERATIONS: u32 = 16;
const MAX_SECONDS: u64 = 86_400;
const MAX_OUTPUT: usize = 16_384;

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Execution {
    #[serde(default)]
    history: Vec<Iteration>,
    active: Option<Active>,
    budget: Option<Budget>,
    stop_reason: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Iteration {
    number: u32,
    started_at: u64,
    ended_at: u64,
    job_id: Option<String>,
    outcome: String,
    detail: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Active {
    number: u32,
    started_at: u64,
    job_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    runner: PathBuf,
    digest: String,
    deadline: u64,
    through: u32,
    retries: u32,
    failures: u32,
    stagnant: u32,
}

impl Execution {
    pub(super) fn is_empty(&self) -> bool {
        self.history.is_empty()
            && self.active.is_none()
            && self.budget.is_none()
            && self.stop_reason.is_none()
    }

    pub(super) fn is_active(&self) -> bool {
        self.active.is_some()
    }

    pub(super) fn count(&self) -> u32 {
        self.history.last().map_or(0, |turn| turn.number)
    }

    pub(super) fn resume_paused_iteration(&mut self) {
        if self
            .history
            .last()
            .is_some_and(|turn| turn.outcome == "paused")
        {
            self.stop_reason = None;
        }
    }

    pub(super) fn stop_reason(&self) -> Option<&str> {
        self.stop_reason.as_deref()
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.history.len() > MAX_ITERATIONS as usize
            || self.history.iter().any(|turn| {
                turn.number == 0
                    || turn.started_at > turn.ended_at
                    || turn.job_id.as_deref().is_some_and(|id| !is_id(id))
                    || !matches!(
                        turn.outcome.as_str(),
                        "progress"
                            | "failed"
                            | "blocked"
                            | "timed_out"
                            | "interrupted"
                            | "cancelled"
                            | "paused"
                            | "completed"
                    )
                    || !text(&turn.detail, 1024)
            })
            || self
                .history
                .windows(2)
                .any(|w| w[0].number.checked_add(1) != Some(w[1].number))
            || self.active.as_ref().is_some_and(|turn| {
                self.count().checked_add(1) != Some(turn.number)
                    || turn.job_id.as_deref().is_some_and(|id| !is_id(id))
                    || self.budget.is_none()
            })
            || self.budget.as_ref().is_some_and(|budget| {
                !budget.runner.is_absolute()
                    || budget.digest.len() != 64
                    || budget.deadline == 0
                    || budget.through < self.count()
                    || budget.retries > 5
                    || budget.failures > budget.retries + 1
                    || budget.stagnant > 3
            })
            || self
                .stop_reason
                .as_deref()
                .is_some_and(|reason| !text(reason, 1024))
        {
            return Err("Invalid goal execution history".into());
        }
        Ok(())
    }
}

struct Options {
    runner: PathBuf,
    digest: String,
    iterations: u32,
    seconds: u64,
    retries: u32,
}

struct Controller<'a> {
    config: &'a Path,
    goal_id: &'a str,
    audit: AuditSink,
    jobs: Jobs,
    job_path: PathBuf,
    _guard: OwnedFd,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    progress: String,
    #[serde(default)]
    roadmap: Option<Vec<Task>>,
    #[serde(default)]
    acceptance_criteria: Option<Vec<Criterion>>,
    #[serde(default)]
    blockers: Option<Vec<String>>,
    #[serde(default)]
    decisions: Option<Vec<String>>,
    #[serde(default)]
    findings: Option<Vec<String>>,
    #[serde(default)]
    evidence: Option<Vec<String>>,
    checkpoint: Option<Checkpoint>,
}

pub(super) fn cli(args: &[OsString]) -> Result<(), String> {
    let retry = args[0] == "retry";
    let id = args
        .get(1)
        .and_then(|id| id.to_str())
        .filter(|id| is_id(id))
        .ok_or(USAGE)?;
    let (mut runner, mut config) = (None, None);
    let (mut iterations, mut seconds, mut retries) = (None, None, None);
    let mut confirmed = false;
    let mut flags = args[2..].iter();
    while let Some(arg) = flags.next() {
        match arg.to_str().ok_or(USAGE)? {
            "--runner" if runner.is_none() => {
                runner = Some(PathBuf::from(flags.next().ok_or(USAGE)?))
            }
            "--config" if config.is_none() => {
                config = Some(PathBuf::from(flags.next().ok_or(USAGE)?))
            }
            "--confirm-runner" if !confirmed => confirmed = true,
            "--iterations" if iterations.is_none() => {
                iterations = Some(number(flags.next(), 1, MAX_ITERATIONS.into())? as u32)
            }
            "--seconds" if seconds.is_none() => {
                seconds = Some(number(flags.next(), 1, MAX_SECONDS)?)
            }
            "--retries" if retries.is_none() => retries = Some(number(flags.next(), 0, 5)? as u32),
            _ => return Err(USAGE.into()),
        }
    }
    if !confirmed {
        return Err(
            "Explicit --confirm-runner required for host execution and possible model charges"
                .into(),
        );
    }
    let (runner, digest) = identify(&runner.ok_or(USAGE)?)?;
    let options = Options {
        runner,
        digest,
        iterations: iterations.unwrap_or(8),
        seconds: seconds.unwrap_or(900),
        retries: retries.unwrap_or(2),
    };
    let config = resolve_config(config)?;
    let controller = Controller::open(&config, id)?;
    controller.run(&options, retry)
}

fn number(arg: Option<&OsString>, min: u64, max: u64) -> Result<u64, String> {
    arg.and_then(|arg| arg.to_str())
        .and_then(|n| n.parse().ok())
        .filter(|n| (min..=max).contains(n))
        .ok_or(USAGE.into())
}

fn identify(path: &Path) -> Result<(PathBuf, String), String> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    if !path.is_absolute() {
        return Err("Runner requires an explicit absolute executable path".into());
    }
    let path = path
        .canonicalize()
        .map_err(|_| "Runner executable unavailable")?;
    let file = std::fs::File::open(&path).map_err(|_| "Runner executable unavailable")?;
    let metadata = file.metadata().map_err(|_| "Runner metadata unavailable")?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || !matches!(metadata.uid(), 0) && metadata.uid() != uid
        || metadata.mode() & 0o6022 != 0
        || metadata.mode() & 0o100 == 0
        || metadata.len() > 64 * 1024 * 1024
    {
        return Err("Runner must be an executable owned by the operator or root and cannot grant elevated privileges".into());
    }
    let mut file = file.take(64 * 1024 * 1024 + 1);
    let mut hasher = Sha256::new();
    if std::io::copy(&mut file, &mut hasher).map_err(|_| "Cannot hash runner")? != metadata.len() {
        return Err("Runner executable changed while being read".into());
    }
    Ok((path, format!("{:x}", hasher.finalize())))
}

impl<'a> Controller<'a> {
    fn open(config: &'a Path, goal_id: &'a str) -> Result<Self, String> {
        let guard = {
            let store = Store::open_goals(config)?;
            get(&load(&store)?, goal_id, None)?;
            store.goal_run_guard(goal_id)?
        };
        let policy = PolicyFile::lock(config, false)?;
        let settings = policy.snapshot()?;
        verify_approvals(&settings)?;
        let audit_path = settings
            .audit_log
            .as_ref()
            .ok_or("Goals require an audit ledger")?;
        let (job_path, profiles) = settings
            .jobs
            .as_ref()
            .ok_or("Goals require configured jobs")?;
        Ok(Self {
            config,
            goal_id,
            job_path: job_path.clone(),
            _guard: guard,
            jobs: Jobs::open(
                job_path,
                profiles.clone(),
                audit_path,
                settings.audit_limits,
            )?,
            audit: AuditSink::open_with_limits(audit_path, settings.audit_limits)
                .map_err(|_| "Goal audit unavailable")?,
        })
    }

    fn open_store(&self) -> Result<Store, String> {
        for _ in 0..4 {
            match Store::open_goals(self.config) {
                Err(error) if error == "State in use or lock unavailable" => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                result => return result,
            }
        }
        Store::open_goals(self.config)
    }

    fn read(&self) -> Result<Goal, String> {
        let mut registry = load(&self.open_store()?)?;
        registry
            .goals
            .remove(self.goal_id)
            .ok_or("Goal unavailable".into())
    }

    fn change(
        &self,
        action: &str,
        change: impl FnOnce(&mut Goal) -> Result<(), String>,
    ) -> Result<(), String> {
        let store = self.open_store()?;
        let mut registry = load(&store)?;
        let goal = registry
            .goals
            .get_mut(self.goal_id)
            .ok_or("Goal unavailable")?;
        goal.updated_at = crate::http::unix_seconds().max(goal.updated_at);
        goal.revision = goal
            .revision
            .checked_add(1)
            .ok_or("Invalid goal revision")?;
        change(goal)?;
        publish(&store, &registry, self.goal_id, &|id, phase| {
            self.audit
                .record_runtime_mode(
                    "local_operator",
                    &format!("goal_{action}/{id}"),
                    "standard",
                    phase,
                    crate::http::unix_seconds(),
                )
                .is_ok()
        })?;
        Ok(())
    }

    fn run(&self, options: &Options, retry: bool) -> Result<(), String> {
        let initial = self.read()?;
        if matches!(initial.state, State::Completed | State::Cancelled)
            && !initial.execution.is_active()
        {
            return Err("Goal is already terminal".into());
        }
        if retry && initial.execution.is_active() {
            return Err("Reconcile the active iteration with goal run before retrying".into());
        }
        if !initial.execution.is_active() && (retry || initial.execution.budget.is_none()) {
            let (_policy, settings) = self.authority()?;
            eligible_client(&initial, &settings)?;
            self.change(if retry { "retry" } else { "run" }, |goal| {
                if matches!(goal.state, State::Completed | State::Cancelled)
                    || !goal.blockers.is_empty()
                {
                    return Err("Resolve the goal's blockers before starting another run".into());
                }
                goal.execution.budget = Some(Budget {
                    runner: options.runner.clone(),
                    digest: options.digest.clone(),
                    deadline: crate::http::unix_seconds().saturating_add(options.seconds),
                    through: goal
                        .execution
                        .count()
                        .checked_add(options.iterations)
                        .ok_or("Iteration counter overflow")?,
                    retries: options.retries,
                    failures: 0,
                    stagnant: 0,
                });
                goal.execution.stop_reason = None;
                goal.completed_at = None;
                goal.state = State::Running;
                Ok(())
            })?;
        }

        loop {
            let goal = self.read()?;
            if let Some(active) = &goal.execution.active {
                self.reconcile(&goal, active)?;
                continue;
            }
            if goal.state != State::Running || goal.execution.stop_reason.is_some() {
                return print_goal(&goal);
            }
            let budget = goal
                .execution
                .budget
                .as_ref()
                .ok_or("Goal run has no budget")?;
            if budget.runner != options.runner || budget.digest != options.digest {
                return Err("Runner changed. Authorize it with goal retry and a new budget".into());
            }
            let now = crate::http::unix_seconds();
            if goal.execution.count() >= budget.through
                || now >= budget.deadline
                || goal.jobs.len() >= 32
            {
                self.stop("Execution budget reached")?;
                continue;
            }
            let context = context(&goal)?;
            let (policy, settings) = self.authority()?;
            let client = eligible_client(&goal, &settings)?;
            if identify(&options.runner)?.1 != options.digest {
                return Err("Runner changed before launch".into());
            }
            let timeout = (budget.deadline - now).min(client.job_runtime_limit_seconds);
            let active = Active {
                number: goal.execution.count() + 1,
                started_at: now,
                job_id: None,
            };
            self.change("iteration_start", |current| {
                if current.state != State::Running || current.revision != goal.revision + 1 {
                    return Err("Goal changed before iteration admission".into());
                }
                current.execution.active = Some(active.clone());
                Ok(())
            })?;
            let mut argv = vec![
                options
                    .runner
                    .to_str()
                    .ok_or("Runner path must be UTF-8")?
                    .to_owned(),
            ];
            argv.extend(chunks(&context));
            // Do not hold the policy lock while waiting for a job. The signed
            // runner revalidates this exact native grant before and during spawn.
            drop(policy);
            let request = self.request(active.number);
            let job_policy = JobPolicy {
                oauth_family: false,
                oauth_bounded_workspace: false,
                yolo: false,
                session: None,
                native_authority: client
                    .yolo_revision
                    .as_deref()
                    .map(|rev| (self.config, rev)),
                oauth: None,
                full: true,
                job_runtime_limit_seconds: client.job_runtime_limit_seconds,
                native_default_timeout: client.native_default_timeout,
                job_cpu_percent_limit: client.job_cpu_percent_limit,
                job_memory_bytes_limit: client.job_memory_bytes_limit,
                job_output_limit_bytes: client.job_output_limit_bytes,
                job_retention_count: client.job_retention_count,
                broad: None,
                workspace_mounts: None,
            };
            let args = json!({"argv":argv, "timeout_seconds":timeout, "wait_seconds":0,
                "max_output_bytes":MAX_OUTPUT.min(client.job_output_limit_bytes), "request_id":request});
            let result = self.jobs.call(
                Tool::TaskRun,
                Some(&args),
                &goal.owner,
                client
                    .job_root
                    .as_ref()
                    .ok_or("Goal workspace unavailable")?,
                job_policy,
            );
            if result["isError"] == false {
                let job: Value = serde_json::from_str(
                    result["content"][0]["text"]
                        .as_str()
                        .ok_or("Invalid job response")?,
                )
                .map_err(|_| "Invalid job response")?;
                self.attach(
                    active.number,
                    job["job_id"]
                        .as_str()
                        .filter(|id| is_id(id))
                        .ok_or("Invalid job receipt")?,
                )?;
            } else {
                // A launch error can occur after spawn. Reconcile by request
                // before allowing a new attempt or reporting a policy error.
                eprintln!(
                    "Goal iteration requires reconciliation: {}",
                    result["content"][0]["text"]
                        .as_str()
                        .unwrap_or("job unavailable")
                );
            }
        }
    }

    fn authority(&self) -> Result<(PolicyFile, crate::http::admission::Configuration), String> {
        let policy = PolicyFile::lock(self.config, false)?;
        let settings = policy.snapshot()?;
        verify_approvals(&settings)?;
        if settings.job_state_path() != Some(&self.job_path) {
            return Err("Job state changed while the controller was active".into());
        }
        Ok((policy, settings))
    }

    fn request(&self, number: u32) -> String {
        format!("goal-{}-{number}", self.goal_id)
    }

    fn attach(&self, number: u32, id: &str) -> Result<(), String> {
        self.change("iteration_link", |goal| {
            let active = goal
                .execution
                .active
                .as_mut()
                .filter(|turn| turn.number == number)
                .ok_or("Goal iteration changed")?;
            if active.job_id.as_deref().is_some_and(|job| job != id) {
                return Err("Goal iteration job changed".into());
            }
            active.job_id = Some(id.to_owned());
            if !goal.jobs.iter().any(|job| job == id) {
                goal.jobs.push(id.to_owned());
            }
            Ok(())
        })
    }

    fn reconcile(&self, goal: &Goal, active: &Active) -> Result<(), String> {
        let id = match &active.job_id {
            Some(id) => Some(id.clone()),
            None => self
                .jobs
                .find_request(&goal.owner, &self.request(active.number))?,
        };
        let Some(id) = id else {
            return self.finish(
                active.number,
                "interrupted",
                "Job delivery uncertain. Inspect jobs before an explicit retry",
                None,
            );
        };
        if active.job_id.is_none() {
            return self.attach(active.number, &id);
        }
        let arguments = serde_json::Map::new();
        let status = match self
            .jobs
            .owned_tool(Tool::JobStatus, &id, &goal.owner, &arguments)
        {
            Ok(status) => status,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return self.finish(
                    active.number,
                    "interrupted",
                    "Job receipt unavailable. Inspect the workspace before retrying",
                    None,
                );
            }
            Err(_) => {
                return Err(
                    "Cannot read the active job. Reconnect without starting another iteration"
                        .into(),
                );
            }
        };
        let state = status["state"].as_str().ok_or("Invalid job state")?;
        let goal_stopped = matches!(goal.state, State::Paused | State::Cancelled);
        let now = crate::http::unix_seconds();
        let deadline = goal
            .execution
            .budget
            .as_ref()
            .ok_or("Goal run has no budget")?
            .deadline;
        if matches!(state, "starting" | "queued" | "running") || status["recovery"].is_string() {
            if now > deadline.saturating_add(10) {
                return Err("Iteration deadline passed with an active receipt. Inspect the linked job before retrying".into());
            }
            if goal_stopped || now >= deadline {
                self.jobs
                    .owned_tool(Tool::JobCancel, &id, &goal.owner, &arguments)
                    .map_err(|_| "Job cancellation uncertain. Reconnect to reconcile")?;
            }
            std::thread::sleep(Duration::from_secs(1));
            return Ok(());
        }
        if !goal_stopped && (state == "timed_out" || state == "canceled" && now >= deadline) {
            return self.finish(
                active.number,
                "timed_out",
                "An iteration reached its execution time limit",
                None,
            );
        }
        if goal_stopped || matches!(state, "interrupted" | "canceled" | "lost" | "uncertain") {
            let outcome = match goal.state {
                State::Paused => "paused",
                State::Cancelled => "cancelled",
                _ => "interrupted",
            };
            return self.finish(
                active.number,
                outcome,
                "Iteration stopped. Inspect the linked job and workspace",
                None,
            );
        }
        if status["exit_code"] != 0 {
            return self.finish(
                active.number,
                "failed",
                "Runner exited unsuccessfully. Inspect the linked job logs",
                None,
            );
        }
        let mut log_args = serde_json::Map::new();
        log_args.insert("max_bytes".into(), json!(MAX_OUTPUT));
        let logs = self
            .jobs
            .owned_tool(Tool::JobLogs, &id, &goal.owner, &log_args)
            .map_err(|_| "Iteration logs unavailable. Reconnect to reconcile")?;
        let output = logs["stdout"].as_str().unwrap_or_default();
        if logs["stdout_truncated"] == true || output.len() >= MAX_OUTPUT {
            return self.finish(
                active.number,
                "failed",
                "Runner output exceeded the iteration limit",
                None,
            );
        }
        let response: Response =
            match crate::http::operator::parse_unique_json(output.as_bytes()).and_then(decode) {
                Ok(response) => response,
                Err(_) => {
                    return self.finish(
                        active.number,
                        "failed",
                        "Runner did not return one valid result object",
                        None,
                    );
                }
            };
        let result = self.finish(
            active.number,
            "progress",
            "Recorded the runner result",
            Some(response),
        );
        if result
            .as_ref()
            .is_err_and(|error| error.starts_with("Invalid runner result:"))
        {
            return self.finish(
                active.number,
                "failed",
                "Runner result violates the goal contract. Inspect the linked logs",
                None,
            );
        }
        result
    }

    fn finish(
        &self,
        number: u32,
        mut outcome: &str,
        detail: &str,
        result: Option<Response>,
    ) -> Result<(), String> {
        self.change("iteration_finish", |goal| {
            let active = goal
                .execution
                .active
                .take()
                .filter(|turn| turn.number == number)
                .ok_or("Goal iteration changed")?;
            if goal.state == State::Paused {
                outcome = "paused";
            }
            if goal.state == State::Cancelled {
                outcome = "cancelled";
            }
            let mut advanced = false;
            if outcome == "progress"
                && let Some(result) = result
            {
                let before = achievement(goal);
                apply(goal, result).map_err(|error| format!("Invalid runner result: {error}"))?;
                advanced = achievement(goal) != before;
                if !goal.blockers.is_empty() {
                    outcome = "blocked";
                    goal.state = State::Blocked;
                } else if !goal.roadmap.is_empty() && goal.verified() {
                    outcome = "completed";
                    goal.state = State::Completed;
                    goal.active_task = None;
                    goal.completed_at = Some(goal.updated_at);
                }
            }
            let budget = goal
                .execution
                .budget
                .as_mut()
                .ok_or("Goal run has no budget")?;
            budget.failures = if outcome == "failed" {
                budget.failures + 1
            } else {
                0
            };
            budget.stagnant = if outcome == "progress" && !advanced {
                budget.stagnant + 1
            } else {
                0
            };
            let stop = match outcome {
                "failed" if budget.failures > budget.retries => {
                    Some("Runner retry budget exhausted")
                }
                "progress" if budget.stagnant >= 3 => {
                    Some("Three iterations made no verifiable progress")
                }
                "timed_out" | "interrupted" | "paused" | "cancelled" => Some(detail),
                "blocked" => Some("Runner reported a blocker"),
                "completed" => Some("Acceptance criteria and roadmap recorded"),
                _ => None,
            };
            if let Some(reason) = stop {
                goal.execution.stop_reason = Some(reason.into());
                if goal.state == State::Running {
                    goal.state = State::Paused;
                }
            }
            if goal.state == State::Cancelled {
                goal.completed_at = Some(goal.updated_at);
            }
            if goal.execution.history.len() == MAX_ITERATIONS as usize {
                goal.execution.history.remove(0);
            }
            goal.execution.history.push(Iteration {
                number,
                started_at: active.started_at,
                ended_at: goal.updated_at,
                job_id: active.job_id,
                outcome: outcome.into(),
                detail: detail.into(),
            });
            goal.validate()
                .map_err(|error| format!("Invalid runner result: {error}"))?;
            let encoded = serde_json::to_vec(goal).map_err(|_| "Cannot encode result")?;
            if encoded.len() > 48_000 {
                return Err("Invalid runner result: goal exceeds 48 KB".into());
            }
            Ok(())
        })
    }

    fn stop(&self, reason: &str) -> Result<(), String> {
        self.change("budget_stop", |goal| {
            if goal.state == State::Running {
                goal.state = State::Paused;
                goal.execution.stop_reason = Some(reason.into());
            }
            Ok(())
        })
    }
}

fn eligible_client<'a>(
    goal: &Goal,
    settings: &'a crate::http::admission::Configuration,
) -> Result<&'a crate::http::admission::Client, String> {
    let now = crate::http::unix_seconds();
    settings
        .clients
        .iter()
        .find(|client| {
            client.id == goal.owner
                && client.root == goal.workspace
                && !client.is_disabled()
                && client.expires_at > now
                && client.mode == ExecutionMode::Yolo
                && client.yolo_revision.is_some()
                && client.job_root.is_some()
        })
        .ok_or(
            "Automatic runs require an enabled, unexpired static YOLO owner with job access".into(),
        )
}

fn print_goal(goal: &Goal) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(goal).map_err(|_| "Cannot encode goal response")?
    );
    Ok(())
}

fn achievement(goal: &Goal) -> (usize, usize, bool) {
    fn done(tasks: &[Task]) -> usize {
        tasks
            .iter()
            .map(|task| usize::from(task.completed) + done(&task.subtasks))
            .sum()
    }
    (
        done(&goal.roadmap),
        goal.acceptance_criteria
            .iter()
            .filter(|criterion| criterion.evidence.is_some())
            .count(),
        !goal.roadmap.is_empty(),
    )
}

fn apply(goal: &mut Goal, result: Response) -> Result<(), String> {
    fn keeps_completed(old: &[Task], new: &[Task]) -> bool {
        old.iter().all(|task| {
            (!task.completed
                || find_task(new, &task.id).is_some_and(|current| {
                    current.completed && current.description == task.description
                }))
                && keeps_completed(&task.subtasks, new)
        })
    }
    if !text(&result.progress, 2048)
        || result
            .roadmap
            .as_ref()
            .is_some_and(|roadmap| !keeps_completed(&goal.roadmap, roadmap))
        || result.acceptance_criteria.as_ref().is_some_and(|criteria| {
            criteria.len() != goal.acceptance_criteria.len()
                || criteria
                    .iter()
                    .zip(&goal.acceptance_criteria)
                    .any(|(new, old)| {
                        new.description != old.description
                            || old.evidence.is_some() && new.evidence.is_none()
                    })
        })
    {
        return Err("Keep the acceptance criteria and completed work".into());
    }
    apply_update(
        goal,
        Update {
            goal_id: goal.id.clone(),
            revision: goal.revision,
            state: None,
            acceptance_criteria: result.acceptance_criteria,
            roadmap: result.roadmap,
            active_task: None,
            progress: Some(result.progress),
            decisions: result.decisions,
            findings: result.findings,
            blockers: result.blockers,
            evidence: result.evidence,
            jobs: None,
        },
        &|_, _| false,
    )?;
    goal.active_task = next_task(&goal.roadmap).map(|task| task.id.clone());
    if let Some(handoff) = result.checkpoint {
        if !handoff.valid() || !handoff.jobs.iter().all(|job| goal.jobs.contains(job)) {
            return Err("Checkpoint references an unavailable job or exceeds the limits".into());
        }
        if goal.checkpoints.len() == 12 {
            goal.checkpoints.remove(0);
        }
        goal.checkpoints.push(SavedCheckpoint {
            at: goal.updated_at,
            handoff,
        });
    }
    Ok(())
}

pub(super) fn cancel_active(jobs: &Jobs, goal: &Value) -> Result<(), String> {
    let Some(number) = goal["execution"]["active"]["number"].as_u64() else {
        return Ok(());
    };
    let goal_id = goal["id"]
        .as_str()
        .filter(|id| is_id(id))
        .ok_or("Invalid goal ID")?;
    let owner = goal["owner"].as_str().ok_or("Invalid goal owner")?;
    let job_id = match goal["execution"]["active"]["job_id"].as_str() {
        Some(id) => Some(id.to_owned()),
        None => jobs.find_request(owner, &format!("goal-{goal_id}-{number}"))?,
    };
    if let Some(id) = job_id {
        jobs.owned_tool(Tool::JobCancel, &id, owner, &serde_json::Map::new())
            .map_err(
                |_| "Goal stop was saved. Check the active job before retrying cancellation",
            )?;
    }
    Ok(())
}

fn context(goal: &Goal) -> Result<String, String> {
    let text = json!({
        "protocol": "veyl-goal-turn-v1", "goal_id": goal.id, "objective": goal.description,
        "iteration": goal.execution.count() + 1, "acceptance_criteria": goal.acceptance_criteria,
        "roadmap": goal.roadmap, "active_task": goal.active_task, "progress": goal.progress,
        "checkpoint": goal.checkpoints.last(), "recent_iteration": goal.execution.history.last(),
    })
    .to_string();
    if text.len() > 8_000 {
        return Err(
            "The runner handoff exceeds 8 KB. Condense the roadmap or latest checkpoint".into(),
        );
    }
    Ok(text)
}

fn chunks(mut context: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    while !context.is_empty() {
        let at = context.floor_char_boundary(context.len().min(1024));
        let (chunk, remainder) = context.split_at(at);
        chunks.push(chunk.to_owned());
        context = remainder;
    }
    chunks
}
