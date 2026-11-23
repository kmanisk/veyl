//! Validates tool inputs and returns owner-scoped, bounded responses.

use std::io::{self, ErrorKind};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use mcp_gateway::security::audit::{AuditAction, AuditPhase};

use crate::tools::registry::{Tool, tool_text};

use super::receipt::Receipt;
use super::store::{JobDir, valid_id};
use super::{JobPolicy, JobRoot, Jobs, SHORT_TIMEOUT, invalid, logs, process, record};

const PAGE_SIZE: usize = 40;

impl Jobs {
    pub(crate) fn call(
        &self,
        tool: Tool,
        args: Option<&Value>,
        owner: &str,
        root: &JobRoot,
        policy: JobPolicy<'_>,
    ) -> Value {
        if !self.available() {
            return tool_text(true, "Job audit unavailable");
        }
        let empty = serde_json::Map::new();
        let args = match args {
            None if tool == Tool::ListJobs => &empty,
            Some(Value::Object(args)) => args,
            _ => return tool_text(true, "Expected a job arguments object"),
        };
        let result = match tool {
            Tool::StartJob | Tool::JobStart | Tool::RunCommand => {
                let short = tool == Tool::RunCommand;
                let selected = match args.len() {
                    1 if args.contains_key("profile") => {
                        args["profile"].as_str().and_then(|name| {
                            self.profiles
                                .named(name)
                                .map(|profile| (name.to_owned(), profile))
                        })
                    }
                    1 if short && args.contains_key("argv") => {
                        self.profiles.matching(&args["argv"])
                    }
                    _ => return tool_text(true, "Expected exactly one configured job profile"),
                };
                let Some((name, mut profile)) = selected else {
                    return tool_text(true, "Unknown or invalid job profile");
                };
                if short {
                    profile.timeout_seconds = profile.timeout_seconds.min(SHORT_TIMEOUT);
                }
                self.start(owner, root, name, profile, policy)
                    .and_then(|receipt| {
                        if short {
                            self.wait_short(owner, &receipt.job_id)
                        } else {
                            Ok(receipt.status())
                        }
                    })
            }
            Tool::ListJobs => match args.get("cursor") {
                None if args.is_empty() => self.list(owner, ""),
                Some(Value::String(id)) if args.len() == 1 && valid_id(id) => self.list(owner, id),
                _ => return tool_text(true, "Expected an optional job cursor"),
            },
            Tool::JobStatus | Tool::JobLogs | Tool::CancelJob | Tool::JobCancel => {
                let Some(id) = args
                    .get("job_id")
                    .and_then(Value::as_str)
                    .filter(|id| args.len() == 1 && valid_id(id))
                else {
                    return tool_text(true, "Expected exactly one job identifier");
                };
                self.owned_tool(tool, id, owner)
            }
            _ => return tool_text(true, "Invalid job tool"),
        };
        match result {
            Ok(value) => tool_text(false, &value.to_string()),
            Err(error) if error.kind() == ErrorKind::NotFound => tool_text(true, "Job not found"),
            Err(error) if error.kind() == ErrorKind::Unsupported => {
                tool_text(true, "Required Linux execution isolation unavailable")
            }
            Err(error) if error.kind() == ErrorKind::PermissionDenied => tool_text(
                true,
                "Job execution denied; verify inherited descriptors and workspace permissions",
            ),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                tool_text(true, "Job capacity reached")
            }
            Err(_) => tool_text(true, "Job operation unavailable or uncertain"),
        }
    }

    fn wait_short(&self, owner: &str, id: &str) -> io::Result<Value> {
        let receipt = self.wait_for_end(owner, id, Duration::from_secs(SHORT_TIMEOUT + 2))?;
        if receipt.state.active() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        let mut status = receipt.status();
        status["logs"] = logs::excerpts(&self.store.job(id)?, &receipt)?;
        Ok(status)
    }

    pub(crate) fn owned_tool(&self, tool: Tool, id: &str, owner: &str) -> io::Result<Value> {
        let _transaction = self.store.lock(false)?;
        let job = self.store.job(id)?;
        let mut receipt = self.owned_receipt(&job, owner)?;
        match tool {
            Tool::JobStatus => Ok(self.present_status(&receipt)),
            Tool::JobLogs => logs::excerpts(&job, &receipt),
            Tool::CancelJob | Tool::JobCancel => {
                if receipt.state.active() && !receipt.cancel_requested {
                    let mut audit = self.audit.lock().map_err(|_| invalid())?;
                    record(
                        &mut audit,
                        &receipt,
                        AuditAction::JobCancel,
                        AuditPhase::Intent,
                    )?;
                    receipt.cancel_requested = true;
                    job.save(&receipt)?;
                }
                if receipt.state.active() {
                    drop(_transaction);
                    return Ok(self
                        .wait_for_end(owner, id, Duration::from_secs(2))?
                        .status());
                }
                Ok(self.present_status(&receipt))
            }
            _ => Err(invalid()),
        }
    }

    fn wait_for_end(&self, owner: &str, id: &str, timeout: Duration) -> io::Result<Receipt> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let _transaction = self.store.lock(false)?;
                let job = self.store.job(id)?;
                let receipt = self.owned_receipt(&job, owner)?;
                if !receipt.state.active() || Instant::now() >= deadline {
                    return Ok(receipt);
                }
            }
            thread::sleep(process::TICK);
        }
    }

    pub(crate) fn list(&self, owner: &str, cursor: &str) -> io::Result<Value> {
        let _transaction = self.store.lock(false)?;
        let mut receipts = Vec::new();
        let mut next = None;
        for id in self
            .store
            .jobs()?
            .into_iter()
            .filter(|id| id.as_str() > cursor)
        {
            let job = self.store.job(&id)?;
            let Some(receipt) = self.read_if_published(&job)? else {
                continue;
            };
            if receipt.client_id != owner {
                continue;
            }
            if receipts.len() == PAGE_SIZE {
                next = receipts
                    .last()
                    .and_then(|receipt: &Value| receipt.get("job_id"))
                    .cloned();
                break;
            }
            receipts.push(self.present_status(&receipt));
        }
        Ok(json!({"jobs":receipts,"next_cursor":next}))
    }

    fn owned_receipt(&self, job: &JobDir<'_>, owner: &str) -> io::Result<Receipt> {
        let mut receipt = job.read()?;
        if receipt.client_id != owner {
            return Err(io::Error::from(ErrorKind::NotFound));
        }
        self.reconcile(job, &mut receipt)?;
        Ok(receipt)
    }

    /// A detached runner remains responsible for finishing the job after an
    /// HTTP restart. The new HTTP instance must not assert a fresh RUNNING
    /// observation for a job it did not launch. This is a presentation-only
    /// uncertainty marker: the signed receipt stays RUNNING, concurrency
    /// limits still count it, and the runner can publish its real final state.
    fn present_status(&self, receipt: &Receipt) -> Value {
        let mut status = receipt.status();
        if receipt.state.active() && self.recovered.contains(&receipt.job_id) {
            status["state"] = json!("uncertain");
            status["recovery"] =
                json!("detached runner may still be active; awaiting final receipt");
        }
        status
    }
}
