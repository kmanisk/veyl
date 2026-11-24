//! Bounded, metadata-only operator view of this gateway's MCP calls.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;
use serde_json::{Value, json};

use crate::tools::registry::Tool;
use mcp_gateway::security::policy::Action;

const RECENT_CALLS: usize = 128;
const RECENT_ADMISSIONS: usize = 32;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Running,
    Success,
    Failure,
    TimedOut,
    Canceled,
}

#[derive(Clone, Serialize)]
struct Record {
    kind: &'static str,
    call_id: Option<String>,
    time: u64,
    client: Option<String>,
    tool: &'static str,
    status: Status,
    duration_ms: Option<u64>,
    target_summary: &'static str,
}

struct Active {
    record: Record,
    started: Instant,
}

#[derive(Default)]
struct Records {
    sequence: u64,
    active: BTreeMap<u64, Active>,
    recent: VecDeque<(u64, Record)>,
    admissions: VecDeque<(u64, Record)>,
}

impl Records {
    fn next(&mut self) -> Option<u64> {
        self.sequence = self.sequence.checked_add(1)?;
        Some(self.sequence)
    }
}

#[derive(Default)]
pub(super) struct Activity(Mutex<Records>);

impl Activity {
    pub(super) fn start(self: &Arc<Self>, client: &str, payload: &Value) -> Option<Call> {
        if payload["method"] != "tools/call" || payload.get("id").is_none() {
            return None;
        }
        let mut records = self.0.lock().ok()?;
        if records.active.len() >= super::MAX_CONNECTIONS {
            return None;
        }
        let sequence = records.next()?;
        let id = format!("call-{sequence}");
        let started = Instant::now();
        let tool = payload["params"]["name"].as_str().and_then(Tool::parse);
        // Copy only server-owned labels. A path, profile, section, upstream
        // name or even an unknown tool name can itself contain a credential.
        let record = Record {
            kind: "mcp_call",
            call_id: Some(id.clone()),
            time: super::unix_seconds(),
            client: Some(client.to_owned()),
            tool: tool.map_or("tools/call", Tool::name),
            status: Status::Running,
            duration_ms: None,
            target_summary: summary(tool),
        };
        records.active.insert(sequence, Active { record, started });
        Some(Call {
            tracker: Arc::clone(self),
            sequence,
            id,
            started,
            finished: false,
        })
    }

    pub(super) fn funnel_admission(&self, client: Option<&str>, status: Status) {
        let Ok(mut records) = self.0.lock() else {
            return;
        };
        let Some(sequence) = records.next() else {
            return;
        };
        let event = Record {
            kind: "funnel_admission",
            call_id: None,
            time: super::unix_seconds(),
            client: client.map(str::to_owned),
            tool: "funnel_admission",
            status,
            duration_ms: None,
            target_summary: "Public MCP admission",
        };
        push_bounded(
            &mut records.admissions,
            (sequence, event),
            RECENT_ADMISSIONS,
        );
    }

    pub(super) fn active_count(&self) -> usize {
        self.0.lock().map_or(0, |records| records.active.len())
    }

    pub(super) fn view(&self, include_funnel: bool) -> Option<Value> {
        let records = self.0.lock().ok()?;
        let mut events: Vec<_> = records.recent.iter().cloned().collect();
        events.extend(records.active.iter().map(|(&sequence, active)| {
            let mut event = active.record.clone();
            event.duration_ms = Some(duration_ms(active.started));
            (sequence, event)
        }));
        if include_funnel {
            events.extend(records.admissions.iter().cloned());
        }
        events.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        Some(json!({
            "active_calls": records.active.len(),
            "events": events.into_iter().map(|(_, event)| event).collect::<Vec<_>>(),
        }))
    }
}

pub(super) struct Call {
    tracker: Arc<Activity>,
    sequence: u64,
    id: String,
    started: Instant,
    finished: bool,
}

impl Call {
    pub(super) fn trace_key(&self) -> (String, Instant) {
        (self.id.clone(), self.started)
    }

    pub(super) fn finish(mut self, status: Status) {
        self.record_outcome(status);
    }

    fn record_outcome(&mut self, status: Status) {
        self.finished = true;
        if let Ok(mut records) = self.tracker.0.lock()
            && let Some(mut call) = records.active.remove(&self.sequence)
        {
            call.record.status = status;
            call.record.duration_ms = Some(duration_ms(call.started));
            push_bounded(
                &mut records.recent,
                (self.sequence, call.record),
                RECENT_CALLS,
            );
        }
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if !self.finished {
            self.record_outcome(Status::Canceled);
        }
    }
}

pub(super) fn duration_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn push_bounded<T>(queue: &mut VecDeque<T>, item: T, limit: usize) {
    if queue.len() >= limit {
        queue.pop_front();
    }
    queue.push_back(item);
}

fn summary(tool: Option<Tool>) -> &'static str {
    match tool.map(Tool::action) {
        Some(Action::StartJob) => "Start supervised job",
        Some(Action::RunShortJob) => "Run supervised command",
        Some(Action::CancelJob) => "Request job cancellation",
        Some(Action::JobLogs | Action::JobStatus | Action::ListJobs) => "Inspect job state",
        Some(Action::WriteFile | Action::ApplyPatch) => "Modify file",
        Some(
            Action::ReadFile
            | Action::SearchFiles
            | Action::GitInspect
            | Action::ProjectContext
            | Action::SystemContext,
        ) => "Inspect workspace",
        Some(Action::SystemInspect | Action::SystemInfo | Action::ServiceStatus) => {
            "Inspect gateway or host"
        }
        Some(Action::ListSkills | Action::ReadSkill) => "Inspect skills",
        Some(Action::ListUpstreams | Action::CallUpstream) => "Upstream MCP access",
        _ => "Tool invocation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(tool: &str) -> Value {
        json!({"method":"tools/call","id":1,"params":{"name":tool,
            "arguments":{"command":"curl --header 'Authorization: Bearer CREDENTIAL'",
                         "job_id":"same-fixture-job","path":"/mcp/CREDENTIAL"}}})
    }

    #[test]
    fn simultaneous_calls_are_distinct_and_cleanup_is_monotonic() {
        let tracker = Arc::new(Activity::default());
        let first = tracker.start("client", &payload("job_logs")).unwrap();
        let identical = tracker.start("client", &payload("job_logs")).unwrap();
        let cancel = tracker.start("client", &payload("job_cancel")).unwrap();
        assert_eq!(tracker.active_count(), 3);
        assert_ne!(first.id, identical.id);
        assert_ne!(first.id, cancel.id);
        std::thread::sleep(std::time::Duration::from_millis(12));
        identical.finish(Status::Failure);
        cancel.finish(Status::TimedOut);
        assert_eq!(tracker.active_count(), 1);
        drop(first);
        let view = tracker.view(false).unwrap();
        assert_eq!(view["active_calls"], 0);
        assert_eq!(view["events"][0]["status"], "timed_out");
        assert_eq!(view["events"][1]["status"], "failure");
        assert_eq!(view["events"][2]["status"], "canceled");
        assert!(
            view["events"]
                .as_array()
                .unwrap()
                .iter()
                .all(|event| event["duration_ms"].as_u64().unwrap() >= 12)
        );
        assert!(!view.to_string().contains("CREDENTIAL"));
    }

    #[test]
    fn history_and_live_slots_are_independently_bounded() {
        let tracker = Arc::new(Activity::default());
        let active: Vec<_> = (0..super::super::MAX_CONNECTIONS)
            .map(|_| tracker.start("client", &payload("read_file")).unwrap())
            .collect();
        assert!(tracker.start("client", &payload("read_file")).is_none());
        drop(active);
        for _ in 0..(RECENT_CALLS + RECENT_ADMISSIONS) {
            tracker
                .start("client", &payload("CREDENTIAL"))
                .unwrap()
                .finish(Status::Success);
            tracker.funnel_admission(None, Status::Failure);
        }
        let view = tracker.view(true).unwrap();
        assert_eq!(
            view["events"].as_array().unwrap().len(),
            RECENT_CALLS + RECENT_ADMISSIONS
        );
        assert_eq!(view["events"][0]["duration_ms"], Value::Null);
        assert_eq!(
            tracker.view(false).unwrap()["events"]
                .as_array()
                .unwrap()
                .len(),
            RECENT_CALLS
        );
        assert!(!view.to_string().contains("CREDENTIAL"));
    }
}
