//! Optional, bounded, local-session-only command trace. Never written to disk.

use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::AbortHandle;

const LIMIT: usize = 24;
const MAX_VALUE: usize = 8192;
const TTL: Duration = Duration::from_secs(600);

#[derive(Default)]
pub(super) struct Trace {
    owner: Option<String>,
    until: Option<Instant>,
    events: VecDeque<Value>,
    expiry: Option<AbortHandle>,
}

fn bounded(value: &Value) -> Value {
    match serde_json::to_vec(value) {
        Ok(bytes) if bytes.len() <= MAX_VALUE => value.clone(),
        Ok(bytes) => json!({"omitted":"payload exceeds trace limit","bytes":bytes.len()}),
        Err(_) => json!({"omitted":"serialization failed"}),
    }
}

impl Trace {
    fn expire_at(&mut self, now: Instant) {
        if self.until.is_some_and(|until| now >= until) {
            self.clear();
        }
    }

    fn clear(&mut self) {
        if let Some(expiry) = self.expiry.take() {
            expiry.abort();
        }
        self.owner = None;
        self.until = None;
        self.events.clear();
    }

    pub(super) fn set(&mut self, owner: &str, enabled: bool) -> bool {
        self.expire_at(Instant::now());
        if self
            .owner
            .as_deref()
            .is_some_and(|existing| existing != owner)
        {
            return false;
        }
        self.clear();
        self.owner = enabled.then(|| owner.to_owned());
        self.until = enabled.then(|| Instant::now() + TTL);
        true
    }

    /// At most one one-shot timer, and only while tracing is enabled.
    pub(super) fn schedule_expiry(&mut self, trace: &Arc<Mutex<Self>>) {
        let Some(until) = self.until else { return };
        let weak = Arc::downgrade(trace);
        self.expiry = Some(
            tokio::spawn(async move {
                tokio::time::sleep_until(until.into()).await;
                if let Some(trace) = weak.upgrade()
                    && let Ok(mut trace) = trace.lock()
                {
                    trace.expire_at(Instant::now());
                }
            })
            .abort_handle(),
        );
    }

    pub(super) fn view(&mut self, owner: &str, include_events: bool) -> Value {
        self.expire_at(Instant::now());
        let enabled = self.owner.as_deref() == Some(owner);
        let remaining_ms = if enabled {
            self.until
                .map(|until| until.saturating_duration_since(Instant::now()).as_millis() as u64)
        } else {
            None
        };
        json!({"enabled":enabled,"busy":self.owner.is_some() && !enabled,
            "remaining_ms":remaining_ms,
            "events":if enabled && include_events { self.events.iter().cloned().collect::<Vec<_>>() } else { Vec::new() }})
    }

    pub(super) fn begin(&mut self, id: &str, client: &str, payload: &Value) -> bool {
        self.expire_at(Instant::now());
        if self.owner.is_none() || payload["method"] != "tools/call" {
            return false;
        }
        let Some(name) = payload["params"]["name"].as_str() else {
            return false;
        };
        // File-tool content and responses stay outside the raw trace
        // contract. An explicitly enabled local trace may show a bounded
        // target path, never file contents, patch text, or search terms.
        if matches!(
            name,
            "read_file"
                | "write_file"
                | "apply_patch"
                | "edit_file"
                | "file_info"
                | "list_directory"
                | "directory_tree"
                | "create_directory"
                | "git_inspect"
                | "project_context"
        ) {
            let Some(path) = payload["params"]["arguments"]["path"]
                .as_str()
                .filter(|path| !path.is_empty() && path.len() <= 1024)
            else {
                return false;
            };
            if self.events.len() >= LIMIT {
                self.events.pop_front();
            }
            self.events
                .push_back(json!({"call_id":id,"source":"local_target_trace",
                "time":super::unix_seconds(),"client":client,"tool":name,
                "phase":"running","target_preview":path}));
            return true;
        }
        // Skill and upstream payloads, and transport credentials,
        // are outside the raw trace contract.
        if !matches!(
            name,
            "exec_command"
                | "run_command"
                | "start_job"
                | "job_start"
                | "task_run"
                | "job_wait"
                | "job_status"
                | "job_logs"
                | "cancel_job"
                | "job_cancel"
                | "list_jobs"
                | "system_info"
                | "system_inspect"
                | "service_status"
        ) {
            return false;
        }
        if self.events.len() >= LIMIT {
            self.events.pop_front();
        }
        self.events
            .push_back(json!({"call_id":id,"source":"live_trace",
            "time":super::unix_seconds(),"client":client,"tool":name,"phase":"running",
            "arguments":bounded(&payload["params"]["arguments"])}));
        true
    }

    pub(super) fn finish(&mut self, id: &str, started: Instant, response: Option<&Value>) {
        self.expire_at(Instant::now());
        let Some(event) = self.events.iter_mut().find(|v| v["call_id"] == id) else {
            return;
        };
        let failure =
            response.is_none_or(|v| v.get("error").is_some() || v["result"]["isError"] == true);
        event["phase"] = json!(if failure { "failure" } else { "success" });
        event["duration_ms"] = json!(super::activity::duration_ms(started));
        if event["source"] == "local_target_trace" {
            return;
        }
        // Only correlate successful launch receipts. Never use a user-supplied
        // job_id or a job status/log response as a launch correlation key.
        if !failure
            && event["tool"].as_str().is_some_and(|tool| {
                matches!(
                    tool,
                    "exec_command" | "task_run" | "run_command" | "start_job" | "job_start"
                )
            })
            && let Some(text) = response.and_then(|v| v["result"]["content"][0]["text"].as_str())
            && text.len() <= 512 * 1024
            && let Ok(receipt) = serde_json::from_str::<Value>(text)
            && let Some(job_id) = receipt["job_id"]
                .as_str()
                .filter(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            event["job_id"] = json!(job_id);
        }
        event["response"] = response
            .map(|v| {
                bounded(
                    v.get("result")
                        .or_else(|| v.get("error"))
                        .unwrap_or(&Value::Null),
                )
            })
            .unwrap_or(Value::Null);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Value {
        json!({"method":"tools/call","params":{"name":"exec_command",
            "arguments":{"command":"printf synthetic"}}})
    }

    #[test]
    fn trace_is_opt_in_session_scoped_bounded_and_clearable() {
        let mut t = Trace::default();
        assert!(!t.begin("call-1", "chatgpt", &payload()));
        assert!(t.set("local", true));
        assert!(!t.set("foreign", true));
        assert!(t.begin("call-1", "chatgpt", &payload()));
        t.finish(
            "call-1",
            Instant::now(),
            Some(&json!({"result":{"value":"ok"}})),
        );
        assert_eq!(
            t.view("local", true)["events"][0]["response"]["value"],
            "ok"
        );
        assert_eq!(t.view("local", true)["events"][0]["call_id"], "call-1");
        assert_eq!(
            t.view("foreign", true)["events"].as_array().unwrap().len(),
            0
        );
        assert!(!t.begin(
            "call-2",
            "chatgpt",
            &json!({"method":"tools/call","params":{"name":"read_file"}})
        ));
        for i in 2..42 {
            t.begin(&format!("call-{i}"), "codex", &payload());
        }
        assert_eq!(
            t.view("local", true)["events"].as_array().unwrap().len(),
            LIMIT
        );
        assert!(
            bounded(&json!("a".repeat(MAX_VALUE + 1)))
                .get("omitted")
                .is_some()
        );
        assert!(t.set("local", false));
        assert!(!t.begin("call-42", "chatgpt", &payload()));
        assert_eq!(t.view("local", true)["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn local_file_trace_records_only_target_and_no_content() {
        let mut t = Trace::default();
        let payload = json!({"method":"tools/call","params":{"name":"write_file",
            "arguments":{"path":"src/main.rs","content":"SECRET_FILE_CONTENT"}}});
        assert!(!t.begin("call-1", "dev", &payload));
        assert!(t.set("local", true));
        assert!(t.begin("call-1", "dev", &payload));
        t.finish(
            "call-1",
            Instant::now(),
            Some(&json!({"result":"SECRET_RESPONSE"})),
        );
        let record = &t.view("local", true)["events"][0];
        assert_eq!(record["target_preview"], "src/main.rs");
        assert!(record.get("arguments").is_none());
        assert!(record.get("response").is_none());
        assert!(!record.to_string().contains("SECRET"));
        assert!(
            t.view("other", true)["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(t.set("local", false));
        assert!(
            t.view("local", true)["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn launch_trace_correlates_only_successful_job_receipts() {
        let mut trace = Trace::default();
        assert!(trace.set("local", true));
        let id = "0123456789abcdef0123456789abcdef";
        let response = json!({"result":{"isError":false,"content":[{"type":"text","text":json!({"job_id":id}).to_string()}]}});
        assert!(trace.begin("call-1", "client", &payload()));
        trace.finish("call-1", Instant::now(), Some(&response));
        assert_eq!(trace.view("local", true)["events"][0]["job_id"], id);
        assert!(trace.begin(
            "call-2",
            "client",
            &json!({"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":id}}})
        ));
        trace.finish("call-2", Instant::now(), Some(&response));
        assert!(
            trace.view("local", true)["events"][1]
                .get("job_id")
                .is_none()
        );
        assert!(trace.begin("call-3", "client", &payload()));
        let denied = json!({"result":{"isError":true,"content":[{"text":json!({"job_id":id}).to_string()}]}});
        trace.finish("call-3", Instant::now(), Some(&denied));
        assert!(
            trace.view("local", true)["events"][2]
                .get("job_id")
                .is_none()
        );
        assert!(
            trace.view("other", true)["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(trace.set("local", false));
        assert!(
            trace.view("local", true)["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn trace_expiry_drops_raw_data_and_prevents_late_backfill() {
        let mut t = Trace::default();
        assert!(t.set("local", true));
        assert!(t.begin("call-1", "client", &payload()));
        t.expire_at(t.until.unwrap());
        assert!(t.events.is_empty());
        assert!(t.set("other", true));
        t.finish("call-1", Instant::now(), Some(&json!({"result":"late"})));
        assert!(t.events.is_empty());
    }

    #[test]
    fn trace_timer_clears_payload_without_a_reader() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let shared = Arc::new(Mutex::new(Trace::default()));
            {
                let mut trace = shared.lock().unwrap();
                assert!(trace.set("local", true));
                assert!(trace.begin("call-1", "client", &payload()));
                trace.until = Some(Instant::now() + Duration::from_millis(10));
                trace.schedule_expiry(&shared);
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
            let trace = shared.lock().unwrap();
            assert!(trace.events.is_empty() && trace.owner.is_none());
        });
    }
}
