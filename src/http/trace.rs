//! Optional, bounded, local-session-only command trace. Never written to disk.
//! The durable audit ledger deliberately remains metadata-only.
use serde_json::{Value,json};
use std::{collections::VecDeque,time::{Duration,Instant}};
const LIMIT: usize = 24;
const MAX_VALUE: usize = 8192;
const TTL: Duration = Duration::from_secs(600);
#[derive(Default)]
pub(super) struct Trace {
    owner: Option<String>,
    until: Option<Instant>,
    sequence: u64,
    events: VecDeque<Value>,
}
fn bounded(value: &Value) -> Value {
    match serde_json::to_vec(value) {
        Ok(bytes) if bytes.len() <= MAX_VALUE => value.clone(),
        Ok(bytes) => json!({"omitted":"payload exceeds trace limit","bytes":bytes.len()}),
        Err(_) => json!({"omitted":"serialization failed"}),
    }
}
impl Trace {
    fn expire(&mut self) {
        if self.until.is_some_and(|until| Instant::now() >= until) {
            self.owner = None; self.until = None; self.events.clear();
        }
    }
    pub(super) fn set(&mut self, owner: &str, enabled: bool) -> bool {
        self.expire();
        if self.owner.as_deref().is_some_and(|existing| existing != owner) { return false; }
        self.events.clear();
        self.owner = enabled.then(||owner.to_owned());
        self.until = enabled.then(||Instant::now()+TTL);
        true
    }
    pub(super) fn view(&mut self, owner: &str) -> Value {
        self.expire();
        let enabled = self.owner.as_deref() == Some(owner);
        json!({"enabled":enabled,"busy":self.owner.is_some() && !enabled,
            "events":if enabled {self.events.iter().cloned().collect::<Vec<_>>()} else {Vec::new()}})
    }
    pub(super) fn begin(&mut self, client: &str, payload: &Value) -> Option<(u64,Instant)> {
        self.expire();
        self.owner.as_ref()?;
        if payload["method"] != "tools/call" { return None; }
        let name = payload["params"]["name"].as_str()?;
        // Explicitly exclude file contents, mutations, skill bodies,
        // arbitrary upstream payloads, and all transport credentials.
        if !matches!(name,"exec_command"|"run_command"|"start_job"|"job_start"|"task_run"|"job_wait"|"job_status"|"job_logs"|"cancel_job"|"job_cancel"|"list_jobs"|"system_info"|"system_inspect"|"service_status") {return None;}
        self.sequence=self.sequence.checked_add(1)?;
        let id=self.sequence;
        if self.events.len() >= LIMIT { self.events.pop_front(); }
        self.events.push_back(json!({"trace_id":id,"source":"live_trace",
            "time":super::unix_seconds(),"client":client,"tool":name,"phase":"running",
            "arguments":bounded(&payload["params"]["arguments"])}));
        Some((id,Instant::now()))
    }
    pub(super) fn finish(&mut self, id:u64, started:Instant, response:Option<&Value>) {
        self.expire();
        let Some(event)=self.events.iter_mut().find(|v|v["trace_id"].as_u64()==Some(id)) else {return;};
        let failure=response.is_none_or(|v|v.get("error").is_some()||v["result"]["isError"]==true);
        event["phase"]=json!(if failure {"failure"} else {"success"});
        event["duration_ms"]=json!(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
        event["response"]=response.map(|v| bounded(v.get("result").or_else(||v.get("error")).unwrap_or(&Value::Null))).unwrap_or(Value::Null);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trace_is_opt_in_session_scoped_bounded_and_clearable() {
        let mut t=Trace::default();
        let p=json!({"method":"tools/call","params":{"name":"exec_command","arguments":{"command":"printf test"}}});
        assert!(t.begin("chatgpt",&p).is_none());
        assert!(t.set("local",true));
        assert!(!t.set("foreign",true));
        let (id,start)=t.begin("chatgpt",&p).unwrap();
        t.finish(id,start,Some(&json!({"result":{"value":"ok"}})));
        assert_eq!(t.view("local")["events"][0]["response"]["value"],"ok");
        assert_eq!(t.view("foreign")["events"].as_array().unwrap().len(),0);
        assert!(t.begin("chatgpt",&json!({"method":"tools/call","params":{"name":"read_file"}})).is_none());
        for _ in 0..40 {t.begin("codex",&p);}
        assert_eq!(t.view("local")["events"].as_array().unwrap().len(),LIMIT);
        assert!(bounded(&json!("a".repeat(MAX_VALUE+1))).get("omitted").is_some());
        assert!(t.set("local",false));
        assert!(t.begin("chatgpt",&p).is_none());
        assert_eq!(t.view("local")["events"].as_array().unwrap().len(),0);
    }
}
