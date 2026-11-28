//! Terminal activity monitor with no persistent workers.
use super::{Monitor, clean_id};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcgetwinsize, tcsetattr};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    time::{Duration, Instant},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const VIEWS: [&str; 8] = [
    "health",
    "clients",
    "jobs",
    "activity",
    "skills",
    "upstreams",
    "integrations",
    "goals",
];
const LABELS: [&str; 8] = [
    "Health",
    "Clients",
    "Jobs",
    "Activity",
    "Skills",
    "Upstreams",
    "Integrations",
    "Goals",
];
const GOALS: usize = 7;
const TAB_ORDER: [usize; 8] = [3, 2, 0, 1, 4, 5, 6, GOALS];

struct Screen {
    tty: File,
    saved: Termios,
}
impl Screen {
    fn open() -> Result<Self, String> {
        let tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| "No interactive terminal; use --view")?;
        let saved = tcgetattr(&tty).map_err(|_| "Cannot read terminal attributes")?;
        let mut raw = saved.clone();
        raw.make_raw();
        tcsetattr(&tty, OptionalActions::Now, &raw).map_err(|_| "Cannot enter raw mode")?;
        let mut screen = Self { tty, saved };
        screen
            .tty
            .write_all(b"\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1006h")
            .map_err(|_| "Cannot open alternate screen")?;
        Ok(screen)
    }
    fn size(&self) -> (usize, usize) {
        let size = tcgetwinsize(&self.tty).ok();
        (
            size.as_ref()
                .filter(|s| s.ws_col != 0)
                .map_or(100, |s| usize::from(s.ws_col))
                .clamp(1, 300),
            size.as_ref()
                .filter(|s| s.ws_row != 0)
                .map_or(30, |s| usize::from(s.ws_row))
                .clamp(1, 120),
        )
    }
    fn input(&mut self) -> Result<Vec<u8>, String> {
        let mut fds = [PollFd::new(&self.tty, PollFlags::IN)];
        let wait = Timespec {
            tv_sec: 0,
            tv_nsec: 250_000_000,
        };
        match poll(&mut fds, Some(&wait)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => return Ok(Vec::new()),
            Err(_) => return Err("Terminal polling failed".into()),
            _ => {}
        }
        if fds[0].revents().intersects(PollFlags::HUP | PollFlags::ERR) {
            return Err("Terminal closed".into());
        }
        let mut buf = [0; 128];
        let n = self
            .tty
            .read(&mut buf)
            .map_err(|_| "Cannot read terminal")?;
        if n == 0 {
            return Err("Terminal closed".into());
        }
        Ok(buf[..n].to_vec())
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = self
            .tty
            .write_all(b"\x1b[?1006l\x1b[?1000l\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = tcsetattr(&self.tty, OptionalActions::Now, &self.saved);
    }
}

// Control characters and bidirectional overrides can change terminal state
// or falsify the displayed order of trusted fields.
fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                '?'
            } else {
                c
            }
        })
        .collect()
}
fn strval(value: &Value) -> String {
    if let Some(s) = value.as_str() {
        safe(s)
    } else if value.is_null() {
        "-".into()
    } else {
        safe(&value.to_string())
    }
}
fn cell(text: &str, width: usize) -> String {
    let mut result = String::new();
    let mut used = 0;
    for character in safe(text).chars() {
        let size = character.width().unwrap_or(0);
        if used + size > width {
            break;
        }
        used += size;
        result.push(character);
    }
    result.push_str(&" ".repeat(width - used));
    result
}
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut line = String::new();
    let mut used = 0;
    let mut rows = Vec::new();
    for character in safe(text).chars() {
        let size = character.width().unwrap_or(0);
        if used + size > width && !line.is_empty() {
            rows.push(std::mem::take(&mut line));
            used = 0;
        }
        if size <= width {
            line.push(character);
            used += size;
        }
    }
    rows.push(line);
    rows
}
fn short_path(path: &str, width: usize) -> String {
    let short = std::env::var("HOME")
        .ok()
        .and_then(|home| {
            path.strip_prefix(&home)
                .filter(|rest| rest.is_empty() || rest.starts_with('/'))
                .map(|suffix| format!("~{suffix}"))
        })
        .unwrap_or_else(|| path.to_owned());
    if short.width() <= width {
        return short;
    }
    let mut used = 1;
    let mut tail = Vec::new();
    for c in short.chars().rev() {
        used += c.width().unwrap_or_default();
        if used > width {
            break;
        }
        tail.push(c);
    }
    std::iter::once('…').chain(tail.into_iter().rev()).collect()
}
fn short_id(value: &Value) -> String {
    strval(value).chars().take(8).collect()
}
fn job_state(job: &Value) -> String {
    if job["state"] == "completed" {
        if job["exit_code"].as_i64().is_some_and(|code| code != 0)
            || job["signal"].as_i64().is_some_and(|sig| sig > 0)
        {
            return "failed".into();
        }
        if job["exit_code"] == 0 {
            return "success".into();
        }
    }
    strval(&job["state"])
}

fn row(out: &mut String, text: &str, width: usize, color: &str) {
    out.push_str(color);
    out.push_str(&cell(text, width));
    out.push_str("\x1b[0m\r\n");
}
// Use the terminal's own ANSI palette for status text, never a fixed
// background. Selection adds weight without hiding the outcome color.
fn phase_color(phase: &str) -> &'static str {
    match phase {
        "success" | "SUCCESS" => "\x1b[32m",
        "failure" | "denied" | "FAILED" => "\x1b[31m",
        "running" | "RUNNING" => "\x1b[36m",
        "uncertain" | "pending" | "canceled" | "CANCELED" => "\x1b[33m",
        "timed_out" | "TIMED_OUT" => "\x1b[1;31m",
        _ => "",
    }
}
fn job_color(state: &str, exit: &Value, signal: &Value) -> &'static str {
    match state {
        "completed"
            if exit.as_i64().is_some_and(|code| code != 0)
                || signal.as_i64().is_some_and(|code| code != 0) =>
        {
            "\x1b[31m"
        }
        "completed" if exit.as_i64() == Some(0) => "\x1b[32m",
        "completed" => "\x1b[33m",
        "running" => "\x1b[36m",
        "starting" | "canceled" | "uncertain" => "\x1b[33m",
        "failed" | "timed_out" | "interrupted" | "lost" => "\x1b[31m",
        _ => "",
    }
}
fn record_row(out: &mut String, text: &str, width: usize, color: &str, selected: bool) {
    out.push_str(if selected { "\x1b[1;36m" } else { color });
    out.push_str(if selected {
        "> "
    } else if color.is_empty() {
        "  "
    } else {
        "* "
    });
    out.push_str("\x1b[0m");
    if selected {
        out.push_str("\x1b[1m");
    }
    out.push_str(color);
    out.push_str(&cell(text, width.saturating_sub(2)));
    out.push_str("\x1b[0m\r\n");
}
// Border glyphs are trusted literals. Data still passes through cell/safe.
fn border(out: &mut String, width: usize, top: bool) {
    out.push_str("\x1b[2m");
    out.push_str(if top { "╭" } else { "╰" });
    out.push_str(&"─".repeat(width.saturating_sub(2)));
    out.push_str(if top { "╮" } else { "╯" });
    out.push_str("\x1b[0m\r\n");
}
fn panel_line(out: &mut String, draw: impl FnOnce(&mut String)) {
    out.push_str("\x1b[2m│\x1b[0m");
    draw(out);
    // All internal row renderers finish with CRLF.
    debug_assert!(out.ends_with("\r\n"));
    out.truncate(out.len() - 2);
    out.push_str("\x1b[2m│\x1b[0m\r\n");
}
fn table_rows(value: &Value, key: &str) -> Vec<Value> {
    if let Some(rows) = value.as_array() {
        rows.clone()
    } else {
        value[key].as_array().cloned().unwrap_or_default()
    }
}
fn local_time_label(value: &Value) -> String {
    use jiff::tz::TimeZone;
    static ZONE: std::sync::OnceLock<TimeZone> = std::sync::OnceLock::new();
    time_in_zone(value, ZONE.get_or_init(TimeZone::system))
}

fn time_in_zone(value: &Value, zone: &jiff::tz::TimeZone) -> String {
    value
        .as_i64()
        .and_then(|time| jiff::Timestamp::from_second(time).ok())
        .map(|time| {
            time.to_zoned(zone.clone())
                .strftime("%I:%M:%S %p")
                .to_string()
        })
        .unwrap_or_else(|| "-".into())
}

fn format_duration(ms: Option<u64>) -> String {
    let Some(ms) = ms else {
        return "-".into();
    };
    if ms == 0 {
        "<1ms".into()
    } else if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{}.{:03}s", ms / 1000, ms % 1000)
    } else {
        format!("{}m{:02}.{:03}s", ms / 60_000, (ms / 1000) % 60, ms % 1000)
    }
}

fn mouse_event(bytes: &[u8]) -> Option<(usize, usize, usize)> {
    let fields = bytes.strip_prefix(b"\x1b[<")?;
    let fields = fields
        .strip_suffix(b"M")
        .or_else(|| fields.strip_suffix(b"m"))?;
    let mut fields = std::str::from_utf8(fields).ok()?.split(';');
    let button = fields.next()?.parse().ok()?;
    let x = fields.next()?.parse().ok()?;
    let y = fields.next()?.parse().ok()?;
    if fields.next().is_some() || x == 0 || y == 0 {
        return None;
    }
    Some((button, x, y))
}
#[derive(Default)]
struct View {
    tab: usize,
    client: Option<String>,
    clients: Vec<String>,
    value: Value,
    health: Value,
    selected: usize,
    list_return: Option<(usize, Value)>,
    filter: String,
    editing_filter: bool,
    logs: Option<String>,
    details: Option<Value>,
    detail_width: usize,
    detail_json: bool,
    goal_log_index: usize,
    trace_enabled: bool,
    trace_rows: Value,
    trace_until: Option<Instant>,
    show_funnel: bool,
    audit_ledger: bool,
    confirm: Option<String>,
    notice: String,
    cursor: String,
    sort_ascending: bool,
    probes: std::collections::BTreeMap<String, Value>,
    oauth_clients: Vec<Value>,
    next_oauth_sample: Option<Instant>,
}
impl View {
    fn live_status(&self) -> (String, &'static str) {
        if !self.notice.is_empty() {
            return ("MCP: status unavailable".into(), "\x1b[33m");
        }
        if self.details.is_some() || self.confirm.is_some() || self.editing_filter {
            return ("MCP: refresh paused".into(), "\x1b[2m");
        }
        let Some(count) = self.health["active_calls"].as_u64() else {
            return ("MCP: status unavailable".into(), "\x1b[33m");
        };
        if count == 0 {
            return ("No active MCP call".into(), "\x1b[2m");
        }
        let mut line = format!("MCP running: {count}");
        if let Some(tools) = self.health["active_tools"].as_array() {
            for call in tools.iter().take(3) {
                let name = strval(&call["tool"]);
                line.push_str(&format!(" | {name}"));
                if let Some(ms) = call["duration_ms"].as_u64() {
                    line.push_str(&format!(" {}.{:03}s", ms / 1000, ms % 1000));
                }
                // Use only the explicitly opted-in, session-owned trace.
                if matches!(self.tab, 2 | 3)
                    && !self.audit_ledger
                    && let Some(preview) = self.trace_preview(call)
                {
                    line.push_str(&format!(" | {preview}"));
                }
            }
        }
        (line, "\x1b[36m")
    }
    fn matches(&self, value: &Value) -> bool {
        value
            .to_string()
            .to_ascii_lowercase()
            .contains(&self.filter.to_ascii_lowercase())
    }
    fn filtered(&self, key: &str) -> Vec<Value> {
        let mut rows = table_rows(&self.value, key);
        if !self.filter.is_empty() {
            rows.retain(|row| self.matches(row));
        }
        if self.sort_ascending {
            rows.reverse();
        }
        rows
    }

    fn activity_rows(&self) -> Vec<Value> {
        self.filtered("events")
    }
    fn trace_preview(&self, call: &Value) -> Option<String> {
        if !self.trace_enabled || self.trace_until.is_none_or(|until| Instant::now() >= until) {
            return None;
        }
        let event = Self::matching_trace(&self.trace_rows, call)?;
        if let Some(path) = event["target_preview"].as_str() {
            return Some(safe(path));
        }
        let args = &event["arguments"];
        for key in ["command", "argv", "profile", "job_id", "sections"] {
            if !args[key].is_null() {
                return Some(format!("{} {}", key, strval(&args[key])));
            }
        }
        None
    }

    fn matching_trace<'a>(events: &'a Value, record: &Value) -> Option<&'a Value> {
        let events = events.as_array()?;
        if let Some(id) = record["call_id"].as_str() {
            return events.iter().find(|event| event["call_id"] == id);
        }
        let id = record["job_id"].as_str()?;
        let client = record["client"].as_str()?;
        events
            .iter()
            .find(|event| event["job_id"] == id && event["client"] == client)
    }

    fn refresh_trace(&mut self, monitor: &Monitor) {
        if !self.trace_enabled {
            return;
        }
        let requested = Instant::now();
        match monitor.request("trace", None) {
            Ok((trace, _)) if trace["enabled"] == true => {
                self.trace_rows = trace["events"].clone();
                self.trace_until = trace["remaining_ms"]
                    .as_u64()
                    .map(|ms| requested + Duration::from_millis(ms.min(600_000)));
                if self.trace_until.is_none_or(|until| Instant::now() >= until) {
                    self.trace_enabled = false;
                    self.clear_trace_preview();
                }
            }
            _ => {
                self.trace_enabled = false;
                self.clear_trace_preview();
            }
        }
    }

    fn clear_trace_preview(&mut self) {
        self.trace_rows = Value::Null;
        self.trace_until = None;
        if self
            .details
            .as_ref()
            .is_some_and(|v| v.get("local_trace").is_some())
        {
            self.close_overlay();
        }
    }

    fn refresh_interval(&self) -> Duration {
        if self.trace_enabled && matches!(self.tab, 2 | 3) {
            Duration::from_millis(500)
        } else if self.logs.is_some()
            || self.tab == 3 && self.health["active_calls"].as_u64().unwrap_or_default() > 0
        {
            Duration::from_secs(1)
        } else if self.tab == 2 || self.tab == GOALS || self.tab == 3 {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(5)
        }
    }

    // Overlay scrolling must never overwrite list selection or its record set.
    fn enter_overlay(&mut self) {
        self.list_return = Some((self.selected, self.value.clone()));
        self.selected = 0;
    }

    fn close_overlay(&mut self) {
        self.details = None;
        self.detail_json = false;
        self.logs = None;
        if let Some((selected, value)) = self.list_return.take() {
            self.selected = selected;
            self.value = value;
        }
    }

    fn escape(&mut self) {
        if self.details.is_some() || self.logs.is_some() {
            self.close_overlay();
        } else if self.confirm.is_some() {
            self.confirm = None;
        } else if self.editing_filter {
            self.editing_filter = false;
            self.filter.clear();
            self.selected = 0;
        } else if !self.filter.is_empty() {
            self.filter.clear();
            self.selected = 0;
        }
    }

    fn selected_record(&self) -> Option<Value> {
        match self.tab {
            2 => self.job_rows().get(self.selected).cloned(),
            3 => self.activity_rows().get(self.selected).cloned(),
            1 => self.filtered("clients").get(self.selected).cloned(),
            4 => self.filtered("skills").get(self.selected).cloned(),
            5 => self.filtered("servers").get(self.selected).cloned(),
            GOALS => self.goal_rows().get(self.selected).cloned(),
            _ => Some(self.value.clone()),
        }
    }
    fn open_details(&mut self, monitor: &Monitor) {
        if self.details.is_none()
            && self.logs.is_none()
            && let Some(mut value) = self.selected_record()
        {
            if self.tab == 5
                && let Some(probe) = value["id"].as_str().and_then(|id| self.probes.get(id))
            {
                value["latest_probe"] = probe.clone();
            }
            if self.tab == GOALS {
                let Some(id) = value["id"].as_str().filter(|s| clean_id(s)) else {
                    return;
                };
                match monitor.request(&format!("goals?goal_id={id}"), None) {
                    Ok((goal, _)) => value = goal,
                    Err(error) => {
                        self.notice = error;
                        return;
                    }
                }
            }
            if (self.tab == 2 || self.tab == 3 && !self.audit_ledger) && self.trace_enabled {
                self.refresh_trace(monitor);
                if self.trace_enabled
                    && let Some(event) = Self::matching_trace(&self.trace_rows, &value)
                {
                    value["local_trace"] = event.clone();
                }
            }
            self.enter_overlay();
            self.detail_json = false;
            self.goal_log_index = 0;
            self.details = Some(value);
        }
    }
    fn goal_log(&mut self, monitor: &Monitor) {
        let Some(record) = self.details.as_ref() else {
            return;
        };
        let goal = record.get("goal").unwrap_or(record);
        let Some(id) = goal["id"].as_str().filter(|id| clean_id(id)) else {
            return;
        };
        let Some(jobs) = goal["jobs"].as_array().filter(|jobs| !jobs.is_empty()) else {
            return;
        };
        let Some(job) = jobs[self.goal_log_index % jobs.len()]
            .as_str()
            .filter(|id| clean_id(id))
        else {
            return;
        };
        match monitor.request(&format!("goals?goal_id={id}&job_id={job}"), None) {
            Ok((logs, _)) => {
                self.details = Some(serde_json::json!({"goal":goal,"logs":logs,"job_id":job}));
                self.goal_log_index += 1;
                self.selected = 0;
            }
            Err(error) => self.notice = error,
        }
    }
    fn goal_rows(&self) -> Vec<Value> {
        self.filtered("goals")
    }
    fn goal_action(&mut self, monitor: &Monitor, action: &str) {
        if let Some(goal) = self.selected_record() {
            self.notice = monitor.request(
                "goals", Some(json!({
                    "action": action, "goal_id": goal["id"], "revision": goal["revision"], "confirm": true
                })),
            ).err().unwrap_or_default();
        }
    }
    fn job_rows(&self) -> Vec<Value> {
        let mut rows = self.filtered("jobs");
        if self.sort_ascending {
            rows.sort_by_key(|job| job["created_at"].as_u64().unwrap_or_default());
        } else {
            rows.sort_by_key(|job| {
                std::cmp::Reverse(job["created_at"].as_u64().unwrap_or_default())
            });
        }
        rows
    }

    fn client_action(&mut self, monitor: &Monitor, action: &str) {
        let Some(client) = self.selected_record() else {
            return;
        };
        let oauth = client["authentication"] == "OAuth";
        let (route, key) = if oauth {
            ("oauth", "client_id")
        } else {
            ("clients/mode", "client")
        };
        let mut args =
            json!({"action":if action == "revoke" { action } else { "mode" }, "confirm":true});
        args[key] = client["id"].clone();
        if action != "revoke" {
            args["mode"] = action.into();
        }
        match monitor.request(route, Some(args)) {
            Ok(_) => {
                self.next_oauth_sample = None;
                self.notice.clear();
            }
            Err(error) => self.notice = error,
        }
    }

    fn probe(&mut self, monitor: &Monitor) {
        let Some(record) = self.selected_record() else {
            return;
        };
        let Some(id) = record["id"].as_str() else {
            return;
        };
        match monitor.request(
            "servers",
            Some(json!({"action":"probe","id":id,"confirm":true})),
        ) {
            Ok((probe, _)) => {
                self.probes.insert(id.to_owned(), probe);
                self.notice.clear();
                self.open_details(monitor);
            }
            Err(error) => self.notice = error,
        }
    }

    fn goal_detail_rows(&self, goal: &Value) -> Vec<(String, &'static str)> {
        let mut rows = Vec::new();
        let mut item = |text: String, color| {
            rows.extend(
                wrap(&text, self.detail_width.saturating_sub(2).max(1))
                    .into_iter()
                    .map(|line| (line, color)),
            )
        };
        item(strval(&goal["description"]), "\x1b[1m");
        item(
            format!(
                "{}  {}  {}",
                strval(&goal["state"]),
                strval(&goal["owner"]),
                strval(&goal["workspace"])
            ),
            "",
        );
        let execution = &goal["execution"];
        if let Some(active) = execution["active"]["number"].as_u64() {
            item(
                format!(
                    "Iteration {active} running · job {}",
                    short_id(&execution["active"]["job_id"])
                ),
                "\x1b[36m",
            );
        }
        for (label, value) in [
            ("Active task", &goal["active_task"]),
            ("Progress", &goal["progress"]),
            ("Stopped", &execution["stop_reason"]),
        ] {
            if value.as_str().is_some_and(|text| !text.is_empty()) {
                item(format!("{label}: {}", strval(value)), "");
            }
        }
        fn roadmap(tasks: &Value, depth: usize, output: &mut Vec<(String, &'static str)>) {
            for task in tasks.as_array().into_iter().flatten() {
                let done = task["completed"] == true;
                output.push((
                    format!(
                        "{}{} {}",
                        "  ".repeat(depth),
                        if done { "[x]" } else { "[ ]" },
                        strval(&task["description"])
                    ),
                    if done { "\x1b[32m" } else { "" },
                ));
                roadmap(&task["subtasks"], depth + 1, output);
            }
        }
        let mut tasks = Vec::new();
        roadmap(&goal["roadmap"], 0, &mut tasks);
        item("Roadmap".into(), "\x1b[1m");
        for (text, color) in tasks {
            item(text, color);
        }
        item("Acceptance criteria".into(), "\x1b[1m");
        for criterion in goal["acceptance_criteria"].as_array().into_iter().flatten() {
            item(format!("- {}", strval(&criterion["description"])), "");
            if !criterion["evidence"].is_null() {
                item(
                    format!("  Evidence: {}", strval(&criterion["evidence"])),
                    "\x1b[32m",
                );
            }
        }
        for (field, label) in [
            ("blockers", "Blocker"),
            ("evidence", "Evidence"),
            ("decisions", "Decision"),
            ("findings", "Finding"),
            ("jobs", "Linked job"),
        ] {
            for entry in goal[field].as_array().into_iter().flatten() {
                item(format!("{label}: {}", strval(entry)), "");
            }
        }
        for turn in execution["history"].as_array().into_iter().flatten().rev() {
            item(
                format!(
                    "#{} {} · {}",
                    strval(&turn["number"]),
                    strval(&turn["outcome"]),
                    strval(&turn["detail"])
                ),
                "",
            );
        }
        for entry in goal["checkpoints"].as_array().into_iter().flatten().rev() {
            item(
                format!(
                    "Checkpoint {} · {}",
                    local_time_label(&entry["at"]),
                    strval(&entry["handoff"]["next_action"])
                ),
                "",
            );
        }
        rows
    }

    fn activity_detail(&self) -> bool {
        self.tab == 3 && !self.audit_ledger && self.details.is_some()
    }

    fn activity_detail_rows(&self, value: &Value) -> Vec<(String, &'static str)> {
        let mut lines: Vec<(String, &'static str)> = Vec::new();
        let trace = &value["local_trace"];
        let args = &trace["arguments"];
        let tool = value["tool"].as_str().unwrap_or("");
        let command_tool = matches!(
            tool,
            "exec_command" | "task_run" | "run_command" | "start_job" | "job_start"
        );
        lines.push((
            format!(
                "{}  |  {}",
                strval(&value["tool"]),
                strval(&value["status"])
            ),
            phase_color(value["status"].as_str().unwrap_or("")),
        ));
        lines.push((
            format!(
                "Client: {}  |  {}  |  {}",
                strval(&value["client"]),
                local_time_label(&value["time"]),
                format_duration(value["duration_ms"].as_u64())
            ),
            "",
        ));
        lines.push((format!("Call: {}", strval(&value["call_id"])), "\x1b[2m"));
        lines.push((String::new(), ""));
        lines.push(("COMMAND / TARGET".into(), "\x1b[1;36m"));
        if command_tool {
            if let Some(command) = args["command"].as_str() {
                lines.push(("Requested shell command:".into(), "\x1b[2m"));
                for line in command.split('\n') {
                    lines.push((line.to_owned(), ""));
                }
            } else if let Some(argv) = args["argv"].as_array() {
                lines.push(("Requested argv (exact JSON array):".into(), "\x1b[2m"));
                lines.push((Value::Array(argv.clone()).to_string(), ""));
            } else if let Some(profile) = args["profile"].as_str() {
                lines.push((format!("Configured profile: {profile}"), ""));
                lines.push((
                    "Exact configured command was not captured.".into(),
                    "\x1b[2m",
                ));
            } else if args.get("omitted").is_some() {
                lines.push((
                    "Command omitted: trace payload exceeds capture limit.".into(),
                    "\x1b[33m",
                ));
            } else {
                lines.push((
                    "Command unavailable: not captured, expired or evicted.".into(),
                    "\x1b[33m",
                ));
                lines.push((
                    "Esc, then t and y to capture subsequent supported calls.".into(),
                    "\x1b[2m",
                ));
            }
            if let Some(cwd) = args["cwd"].as_str() {
                lines.push((format!("Requested working directory: {cwd}"), ""));
            }
            if let Some(job) = trace["job_id"].as_str() {
                lines.push((format!("Job: {job}"), ""));
            }
        } else {
            let message = match tool {
                "process_input" => {
                    "Interactive input is intentionally not captured (may contain passwords)."
                }
                "process_start" => "Configured process launch; exact command is not captured.",
                _ => "No shell command for this activity.",
            };
            lines.push((message.into(), "\x1b[2m"));
            if let Some(target) = trace["target_preview"].as_str() {
                lines.push((format!("Target: {target}"), ""));
            }
        }
        lines.push((String::new(), ""));
        lines.push((
            format!("Operation: {}", strval(&value["target_summary"])),
            "",
        ));
        if !trace.is_null() {
            lines.push(("Captured locally; may contain sensitive values. RPC success is not a process exit code.".into(), "\x1b[2m"));
        }
        lines.push((
            "Press d for full JSON, including available local trace.".into(),
            "\x1b[2m",
        ));
        lines
            .into_iter()
            .flat_map(|(line, color)| {
                let line = safe(&line);
                if line.is_empty() {
                    return vec![(String::new(), color)];
                }
                line.as_bytes()
                    .chunks(self.detail_width.max(1))
                    .map(|part| (String::from_utf8_lossy(part).into_owned(), color))
                    .collect()
            })
            .collect()
    }

    fn rows(&self) -> Vec<(String, &'static str)> {
        if let Some(value) = &self.details {
            if self.activity_detail() && !self.detail_json {
                return self.activity_detail_rows(value);
            }
            if self.tab == GOALS
                && let Some(logs) = value.get("logs")
            {
                let mut lines = vec![(format!("Job {}", strval(&value["job_id"])), "\x1b[36m")];
                for stream in ["stdout", "stderr"] {
                    lines.push((format!("--- {stream} ---"), "\x1b[36m"));
                    lines.extend(
                        logs[stream]
                            .as_str()
                            .unwrap_or_default()
                            .lines()
                            .map(|line| (safe(line), "")),
                    );
                }
                return lines;
            }
            if self.tab == GOALS && !self.detail_json {
                return self.goal_detail_rows(value);
            }
            let width = self.detail_width.saturating_sub(2).max(1);
            let mut rows = Vec::new();
            if self.tab == 2 {
                let id = format!("Job {}", strval(&value["job_id"]));
                rows.extend(wrap(&id, width).into_iter().map(|line| (line, "\x1b[1m")));
            }
            let json = serde_json::to_string_pretty(value).unwrap_or_default();
            rows.extend(
                json.lines()
                    .flat_map(|line| wrap(line, width))
                    .map(|part| (part, "")),
            );
            return rows;
        }
        if self.logs.is_some() {
            let mut lines = Vec::new();
            for stream in ["stdout", "stderr"] {
                lines.push((format!("--- {stream} ---"), "\x1b[36m"));
                for line in self.value[stream].as_str().unwrap_or("").lines() {
                    lines.extend(
                        wrap(line, self.detail_width.saturating_sub(2).max(1))
                            .into_iter()
                            .map(|part| (part, "")),
                    );
                }
            }
            return lines;
        }
        match self.tab {
            GOALS => self
                .goal_rows()
                .iter()
                .map(|goal| {
                    (
                        format!(
                            "{} {}/{}  {}{}",
                            cell(&strval(&goal["state"]), 10),
                            strval(&goal["completed_milestones"]),
                            strval(&goal["milestones"]),
                            strval(&goal["description"]),
                            goal["iterations"]
                                .as_u64()
                                .filter(|n| *n > 0)
                                .map_or_else(String::new, |n| format!("  · {n} turns"))
                        ),
                        phase_color(&strval(&goal["state"])),
                    )
                })
                .collect(),
            0 => {
                let v = &self.value;
                let mut lines = vec![
                    (
                        format!("Gateway version       {}", strval(&v["version"])),
                        "",
                    ),
                    (
                        format!("MCP listener          {}", strval(&v["listener"])),
                        "",
                    ),
                    (
                        format!(
                            "Recent MCP sessions   {} (30 min idle expiry)",
                            strval(&v["sessions"])
                        ),
                        "",
                    ),
                    (
                        format!("Open MCP connections  {}", strval(&v["connections"])),
                        "",
                    ),
                    (
                        format!("Memory                {} KiB", strval(&v["rss_kib"])),
                        "",
                    ),
                    (
                        format!("CPU                   {} %", strval(&v["cpu_percent"])),
                        "",
                    ),
                    (
                        format!("Audit ledger          {}", strval(&v["audit"])),
                        if v["audit"] == "verified" {
                            "\x1b[32m"
                        } else {
                            "\x1b[33m"
                        },
                    ),
                ];
                if let Some(entries) = v["configuration"].as_object() {
                    lines.extend(
                        entries
                            .iter()
                            .map(|(k, v)| (format!("{:<22} {}", k, strval(v)), "")),
                    );
                }
                lines
            }
            1 => self
                .filtered("clients")
                .iter()
                .map(|client| {
                    let auth = client["authentication"].as_str().unwrap_or("Bearer");
                    let state = if client["disabled"] == true {
                        "revoked"
                    } else if client["expired"] == true {
                        "expired"
                    } else if client["connections"].as_u64().unwrap_or_default() > 0 {
                        "connected"
                    } else if auth == "OAuth" && client["active_families"] == 0 {
                        "pending"
                    } else {
                        "idle"
                    };
                    let name = client.get("display_name").unwrap_or(&client["id"]);
                    (
                        format!(
                            "{} {} {} {} {}",
                            cell(&strval(name), (self.detail_width / 4).clamp(9, 22)),
                            cell(auth, 6),
                            cell(&strval(&client["mode"]), 8),
                            cell(state, 10),
                            strval(&client["connections"])
                        ),
                        if state == "connected" { "\x1b[32m" } else { "" },
                    )
                })
                .collect(),
            2 => self
                .job_rows()
                .iter()
                .map(|job| {
                    let original = strval(&job["state"]);
                    let state = job_state(job);
                    let color = job_color(&original, &job["exit_code"], &job["signal"]);
                    let elapsed = format_duration(
                        job["execution_duration_ms"]
                            .as_u64()
                            .or_else(|| job["live_elapsed_ms"].as_u64()),
                    );
                    let exe = job["executable"]
                        .as_str()
                        .and_then(|path| path.rsplit('/').next())
                        .unwrap_or("-");
                    let command = self.trace_preview(job).unwrap_or_else(|| {
                        if exe == "sh" {
                            strval(&job["profile"])
                        } else {
                            safe(exe)
                        }
                    });
                    let path = strval(&job["cwd"]);
                    let main = format!(
                        "{} {} {}",
                        short_id(&job["job_id"]),
                        cell(&state, 11),
                        cell(&elapsed, 9)
                    );
                    let line = if self.detail_width < 62 {
                        format!("{main} {command}")
                    } else if self.detail_width < 105 {
                        format!("{main} {} {command}", cell(&short_path(&path, 20), 20))
                    } else {
                        format!(
                            "{main} {} {} {command}",
                            cell(&local_time_label(&job["created_at"]), 11),
                            cell(
                                &short_path(&path, self.detail_width.min(132) / 4),
                                self.detail_width.min(132) / 4
                            )
                        )
                    };
                    (line, color)
                })
                .collect(),
            3 => self
                .activity_rows()
                .iter()
                .map(|v| {
                    let phase = strval(if self.audit_ledger {
                        &v["phase"]
                    } else {
                        &v["status"]
                    });
                    let status = match phase.as_str() {
                        "success" => "SUCCESS",
                        "running" => "RUNNING",
                        "failure" | "denied" => "FAILED",
                        "canceled" => "CANCELED",
                        "timed_out" => "TIMED_OUT",
                        other => other,
                    };
                    let duration = format_duration(v["duration_ms"].as_u64());
                    let tool = strval(&v["tool"]);
                    let summary = if self.audit_ledger {
                        "Verified audit metadata".into()
                    } else {
                        self.trace_preview(v)
                            .unwrap_or_else(|| strval(&v["target_summary"]))
                    };
                    let line = if self.detail_width < 60 {
                        format!(
                            "{} {} {} {}",
                            cell(&local_time_label(&v["time"]), 11),
                            cell(status, 9),
                            tool,
                            summary
                        )
                    } else {
                        format!(
                            "{} {} {} {} {} {}",
                            cell(&local_time_label(&v["time"]), 11),
                            cell(&tool, 19),
                            cell(&strval(&v["client"]), 11),
                            cell(status, 9),
                            cell(&duration, 8),
                            summary
                        )
                    };
                    (line, phase_color(status))
                })
                .collect(),
            4 => self
                .filtered("skills")
                .iter()
                .map(|v| {
                    (
                        format!(
                            "{} {}  {}",
                            cell(
                                if v["enabled"] == true {
                                    "enabled"
                                } else {
                                    "disabled"
                                },
                                9
                            ),
                            cell(&strval(&v["name"]), (self.detail_width / 3).clamp(12, 24)),
                            strval(&v["description"])
                        ),
                        "",
                    )
                })
                .collect(),
            5 => self
                .filtered("servers")
                .iter()
                .map(|server| {
                    let id = strval(&server["id"]);
                    let probe = self.probes.get(&id);
                    let health = if server["enabled"] != true {
                        "disabled"
                    } else {
                        probe
                            .and_then(|result| result["health"].as_str())
                            .unwrap_or("unprobed")
                    };
                    let tools = probe
                        .and_then(|result| result["tools"].as_array())
                        .map_or(0, Vec::len);
                    (
                        format!(
                            "{} {} {}{}",
                            cell(&id, (self.detail_width / 3).clamp(12, 22)),
                            cell(&strval(&server["transport"]), 7),
                            health,
                            if health == "ready" {
                                format!("  · {tools} tools")
                            } else {
                                String::new()
                            }
                        ),
                        if health == "ready" {
                            "\x1b[32m"
                        } else if health == "unavailable" {
                            "\x1b[31m"
                        } else {
                            ""
                        },
                    )
                })
                .collect(),
            _ => self
                .value
                .as_object()
                .map(|v| {
                    v.iter()
                        .flat_map(|(k, v)| {
                            if let Some(obj) = v.as_object() {
                                obj.iter()
                                    .map(|(field, value)| {
                                        (format!("{k}.{field:<24} {}", strval(value)), "")
                                    })
                                    .collect::<Vec<_>>()
                            } else {
                                vec![(format!("{k}: {}", strval(v)), "")]
                            }
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
    fn refresh(&mut self, monitor: &Monitor) {
        let selected_call = (self.tab == 3 && !self.audit_ledger)
            .then(|| {
                self.activity_rows()
                    .get(self.selected)?
                    .get("call_id")?
                    .as_str()
                    .map(str::to_owned)
            })
            .flatten();
        let selected_job = if self.tab == 2 && self.logs.is_none() {
            self.job_rows()
                .get(self.selected)
                .and_then(|row| row["job_id"].as_str())
                .map(str::to_owned)
        } else {
            None
        };
        let result = (|| {
            let (mut status, _) = monitor.request("status", None)?;
            self.clients = table_rows(&status, "clients")
                .iter()
                .filter_map(|v| v["id"].as_str().filter(|s| clean_id(s)).map(str::to_owned))
                .collect();
            if self
                .client
                .as_ref()
                .is_none_or(|c| !self.clients.contains(c))
            {
                self.client = self.clients.first().cloned();
            }
            if let Some(obj) = status.as_object_mut() {
                obj.remove("csrf");
            }
            self.health = status.clone();
            if self.tab == 2 || self.tab == 3 && !self.audit_ledger {
                self.refresh_trace(monitor);
            }
            if let Some(job) = &self.logs {
                return monitor.show("logs", self.client.as_deref(), Some(job));
            }
            match self.tab {
                0 => Ok(status),
                1 => {
                    let mut clients = table_rows(&status, "clients");
                    if status["oauth_preview"] == true {
                        if self
                            .next_oauth_sample
                            .is_none_or(|due| Instant::now() >= due)
                        {
                            if let Ok((data, _)) =
                                monitor.request("oauth", Some(json!({"action":"list"})))
                            {
                                self.oauth_clients = table_rows(&data, "registrations");
                            }
                            self.next_oauth_sample = Some(Instant::now() + Duration::from_secs(15));
                        }
                        for oauth in &self.oauth_clients {
                            let id = oauth["client_id"].as_str().unwrap_or_default();
                            clients.push(json!({"id":id,"display_name":oauth["client_name"],"mode":oauth["mode"],
                                "authentication":"OAuth","active_families":oauth["active_families"],
                                "connections":if oauth["active_families"] == 0 { json!(0) } else {
                                    status["oauth_sessions"][id].as_u64().unwrap_or_default().into()
                                }, "redirect_uris":oauth["redirect_uris"]}));
                        }
                    }
                    Ok(json!({"clients":clients}))
                }
                2 if self.client.is_some() => monitor
                    .request(
                        &format!(
                            "jobs?client={}&cursor={}",
                            self.client.as_deref().unwrap_or_default(),
                            self.cursor
                        ),
                        None,
                    )
                    .map(|(v, _)| v),
                2 => Ok(Value::Null),
                3 if self.audit_ledger => monitor.show("audit", None, None),
                3 => {
                    let route = if self.show_funnel {
                        "activity?funnel=1"
                    } else {
                        "activity"
                    };
                    let (value, _) = monitor.request(route, None)?;
                    Ok(value)
                }
                _ => monitor.show(VIEWS[self.tab], self.client.as_deref(), None),
            }
        })();
        match result {
            Ok(value) => {
                self.value = value;
                self.notice.clear();
            }
            Err(e) => self.notice = e,
        }
        if let Some(id) = selected_job
            && let Some(position) = self.job_rows().iter().position(|job| job["job_id"] == id)
        {
            self.selected = position;
        }
        if let Some(id) = selected_call
            && let Some(position) = self
                .activity_rows()
                .iter()
                .position(|row| row["call_id"] == id)
        {
            self.selected = position;
        }
        self.selected = self.selected.min(self.rows().len().saturating_sub(1));
    }
    fn switch(&mut self, tab: usize) {
        self.tab = tab;
        self.selected = 0;
        self.logs = None;
        self.details = None;
        self.detail_json = false;
        self.list_return = None;
        self.confirm = None;
        self.cursor.clear();
        self.filter.clear();
        self.sort_ascending = false;
        self.editing_filter = false;
        self.value = Value::Null;
    }
    fn draw(&self, screen: &mut Screen) -> Result<(), String> {
        let (w, h) = screen.size();
        let mut out = String::from("\x1b[H\x1b[2J");
        if h < 12 || w < 30 {
            row(&mut out, "Veyl - resize terminal; q quits", w, "\x1b[36m");
        } else {
            let label = if std::env::var_os("VEYL_TUI_PREVIEW").is_some() {
                "Veyl / preview"
            } else {
                "Veyl"
            };
            let title = format!("{label}  {}", env!("CARGO_PKG_VERSION"));
            let state = if self.notice.is_empty() {
                "LIVE"
            } else {
                "STALE"
            };
            out.push_str("\x1b[1m");
            out.push_str(&cell(&title, w.saturating_sub(state.len() + 2)));
            out.push_str("\x1b[0m");
            out.push_str(if self.notice.is_empty() {
                "\x1b[32m"
            } else {
                "\x1b[33m"
            });
            out.push_str(&format!("  {state}\x1b[0m\r\n"));
            let (live_status, color) = self.live_status();
            row(&mut out, &live_status, w, color);
            let mut used = 0;
            for (position, tab) in TAB_ORDER.iter().enumerate() {
                let label = format!(" {} {} ", position + 1, LABELS[*tab]);
                if used + label.len() + 1 > w {
                    break;
                }
                out.push_str(if *tab == self.tab {
                    "\x1b[1;4;33m"
                } else {
                    "\x1b[2m"
                });
                out.push_str(&label);
                out.push_str("\x1b[0m ");
                used += label.len() + 1;
            }
            out.push_str("\r\n");
            let section = if self.details.is_some() {
                "details"
            } else if self.logs.is_some() {
                "logs"
            } else if self.tab == 3 && self.audit_ledger {
                "audit ledger"
            } else if self.tab == 3 && self.show_funnel {
                "activity + Funnel"
            } else {
                VIEWS[self.tab]
            };
            let mut context = format!("Veyl / {section}");
            if self.tab == 2 {
                context.push_str(&format!("  |  {}", self.client.as_deref().unwrap_or("-")));
            }
            if !self.filter.is_empty() {
                context.push_str(&format!("  Filter: {}", self.filter));
            }
            row(&mut out, &context, w, "\x1b[1m");
            let heading = if self.details.is_some() {
                if self.tab == GOALS && !self.detail_json {
                    "Goal details"
                } else if self.activity_detail() && !self.detail_json {
                    "Activity details - command / target"
                } else {
                    "Details & Parameters (JSON) - Esc to close"
                }
            } else if self.logs.is_some() {
                "Job output"
            } else {
                match self.tab {
                    1 => "CLIENT / AUTH / MODE / CONNECTION / SESSIONS",
                    2 if w < 66 => "JOB       STATE       ELAPSED   COMMAND",
                    2 if w < 109 => "JOB       STATE       ELAPSED   DIRECTORY            COMMAND",
                    2 => "JOB       STATE       ELAPSED   STARTED / DIRECTORY / COMMAND",
                    3 if w < 64 => "TIME / STATE / EVENT",
                    3 => "TIME / TOOL / CLIENT / STATE / ELAPSED / DETAIL",
                    5 => "PROVIDER / TRANSPORT / HEALTH / TOOLS",
                    GOALS => "STATE / ROADMAP / OBJECTIVE",
                    _ => LABELS[self.tab],
                }
            };
            border(&mut out, w, true);
            let inner = w.saturating_sub(2);
            panel_line(&mut out, |out| {
                row(out, &format!("  {heading}"), inner, "\x1b[1;4m")
            });
            let rows = self.rows();
            let space = h.saturating_sub(11);
            let start = self.selected.saturating_sub(space.saturating_sub(1));
            for i in 0..space {
                if let Some((text, color)) = rows.get(start + i) {
                    panel_line(&mut out, |out| {
                        record_row(out, text, inner, color, start + i == self.selected)
                    });
                } else {
                    panel_line(&mut out, |out| {
                        row(
                            out,
                            if i == 0 && rows.is_empty() {
                                "No records."
                            } else {
                                ""
                            },
                            inner,
                            "",
                        )
                    });
                }
            }
            border(&mut out, w, false);
            let status = if let Some(id) = &self.confirm {
                if let Some(action) = id.strip_prefix("client:") {
                    if action == "yolo" {
                        "Grant native host-user YOLO? y confirms / n returns".into()
                    } else {
                        format!("Apply {action} to the selected client? y confirms / n returns")
                    }
                } else if id == "goal-cancel" {
                    "Cancel the selected goal? y confirms / n returns".into()
                } else if id == "local-trace" {
                    "Capture command arguments and responses for 10 min (may contain secrets)? y confirms".into()
                } else {
                    format!("Cancel {id}? y confirms / n returns")
                }
            } else if self.editing_filter {
                format!("Filter: {} (Enter accepts, Esc clears)", self.filter)
            } else if !self.notice.is_empty() {
                self.notice.clone()
            } else if self.details.is_some() {
                if self.activity_detail() && !self.detail_json {
                    "Activity details | d: JSON | Esc returns to list".into()
                } else {
                    "JSON details | Esc returns to list".into()
                }
            } else if let Some(id) = &self.logs {
                format!("Job {id} | Esc returns to jobs")
            } else {
                format!(
                    "{} records | selected {}{}",
                    rows.len(),
                    self.selected + usize::from(!rows.is_empty()),
                    if self.trace_enabled {
                        " | LOCAL TRACE ON"
                    } else {
                        ""
                    }
                )
            };
            row(&mut out, &status, w, "\x1b[2m");
            out.push_str("\x1b[2m");
            out.push_str(&"─".repeat(w));
            out.push_str("\x1b[0m\r\n");
            row(
                &mut out,
                if self.details.is_some() || self.logs.is_some() {
                    if self.tab == GOALS {
                        "[j/k] Scroll  [l] Cycle linked job logs  [Esc] Back"
                    } else if self.activity_detail() {
                        "[j/k] Scroll  [d] Details/JSON  [Esc] Back  [q] Quit"
                    } else {
                        "[j/k] Scroll  [Esc] Back  [q] Quit"
                    }
                } else if w < 64 {
                    "Tab View  j/k Move  Enter Info  / Filter  s Sort"
                } else {
                    "[Tab] View  [j/k] Move  [Enter] Details  [/] Filter  [s] Sort"
                },
                w,
                "\x1b[39m",
            );
            // Last line intentionally has no newline (avoids terminal scrolling).
            out.push_str("\x1b[2m");
            out.push_str(&cell(
                if self.details.is_some() || self.logs.is_some() {
                    ""
                } else if w < 64 {
                    match self.tab {
                        3 => "t Capture  f Funnel  a Audit  r Ref  q Quit",
                        GOALS => "P Pause  R Resume  C Cancel  r Ref  q Quit",
                        1 => "Y YOLO  S Standard  X Revoke  r Ref  q Quit",
                        5 => "p Probe  r Ref  q Quit",
                        2 => "p Client l Logs n Next x Cancel t Trace r Ref q Quit",
                        _ => "r Ref  q Quit",
                    }
                } else if self.tab == 3 {
                    "[t] Capture commands  [f] Funnel  [a] Audit  [r] Refresh  [q] Quit"
                } else if self.tab == GOALS {
                    "[P] Pause  [R] Resume  [C] Cancel  [r] Refresh  [q] Quit"
                } else if self.tab == 1 {
                    "[Y] YOLO  [S] Standard  [X] Revoke  [r] Refresh"
                } else if self.tab == 5 {
                    "[p] Probe provider  [r] Refresh  [q] Quit"
                } else if self.tab == 2 {
                    "[p] Client  [l] Logs  [n] Next  [x] Cancel  [t] Trace  [r] Refresh  [q] Quit"
                } else {
                    "[r] Refresh  [q] Quit"
                },
                w,
            ));
            out.push_str("\x1b[0m");
        }
        screen
            .tty
            .write_all(out.as_bytes())
            .and_then(|_| screen.tty.flush())
            .map_err(|_| "Cannot render terminal".into())
    }
}

pub(super) fn run(monitor: &Monitor, client: Option<String>) -> Result<(), String> {
    let mut screen = Screen::open()?;
    let mut v = View {
        tab: TAB_ORDER[0],
        client,
        detail_width: 80,
        ..View::default()
    };
    let mut next = Instant::now();
    let mut redraw = true;
    let mut escape = Vec::new();
    let mut dimensions = (0, 0);
    loop {
        let current_size = screen.size();
        if dimensions != current_size {
            dimensions = current_size;
            v.detail_width = dimensions.0.saturating_sub(4).max(1);
            redraw = true;
        }
        if v.trace_until.is_some_and(|until| Instant::now() >= until) {
            v.trace_enabled = false;
            v.clear_trace_preview();
            redraw = true;
        }
        if Instant::now() >= next && v.confirm.is_none() && !v.editing_filter && v.details.is_none()
        {
            v.refresh(monitor);
            next = Instant::now() + v.refresh_interval();
            redraw = true;
        }
        if redraw {
            v.draw(&mut screen)?;
            redraw = false;
        }
        let keys = screen.input()?;
        if keys.is_empty() && !escape.is_empty() {
            escape.clear();
            v.escape();
            next = Instant::now();
            redraw = true;
        }
        for key in keys {
            redraw = true;
            let key = if !escape.is_empty() || key == 27 {
                escape.push(key);
                if escape.as_slice() == b"\x1b[A" {
                    escape.clear();
                    b'k'
                } else if escape.as_slice() == b"\x1b[B" {
                    escape.clear();
                    b'j'
                } else if escape.starts_with(b"\x1b[<") {
                    if key == b'M' || key == b'm' {
                        if let Some((button, x, y)) = mouse_event(&escape)
                            && v.confirm.is_none()
                            && !v.editing_filter
                        {
                            if button == 64 {
                                v.selected = v.selected.saturating_sub(3);
                            }
                            if button == 65 {
                                v.selected = (v.selected + 3).min(v.rows().len().saturating_sub(1));
                            }
                            if button == 0 && key == b'M' {
                                if y == 3 {
                                    let mut start = 1;
                                    for (position, tab) in TAB_ORDER.iter().enumerate() {
                                        let end = start
                                            + format!(" {} {} ", position + 1, LABELS[*tab]).len()
                                            + 1;
                                        if (start..end).contains(&x) {
                                            v.switch(*tab);
                                            next = Instant::now();
                                            break;
                                        }
                                        start = end;
                                    }
                                } else if v.details.is_none()
                                    && v.logs.is_none()
                                    && (7..screen.size().1.saturating_sub(4)).contains(&y)
                                {
                                    let space = screen.size().1.saturating_sub(11);
                                    let start = v.selected.saturating_sub(space.saturating_sub(1));
                                    let row = start + y - 7;
                                    if row < v.rows().len() {
                                        v.selected = row;
                                        v.open_details(monitor);
                                    }
                                }
                            }
                        }
                        escape.clear();
                    } else if escape.len() > 32 {
                        escape.clear();
                    }
                    continue;
                } else if escape.len() == 2 && !matches!(key, b'[' | b'O') {
                    escape.clear();
                    v.escape();
                    next = Instant::now();
                    key
                } else if escape.len() < 3 {
                    continue;
                } else {
                    escape.clear();
                    continue;
                }
            } else {
                key
            };
            if key == 3 {
                if v.trace_enabled {
                    let _ = monitor.request(
                        "trace",
                        Some(serde_json::json!({"enabled":false,"confirm":true})),
                    );
                }
                return Ok(());
            }
            if let Some(id) = v.confirm.take() {
                if let Some(action) = id.strip_prefix("client:") {
                    if key == b'y' {
                        v.client_action(monitor, action);
                    }
                    next = Instant::now() + Duration::from_millis(250);
                    continue;
                }
                if id == "goal-cancel" {
                    if key == b'y' {
                        v.goal_action(monitor, "cancel");
                    }
                    next = Instant::now();
                    continue;
                }
                if id == "local-trace" {
                    if key == b'y' {
                        match monitor.request(
                            "trace",
                            Some(serde_json::json!({"enabled":true,"confirm":true})),
                        ) {
                            Ok((value, _)) => v.trace_enabled = value["enabled"] == true,
                            Err(e) => v.notice = e,
                        }
                    }
                    next = Instant::now();
                    continue;
                }
                if key == b'y'
                    && let Some(client) = &v.client
                {
                    v.notice = monitor
                        .cancel(client, &id)
                        .map(|_| "Cancellation requested".into())
                        .unwrap_or_else(|e| e);
                }
                next = Instant::now();
                continue;
            }
            if v.editing_filter {
                match key {
                    b'\r' | b'\n' => {
                        v.editing_filter = false;
                        next = Instant::now();
                    }
                    8 | 127 => {
                        v.filter.pop();
                    }
                    32..=126 if v.filter.len() < 100 => v.filter.push(char::from(key)),
                    _ => {}
                }
                v.selected = 0;
                continue;
            }
            match key {
                b'q' => {
                    if v.trace_enabled {
                        let _ = monitor.request(
                            "trace",
                            Some(serde_json::json!({"enabled":false,"confirm":true})),
                        );
                    }
                    return Ok(());
                }
                b't' if matches!(v.tab, 2 | 3) && v.details.is_none() && v.logs.is_none() => {
                    if v.trace_enabled {
                        match monitor.request(
                            "trace",
                            Some(serde_json::json!({"enabled":false,"confirm":true})),
                        ) {
                            Ok(_) => {
                                v.trace_enabled = false;
                                v.clear_trace_preview();
                                next = Instant::now();
                            }
                            Err(e) => v.notice = e,
                        }
                    } else {
                        v.confirm = Some("local-trace".into());
                    }
                }
                b'1'..=b'8' => {
                    v.switch(TAB_ORDER[usize::from(key - b'1')]);
                    next = Instant::now();
                }
                b'\t' => {
                    let position = TAB_ORDER
                        .iter()
                        .position(|tab| *tab == v.tab)
                        .unwrap_or_default();
                    v.switch(TAB_ORDER[(position + 1) % TAB_ORDER.len()]);
                    next = Instant::now();
                }
                b'j' => v.selected = (v.selected + 1).min(v.rows().len().saturating_sub(1)),
                b'k' => v.selected = v.selected.saturating_sub(1),
                b'g' => v.selected = 0,
                b'G' => v.selected = v.rows().len().saturating_sub(1),
                4 => {
                    v.selected =
                        (v.selected + dimensions.1 / 2).min(v.rows().len().saturating_sub(1))
                }
                21 => v.selected = v.selected.saturating_sub(dimensions.1 / 2),
                b's' if v.details.is_none() && v.logs.is_none() => {
                    v.sort_ascending = !v.sort_ascending;
                    v.selected = 0;
                }
                b'Y' | b'S' | b'X'
                    if v.tab == 1 && v.details.is_none() && v.selected_record().is_some() =>
                {
                    let action = match key {
                        b'Y' => "yolo",
                        b'S' => "standard",
                        _ => "revoke",
                    };
                    v.confirm = Some(format!("client:{action}"));
                }
                b'p' if v.tab == 5 && v.details.is_none() => v.probe(monitor),
                b'P' | b'R' if v.tab == GOALS && v.details.is_none() => {
                    v.goal_action(monitor, if key == b'P' { "pause" } else { "resume" });
                    next = Instant::now();
                }
                b'C' if v.tab == GOALS && v.details.is_none() && v.selected_record().is_some() => {
                    v.confirm = Some("goal-cancel".into());
                }
                b'p' => {
                    if !v.clients.is_empty() {
                        let i = v
                            .clients
                            .iter()
                            .position(|c| Some(c) == v.client.as_ref())
                            .unwrap_or(0);
                        v.client = Some(v.clients[(i + 1) % v.clients.len()].clone());
                        v.switch(2);
                        next = Instant::now();
                    }
                }
                b'/' if !matches!(v.tab, 0 | 6) && v.logs.is_none() && v.details.is_none() => {
                    v.editing_filter = true;
                    v.filter.clear();
                }
                b'n' if v.tab == 2 && v.logs.is_none() && v.details.is_none() => {
                    if let Some(cursor) = v.value["next_cursor"].as_str().filter(|s| clean_id(s)) {
                        v.cursor = cursor.into();
                        v.selected = 0;
                        next = Instant::now();
                    }
                }
                b'f' if v.tab == 3 && !v.audit_ledger && v.details.is_none() => {
                    v.show_funnel = !v.show_funnel;
                    v.selected = 0;
                    next = Instant::now();
                }
                b'a' if v.tab == 3 && v.details.is_none() => {
                    v.audit_ledger = !v.audit_ledger;
                    v.selected = 0;
                    next = Instant::now();
                }
                b'd' if v.activity_detail() || v.tab == GOALS && v.details.is_some() => {
                    v.detail_json = !v.detail_json;
                    v.selected = 0;
                }
                b'\r' | b'\n' if v.logs.is_none() => v.open_details(monitor),
                b'l' if v.tab == GOALS && v.details.is_some() => v.goal_log(monitor),
                b'l' if v.tab == 2 && v.logs.is_none() && v.details.is_none() => {
                    if let Some(id) = v
                        .job_rows()
                        .get(v.selected)
                        .and_then(|job| job["job_id"].as_str())
                        .filter(|id| clean_id(id))
                    {
                        let id = id.to_owned();
                        v.enter_overlay();
                        v.logs = Some(id);
                        next = Instant::now();
                    }
                }
                b'x' if v.tab == 2
                    && v.logs.is_none()
                    && v.details.is_none()
                    && v.notice.is_empty() =>
                {
                    if let Some(id) = v
                        .job_rows()
                        .get(v.selected)
                        .filter(|job| {
                            matches!(
                                job["state"].as_str(),
                                Some("running" | "starting" | "uncertain")
                            )
                        })
                        .and_then(|job| job["job_id"].as_str())
                        .filter(|id| clean_id(id))
                    {
                        v.confirm = Some(id.into());
                    }
                }
                b'r' => next = Instant::now(),
                _ => {}
            }
            // Render a tab transition even if more input is buffered.
            if next <= Instant::now()
                && v.confirm.is_none()
                && !v.editing_filter
                && v.details.is_none()
            {
                v.refresh(monitor);
                next = Instant::now() + v.refresh_interval();
                v.draw(&mut screen)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_cells_keep_wide_text_and_escape_remote_controls() {
        assert_eq!(cell("A界B", 3), "A界");
        assert_eq!(cell("A界B", 2), "A ");
        assert_eq!(wrap("ab界é", 2), ["ab", "界", "é"]);
        assert_eq!(safe("hello\u{1b}\u{202e}"), "hello??");
    }

    #[test]
    fn live_header_distinguishes_idle_running_and_unavailable() {
        let mut v = View::default();
        assert_eq!(v.live_status().0, "MCP: status unavailable");
        v.health = serde_json::json!({"active_calls":0});
        assert_eq!(v.live_status().0, "No active MCP call");
        v.health = serde_json::json!({"active_calls":2,"active_tools":[
            {"tool":"exec_command","duration_ms":1250,"call_id":"call-1"},
            {"tool":"job_wait","duration_ms":25,"call_id":"call-2"}
        ]});
        assert_eq!(
            v.live_status().0,
            "MCP running: 2 | exec_command 1.250s | job_wait 0.025s"
        );
        v.details = Some(Value::Null);
        assert_eq!(v.live_status().0, "MCP: refresh paused");
        v.notice = "network failure".into();
        assert_eq!(v.live_status().0, "MCP: status unavailable");
    }

    #[test]
    fn overlay_restores_selection_filter_and_list_after_scrolling() {
        let value = serde_json::json!({"events":[
            {"call_id":"a","tool":"read_file"},
            {"call_id":"b","tool":"read_file"},
            {"call_id":"c","tool":"read_file"}
        ]});
        let mut v = View {
            tab: 3,
            selected: 2,
            filter: "read_file".into(),
            value: value.clone(),
            ..View::default()
        };
        let record = v.selected_record().unwrap();
        v.enter_overlay();
        v.details = Some(record.clone());
        v.selected = 8;
        v.escape();
        assert_eq!(v.selected, 2);
        assert_eq!(v.filter, "read_file");
        assert_eq!(v.selected_record(), Some(record));
        assert_eq!(v.value, value);
        assert!(v.list_return.is_none());

        v.tab = 2;
        v.value = serde_json::json!({"jobs":[{"job_id":"a"},{"job_id":"b"},{"job_id":"c"}]});
        v.filter.clear();
        let original = v.value.clone();
        v.enter_overlay();
        v.logs = Some("c".into());
        v.value = serde_json::json!({"stdout":"example"});
        v.selected = 4;
        v.escape();
        assert_eq!(v.selected, 2);
        assert_eq!(v.value, original);
        assert_eq!(v.selected_record().unwrap()["job_id"], "c");
        assert!(v.logs.is_none());
    }

    #[test]
    fn trace_expiry_restores_selection_without_retaining_raw_details() {
        let mut v = View {
            tab: 3,
            selected: 2,
            value: serde_json::json!({"events":[]}),
            ..View::default()
        };
        v.enter_overlay();
        v.details = Some(serde_json::json!({"local_trace":{"arguments":"synthetic"}}));
        v.trace_rows = serde_json::json!([{"arguments":"synthetic"}]);
        v.clear_trace_preview();
        assert!(v.details.is_none() && v.trace_rows.is_null() && v.list_return.is_none());
        assert_eq!(v.selected, 2);
    }

    #[test]
    fn activity_details_show_command_before_json_and_preserve_boundaries() {
        let mut v = View {
            tab: 3,
            detail_width: 100,
            details: Some(
                serde_json::json!({"tool":"exec_command","client":"primary","status":"success",
                "duration_ms":21,"call_id":"call-1","local_trace":{"arguments":{"command":"printf first\nprintf second\u{1b}[31m","cwd":"project"},"job_id":"job-1"}}),
            ),
            ..View::default()
        };
        let text = |v: &View| {
            v.rows()
                .into_iter()
                .map(|(s, _)| s)
                .collect::<Vec<_>>()
                .join("\n")
        };
        let rows = text(&v);
        assert!(rows.contains("Requested shell command:"));
        assert!(rows.contains("printf first\nprintf second?[31m"));
        assert!(rows.contains("Requested working directory: project"));
        assert!(!rows.contains('\u{1b}'));
        v.detail_json = true;
        assert!(text(&v).contains("\"local_trace\""));
        v.detail_json = false;
        v.details = Some(serde_json::json!({"tool":"exec_command","status":"failure"}));
        assert!(text(&v).contains("Command unavailable"));
        v.details = Some(
            serde_json::json!({"tool":"exec_command","local_trace":{"arguments":{"argv":["printf","a b","'quoted'"]}}}),
        );
        assert!(text(&v).contains(r#"["printf","a b","'quoted'"]"#));
        v.details = Some(
            serde_json::json!({"tool":"service_status","local_trace":{"arguments":{"command":"SYNTHETIC_INVALID_ARGUMENT"}}}),
        );
        assert!(text(&v).contains("No shell command"));
        assert!(!text(&v).contains("SYNTHETIC_INVALID_ARGUMENT"));
        v.audit_ledger = true;
        assert!(text(&v).contains("\"tool\""));
    }

    #[test]
    fn terminal_text_cannot_inject_controls_and_fits_columns() {
        assert_eq!(cell("a\x1b[31m\n", 4), "a?[3");
        assert_eq!(cell("ab", 4), "ab  ");
    }
    #[test]
    fn record_colors_keep_terminal_background_and_text_readable() {
        let mut rendered = String::new();
        record_row(&mut rendered, "success", 12, "\x1b[32m", false);
        assert_eq!(rendered, "\x1b[32m* \x1b[0m\x1b[32msuccess   \x1b[0m\r\n");
        rendered.clear();
        record_row(&mut rendered, "selected", 12, "\x1b[31m", true);
        assert_eq!(
            rendered,
            "\x1b[1;36m> \x1b[0m\x1b[1m\x1b[31mselected  \x1b[0m\r\n"
        );
        rendered.clear();
        record_row(&mut rendered, "intent", 12, phase_color("intent"), false);
        assert_eq!(rendered, "  \x1b[0mintent    \x1b[0m\r\n");
    }
    #[test]
    fn outcomes_use_semantic_palette_and_nonzero_exit_is_failure() {
        use serde_json::json;
        assert_eq!(phase_color("success"), "\x1b[32m");
        assert_eq!(phase_color("failure"), "\x1b[31m");
        assert_eq!(phase_color("running"), "\x1b[36m");
        assert_eq!(phase_color("uncertain"), "\x1b[33m");
        assert_eq!(phase_color("intent"), "");
        assert_eq!(job_color("completed", &json!(0), &Value::Null), "\x1b[32m");
        assert_eq!(job_color("completed", &json!(3), &Value::Null), "\x1b[31m");
        assert_eq!(job_color("completed", &Value::Null, &json!(15)), "\x1b[31m");
        assert_eq!(
            job_color("completed", &Value::Null, &Value::Null),
            "\x1b[33m"
        );
        assert_eq!(job_color("running", &Value::Null, &Value::Null), "\x1b[36m");
        assert_eq!(
            job_color("starting", &Value::Null, &Value::Null),
            "\x1b[33m"
        );
        for state in ["failed", "timed_out", "interrupted", "lost"] {
            assert_eq!(job_color(state, &Value::Null, &Value::Null), "\x1b[31m");
        }
    }
    #[test]
    fn panel_borders_preserve_width_and_sanitize_contents() {
        let mut rendered = String::new();
        border(&mut rendered, 8, true);
        panel_line(&mut rendered, |out| row(out, "a\x1b", 6, ""));
        border(&mut rendered, 8, false);
        assert!(rendered.contains("╭──────╮"));
        assert!(rendered.contains("a?    "));
        assert!(rendered.contains("╰──────╯"));
    }
    #[test]
    fn local_time_uses_historical_daylight_rules() {
        let ny = jiff::tz::TimeZone::get("America/New_York").unwrap();
        for (epoch, expected) in [
            (1_705_320_000, "07:00:00 AM"),
            (1_721_044_800, "08:00:00 AM"),
            (1_730_611_800, "01:30:00 AM"),
            (1_730_615_400, "01:30:00 AM"),
        ] {
            assert_eq!(time_in_zone(&serde_json::json!(epoch), &ny), expected);
        }
        assert_eq!(
            time_in_zone(&serde_json::json!(43_200), &jiff::tz::TimeZone::UTC),
            "12:00:00 PM"
        );
    }

    #[test]
    fn elapsed_preserves_millisecond_precision() {
        assert_eq!(format_duration(None), "-");
        assert_eq!(format_duration(Some(42)), "42ms");
        assert_eq!(format_duration(Some(1234)), "1.234s");
        assert_eq!(format_duration(Some(62345)), "1m02.345s");
    }

    #[test]
    fn mouse_and_timestamp_decoding() {
        assert_eq!(mouse_event(b"\x1b[<0;12;7M"), Some((0, 12, 7)));
        assert_eq!(mouse_event(b"\x1b[<0;0;7M"), None);
        assert_eq!(mouse_event(b"\x1b[<0;12;7;8M"), None);
        assert_eq!(
            time_in_zone(&serde_json::json!(3661), &jiff::tz::TimeZone::UTC),
            "01:01:01 AM"
        );
    }
}
