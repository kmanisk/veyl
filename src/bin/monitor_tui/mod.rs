//! Terminal activity monitor. No persistent workers or terminal dependencies.
use super::{Monitor, clean_id};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcgetwinsize, tcsetattr};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    time::{Duration, Instant},
};

const VIEWS: [&str; 7] = [
    "health",
    "clients",
    "jobs",
    "activity",
    "skills",
    "upstreams",
    "integrations",
];
const LABELS: [&str; 7] = [
    "Health",
    "Clients",
    "Jobs",
    "Activity",
    "Skills",
    "Upstreams",
    "Integrations",
];
const TAB_ORDER: [usize; 7] = [3, 2, 0, 1, 4, 5, 6];

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

// All remote strings are escaped before reaching the terminal. Keep
// single-column printable characters so clipping is exact in any locale.
fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
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
    let mut s: String = safe(text).chars().take(width).collect();
    if s.len() < width {
        s.push_str(&" ".repeat(width - s.len()));
    }
    s
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
struct View {
    tab: usize,
    client: Option<String>,
    clients: Vec<String>,
    value: Value,
    health: Value,
    selected: usize,
    filter: String,
    editing_filter: bool,
    logs: Option<String>,
    details: Option<Value>,
    detail_width: usize,
    trace_enabled: bool,
    trace_rows: Value,
    trace_until: Option<Instant>,
    show_funnel: bool,
    audit_ledger: bool,
    confirm: Option<String>,
    notice: String,
    cursor: String,
}
impl View {
    fn matches(&self, value: &Value) -> bool {
        value
            .to_string()
            .to_ascii_lowercase()
            .contains(&self.filter.to_ascii_lowercase())
    }
    fn activity_rows(&self) -> Vec<Value> {
        table_rows(&self.value, "events")
            .into_iter()
            .filter(|value| self.matches(value))
            .collect()
    }
    fn trace_preview(&self, call: &Value) -> Option<String> {
        if !self.trace_enabled || self.trace_until.is_none_or(|until| Instant::now() >= until) {
            return None;
        }
        let id = call["call_id"].as_str()?;
        let event = self
            .trace_rows
            .as_array()?
            .iter()
            .find(|v| v["call_id"] == id)?;
        if let Some(path) = event["target_preview"].as_str() {
            return Some(safe(path));
        }
        let args = &event["arguments"];
        for key in ["command", "argv", "profile"] {
            if !args[key].is_null() {
                return Some(format!("{} {}", key, strval(&args[key])));
            }
        }
        None
    }

    fn clear_trace_preview(&mut self) {
        self.trace_rows = Value::Null;
        self.trace_until = None;
        if self
            .details
            .as_ref()
            .is_some_and(|v| v.get("local_trace").is_some())
        {
            self.details = None;
        }
    }

    fn refresh_interval(&self) -> Duration {
        if (self.tab == 3 && !self.audit_ledger) || self.tab == 2 {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(2)
        }
    }

    fn client_modes_summary(&self) -> String {
        let clients = table_rows(&self.health, "clients");
        if clients.is_empty() {
            return "-".into();
        }
        clients
            .iter()
            .map(|c| {
                format!(
                    "{}: {}",
                    strval(&c["id"]),
                    strval(&c["mode"]).to_uppercase()
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
    fn selected_record(&self) -> Option<Value> {
        match self.tab {
            2 => self.job_rows().get(self.selected).cloned(),
            3 => self.activity_rows().get(self.selected).cloned(),
            1 => table_rows(&self.value, "clients")
                .get(self.selected)
                .cloned(),
            4 => table_rows(&self.value, "skills")
                .get(self.selected)
                .cloned(),
            5 => table_rows(&self.value, "servers")
                .get(self.selected)
                .cloned(),
            _ => Some(self.value.clone()),
        }
    }
    fn open_details(&mut self, monitor: &Monitor) {
        if self.details.is_none()
            && self.logs.is_none()
            && let Some(mut value) = self.selected_record()
        {
            if self.tab == 3
                && !self.audit_ledger
                && self.trace_enabled
                && let Some(id) = value["call_id"].as_str()
                && let Ok((trace, _)) = monitor.request("trace", None)
                && let Some(event) = table_rows(&trace, "events")
                    .into_iter()
                    .find(|event| event["call_id"] == id)
            {
                value["local_trace"] = event;
            }
            self.details = Some(value);
            self.selected = 0;
        }
    }
    fn job_rows(&self) -> Vec<Value> {
        let mut rows: Vec<_> = table_rows(&self.value, "jobs")
            .into_iter()
            .filter(|job| {
                self.filter.is_empty()
                    || job
                        .to_string()
                        .to_ascii_lowercase()
                        .contains(&self.filter.to_ascii_lowercase())
            })
            .collect();
        rows.sort_by_key(|v| std::cmp::Reverse(v["created_at"].as_u64().unwrap_or(0)));
        rows
    }
    fn rows(&self) -> Vec<(String, &'static str)> {
        if let Some(value) = &self.details {
            let json = serde_json::to_string_pretty(value).unwrap_or_default();
            return json
                .lines()
                .flat_map(|line| {
                    let line = safe(line);
                    line.as_bytes()
                        .chunks(self.detail_width.max(1))
                        .map(|part| (String::from_utf8_lossy(part).into_owned(), ""))
                        .collect::<Vec<_>>()
                })
                .collect();
        }
        if self.logs.is_some() {
            let mut lines = Vec::new();
            for stream in ["stdout", "stderr"] {
                lines.push((format!("--- {stream} ---"), "\x1b[36m"));
                for line in self.value[stream].as_str().unwrap_or("").lines() {
                    lines.push((safe(line), ""));
                }
            }
            return lines;
        }
        match self.tab {
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
                        format!("MCP sessions          {}", strval(&v["sessions"])),
                        "",
                    ),
                    (
                        format!("TCP connections       {}", strval(&v["connections"])),
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
            1 => table_rows(&self.value, "clients")
                .iter()
                .map(|v| {
                    (
                        format!(
                            "{:<18} {:<16} sessions={}  grants={}",
                            strval(&v["id"]),
                            strval(&v["mode"]),
                            strval(&v["connections"]),
                            v["grants"].as_array().map_or(0, Vec::len)
                        ),
                        "",
                    )
                })
                .collect(),
            2 => self
                .job_rows()
                .iter()
                .map(|v| {
                    let state = strval(&v["state"]);
                    let color = job_color(&state, &v["exit_code"], &v["signal"]);
                    (
                        format!(
                            "{:<33} {:<11} {:<6} {:<12} {:<10} {} {}",
                            strval(&v["job_id"]),
                            state,
                            strval(&v["exit_code"]),
                            local_time_label(&v["created_at"]),
                            format_duration(
                                v["execution_duration_ms"]
                                    .as_u64()
                                    .or_else(|| v["live_elapsed_ms"].as_u64())
                            ),
                            cell(&strval(&v["cwd"]), 26),
                            format_args!("{} {}", strval(&v["profile"]), strval(&v["executable"]))
                        ),
                        color,
                    )
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
                    (
                        format!(
                            "{} {} {} {} {} {}",
                            cell(&local_time_label(&v["time"]), 13),
                            cell(&tool, 22),
                            cell(&strval(&v["client"]), 14),
                            cell(status, 11),
                            cell(&duration, 15),
                            summary
                        ),
                        phase_color(status),
                    )
                })
                .collect(),
            4 => table_rows(&self.value, "skills")
                .iter()
                .map(|v| {
                    (
                        format!(
                            "{:<22} enabled={}  {}",
                            strval(&v["name"]),
                            strval(&v["enabled"]),
                            strval(&v["description"])
                        ),
                        "",
                    )
                })
                .collect(),
            5 => table_rows(&self.value, "servers")
                .iter()
                .map(|v| {
                    (
                        format!(
                            "{:<22} {:<14} enabled={}",
                            strval(&v["id"]),
                            strval(&v["transport"]),
                            strval(&v["enabled"])
                        ),
                        "",
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
            if let Some(job) = &self.logs {
                return monitor.show("logs", self.client.as_deref(), Some(job));
            }
            match self.tab {
                0 => Ok(status),
                1 => Ok(status["clients"].clone()),
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
                    self.health["active_calls"] = value["active_calls"].clone();
                    if self.trace_enabled {
                        let requested = Instant::now();
                        match monitor.request("trace", None) {
                            Ok((trace, _)) if trace["enabled"] == true => {
                                self.trace_rows = trace["events"].clone();
                                self.trace_until = trace["remaining_ms"]
                                    .as_u64()
                                    .map(|ms| requested + Duration::from_millis(ms.min(600_000)));
                            }
                            _ => {
                                self.trace_enabled = false;
                                self.clear_trace_preview();
                            }
                        }
                    }
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
        self.confirm = None;
        self.cursor.clear();
        self.filter.clear();
        self.editing_filter = false;
        self.value = Value::Null;
    }
    fn draw(&self, screen: &mut Screen) -> Result<(), String> {
        let (w, h) = screen.size();
        let mut out = String::from("\x1b[H\x1b[2J");
        if h < 12 || w < 30 {
            row(&mut out, "Veyl - resize terminal; q quits", w, "\x1b[36m");
        } else {
            row(
                &mut out,
                &format!(
                    "Veyl Activity Monitor   {}   [ {} ]",
                    strval(&self.health["version"]),
                    if self.notice.is_empty() {
                        "LIVE"
                    } else {
                        "STALE"
                    }
                ),
                w,
                "\x1b[1;36m",
            );
            let active_calls = self.health["active_calls"]
                .as_u64()
                .map_or("-".to_owned(), |n| n.to_string());
            let modes_summary = self.client_modes_summary();
            row(
                &mut out,
                &format!(
                    "Calls: {} active | Clients: {} | MCP: {} | Sessions: {} | RSS: {} KiB",
                    active_calls,
                    modes_summary,
                    strval(&self.health["listener"]),
                    strval(&self.health["sessions"]),
                    strval(&self.health["rss_kib"])
                ),
                w,
                "\x1b[2m",
            );
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
            row(
                &mut out,
                &format!(
                    "Veyl / {}   Client: {}   Filter: {}",
                    if self.details.is_some() {
                        "details"
                    } else if self.logs.is_some() {
                        "logs"
                    } else if self.tab == 3 && self.audit_ledger {
                        "audit ledger"
                    } else if self.tab == 3 && self.show_funnel {
                        "activity + Funnel"
                    } else {
                        VIEWS[self.tab]
                    },
                    if self.tab == 3 {
                        "all"
                    } else {
                        self.client.as_deref().unwrap_or("-")
                    },
                    self.filter
                ),
                w,
                "\x1b[1m",
            );
            let heading = if self.details.is_some() {
                "Details & Parameters (JSON) - Esc to close"
            } else if self.logs.is_some() {
                "Job output"
            } else {
                match self.tab {
                    1 => "CLIENT             MODE             SESSIONS / GRANTS",
                    2 => {
                        "JOB ID                            STATUS      EXIT   CREATED      JOB TIME   DIRECTORY       PROFILE"
                    }
                    3 => {
                        "TIME          TOOL / EVENT            CLIENT         STATUS      ELAPSED         COMMAND / SUMMARY"
                    }
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
                if id == "local-trace" {
                    "Capture command arguments and responses for 10 min (may contain secrets)? y confirms".into()
                } else {
                    format!("Cancel {id}? y confirms / n returns")
                }
            } else if self.editing_filter {
                format!("Filter: {} (Enter accepts, Esc clears)", self.filter)
            } else if !self.notice.is_empty() {
                self.notice.clone()
            } else if self.details.is_some() {
                "JSON details | Esc returns to list".into()
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
                "[Tab] View  [j/k] Move  [p] Client  [/] Filter  [Enter] Details  [l] Logs",
                w,
                "\x1b[39m",
            );
            // Last line intentionally has no newline (avoids terminal scrolling).
            out.push_str("\x1b[2m");
            out.push_str(&cell(
                if self.tab == 3 {
                    "[f] Funnel  [a] Audit ledger  [t] Trace  [r] Refresh  [q] Quit"
                } else {
                    "[n] Next page  [Esc] Back  [x] Cancel  [r] Refresh  [q] Quit"
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
        clients: vec![],
        value: Value::Null,
        health: Value::Null,
        selected: 0,
        filter: String::new(),
        editing_filter: false,
        logs: None,
        details: None,
        detail_width: 80,
        trace_enabled: false,
        trace_rows: Value::Null,
        trace_until: None,
        show_funnel: false,
        audit_ledger: false,
        confirm: None,
        notice: String::new(),
        cursor: String::new(),
    };
    let mut next = Instant::now();
    let mut redraw = true;
    let mut escape = Vec::new();
    loop {
        v.detail_width = screen.size().0.saturating_sub(4).max(1);
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
            v.logs = None;
            v.details = None;
            v.confirm = None;
            v.editing_filter = false;
            v.filter.clear();
            next = Instant::now();
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
                b't' if v.tab == 3 && v.details.is_none() => {
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
                b'1'..=b'7' => {
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
                b'/' if matches!(v.tab, 2 | 3) && v.logs.is_none() && v.details.is_none() => {
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
                b'\r' | b'\n' if v.logs.is_none() => v.open_details(monitor),
                b'l' if v.tab == 2 && v.logs.is_none() && v.details.is_none() => {
                    if let Some(id) = v
                        .job_rows()
                        .get(v.selected)
                        .and_then(|job| job["job_id"].as_str())
                        .filter(|id| clean_id(id))
                    {
                        v.logs = Some(id.into());
                        v.selected = 0;
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
