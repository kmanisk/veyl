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
    "audit",
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
            .write_all(b"\x1b[?1049h\x1b[?25l")
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
        let _ = self.tty.write_all(b"\x1b[0m\x1b[?25h\x1b[?1049l");
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
// Inherit the terminal's live foreground/background. Accent only the
// selection/status marker; never paint a bright or fixed background.
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
    confirm: Option<String>,
    notice: String,
    cursor: String,
}
impl View {
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
                            ""
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
                    let color = match state.as_str() {
                        "completed" => "\x1b[32m",
                        "running" | "starting" => "\x1b[36m",
                        "failed" => "\x1b[31m",
                        "canceled" | "uncertain" => "\x1b[33m",
                        _ => "",
                    };
                    (
                        format!(
                            "{:<33} {:<11} {:<6} {:<10} {} {}",
                            strval(&v["job_id"]),
                            state,
                            strval(&v["exit_code"]),
                            strval(&v["created_at"]),
                            cell(&strval(&v["cwd"]), 26),
                            strval(&v["profile"])
                        ),
                        color,
                    )
                })
                .collect(),
            3 => table_rows(&self.value, "events")
                .iter()
                .rev()
                .map(|v| {
                    let phase = strval(&v["phase"]);
                    (
                        format!(
                            "{:<12} {:<22} {:<18} {}",
                            strval(&v["time"]),
                            strval(&v["tool"]),
                            strval(&v["client"]),
                            phase
                        ),
                        match phase.as_str() {
                            "failure" => "\x1b[31m",
                            "uncertain" => "\x1b[33m",
                            "success" => "\x1b[32m",
                            _ => "",
                        },
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
        self.selected = self.selected.min(self.rows().len().saturating_sub(1));
    }
    fn switch(&mut self, tab: usize) {
        self.tab = tab;
        self.selected = 0;
        self.logs = None;
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
            row(
                &mut out,
                &format!(
                    "MCP: {} | Sessions: {} | RSS: {} KiB | Audit: {}",
                    strval(&self.health["listener"]),
                    strval(&self.health["sessions"]),
                    strval(&self.health["rss_kib"]),
                    strval(&self.health["audit"])
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
                    if self.logs.is_some() {
                        "logs"
                    } else {
                        VIEWS[self.tab]
                    },
                    self.client.as_deref().unwrap_or("-"),
                    self.filter
                ),
                w,
                "\x1b[1m",
            );
            let heading = if self.logs.is_some() {
                "Job output"
            } else {
                match self.tab {
                    1 => "CLIENT             MODE             SESSIONS / GRANTS",
                    2 => {
                        "JOB ID                            STATUS      EXIT   CREATED    DIRECTORY                  PROFILE"
                    }
                    3 => "TIME         OPERATION              CLIENT             PHASE",
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
                format!("Cancel {id}? y confirms / n returns")
            } else if self.editing_filter {
                format!("Filter: {} (Enter accepts, Esc clears)", self.filter)
            } else if !self.notice.is_empty() {
                self.notice.clone()
            } else if let Some(id) = &self.logs {
                format!("Job {id} | Esc returns to jobs")
            } else {
                format!(
                    "{} records | selected {}",
                    rows.len(),
                    self.selected + usize::from(!rows.is_empty())
                )
            };
            row(&mut out, &status, w, "\x1b[2m");
            out.push_str("\x1b[2m");
            out.push_str(&"─".repeat(w));
            out.push_str("\x1b[0m\r\n");
            row(
                &mut out,
                "[Tab] View  [j/k] Move  [p] Client  [/] Filter  [Enter/l] Logs  [x] Cancel",
                w,
                "\x1b[39m",
            );
            // Last line intentionally has no newline (avoids terminal scrolling).
            out.push_str("\x1b[2m");
            out.push_str(&cell("[n] Next page  [Esc] Back  [r] Refresh  [q] Quit", w));
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
        confirm: None,
        notice: String::new(),
        cursor: String::new(),
    };
    let mut next = Instant::now();
    let mut redraw = true;
    let mut escape = Vec::new();
    loop {
        if Instant::now() >= next && v.confirm.is_none() && !v.editing_filter {
            v.refresh(monitor);
            next = Instant::now() + Duration::from_secs(2);
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
                return Ok(());
            }
            if let Some(id) = v.confirm.take() {
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
                b'q' => return Ok(()),
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
                b'/' if v.tab == 2 && v.logs.is_none() => {
                    v.editing_filter = true;
                    v.filter.clear();
                }
                b'n' if v.tab == 2 && v.logs.is_none() => {
                    if let Some(cursor) = v.value["next_cursor"].as_str().filter(|s| clean_id(s)) {
                        v.cursor = cursor.into();
                        v.selected = 0;
                        next = Instant::now();
                    }
                }
                b'\r' | b'\n' | b'l' if v.tab == 2 && v.logs.is_none() => {
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
                b'x' if v.tab == 2 && v.logs.is_none() && v.notice.is_empty() => {
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
            if next <= Instant::now() && v.confirm.is_none() && !v.editing_filter {
                v.refresh(monitor);
                next = Instant::now() + Duration::from_secs(2);
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
        assert_eq!(rendered, "\x1b[32m* \x1b[0msuccess   \x1b[0m\r\n");
        rendered.clear();
        record_row(&mut rendered, "selected", 12, "\x1b[31m", true);
        assert_eq!(rendered, "\x1b[1;36m> \x1b[0m\x1b[1mselected  \x1b[0m\r\n");
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
}
