#![forbid(unsafe_code)]

//! On-demand operator monitor for the local authenticated Veyl admin API.

use std::{
    io::{self, BufRead, BufReader, IsTerminal, Write},
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, StatusCode, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const HELP: &str = "Usage: mcp-gateway dashboard pair --config PATH | veyl-monitor --listen 127.0.0.1:PORT [--client ID] [--view health|clients|jobs|logs|audit|skills|upstreams|integrations] [--job ID]\n    Use --cancel JOB --client ID --confirm for non-interactive cancellation.";
struct Monitor {
    rt: tokio::runtime::Runtime,
    addr: SocketAddrV4,
    session: String,
    csrf: String,
}

impl Monitor {
    fn request(
        &self,
        endpoint: &str,
        data: Option<Value>,
    ) -> Result<(Value, Option<String>), String> {
        self.rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(6), async {
                let mut req = Request::builder()
                    .method(if data.is_some() {
                        Method::POST
                    } else {
                        Method::GET
                    })
                    .uri(format!("/dashboard/api/{endpoint}"))
                    .header(header::HOST, self.addr.to_string())
                    .header(header::CONNECTION, "close");
                let bytes = if let Some(data) = data {
                    req = req
                        .header(header::ORIGIN, format!("http://{}", self.addr))
                        .header(header::CONTENT_TYPE, "application/json");
                    serde_json::to_vec(&data).map_err(|_| "Cannot build request")?
                } else {
                    vec![]
                };
                if !self.session.is_empty() {
                    req = req
                        .header(header::COOKIE, &self.session)
                        .header("X-CSRF-Token", &self.csrf);
                }
                let req = req
                    .body(Full::new(Bytes::from(bytes)))
                    .map_err(|_| "Cannot build request")?;
                let transport = TcpStream::connect(self.addr)
                    .await
                    .map_err(|_| "Cannot reach Veyl admin listener")?;
                let (mut sender, conn) = http1::Builder::new()
                    .max_buf_size(32_768)
                    .handshake(TokioIo::new(transport))
                    .await
                    .map_err(|_| "Admin HTTP handshake failed")?;
                let task = tokio::spawn(conn);
                let result = async {
                    let reply = sender
                        .send_request(req)
                        .await
                        .map_err(|_| "Admin HTTP request failed")?;
                    if reply.status() != StatusCode::OK {
                        return Err(format!("Veyl returned {}", reply.status()));
                    }
                    let cookie = reply
                        .headers()
                        .get(header::SET_COOKIE)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.split(';').next())
                        .filter(|value| value.starts_with("mcp_dash_session="))
                        .map(str::to_owned);
                    let payload = Limited::new(reply.into_body(), 1_048_576)
                        .collect()
                        .await
                        .map_err(|_| "Invalid or oversized admin reply")?
                        .to_bytes();
                    let value =
                        serde_json::from_slice(&payload).map_err(|_| "Invalid admin JSON")?;
                    Ok((value, cookie))
                }
                .await;
                task.abort();
                result
            })
            .await
            .map_err(|_| "Admin request timed out".to_owned())?
        })
    }

    fn open(addr: SocketAddrV4, token: &str) -> Result<Self, String> {
        let mut monitor = Self {
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "Cannot start monitor runtime")?,
            addr,
            session: String::new(),
            csrf: String::new(),
        };
        let (data, cookie) = monitor.request("pair", Some(json!({"pairing_token":token})))?;
        monitor.session = cookie.ok_or("Missing Veyl session")?;
        monitor.csrf = data["csrf"]
            .as_str()
            .filter(|s| s.len() == 48 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or("Invalid session proof")?
            .into();
        Ok(monitor)
    }

    fn show(&self, view: &str, client: Option<&str>, job: Option<&str>) -> Result<Value, String> {
        let data = match view {
            "health" | "clients" => {
                let (mut status, _) = self.request("status", None)?;
                if view == "clients" {
                    return Ok(status["clients"].take());
                }
                if let Some(object) = status.as_object_mut() {
                    for name in ["csrf", "clients", "audit_log", "job_state_dir"] {
                        object.remove(name);
                    }
                }
                return Ok(status);
            }
            "jobs" => format!(
                "jobs?client={}",
                client.ok_or("Use --client ID or select a client with p ID")?
            ),
            "logs" => format!(
                "jobs/{}/logs?client={}",
                job.ok_or("Specify a job ID")?,
                client.ok_or("Select a client first")?
            ),
            "audit" | "skills" | "integrations" => view.into(),
            "upstreams" => "servers".into(),
            _ => return Err("Unknown view".into()),
        };
        self.request(&data, None).map(|(value, _)| value)
    }

    fn cancel(&self, client: &str, id: &str) -> Result<Value, String> {
        self.request(
            "jobs/cancel",
            Some(json!({"client":client,"job_id":id,"confirm":true})),
        )
        .map(|(v, _)| v)
    }
}

fn clean_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn render(value: &Value) {
    // Serialize values rather than writing arbitrary job output to the terminal.
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_default()
    );
}

fn run() -> Result<(), String> {
    let mut addr = None;
    let mut view = None;
    let mut client = None;
    let mut job = None;
    let mut cancel = None;
    let mut confirm = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" => {
                println!("{HELP}");
                return Ok(());
            }
            "--version" => {
                println!("veyl-monitor {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--listen" if addr.is_none() => {
                addr = Some(
                    args.next()
                        .ok_or(HELP)?
                        .parse::<SocketAddrV4>()
                        .map_err(|_| HELP)?,
                )
            }
            "--client" if client.is_none() => {
                client = Some(
                    args.next()
                        .filter(|id| clean_id(id))
                        .ok_or("Invalid client identifier")?,
                )
            }
            "--view" if view.is_none() => view = Some(args.next().ok_or(HELP)?),
            "--job" if job.is_none() => {
                job = Some(
                    args.next()
                        .filter(|id| clean_id(id))
                        .ok_or("Invalid job ID")?,
                )
            }
            "--cancel" if cancel.is_none() => {
                cancel = Some(
                    args.next()
                        .filter(|id| clean_id(id))
                        .ok_or("Invalid job ID")?,
                )
            }
            "--confirm" if !confirm => confirm = true,
            _ => return Err(HELP.into()),
        }
    }
    if cancel.is_some() != confirm || cancel.is_some() && view.is_some() {
        return Err(HELP.into());
    }
    let addr = addr
        .filter(|a| *a.ip() == Ipv4Addr::LOCALHOST && a.port() != 0)
        .ok_or("Use a fixed IPv4 loopback admin address")?;
    if io::stdin().is_terminal() {
        return Err("Pipe a fresh dashboard pairing code to the monitor".into());
    }
    let mut token = String::new();
    std::io::Read::take(io::stdin().lock(), 128)
        .read_line(&mut token)
        .map_err(|_| "Cannot read pairing code")?;
    let token = token
        .trim()
        .strip_prefix("PAIRING_TOKEN=")
        .unwrap_or(token.trim());
    if token.len() != 48 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid pairing code".into());
    }
    let monitor = Monitor::open(addr, token)?;
    let result = if let Some(id) = cancel {
        client
            .as_deref()
            .ok_or_else(|| "Use --client to identify the job owner".to_owned())
            .and_then(|client| monitor.cancel(client, &id).map(|value| render(&value)))
    } else if let Some(view) = view {
        monitor
            .show(&view, client.as_deref(), job.as_deref())
            .map(|value| render(&value))
    } else {
        interactive(&monitor, client)
    };
    let _ = monitor.request("logout", Some(json!({})));
    result
}

fn interactive(monitor: &Monitor, mut client: Option<String>) -> Result<(), String> {
    let terminal = std::fs::File::open("/dev/tty")
        .map_err(|_| "An interactive terminal is unavailable. Use --view.")?;
    let mut input = BufReader::new(terminal);
    let mut view = "health";
    let mut job: Option<String> = None;
    loop {
        if io::stdout().is_terminal() {
            print!("\x1b[2J\x1b[H");
        }
        println!("Veyl / {view}");
        match monitor.show(view, client.as_deref(), job.as_deref()) {
            Ok(value) => render(&value),
            Err(error) => eprintln!("{error}"),
        }
        print!(
            "\n1 Health  2 Clients  3 Jobs  4 Audit  5 Skills  6 Upstreams  7 Integrations\np CLIENT  l JOB  x JOB  r Refresh  q Quit\n> "
        );
        io::stdout().flush().map_err(|_| "Cannot write terminal")?;
        let mut value = String::new();
        let count = input
            .read_line(&mut value)
            .map_err(|_| "Cannot read terminal")?;
        if count == 0 {
            break;
        }
        let fields: Vec<_> = value.split_whitespace().collect();
        match fields.as_slice() {
            ["q"] => break,
            ["r"] => (),
            ["1"] => view = "health",
            ["2"] => view = "clients",
            ["3"] => view = "jobs",
            ["4"] => view = "audit",
            ["5"] => view = "skills",
            ["6"] => view = "upstreams",
            ["7"] => view = "integrations",
            ["p", id] if clean_id(id) => {
                client = Some((*id).into());
                view = "jobs";
            }
            ["l", id] if clean_id(id) => {
                job = Some((*id).into());
                view = "logs";
            }
            ["x", id] if clean_id(id) => {
                let Some(client) = &client else {
                    eprintln!("Select a client first");
                    continue;
                };
                print!("Type cancel and press Enter to cancel {id}: ");
                io::stdout().flush().map_err(|_| "Cannot write terminal")?;
                let mut proof = String::new();
                input
                    .read_line(&mut proof)
                    .map_err(|_| "Cannot read confirmation")?;
                if proof.trim() == "cancel" {
                    match monitor.cancel(client, id) {
                        Ok(value) => render(&value),
                        Err(err) => eprintln!("{err}"),
                    }
                }
            }
            _ => eprintln!("Unknown command"),
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("veyl-monitor: {error}");
        std::process::exit(2);
    }
}
