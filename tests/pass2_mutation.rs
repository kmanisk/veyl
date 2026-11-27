#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Barrier, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const WRITER: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const READER: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const TIMEOUT: Duration = Duration::from_secs(5);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "mcp-pass2-local-{:032x}",
            u128::from_ne_bytes(nonce)
        ));
        fs::create_dir(&dir).unwrap();
        let root = dir.join("root");
        let audit = dir.join("audit");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&audit).unwrap();
        fs::set_permissions(&audit, fs::Permissions::from_mode(0o700)).unwrap();
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let config = json!({
            "audit_log": audit.join("events.jsonl"),
            "clients": [
                {"id": "writer", "token_sha256": digest(WRITER), "expires_at_unix_seconds": expires,
                 "root": root, "tools": ["read_file", "write_file", "apply_patch"]},
                {"id": "reader", "token_sha256": digest(READER), "expires_at_unix_seconds": expires,
                 "root": root, "tools": ["read_file"]}
            ]
        });
        let path = dir.join("clients.json");
        fs::write(&path, config.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Self(dir)
    }

    fn root(&self, file: &str) -> PathBuf {
        self.0.join("root").join(file)
    }

    fn log(&self) -> PathBuf {
        self.0.join("audit/events.jsonl")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Gateway(Child);

impl Gateway {
    fn start(fixture: &Fixture) -> (Self, SocketAddr) {
        let mut server = Self(
            Command::new(env!("CARGO_BIN_EXE_veyl"))
                .args(["http", "--listen", "127.0.0.1:0", "--config"])
                .arg(fixture.0.join("clients.json"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let (sender, receiver) = mpsc::channel();
        let stderr = server.0.stderr.take().unwrap();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(address) = line.strip_prefix("MCP_HTTP_LISTEN=") {
                    let _ = sender.send(address.parse::<SocketAddr>().unwrap());
                }
            }
        });
        let addr = receiver
            .recv_timeout(TIMEOUT)
            .expect("gateway should bind loopback");
        (server, addr)
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Client {
    addr: SocketAddr,
    token: &'static str,
    session: String,
    id: u64,
}

impl Client {
    fn connect(addr: SocketAddr, token: &'static str) -> Self {
        let init = json!({
            "jsonrpc":"2.0","id":0,"method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"local-test","version":"1"}}
        });
        let (headers, response) = http(addr, token, None, init);
        assert!(response["result"].is_object(), "{response}");
        let session = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case("mcp-session-id"))
            .unwrap()
            .1
            .trim()
            .to_owned();
        let (_, notification) = http(
            addr,
            token,
            Some(&session),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        assert!(notification.is_null());
        Self {
            addr,
            token,
            session,
            id: 0,
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let (_, reply) = http(
            self.addr,
            self.token,
            Some(&self.session),
            json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":params}),
        );
        reply
    }

    fn call(&mut self, name: &str, args: Value) -> Value {
        let reply = self.rpc("tools/call", json!({"name":name,"arguments":args}));
        assert!(reply["result"]["isError"].is_boolean(), "{reply}");
        reply["result"].clone()
    }
}

fn http(addr: SocketAddr, token: &str, session: Option<&str>, body: Value) -> (String, Value) {
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
    let body = body.to_string();
    write!(
        stream,
        "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    ).unwrap();
    if let Some(session) = session {
        write!(stream, "Mcp-Session-Id: {session}\r\n").unwrap();
    }
    write!(stream, "\r\n{body}").unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    let (headers, body) = reply.split_once("\r\n\r\n").expect("HTTP response");
    if body.is_empty() {
        assert!(headers.starts_with("HTTP/1.1 202"), "{headers}");
        return (headers.to_owned(), Value::Null);
    }
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    (headers.to_owned(), serde_json::from_str(body).unwrap())
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn audit_directory_replacement_denies_a_write_before_mutation() {
    let fixture = Fixture::new();
    let (_server, addr) = Gateway::start(&fixture);
    let mut client = Client::connect(addr, WRITER);
    let prior = fixture.0.join("retired-audit");
    fs::rename(fixture.0.join("audit"), &prior).unwrap();
    fs::create_dir(fixture.0.join("audit")).unwrap();
    fs::set_permissions(fixture.0.join("audit"), fs::Permissions::from_mode(0o700)).unwrap();

    let reply = client.call(
        "write_file",
        json!({"path":"blocked","content":"not written"}),
    );
    assert_eq!(reply["isError"], true);
    assert!(
        reply["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Audit intent unavailable")
    );
    assert!(!fixture.root("blocked").exists());
    assert!(!fixture.log().exists());
    assert_eq!(fs::metadata(prior.join("events.jsonl")).unwrap().len(), 0);
    assert_eq!(
        client.rpc("tools/list", json!({}))["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn atomic_overwrite_keeps_old_descriptor_and_preserves_mode() {
    let fixture = Fixture::new();
    let (_server, addr) = Gateway::start(&fixture);
    let mut client = Client::connect(addr, WRITER);
    let path = fixture.root("sample");
    assert_eq!(
        client.call(
            "write_file",
            json!({"path":"sample","content":"old marker"})
        )["isError"],
        false
    );
    assert_eq!(mode(&path), 0o600);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let mut before = File::open(&path).unwrap();

    assert_eq!(
        client.call(
            "write_file",
            json!({"path":"sample","content":"new marker","overwrite":true})
        )["isError"],
        false
    );
    assert_eq!(mode(&path), 0o640);
    assert_eq!(fs::read_to_string(path).unwrap(), "new marker");
    let mut old = String::new();
    before.read_to_string(&mut old).unwrap();
    assert_eq!(old, "old marker");

    let log = fs::read_to_string(fixture.log()).unwrap();
    for secret in [WRITER, READER, "old marker", "new marker"] {
        assert!(!log.contains(secret));
    }
    let phases: Vec<_> = log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["phase"].clone())
        .collect();
    assert_eq!(phases, ["intent", "success", "intent", "success"]);
}

#[test]
fn concurrent_patches_with_one_snapshot_have_one_winner() {
    let fixture = Fixture::new();
    fs::write(fixture.root("test"), "old").unwrap();
    let (_server, addr) = Gateway::start(&fixture);
    let barrier = Barrier::new(2);
    let outcomes = thread::scope(|scope| {
        ["left", "right"]
            .map(|replacement| {
                let barrier = &barrier;
                scope.spawn(move || {
                    let mut client = Client::connect(addr, WRITER);
                    barrier.wait();
                    client.call("apply_patch", json!({
                    "path":"test","expected_sha256":digest("old"),"old":"old","new":replacement
                }))["isError"].as_bool().unwrap()
                })
            })
            .map(|handle| handle.join().unwrap())
    });
    assert_ne!(outcomes[0], outcomes[1]);
    assert_eq!(
        fs::read_to_string(fixture.root("test")).unwrap(),
        if outcomes[0] { "right" } else { "left" }
    );
}

#[test]
fn grants_and_encoded_byte_limits_apply_to_each_mutation() {
    let fixture = Fixture::new();
    let (_server, addr) = Gateway::start(&fixture);
    let mut writer = Client::connect(addr, WRITER);
    let mut reader = Client::connect(addr, READER);
    let content = "é".repeat(32_768);
    assert_eq!(
        writer.call("write_file", json!({"path":"limit","content":content}))["isError"],
        false
    );
    assert_eq!(writer.call("apply_patch", json!({
        "path":"limit","expected_sha256":digest(&content),"old":content,"new":content.clone() + "a"
    }))["isError"], true);
    assert_eq!(
        reader.call(
            "apply_patch",
            json!({
                "path":"limit","expected_sha256":digest(&content),"old":content,"new":"other"
            })
        )["isError"],
        true
    );
    assert_eq!(fs::read_to_string(fixture.root("limit")).unwrap(), content);
}
