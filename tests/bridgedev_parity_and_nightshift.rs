#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CLIENT_TOKEN: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const TIMEOUT: Duration = Duration::from_secs(5);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "mcp-parity-local-{:032x}",
            u128::from_ne_bytes(nonce)
        ));
        fs::create_dir(&dir).unwrap();
        let root = dir.join("root");
        let audit = dir.join("audit");
        let jobs = dir.join("jobs");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&audit).unwrap();
        fs::create_dir(&jobs).unwrap();
        fs::set_permissions(&audit, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;

        let config = json!({
            "policy_version": 3,
            "audit_log": audit.join("events.jsonl"),
            "job_state_dir": jobs,
            "job_profiles": {
                "echo": {
                    "executable": "/usr/bin/echo",
                    "args": ["gateway-job-ok"],
                    "timeout_seconds": 5,
                    "max_output_bytes": 4096
                },
                "sleep": {
                    "executable": "/usr/bin/sleep",
                    "args": ["30"],
                    "timeout_seconds": 30,
                    "max_output_bytes": 4096
                }
            },
            "clients": [
                {
                    "id": "dev",
                    "mode": "standard",
                    "disabled": false,
                    "token_sha256": digest(CLIENT_TOKEN),
                    "expires_at_unix_seconds": expires,
                    "root": root,
                    "tools": [
                        "read_file", "write_file", "apply_patch", "edit_file",
                        "create_directory", "list_directory", "directory_tree",
                        "file_info", "exec_command", "task_run", "start_job",
                        "job_status", "job_logs", "job_wait", "cancel_job", "list_jobs",
                        "system_info", "service_status"
                    ]
                }
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Gateway(Child);

impl Gateway {
    fn start(fixture: &Fixture) -> (Self, SocketAddr) {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        cmd.args(["http", "--listen", "127.0.0.1:0", "--config"])
            .arg(fixture.0.join("clients.json"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(|| {
                std::arch::asm!(
                    "syscall",
                    in("rax") 436, // sys_close_range(3, 1024, 0)
                    in("rdi") 3,
                    in("rsi") 1024,
                    in("rdx") 0,
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack)
                );
                Ok(())
            });
        }
        let mut server = Self(cmd.spawn().unwrap());
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

fn digest(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn http(addr: SocketAddr, token: &str, session: Option<&str>, body: Value) -> (String, Value) {
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();
    let body = body.to_string();
    let mut request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(session) = session {
        request.push_str(&format!("mcp-session-id: {session}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (
        head.to_owned(),
        if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(body).unwrap()
        },
    )
}

#[test]
fn test_inspection_tools_parity() {
    let fixture = Fixture::new();
    fs::write(fixture.root("file1.txt"), b"Hello from file 1").unwrap();
    fs::create_dir(fixture.root("subdir")).unwrap();
    fs::write(
        fixture.root("subdir/file2.txt"),
        b"Nested content in subdir",
    )
    .unwrap();
    fs::write(fixture.root(".hidden.txt"), b"Hidden file").unwrap();

    let (_gw, addr) = Gateway::start(&fixture);
    let mut client = Client::connect(addr, CLIENT_TOKEN);

    // 1. list_directory non-recursive
    let list_res = client.call("list_directory", json!({"path": "."}));
    assert_eq!(list_res["isError"], false);
    let text = list_res["content"][0]["text"].as_str().unwrap();
    let list_json: Value = serde_json::from_str(text).unwrap();
    let entries = list_json["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["name"] == "file1.txt"));
    assert!(
        entries
            .iter()
            .any(|e| e["name"] == "subdir" && e["type"] == "directory")
    );
    assert!(!entries.iter().any(|e| e["name"] == ".hidden.txt"));

    // 2. list_directory recursive with hidden
    let list_rec = client.call(
        "list_directory",
        json!({"path": ".", "recursive": true, "show_hidden": true}),
    );
    assert_eq!(list_rec["isError"], false);
    let rec_text = list_rec["content"][0]["text"].as_str().unwrap();
    let rec_json: Value = serde_json::from_str(rec_text).unwrap();
    let rec_entries = rec_json["entries"].as_array().unwrap();
    assert!(rec_entries.iter().any(|e| e["name"] == ".hidden.txt"));
    assert!(rec_entries.iter().any(|e| e["path"] == "subdir/file2.txt"));

    // 3. directory_tree
    let tree_res = client.call("directory_tree", json!({"path": ".", "max_depth": 3}));
    assert_eq!(tree_res["isError"], false);
    let tree_text = tree_res["content"][0]["text"].as_str().unwrap();
    let tree_json: Value = serde_json::from_str(tree_text).unwrap();
    assert_eq!(tree_json["type"], "directory");
    let children = tree_json["children"].as_array().unwrap();
    assert!(children.iter().any(|c| c["name"] == "file1.txt"));

    // 4. file_info
    let info_res = client.call("file_info", json!({"path": "file1.txt"}));
    assert_eq!(info_res["isError"], false);
    let info_text = info_res["content"][0]["text"].as_str().unwrap();
    let info_json: Value = serde_json::from_str(info_text).unwrap();
    assert_eq!(info_json["type"], "file");
    assert_eq!(info_json["size_bytes"], 17);
    assert!(info_json["sha256"].is_string());
}

#[test]
fn test_mutation_tools_parity() {
    let fixture = Fixture::new();
    let (_gw, addr) = Gateway::start(&fixture);
    let mut client = Client::connect(addr, CLIENT_TOKEN);

    // 1. create_directory
    let mkdir_res = client.call("create_directory", json!({"path": "created_dir"}));
    assert_eq!(mkdir_res["isError"], false);
    assert!(fixture.root("created_dir").is_dir());

    let nested = json!({"path": "created_dir/nested/child"});
    for _ in 0..2 {
        assert_eq!(
            client.call("create_directory", nested.clone())["isError"],
            false
        );
    }
    assert!(fixture.root("created_dir/nested/child").is_dir());

    let sibling = fixture.0.join("sibling");
    fs::create_dir(&sibling).unwrap();
    std::os::unix::fs::symlink(&sibling, fixture.root("escape")).unwrap();
    for path in ["escape", "escape/escaped"] {
        assert_eq!(
            client.call("create_directory", json!({"path": path}))["isError"],
            true,
            "{path}"
        );
    }
    assert!(fs::read_dir(&sibling).unwrap().next().is_none());

    // 2. write_file
    let write_res = client.call(
        "write_file",
        json!({"path": "created_dir/doc.txt", "content": "The quick brown fox jumps over the lazy dog"}),
    );
    assert_eq!(write_res["isError"], false);

    // 3. edit_file
    let edit_res = client.call(
        "edit_file",
        json!({
            "path": "created_dir/doc.txt",
            "target": "brown fox",
            "replacement": "red panda"
        }),
    );
    assert_eq!(edit_res["isError"], false);
    let updated = fs::read_to_string(fixture.root("created_dir/doc.txt")).unwrap();
    assert_eq!(updated, "The quick red panda jumps over the lazy dog");
}

#[test]
fn test_nightshift_primitives() {
    let fixture = Fixture::new();
    let (_gw, addr) = Gateway::start(&fixture);
    let mut client = Client::connect(addr, CLIENT_TOKEN);

    // 1. exec_command
    let exec_res = client.call(
        "exec_command",
        json!({
            "command": "echo exec_command_parity_verified",
            "timeout_seconds": 5
        }),
    );
    assert_eq!(exec_res["isError"], false);
    let exec_text = exec_res["content"][0]["text"].as_str().unwrap();
    let exec_json: Value = serde_json::from_str(exec_text).unwrap();
    assert_eq!(exec_json["exit_code"], 0);
    assert!(
        exec_json["stdout"]
            .as_str()
            .unwrap()
            .contains("exec_command_parity_verified")
    );

    // 2. task_run with request_id idempotency
    let task_res1 = client.call(
        "task_run",
        json!({
            "command": "echo task_run_nightshift_test",
            "request_id": "test-req-001",
            "timeout_seconds": 10
        }),
    );
    assert_eq!(task_res1["isError"], false);
    let task_text1 = task_res1["content"][0]["text"].as_str().unwrap();
    let task_json1: Value = serde_json::from_str(task_text1).unwrap();
    assert_eq!(task_json1["exit_code"], 0);
    assert!(task_json1["task_id"].is_string());

    // The same admitted operation replays; a conflicting payload fails closed.
    let task_res2 = client.call(
        "task_run",
        json!({
            "command": "echo task_run_nightshift_test",
            "request_id": "test-req-001",
            "timeout_seconds": 10
        }),
    );
    assert_eq!(task_res2["isError"], false);
    let task_text2 = task_res2["content"][0]["text"].as_str().unwrap();
    let task_json2: Value = serde_json::from_str(task_text2).unwrap();
    assert_eq!(task_json2["idempotent_replay"], true);
    assert_eq!(task_json2["task_id"], task_json1["task_id"]);
    let conflict = client.call(
        "task_run",
        json!({
            "command": "echo should_not_run_again",
            "request_id": "test-req-001",
            "timeout_seconds": 10
        }),
    );
    assert_eq!(conflict["isError"], true);
    let receipt = client.call("job_status", json!({"job_id": task_json1["job_id"]}));
    assert_eq!(receipt["isError"], false);

    // 3. job_start, job_wait, and job_logs with offset
    let start_res = client.call("start_job", json!({"profile": "echo"}));
    assert_eq!(start_res["isError"], false);
    let start_text = start_res["content"][0]["text"].as_str().unwrap();
    let start_json: Value = serde_json::from_str(start_text).unwrap();
    let job_id = start_json["job_id"].as_str().unwrap();

    // job_wait
    let wait_res = client.call("job_wait", json!({"job_id": job_id, "timeout_seconds": 5}));
    assert_eq!(wait_res["isError"], false);
    let wait_text = wait_res["content"][0]["text"].as_str().unwrap();
    let wait_json: Value = serde_json::from_str(wait_text).unwrap();
    assert!(wait_json["state"] == "completed" || wait_json["state"] == "running");

    // job_logs with offset
    let logs_res = client.call(
        "job_logs",
        json!({"job_id": job_id, "offset": 0, "max_bytes": 1024}),
    );
    assert_eq!(logs_res["isError"], false);
    let logs_text = logs_res["content"][0]["text"].as_str().unwrap();
    let logs_json: Value = serde_json::from_str(logs_text).unwrap();
    assert!(logs_json["stdout"].is_string());

    // 4. cancel_job terminates long-running job cleanly
    let sleep_res = client.call("start_job", json!({"profile": "sleep"}));
    assert_eq!(sleep_res["isError"], false);
    let sleep_text = sleep_res["content"][0]["text"].as_str().unwrap();
    let sleep_json: Value = serde_json::from_str(sleep_text).unwrap();
    let sleep_id = sleep_json["job_id"].as_str().unwrap();

    let cancel_res = client.call("cancel_job", json!({"job_id": sleep_id}));
    assert_eq!(cancel_res["isError"], false);
    let cancel_text = cancel_res["content"][0]["text"].as_str().unwrap();
    let cancel_json: Value = serde_json::from_str(cancel_text).unwrap();
    assert!(
        cancel_json["state"] == "canceled"
            || cancel_json["state"] == "completed"
            || cancel_json["cancel_requested"] == true
    );

    // 5. system_info and service_status diagnostics
    let sys_res = client.call("system_info", json!({}));
    assert_eq!(sys_res["isError"], false);
    let sys_text = sys_res["content"][0]["text"].as_str().unwrap();
    let sys_json: Value = serde_json::from_str(sys_text).unwrap();
    assert!(sys_json["logical_cpus"].as_u64().unwrap() > 0);
    assert!(sys_json["memory_total_kib"].as_u64().unwrap() > 0);
    assert!(
        sys_json["workspace_filesystem"]["total_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );

    let srv_res = client.call("service_status", json!({}));
    assert_eq!(srv_res["isError"], false);
    let srv_text = srv_res["content"][0]["text"].as_str().unwrap();
    let srv_json: Value = serde_json::from_str(srv_text).unwrap();
    assert!(srv_json.get("LoadState").is_some() || srv_json.get("ActiveState").is_some());

    // 6. task_run with ephemeral_worktree
    let root = fixture.root(".");
    let _ = Command::new("git")
        .args(["init"])
        .current_dir(&root)
        .status();
    let _ = Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(&root)
        .status();
    let _ = Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(&root)
        .status();
    fs::write(fixture.root("base.txt"), b"base content").unwrap();
    let _ = Command::new("git")
        .args(["add", "base.txt"])
        .current_dir(&root)
        .status();
    let _ = Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(&root)
        .status();

    let wt_task = client.call(
        "task_run",
        json!({
            "command": "echo 'worktree modification' >> base.txt",
            "request_id": "test-wt-req",
            "ephemeral_worktree": true,
            "wait_seconds": 15
        }),
    );
    assert_eq!(wt_task["isError"], false);
    let wt_res: Value =
        serde_json::from_str(wt_task["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(wt_res["ephemeral_worktree"], true);
    assert_eq!(wt_res["worktree_cleaned"], true);
    assert_eq!(wt_res["exit_code"], 0);
    assert_eq!(fs::read(fixture.root("base.txt")).unwrap(), b"base content");
    let branches = Command::new("git")
        .args(["branch", "--list", "veyl-task-*"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(branches.status.success());
    assert!(branches.stdout.is_empty());

    // No ephemeral worktree directory may be created.
    let entries = fs::read_dir(&root).unwrap();
    for entry in entries {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        assert!(!name.starts_with(".veyl-wt-"));
    }
}
