#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new(mode: &str) -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let dir =
            std::env::temp_dir().join(format!("mcp-gate3-{:032x}", u128::from_le_bytes(nonce)));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        for name in ["audit", "workspace"] {
            DirBuilder::new()
                .mode(0o700)
                .create(dir.join(name))
                .unwrap();
        }
        let fixture = Self(dir);
        fixture.write(&json!({
            "policy_version": 1,
            "audit_log": fixture.0.join("audit/events"),
            "clients": [{
                "id": "fixture", "root": fixture.0.join("workspace"),
                "token_sha256": "a".repeat(64), "expires_at_unix_seconds": u64::MAX,
                "tools": ["read_file"], "mode": mode, "yolo_roots": [],
            }]
        }));
        fixture
    }

    fn config(&self) -> PathBuf {
        self.0.join("clients.json")
    }

    fn read(&self) -> Value {
        serde_json::from_slice(&fs::read(self.config()).unwrap()).unwrap()
    }

    fn write(&self, value: &Value) {
        fs::write(self.config(), value.to_string()).unwrap();
        fs::set_permissions(self.config(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
            .args(args)
            .arg("--config")
            .arg(self.config())
            .output()
            .unwrap()
    }

    fn mode(&self, args: &[&str]) -> Output {
        let mut command = vec!["yolo"];
        command.extend_from_slice(args);
        command.extend_from_slice(&["--client", "fixture"]);
        self.run(&command)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ok(result: Output) -> String {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

#[test]
fn reset_recovers_disabled_to_standard_and_preserves_credentials() {
    let f = Fixture::new("disabled");
    let previous = f.read();
    assert!(!f.mode(&["enable"]).status.success());
    let output = ok(f.mode(&["reset"]));
    assert!(output.contains("client=fixture client_state=enabled"));
    assert!(output.contains("mode=standard"));
    assert!(!output.contains(&"a".repeat(64)));
    let mut expected = previous;
    expected["clients"][0]["mode"] = "standard".into();
    assert_eq!(f.read(), expected);
    let audit = ok(f.run(&["audit", "inspect"]));
    assert!(audit.contains("\"previous_mode\":\"disabled\""));
    assert!(audit.contains("\"requested_mode\":\"standard\""));
    assert!(audit.contains("\"phase\":\"success\""));
}

#[test]
fn legacy_approval_is_scoped_across_processes_and_cannot_be_replayed() {
    let f = Fixture::new("standard");
    assert!(ok(f.mode(&["enable"])).contains("effective_policy=legacy_scoped_yolo"));
    let granted = f.read();
    assert_eq!(granted["policy_version"], 1);
    assert_eq!(granted["clients"][0]["mode"], "yolo");
    assert_eq!(granted["clients"][0]["yolo_roots"], json!([]));
    assert!(ok(f.mode(&["status"])).contains("effective_policy=legacy_scoped_yolo"));
    assert!(ok(f.mode(&["set", "--mode", "standard"])).contains("mode=standard"));
    f.write(&granted);
    assert!(!f.mode(&["status"]).status.success());
    ok(f.mode(&["disable"]));
}

#[test]
fn interrupted_policy_requires_recovery_to_standard() {
    let f = Fixture::new("standard");
    ok(f.mode(&["enable"]));
    let marker = f.0.join(".clients.json.policy-pending");
    fs::write(&marker, "fixture").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!f.mode(&["status"]).status.success());
    assert!(!f.mode(&["enable"]).status.success());
    assert!(ok(f.mode(&["reset"])).contains("mode=standard"));
    assert!(!marker.exists());
}

#[test]
fn malformed_legacy_mode_cannot_be_activated() {
    let f = Fixture::new("yolo");
    assert!(!f.mode(&["status"]).status.success());
    let f = Fixture::new("full");
    assert!(!f.mode(&["status"]).status.success());
}
