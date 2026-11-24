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
fn new_mode_cli_uses_the_existing_audited_policy_transaction() {
    let f = Fixture::new("standard");
    let original = f.read();
    assert!(ok(f.run(&["mode", "get", "fixture"])).contains("mode=standard"));
    assert!(!f.run(&["mode", "set", "fixture", "full"]).status.success());
    assert_eq!(f.read(), original);
    assert!(
        ok(f.run(&[
            "mode",
            "set",
            "--client",
            "fixture",
            "--mode",
            "full",
            "--confirm-full"
        ]))
        .contains("mode=full")
    );
    assert!(ok(f.run(&["mode", "get", "--client", "fixture"])).contains("effective_policy=full"));
    assert!(ok(f.run(&["mode", "set", "fixture", "standard"])).contains("mode=standard"));
    let after = f.read();
    assert_eq!(
        after["clients"][0]["token_sha256"],
        original["clients"][0]["token_sha256"]
    );
    assert_eq!(after["clients"][0]["mode"], "standard");
    assert!(after["clients"][0].get("yolo_revision").is_none());
    let audit = ok(f.run(&["audit", "inspect"]));
    assert!(audit.contains("\"requested_mode\":\"full\""));
    assert!(audit.contains("\"requested_mode\":\"standard\""));
    assert!(ok(f.run(&["audit", "verify"])).contains("VERIFY_RESULT=VALID"));
}

#[test]
fn version_three_migration_preserves_scopes_and_refuses_legacy_enable() {
    let f = Fixture::new("standard");
    let extra = f.0.join("extra");
    DirBuilder::new().mode(0o700).create(&extra).unwrap();
    let mut document = f.read();
    document["clients"][0]["yolo_roots"] = json!([extra]);
    f.write(&document);
    ok(f.mode(&["enable"]));
    let old_policy = f.read();
    assert_eq!(old_policy["clients"][0]["mode"], "yolo");
    ok(f.run(&["mode", "migrate"]));
    let migrated = f.read();
    assert_eq!(migrated["policy_version"], 3);
    assert_eq!(migrated["clients"][0]["mode"], "standard");
    assert_eq!(migrated["clients"][0]["extra_roots"], json!([extra]));
    assert_eq!(migrated["clients"][0]["disabled"], false);
    assert_eq!(
        migrated["clients"][0]["token_sha256"],
        old_policy["clients"][0]["token_sha256"]
    );
    assert!(migrated["clients"][0].get("yolo_revision").is_none());
    assert!(!f.mode(&["enable"]).status.success());
    assert_eq!(f.read(), migrated);
    f.write(&old_policy);
    assert!(!f.mode(&["status"]).status.success());
    f.write(&migrated);
    assert!(ok(f.run(&["mode", "get", "fixture"])).contains("mode=standard"));
}

#[test]
fn version_three_independent_client_activation_preserves_mode() {
    let f = Fixture::new("standard");
    ok(f.run(&["mode", "migrate"]));
    ok(f.run(&["mode", "set", "fixture", "full", "--confirm-full"]));
    let active = f.read();
    ok(f.run(&["mode", "disable", "fixture"]));
    let mut disabled = active.clone();
    disabled["clients"][0]["disabled"] = true.into();
    assert_eq!(f.read(), disabled);
    assert!(ok(f.run(&["mode", "get", "fixture"])).contains("client_state=disabled"));
    assert!(
        !f.run(&["mode", "set", "fixture", "standard"])
            .status
            .success()
    );
    ok(f.run(&["mode", "enable", "fixture"]));
    assert_eq!(f.read(), active);
    assert!(ok(f.run(&["audit", "verify"])).contains("VERIFY_RESULT=VALID"));
    ok(f.run(&["mode", "set", "fixture", "standard"]));
    assert_eq!(f.read()["clients"][0]["mode"], "standard");
    assert_eq!(f.read()["policy_version"], 3);
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

#[test]
fn full_requires_confirmed_mode_specific_approval_and_disallows_replay() {
    let f = Fixture::new("standard");
    let standard = f.read();
    assert!(!f.mode(&["set", "--mode", "full"]).status.success());
    assert_eq!(f.read(), standard);
    assert!(ok(f.mode(&["set", "--mode", "full", "--confirm-full"])).contains("mode=full"));
    let full = f.read();
    assert_eq!(full["policy_version"], 2);
    assert!(ok(f.mode(&["status"])).contains("effective_policy=full"));
    let mut forged = full.clone();
    forged["clients"][0]["mode"] = "yolo".into();
    f.write(&forged);
    assert!(!f.mode(&["status"]).status.success());
    f.write(&full);
    assert!(!f.mode(&["enable"]).status.success());
    ok(f.mode(&["reset"]));
    assert_eq!(f.read()["policy_version"], 2);
    f.write(&full);
    assert!(!f.mode(&["status"]).status.success());
}

#[test]
fn disabled_client_cannot_select_full_even_with_confirmation() {
    let f = Fixture::new("disabled");
    let original = f.read();
    assert!(
        !f.mode(&["set", "--mode", "full", "--confirm-full"])
            .status
            .success()
    );
    assert_eq!(f.read(), original);
}

#[test]
fn audit_anchor_pins_a_prefix_across_append_and_rotation() {
    let f = Fixture::new("disabled");
    ok(f.mode(&["reset"]));
    let anchor = f.0.join("anchor.json");
    let path = anchor.to_str().unwrap();
    assert!(ok(f.run(&["audit", "export-head", "--out", path])).contains("EXPORTED"));
    let original = fs::read(&anchor).unwrap();
    let checkpoint: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(checkpoint["format_version"], 1);
    assert!(checkpoint["sequence"].as_u64().unwrap() >= 2);
    assert_eq!(checkpoint["ledger_identity"].as_str().unwrap().len(), 64);
    assert_eq!(
        fs::metadata(&anchor).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !f.run(&["audit", "export-head", "--out", path])
            .status
            .success()
    );
    assert_eq!(fs::read(&anchor).unwrap(), original);
    ok(f.run(&["audit", "rotate"]));
    ok(f.mode(&["enable"]));
    assert!(ok(f.run(&["audit", "verify", "--anchor", path])).contains("VERIFY_RESULT=VALID"));

    let other = Fixture::new("disabled");
    ok(other.mode(&["reset"]));
    let other_anchor = other.0.join("anchor.json");
    ok(other.run(&[
        "audit",
        "export-head",
        "--out",
        other_anchor.to_str().unwrap(),
    ]));
    assert!(
        !other
            .run(&["audit", "verify", "--anchor", path])
            .status
            .success()
    );

    for (field, replacement) in [
        ("hash", Value::from("0".repeat(64))),
        ("sequence", Value::from(u64::MAX)),
        ("format_version", Value::from(9)),
    ] {
        let mut invalid = checkpoint.clone();
        invalid[field] = replacement;
        fs::write(&anchor, invalid.to_string()).unwrap();
        assert!(
            !f.run(&["audit", "verify", "--anchor", path])
                .status
                .success(),
            "{field}"
        );
    }
    fs::write(&anchor, &original).unwrap();
    let archive = fs::read_dir(f.0.join("audit"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".segment-")
        })
        .unwrap();
    fs::write(archive, b"tampered\n").unwrap();
    assert!(
        !f.run(&["audit", "verify", "--anchor", path])
            .status
            .success()
    );
}
