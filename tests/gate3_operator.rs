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
            "policy_version": 4,
            "audit_log": fixture.0.join("audit/events"),
            "clients": [{
                "id": "fixture", "root": fixture.0.join("workspace"),
                "token_sha256": "a".repeat(64), "expires_at_unix_seconds": u64::MAX,
                "tools": ["read_file"], "mode": if mode == "disabled" { "standard" } else { mode },
                "disabled": mode == "disabled",
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
        Command::new(env!("CARGO_BIN_EXE_veyl"))
            .args(args)
            .arg("--config")
            .arg(self.config())
            .output()
            .unwrap()
    }

    fn mode(&self, args: &[&str]) -> Output {
        let mut command = vec!["mode"];
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
    assert!(
        !f.run(&["mode", "set", "fixture", "full", "--confirm-native"])
            .status
            .success()
    );
    assert!(!f.run(&["mode", "yolo", "fixture"]).status.success());
    assert_eq!(f.read(), original);
    assert!(
        ok(f.run(&[
            "mode",
            "set",
            "--client",
            "fixture",
            "--mode",
            "yolo",
            "--confirm-native"
        ]))
        .contains("mode=yolo")
    );
    assert!(
        ok(f.run(&["mode", "get", "--client", "fixture"])).contains("migration_required=false")
    );
    assert!(ok(f.run(&["mode", "set", "fixture", "standard"])).contains("mode=standard"));
    let after = f.read();
    assert_eq!(
        after["clients"][0]["token_sha256"],
        original["clients"][0]["token_sha256"]
    );
    assert_eq!(after["clients"][0]["mode"], "standard");
    assert!(after["clients"][0].get("yolo_revision").is_none());
    let audit = ok(f.run(&["audit", "inspect"]));
    assert!(audit.contains("\"requested_mode\":\"native_yolo_preset\""));
    assert!(audit.contains("\"requested_mode\":\"standard\""));
    assert!(ok(f.run(&["audit", "verify"])).contains("VERIFY_RESULT=VALID"));
}

#[test]
fn version_four_migration_retains_standard_grants_without_promotion() {
    let f = Fixture::new("standard");
    let mut original = f.read();
    original["policy_version"] = 1.into();
    original["clients"][0]
        .as_object_mut()
        .unwrap()
        .remove("disabled");
    f.write(&original);
    assert!(!f.mode(&["yolo", "--confirm-native"]).status.success());
    ok(f.run(&["mode", "migrate"]));
    let migrated = f.read();
    assert_eq!(migrated["policy_version"], 4);
    assert_eq!(migrated["clients"][0]["mode"], "standard");
    assert_eq!(
        migrated["clients"][0]["token_sha256"],
        original["clients"][0]["token_sha256"]
    );
    assert_eq!(
        migrated["clients"][0]["tools"],
        original["clients"][0]["tools"]
    );
    assert!(migrated["clients"][0].get("yolo_revision").is_none());
    assert!(ok(f.mode(&["get"])).contains("mode=standard"));
}

#[test]
fn disabled_clients_return_to_standard_on_enable() {
    let f = Fixture::new("standard");
    ok(f.mode(&["yolo", "--confirm-native"]));
    ok(f.mode(&["disable"]));
    assert!(ok(f.mode(&["get"])).contains("client_state=disabled mode=standard"));
    assert!(!f.mode(&["yolo", "--confirm-native"]).status.success());
    ok(f.mode(&["enable"]));
    assert!(ok(f.mode(&["get"])).contains("client_state=enabled mode=standard"));
    assert!(f.read()["clients"][0].get("yolo_revision").is_none());
    assert!(ok(f.run(&["audit", "verify"])).contains("VERIFY_RESULT=VALID"));
}

#[test]
fn new_user_init_and_default_commands_need_no_manual_json() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new("standard");
    let home = f.0.join("new-home");
    DirBuilder::new().mode(0o700).create(&home).unwrap();
    let workspace = f.0.join("workspace");
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_veyl"))
            .env("HOME", &home)
            .args(args)
            .output()
            .unwrap()
    };
    let result = ok(invoke(&[
        "init",
        "--root",
        workspace.to_str().unwrap(),
        "--tailscale-host",
        "demo.example.ts.net",
    ]));
    let state = home.join(".local/state/veyl");
    let config = state.join("clients.json");
    let document: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    let bearer = fs::read_to_string(state.join("dev.bearer")).unwrap();
    assert_eq!(bearer.len(), 64);
    assert!(!result.contains(&bearer));
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(state.join("dev.bearer"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        document["clients"][0]["token_sha256"],
        format!("{:x}", Sha256::digest(bearer.as_bytes()))
    );
    assert_eq!(document["clients"][0]["mode"], "standard");
    assert!(ok(invoke(&["mode", "get", "dev"])).contains("mode=standard"));
    assert!(ok(invoke(&["service", "validate"])).contains("Configuration valid"));
    let pair = ok(invoke(&["dashboard", "pair"]));
    assert!(pair.starts_with("PAIRING_TOKEN="));
    assert!(
        !invoke(&["init", "--root", workspace.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(
        fs::read_to_string(state.join("dev.bearer")).unwrap(),
        bearer
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&config).unwrap()).unwrap(),
        document
    );
}

#[test]
fn enable_preserves_credentials() {
    let f = Fixture::new("disabled");
    let mut expected = f.read();
    let output = ok(f.mode(&["enable"]));
    assert!(output.contains("client=fixture client_state=enabled mode=standard"));
    assert!(!output.contains(&"a".repeat(64)));
    expected["clients"][0]["disabled"] = false.into();
    assert_eq!(f.read(), expected);
    let audit = ok(f.run(&["audit", "inspect"]));
    assert!(audit.contains("client_enable"));
    assert!(audit.contains("\"phase\":\"success\""));
}

#[test]
fn interrupted_policy_requires_recovery_to_standard() {
    let f = Fixture::new("standard");
    ok(f.mode(&["yolo", "--confirm-native"]));
    let marker = f.0.join(".clients.json.policy-pending");
    fs::write(&marker, "fixture").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!f.mode(&["get"]).status.success());
    assert!(!f.mode(&["yolo", "--confirm-native"]).status.success());
    assert!(ok(f.mode(&["standard"])).contains("mode=standard"));
    assert!(!marker.exists());
}

#[test]
fn malformed_legacy_mode_cannot_be_activated() {
    for mode in ["yolo", "full"] {
        let f = Fixture::new(mode);
        assert!(!f.mode(&["get"]).status.success());
    }
}

#[test]
fn native_preset_requires_a_mode_specific_approval_and_disallows_replay() {
    let f = Fixture::new("standard");
    ok(f.mode(&["yolo", "--confirm-native"]));
    let approved = f.read();
    let mut forged = approved.clone();
    forged["clients"][0]
        .as_object_mut()
        .unwrap()
        .remove("native_tool_preset");
    f.write(&forged);
    assert!(!f.mode(&["get"]).status.success());
    f.write(&approved);
    ok(f.mode(&["standard"]));
    f.write(&approved);
    assert!(!f.mode(&["get"]).status.success());
}

#[test]
fn audit_anchor_pins_a_prefix_across_append_and_rotation() {
    let f = Fixture::new("disabled");
    ok(f.mode(&["enable"]));
    let anchor = f.0.join("anchor.json");
    let path = anchor.to_str().unwrap();
    assert!(ok(f.run(&["audit", "export-head", "--out", path])).contains("EXPORTED"));
    let original = fs::read(&anchor).unwrap();
    let checkpoint: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(checkpoint["format_version"], 1);
    assert!(checkpoint["sequence"].as_u64().unwrap() >= 1);
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
    ok(f.mode(&["yolo", "--confirm-native"]));
    assert!(ok(f.run(&["audit", "verify", "--anchor", path])).contains("VERIFY_RESULT=VALID"));

    let other = Fixture::new("disabled");
    ok(other.mode(&["enable"]));
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
