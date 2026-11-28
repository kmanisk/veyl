#![cfg(target_os = "linux")]

// Run in its own integration test binary so other fixtures cannot remove
// temporary directories while the broad sandbox projects /tmp.
use serde_json::Value;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Mutex;

static SERIAL_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn branded_help_is_available_without_configuration() {
    let fixture = Fixture::new();
    let alias = fixture.0.join("veyl");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_veyl"), &alias).unwrap();
    for binary in [PathBuf::from(env!("CARGO_BIN_EXE_veyl")), alias] {
        let run = |args: &[&str]| {
            Command::new(&binary)
                .args(args)
                .env("HOME", &fixture.0)
                .output()
                .unwrap()
        };
        for args in [&[][..], &["help"][..], &["--help"][..], &["-h"][..]] {
            let output = ok(run(args));
            assert!(output.contains("Usage: veyl"));
            assert!(output.contains("monitor"));
            assert!(!output.contains("mcp-gateway"));
        }
        for command in [
            "init",
            "setup",
            "connect",
            "run",
            "portable",
            "ui",
            "dashboard",
            "monitor",
            "tui",
            "service",
            "mode",
            "diagnostics",
            "audit",
            "skills",
            "mcp-servers",
            "state",
            "serve",
            "protected-paths",
            "yolo",
            "http",
        ] {
            for args in [[command, "--help"], ["help", command], [command, "-h"]] {
                let output = ok(run(&args));
                assert!(output.contains("veyl"), "{args:?}: {output}");
                assert!(!output.contains("mcp-gateway"), "{args:?}: {output}");
            }
        }
        let invalid = run(&["not-a-command"]);
        assert!(!invalid.status.success());
        let stderr = String::from_utf8_lossy(&invalid.stderr);
        assert!(stderr.starts_with("veyl:"));
        assert!(stderr.contains("veyl --help"));
        assert!(!stderr.contains("mcp-gateway"));
        assert!(invalid.stdout.is_empty());
        assert!(ok(run(&["--version"])).starts_with("veyl "));
    }
    assert!(!fixture.0.join(".local").exists());
}

#[test]
fn short_mode_commands_select_single_client_and_reject_ambiguous_changes() {
    let _lock = SERIAL_LOCK.lock().unwrap();
    let f = Fixture::new();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_veyl"))
            .env("HOME", &f.0)
            .args(args)
            .output()
            .unwrap()
    };
    ok(invoke(&[
        "init",
        "--root",
        f.0.join("workspace").to_str().unwrap(),
    ]));
    assert!(ok(invoke(&["mode"])).contains("dev\tstandard\tenabled"));
    assert!(ok(invoke(&["mode", "get"])).contains("mode=standard"));
    assert!(!invoke(&["mode", "full"]).status.success());
    ok(invoke(&["mode", "disable"]));
    assert!(ok(invoke(&["mode"])).contains("dev\tstandard\tdisabled"));
    ok(invoke(&["mode", "enable"]));
    assert!(ok(invoke(&["mode"])).contains("dev\tstandard\tenabled"));
    let config = f.0.join(".local/state/veyl/clients.json");
    let mut doc: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    let mut other = doc["clients"][0].clone();
    other["id"] = "other".into();
    other["token_sha256"] =
        "abababababababababababababababababababababababababababababababab".into();
    doc["clients"].as_array_mut().unwrap().push(other);
    fs::write(&config, serde_json::to_vec(&doc).unwrap()).unwrap();
    let before = fs::read(&config).unwrap();
    let ambiguous = invoke(&["mode", "get"]);
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("Multiple clients configured"));
    assert_eq!(fs::read(&config).unwrap(), before);
    ok(invoke(&["mode", "yolo", "--confirm-native"]));
    assert!(ok(invoke(&["mode"])).contains("default_mode=yolo"));
    assert!(ok(invoke(&["mode"])).contains("dev\tyolo\tenabled"));
    ok(invoke(&["mode", "standard"]));
    ok(invoke(&["mode", "disable", "other"]));
    assert!(ok(invoke(&["mode"])).contains("other\tstandard\tdisabled"));
    assert!(ok(invoke(&["mode"])).contains("dev\tstandard\tenabled"));
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "veyl-onboarding-{:032x}",
            u128::from_le_bytes(nonce)
        ));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        DirBuilder::new()
            .mode(0o700)
            .create(dir.join("workspace"))
            .unwrap();
        Self(dir)
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
fn fresh_public_setup_provisions_distinct_clients_and_connector() {
    let _lock = SERIAL_LOCK.lock().unwrap();
    use sha2::{Digest, Sha256};
    let f = Fixture::new();
    let home = f.0.join("new-home");
    DirBuilder::new().mode(0o700).create(&home).unwrap();
    let workspace = f.0.join("workspace");
    let invoke = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_veyl"));
        cmd.env("HOME", &home).args(args);
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
        cmd.output().unwrap()
    };
    let output = ok(invoke(&[
        "init",
        "--root",
        workspace.to_str().unwrap(),
        "--tailscale-host",
        "demo.example.ts.net",
        "--chatgpt-yolo",
    ]));
    let state = home.join(".local/state/veyl");
    let policy: Value =
        serde_json::from_slice(&fs::read(state.join("clients.json")).unwrap()).unwrap();
    let url = fs::read_to_string(state.join("chatgpt-connector-url.txt")).unwrap();
    let public = url
        .strip_prefix("https://demo.example.ts.net/veyl/mcp/")
        .unwrap();
    let private = fs::read_to_string(state.join("chatgpt.bearer")).unwrap();
    let dev = fs::read_to_string(state.join("dev.bearer")).unwrap();
    assert_ne!(public, private);
    assert_ne!(public, dev);
    assert_ne!(dev, private);
    assert_eq!(
        policy["tailscale_serve"]["funnel"]["token_sha256"],
        format!("{:x}", Sha256::digest(public.as_bytes()))
    );
    assert_eq!(policy["tailscale_serve"]["standalone_funnel"], true);
    assert_eq!(policy["clients"][0]["mode"], "standard");
    assert_eq!(policy["clients"][1]["mode"], "yolo");
    assert_eq!(policy["clients"][1]["id"], "chatgpt");
    assert!(!output.contains(public) && !output.contains(&private) && !output.contains(&dev));
    assert!(ok(invoke(&["mode", "get", "chatgpt"])).contains("mode=yolo"));
}

#[test]
fn repeated_and_invalid_setup_rejected_without_overwriting() {
    let _lock = SERIAL_LOCK.lock().unwrap();
    let f = Fixture::new();
    let home = f.0.join("home");
    DirBuilder::new().mode(0o700).create(&home).unwrap();
    let workspace = f.0.join("workspace");
    let invoke = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_veyl"));
        cmd.env("HOME", &home).args(args);
        unsafe {
            cmd.pre_exec(|| {
                std::arch::asm!(
                    "syscall",
                    in("rax") 436,
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
        cmd.output().unwrap()
    };

    // First init succeeds
    assert!(
        invoke(&[
            "init",
            "--root",
            workspace.to_str().unwrap(),
            "--tailscale-host",
            "demo.example.ts.net",
        ])
        .status
        .success()
    );
    let state = home.join(".local/state/veyl");
    let initial_bearer = fs::read_to_string(state.join("dev.bearer")).unwrap();

    // Repeated init must fail and preserve state
    let repeated = invoke(&["init", "--root", workspace.to_str().unwrap()]);
    assert!(!repeated.status.success());
    assert!(String::from_utf8_lossy(&repeated.stderr).contains("Veyl state already exists"));
    assert_eq!(
        fs::read_to_string(state.join("dev.bearer")).unwrap(),
        initial_bearer
    );

    // Invalid non-existent workspace
    let non_existent = invoke(&["init", "--root", "/tmp/nonexistent-workspace-path"]);
    assert!(!non_existent.status.success());

    // Both --tailscale and --tailscale-host
    let conflicting = invoke(&[
        "init",
        "--root",
        workspace.to_str().unwrap(),
        "--tailscale",
        "--tailscale-host",
        "demo.example.ts.net",
    ]);
    assert!(!conflicting.status.success());
}

#[test]
fn mode_transitions_and_native_confirmation_workflow() {
    let _lock = SERIAL_LOCK.lock().unwrap();
    let f = Fixture::new();
    let home = f.0.join("home");
    DirBuilder::new().mode(0o700).create(&home).unwrap();
    let workspace = f.0.join("workspace");
    let invoke = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_veyl"));
        cmd.env("HOME", &home).args(args);
        unsafe {
            cmd.pre_exec(|| {
                std::arch::asm!(
                    "syscall",
                    in("rax") 436,
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
        cmd.output().unwrap()
    };

    ok(invoke(&[
        "init",
        "--root",
        workspace.to_str().unwrap(),
        "--tailscale-host",
        "demo.example.ts.net",
        "--chatgpt-yolo",
    ]));

    // 1. Initial state
    assert!(ok(invoke(&["mode", "get", "chatgpt"])).contains("mode=yolo"));

    assert!(!invoke(&["mode", "set", "chatgpt", "full"]).status.success());
    assert!(!invoke(&["mode", "yolo", "chatgpt"]).status.success());
    assert!(ok(invoke(&["mode", "yolo", "chatgpt", "--confirm-native"])).contains("mode=yolo"));

    // 3. Disable client
    let disable_res = ok(invoke(&["mode", "disable", "chatgpt"]));
    assert!(disable_res.contains("client_state=disabled"));

    // 4. Modifying disabled client is rejected
    let set_disabled = invoke(&["mode", "yolo", "chatgpt", "--confirm-native"]);
    assert!(!set_disabled.status.success());

    // 5. Re-enable client
    let enable_res = ok(invoke(&["mode", "enable", "chatgpt"]));
    assert!(enable_res.contains("client_state=enabled"));

    // 6. Return to standard
    let set_standard = ok(invoke(&["mode", "set", "chatgpt", "standard"]));
    assert!(set_standard.contains("mode=standard"));
    assert!(ok(invoke(&["mode", "get", "chatgpt"])).contains("mode=standard"));
    assert!(ok(invoke(&["mode", "yolo", "chatgpt", "--confirm-native"])).contains("mode=yolo"));
    assert!(ok(invoke(&["mode", "standard", "chatgpt"])).contains("mode=standard"));
}

#[test]
fn connect_validates_connector_and_rejects_tampering() {
    let _lock = SERIAL_LOCK.lock().unwrap();
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let home = f.0.join("home");
    DirBuilder::new().mode(0o700).create(&home).unwrap();
    let workspace = f.0.join("workspace");
    let invoke = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_veyl"));
        cmd.env("HOME", &home).args(args);
        unsafe {
            cmd.pre_exec(|| {
                std::arch::asm!(
                    "syscall",
                    in("rax") 436,
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
        cmd.output().unwrap()
    };

    ok(invoke(&[
        "init",
        "--root",
        workspace.to_str().unwrap(),
        "--tailscale-host",
        "demo.example.ts.net",
        "--chatgpt-yolo",
    ]));

    let state = home.join(".local/state/veyl");
    let url_file = state.join("chatgpt-connector-url.txt");
    let original_url = fs::read_to_string(&url_file).unwrap();

    // Tampered token in URL file
    fs::write(
        &url_file,
        "https://demo.example.ts.net/veyl/mcp/tamperedtoken12345",
    )
    .unwrap();
    let tampered_res = invoke(&["connect"]);
    assert!(!tampered_res.status.success());
    assert!(
        String::from_utf8_lossy(&tampered_res.stderr)
            .contains("Saved connector URL no longer matches")
    );

    // Insecure permissions (0644 instead of 0600)
    fs::write(&url_file, &original_url).unwrap();
    fs::set_permissions(&url_file, fs::Permissions::from_mode(0o644)).unwrap();
    let perm_res = invoke(&["connect"]);
    assert!(!perm_res.status.success());
    assert!(String::from_utf8_lossy(&perm_res.stderr).contains("Unsafe connector URL file"));
}
