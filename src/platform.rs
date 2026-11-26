//! Explicit, fail-closed platform capability boundary for the port bootstrap.
use serde_json::{Value, json};

pub fn report() -> Value {
    let linux = cfg!(target_os = "linux");
    let android = cfg!(target_os = "android");
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "version": env!("CARGO_PKG_VERSION"),
        "stage": if linux { "linux_baseline" } else { "experimental_port_bootstrap" },
        "probe": {"transport":"stdio","tools":["platform_info"],"network":false},
        "android_loopback_http": android,
        "private_workspace_reader": if android { "experimental_requires_native_acceptance" } else { "not_available_in_probe" },
        "linux_features": {
            "authenticated_http": linux, "native_mutation": linux,
            "sandbox_jobs": linux, "pty": linux, "systemd": linux,
            "dashboard": linux, "timeshift": linux, "upstream_mcp": linux
        },
        "note":"Compiled feature inventory, not a runtime security or parity certification."
    })
}

#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
pub mod private_workspace;
