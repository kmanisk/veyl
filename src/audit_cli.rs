//! Operator-facing inspection and rotation of the Linux audit ledger.

use std::ffi::OsString;
use std::path::PathBuf;

use mcp_gateway::security::audit::{AuditLimits, AuditSink};

use crate::http::admission::read_config;

pub(crate) fn run(args: &[OsString]) -> Result<(), (i32, String)> {
    const USAGE: &str = "usage: mcp-gateway audit <verify|status|inspect|rotate> [--config PATH | --log PATH] [--json]";
    let invalid = || (2, USAGE.to_owned());
    let action = args
        .first()
        .and_then(|arg| arg.to_str())
        .ok_or_else(invalid)?;
    if action == "--help" || args[1..].iter().any(|arg| arg == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    if !matches!(action, "verify" | "status" | "inspect" | "rotate") {
        return Err(invalid());
    }
    let mut path = None;
    let mut limits = AuditLimits::default();
    let mut json = false;
    let mut args = args[1..].iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--json") if !json => json = true,
            Some("--log") if path.is_none() => {
                path = Some(PathBuf::from(args.next().ok_or_else(invalid)?));
            }
            Some("--config") if path.is_none() => {
                let config_path = PathBuf::from(args.next().ok_or_else(invalid)?);
                let cfg = read_config(&config_path).map_err(|error| (2, error))?;
                let document: serde_json::Value = serde_json::from_slice(&cfg)
                    .map_err(|_| (2, "Invalid credential configuration".into()))?;
                limits =
                    AuditLimits::from_config(&document).map_err(|error| (2, error.to_string()))?;
                path = document
                    .get("audit_log")
                    .and_then(|value| value.as_str())
                    .map(PathBuf::from);
            }
            _ => return Err(invalid()),
        }
    }
    let path = path.filter(|path| path.is_absolute()).ok_or_else(invalid)?;
    if action == "rotate" {
        AuditSink::rotate(&path, limits)
            .map_err(|error| (1, format!("Audit rotation failed: {error}")))?;
    }
    let result = AuditSink::inspect(&path, action == "inspect").map_err(|error| {
        (
            1,
            format!("VERIFY_RESULT=TAMPERED: broken or unavailable audit history: {error}"),
        )
    })?;
    if json || action == "inspect" {
        println!("{result}");
    } else {
        println!(
            "VERIFY_RESULT=VALID records={} segments={} bytes={}",
            result["sequence"], result["segments"], result["bytes"]
        );
    }
    Ok(())
}
