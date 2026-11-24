//! Operator-facing inspection and rotation of the Linux audit ledger.

use std::ffi::OsString;
use std::path::PathBuf;

use mcp_gateway::security::audit::{AuditLimits, AuditSink};

use crate::http::admission::read_config;

pub(crate) fn run(args: &[OsString]) -> Result<(), (i32, String)> {
    const USAGE: &str = "usage: veyl audit <verify|status|inspect|rotate|export-head> [--config PATH | --log PATH] [--json] [--anchor FILE | --out PATH]";
    let invalid = || (2, USAGE.to_owned());
    let action = args
        .first()
        .and_then(|arg| arg.to_str())
        .ok_or_else(invalid)?;
    if action == "--help" || args[1..].iter().any(|arg| arg == "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    if !matches!(
        action,
        "verify" | "status" | "inspect" | "rotate" | "export-head"
    ) {
        return Err(invalid());
    }
    let mut path = None;
    let mut limits = AuditLimits::default();
    let mut json = false;
    let mut anchor = None;
    let mut out = None;
    let mut args = args[1..].iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--anchor") if action == "verify" && anchor.is_none() => {
                anchor = Some(PathBuf::from(args.next().ok_or_else(invalid)?));
            }
            Some("--out") if action == "export-head" && out.is_none() => {
                out = Some(PathBuf::from(args.next().ok_or_else(invalid)?));
            }
            Some("--json") if !json && action != "export-head" => json = true,
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
    if action == "export-head" {
        let out = out.ok_or_else(invalid)?;
        AuditSink::export_head(&path, &out)
            .map_err(|error| (1, format!("Audit checkpoint export failed: {error}")))?;
        println!("AUDIT_ANCHOR=EXPORTED");
        return Ok(());
    }
    if action == "rotate" {
        AuditSink::rotate(&path, limits)
            .map_err(|error| (1, format!("Audit rotation failed: {error}")))?;
    }
    let result = match anchor {
        Some(anchor) => AuditSink::verify_anchor(&path, &anchor),
        None => AuditSink::inspect(&path, action == "inspect"),
    }
    .map_err(|error| {
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
