#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod audit_cli;
mod file_access;
mod http;
#[cfg(target_os = "linux")]
mod jobs;
mod protocol;
#[cfg(target_os = "linux")]
mod service_cli;
mod tools;
mod transport;
#[cfg(target_os = "linux")]
mod yolo_cli;

use std::io;
use std::path::PathBuf;

use file_access::FileAccess;
use protocol::Protocol;

fn main() {
    #[cfg(target_os = "linux")]
    {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.first().is_some_and(|arg| arg == "audit") {
            if let Err((status, message)) = audit_cli::run(&args[1..]) {
                eprintln!("mcp-gateway: {message}");
                std::process::exit(status);
            }
            return;
        }
    }
    if let Err(message) = run() {
        eprintln!("mcp-gateway: {message}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 {
        if args[0] == "--version" {
            println!("mcp-gateway {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        if args[0] == "--help" {
            println!(
                "mcp-gateway --root DIR | http --listen 127.0.0.1:PORT --config PATH
\
                      mcp-gateway yolo --help | audit --help | service --help"
            );
            return Ok(());
        }
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "service") {
        return service_cli::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.len() == 1 && args[0] == "--job-runner" {
        return jobs::run_worker().map_err(|_| "job runner unavailable".into());
    }
    #[cfg(target_os = "linux")]
    if args.len() == 2 && args[0] == "--job-scope-check" {
        return jobs::verify_scope(args[1].to_str().unwrap_or_default())
            .map_err(|_| "job resource ceilings unavailable".into());
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "yolo") {
        return yolo_cli::run(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "http") {
        return http::run(args.into_iter().skip(1).collect());
    }
    let mut args = args.into_iter();
    let root = match (args.next(), args.next(), args.next()) {
        (Some(option), Some(root), None) if option == "--root" => PathBuf::from(root),
        _ => return Err("usage: mcp-gateway --root <existing-directory>".to_string()),
    };

    let files = FileAccess::new(&root)?;
    transport::run(
        io::stdin().lock(),
        io::stdout().lock(),
        Protocol::new(files),
    )
    .map_err(|error| format!("stdio communication failed: {error}"))
}
