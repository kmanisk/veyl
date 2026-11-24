#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod audit_cli;
mod file_access;
mod http;
#[cfg(target_os = "linux")]
mod inspection;
#[cfg(target_os = "linux")]
mod jobs;
#[cfg(target_os = "linux")]
mod linux_command;
#[cfg(target_os = "linux")]
mod local_cli;
#[cfg(target_os = "linux")]
mod mode_cli;
#[cfg(target_os = "linux")]
mod protected_cli;
#[cfg(target_os = "linux")]
mod protected_paths;
mod protocol;
#[cfg(target_os = "linux")]
mod serve_plan;
#[cfg(target_os = "linux")]
mod service_cli;
#[cfg(target_os = "linux")]
mod skills;
#[cfg(target_os = "linux")]
mod skills_cli;
#[cfg(target_os = "linux")]
mod state_cli;
#[cfg(target_os = "linux")]
mod tailnet;
mod tools;
mod transport;
#[cfg(target_os = "linux")]
mod upstream;
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
    #[cfg(target_os = "linux")]
    let args = local_cli::normalize(args)?;
    if args.len() == 1 {
        if args[0] == "--version" {
            println!("mcp-gateway {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        if args[0] == "--help" {
            println!(
                "mcp-gateway --root DIR | http --listen 127.0.0.1:PORT --config PATH
\
                      veyl init --root DIR | veyl ui | veyl run | veyl portable | veyl service on | veyl mode --help | monitor --help | yolo --help | audit --help | service --help | protected-paths --help | state --help | serve --help | skills --help | dashboard --help | mcp-servers --help"
            );
            return Ok(());
        }
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "service") {
        return service_cli::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "init") {
        return local_cli::init(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "setup") {
        return local_cli::setup(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "connect") {
        return local_cli::connect(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "portable") {
        return service_cli::portable(&args[1..]);
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
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "mode") {
        return mode_cli::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "protected-paths") {
        return protected_cli::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "state") {
        return state_cli::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "serve") {
        return serve_plan::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args
        .first()
        .is_some_and(|arg| arg == "--git-inspect-worker")
    {
        return jobs::git_worker(&args[1..])
            .map_err(|_| "Git worker confinement unavailable".into());
    }
    #[cfg(target_os = "linux")]
    if args
        .first()
        .is_some_and(|arg| arg == "--mcp-upstream-worker")
    {
        return jobs::upstream_worker(&args[1..])
            .map_err(|_| "Upstream runtime could not enter its sandbox".into());
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "mcp-servers") {
        return upstream::admin::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "monitor") {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("veyl-monitor")))
            .filter(|p| p.is_file())
            .unwrap_or_else(|| std::path::PathBuf::from("veyl-monitor"));
        return local_cli::monitor(&exe, &args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "dashboard") {
        return http::dashboard::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "skills") {
        return skills_cli::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "--broad-exec") {
        return jobs::broad::exec(&args[1..])
            .map_err(|error| format!("Broad execution guard refused job: {error}"));
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
