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

use std::io;
use std::path::PathBuf;

use file_access::FileAccess;
use protocol::Protocol;

const HELP: &str = "Veyl — local-first MCP gateway

Usage: veyl <command> [options]

Getting started
  setup --root DIR [--tailscale | --yolo]          Set up Veyl
  init --root DIR                                Initialize local configuration
  connect                                        Copy the connector URL

Daily use
  ui [--remote]                                  Open and pair the dashboard
  dashboard                                      Alias for ui
  tui | monitor                                  Open the terminal monitor
  service on | status                            Manage the user service
  run                                            Run in the foreground
  portable                                       Switch to foreground operation
  mode                                           List client modes
  mode get [CLIENT]                              Show a client mode and state
  mode standard|yolo|full [CLIENT]               Change a client mode
  mode enable|disable [CLIENT]                   Enable or disable a client

Administration
  diagnostics, skills, mcp-servers, audit, state, serve, protected-paths

Advanced transport
  --root DIR                                     MCP over stdio
  http --listen 127.0.0.1:PORT --config PATH      MCP over HTTP

Use veyl help <command> or veyl <command> --help for options.
Use veyl --version to display the installed version.";

fn main() {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "tui") {
        args[0] = "monitor".into();
    }
    if args.len() == 2 && args[0] == "help" && args[1] == "tui" {
        args[1] = "monitor".into();
    }
    let public_command = |arg: &std::ffi::OsString| matches!(arg.to_str(),
        Some("init" | "setup" | "connect" | "run" | "portable" | "ui" | "dashboard" | "monitor" | "service" | "mode" | "diagnostics" | "audit" | "skills" | "mcp-servers" | "state" | "serve" | "protected-paths" | "yolo" | "http"));
    if args.len() == 2 && args[0] == "help" && public_command(&args[1]) {
        args.swap(0, 1);
        args[1] = "--help".into();
    }
    if args.len() == 2 && args[1] == "-h" && public_command(&args[0]) {
        args[1] = "--help".into();
    }
    #[cfg(target_os = "linux")]
    {
        if args.first().is_some_and(|arg| arg == "audit") {
            if let Err((status, message)) = audit_cli::run(&args[1..]) {
                eprintln!("veyl: {message}");
                std::process::exit(status);
            }
            return;
        }
    }
    if let Err(message) = run(args) {
        eprintln!("veyl: {message}");
        std::process::exit(2);
    }
}

fn run(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    let invoked_as_veyl = std::env::args_os().next()
        .is_some_and(|p| std::path::Path::new(&p).file_name().is_some_and(|n| n == "veyl"));
    if args == ["help"] || args == ["--help"] || args == ["-h"] || (args.is_empty() && invoked_as_veyl) {
        println!("{HELP}");
        return Ok(());
    }
    if args == ["version"] || args == ["--version"] || args == ["-V"] {
        println!("{} {}", if invoked_as_veyl { "veyl" } else { env!("CARGO_BIN_NAME") }, env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args == ["http", "--help"] {
        println!("Usage: veyl http --listen 127.0.0.1:PORT --config PATH");
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args == ["ui", "--help"] {
        println!("Usage: veyl ui [--remote] [--config PATH]\nOpen and pair the dashboard.");
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args == ["run", "--help"] || args == ["portable", "--help"] {
        println!("Usage: veyl {} [--config PATH] [--listen 127.0.0.1:PORT]\nRun in the foreground; portable first stops and disables the matching Veyl user service.", args[0].to_string_lossy());
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    let args = local_cli::normalize(args)?;
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(());
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
    if args.len() == 1 && args[0] == "--job-sandbox-probe" {
        return jobs::probe_sandbox_worker().map_err(|_| "job sandbox unavailable".into());
    }
    #[cfg(target_os = "linux")]
    if args.len() == 2 && args[0] == "--job-scope-check" {
        return jobs::verify_scope(args[1].to_str().unwrap_or_default())
            .map_err(|_| "job resource ceilings unavailable".into());
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "yolo") {
        return mode_cli::legacy(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "mode") {
        return mode_cli::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "diagnostics") {
        return local_cli::diagnostics(&args[1..]);
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
        if args.len() == 2 && args[1] == "--help" {
            println!("Usage: veyl monitor [--client ID] [--view health|clients|jobs|logs|audit|skills|upstreams|integrations] [--job ID]\nPairs automatically. Without --view, opens the interactive terminal monitor.");
            return Ok(());
        }
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
        _ => return Err("Invalid command or arguments. Use veyl --help for available commands.".to_string()),
    };

    let files = FileAccess::new(&root)?;
    transport::run(
        io::stdin().lock(),
        io::stdout().lock(),
        Protocol::new(files),
    )
    .map_err(|error| format!("stdio communication failed: {error}"))
}
