#[cfg(target_os = "android")]
#[path = "platform/android/http.rs"]
mod android_http;
#[cfg(target_os = "linux")]
mod audit_cli;
mod connector;
#[cfg(target_os = "linux")]
mod file_access;
#[cfg(target_os = "linux")]
mod http;
#[cfg(target_os = "linux")]
mod inspection;
#[cfg(target_os = "linux")]
mod jobs;
#[cfg(target_os = "linux")]
#[path = "platform/linux/cli.rs"]
mod linux_cli;
#[cfg(target_os = "linux")]
mod linux_command;
#[cfg(target_os = "linux")]
mod local_cli;
#[cfg(target_os = "linux")]
mod mode_cli;
mod monitor;
#[cfg(target_os = "linux")]
mod oauth_cli;
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
#[cfg(target_os = "linux")]
mod tools;
mod transport;
#[cfg(target_os = "linux")]
mod update_cli;
#[cfg(target_os = "linux")]
mod upstream;

#[cfg(target_os = "linux")]
use file_access::FileAccess;
use protocol::Protocol;
use std::io;

const HELP: &str = "Veyl — local-first MCP gateway

Usage: veyl <command> [options]

Getting started
  login [--root DIR]                              Connect via direct Standard OAuth
  logout                                         Stop and revoke managed OAuth login
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
  update [--check | --reinstall | --from-dir DIR] Update installed user binaries
  mode                                           List client modes
  mode get [CLIENT]                              Show a client mode and state
  mode standard|yolo|full [CLIENT]               Change a client mode
  mode enable|disable [CLIENT]                   Enable or disable a client

Administration
  diagnostics, skills, mcp-servers, marketplace, audit, state, serve, protected-paths
  oauth                                          Local OAuth preview consent
  connector                                      Experimental loopback connector

Advanced transport
  platform                                       Show compiled platform capabilities\n  platform-probe [--root DIR]                    Experimental foreground MCP probe\n  --root DIR                                     MCP over stdio (Linux legacy)
  http --listen 127.0.0.1:PORT --config PATH      MCP over HTTP

Use veyl help <command> or veyl <command> --help for options.
Use veyl --version to display the installed version.";

fn main() {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    let invoked = std::env::args_os()
        .next()
        .and_then(|p| std::path::Path::new(&p).file_name().map(|n| n.to_owned()));
    let alias = invoked.as_deref().and_then(std::ffi::OsStr::to_str);
    if alias == Some("veyl-monitor") || args.first().is_some_and(|a| a == "--monitor-worker") {
        if alias != Some("veyl-monitor") {
            args.remove(0);
        }
        if let Err(error) = text_args(args).and_then(monitor::run) {
            eprintln!("veyl monitor: {error}");
            std::process::exit(2);
        }
        return;
    }
    if alias == Some("veyl-connector") {
        if let Err(error) = text_args(args).and_then(connector::run) {
            eprintln!("veyl connector: {error}");
            std::process::exit(2);
        }
        return;
    }
    if args.first().is_some_and(|arg| arg == "tui") {
        args[0] = "monitor".into();
    }
    if args.len() == 2 && args[0] == "help" && args[1] == "tui" {
        args[1] = "monitor".into();
    }
    let public_command = |arg: &std::ffi::OsString| {
        matches!(
            arg.to_str(),
            Some(
                "init"
                    | "login"
                    | "logout"
                    | "setup"
                    | "connect"
                    | "run"
                    | "portable"
                    | "update"
                    | "ui"
                    | "dashboard"
                    | "monitor"
                    | "service"
                    | "mode"
                    | "diagnostics"
                    | "audit"
                    | "skills"
                    | "mcp-servers"
                    | "marketplace"
                    | "state"
                    | "serve"
                    | "protected-paths"
                    | "yolo"
                    | "http"
                    | "oauth"
                    | "connector"
            )
        )
    };
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

fn text_args(args: Vec<std::ffi::OsString>) -> Result<Vec<String>, String> {
    args.into_iter()
        .map(|a| {
            a.into_string()
                .map_err(|_| "Expected UTF-8 arguments".to_owned())
        })
        .collect()
}

fn run(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    if args.first().is_some_and(|a| a == "connector") {
        return text_args(args.into_iter().skip(1).collect()).and_then(connector::run);
    }
    let invoked_as_veyl = std::env::args_os().next().is_some_and(|p| {
        std::path::Path::new(&p)
            .file_name()
            .is_some_and(|n| n == "veyl")
    });
    if args == ["help"]
        || args == ["--help"]
        || args == ["-h"]
        || (args.is_empty() && invoked_as_veyl)
    {
        println!("{HELP}");
        return Ok(());
    }
    if args == ["version"] || args == ["--version"] || args == ["-V"] {
        println!(
            "{} {}",
            if invoked_as_veyl {
                "veyl"
            } else {
                if std::env::args_os().next().is_some_and(|p| {
                    std::path::Path::new(&p)
                        .file_name()
                        .is_some_and(|n| n == "mcp-gateway")
                }) {
                    "mcp-gateway"
                } else {
                    "veyl"
                }
            },
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    #[cfg(target_os = "android")]
    if args
        .first()
        .is_some_and(|a| a.to_str().is_some_and(|s| s.starts_with("android-")))
    {
        return android_http::run(&args);
    }
    if args == ["platform"] {
        println!("{}", mcp_gateway::platform::report());
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "platform-probe") {
        let root = match args.as_slice() {
            [_] => None,
            [_, flag, dir] if flag == "--root" => Some(std::path::Path::new(dir)),
            _ => return Err("usage: veyl platform-probe [--root ABSOLUTE_PRIVATE_DIR]".into()),
        };
        return transport::run(
            io::stdin().lock(),
            io::stdout().lock(),
            Protocol::platform_probe(root)?,
        )
        .map_err(|err| format!("stdio communication failed: {err}"));
    }
    #[cfg(target_os = "linux")]
    {
        linux_cli::run(args)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("Experimental platform: use platform or platform-probe. Native credential containment and remote execution are not yet accepted.".into())
    }
}
