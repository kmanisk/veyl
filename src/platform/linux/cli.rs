//! Linux CLI and native execution entry points.
use crate::{
    FileAccess, HELP, Protocol, http, io, jobs, local_cli, mode_cli, protected_cli, serve_plan,
    service_cli, skills_cli, state_cli, transport, update_cli, upstream,
};
use std::path::PathBuf;

pub(super) fn run(args: Vec<std::ffi::OsString>) -> Result<(), String> {
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
        println!(
            "Usage: veyl {} [--config PATH] [--listen 127.0.0.1:PORT]\nRun in the foreground; portable first stops and disables the matching Veyl user service.",
            args[0].to_string_lossy()
        );
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "update") {
        return update_cli::run(&args[1..]);
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
        return jobs::verify_scope(args[1].to_str().unwrap_or_default(), 100, 256 * 1024 * 1024)
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
    if args.len() == 1 && args[0] == "--git-tool-worker" {
        return jobs::git_tool_worker()
            .map_err(|_| "Git tool worker confinement unavailable".into());
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
    if args.first().is_some_and(|arg| arg == "marketplace") {
        return upstream::installer::run(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|arg| arg == "monitor") {
        if args.len() == 2 && args[1] == "--help" {
            println!(
                "Usage: veyl monitor [--client ID] [--view health|clients|jobs|logs|audit|skills|upstreams|integrations] [--job ID]\nPairs automatically. Without --view, opens the interactive terminal monitor."
            );
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
        _ => {
            return Err(
                "Invalid command or arguments. Use veyl --help for available commands.".to_string(),
            );
        }
    };

    let files = FileAccess::new(&root)?;
    transport::run(
        io::stdin().lock(),
        io::stdout().lock(),
        Protocol::new(files),
    )
    .map_err(|error| format!("stdio communication failed: {error}"))
}
