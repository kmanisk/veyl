#![forbid(unsafe_code)]

mod file_access;
mod http;
mod protocol;
mod transport;

use std::io;
use std::path::PathBuf;

use file_access::FileAccess;
use protocol::Protocol;

fn main() {
    if let Err(message) = run() {
        eprintln!("mcp-gateway: {message}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
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
