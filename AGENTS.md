# Greenfield Rust MCP Gateway — Project Rules

Read `SPEC.md` and `HANDOFF.md` before coding. Use `agent-context system` and
inspect existing jobs, Git status, and resource pressure before major work.

## Design

- Greenfield Rust project; **not** a rewrite or replacement of any BridgeDev
  installation. This milestone runs as a user-launched **stdio** process.
- Small independent responsibilities: CLI/root configuration, MCP JSON-RPC
  transport, protocol dispatch/tool schema, and scoped file reader. No large
  monolithic `main.rs` and no premature multi-crate workspace.
- `#![forbid(unsafe_code)]` in every crate root. No `unsafe` in our own code.
- Only `std` and the already pinned `serde_json = "=1.0.154"` are permitted in
  Milestone 1. Do not add new runtime dependencies, background services,
  global configuration, or extra monitoring.
- Use JSON-RPC 2.0 MCP over **newline-delimited stdio**, pinned to the legacy
  `2025-11-25` initialization lifecycle. Modern `2026-07-28` discovery and HTTP
  transport are out of scope until a separate compatibility milestone.
- STDOUT: MCP JSON messages only. STDERR: diagnostics only. Never emit secrets.
- No authentication, patching, audit ledger, Windows adapter, Funnel, HTTP or
  privilege broker in this milestone.

## Test-first contract

- The independently authored acceptance test is held at
  `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`,
  outside the agent's writable worktree. Do not access, copy, bypass, modify,
  weaken or regenerate it.
- Make changes only to `src/*.rs`, with no Cargo manifest/lockfile or test
  changes. Prefer `src/transport.rs`, `src/protocol.rs` and `src/file_access.rs`
  as focused modules, coordinated by a minimal `src/main.rs`.
- Local check: `cargo build --offline --locked && python3
  /home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`
  when running as the trusted operator. The coding-agent sandbox deliberately
  hides the external test directory; only the trusted harness runs it.
- Agent output remains in a separate Git attempt worktree. Do not modify
  `main`, merge, publish, deploy, restart services, run sudo, or commit outside
  that attempt branch. Independently review the diff and rerun black-box tests.

## Security

- `--root` must refer to an existing directory. Relative `read_file.path` only.
- Reject `..`, absolute paths, symlinks resolving outside root, non-files,
  missing files, files larger than **65,536 bytes**, and non-UTF-8 contents.
- Keep file resolution code separate from protocol dispatch; do not assume a
  symlink-safe canonicalization check defeats concurrent symlink swap attacks.
  Race-free OS-level containment is a later security milestone.