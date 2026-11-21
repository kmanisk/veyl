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

## Pass 1 addendum (supersedes Milestone 1-only restrictions above)

The `milestone2/service-contract` branch now includes an **uncommitted**, tested
foreground Rust HTTP implementation. Preserve the already accepted stdio
behavior and independent black-box tests. Pass 1 explicitly permits the pinned
minimal Hyper/Tokio transport and cryptography dependencies in `Cargo.toml` and
`Cargo.lock` along with `src/http/**` and `src/security/**`; the earlier
`serde_json`-only rule applies only to the M1 historical baseline.

Both M1 suites, the M2 STANDARD-policy suite, and the two separate M2 HTTP
suites are mandatory before further code is accepted. They are owned by the
trusted external harness at `~/Projects/rust-mcp-gateway-lab/acceptance_*/`
and must never be modified by the coding agent. Inspect the pinned SHA-256
values in `harness/acceptance.py` and run the trusted network-disabled verifier.

Do not silently claim support for MCP 2026-07-28, OAuth, public ingress, root
execution, durable audit, permanent YOLO, Windows, managed services or
race-free filesystem access. These still require separate acceptance gates.

## Pass 2 audit-first development (current review branch)

The `milestone2/tools-jobs` branch builds on the independently accepted
Pass 1 commit `b04989af04ce3b162edb386ea67cff7978b52605`. Its next
**single bounded agent task** is a pure Rust audit-sink module only, under
`src/security/audit.rs` exported by `src/security/mod.rs`. The agent must not
add write, patch, shell, process, service, privileged or YOLO behavior during
this task. Preserve the working HTTP and stdio implementations and the pinned
Cargo manifest/lockfile. No global installs or persistent services.

The external independent audit oracle is
`~/Projects/rust-mcp-gateway-lab/acceptance_pass2_audit/locked_audit_contract.rs`;
its SHA-256 is `88f268f3cb60c684c037381a4a729a5b995944db15bf252a43b81fe90f8801c2`.
All 43 established gateway tests remain mandatory. Do not access or modify
any independent acceptance suite. The file-write and durable-jobs suites
are locked externally but currently **expected red**; they must not be
silently marked passing or bypassed. Stop for manual review after audit passes.