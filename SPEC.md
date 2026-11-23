# Rust MCP Gateway — Milestone 1 Specification

## Scope and protocol contract

The **only** transport is a foreground subprocess on newline-delimited **stdio**.
Use a deliberately small JSON-RPC 2.0 adapter implemented with Rust standard
library and pinned `serde_json = "=1.0.154"`. The official Rust MCP SDK
(`rmcp`) is preferred for future expanded protocol/HTTP support, but is not
currently in the offline Cargo cache; replacing this adapter must preserve
these independent black-box tests.

Pin the **legacy MCP 2025-11-25 lifecycle**: `initialize` request,
`notifications/initialized` notification, then tool methods. One request per
line and exactly one JSON-RPC response per request, flushed promptly. Do not
respond to notifications. No prompts/resources, networking, auth, sessions,
audit ledger, filesystem mutation, or service-mode integration.

Invocation: `mcp-gateway --root /absolute/path/to/existing/directory`.
Canonicalize the root at startup and fail with a nonzero exit and stderr-only
diagnostic if invalid. Do not use the current working directory as an implicit
access root. Cleanly exit when stdin reaches EOF.

### `initialize`

Request `params.protocolVersion = "2025-11-25"`; accept a normal `clientInfo`
and `capabilities` object. Successful result must include:

```json
{
  "protocolVersion": "2025-11-25",
  "capabilities": { "tools": {} },
  "serverInfo": { "name": "mcp-gateway", "version": "0.1.0" }
}
```

Use ordinary JSON-RPC `id` echoing and `jsonrpc: "2.0"`. Implement method
dispatch for `initialize`, `notifications/initialized`, `tools/list`, and
`tools/call`. Unknown methods return JSON-RPC `-32601`; malformed requests
return protocol errors rather than panicking. No binary stdout greetings or
logging. Reject normal tool calls before completing initialization.

### `tools/list` — exactly one tool

The only advertised tool has this name and input schema:

```json
{
  "name": "read_file",
  "description": "Read a UTF-8 text file relative to the configured allowed root (max 65536 bytes)",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Relative file path inside the configured root"
      }
    },
    "required": ["path"],
    "additionalProperties": false
  },
  "annotations": { "readOnlyHint": true, "destructiveHint": false }
}
```

### `tools/call` — only `read_file`

Request:

```json
{ "name": "read_file", "arguments": { "path": "relative/file.txt" } }
```

Successful result:

```json
{ "content": [{ "type": "text", "text": "file contents" }], "isError": false }
```

Tool-level failures (missing file, traversal, symlink escape, oversize,
non-UTF-8, directory, invalid `path`) return the same content shape with
`isError: true` and a short safe human-readable text error. Never return data
from an escaped path. Reject absolute paths and any parent `..` component.

Security: canonicalize and compare resolved paths against the canonical root;
only open regular files; bound reads to **65,537** bytes and reject anything
over **65,536** bytes (no truncation). This is Milestone 1's symlink escape
check, not a claim of race-free `openat2` containment. Prefer UTF-8 decoding
with explicit error rather than lossy replacement.

## Black-box acceptance cases (locked outside this repo)

Source: `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`

1. MCP initialize response succeeds and advertises the tools capability.
2. `tools/list` lists precisely one `read_file` with the required schema.
3. Reading an in-root UTF-8 file returns exactly its bytes as text.
4. `../` traversal is rejected without leaking a sibling secret.
5. A symlink escaping the root is rejected without leaking the target.
6. A missing file returns a tool-level error, without a crash.
7. An oversized (65,537-byte) file returns an error, not truncated content.
8. An absolute path is rejected without leaking its target.

Verifier: `cargo build --offline --locked --quiet && python3
/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`

Before implementing, run this against the initial stub to establish a genuine
**red** baseline. Only the trusted harness executes the external verifier.
The coding agent should implement source modules to turn it **green**.

## Milestone acceptance and exclusions

All eight external black-box tests must pass with the same SHA-256 checksum
before and after; no modifications outside `src/*.rs`, no extra dependencies,
and no `unsafe`. Keep the passing output in a separate Git attempt branch,
inspect the entire patch, and stop at `READY_FOR_USER_REVIEW` without merging.

Deferred: durable authorization, sessions, write/patch tools, audit ledger,
Windows adapters, Tailscale Funnel, HTTPS/HTTP transport, full modern MCP
2026-07-28 support, race-free filesystem resolution, and dashboard/CLI polish.

## Current Pass 2 authenticated HTTP extension (2026-11-22)

The scope and exclusions above describe **Milestone 1 only**, not the current
Linux HTTP implementation. The accepted Pass 1 HTTP baseline is `b04989a`.
The Pass 2 review branch adds explicitly granted `write_file` and
`apply_patch` tools for authenticated HTTP clients. Stdio retains its original
`read_file` behavior.

- `write_file`: `{path, content, overwrite?: boolean}`; maximum **65,536
  UTF-8 encoded bytes**. Existing files require `overwrite: true`; new files
  are created with mode `0600`.
- `apply_patch`: `{path, expected_sha256, old, new}`; original SHA-256 must
  match and `old` must occur **exactly once**, with the final size bounded.
- Both require a per-client grant and a private, synced write-ahead audit
  intent **before** file modification. The outcome is synced before success;
  a failed post-mutation outcome is reported as uncertain, not successful.
- Linux-only handle-relative `openat2` containment, private same-directory
  staging, atomic rename and directory fsync; owner and ordinary mode bits
  are preserved on normal replacement, and outside-root symlinks are rejected.
- Unrelated hostile same-user writers, path moves, torn audit records and
  power loss remain open risks; a crash before rename can leave a staging file.
- This increment excludes YOLO, elevated OS access, remote ingress,
  installed Linux services and Windows adapters. The separate Linux jobs
  increment is described below.

See `PASS2_TOOLS_JOBS_SPEC.md`, `PASS2_WRITE_PATCH_REVIEW.md` and `HANDOFF.md`
for independent test gates, details and remaining limits.

## Phase A durable supervised jobs on Linux

The foreground loopback HTTP gateway authorizes jobs using operator grants
for the authenticated client. The original stdio tool set remains
`read_file`. Listed and callable job tools require the relevant grant.
The start and cancel aliases share their respective grants.

| Tool | Accepted arguments | Result |
| --- | --- | --- |
| `start_job`, `job_start` | Exactly `{"profile":"name"}` | Opaque job ID and starting status |
| `run_command` | Exactly `{"profile":"name"}` or `{"argv":[...]}` matching a configured executable and arguments | Status and bounded log excerpts after a run limited to two seconds |
| `job_status` | Exactly `{"job_id":"id"}` | Owner-only status, exit code or signal, log paths and truncation flags |
| `job_logs` | Exactly `{"job_id":"id"}` | Owner-only stdout and stderr excerpts, up to 4,096 input bytes per stream |
| `cancel_job`, `job_cancel` | Exactly `{"job_id":"id"}` | Owner-only cancellation status, which may still be pending |
| `list_jobs` | Empty object or `{"cursor":"id"}` | Up to 40 owner-only statuses and a continuation cursor |

Job-enabled credential configuration is a private, single-link file owned
by the unprivileged gateway user. It adds `audit_log`, `job_state_dir` and
`job_profiles` alongside `clients`. The audit record is mode `0600` in a
mode `0700` directory. The gateway can create the mode `0700` state directory
under an existing parent. Keep the credentials, audit log and
state directory outside every served root. Profile executables must also
be outside every HTTP mutation root. Trusted operators supply absolute
executable paths, fixed argument vectors and limits.

```json
{
  "noop": {
    "executable": "/usr/bin/true",
    "args": [],
    "timeout_seconds": 2,
    "max_output_bytes": 4096
  }
}
```

The example is the value of `job_profiles`. Profiles accept 1–300 seconds
and 1–65,536 bytes retained per stream. If `max_output_bytes` is omitted,
the secure default is **4096 bytes per stream**. A state store allows up to eight
active or uncertain jobs globally and five per client. It retains at most
1,024 job directories. Before reaching the retention limit, the operator
can archive completed directories while the gateway is stopped. Unknown
outcomes retain their reservations pending operator reconciliation.

The gateway syncs an audit intent and a signed `starting` receipt before
launching a detached runner. The runner holds a kernel lease for the job,
sets its working directory by a verified root handle and uses a fixed
`PATH` and `LC_ALL`. Profile execution uses direct argv and disables Linux
privilege gains on exec. The runner owns a separate session and gives its
child a distinct process group. The runner holds the leader's PID until it
has sent TERM and any needed KILL, then reaps children, including adopted
descendants. Each job directory contains separate private `stdout.log` and
`stderr.log` files. Pipes continue to drain after their retention caps.

When an available user systemd manager provides cgroup v2 quotas, the
runner verifies a transient scope with a 100% CPU quota and a 256 MiB memory
ceiling. The scope also has a runtime backstop. A gateway launched without
the standard user runtime directory or without verified quotas exposes CPU
and memory ceilings as unavailable.

Receipts include the client, argv hash, root and working directory, limits,
runner and child identities, exit information, and truncation status.
Updates fsync the stage, rename it, then fsync the directory. The runner
syncs its final audit outcome before publishing a terminal receipt. The
gateway verifies receipts with a store-local HMAC key and reconciles
unfinished receipts using the lease and process identity. It never
replays jobs. The runner continues across a gateway exit. On a new HTTP
instance a previously active detached job is conservatively presented as
`uncertain` until its independently signed final receipt arrives, without
interrupting its actual runner or changing the persisted running state.
If the lease is free and both runner and child are verifiably absent without
final completion, the receipt becomes `lost`; if process existence cannot
be determined, it remains `uncertain`. Recovery never signals numeric
PIDs from stored records.

Job audit entries carry client principal, job ID, argv SHA-256, cwd, timeout
and retained-output limits, state transitions, and retained stdout/stderr
byte counts. Raw argv, token material, environment and command output are
excluded from the audit. The audit JSONL chain/rotation and torn-record
reconciliation remain separate gated work.

Profiles execute with the gateway user's OS access. A working-directory
handle does not restrict the executable's later filesystem or network
operations. The receipt key and private state rely on that UID and the
operator-controlled paths. Audit chaining and independently verified
power-loss behavior remain separate gates. See [the Phase A gate](PASS2_JOBS_GATE.md)
for validation and open acceptance checks.

## Product management extension

The MCP listener continues to accept bearer-authenticated requests on
`/mcp`. The optional Linux admin listener has a separate loopback socket,
session state and connection budget. Embedded static assets render the
operator UX. Skill and upstream changes share policy locking, atomic
replacement and an audit intent/outcome protocol across the CLI and
authenticated admin API. Credential verifiers are excluded from status
DTOs. See [dashboard](docs/DASHBOARD.md), [skills](docs/SKILLS.md) and
[upstream transports](docs/UPSTREAM-MCP.md) for configuration and security
boundaries.

## Linux operator and inspection extension

The daemon retains separate loopback MCP and admin listeners. An opt-in
Serve configuration adds explicit HTTPS host authorities, independent
browser proof for remote admin reads, and the same bearer boundary for
MCP. The trusted Serve CLI scopes conditional updates to owned ports.
The user-unit lifecycle remains local administration.

Linux inspection grants share the core MCP policy and audit boundary.
The native search begins from a pinned workspace handle. Git inspection
runs a bounded snapshot through offline Bubblewrap with fixed commands.
The separate terminal monitor pairs through the admin API and reads views
on demand. See the [operator guide](docs/LINUX.md) and
[capability and scope map](docs/PARITY.md).
