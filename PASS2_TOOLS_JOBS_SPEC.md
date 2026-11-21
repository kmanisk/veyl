# Pass 2 — Scoped Tools and Durable Jobs (Proposed Test Contract)

**Status:** independently accepted Pass 1 baseline `b04989af04ce3b162edb386ea67cff7978b52605`;
Pass 2 specification and externally locked red tests only. No write tool,
process-execution capability, privileged service or YOLO is enabled yet.

## Gate 2A: audit sink first (the only current implementation target)

Implement a standalone safe Rust module, exported at
`mcp_gateway::security::audit`, without integrating it into live tools yet.

Required public API for the independent Rust test:

- `AuditSink::open(path: &Path) -> Result<AuditSink, ...>`: accept a private
  absolute path in an existing `0700` directory. Create a private `0600`
  log if missing; reopen an existing private regular file for append. Reject
  symlinks and files accessible to group/others, broad parent directories,
  missing parents and malformed paths. The opening implementation must be
  validated for symlink races before use by any host mutation tool.
- Public enums `AuditAction::{WriteFile, ApplyPatch, JobStart, JobCancel}` and
  `AuditPhase::{Intent, Success, Failure}`.
- `AuditSink::record(&mut self, principal: &str, action: AuditAction,
  phase: AuditPhase, at_unix_seconds: u64) -> Result<(), ...>`: validate a
  short, nonempty, control-free principal, then append exactly one bounded
  JSON line with `principal`, `tool`, `phase`, `unix_seconds`. Return success
  only after flushing and syncing the entry to disk. Never log tokens,
  secrets, commands, paths or file contents. Never truncate an existing log.

No MCP client-facing capabilities may be enabled by Gate 2A. A standalone
audit component is *necessary but not sufficient* for safely enabling writes
or jobs; subsequent gates must verify fail-closed integration atomically.

Independent oracle:
`~/Projects/rust-mcp-gateway-lab/acceptance_pass2_audit/locked_audit_contract.rs`,
SHA-256 `88f268f3cb60c684c037381a4a729a5b995944db15bf252a43b81fe90f8801c2`,
**6** cases. The baseline fails due to an unresolved Rust audit module.

The later, separately locked end-to-end suites are:
`acceptance_pass2_files/locked_file_mutation.py`, SHA-256
`8b26c330e203b5417357dd72ee90badfb8dceb4c13c90ef70c24550a9ce6ca2e`
(9 cases), and `acceptance_pass2_jobs/locked_durable_jobs.py`, SHA-256
`6f9cd819a1fc6d8f7907beea51fa27cb80a16658a8db20195909d2981e7da338`
(9 cases). Both establish red baselines because the gateway does not yet
support write/job grants. Do **not** claim these suites are green after 2A.

## Core requirements

Reuse existing HTTP/authentication/policy modules; extend them through
explicit per-client grants, never through client-provided mode/roots. Keep
the single Rust binary modular: `tools/registry`, `tools/filesystem`,
`jobs/supervisor`, `jobs/store`, and portable platform adapters. Preserve all
43 existing independent locked cases and pin each new suite before coding.

### File tools

**Audit-first invariant:** Before activating any mutating tool or job, require
an operator-configured, private append-only local JSONL audit sink and write
an intent record *durably before* execution, plus a bounded outcome record
afterward. If the intent cannot be recorded, deny execution **without making
changes**. Keep token/verifier, file contents, argv secrets and environment
values out of the log. An unavailable sink must fail closed for all mutating
operations. This is a minimal local write-ahead audit gate; the tamper-evident
chain, retention and operator modes remain Pass 3 work.

For independent fixtures, extend the existing protected `clients.json` with
`"audit_log": "/absolute/path/to/audit/events.jsonl"`. Audit directory
mode `0700`, file mode `0600`; no auto-creation outside the explicitly
configured owned directory. Without this sink, `write_file`, `apply_patch`,
`job_start` and `job_cancel` **cannot execute**, even when a client is granted
the tool name. Only local trusted configuration can enable a capability.

- `read_file`: retain exactly the M1 behavior and the 65,536-byte limit.
- `write_file` schema: `{path: string, content: string, overwrite?: boolean}`.
  Files are UTF-8, bounded to 65,536 encoded bytes. Default `overwrite=false`.
  Never write nonregular files, directories, special files, absolute paths,
  parent traversal or symlink escapes. Use atomic same-directory creation and
  replacement, 0600 private file mode where appropriate, no partial writes.
- `apply_patch` schema:
  `{path: string, expected_sha256: string, old: string, new: string}`.
  Require a unique exact occurrence of `old` and a matching expected original
  SHA-256; on conflict or ambiguous target, make **no** changes. Patch size
  and final file size bounded to 65,536 bytes. Preserve file metadata safely
  and return a new checksum for concurrency-safe subsequent requests.
- All file writes require **handle-relative OS-enforced containment**, not
  canonicalize-then-open. On Linux evaluate the already cached maintained
  `rustix` `openat2` APIs or a vetted capability-filesystem crate; on Windows
  use a separately tested handle-relative adapter. No first-party `unsafe`
  without an explicit security review.
- Scope every operation to the authenticated client's canonical allowed root
  and per-tool grant, with generic errors and bounded outputs.

### Durable jobs

- `job_start` accepts **operator-defined named job profiles only** in STANDARD
  mode: `{profile: string}`. An arbitrary `argv`, shell expression, script or
  executable path from an MCP client is **not allowed** until separately
  authorized, audited YOLO exists in Pass 3.
- An operator-only 0600 config can define a profile with exact executable,
  immutable argument vector, work root, timeout, max output, and concurrency.
  Fixture profiles: `noop` (fixed `/usr/bin/true`) and `short_sleep` (fixed
  `/usr/bin/sleep 2`). No shell interpolation and no host environment leak.
- `job_status` `{job_id:string}` returns durable, bounded state, exit code,
  exit reason and relative log paths. No credential or secret values.
- `job_cancel` `{job_id:string}` cancels owned processes only, verifying
  process identity before signaling, with a bounded TERM/KILL escalation.
- The job store lives in an operator-owned 0700 directory, writes atomic
  receipts and bounded logs, and distinguishes interrupted/uncertain state
  from successful completion after restart. No PID reuse mistakes, no blind
  replay of non-idempotent jobs, no deletion of unrelated processes.
- Provide strict global/per-client concurrent job ceilings, timeouts,
  output caps and clean detached foreground-worker semantics.

The independent fixture config adds `"job_state_dir": "/absolute/private/jobs"`
and `"job_profiles": {"noop": {"executable": "/usr/bin/true", "args": [],
"timeout_seconds": 2}, "short_sleep": {"executable": "/usr/bin/sleep",
"args": ["5"], "timeout_seconds": 3}}`. Operator-defined profiles alone
are executable; untrusted MCP arguments may name only an existing profile.
Expose `job_start`, `job_status`, `job_cancel` via `tools/call`, taking exactly
the `profile` or `job_id` parameter. Return a single text-content element
containing a bounded JSON object with `job_id`, `state`, and when final,
`exit_code`. Keep status/cancel private to the owning authenticated client.

## Acceptance gates

The independent tests live outside the writable worktree. The fixture
requires a temporary root, protected test config and isolated local HTTP
session. First demonstrate an expected **red baseline** against Pass 1,
then implement in small increments. Required tests:

1. Read-only client cannot discover/use write, patch or job-start tools.
2. A write-granted client creates a private text file, then reads identical
   data; overwrite denied by default and allowed only when explicitly granted.
3. Traversal, absolute paths, outside symlinks, special files and symlink
   swap attacks cannot modify outside-root marker files.
4. Oversized/invalid input rejected with no partial destination file.
5. Patch verifies expected SHA-256 and unique old content; on mismatch,
   conflict or ambiguity the original bytes are unchanged.
6. Named `noop` job starts, records a durable ID, exits 0 and exposes bounded
   status; `short_sleep` may be canceled safely.
7. Restart recovers persisted job receipts; active/incomplete process state
   is marked uncertain rather than replayed or falsely completed.
8. Arbitrary command execution, privilege mode toggles and OS elevation
   remain denied in STANDARD mode, even if client JSON requests YOLO.
9. Client A cannot inspect, cancel, read logs or manage client B's jobs.
10. All 43 preexisting M1/Pass 1 suites still pass, no test SHA changes.

## Development boundary

Do not implement Pass 2 until Pass 1 source and dependency changes have been
reviewed and preserved as a standalone baseline. No `systemd` enable, public
listener, persistent YOLO or OS root/Administrator privileges are authorized.