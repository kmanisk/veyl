# Pass 2 — Scoped Tools and Durable Jobs (Proposed Test Contract)

**Status:** specification and external red tests only. No new write tool,
process-execution capability, privileged service, YOLO or production change
is authorized until the separately reviewed Pass 1 HTTP implementation is
accepted.

## Core requirements

Reuse existing HTTP/authentication/policy modules; extend them through
explicit per-client grants, never through client-provided mode/roots. Keep
the single Rust binary modular: `tools/registry`, `tools/filesystem`,
`jobs/supervisor`, `jobs/store`, and portable platform adapters. Preserve all
43 existing independent locked cases and pin each new suite before coding.

### File tools

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