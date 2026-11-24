# Pass 2 — Separate supervised jobs increment: independently locked red gates

Date: 2026-11-22. Worktree
`~/Projects/rust-mcp-gateway-lab/worktrees/m2-jobs-supervisor`, branch
`milestone2/jobs-supervisor`. Base:
`ec2d4e75b01e73e35e8ffdea748581a88b19c1f5`, a documentation-only
descendant of the accepted audited write/patch commit `46e4f941`.

**Current state: Phase A implemented and locally exercised.** Independent
acceptance is blocked in this execution environment. The original locked
red baseline and implementation contract are preserved below.

## Independent oracles

- `~/Projects/rust-mcp-gateway-lab/acceptance_pass2_jobs/locked_durable_jobs.py`
  — **9 cases**, SHA-256
  `6f9cd819a1fc6d8f7907beea51fa27cb80a16658a8db20195909d2981e7da338`.
  Covers named profiles, durable receipts, audit, cancel, hard timeout,
  completed-status recovery, client separation, rejection of injected argv,
  child-process-tree cancellation and interrupted jobs never silently
  rerunning as successful.
- `~/Projects/rust-mcp-gateway-lab/acceptance_pass2_jobs_limits/locked_output_caps.py`
  — **1 case**, SHA-256
  `597bb1e3c5b936941dfee5d1b31271b9607e52c1f29594d561feca1abbe1be70`.
  A trusted `flood` profile emits more than 100,000 characters on each
  stream, testing two separate `4096`-byte logs (`stdout.log` and
  `stderr.log`), a bounded status response and eventual exit 0.

Both are located outside agent-writable worktrees, with source files mode
`0444` and parent directories mode `0555`. The network-isolated trusted
verifier checked their hashes before/after running the first job case and
the output-cap case against the current gateway. Both were **red at
job-enabled fixture startup**, because the current operator config does not
support any job profile or job grant. The existing 68 mandatory regression
cases passed first. These are feature absence, not sandbox or test errors.

The 10 job acceptance cases should become a **mandatory** test gate only
after the job increment has passed independent review and been committed,
so old accepted Linux write/patch branches remain testable.

## Implementation contract for a future bounded attempt

1. Reuse existing authenticated HTTP principal/grant identity and private
   `AuditSink`; require durably synced intent before any job spawn, cancellation
   or state change. If audit unavailable, fail closed.
2. In STANDARD mode, clients may choose only a locally configured **named
   profile**. No request-supplied argv/shell command/working directory.
   Use private mode-0600 operator configuration and mode-0700 owned job state.
3. Keep independent Rust modules for tool API, profile validation, process
   ownership, supervisor, durable store, log sink and recovery. Avoid a large
   single-file or always-running background polling loop.
4. Process groups must be owned/tracked before signaling; guard against PID
   reuse, unrelated processes and missed children. Bounded TERM/KILL escalation,
   timeout handling and resource ceilings are required.
5. Never replay unacknowledged/interrupted jobs after a crash. Persist
   completion receipts atomically and classify unknown completion as
   interrupted/uncertain; restore completed receipts accurately after restart.
6. Apply bounded log sizes **per stream**. The minimum independent fixture
   contract requires `max_output_bytes: 4096` and
   `stdout.log`/`stderr.log` of at most 4096 bytes each. Handle flooding
   without a pipe deadlock or unbounded memory growth.
7. Preserve all **68** existing locked cases and their SHA-256 hashes.
   No privileged root/controller configuration, Funnel, systemd unit,
   Windows process code, YOLO or new service installation in this increment.

No Codex implementation was started during the gate-preparation step.

## Phase A attempt 1

The code provides all eight grant-controlled HTTP tool names, including
the start and cancel aliases. The synchronous `run_command` API accepts a
named profile or an argv vector that exactly matches an operator profile.
See [SPEC](SPEC.md#phase-a-durable-supervised-jobs-on-linux) for arguments,
limits, receipt semantics and platform boundaries.

Local offline build, formatting, Clippy with warnings denied and Git
whitespace checks passed. Both added Rust tests passed. Across all Cargo
targets, 22 unit tests passed. One mutation unit test and four mutation
integration tests failed. An isolated export of the unchanged base commit
reproduced the same five failures, including `ENOSYS` for `openat2` and
failure to start mutation-enabled HTTP fixtures.

The trusted network-disabled verifier rejected the environment before
running tests with `bwrap: Can't open source /usr: Function not implemented`.
An independent namespace probe also returned `Operation not permitted`
for `unshare --net`. All 11 SHA-256 pins matched before and after the
verifier invocation. They cover nine suites with 68 existing cases, the
nine-case jobs suite and the one-case output suite. The 78 cases still
require a trusted run in a compatible environment.

Two disposable loopback probes exercised grants, alias arguments,
cross-client denials, synchronous commands, working directory, environment,
SIGKILL of the gateway followed by continuation of the same runner and PID,
completed receipt recovery, TERM-resistant grouped and detached
descendants, timeout, five-per-client and eight-global concurrency,
separate 4,096-byte logs retaining a fraction of 150,000 bytes per stream,
audit failure, signed receipt tampering, and loss of the runner. Further
probes denied duplicate profiles, public credential and state modes, and
replaced or symlinked job roots. Removing the audit sink stopped an active
job, which reconciled as uncertain after the original sink was restored.
The PID-reuse unit test presented a mismatched start time for a live PID.

Debug idle RSS was measured from Linux `/proc/<pid>/status` in KiB. The
zero-job sample used an initialized loopback gateway. The five-job sample
used five concurrent fixed `/usr/bin/sleep 10` profiles with open runners
and no log output. Values are medians of five snapshots per condition.
Summed process RSS can count shared pages more than once.

| Scope mode | Gateway RSS, zero jobs | Gateway RSS, five jobs | Five runners, summed | Five children, summed |
| --- | ---: | ---: | ---: | ---: |
| Unscoped | 5,400 | 5,568 | 25,276 | 10,160 |
| Verified cgroup ceilings | 5,396 | 5,664 | 25,220 | 10,188 |

The project-local RustSec `cargo-audit 0.23.0` reported zero
vulnerabilities and warnings across 49 lockfile packages. It used the
already-installed advisory database at `55e1c3dfb`, dated 2026-11-21,
with `--no-fetch --deny warnings`. The pinned `serde 1.0.229` was promoted
from transitive to direct for typed configuration and authenticated
receipts with derives. The normal Linux Cargo tree grew from 35 to 41
packages including the gateway, of which five added nodes are derive
tooling. The lockfile package count remains 49.

Attempt 1 was one Codex implementation pass. The branch remains uncommitted
pending the locked acceptance results. Codex's final JSON receipt recorded
5,695,859 input tokens (5,541,376 cache hits), 64,171 output tokens,
including 25,699 reasoning-output tokens. This is the aggregate usage
reported by the single large Codex turn, not an estimate.

## Trusted host verification and locked oracle blocker (2026-11-22)

The NoNewPrivileges/bwrap `ENOSYS` diagnostics above are specific to the
restricted Codex job, **not** the trusted host. The operator ran the same
immutable suites through the trusted network-isolated Bubblewrap verifier
using the actual uncommitted Rust implementation, without changing any suite,
the harness or the runner. Results:

- All nine prior suites: **68/68 green**.
- `locked_durable_jobs.py`: **8/9 green** (all but case 08).
- `locked_output_caps.py`: **1/1 green**.
- **77/78 overall**, so the phase is **not accepted**. All 11 locked
  SHA-256 values matched before and after.
- `cargo fmt --all --check`, offline locked build, Clippy
  `-D warnings`, `cargo test --offline --locked` (23 binary unit tests
  and 4 mutation integration tests), `git diff --check`: **green**.

Two real API defects were corrected without modifying tests: missing
`max_output_bytes` on an operator profile now defaults to 4096 bytes per
stream, and terminal JSON states use `completed` and `canceled`.
A recovered but still active detached runner remains operational and is
conservatively presented to the restarted HTTP instance as `uncertain`
until a signed terminal receipt arrives. If an abandoned job has neither
a live runner nor a live child, the durable state becomes `lost`.
Audit records now also contain the argv SHA-256, cwd, timeout/output
limits, state and retained stdout/stderr byte counts, but never raw argv,
environment, credentials or command output. A real `noop` fixture
confirmed all audit fields and token absence.

**Independent case 08 has a demonstrable false-negative.** In
`acceptance_pass2_jobs/locked_durable_jobs.py` lines 254–260, the
`while Path('/proc/PID').exists() ... else: fail` construct fails whenever
the PID **disappears** normally, because Python's `while...else` executes
when a loop exits without `break`. It only passes if the PID remains as a
`Z` zombie long enough for the condition at line 256. The operator executed
the exact locked test method under the trusted sandbox with a diagnostic-only
`fail` callback and independently observed `FAIL_MSG child process
survived...` immediately followed by `GONE` from `/proc/PID`. A separate
diagnostic against the same binary recorded the child's PID before cancel
and confirmed that it was **gone** after cancellation. No locked test was
altered. Forcing a zombie or delaying proper child reaping merely to make
this case pass would be an inappropriate security regression.

The independently authored suite owner must correct that oracle **in a
separate authorized review**, then pin a new SHA-256 and establish an
appropriate baseline. Do not bypass or suppress case 08 in the harness.
No agent retry/second attempt was initiated against the false-negative;
the single large Codex attempt and operator source corrections are preserved.

Dependency review: one new direct crate `serde =1.0.229` (now
`default-features=false` with `std,derive`), plus the `thread` feature on
existing `rustix =1.1.6`. Cargo's unique normal-dependency graph is 35
packages before vs. 41 after (excluding the location-differing local
application package); the lockfile contains 49 dependencies. An actual
`cargo-audit 0.23.0 --no-fetch --deny warnings` run returned exit 0, zero
vulnerabilities and zero warnings. Report:
`~/Projects/rust-mcp-gateway-lab/review_reports/pass2_jobs_cargo_audit_20261122.json`.

**Part B remains skipped:** no independently locked audit-chain suite or
recorded hash exists. This phase is Linux-only; no YOLO, public listener,
Funnel, persistent service, Windows support or deployment was enabled.
