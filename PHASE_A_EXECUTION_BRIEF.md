# Large Phase A — Complete durable supervised jobs in Rust

**Execution contract:** Implement all of Part A as one coherent feature across
independent modules. Do not implement audit chaining (Part B; independently
locked suite does not exist), YOLO, public access, installed services, Windows
or Termux. Do not touch other repositories or the trusted harness/acceptance
tests. The current branch contains one untracked `PASS2_JOBS_GATE.md`:
preserve it and all unrelated state. Do not merge, push or deploy.

## Read first

Run `agent-context system`, read AGENTS.md, SPEC.md, HANDOFF.md,
PASS2_JOBS_GATE.md, PASS2_AUDIT_REVIEW.md, and the existing
src/security/{audit,policy,linux_fs}.rs, src/http/{mod,admission}.rs,
src/tools/{registry,mutation}.rs and src/main.rs.
Check git status and relevant background processes. Confirm original 68
external acceptance tests unchanged and existing locked job-suite hashes:
* /home/onyx/Projects/rust-mcp-gateway-lab/acceptance_pass2_jobs/locked_durable_jobs.py
  6f9cd819a1fc6d8f7907beea51fa27cb80a16658a8db20195909d2981e7da338
* /home/onyx/Projects/rust-mcp-gateway-lab/acceptance_pass2_jobs_limits/locked_output_caps.py
  597bb1e3c5b936941dfee5d1b31271b9607e52c1f29594d561feca1abbe1be70
These are independently locked; never edit or weaken them.

## Part A feature contract

Expose tools named `run_command` (short synchronous), `start_job`,
`job_status`, `job_logs`, `cancel_job`, `list_jobs`, **and compatible
aliases** `job_start`, `job_cancel` required by the existing locked oracle.
All default denied, require explicit client grants, hidden from tools/list
for unauthorized principals. Never copy policy/grants from the request body.
STD mode job_start takes EXACTLY {profile: string} referring to a
trusted-operator configured, fixed executable & argv. Never accept arbitrary
`argv` under the named-only alias; the locked test rejects that. A
separately explicit `run_command` grant may accept bounded argv arrays as
requested, but this is high risk and disabled for default and test clients.
No implicit shell for any tool. Cwd must remain confined to client's root
using handle-relative checks. Scrub environment to a fixed minimal list,
never pass bearer tokens, verifiers, config secrets or host env.

Operator-only protected config keys:
`audit_log`, `job_state_dir` (0700), `job_profiles` object of fixed
{executable, args, timeout_seconds, max_output_bytes}; entries `noop`,
`short_sleep`, `tree`, `flood` in the locked suites. All job/client
config validation must fail closed. Never log raw tokens/argv/output.
Audit durable intent (synced) and a persisted durable state=STARTING
(synced) **before any spawn**. Final outcome record synced before reporting
final status. Job IDs random, unique, opaque. Atomic receipt updates
(write+fsync+rename+directory fsync) with private 0600 log/receipts and owner.
Include client id, argv hash, root/cwd, limits, PID+start time, exit code
or signal, state and log truncation status. No replay on restart.

**Detached survival/recovery:** Runner mode within same binary launched for
each job, independent of foreground HTTP process, with its own process group.
Runner launches only a validated fixed profile, waits/reaps children and
atomically writes durable receipt. It must continue across the gateway
process exit; no always-on global daemon or polling watcher. On restart,
reconcile `STARTING` or `RUNNING` against real process identity and signed
receipt; no PID reuse bug or false success. If uncertain, mark
`interrupted` / `uncertain` / `lost` as appropriate, never re-run.

**Cancel/timeout:** Separate child process group via safe std
`CommandExt::process_group(0)`; SIGTERM then bounded SIGKILL of the verified
owned group (never another job or unrelated process). Kill descendants.
Limit concurrency globally/per client, maximum runtime, bounded result
size, safe signals; avoid signal-by-PID alone. If no `systemd-run --user
--scope` support, report CPU/memory ceilings unavailable rather than
pretend. Use Tokio asynchronous process/time/signal if it materially helps;
no unsafe in own code and avoid new direct crate if possible.

**Logs:** Keep stdout/stderr separate, capped per stream (the independent
`flood` profile requires max_output_bytes=4096 and two bounded files
named `stdout.log`, `stderr.log`). Drain beyond limit without deadlock
or OOM; mark truncated. Return only bounded excerpts through job_logs.

## Acceptance criteria

Run Rust fmt, Clippy -D warnings, offline locked build & tests, Git whitespace.
All **68** preexisting locked suites must remain green (trusted operator
verifier, no edits). Make the external **9-case jobs suite and 1-case output
cap** green; fail closed for unknown profiles and client-injected argv.
Self-test SIGKILL gateway mid-job and restart: no rerun, no false success;
grandchild termination; timeout; log flood; PID reuse.
Verify 10 hashes before & after running suites. Measure debug idle RSS
with zero and five jobs, record the workload and units. Run project-local
RustSec cargo-audit; state dependency-tree delta. Prefer zero new direct
crates, at most one pinned if essential.

**Attempt budget:** Five Codex attempts maximum; if same Part A failure
persists for three attempts, stop. This is attempt **1**, one substantial
implementation pass, not a collection of tiny tasks. Keep a clear record
of model usage if available. You may commit on this branch *only after* all
acceptance gates pass. Do not begin Part B (no independent suite/hash).
Update HANDOFF, SPEC and PASS2_JOBS_GATE accurately. Report work done and
any limitations. Do not touch production BridgeDev, chezmoi or Tailscale.