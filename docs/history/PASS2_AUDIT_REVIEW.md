# Pass 2 — Audit-first review and locked test baselines

**Date:** 2026-11-21 (Asia/Kolkata)

## Accepted starting point

- Pass 1 was saved at `b04989af04ce3b162edb386ea67cff7978b52605`
  on `milestone2/service-contract` after complete staged-diff review.
- A separate `--no-local` clean clone of the committed branch passed offline
  build, Cargo unit/lint checks and all **43/43** independent acceptance
  checks. Its temporary checkout was clean and removed only after success.
- The real `@modelcontextprotocol/sdk` TypeScript client **v1.30.0** connected
  using a disposable scoped bearer token; MCP initialization, `tools/list`
  (exactly `read_file`) and `tools/call` read succeeded. A live `ss -ltnp`
  check confirmed only the selected `127.0.0.1` test port. No raw bearer
  or SHA-256 verifier occurred in captured server/client diagnostics.
- The installed system lacks `cargo-audit` and `cargo-deny`. An online
  **OSV querybatch** checked all 44 version-pinned crates.io packages in
  `Cargo.lock` and returned **zero affected packages** at that time. This is
  **not equivalent to a complete RustSec cargo-audit attestation**; a
  dedicated RustSec scan remains a prerequisite for remote deployment.
- Canonical `main`, production BridgeDev and production Tailscale stayed
  unchanged. No service was installed or enabled.

## Pass 2 isolated branch

Worktree: `~/Projects/rust-mcp-gateway-lab/worktrees/m2-tools-jobs`, branch
`milestone2/tools-jobs`. Planning baseline commit:
`432507e95f39506d9cf6803923bef9f58745a54a`. This contains
`PASS2_TOOLS_JOBS_SPEC.md` and precise audit-first agent rules.

| Locked external oracle | SHA-256 | State |
| --- | --- | --- |
| `acceptance_pass2_audit/locked_audit_contract.rs` | `88f268f3cb60c684c037381a4a729a5b995944db15bf252a43b81fe90f8801c2` | 6/6 green in isolated attempt |
| `acceptance_pass2_files/locked_file_mutation.py` | `8b26c330e203b5417357dd72ee90badfb8dceb4c13c90ef70c24550a9ce6ca2e` | Expected red — tools absent |
| `acceptance_pass2_jobs/locked_durable_jobs.py` | `6f9cd819a1fc6d8f7907beea51fa27cb80a16658a8db20195909d2981e7da338` | Expected red — tools absent |

All three oracles were written **before** Pass 2 implementation, live
outside all coding-agent worktrees, with `0444` files and `0555` directories.
The red audit run failed on unresolved module import. The file/job red runs
failed because Pass 1 rejects unknown write/job grants. No oracle was weakened
or modified to make the implementations pass.

## Agent audit attempt (candidate, not accepted)

Durable job: `job-20261121-231618-729b7a`.
Attempt worktree:
`~/Projects/rust-mcp-gateway-lab/worktrees/job-20261121-231618-729b7a/attempt-01`.
Agent-produced commit: `f93923f` (`Attempt 01 changes by agent`).

Exactly one agent call was allowed, with a 7,000-token threshold checked
between calls. The agent hard-exited after its
60-second deadline, so model token usage was not reliably recorded. The
harness terminal state is **BUDGET_EXPIRED**, not review-approved; never
rewrite that historical status.

The agent changed **only** `src/security/audit.rs` and
`src/security/mod.rs` (+139/−1 lines). The new module defines typed actions
and phases, private append-only JSONL audit records, principal validation,
and flush + `sync_data()` before returning a successful intent receipt.
It does not wire any new MCP tool, process execution or YOLO capability.

The original verifier failed because Cargo 1.100 can put dependency libraries
under `target/debug/build/<crate>/<unit>/out` instead of just `deps/`.
`harness/acceptance.py` now adds these trusted dependency locations to the
external `rustc --test` invocation, and its regression test checks the fix.

An independent **new run**, without another model call, gave:

- All five previous suites: **43/43 pass**.
- New audit suite: **6/6 pass**. SHA remains identical.
- Rust unit tests: **17/17 pass**.
- `cargo fmt --all --check`, `cargo clippy --offline --locked --all-targets
  -- -D warnings`, and `git diff --check`: **pass**.
- Harness regression tests: **34/34 pass**; hardening script: **6/6 pass**.

## Security limits and next action

This module is an isolated, unintegrated local primitive. It checks private
parent/file modes, rejects static symlinks and detects inode replacement,
but **parent path substitution remains a race** if another same-user actor can
modify the audit directory. Do not use it to authorize writes/jobs until
handle-relative containment and fail-closed HTTP integration are independently
tested. Tamper-evident audit chains remain Pass 3.

Next review step: inspect `f93923f`, verify its source and permission behavior,
and choose whether to promote **only those two Rust files** into the
`milestone2/tools-jobs` review branch. Do not automatically cherry-pick,
merge, push, deploy, or enable tools. The currently red 9+9 file/job tests
must drive subsequent bounded development increments.

Outstanding HTTP hardening: client/token-specific rate limiting instead of
global peer-IP only, configurable validated Host/Origin for future Funnel,
instant token revocation without file watcher, operator-generated random
tokens, the modern protocol revision, race-resistant file access and a full
RustSec dependency audit. No remote/public exposure is authorized.