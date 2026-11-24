# Pass 2 — Reviewed Linux HTTP write/patch increment

Date: 2026-11-22. Branch `milestone2/tools-jobs`, based on Pass 1
`b04989af04ce3b162edb386ea67cff7978b52605`. This document records the
pre-commit security and test review; any eventual commit and external harness
policy update must be verified independently. No production deployment.

## Exact interface and boundaries

- HTTP `write_file({path, content, overwrite?})` and
  `apply_patch({path, expected_sha256, old, new})`, both with a strict
  65,536-byte UTF-8 limit and explicit per-client grants.
- Read-only clients cannot discover or invoke mutation tools.
- Linux `rustix =1.1.6` is the one added direct dependency. The code uses
  `openat2` handles with `RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS |`
  `NO_XDEV` and checks pinned directory/file identity.
- Before staging, `MutationAudit::run_audited` records a durable intent.
  Atomic publication writes/syncs a private same-directory stage, renames
  it, and fsyncs the directory. Success requires a synced audit outcome;
  publication or outcome ambiguity returns a tool-level uncertain error.
- New files have mode `0600`; normal overwrite preserves original UID, GID
  and ordinary mode bits. Extended ACL or special-mode targets are rejected.
- Patch requires original SHA-256 plus exactly one matching old-text
  occurrence. Cooperative writers serialize using directory advisory locks.

## External independently locked oracles

The first seven suites were locked before the write/patch implementation;
the two supplemental adversarial suites were authored afterwards to close
specific coverage gaps and were mutation-tested. All live **outside** writable
Rust worktrees, with mode `0444` test files and read-only directories.

| Suite path beneath `~/Projects/rust-mcp-gateway-lab/` | SHA-256 | Cases |
| --- | --- | ---: |
| `acceptance_m1/locked_stdio_acceptance.py` | `0b9a680e155b156f65cbbb766dc7e9444bf494aeb45bfb4c43c596a55cdadc9f` | 8 |
| `acceptance_m1_edge/locked_stdio_edge_acceptance.py` | `5379e25caf867bd6db739a36fc21bc5c80ac4607b77ed7ebdd488d5122f76dde` | 7 |
| `acceptance_m2_policy/locked_standard_policy.rs` | `76edbb613950fc66a0fbe9c68bed7d66a19c30a48f2af3d8de4cf1d9378f262b` | 10 |
| `acceptance_m2_http/locked_http_acceptance.py` | `3d5f29e088275ab05ec3f8695e036a7cc5a78dde34a54049a09fb025cc07bcbd` | 12 |
| `acceptance_m2_http_edge/locked_http_security_edge.py` | `f6331f44e1b4f08f75f841a04f40430014d0e30494b8b60bcf15f5e7c72a8fbd` | 6 |
| `acceptance_pass2_audit/locked_audit_contract.rs` | `88f268f3cb60c684c037381a4a729a5b995944db15bf252a43b81fe90f8801c2` | 6 |
| `acceptance_pass2_files/locked_file_mutation.py` | `8b26c330e203b5417357dd72ee90badfb8dceb4c13c90ef70c24550a9ce6ca2e` | 9 |
| `acceptance_pass2_failclosed/locked_http_audit_failclosed.py` | `de520c15c57cb7a76326a0d4497c85cbe448445f8eece85d70bfe879781b3c20` | 8 |
| `acceptance_pass2_containment/locked_parent_symlink.py` | `ac5683be0d218381af585332d1a7a62e607deff17ca9d6e1f760f09b647736ba` | 2 |

Total: **68 independent black-box/policy test cases**. Hashes must be
verified before and after. The locked jobs suite (9 cases) is **intentionally
not run** and does not apply until the later process-supervisor increment.

## Negative-code mutation checks

The operator reviewed the full source and built a throwaway local clone using
the exact working-tree source files; the review branch was never mutated.

- When the durable audit `Intent` record was bypassed, the HTTP fail-closed
  test failed at its intent-before-success assertion (**caught**).
- Removing `BENEATH` and the symlink ban alone did **not** cause an escape;
  the independent `NO_XDEV` safeguard still rejected it. Removing the
  combined scoped-resolution safeguards then made the parent-symlink
  black-box test fail when an attempted write escaped the root (**caught**).
- After restoring the original source in another disposable clone, both
  tests passed again; the successful clone was deleted. Earlier failed
  diagnostic evidence was retained for review.

## Crash and staging behavior

A separate disposable clone inserted a one-second pause **after staging and
before rename**. Killing only the owned fixture gateway with SIGKILL left the
original file unchanged, but also left one `.mcp-stage-*` orphan. A separate
forced ordinary error after stage creation left the original unchanged and
cleaned up the temporary stage. These were deliberate faults in disposable
copies, not production code.

## Remaining limits

- Same-user noncooperating writers and hostile directory moves can still
  race the final rename; kernel handle resolution covers traversal/symlinks,
  not every external modification at publication.
- Interrupted operations can leave stage files, and the audit JSONL does not
  yet have tamper-evident chaining, torn-record repair or crash reconciliation.
- The synchronous filesystem work runs in the HTTP loop; heavy-load
  resilience needs testing. No service, public ingress or YOLO permission is
  enabled.
- Initial Pass 2 dependency review used OSV exact-version checks. A full
  RustSec `cargo audit` is a separate gate; see the post-review handoff.

**Deferred:** all jobs/process execution, Windows, Linux systemd integration,
Funnel, permanent YOLO, elevated host operations, dashboard and packaging.

## Post-commit independent acceptance — 2026-11-22

- **Commit:** `46e4f94155aab1cfc2c5cac1fd3a59928a270904` on
  `milestone2/tools-jobs`; 22 intended source, test, Cargo and documentation
  files. No merge, push or deployment.
- A separate `git clone --no-local` of the committed branch passed offline
  build, Rust tests (21 unit plus 4 integration), formatting, Clippy with
  warnings denied and all **68 external acceptance tests** in isolated
  Bubblewrap. All nine SHA-256 checks remained unchanged, the checkout was
  clean and the temporary clone was removed after successful verification.
- The trusted harness now automatically selects all 68 cases for this commit
  and its descendants but preserves the historical 43 cases for older branches.
  Harness regression tests **35/35** and hardening checks **6/6** passed.
- The real `cargo-audit 0.23.0` completed with exit **0**: 49 lockfile
  dependencies, 0 vulnerabilities, 0 warnings against a 1,555-advisory
  database. JSON receipt:
  `~/Projects/rust-mcp-gateway-lab/review_reports/pass2_cargo_audit_20261122.json`.
- Current normal-dependency graph: Pass 1 **37** entries, Pass 2 **40**
  entries, including the application. `rustix 1.1.6` is the only additional
  direct crate. There was no global package install or permanent service.

The two deliberate code faults were caught by the independently locked audit
and parent-symlink tests; SIGKILL left the target intact but revealed orphaned
staging as an outstanding crash-reconciliation task. Jobs remain separate.