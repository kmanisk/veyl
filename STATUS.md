# Gate 3 status

**Blocked at Checkpoint 1, acceptance compatibility.**
Branch `milestone3/modes-service` starts at Gate 2 commit
`7a666d3c42c17fc4a8e0506005b3ec9ac258c15c`, also tagged locally as
`gate2-scoped`. This is the last green implementation checkpoint.

## Preflight evidence

Ran `agent-context system`, reviewed the project instructions, Gate 2
handoff, current implementation, Git refs and worktrees, and the locked
assertions. The modes suite directory contains the suite file and has no
README. No separate execution-allowance readout was available.

The trusted `harness.acceptance.run_acceptance` built the exact Gate 2
source archive offline and ran the current pinned suites in an isolated
verifier. Only the audit suite used the separate `test-hooks` binary.

| Suite group | Passed | Failed | Exit |
| --- | ---: | ---: | ---: |
| Milestone 2 inherited, including jobs 9/9 and output caps 1/1 | 78 | 0 | 0 |
| Gate 1 audit chain | 13 | 0 | 0 |
| Gate 2 YOLO and CLI, including SEC-04 | 11 | 0 | 0 |
| Gate 3 execution modes | 2 | 3 | 1 |

The inherited suites ran as one group and exited zero. The baseline
total is 104/107. Mode cases 02 and 03 passed. Case 01 retained
`mode=disabled`, case 04 returned exit 101 for the job, and case 05
could not report `mode=full`. These results match the expected red/green
split. They do not resolve the fixture contract conflicts below.

All 16 pinned files matched before and after. Dashboard and service/network
were hash-checked only. Full pins, timings and exits are under
`/home/onyx/Projects/rust-mcp-gateway-lab/gate3-preflight-oSpfqO/` in
`verification.log`, `gate2-102.log`, and `gate3-modes.log`.
Execution session `85273` completed. The inherited and mode verifier
invocations returned 0 and 1 respectively.

## Acceptance compatibility

Paths below are relative to the acceptance root.

| Assertion | Classification | Proposed independent AGY action |
| --- | --- | --- |
| Authentication, grants, audit, job ownership and cleanup, output caps, and receipt recovery in the inherited suites | Still valid | Retain assertions. Keep cleanup checks tied to a live descendant with verified identity before cancellation and timeout. |
| `acceptance_pass3_yolo/locked_yolo_service.py` cases 03–06, 10 and 11 use the legacy enable command, scoped filesystem fixtures, runtime YOLO audit flags and a distinct mount namespace | Legacy scoped YOLO where the established scope or activation command is assumed. Audit and protected-state checks remain valid for sandboxed policies. | Preserve legacy behavior and add separate fixtures for explicit broad activation. The legacy suite makes no universal offline assertion about future modes. |
| `acceptance_m2_http/locked_http_acceptance.py` scoped path denials and `acceptance_pass3_modes/locked_mode_suites.py` case 02 | Valid for Standard | Retain the root and offline assertions. |
| `acceptance_pass2_jobs/locked_durable_jobs.py:35–60,242–253,319–327`. The unversioned Standard fixture launches a script outside its declared root and requires a PID file there, then uses that PID in the verifier's own process namespace. | Contradicts mandatory sandboxed, workspace-confined Standard. | Put the script and marker in the granted workspace and observe the live descendant from the verifier across namespaces using a unique test marker and process start identity. Retain both cancellation and timeout proofs. |
| `acceptance_pass3_modes/locked_mode_suites.py:218–229`. Case 01 tries a local Standard command and expects an enabled Standard client. | Still valid as an outcome. Command spelling needs independent review. | Exercise the specified `yolo reset` entry point and verify that revoked elevated or full authority cannot return. |
| `acceptance_pass3_modes/locked_mode_suites.py:332–357`. Case 03 uses legacy enable on a version-1 fixture and only asserts that protected files stay hidden. | Unclear for broad YOLO. Its green result demonstrates the existing scoped sandbox. | Explicitly opt in to broad YOLO, confirm the effective profile, and add an approved off-root positive control alongside the protected-path negative controls. |
| `acceptance_pass3_modes/locked_mode_suites.py:82,363–406`. Case 04 calls legacy enable on a version-1 fixture and requires an IPv4 UDP connect to a public address to return 0. The verifier creates an offline network namespace. | Contradicts legacy offline activation and lacks a controlled network endpoint. | Verify legacy denial first. Exercise `yolo set --mode yolo` explicitly and use a disposable loopback peer inside the verifier's network namespace. |
| `acceptance_pass3_modes/locked_mode_suites.py:435,448–457,468–469`. Case 05 writes `"mode":"full"` directly, then demands status and unsandboxed job success without an operator transition. | Contradicts mandatory `--confirm-full` and durable audit approval. | Require direct configuration and unconfirmed activation to fail. Enable FULL via the confirmed audited CLI and verify genuine unsandboxed execution only against synthetic files in a disposable environment. |

## Worktree and resumption

Created the requested branch, rollback tag, and this worktree. Added the
release-directory ignore rule. The pending worktree changes are
`.gitignore` and `STATUS.md`. No Rust source, Cargo manifests, locked
tests, runner, or harness changed. No checkpoint commit was made.

Next actionable task is an independent AGY compatibility review and
re-pinned acceptance fixtures. Once available, rerun the preflight before
starting migration and SEC-01. For an exact rerun, create a disposable Git
archive of `gate2-scoped`, import `harness.acceptance` from the lab, and call
`run_acceptance(snapshot, None, "true", suites, 100)` with the inherited
plus audit and YOLO suites as one group and the modes suite as a separate
group. Use `verify_locked_tests` against all registered pins before and
after. The historical manifests and logs identify the exact files.

Checkpoints 2–8 remain pending. Audit-head export, service generation,
release artifacts, new mutation checks, and Gate 3 measurements have
not been produced. Any additional security coverage needs independent
acceptance before a final Gate 3 claim. Existing same-UID whole-ledger
rewrite risk remains. No service installation, deployment, push, or
host configuration change occurred.

## Checkpoint 2 resumed, verified locally

The earlier stop decision above records the original preflight. Work
resumed on the same branch. `Mode::ScopedYolo` makes the legacy policy
explicit internally and retains the exact version-1 JSON and audit wire
label. Local reset and explicit Standard selection now recover Disabled
to Standard. They use the existing atomic policy and audit transaction.
Legacy enable still activates only the old scoped policy. The resume
handoff is in `AGY_GATE3_TEST_HANDOFF.md`.

Four local integration checks passed, covering credentials and grants,
the version-1 scoped approval and replay denial, pending-state recovery,
and malformed state. Clippy passed. The existing YOLO suite passed
11/11. The modes suite passed 3/5, including SEC-01. Cases 04 and 05
retain the independently disputed expectations. Sessions 25553, 51061
and 11058 completed. Logs are under `target/gate3/` and
`/tmp/mcp-gate3-checkpoint2-cargo.log`.

Next task is explicit confirmed mode approval and supervised FULL
execution. Broader YOLO remains unavailable until its required isolation
can be verified. Audit anchors and service preparation are separate
implementation checkpoints.

## Explicit FULL approval and supervised execution

Gate 3 stores confirmed FULL in policy schema 2. A mode-specific chain
approval is required at startup and refresh. Existing Gate 2 version-1
scoped YOLO approvals are recognized without rewriting configurations.
Missing confirmation, old schema, forged mode/approval combinations,
Disabled-to-FULL activation, and replay after reset are rejected. The
legacy enable command never selects FULL or broad networked YOLO.

FULL job admission uses the normal grants, audit, signing and supervisor.
It selects the existing host execution branch with inherited
NoNewPrivileges, scrubbed environment, owned process supervision and the
gateway UID. Direct file tools remain scoped. FULL jobs carry the host
UID's file and network permissions and may access or alter same-UID
control-plane state, including audit history. Keep FULL disabled for
clients that lack local-operator trust. Gate 2 refuses schema 2 during
rollback. Retain the older file separately and never use stale approvals
to recover an active policy.

Local tests passed 6/6 and Clippy passed. The synthetic FULL probe ran
`id -u` through authenticated MCP and returned UID 1000, a signed
unconfined receipt, and FULL runtime audit intent and outcome. It used
a throwaway HOME for the controller and ran only the harmless id command.
The pinned legacy YOLO suite passed 11/11. The pinned modes suite passed
3/5, with only the disputed cases 04 and 05 failing. Execution sessions
11724 and 68027 completed. Broad YOLO remains fail-closed.

## Audit anchors locally verified

`audit export-head --out PATH` and `audit verify --anchor FILE` are
implemented and locally tested. The first export assigns a private,
persistent random ledger ID. The verified export is published atomically
without replacement. Verification authenticates the requested prefix
against the whole verified chain, across appends and segment rotation.
Local tests cover wrong ledger, hash, sequence, format, archived tampering,
and existing output. The audit-chain suite passed 13/13 and Clippy passed.
Session 78620 completed. Local evidence is awaiting independent acceptance.
The retained anchor must be outside FULL's write authority for independent
whole-log rewrite detection. Next task is Linux service preparation.
