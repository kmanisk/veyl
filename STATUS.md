# Gate 3b status

Branch `milestone3/broad-yolo` starts at
`093c4a514a7c73264213a04e3926ff3e7023ed74`, tagged locally as `gate3-partial`.
The `milestone3/modes-service` worktree and `gate2-scoped` tag remain available
for rollback.

## Preflight

The trusted runner matched all 24 pins before and after running the 22
required suites. It executed 195 cases. 181 passed and 14 failed in the
sandbox. Twelve failures were expected: modes 04, Suite A 03–05, and
Suite F 01–07 and 11. The two additional failures were service preparation
07 (no systemd user runtime directory) and 09 (no user manager bus). The
unchanged service suite passed 10/10, exit 0, in the same host user-manager
environment used in AGY's raw report. The combined baseline is 183/195 with
that independently recorded environment distinction. No service was
installed, activated or modified.

The detailed baseline log and pin comparisons are under
`target/gate3b/baseline/`. The primary command was
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD" python3 worktrees/m3-broad-yolo/target/gate3b/run.py baseline`
from the lab root. The driver invokes the existing trusted verifier per
suite and records each exit code. Session 71383 exited 1 with the expected
red cases and the two environment-dependent failures. The read-only
service rerun used `python3 -I -B ../../acceptance_pass3_service/locked_service_preparation.py`
from the worktree.

### Suite D boundary review

All eight cases ran in the verifier namespace. None invokes the gateway,
activates Broad or scoped YOLO, tests gateway admission or mounts a protected
directory. Their 8/8 result characterizes the synthetic fixtures and
demonstrates some failure modes. It provides no positive kernel-masking
acceptance.

| Case | Actual assertion and coverage |
| --- | --- |
| 01 | A hardlink in another directory resolves to the protected inode and reveals its synthetic data. No mask is installed. |
| 02 | An ordinary atomic rename replaces content in an unmounted directory. No file mask or namespace transition is tested. |
| 03 | An ordinary parent lookup exposes a replacement directory. No active mountpoint is replaced. |
| 04 | A swapped symlink resolves to the protected directory. No gateway or sandbox denial is attempted. |
| 05 | CLOEXEC is set on a test descriptor. The child cannot read a descriptor already closed by the fixture, so live gateway FD inheritance is untested. |
| 06 | A standalone Python child returns a nonempty procfs FD listing. It does not check which descriptors are exposed. |
| 07 | A test-side link count predicate rejects a doubly linked file. No gateway admission or runtime inventory is exercised. |
| 08 | A same-UID actor creates an alias after an initial link-count check. No gateway startup or post-check enforcement is exercised. |

## Checkpoint 1 — FULL direct file tools

The existing authenticated tool dispatcher now resolves FULL file targets
against a pinned host parent directory. The existing read, atomic
replacement, hash-guarded patch, staging and audit code is reused. A FULL
overwrite requires kernel write access to the original inode as well as
the parent directory. FULL supports absolute host paths with the existing
regular-file safety constraints. Symlinks, unsafe path components and
incompatible metadata remain rejected. Only the FULL branch can use a
host parent, and it rejects root execution.

Host-parent proof is optional in the ledger format, so older records remain
valid. Recovery uses the proven identity and the existing parent lock even
if the operator revoked the client since the write. FULL is intentionally
same-UID authority and can access state readable by the gateway owner.

Files changed: `src/http/mod.rs`, `src/security/audit.rs`,
`src/tools/filesystem.rs`, `src/tools/mutation.rs`, `src/tools/write.rs`,
`STATUS.md`. Checkpoint commit message:
`fix(files): honor confirmed full mode in direct file tools`.

Session 96084 exited 0. Suite A passed 8/8. File mutations, parent symlinks,
audit chain, scoped YOLO and migration passed 49/49. Logs and pins are
under `target/gate3b/full/`. The supplemental authenticated probe passed
invalid token, missing grant, symlink denial, live revocation, non-root
identity and FULL audit intent/outcome. Reproduce it with
`python3 -B target/gate3b/full-probe.py target/debug/mcp-gateway`.

Checkpoint 1 commit: `590fba650e6aa32660e01d28b0b010821e84975a`.

## Checkpoint 2 — Protected-path policy administration

The local CLI implements list, add, remove and validate, with Suite F's
`--mandatory`, `--optional` and `--readonly` selectors. Config, its
companions, the audit directory and job state are mandatory. The CLI
lists built-in default templates and manages custom entries. Optional
masks accept directories. Read-only rules accept directories or
singly-linked regular files. Descriptor-based validation rejects
symlink components and leaf mount crossings. Saved device and inode
identity detect replaced entries during follow-up validation. These
rules are staged for broad YOLO and have no effect on established
Standard, legacy YOLO or FULL authority.

Rules live in a versioned section of the private policy document. A
policy lock, durable transaction marker and hashed-path audit records
guard edits. Recovery requires repeating the exact local command.
File-only configurations can now reserve a private job-state path.
A directory path alone does not configure job profiles or grant jobs.
Older binaries reject the new rule field. A supported rollback must
restore the matching configuration or remove custom rules first.

Files changed: `src/main.rs`, `src/protected_cli.rs`,
`src/protected_paths.rs`, `src/http/admission.rs`, `src/http/operator.rs`,
`src/http/scope.rs`, `src/jobs/config.rs`, `src/security/audit.rs`,
`STATUS.md`. Checkpoint commit message:
`feat(cli): add durable protected-path management`.

Session 64288 exited 1 on the fixture's file-only state declaration.
The implementation now reserves that path while requiring actual
profiles for every job grant. Session 79112 exited 0 with 70/70,
including Suite F 15/15. Clippy passed. Logs and pin comparisons are
in `target/gate3b/protected-v2/`. Two supplemental local checks verified
audit intent/outcome, mandatory-path rejection, alias rejection, stale
identity, exact command recovery and unchanged policy on audit failure. The
Suite F remote check is a no-op and its audit assertion is tautological.
The local probes do not constitute independent acceptance.

Next: record the verified same-UID architecture blocker and finish
regressions of the independently shippable checkpoints.


Checkpoint 2 commit and current implementation HEAD:
`5eb25fb17b4948f92e4ef81c4d966b697280fc0e`.

## Checkpoint 3 — Broad YOLO remains fail-closed

The disposable directory-mask probe used a 0700 synthetic state directory,
a separate mount namespace, a host network namespace, Bubblewrap
`--new-session --cap-drop ALL --die-with-parent`, zero effective
capabilities and NoNewPrivs 1. Direct accesses and symlink aliases
returned ENOENT. Renaming the mounted directory returned EBUSY.
A same-UID process outside the sandbox then created a hardlink in an
exposed directory after the startup check. The sandbox read the original
protected inode through the alias. After an atomic host-side replacement,
a second alias exposed the new contents. The direct path stayed masked.
Reproduce using `/usr/bin/python3 -I -B target/gate3b/mask-probe.py`.
Evidence is in `target/gate3b/architecture/directory-mask.log`.

A preflight link count check cannot close this race. A 0700 directory
sharing the execution UID cannot exclude that UID under normal DAC.
Existing subordinate UID ranges are delegated to the same operator and
do not by themselves provide independent control-plane ownership from
host code running as that operator. FULL intentionally exposes same-UID
state. Broad activation, state migration, the `state check` command,
Git-hook protections, runtime mount enforcement for the new rules and
a gateway-launched broad socket probe remain pending. There was no
broad-mode fallback. No checkpoint 3 source changes were committed.

Next engineering task is to agree and verify a control-plane storage
boundary independently owned from the broad job UID. The operator
path and job launcher must authenticate the boundary. Protected links,
replace/rename, mounts, inherited descriptors and daemon-mediated
access need positive and negative runtime tests. Isolation of
localhost applications and abstract Unix sockets needs a separate
network policy if required. Host networking would keep both reachable
subject to application authentication and local policy.

AGY review request: add a positive-control fixture that proves the
gateway launched a genuinely broad job with off-root access and
controlled networking, then exercises protected directories, pre- and
post-admission aliases, atomic replacement, mount aliases, and direct
file-tool protections. Keep Suite D's synthetic evidence distinct.
Suite F 10 and 12 require genuine remote-denial and audit assertions
before they can independently establish those guarantees.

## Final verification of completed checkpoints

All 24 pins match before and after. The 22 selected suites contain
195 cases. Trusted sandbox: 192 passed, 3 failed, exit 1. Mode 04
stops at the explicit broad activation denial. Service Preparation 07
and 09 require the user systemd runtime and bus. They pass in AGY's
original environment, where the unchanged suite passed 10/10, exit 0.
The combined result is 194/195. Dashboard and service/network
integration are hash-checked only.

Suite A 8/8, Suite F 15/15, inherited Milestone 2 78/78, audit chain
13/13, scoped YOLO 11/11, migration 14/14, jobs cleanup 8/8, Suite D
8/8 synthetic, persistence 8/8, audit anchors 17/17. See
`target/gate3b/final/acceptance.tsv` for every suite and exact digest,
`acceptance.log` for process IDs and per-suite exits, and
`pins-before.tsv` and `pins-after.tsv` for the raw pin verification.

Formatting, Clippy with denied warnings, offline debug and release
builds, 36 Rust tests, Git whitespace, clean-clone release, 37 harness
tests, six hardening checks and project-local cargo-audit all exited 0.
The dependency trees matched and there were no dependency changes.
The normal release string scan returned no hook match, grep exit 1.
The supplementary crash probe used the separate audit hook binary
until SIGKILL at the ready marker. The release then recovered the
unpublished off-root FULL stage after revocation and verified its
cleanup events and audit chain. The release CLI probe verified reset,
FULL confirmation, broad rejection, rule persistence, bind-alias
denial, append-compatible anchors and a disposable systemd unit.
Whole-ledger rewriting remains possible for the audit owner or FULL.
Retain audit anchors beyond that UID's control to detect rewriting.

Four disposable mutations compiled and were detected. Suite A 03–05
detected FULL remaining scoped. Suite F 08 detected a false success
for mandatory removal. Migration 03 and 04 detected legacy enable
redirected to FULL, an expansion surrogate because broad is absent.
Modes 04 caught networking enabled in the shared offline launcher via
its legacy negative control. Modes 02 did not catch the latter under
the trusted runner's offline network namespace. The separate real
Standard job probe detected it with a controlled TCP peer. Broad
masking, NNP, networking, hardlink and direct file-policy mutations
could not reach an unimplemented mode. See `mutations.log` and
`mutant-*.log` under `target/gate3b/final/`.

Matched release measurements, baseline → current, with five confirmed
running synthetic jobs and one idle sample per mode:

| Mode | Idle RSS KiB | Five-job gateway RSS KiB | Startup ms | Shutdown ms | Median admission ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Standard | 4160 → 4204 | 4436 → 4476 | 1.109 → 1.217 | 0.933 → 1.251 | 9.142 → 3.424 |
| Legacy | 4184 → 4224 | 4328 → 4372 | 1.385 → 1.100 | 1.174 → 0.921 | 9.234 → 9.081 |
| FULL | 4204 → 4112 | 4336 → 4248 | 1.339 → 1.330 | 1.207 → 1.001 | 3.331 → 3.558 |

Idle CPU was zero ticks per five seconds throughout. Broad YOLO
latency is unavailable. The single-run differences do not establish
a performance improvement.

The runnable, partial Linux build is `target/release/mcp-gateway`
(2,746,240 bytes), SHA-256
`5451bdc6fcbe73de49b3ae6d6350695fa3874f928df63e6c9ad5a1d0bda35809`.
A clean local clone at the same HEAD produced a byte-identical binary.
The Gate 3b beta archive was gated on zero mandatory failures.
No installation, activation, deployment, merge or push occurred.

Tracked execution sessions, all finished: 71383 baseline (exit 1),
96084 FULL suites (0), 64288 first protected-path run (1), 79112 fixed
protected-path run (0), 97288 Rust verification followed by the
trusted acceptance matrix (combined exit 1), 11403 harness tests (0),
17326 hardening (0), 98923 clean clone (0), 68659 mutations (0), and
24405 performance (0). Exact Codex usage was unavailable. Only this
final STATUS update is pending in the worktree. Production changes are
committed through checkpoint 2.

---

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

## Linux service preparation locally verified

Unit generation and dry-run passed local checks, including escaped
systemd values, fixed loopback binding, and `systemd-analyze --user verify`
in a temporary directory. Dry-run wrote no unit. Confirmed installation
is file-only, atomic and non-replacing. It leaves activation to the
operator. This run did not execute installation or activation.

Unix SIGTERM and SIGINT stop accepting connections and drain in-flight
HTTP work within a bound. Detached jobs retain their runner leases.
The unit uses `KillMode=process` to preserve that behavior, and sets
restart, memory and task limits. The existing Tokio dependency enables
its signal feature, which adds locked signal-hook-registry 1.4.8
(MIT OR Apache-2.0). Local checks passed 25 unit and 11 integration
tests, Clippy, the supervised FULL probe and unit validation.
Sessions 13057 and 58092 completed. Service work awaits independent
acceptance.

## Partial release verification

The final Rust implementation checkpoint is `2ddd40c`, after scoped
compatibility and SEC-01 (`42315e6`), confirmed FULL (`cb17b8c`), and
audit anchors (`633f915`). `GATE3_BETA.md` gives mode semantics, operator
commands, service planning and rollback instructions.

All original 102 cases pass. The Gate 3 mode suite remains 3/5 with only
the disputed networking and raw FULL cases. The inherited jobs suite
passed 9/9 on its original unversioned compatibility profile. All 16
locked pins matched. The hardening script passed 6/6, and the harness
regression run passed 36/37. Its sole failure expects four Pass 3
registrations but the trusted manifest now contains five. The handoff
records this separate review item. No independent files were edited.

Formatting, Clippy, locked debug and release builds, all 36 Rust tests,
and RustSec audit of 50 crates passed. The release excluded both audit
crash-hook controls. Controlled loopback was denied in Standard and
scoped YOLO. FULL ran supervised as the gateway UID. Seven disposable
mutants compiled and were detected by local assertions. These covered
confirmation, reset, audit anchors, FULL confinement and audit mode, and
network isolation for Standard and scoped YOLO. These local oracles
await independent review.

Broad YOLO activation stays fail-closed. A synthetic writable-mount probe
demonstrated that masking a single path leaves an existing hardlink
visible and can lose the mask after atomic replacement. Mandatory
control-plane protection, persistence mounts, optional protection CLI,
direct file-tool parity, and broad socket probes are unfinished.
Next smallest implementation task is a protected-directory mount design
and local alias/replacement tests that prove the boundary before any
networked host-write profile is admitted.

Matched single-run release measurements, without the user systemd
manager, use the same disposable fixture. Idle samples measured zero CPU
ticks over five seconds for every tested policy.

| Policy | Gate 2 RSS KiB | Partial Gate 3 RSS KiB | Gate 2 admission ms | Partial Gate 3 admission ms |
| --- | ---: | ---: | ---: | ---: |
| Managed Standard | 3944 | 4068 | 10.282 | 10.457 |
| Legacy scoped YOLO | 4088 | 4168 | 11.038 | 12.502 |
| Confirmed FULL | — | 4068 | — | 3.139 |

Partial Gate 3 startup/shutdown samples were 2.272/0.882 ms for Standard,
2.479/1.089 ms for scoped YOLO and 3.272/0.412 ms for FULL. Gate 2
returned signal termination under the same shutdown probe. Five-job RSS
was not sampled. Broad YOLO was unavailable for measurement.

Receipts and reproducible local probes are in `target/gate3/`. Sessions
22086, 54244, 79044, 17318 and 33805 completed. Only source, tests and
documentation belong in the commits. Release artifacts belong in ignored
`dist/`. No persistent service or host changes were made.

## Packaged partial release

A clean local clone of `afa56e9c0c0d3b4b746b59ce004b1137884b1f9a`
built offline in debug and release. The archive uses that release
binary. The extraction smoke passed checksums, help and version, a
disposable generated systemd unit, authenticated managed Standard and
scoped YOLO network-denial probes, and supervised FULL running as UID
1000. All gateway probes exited zero after SIGTERM. A separate extracted
CLI smoke confirmed Disabled reset, FULL confirmation enforcement,
anchor export, verification after a later append, and a side-effect-free
service dry-run. The example configuration uses placeholders and is
deliberately disabled with an expired credential until locally edited.

- Binary `dist/gate3-beta/mcp-gateway` SHA-256
  `189df235d6d6a7eb3c1b5924641bed9bc05decc6532ae062c6cdb38461d8227f`.
- Archive `dist/mcp-gateway-gate3-linux-x86_64.tar.gz` SHA-256
  `077a2dc0b5ec93aabb815f3303b2a589ab6917b1ecc0a2508ed0231ff96597e0`.
- Release session 51379 completed with exit 0. See
  `target/gate3/release.log` and `target/gate3/release-cli.log`.
- Final independent pin check matched all 16 files. Packaging created
  only ignored artifacts. This receipt is documentation-only.
