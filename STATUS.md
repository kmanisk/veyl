# Gate 3d status

## 2026-11-24 — v0.2.1-alpha production upgrade

Independently verified the packaged candidate against AGY's recorded
checksums, all 28 historical pins and the current six-case mode suite.
The candidate passed 15 Linux probes, five product probes, the disposable
Nightshift demo and the Brave automatic-pairing probe. The live source
also passed Rust tests and Clippy; formatting was normalized and the
release binary hashes remained identical. The historical full 287-case
battery was not rerun during this upgrade.

Installed both reviewed binaries and restarted only mcp-gateway.service.
BridgeDev remains active, and existing policy, credentials and Tailscale
routes were retained. Production service, local dashboard endpoint,
automatic monitor pairing, audit verification and actual ChatGPT
system_info/service_status calls passed. Live state layout is valid.
Upgrade receipt: mwusrhl8-yeiqux, exit 0.
Prior binaries: `~/.local/share/veyl-rollback-v0.2.0-alpha.LFwxqA/`.
The current ChatGPT conversation still advertises 16 tools; refresh
client discovery to use the expanded catalog. Next: structured Linux
diagnostics, remaining parity and a real multi-hour model-driven
Nightshift trial. Do not retire BridgeDev yet.

## 2026-11-24 — v0.2.1-alpha Release Candidate & Onboarding Verification Complete

Base: published v0.2.0-alpha, commit 364e954701a950dbaced6dec3dc1678388016c5c on `milestone3/broad-yolo`.
Candidate Version: `v0.2.1-alpha`.

### Release Checksums and Artifacts
Built with Rust 2024 (`cargo build --release --bin mcp-gateway --bin veyl-monitor`):
- `target/release/mcp-gateway` (`veyl-linux-x86_64.bin`): `500680a212b35d72dd9d15f6036e9994a9e25b0cc27cd49bea452adb927e7fc5` (6.2 MB)
- `target/release/veyl-monitor` (`veyl-monitor-linux-x86_64.bin`): `7b9e7e33f0cd442853e67d55e2e7293f84857dfdd89288f7605329c0a61a734f` (1.4 MB)
- `dist/v0.2.1-alpha/veyl-linux-x86_64.tar.gz`: `2f9c579dbfe4407c9046d2ec4b644ee80be534ac934ab17b2f01bd9419e9da59` (3.0 MB)

### Independent Verification Receipts
1. **Rust Tests:** 52/52 passed cleanly across unit and integration targets:
   - `src/main.rs`: 30/30 passed.
   - `tests/bridgedev_parity_and_nightshift.rs`: 3/3 passed (inspection, mutation, nightshift primitives).
   - `tests/gate3_operator.rs`: 11/11 passed (mode CLI, legacy migration, audit anchors, activation).
   - `tests/onboarding.rs`: 4/4 passed (fresh setup, duplicate refusal, mode transitions, connector tampering).
   - `tests/pass2_mutation.rs`: 4/4 passed (file mutations, atomic overwrites, limits).
2. **Clippy:** `cargo clippy --all-targets -- -D warnings` passed with 0 warnings.
3. **Locked External Acceptance:**
   - All 28 external acceptance files match their pinned SHA-256 digests.
   - `acceptance_pass4_three_modes/locked_three_modes.py`: 6/6 PASS in 1.38s.
4. **Product & Linux Probes:**
   - `PYTHONPATH=tests python3 -m unittest tests/product_features.py`: 5/5 PASS in 2.81s.
   - `PYTHONPATH=tests python3 -m unittest tests/linux_features.py`: 15/15 PASS in 4.77s.
   - `tests/gate3_runtime.py`: 3/3 modes PASS (FULL supervised UID 1000, Standard TCP denied, Legacy TCP denied).
   - `tests/systemd_lifecycle.sh`: 7/7 user manager lifecycle steps PASS in 5.13s.
5. **Browser Pairing Timeout Investigation:**
   - Root cause identified: disposable `--user-data-dir` launches in headless Brave block virtual time waiting for CRX3 extension updates and D-Bus portal SecretService calls.
   - Resolution: `--incognito` bypasses network updates while maintaining isolated cookies and storage.
   - Result: `tests/onboarding_browser.py` completes in ~1.5s with `FIRST_RUN_BROWSER_PAIRING_PASS`.
6. **Leaked Descriptor Isolation:**
   - Bubblewrap Broad YOLO preflight (`check_inherited_fds`) rejects non-CLOEXEC file descriptors from parent environments. Added `pre_exec` syscall `sys_close_range(3, 1024, 0)` in test runners to guarantee descriptor cleanliness.
7. **Nightshift Demo Project:**
   - Implemented in `examples/nightshift_demo/demo.py` and `examples/nightshift_demo/README.md`.
   - Verified end-to-end execution: `system_info` and `service_status` diagnostics, `task_run` with `ephemeral_worktree: true` creating automatic branch checkpoint and cleaning up worktree, `task_run` with `request_id` returning `idempotent_replay: true`, `start_job` and `job_logs` streaming, and `cancel_job` cleanly terminating the child process tree.

### Upgrade and Rollback Protocol
- **To Upgrade (when authorized):**
  1. Stop service: `systemctl --user stop mcp-gateway.service`
  2. Backup binary: `cp ~/.local/bin/mcp-gateway ~/.local/bin/mcp-gateway.v0.2.0-alpha.bak`
  3. Install release: `install -Dm755 target/release/mcp-gateway ~/.local/bin/mcp-gateway` and `install -Dm755 target/release/veyl-monitor ~/.local/bin/veyl-monitor`
  4. Restart service: `systemctl --user restart mcp-gateway.service`
  5. Check status: `veyl service status`
- **To Rollback:**
  1. `cp ~/.local/bin/mcp-gateway.v0.2.0-alpha.bak ~/.local/bin/mcp-gateway`
  2. `systemctl --user restart mcp-gateway.service`
  3. State directory `~/.local/state/veyl/clients.json` retains backward-compatible version-3 policy.

Note: Installed production binary (`~/.local/bin/mcp-gateway`) and GitHub remote remain UNMODIFIED.

Base: published v0.2.0-alpha, commit 364e954701a950dbaced6dec3dc1678388016c5c.
Installed binaries matched release checksums. Independently reran the six
three-mode locked cases and three parity/Nightshift integration cases.
All passed. ChatGPT's existing connector still advertised the old 16-tool schema.

The working tree now implements native `init`, `setup`, `connect`, automatic
browser and monitor pairing, default config lookup, `service on`, `run`,
and `portable`. Fresh public setup discovers the signed-in Tailscale node,
creates separate credentials, selects explicitly requested YOLO, and
provisions its own collision-checked 443 Funnel route. Existing shared
routes are retained. The README describes both local and remote first-run flows.

A pre-existing v0.2.0-alpha regression treated private Tailscale user
headers as public Funnel requests. Restored strict Funnel marker
classification. The rebuilt candidate passed all 15 Linux integration
probes and all 5 product probes (process mwuqnr3a-dbz93p, exit 0).
The onboarding candidate previously passed 49 Rust tests and Clippy;
the final marker-only correction still requires a confirmed full Rust
regression receipt. Browser pairing CLI and private verifier generation
were exercised; the original headless browser probe timed out. Real
first-run public provisioning and service/foreground transitions still
need end-to-end independent acceptance. No locked suite was changed.

Do not promote or replace the installed release until the independent
acceptance and live ingress checks are complete. No host service, route,
or existing credential was changed by this checkpoint.


Base: `ca1167356d512a3fd62d30b1f782cc68752a07d6` on `milestone3/broad-yolo`.
The 28 pins matched. Session 50143 ran the correct hook build for audit
(13/13). Required baseline was 218/229 in the trusted namespace.
There were ten broad-mode failures and a systemd user-manager runtime
failure in service preparation case 07.

## A — Persistent state admission

Broad activation is a distinct stored `broad_yolo` approval and keeps
`mode=yolo` in CLI status. Legacy enable still selects scoped YOLO.
Activation verifies the entire private directory containing the config,
audit and job state. It rejects unsafe ownership, modes, links and
overlapping workspaces. Runtime file/job entry points remain gated
until the dedicated launcher is verified.

Targeted session 29735 passed 37/45, including Broad Gateway 01–05, 13
and 14 and all 14 migration cases. Broad Gateway 06–12 await the
runtime. Permanent Permissions 17 still uses separate sibling cfg,
audit and job directories. Their common ancestor also contains the
client workspaces, so admission correctly rejects the fixture. Its
negative control passes. Exact output is in `target/gate3d/admission/`
and full baseline output in `target/gate3d/baseline/`.

Next: build and verify whole-directory masking under the existing
Bubblewrap and supervisor boundaries.


Checkpoint A: `bafbe812e1dba31697efe11afc57b96c7f9efd28`.

## B — Verified sandbox filesystem preflight

Explicit activation now starts an inert process using the production
mount assembly and execution guard. Safe host developer mounts are
projected, HOME ancestors of protected paths are private, and final
directory masks and read-only mounts are verified after assembly.
The guard verifies a changed mount and PID namespace, an empty tmpfs
at each mask, capability drop, non-root UID and NoNewPrivileges.
The launcher refuses visible bind aliases and unexpected kernel
filesystem mounts.

Session 81155 passed 21/28. Broad activation and persistence case 14
passed through real Bubblewrap preflight, as did all migration
controls. Broad workload cases 06–12 remain gated until C connects
the supervisor. Logs: `target/gate3d/sandbox-verified/`.


Checkpoint B: `d4d67a970ddef964d240f64175fa6f1b412fa173`.

## C — Supervised broad networking

The signed receipt now binds the admitted broad mount policy. The
gateway checks state before publishing the job, and the runner checks
state again just before launching Bubblewrap. The broad child shares
host IP networking and retains the private mount, PID, user and IPC
namespaces. Seccomp still rejects kernel file handles, io_uring and
host Unix-domain socket creation. Existing scoped modes keep both
network namespace isolation and socket denial.

Session 67661 passed 36/36 across Broad Gateway, Modes, Durable Jobs
and Managed Jobs Cleanup. Real MCP jobs proved off-root file writes,
state and home masking, loopback networking, NoNewPrivileges and
descriptor isolation. Logs: `target/gate3d/execution/`. Direct broad
file operations remain gated for checkpoint D.


Checkpoint C: `4f7e6cddc1ed5d3e23980ade117d68876865bc86`.

## D — Protected objects and durable mode parity

Broad reads, writes and patches use the same protection plan as
jobs, with checks against pinned parent and resolved object identities.
The job's working directory is checked against the admitted descriptor.
Private namespace projection also protects ancestors of masked paths,
so moving an ancestor is confined to the job's namespace.

Session 20597 passed 49/49 targeted locked cases. Supplemental sessions
63223 and 28406 passed the real MCP and runtime probes: direct off-root
read/write/patch, restart persistence, denial of protected and read-only
objects, hardlink rejection before publishing a receipt, and cancellation.
Real jobs verified empty state tmpfs, mountpoint EBUSY, namespace-local
ancestor rename, persistent path write denial, TLS and UDP loopback,
NoNewPrivileges, zero effective capabilities, and rejection of filesystem
and abstract Unix sockets. An isolated bind-alias probe rejected the
aliased state before activation. See `target/gate3d/runtime-final.log`
and `bind-alias.log`. Next: full regression and release-gate evaluation.


Checkpoint D source: `1f59507d42c33a9a2859ab2d9c25d1873d2144d1`.

## E — Regression, security and release decision

Required acceptance ran 24 suites and 229 cases. All 28 SHA-256 pins
matched before and after. The default pinned run improved from 218/229
to 227/229. The service preparation suite passed all 10 cases after
providing a private XDG runtime directory inside the same network-disabled
verifier. With that result the final tally is **228/229**. The only
remaining scenario is Permanent Permissions 17. Its locked positive
fixture puts `cfg`, `audit`, and `jobs` alongside all client workspaces.
No directory can contain that fixture's required state while excluding
those workspaces. Broad Gateway 14 independently verifies persistence
across restart for a compliant layout. All 14 broad-gateway cases, all
five mode cases and all 13 hook-enabled audit cases passed. The exact
pins, counts and return codes are in `target/gate3d/acceptance.tsv`.

Rust formatting, Clippy with warnings denied, locked offline debug and
release builds, 36 Rust tests, Git whitespace, cargo-audit, 37 harness
tests and six harness hardening checks passed. Cargo manifests are
unchanged. The release binary has no audit hook string. A clean offline
clone at the source checkpoint produced an identical binary.

The runtime regressions used actual authenticated jobs and synthetic
state. Standard and legacy scoped YOLO stayed offline, broad jobs
reached controlled TCP, UDP and HTTPS endpoints, and FULL ran only a
harmless unprivileged command. Broad direct operations and persistence
continued to pass after restart. Existing audit anchor and detached
job recovery tests passed. Broad job `880c54b8f44eb7e2bc85c35ddb738831`
was canceled. Job `36f9981e921aecfb06af0a5c806ab8ff` verified a
namespace-local ancestor rename. Job `3ca34d474bc235fa0edce3435df0bc5e`
verified mountpoint EBUSY, empty state tmpfs, NoNewPrivileges, zero
effective capabilities, and filesystem and abstract socket denial.
See `target/gate3d/binary-smoke.log`.

Ten compiled mutation scenarios ran in disposable sources. Eight
standalone mutants were detected: removing the state mask, masking
only a file, skipping link counts, blocking broad networking, enabling
scoped networking, bypassing file-tool policy, making legacy activation
broad and executing after a mandatory sandbox failure. Dropping the
explicit NoNewPrivileges setting and guard survived because Bubblewrap
still sets it. Dropping mount verification with a correctly assembled
plan also survived. A paired, real runtime overmount fault demonstrated
that the guard changes the result: it refused to run with exit 2,
whereas the same job returned exit 0 and observed the synthetic state
when that guard was simultaneously disabled. See `mutations.log`
and `mutant-*.log` in `target/gate3d/`.

| Mode | Idle RSS KiB, 3c → 3d | Five-job RSS KiB | Median job admission ms |
| --- | ---: | ---: | ---: |
| Standard | 4300 → 4360 | 4540 → 4628 | 4.481 → 10.326 |
| Legacy scoped YOLO | 4228 → 4448 | 4368 → 4588 | 11.992 → 10.749 |
| FULL | 4308 → 4448 | 4448 → 4592 | 3.643 → 3.730 |
| Broad YOLO | — → 4452 | — → 4612 | — → 6.584 |

All idle samples were zero ticks per five seconds. See
`target/gate3d/performance-final.log` for the single-run measurements.

The verified local build is `target/release/mcp-gateway`, 3,047,232
bytes, SHA-256 `a9d3f06cea85c16d953bd35d3d70642e99d54d9212f4db909945fa6d4aee9eb7`.
The complete beta archive and extraction smoke are gated on 229/229.
No services, production configuration, credentials, or external
repositories were changed.

Tracked sessions: baseline 50143 and final suite 97296 exited 1.
Build 55742, harness 22627, resumed mutation sweep 79454, paired
fault 49554, runtime 28406, binary smoke 88600, and performance 5970
exited 0. Supplemental service environment verification is in
`target/gate3d/service-env.log`. Exact token usage was unavailable.

Next: AGY independently corrects Permanent Permissions 17 to keep
config, audit and jobs beneath a mode-0700 state root disjoint from
workspaces. Rerun all 24 required suites with the audit hook build
and private service runtime, then package the beta and hand the
commit to AGY and BridgeDev for double verification.

---

# Gate 3c status

## Verified baseline

- Development branch `milestone3/broad-yolo` was at
  `5eb25fb17b4948f92e4ef81c4d966b697280fc0e` at startup.
- Committed the carried Gate 3b evidence as
  `05e0948c433cfce118ffd311344944d914a9977f`. The new `gate3b-partial`
  tag points to that documentation checkpoint.
- The trusted harness selected 24 of 28 pinned suites. All 28 SHA-256
  pins matched before and after the baseline. The required selection ran
  225 cases, and the four future suites account for 58 cases. Logs:
  `target/gate3c/baseline.log` and `target/gate3c/baseline/`.
- The initial sandbox result was 214/225 (exit 1). The correct audit
  hook build passed 13/13. The service preparation suite was 8/10 in
  the verifier sandbox and 10/10 in the original user systemd environment.
  Together, the baseline was 216/225. The nine implementation reds
  were mode 04, permanent-permissions 17, and broad-gateway 02–08.

## Independent acceptance issues

`acceptance_pass3_broad_gateway/locked_broad_gateway.py` cases 01 and 02
invoke identical broad activation for the same configuration shape with
opposite expected exit codes. The same conflict exists in
`acceptance_pass3_permanent_permissions/locked_permanent_permissions.py`
cases 16 and 17. All three positive suites currently place credentials,
audit and jobs alongside their workspaces. They do not provide a single
dedicated gateway state root. Broad-gateway 04 and 08 submit an echo job,
and 10 connects the test harness itself to the peer. These cases cannot
independently prove the named kernel or network behavior.

AGY follow-up: use an intentionally invalid layout or synthetic alias
for each negative activation case. Use a distinct valid dedicated state
directory for positive activation. The job probes should verify real exit
receipts and observe both an allowed workspace operation and the requested
containment property. The gateway binary and locked tests remain independent.

The dashboard suite starts a single MCP listener and targets administrative
routes on it. Its listener discovery needs a separate admin endpoint before
it can verify the required transport boundary. The service/network suite
case 05 also expects a dashboard response on the MCP listener.

## Verified state-layout diagnostic

`mcp-gateway state check --state-root PATH --config PATH` is read-only.
It checks private ownership, mode, required-entry containment and recursively
detects hardlinks, symlinks and nested mount crossings without printing
state contents. It reports broad activation unavailable even on a valid
layout. The command runs against a quiescent state tree and is a preflight
inspection rather than a runtime mount attestation.

Reproduce the local check with
`python3 -I -B target/gate3c/state-probe.py target/debug/mcp-gateway`.
The valid layout, no mutation, hardlink, symlink, permissions, split
state, malformed configuration and redaction cases passed. Formatting,
Clippy and all 36 Rust tests passed. Files: `src/main.rs`,
`src/state_cli.rs`, `README.md`, and `STATUS.md`.

For a future operator-driven migration, stop admissions and wait for
detached work to finish. Keep the old config and audit state together as
a rollback copy. Prepare a new dedicated mode-0700 directory, preserve
existing audit segments, metadata, job receipts and keys, and update
the copied config's audit and job paths. Run `state check` on the proposed
copy before starting it. No host migration was performed.

The accepted Model A covers sandbox jobs, direct file tools and pre-existing
visible aliases. Model B covers independently compromised same-UID host
processes outside the sandbox. The latter remains outside the broad-mode
threat model. Broad activation is still denied pending runtime mount and
protected-object parity tests. The next task is to implement a constrained
host mount graph, validate protected inode uniqueness before admission and
prove both access and containment in a gateway-launched job.

The state layout diagnostic was committed in
`16811129324a77e4d9aa6e5cae9cb285aa48d7fe`.

## Verified service file lifecycle and Serve planning

`service uninstall --confirm` removes only a private, singly linked file
matching the gateway-generated unit for the supplied configuration and
listener. It accepts the old generated unit shape and refuses changed
units. `--confirm --dry-run` previews removal. Both operations preserve
gateway data. The user unit now includes `ProtectSystem=full`.
A missing unit reports its status without querying a user manager.
`serve plan` validates an MCP loopback target and can read an optional
Serve snapshot while omitting upstream URL values. It reports route
collisions. It does not call Tailscale or apply a plan.

A disposable HOME probe passed unit installation, verification,
modified-unit refusal, removal, absence, and data retention. It also
confirmed snapshot preservation, loopback validation and redaction.
Files: `src/service_cli.rs`, `src/serve_plan.rs`, `src/main.rs`,
`README.md` and `STATUS.md`. See `target/gate3c/service-probe.log`.

The locked service/network suite passed 11/12, exit 1. Case 05 still
expects a dashboard response on the MCP listener. Service preparation
passed 9/10 in the trusted sandbox and 10/10 with the user systemd
environment. The sandbox regression is the test that needs an XDG user
runtime directory. Durable jobs passed 9/9. Session 43114 exited 1.
No production service or Tailscale setting was changed.

Service file lifecycle and Serve planning were committed as
`802055659b1f6b0850c6625e14342651a3c671eb`. The read-only parity
study was committed as `4d3473b6535975259880c0fee50f67fa2db7d55f`.

## Verified instruction packages

The Linux gateway reads bounded, descriptor-confined Markdown packages
from an absolute operator-owned directory. Metadata is validated before
discovery and reading. Existing tool authorization and separate named
grants gate visibility. The local CLI uses the durable policy
transaction and audit ledger for enable and disable. Local calls
proved revocation and restoration on a live authenticated session.
Malformed and symlink-aliased packages were rejected even with a named
grant. The `skills_run` declaration does not expose a callable tool.

The locked skills suite passed 15/15 (exit 0). The same seven-suite
run had 76/77 because mode case 04 remains blocked. Session 15383
exited 1. The supplemental live-session probe and Clippy passed.
See `target/gate3c/skills.log`, `skills-probe.log`, and
`docs/SKILLS.md`. The administration listener remains independently
blocked by the dashboard contract. Upstream provider lifecycle and
the separate monitor remain pending.

## Private GitHub publication

No Git remote existed at startup. The GitHub connector returned 404 for
`kmanisk/rust-mcp-gateway`. HTTPS connectivity to the GitHub API worked.
The configured `gh` account is `kmanisk`, but its Secret Service collection
is locked. Independent attempts to retrieve or validate authorization
hung. No repository creation or push was attempted. Initial redacted
Gitleaks scan found no leaks across the 17 commits in the initial push
set. Re-scan final candidate refs before publishing. There is no project
license file in the inspected refs.

## Final checks and partial release

The final source checkpoint is
`46a1099237105cf1399f017a071095305e604992`. The 28 pinned suites ran
283 cases. The trusted sandbox returned 242/283 overall and 215/225
for the required selection. It exited 1. The nine broad implementation
failures match the starting baseline. Service preparation's
`systemd-analyze --user` case requires a user runtime directory absent
from the trusted sandbox. The unchanged service suite passed 10/10
with the original user-manager environment. Combining those
environments gives 243/283 overall and 216/225 required. Audit passed
13/13 with the dedicated hook build. The dashboard is 0/15, service
network 11/12, skills 15/15, and upstream MCP 1/16. The lone upstream
pass checks the synthetic fixture source and does not validate isolation.

`target/gate3c/acceptance.tsv` records names, paths, exact counts,
exit codes and all 28 matching hashes. Raw output is in
`target/gate3c/final-skills.log` and per-suite files under
`target/gate3c/final-skills/`. The baseline raw output is
`target/gate3c/baseline.log`.

Formatting, Clippy, locked offline debug and release builds, the 36
Rust tests, whitespace, 37 harness tests, six hardening checks,
and project-local cargo-audit passed. Cargo dependency trees matched.
The normal release excludes the audit hook. A clean local clone at
the source checkpoint produced a byte-identical release binary.
The local state probe killed a mutant accepting hardlinks and locked
skills case 05 killed a mutant dropping client-specific read grants.
Unimplemented broad, dashboard and upstream paths have no runtime
mutation result. See `build-final.log`, `harness.log`, and
`mutations.log` in `target/gate3c/`.

The extracted partial archive passed its checksum manifest, private
state checks, disposable service lifecycle, skill authorization and
authenticated MCP smoke tests. Managed Standard and legacy YOLO
denied controlled loopback TCP. Confirmed FULL ran a harmless
unprivileged command through the supervisor.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `dist/gate3d-partial/mcp-gateway` | 2,857,984 | `6836e3ba85895cac52952d5c3ee2a046c3d2b0d064f08a25ad73c1ef7cde6f97` |
| `dist/mcp-gateway-gate3d-linux-x86_64-partial.tar.gz` | 1,116,460 | `87a64a0896d77456eee2302b3e5ea3a4065bae9eee0ac7164e7ec3187895e551` |

The package includes the binary, checksum manifest, configuration and
systemd unit examples, skill format, scope, and rollback documentation.
All distribution files are Git-ignored. See
`target/gate3c/archive-smoke.log`.

Matched release measurements, gate3-partial → current:

| Mode | Idle RSS KiB | Five-job RSS KiB | Startup ms | Shutdown ms | Median job admission ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Standard | 4096 → 4300 | 4368 → 4568 | 1.457 → 1.548 | 1.426 → 1.410 | 9.288 → 9.022 |
| Legacy scoped YOLO | 4164 → 4316 | 4316 → 4464 | 1.393 → 1.375 | 1.284 → 1.215 | 9.871 → 9.725 |
| FULL | 4196 → 4296 | 4328 → 4436 | 1.417 → 1.421 | 1.279 → 1.016 | 3.298 → 3.204 |

All idle samples had zero CPU ticks over five seconds. Single-run
measurements are in `target/gate3c/performance.log`. Broad-mode,
dashboard and upstream overhead are unavailable.

Tracked sessions: 69949 baseline and 9049 final suite matrix (both
exit 1); 94755 build, 54889 harness, 21692 mutations, 34860 archive
smoke, and 25871 benchmark (all exit 0). Exact token usage was not
available.

## Continuation

1. Have AGY distinguish the negative and positive broad fixtures
   and pin their updated versions. Keep the positive state tree
   disjoint from the workspaces. Preserve all independently scoped
   tests. Then validate a pinned host mount graph that avoids nested
   bind aliases, hides the complete state directory, and denies
   protected object identities in direct file tools. Verify it
   through a real supervised networked job before enabling broad.
2. Have AGY discover the separate authenticated admin listener in
   dashboard and service tests, then implement paired admin
   sessions and the live dashboard under that transport.
3. Implement bounded, authorized upstream MCP transport and tool
   namespacing, then add the separate monitor if resources permit.
4. When the existing GitHub credential store is unlocked, verify
   authenticated `gh` identity and destination ownership and
   visibility. Confirm the repository is private before any push.
   The full redacted history scan and tracked filename review
   found no secrets or generated artifacts. The local primary
   branch remains `main`, independent from the development branch.

No service activation, live network changes, production BridgeDev
changes, deployment, publication, or push occurred.

---

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

## Local dashboard, skills and upstream MCP

The execution-mode baseline is `9d792001d82959ae33ef216358507fb20b473d56`.
AGY independently accepted its 229 required cases. The separately preserved
Linux x86_64 beta in `dist/gate3d-beta/` is built from that baseline.
The complete archive is `dist/mcp-gateway-gate3d-linux-x86_64.tar.gz`
(1,171,899 bytes), SHA-256
`c7e0a7052a43187b2af20193e925d8fef936e8ddde62785ad6914e1f0ae80feb`.
The packaged executable SHA-256 is
`a9d3f06cea85c16d953bd35d3d70642e99d54d9212f4db909945fa6d4aee9eb7`.
Extraction, the included checksum manifest and four runtime smoke probes
passed. The product candidate uses the regular build output and has no
release archive.

The candidate enables a separate loopback admin listener, authenticated
browser sessions, job views and cancellation, audited skill import and
grants, and upstream registration, discovery and forwarding. Stdio
upstreams use a fresh Bubblewrap sandbox. Streamable HTTP supports JSON
and SSE. TLS verifies the registered hostname and supports a dedicated
owner-only credential and trust bundle. See the three operator guides
in `docs/` for configuration and rollback.

Verification on the local candidate:

| Check | Result |
| --- | --- |
| Gate 3d inherited | 229/229 |
| Dashboard with isolated Brave | 15/15 |
| Skills | 15/15 |
| External MCP | 16/16 |
| Service and networking | 12/12 |
| Total registered | 287/287 across 28 suites |
| Additional product probes | 5/5 |
| Rust tests | 36 passed |
| Harness regression and hardening | 37/37 and 6/6 |

All 28 pins match before and after. The browser suite was run with only
the installed Brave runtime and a synthetic launcher added read-only to
the offline verifier environment. The unaugmented runner cannot find
Brave. The audit suite used the separate hook-enabled build. Normal
release hook exclusion, formatter, Clippy, offline builds, whitespace
checks and project-local cargo-audit passed. An offline release built from a fresh clone. A separate readable-browser
probe confirmed the real cookie attributes, protected content and desktop
and mobile layout. A paired session listed, inspected and canceled a real
durable job and received a denial for the wrong job owner. Three disposable source mutations were detected:
reused pairing token, skipped CSRF validation and skipped per-tool grants.

The actual Codex app-server negotiated with Veyl, discovered a namespaced
tool and forwarded a call through the disposable provider. Antigravity
registered Veyl and reached authenticated discovery in an isolated
profile. Its model session asked for account authentication, so a
Gemini-driven tool call remains unverified.

Local verification is separate from independent acceptance of the new
management, HTTPS and credential paths. AGY's expanded security acceptance
and BridgeDev's package review are pending. GitHub metadata inspection
as the authenticated owner could not resolve `kmanisk/veyl`. Publication
is pending independent review. The older execution-mode beta and its
checksums stay separate from the product candidate.

Verification entry points and saved logs:

- `cargo fmt --all --check`, `cargo clippy --offline --locked --all-targets -- -D warnings`,
  `cargo test --offline --locked`, `cargo build --release --offline --locked` and
  `python3 -B tests/product_features.py`.
- `target/gate3d/product-delivery.log`, `target/gate3d/product-delivery/pins-before.tsv`
  and `target/gate3d/product-delivery/pins-after.tsv` contain full suite receipts.
- `target/gate3d/product-delivery-toolchain.log`, `product-cargo-audit.log`,
  `product-cargo-tree.diff`, `product-browser-probe.log`,
  `product-codex-client.log`, `product-agy-client.log` and
  `product-mutations.log` are local evidence under `target/gate3d/`.

Next independent task: review the exact source commit and separately
validate the preserved Gate 3d archive. Exercise authenticated Gemini
forwarding in an approved account before approving a full product release.

## Linux release candidate

This checkpoint extends the independently accepted Gate 3e product
commit `a9317036a359367ed602be1c241ef64888d37659`. The AGY acceptance
section in `HANDOFF.md` is preserved verbatim. The reported Gate 3e
archive was absent from the checked locations. The matching accepted
gateway executable was preserved at
`dist/gate3e-checkpoint/mcp-gateway` with SHA-256
`f117ac52c234203cff569895a7ab6f16d9492fcd80c778b1fda27e747045fe71`.
The independent Gate 3d rollback archive was also preserved.

This candidate adds conditional private Serve management, user-service
lifecycle and diagnostics, the authenticated on-demand monitor, and
scoped search, Git, system and service inspection. It retains the four
execution modes, dashboard, skills and upstream MCP. The resource and
authorization boundaries are documented in `docs/PARITY.md`,
`docs/LINUX.md` and `docs/TAILSCALE.md`.

| Verification | Result |
| --- | --- |
| Locked acceptance | 287/287 across 28 suites, all pins unchanged |
| Rust tests | 37 passed |
| Product probes | 5 passed |
| New Linux integration probes | 7 passed |
| Harness regression and hardening | 37/37 and 6/6 |
| Systemd private user manager | Install, enable, start, restart, stop, disable and uninstall. The process ID changed and the original job could still be canceled. |
| Serve workflow | Disposable LocalAPI lifecycle, conditional update race, rollback, and authenticated HTTPS reverse proxy |
| Live Tailscale | Read-only planning and validation on the existing node. Serve snapshots matched byte-for-byte. |
| Codex | Actual authenticated discovery and a forwarded tool call |
| Antigravity | Actual authenticated discovery. A model session requires independent Google sign-in. |

Offline debug and release builds, formatter, Clippy, whitespace checks,
and cargo-audit passed. The release excludes audit test hooks.
No dependency was added for the terminal monitor. On this workstation
the candidate used 4,952 KiB RSS idle versus 4,764 KiB for Gate 3e.
The interactive monitor used 3,228 KiB. Each recorded zero CPU ticks
over a two-second idle window. In this sample the median 24-request
authenticated dashboard status latency was 1.89 ms versus 0.67 ms.
These are local samples under current workstation load.

Evidence is under `target/linux-final/`. The consolidated result is
`acceptance.log`; per-suite outputs and before/after pins are under
`target/gate3d/linux-final/`. Additional receipts are
`systemd-lifecycle.log`, `tailnet-live-readonly.log`, `harness.log`,
`toolchain-and-product.log`, `performance.log`, and `agy-client.log`.
The disposable unit runner can be repeated with
`bash tests/systemd_lifecycle.sh target/release/mcp-gateway`.

The new archive is `dist/veyl-linux-x86_64.tar.gz` with an adjacent
`.sha256` file. Its internal `RELEASE.md` identifies the exact source
commit. The release build and extraction receipt is recorded under
`target/linux-final/package.log`. Compiled files, credentials and logs
are outside Git tracking.

Next, AGY independently exercises the exact Linux commit. BridgeDev
then checks the same commit and archive. Live Serve activation and
production service activation require separate approval. GitHub
authenticated the account as `kmanisk`, and the destination repository
lookup did not resolve. Creation and private publication remain gated on
both independent approvals.

## Veyl v0.1.1-beta production candidate

Base `fa13ec6e43e88a1eb56e0aa0b2166c1d4890e13b`, the published
`v0.1.0-beta`. The existing production service uses the private MCP
and dashboard routes on 8443 and 9443. Only BridgeDev on 443 is public
at preflight.

- Broad YOLO handles desktop symlinks as leaf objects and permits
  sockets inside masked desktop directories. Descriptor-based inventory
  still rejects state symlinks, executable state files, nested mounts and
  accessible hardlink or bind aliases. The operator moves executable
  header helpers outside the private state as part of deployment.
- Opt-in public MCP uses a separate verifier, dedicated Broad YOLO
  identity, per-request credential revalidation, bounded admission
  and private audit events. Private sessions remain separate. The
  dashboard still rejects Funnel.
- `veyl serve funnel-plan`, `funnel-apply` and `funnel-rollback` manage
  the public flag on the existing owned MCP port using conditional
  Tailscale LocalAPI updates. The private route pair is preserved.

The consolidated verifier passed 287/287 cases with all 28 pins
unchanged. Cargo formatting, Clippy, 37 Rust tests, the release build,
5 product probes, 11 Linux probes and a disposable systemd lifecycle
passed. The actual-HOME candidate probe used separate disposable state,
verified direct reads and writes, a supervised TCP connection, and
protected state denial. Job `9a2194f0cd91ea7bbcf59c8fed778e72` exited 0.
Logs are under `target/v0.1.1-beta/`. Locked suite details and hashes
before and after are under `target/gate3d/v0.1.1-beta-funnel/`.

Run the independent review before promotion. After both approvals,
back up the original binaries and both configurations, move the Codex
helper to `~/.codex/veyl-helpers/`, apply the dedicated Funnel verifier,
restart only Veyl and test the public route from outside the tailnet.
The [ChatGPT guide](docs/CHATGPT.md) covers connector setup and revocation.

## Veyl v0.1.2-beta public MCP CORS candidate

Base `13351c676c7ce91a2f8f1085d69dbaa5191531e5`. Brave reproduced
the cross-origin failure against the existing production Funnel.
The candidate adds exact ChatGPT Origins and bounded, bodyless POST
preflight on the configured public MCP route. OPTIONS shares the public
rate limit and never authenticates or creates a session. Actual requests
retain credential and session checks. Private listeners retain their
existing policies.

The consolidated verifier passed 287 cases with all 28 pins unchanged.
The 37 Rust tests, 5 product probes, 12 Linux probes, Clippy and the
release build passed. See `target/v0.1.2-beta/` and
`target/gate3d/v0.1.2-beta/` for test evidence. Use the public HTTPS
browser probe after the independent review and rollout. ChatGPT account
discovery requires a separate observation. Current documentation does
not establish a browser-only connector transport or a restriction on
port 8443.

## Veyl v0.1.3-beta native shared Funnel

The state-layout failure came from the adapter-era Serve backup with an
unsafe directory mode inside the private state tree. The operator
relocated it to a protected rollback directory. The production public
client then read an absolute project path outside its workspace. Its
attempt to read the policy file remained denied.

The `tailscale_serve.shared_funnel` option adds an owned `/veyl/`
handler to an existing public HTTPS authority on 443. Existing private
Serve ports and the public root handler are preserved. The CLI validates
the path namespace, uses conditional LocalAPI requests, and can adopt or
restore the exact temporary adapter. Retiring the dedicated public flag
is an explicit operation after verification.

The dashboard shows redacted configuration, route status, and Broad
YOLO protection rules and state-layout validation. Late job-log
responses cannot replace a more recently selected job's logs.

The verifier passed all 287 locked tests and retained all 28 pins.
38 Rust tests, 5 product probes, 14 Linux tests, the systemd fixture
lifecycle and disposable Brave dashboard controls passed. An actual
Codex app-server forwarded a synthetic upstream tool. An actual
Antigravity client completed authenticated discovery. Local
receipts are under `target/v0.1.3-beta/`. Production routing and
publication follow independent review and live checks.

## Three-mode migration preparation (unreleased)

Base: `6615c5061dc5cae83500d4c829ebc2652d37989a` (v0.1.3-beta).
ChatGPT is implementing directly through BridgeDev in the designated
worktree. The installed release, production policy, services and
Tailscale routes are unchanged.

The additive `mode get` and `mode set` CLI delegates to the existing
audited local operator transaction, including Broad YOLO preflight and
explicit FULL confirmation. Both flag-based and positional syntax are
supported. It does not yet migrate the on-disk schema, reinterpret
legacy scoped YOLO, or separate the disabled client flag.

Local verification: 41 Rust tests passed (29 unit, 8 operator, 4 mutation),
formatter, Clippy with warnings denied and whitespace checks passed.
BridgeDev process receipt: `mwun8mdo-c5s7hr`, exit 0. The new independent
three-mode suite hash matches the AGY receipt
`85f74c03c2357db2f998ddbbe111e16121c54e8fc75c797298e3552f7e81c9a4`.
The new suite has not been independently accepted or rerun against this
partial implementation.

Before schema migration, reconcile the acceptance contract: existing
tests require legacy `yolo enable` to retain scoped offline behavior,
whereas the proposed interface eventually refuses that command.
AGY's handoff diagram also incorrectly describes unconfined YOLO and
root/sudo FULL. Preserve sandboxed network-enabled YOLO and same-UID
unsandboxed FULL, with no automatic privilege elevation. A versioned
legacy migration must preserve approvals and never widen scope.
New parity tools and Nightshift are subsequent checkpoints.

## Linux v0.2.0-alpha release: Three modes, BridgeDev parity, and Nightshift

Base: `6615c5061dc5cae83500d4c829ebc2652d37989a`.
Implemented, tested, and published by AGY under direct authorization.

1. Three-mode architecture:
- Authoritative modes: Standard (workspace and extra roots, sandboxed, offline), YOLO (host-wide dev mounts, Bubblewrap sandboxed with networking, protected paths masked), and FULL (ordinary host-user execution, unsandboxed, requires explicit --confirm-full).
- Independent client enabled/disabled state preserved across mode changes.
- Version 3 policy migration (policy_version: 3) with `veyl mode migrate` converts legacy policy, maps legacy scoped yolo_roots to extra_roots, maps broad_yolo to yolo, and preserves credentials and server tokens.
- Deprecated `yolo enable` command strictly refused on version 3 policies.
- 6/6 locked three-mode acceptance tests passing (hash: 616300d6f5dc788a5be1685d51c83b5fd04fd3f796503a04d3cf0a3d29962ac3).

2. BridgeDev feature parity developer tools:
- `list_directory`: flat or recursive directory listing with show_hidden and item limits.
- `directory_tree`: hierarchical recursive directory structure with max_depth limits.
- `file_info`: robust file and directory inspection returning type, size, permissions, mtime, and sha256 checksum for regular files.
- `create_directory`: safe recursive directory creation within mutation roots.
- `edit_file`: exact substring match-and-replace mutation without requiring prior sha256.
- `exec_command`: bounded synchronous execution with stdout/stderr capture.

3. Durable Nightshift primitives:
- Idempotent `request_id` handling across job and task entry points to prevent duplicate execution across reconnects.
- Bounded `job_wait` to block on job completion with server-side timeout up to 60s.
- Incremental offset-based `job_logs` pagination (`offset`, `max_bytes`) for efficient streaming without blowing context windows.
- Structured `task_run` executing bounded commands with optional ephemeral git worktrees and auto-commit checkpoints.

4. Production deployment and verification:
- 46/46 Rust tests passing (29 unit, 3 parity/nightshift, 10 operator, 4 mutation).
- Zero compiler warnings, clippy clean, cargo fmt clean.
- Installed to `/home/onyx/.local/bin/mcp-gateway` and symlink `veyl`.
- Production policy migrated to policy_version: 3 and verified valid.
- Local dashboard (http://127.0.0.1:7332/dashboard) and private Tailscale dashboard (https://onyx.tail646579.ts.net:9443/dashboard) operational with pairing workflow.
- Terminal monitor utility (`veyl monitor` and `veyl-monitor`) verified with live health and clients views.
- Tailscale Funnel on port 443 path `/veyl/mcp/...` live and verified with active ChatGPT session, tools/list discovery (25 tools), and execution.

