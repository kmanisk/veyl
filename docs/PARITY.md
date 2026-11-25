# BridgeDev capability comparison

## 0.3.0-beta candidate scope

The six-domain planning score remains approximately 86%, not 100%. Includes the real runtime bundle extension probes (REA, Rust Anything and a custom Node MCP provider), compact live TUI status, and a verified fix for disconnected FUSE siblings disrupting Broad YOLO. TimeShift and autonomous Nightshift remain unimplemented. The new version number does not imply final parity.

## 86% functional parity milestone candidate (`parity-86`, 2026-11-25)

Candidate `/home/onyx/.local/share/veyl-development/candidates/parity-86.hjODQIAS/source`
(branch `dev/parity-86`, base `0e2cf55`, version `0.2.5-beta`) completes all
six non-Nightshift functional domains against BridgeDev:

- Six of seven functional domains are implemented (6/7 = 85.7%, ~86%
  functional parity); only autonomous Nightshift orchestration and pre-edit
  `rewind` checkpoints remain unimplemented (14.3%), alongside intentional
  fail-closed differences (no remote package auto-install; explicit per-tool
  grants for mutations, interactive processes, and upstream probing).
- Native tool surface expands from 28 to 68 native MCP tools (plus verified
  native updater `veyl update` / `--recover`).

| Domain | BridgeDev reference (`bridge-dev/src/`) | Veyl candidate (`parity-86`) | Status & intentional difference |
| --- | --- | --- | --- |
| 1. Confined file tools & directory tree | `filesystem.ts`, `safe-edit.ts`, `patch.ts` | IMPLEMENTED (`read_file`, `write_file`, `apply_patch`, `edit_file`, `file_info`, `list_directory`, `directory_tree`, `create_directory`, `search_files`, read-only `chezmoi_inspect`) | Rewind checkpoint history excluded with domain 5 (Nightshift/rewind). |
| 2. Persistent shell & process supervision | `shell.ts`, `persistent-shell.ts` | IMPLEMENTED (`process_start` pipe & kernel PTY, `process_input`, `process_resize`, `shell_status`, `shell_reset`, `job_status`, `job_logs` utf8/base64, `job_wait`, `job_cancel`, `cancel_job`, `list_jobs`, `exec_command`, `run_command`, `start_job`, `job_start`) | Explicitly granted profiles and HMAC-authenticated Unix datagram peer proofs; no unconfigured arbitrary host shell spawn. |
| 3. Structured Git workflows | `git.ts` (12 operations + worktrees) | IMPLEMENTED (`git_inspect`, `git_status`, `git_diff`, `git_log`, `git_add`, `git_commit`, `git_branch`, `git_checkout`, `git_restore`, `git_stash`, `git_reset`, `git_pull`, `git_push`, `task_run` `ephemeral_worktree: true`) | Hardened Bubblewrap git worker (`core.hooksPath=/dev/null`, RO `.git/hooks`, config masking on RO tools, explicit `confirm: true` for destructive/network ops). |
| 4. Durable execution & task budgets | `jobs.ts` (budgets up to 86400s), retries, recovery | IMPLEMENTED (`job_runtime_limit_seconds` up to 86400s, `cpu_percent` 10..1600, `memory_bytes` 16 MiB..16 GiB, `max_output_bytes` up to 16 MiB, `job_retention_count`, atomic `request_id` idempotency, cancellation, recovery) | Managed systemd user scope + signed receipts; no leased root `host-controller`. |
| 5. Nightshift & checkpoints/rewind | `checkpoint.ts`, `rewind.ts`, `ponytail.ts` | NOT IMPLEMENTED as orchestration (`task_run` + `job_wait` + `tests/bridgedev_parity_and_nightshift.rs` cover primitives only) | Final 1/7 domain (~14.3%): autonomous multi-iteration Nightshift loops and pre-edit `rewind` store remain out of scope here. |
| 6. System & context inspection | `system.ts`, `system-inspect.ts`, `context.ts`, `chezmoi.ts` | IMPLEMENTED (`system_info`, `system_inspect` 10 subsystems including `processes`, `network` TX/RX rates, wake-safe GPU/`nvidia_telemetry`, `service_status`, `project_context`, `system_context`, `load_path_rules`, `remember`, `chezmoi_inspect`, `list_skills`, `load_skill`, `skills_list`, `skills_read`) | Descriptor-pinned workspace traversal (`openat2`), zero env/cmdline scraping, and strict runtime PM active check before invoking `nvidia-smi`. |
| 7. Extensions, marketplace & preview | `extensions.ts`, `marketplace.ts` | IMPLEMENTED (`extensions_list`, `extensions_info`, `extensions_search`, `skills_validate`, `mcp_list`, `mcp_status`, `mcp_info` with SHA-256 `provider_fingerprint`, `mcp_test`, 8 inert `*_propose_*` tools, `/api/dashboard/requests`, live-reload `tests/dashboard_preview.py`) | Proposals are strictly inert JSON records (`0600`) in state `proposals/` awaiting operator review; remote auto-download/install omitted by design. |

Measured release resource & latency telemetry (`/home/onyx/Projects/veyl/target/release/mcp-gateway`, 7.4 MiB):
- Idle RSS: `6348` KiB (`6464` KiB after 20 `read_file` calls)
- Idle CPU over 1.0 s: `0` ticks
- Authenticated HTTP MCP `read_file` median latency: `0.164 ms` (`p95 = 0.324 ms`)

## Persistent process candidate (2026-11-25)

The isolated candidate adds explicitly granted `process_start`,
`process_input` and `shell_reset` with pipe and kernel PTY profiles. Existing
owner-scoped `job_status`, `job_logs`, `list_jobs` and `job_cancel` provide
inspection, incremental output, listing and termination. Sessions retain shell
state and reconnect to their signed job across a gateway restart. Managed
profiles support explicit budgets up to 24 hours. This is verified candidate
functionality and awaits personal and independent acceptance.

BridgeDev's `run_command` keeps an implicit working directory and its
`shell_status` shows command history. Veyl names sessions by job ID and
keeps actual process state. One-shot commands stay one-shot. Veyl retains
signed history rather than providing a `clear_processes` equivalent. FULL
interactive sessions, binary terminal streaming, terminal resizing and leased
root operations remain outside this checkpoint. See
[Process sessions](development/PROCESS_SESSIONS.md) for the verification and
the interface. The table below describes the historical baseline.

## Planning score (2026-11-25)

BridgeDev is the 100% comparison reference. With seven equally weighted
functional domains below, one implemented, five partial (half credit), and
one missing gives Veyl 50% approximate planning parity. This is not an
acceptance score; the separate tool-count ratio is 28/52 (53.8%). Aliases,
security differences and workflow depth make tool counts non-equivalent.
TUI/preview corrections do not increase core functional parity. Next focus:
persistent owned processes, long-running jobs, Git operations and Nightshift.

## v0.2.5-beta (checkpoint `7c2db86`) — verified parity & remaining gaps

Compared current Veyl (`/home/onyx/Projects/veyl`, `7c2db86`) against BridgeDev
(`/home/onyx/Projects/bridge-dev`). Veyl exposes 28 native MCP tools under
Broad YOLO with jobs+skills (`apply_patch`, `cancel_job`, `create_directory`,
`directory_tree`, `edit_file`, `exec_command`, `file_info`, `git_inspect`,
`job_cancel`, `job_logs`, `job_start`, `job_status`, `job_wait`,
`list_directory`, `list_jobs`, `project_context`, `read_file`, `run_command`,
`search_files`, `service_status`, `skills_list`, `skills_read`, `start_job`,
`system_context`, `system_info`, `system_inspect`, `task_run`, `write_file`) and
9 `system_inspect` subsystems (`resources`, `gpu`, `storage`, `network`, `audio`,
`bluetooth`, `desktop`, `sway`, `services`), all verified in `target/agy-7c2db86-tui.log`.

| Domain | BridgeDev reference (`bridge-dev/src/`) | Veyl status (`7c2db86`) | Remaining gap |
| --- | --- | --- | --- |
| Confined file tools & directory tree | `filesystem.ts`, `safe-edit.ts`, `patch.ts` | IMPLEMENTED (`read_file`, `write_file`, `apply_patch`, `edit_file`, `file_info`, `list_directory`, `directory_tree`, `create_directory`, `search_files`) | Hash-free `edit_file` vs BridgeDev chezmoi-guard (`chezmoi-guard.ts`) and automatic pre-edit file checkpoints (`checkpoint.ts`). |
| Persistent shell & process supervision | `shell.ts`, `persistent-shell.ts`, `global-shell-state.ts`: `run_command` (stateful cwd), `shell_status`, `shell_reset`, `start_process`, `process_status`, `process_output`, `stop_process`, `clear_processes` | PARTIAL (`exec_command`, `run_command`, `start_job`, `job_start`, `task_run`, `job_status`, `job_logs`, `job_wait`, `job_cancel`, `cancel_job`, `list_jobs`) | No persistent stateful shell session (`shell_status`, `shell_reset`, sticky `cwd` across calls) and no interactive background process API (`start_process` / `process_output` / `stop_process` / `clear_processes`); Veyl uses one-shot supervised jobs instead. |
| Structured Git workflows | `git.ts`: `git_status`, `git_diff`, `git_log`, `git_add`, `git_commit`, `git_branch`, `git_checkout`, `git_restore`, `git_push`, `git_pull`, `git_stash`, `git_reset` | PARTIAL (`git_inspect` read-only offline Bubblewrap snapshot for `info`/`status`/`diff`/`history`) | No discrete structured Git mutation/remote tools (`git_add`, `git_commit`, `git_branch`, `git_checkout`, `git_restore`, `git_stash`, `git_reset`, `git_pull`, `git_push`) or `ephemeral_worktree: true` execution (`task_run` rejects `ephemeral_worktree=true`). |
| Durable execution & task budgets | `jobs.ts` (`system_job` up to `86400s` via systemd), `host-controller.ts` (leased host-root up to `7200s`) | PARTIAL (signed Bubblewrap / FULL supervisor capped at `timeout_seconds: 300`, `live_elapsed_ms`, independent stdout/stderr cursors, `request_id` idempotency) | Maximum task timeout is 300s (no operator-approved multi-hour 2h–24h budget), no `node_repl`, and no host-controller lease equivalent outside `FULL` mode. |
| Nightshift & checkpoints/rewind | `checkpoint.ts`, `rewind.ts` (`rewind` list/preview/restore/status/clear), `ponytail.ts` | NOT IMPLEMENTED as orchestration (`task_run` + `job_wait` + `tests/bridgedev_parity_and_nightshift.rs` cover primitives only) | No pre-edit file checkpoint store, `rewind` rollback tool, or autonomous multi-iteration Nightshift orchestration / stall recovery. |
| System & context inspection | `system.ts`, `system-inspect.ts`, `context.ts` (`list_skills`, `load_skill`, `project_context`, `system_context`, `load_path_rules`, `remember`), `chezmoi.ts` (`chezmoi_inspect`) | PARTIAL (`system_info`, `system_inspect` 9 sections, `service_status`, `project_context`, `system_context`, `skills_list`, `skills_read`) | Missing `chezmoi_inspect` drift guard (source resolution, `.tmpl` & dirty Git checks), repo-local `.claude`/`.agents`/`.gemini` skill discovery, `load_path_rules`, and `remember` auto-memory. |
| Extensions, marketplace & preview | `extensions.ts` (`extensions_*`, `mcp_*`, `skills_validate`, `*_propose_*`), `marketplace.ts` | PARTIAL (106-entry bundled marketplace, custom upstream registration/probe/grants, `tests/dashboard_preview.py` auto-reload preview) | No MCP `extensions_propose_*` / `mcp_propose_*` / `skills_propose_*` proposal workflow tools, no `skills_validate` MCP tool, and no bundled package install/REA Node tree mounting. |

## v0.2.4-beta — production-verified capability checkpoint

The production gateway now runs the unified Standard/YOLO/FULL permission
model, sandbox-confined dynamic execution and task retries, independent log
cursors, live monotonic detached-job timing, and the corrected dashboard and
TUI. Live verification through Funnel and local administration confirmed
28 advertised native tools, structured diagnostics, protected-state masking,
durable task cancellation and command/file-target previews with explicit
local trace. ChatGPT's connector catalog still needs a discovery refresh
or investigation if it exposes fewer tools than the gateway advertises.
No claim of complete BridgeDev parity: interactive processes, longer task
budgets, structured Git mutations, optional integrations and autonomous
agent orchestration remain outstanding.

## Detached-job timing and target previews (verified integration)

Independently verified: cross-process monotonic live job timing (`live_elapsed_ms`
checked against boot ID, time namespace, and live runner identity), final
signed duration (`execution_duration_ms`), local trace file target previews
without file contents or patch bodies, and 500ms terminal job/activity refresh.
Extends the supervised durable job and streaming checkpoint; does not claim
persistent interactive shell, structured Git mutations, or autonomous multi-hour parity.


## Isolated durable execution and live monitor attempt

Independently verified: signed mode-confined ad-hoc commands (`exec_command`
and `task_run`), durable task IDs, atomic client-scoped retries (`request_id`)
with payload mismatch rejection, independent stdout/stderr byte cursors,
transient state rescan, isolated sandbox probing, and live TUI/web command
previews through opt-in local trace. The previous direct command path was removed.
Interactive persistent process sessions, authorized Git/worktree transactions,
multi-hour budgets, and autonomous Nightshift model loops remain open.
See `docs/development/STATUS.md` for evidence and limitations.


## Native context and subsystem checkpoint (local candidate)

Compared BridgeDev b21616a `src/tools/context.ts`, `src/tools/system.ts`,
`src/tools/chezmoi.ts`, and `src/lib/system-inspect.ts` to Veyl.
Added independently granted `project_context` and `system_context`.
They read a fixed Markdown allowlist through the granted workspace
descriptor, not arbitrary agent settings or host paths. Project context
supports bounded relative-directory traversal; system context reads four
known configuration documents from an explicitly granted workspace.
This is intentionally not BridgeDev's context-token admission protocol.
Live system inspection adds Sway outputs/workspaces, Pulse-compatible
audio sinks/sources, Bluetooth connected names, failed systemd units and
kernel pressure. Commands are fixed absolute executable paths, bounded,
on demand and read-only. A paired local dashboard has a subsystem inspector
and skill search/detail views. The existing 106-entry marketplace candidate
is included. No credential or grant changes on the production host.

Remaining: operator-configured cross-root system context, chezmoi/drift,
focused-window and detailed NVIDIA diagnostics without waking suspended
devices, general process sessions/Git workflows, package import/approval
and REA runtime compatibility, project skill discovery/instruction packs,
and persistent Nightshift agent orchestration. Durable job primitives
already exist; full overnight model-driven execution is not verified.

## Local marketplace candidate (unreleased)

Marketplace, Custom and Extensions views now support the bundled
BridgeDev metadata snapshot (106 entries), search, filters, paging,
configuration form prefilling, on-demand provider probes and existing
grant controls. Catalog registration matching does not certify identity,
installation or connectivity. REA example guidance tools are listed;
the actual disposable Veyl probe was unavailable. Automated package
installation, source proposal/approval workflows, instruction packs and
full BridgeDev provider parity remain unimplemented.

## v0.2.3-beta release additions

Veyl v0.2.3-beta establishes verified exact per-tool grant enforcement,
preventing tool discovery leakage where client configurations could observe
or invoke ungranted tool aliases sharing action permissions. Supervises
`job_start` argument validation to reject arbitrary caller `argv` on configured
profiles. Provides the concise operator CLI: `veyl mode <verb>` with automatic
single-client resolution and ambiguous multi-client rejection, `veyl ui` / `veyl dashboard`
browser launch, `veyl tui` / `veyl monitor` interactive terminal monitor, and
client-neutral `veyl setup --root "$PWD" --yolo`.

## v0.2.2-alpha candidate additions
The terminal monitor now offers live keyboard-controlled activity and job
views, and the dashboard uses individual sidebar tabs. Admin job rows
include creation time, cwd and profile. Existing scripts retain JSON.
The separately granted `system_inspect` tool reports bounded structured
resources, PCI GPU information, block devices, network interfaces, ALSA
cards, Bluetooth adapters, DRM connectors and Veyl service status.
It does not yet inspect live Sway, PipeWire, detailed NVIDIA telemetry,
general systemd units, chezmoi mappings or project/system context.
See STATUS.md for the actual candidate tests and deployment evidence.
The historical table below describes the earlier baseline.


This map uses the BridgeDev README and upstream-integration documentation
from a read-only review of checkout `b21616a`. It compares documented
capabilities and makes no claim of API or security compatibility.

| Capability | Veyl Linux status | Verification |
| --- | --- | --- |
| Confined file tools | IMPLEMENTED. Authenticated reads, writes and hash-guarded patches follow the client mode and scope. | Locked file tools, containment and mode suites. |
| Bounded file and content search | IMPLEMENTED. Literal path-name or UTF-8 content search stays within the primary client workspace. Links, protected paths and nested mounts are excluded. Entries, output and scan time are bounded. | Synthetic content matches, traversal denial, hardlink and symlink negative controls. |
| Git repository inspection, status, diff and history | IMPLEMENTED for bounded in-tree checkouts. A private snapshot runs fixed Git read operations in offline Bubblewrap. External configuration, hooks, filters, linked worktrees and host paths cannot widen it. | Real disposable Git commit and worktree edit, four authenticated read operations, and an injected local helper configuration. |
| General Git workflows | NOT IMPLEMENTED. The dedicated Git tool has no commits, merges, pushes or network operations. | Tool argument allowlist. |
| System resources | IMPLEMENTED. Linux CPU count, load and RAM, workspace filesystem capacity, process CPU/RSS and active MCP connections. | Authenticated resource probe and the live dashboard and monitor. |
| Process and durable job control | IMPLEMENTED within owned jobs. The supervisor reports state and bounded logs, handles termination and recovery, and preserves receipts across restart. | Durable-job suites, real service restart and terminal cancellation probe. |
| Arbitrary process or host administration | NOT IMPLEMENTED. The process surface remains tied to Veyl's job authority. | Owner checks and an explicit read-only service query. |
| Command modes | IMPLEMENTED. Standard limits access to approved workspaces, YOLO uses the native preset with a protected sandbox, and confirmed FULL uses host-user access. | Mode, sandbox and protected-path regressions. |
| Dashboard and terminal monitor | IMPLEMENTED. Both authenticate against the separate admin listener. The monitor offers interactive and one-shot views. | Isolated Brave, real PTY keys, API pairing, job logs and cancellation. |
| Upstream MCP management | IMPLEMENTED for supported stdio and Streamable HTTP/HTTPS targets. | Locked MCP suites, HTTPS and isolation probes, and a real Codex forwarded call. |
| Skills | IMPLEMENTED. Import, discovery and individual client grants expose validated instructions. | Locked skills suite and dashboard probes. |
| systemd user service | IMPLEMENTED. Explicit installation, lifecycle, status, validation and removal. | Actual private delegated systemd user manager, nested bus, restart and retained job receipt. |
| Tailscale private ingress | PARTIAL verification. Serve workflow, ownership and collision handling are implemented. Activation on this tailnet awaits separate approval. | Disposable LocalAPI, HTTPS reverse proxy and read-only live planning. |
| Root execution, Windows and Termux | NOT IMPLEMENTED. | Outside the Linux release scope. |

The new MCP grants are `search_files`, `git_inspect`, `system_info` and
`service_status`. They require durable audit intent and outcome records.
Workspace inspection stays inside the client's primary workspace in all modes.
Search accepts `query`, optional `path`, and `content`. Git accepts an optional
`path` and one `operation` from `info`, `status`, `diff` or `history`.
Git limits its snapshot to 64 MiB and 16,384 entries, history to 24 commits,
and command output to 64 KiB. Links and special entries are omitted and
counted. Oversized or incomplete snapshots fail explicitly. Service
inspection always refers to the one Veyl user unit.
# TimeShift checkpoint investigation (2026-11-25)

Rewind and autonomous Nightshift remain unimplemented. BridgeDev's `rewind`
interface offers list, status, preview, restore and clear, and excludes shell
changes. Veyl still needs a signed owner-scoped store and conflict-safe,
currently authorized restore. The existing advisory directory lock does not
exclude external writers, and pathname-based directory creation is not a safe
checkpoint primitive. No new parity percentage or preview is claimed.
