# BridgeDev capability comparison

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
| Command modes | IMPLEMENTED. Managed Standard, scoped YOLO, Broad YOLO and confirmed FULL are separate policies. | Locked mode, broad sandbox and protected-path cases. |
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
