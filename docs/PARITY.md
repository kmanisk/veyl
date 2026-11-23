# BridgeDev capability comparison

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
