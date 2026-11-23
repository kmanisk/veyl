# BridgeDev capability comparison

This map uses the BridgeDev README and upstream-integration documentation
from a read-only review of checkout `b21616a`. It compares documented
capabilities and does not imply API, security, or drop-in compatibility.

| Capability | Rust MCP Gateway status |
| --- | --- |
| File tools | Implemented. Stdio has confined reads. Authenticated HTTP adds explicitly granted writes and hash-guarded patches. |
| Command execution | Implemented. Trusted configuration defines fixed profiles. Managed Standard and legacy YOLO run offline in Bubblewrap. Confirmed FULL executes with host-user authority. Broad network-enabled YOLO is pending. |
| Durable jobs and process control | Implemented. The supervisor tracks detached jobs, bounded logs, receipts, cancellation, deadlines, and process-tree cleanup. Arbitrary system process control is outside the current scope. |
| Git operations | Planned only as a separately specified capability. A trusted operator can configure a fixed local command profile when appropriate. |
| File and content search | Planned, pending bounded-query and path authorization acceptance. |
| System inspection | Partial. Audit status, user-unit status, and private-state checks exist. Host-wide metrics and inspection tools have no current acceptance contract. |
| Local dashboard | Planned. Separate loopback administration and pairing need independent acceptance. |
| MCP server management | Planned. Upstream discovery and forwarding need grants, transport isolation, and cleanup. |
| Skills | Planned. Instructions will have separate read grants and cannot authorize execution modes. |
| Service and ingress | Partial. The user-unit file lifecycle and read-only Serve planning are implemented. Live ingress and host installation are outside this release. |
| Root command execution | Outside scope. |
| Windows and Termux | Outside the current Linux verification scope. |

New capabilities require their own acceptance coverage. The monitor should
remain a separate process and build target so the core daemon has no TUI
dependency.
