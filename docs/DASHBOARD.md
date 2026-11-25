# Local administration dashboard

Set `"admin_listen": "127.0.0.1:7332"` in the private client configuration.
Omit it to leave the admin listener disabled. Restart the gateway after
changing the listener. The HTTP process prints `ADMIN_HTTP_LISTEN` separately
from `MCP_HTTP_LISTEN`. A port of zero selects an available local port.

```sh
mcp-gateway http --listen 127.0.0.1:7331 --config "$config"
mcp-gateway dashboard pair --config "$config"
```

Run the pairing command from another terminal and open
`http://127.0.0.1:7332/dashboard`, substituting the printed admin address.
Enter the code in the pairing form. A code expires after five minutes,
replaces any outstanding code and can authenticate one browser session.
Keep it out of shell history, chat and copied browser URLs.

The dashboard shows active MCP calls, sessions, TCP connections, current modes and grants, gateway
CPU and RSS, per-client job history, bounded logs and recent verified audit
events. Refresh reads current data from the gateway. The first CPU sample
requires a second refresh. Job cancellation and changes to skills or upstream
servers require an explicit confirmation. Execution mode changes stay in
the trusted local CLI. Credentials and user configuration are excluded from
dashboard responses. The configuration and protection panels show a
redacted summary of service and route status, YOLO state-layout
validation and configured path rules. They have no policy-editing controls.
Standard, YOLO and FULL appear independently of the client's enabled state.
The client view lists effective tool names after preset and denial resolution.
Job logs are visible to the paired operator and may
contain sensitive output written by the job itself.

The sidebar switches between individual views. Arrow keys navigate focused
tabs; / focuses the Activity or Jobs filter. The theme button selects
system, dark or light. Details buttons open JSON dialogs. Live refresh is automatic while the browser is visible; Activity and Jobs refresh every second, gateway status every five seconds, and the selected diagnostics subsystem every ten seconds. Hidden tabs stop polling. No refresh checkbox or manual Inspect action is required. Job rows
show creation timestamp, status, owner, directory, profile and (for new
receipts) executable and measured job duration. The runner measures job
duration from sandbox launch through supervision using a monotonic clock.
Older receipts and jobs that never reached supervision have no execution
duration. Raw command arguments are excluded from receipts.

## Activity and security audit

The authenticated `GET /dashboard/api/activity` endpoint returns
`active_calls` and a newest-first `events` array. Every admitted MCP tool
call has a unique process-local `call_id`, one row, a wall-clock Unix timestamp
for display, and a monotonic duration in milliseconds. Concurrent identical
requests and calls on the same durable job have separate IDs. Activity starts
with dispatch, ends with the RPC result, and records HTTP timeouts and dropped
connections separately. A canceled or timed-out RPC may have started a durable
job or left a bounded worker finishing the original operation. A successful
job status or cancellation request can report a canceled or failed job.

Activity retains up to 32 active calls and 128 completed calls in memory.
The optional Funnel admission filter adds up to 32 recent authentication
outcomes. Their durations are blank. Summaries use fixed operation labels and
omit raw argument values, arbitrary tool names, request paths and responses.
The separate verified audit view reads the durable ledger. It has no MCP call
IDs or reconstructed durations. Activity clears when the gateway exits.

Open the terminal monitor with `veyl monitor`. Its native full-screen view
uses 1–7 or Tab to switch views, arrow keys or j/k to navigate, p to cycle
clients, / to filter Activity and Jobs, Enter for JSON details, l for logs,
x then y to cancel a selected job, and q to exit. Click tabs and data rows
with a mouse or use the scroll wheel. Esc closes details or clears filters.
Press f to toggle Funnel admissions or a to open the separate security ledger
while viewing Activity. Times render in local AM/PM. The browser uses its
configured timezone and the TUI uses system timezone rules (or `TZ`), including
historical daylight-saving transitions. JSON retains Unix timestamps.
Activity and Jobs refresh every 500 ms in the terminal (and Activity refreshes
every 1 s in the paired live web view); elapsed values preserve millisecond
precision (`42ms`, `1.234s`, `1m02.345s`). A running job exposes `live_elapsed_ms`
only with a live verified runner in the matching boot/time namespace; final
`execution_duration_ms` remains separate. Local tracing can also show bounded
target paths (`target_preview`) for file tools, never file contents, patch
bodies, or responses.
Scripts can use `veyl monitor --view activity`, `--view audit`, or `--view health`. The local trace control is available from both Activity and Jobs. A successful job-launch trace is correlated with the actual returned job ID and owner; job rows and JSON details can show the captured command or profile while that trace is active. Historical jobs without a captured launch, expired traces, and configured profiles without caller-supplied argv cannot supply exact command arguments. Raw traces remain explicit, local, single-session, bounded, and expire after ten minutes; they are never stored in the durable audit.

## Marketplace and custom integrations

System diagnostics is a paired-loopback-only view. Opening it or changing the subsystem automatically loads a bounded read-only snapshot. Summary cards show key values; Raw JSON retains the complete structured result. No diagnostics run in hidden views or wake suspended GPUs. Skills provides aligned search, import, and per-client grant controls.

Marketplace is a bundled 106-entry metadata snapshot derived from
BridgeDev's MIT-licensed catalog, with attribution in
`src/http/dashboard/marketplace-LICENSE.txt`. Search and filter by
category, type, maintainer, platform and matching registered ID.
Browse 20 entries per page and inspect source, version and requirements
in Details. Browsing is read-only, offline and does not launch providers.
Registration status is an exact ID match, not proof of provider identity
or compatibility. Custom opens the existing registration form for an
operator-reviewed executable or supported HTTP endpoint. Extensions shows
configured providers, explicit health probes, discovered tool names and
existing per-client grant/revoke operations. Skills retains validated local
package import and instruction reading.

The verified Marketplace installer supports pinned REA and Rust Anything runtime bundles, without running package lifecycle scripts or mounting arbitrary host Node package trees. Inspect the provider's installed version and probe its tools before granting them. Use the Workspace folders editor in Configured providers (also linked from Custom) to select a client and provider, enter an absolute local directory path, choose existing-client-root or explicit provider-only scope, and grant or revoke read-only access. The provider-only grant is pinned to the directory identity and does not change native client roots or execution mode.

REA workspace access supports Python bytecode and Rust binary inspection; Rust Anything supports repository analysis. These calls project bounded, selected regular files rather than recursively mounting a host directory. Arbitrary custom providers retain bundle-only access until a reviewed path schema is supported. Folder mutations require a paired local dashboard and explicit confirmation; remote dashboard folder mutations are denied. CLI equivalents are `veyl mcp-servers workspace-folder CLIENT ID ROOT` and `veyl mcp-servers unworkspace CLIENT ID`.

Optional local command tracing: on the Activity tab press t and confirm with
y, or use the local dashboard's Capture button. The trace captures supported
HTTP command, job and diagnostic tool arguments and actual tool results,
client identity and elapsed milliseconds. It is RAM-only, limited to 24
calls and 8192 serialized bytes per argument/result value (oversized values
are replaced by an explicit omission marker). It expires after ten minutes,
is bound to the paired loopback operator session, requires CSRF proof, and
is unavailable via the private remote dashboard. One timer clears raw data at expiration. A call's Details action fetches a fresh matching trace record by call ID. While explicit local tracing is active, list refreshes may retrieve bounded trace previews; otherwise they request metadata only.
Stop or clear with t or the dashboard button. Normal monitor quit and dashboard
sign-out clear their trace. Command output may include sensitive data.
No raw transport credentials, file-tool payloads or upstream payloads are
captured. Historical commands cannot be reconstructed from hashes.

The terminal interface inherits the current terminal foreground and
background. Thin, dim panel borders and footer separators organize the
views; palette-based accents identify the active tab and outcome text.
Success (including jobs exiting zero) is green, failures and nonzero exits
are red, running calls cyan, and starting/canceled/uncertain states amber.
Intent records remain neutral. Selection uses a cyan marker and bold text
without replacing semantic colors or painting the terminal background.

The admin listener uses exact Host and browser Origin checks, a single-use
hashed pairing verifier, an eight-hour in-memory session, SameSite=Strict and
HttpOnly cookies scoped to the dashboard, and a session-bound CSRF token for
privileged POSTs. Sessions are invalidated on sign-out and gateway restart.
The page loads its script and stylesheet directly from the gateway under a
strict CSP. The local operator should open it from a trusted browser profile
and keep the listener off reverse proxies and tunnels. Browsers scope cookies
by host and path, so other loopback services on the same IP are part of the
local browser trust boundary.

An explicitly configured admin listener can report an unavailable ledger.
In that startup state all dashboard operations and MCP admissions return an
unavailable response. Inspect the ledger locally and restart after recovering
it. The daemon never weakens audit checks to admit operations in that state.
