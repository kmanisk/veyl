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

The dashboard shows MCP session and active TCP connection counts, current modes and grants, gateway
CPU and RSS, per-client job history, bounded logs and recent verified audit
events. Refresh reads current data from the gateway. The first CPU sample
requires a second refresh. Job cancellation and changes to skills or upstream
servers require an explicit confirmation. Execution mode changes stay in
the trusted local CLI. Credentials and user configuration are excluded from
dashboard responses. The configuration and protection panels show a
redacted summary of service and route status, Broad YOLO state-layout
validation and configured path rules. They have no policy-editing controls.
Job logs are visible to the paired operator and may
contain sensitive output written by the job itself.

The sidebar switches between individual views. Arrow keys navigate focused
tabs; / focuses the Activity or Jobs filter. The theme button selects
system, dark or light. Details buttons open JSON dialogs. Live refresh
is optional and runs on visible Health, Activity and Jobs views. Job rows
show creation timestamp, status, owner, directory, profile and (for new
receipts) executable. Raw command arguments are not retained in receipts.

Open the terminal monitor with `veyl monitor`. Its native full-screen view
uses 1–7 or Tab to switch views, arrow keys or j/k to navigate, p to cycle
clients, / to filter Activity and Jobs, Enter for JSON details, l for logs,
x then y to cancel a selected job, and q to exit. Click tabs and data rows
with a mouse or use the scroll wheel. Esc closes details or clears filters.
Activity timestamps are UTC; raw timestamps remain in the JSON record.
Scripts retain
one-shot JSON with `veyl monitor --view health`.

## Marketplace and custom integrations

System diagnostics is a paired-loopback-only view. Select a subsystem and
press Inspect to retrieve live JSON; nothing polls automatically. Skills
now provides name/description/status search, metadata details and a
document viewer alongside existing import and per-client grants.

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

REA is an example catalog entry, with three guidance tool names observed
on the existing BridgeDev installation. A disposable Veyl registration
of the installed REA launcher succeeded but probe health was unavailable;
no REA tools were discovered. The current isolated stdio transport does
not mount arbitrary Node package trees. Do not claim REA compatibility
until an independently tested provider transport is available.

Optional local command tracing: on the Activity tab press t and confirm with
y, or use the local dashboard's Capture button. The trace captures supported
HTTP command, job and diagnostic tool arguments and actual tool results,
client identity and elapsed milliseconds. It is RAM-only, limited to 24
calls and 8192 serialized bytes per argument/result value (oversized values
are replaced by an explicit omission marker). It expires after ten minutes,
is bound to the paired loopback operator session, requires CSRF proof, and
is unavailable via the private remote dashboard. Stop/clear with t or the
dashboard button. Normal monitor quit and dashboard sign-out clear their
trace. Command output may include sensitive data; enable only when needed.
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
