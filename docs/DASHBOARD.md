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

The sidebar switches between individual views rather than scrolling through
all panels. Arrow keys navigate the focused tabs. Live refresh is optional
and runs only while the browser is open and visible, on the Health, Activity
and Jobs views. Job rows show creation timestamp, status, directory and
profile; raw command arguments are not retained in receipts.

Open the terminal monitor with `veyl monitor`. Its native full-screen view
uses 1–7 or Tab to switch views, arrow keys or j/k to navigate, p to cycle
clients, / to filter jobs, Enter/l for logs, x then y to cancel a selected job,
and q to exit. The monitor refreshes on demand while open. Scripts retain
one-shot JSON with `veyl monitor --view health`.

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
