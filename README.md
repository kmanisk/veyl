# <img src="assets/veyl.svg" width="36" height="36" alt=""> Veyl

A lightweight Rust MCP gateway for your Linux machine. Give ChatGPT, Codex
and other MCP clients access to your development workspace, supervised
commands, durable jobs, native diagnostics, skills and upstream MCP servers.

**Linux · Native Rust · Local or Tailscale · Web dashboard + terminal monitor**

## Install

Install the Linux beta from [GitHub Releases](https://github.com/kmanisk/veyl/releases). Download the Linux x86_64 bundle and `SHA256SUMS` into a private folder, verify `sha256sum -c SHA256SUMS`, and use the **verified new bundle's** `/absolute/path/to/bundle/veyl update --from-dir /absolute/path/to/bundle` for an existing installation. The 0.6 audit checkpoint migration requires the new updater; an older updater cannot safely reverse the schema change and is refused before migration. Keep the verified bundle until completion and use its `veyl update --recover` for interrupted transactions. The updater restores a verified legacy checkpoint format only when the current chain extends the original prefix and the policy remains unchanged; it refuses incompatible new history instead of discarding records. Veyl builds and distributes a single executable, `veyl`. The terminal monitor runs as `veyl monitor` (or `veyl tui`) and the experimental foreground loopback connector runs as `veyl connector`. The updater migrates legacy `mcp-gateway` and `veyl-monitor` installations to relative compatibility symlinks pointing at `veyl`, preserving the existing generated systemd unit. For the first migration, use the verified new bundle executable, not the older installed updater. Keep the new bundle for interrupted recovery. Release assets consist of `veyl`, `SHA256SUMS`, and GitHub's automatic source archives. No duplicate source bundles or separate monitor/connector executables are needed. To install the checked-out source:

```sh
cargo install --path . --locked --bin veyl
```

Veyl is open source under the MIT license. Source code and prebuilt Linux
binaries are available on GitHub; see [crates.io](https://crates.io/crates/veyl) for published Cargo versions.

Requires Linux, Bubblewrap (`bwrap`) and Git. Add Tailscale for remote
access and a systemd user session for persistent service mode.
Cargo's bin directory must be on PATH.

## Connect a remote client — legacy bearer/secret-path compatibility

The commands below describe the legacy bearer/secret-path compatibility path.
For `0.7.0-beta`, prefer direct OAuth MCP over a public HTTPS
endpoint (see the OAuth section below). No Veyl-hosted account, relay or
standalone ChatGPT plugin is required by the direct architecture.

1. Sign in to Tailscale once. Enable HTTPS, MagicDNS and Funnel for your
   node, and allow your user to manage Serve routes.
2. From your chosen workspace, run:

```sh
veyl setup --root "$PWD" --yolo
```

3. Paste the copied private connector URL into ChatGPT's custom MCP
   connection form using direct HTTP and **No authentication**.

Veyl creates the configuration, starts the user service, configures
the Funnel route and opens the paired dashboard. The URL is itself a
credential. Keep it private. YOLO enables the native developer tool preset
and broad sandboxed access with protected paths excluded. See [ChatGPT setup](docs/CHATGPT.md)
for prerequisites and troubleshooting.

## Local only

```sh
veyl init --root "$PWD"
veyl run
```

Run the monitor or dashboard in another terminal. Ctrl+C stops the
foreground gateway. Tailscale and systemd are not required for this flow.

## Direct OAuth MCP (next-release candidate)

The client-independent remote interface is Streamable HTTP MCP with OAuth
DCR, authorization-code PKCE S256, local consent and explicit scoped tools.
Use the MCP connection settings of a compatible client; no separate plugin
package or hosted connector is needed. Linux is the implemented gateway host;
Windows and Android/Termux gateway ports are future work. A phone can connect
to a remote Linux gateway only if its chosen AI client supports the connection.
Actual ChatGPT, Claude and other client capability/plan support must be tested.

The simplest onboarding entry point uses one foreground command:

```sh
veyl login
```

`veyl login` guides interactive workspace selection (defaulting to the
current directory, or `--root DIR`), checks Tailscale MagicDNS/HTTPS/Funnel
prerequisites on port 8443 or 10000, starts an owner-private profile in
`~/.veyl-login/profile` defaulting new OAuth connections to **Standard**,
copies the HTTPS `/mcp` URL to your clipboard when available, and opens the
local dashboard (`--no-ui` suppresses browser launch). During local approval
in the dashboard you can keep **Standard** (default) or explicitly select
**YOLO** (native access as the gateway user, including Veyl state).

Manage persisted per-connection modes and disconnect remote clients locally:

```sh
veyl mode                          # list connected OAuth clients and modes
veyl mode yolo <CLIENT_ID> --confirm-native  # Reauthorize the remote client
veyl mode standard <CLIENT_ID>     # downgrade (denies elevated operations immediately)
veyl logout --client <CLIENT_ID>   # revoke one OAuth connection
veyl logout --all                  # revoke all managed OAuth connections and stop Funnel
```

For low-level manual Flag/Profile control (`veyl oauth setup/run`), choose a
non-sensitive workspace and new private profile:

```sh
veyl oauth setup --root "$PWD" --profile "$HOME/.veyl-oauth-preview" \
  --funnel --open-ui
```

Paste the emitted HTTPS `/mcp` URL into the client's custom MCP connection,
select OAuth with dynamic client registration, scope `mcp` and PKCE S256,
and review the exact grant in the local dashboard. Resume with the same
profile and `--funnel`; keep the issuer and selected capabilities unchanged.
Live external-client acceptance is still pending; see the release checklist
in [the direct remote plan](docs/development/DIRECT_REMOTE_PLAN.md).

### Local OAuth onboarding (development builds only)

For a separate, read-only local OAuth profile, choose an existing
workspace and a new absolute profile directory with an existing
owner-controlled parent:

```sh
veyl oauth setup --root "$PWD" --profile "$HOME/.veyl-oauth-preview" --open-ui
```

This initializes private state and starts an isolated foreground gateway.
No JSON, manually generated bearer, service install or tunnel setup is
required. The optional flag opens a paired local dashboard. Stop with
Ctrl+C; resume with:

```sh
veyl oauth run --profile "$HOME/.veyl-oauth-preview" --open-ui
```

Setup refuses to overwrite existing profiles; run refuses missing or
invalid authentication state. The OAuth connections tab supports local
review and explicit approval. Without `--funnel` this remains a local
preview with synthetic origin `https://veyl.example`. The explicit
`--workspace-edit` and `--workspace-tools` profiles add scoped editing
and bounded directory/search tools respectively; repeat the selected flag
on restart.

`--workspace-jobs` adds named, operator-approved
commands. Supply a private, owner-controlled JSON file on first setup:

```json
{"job_profiles":{"pwd":{"executable":"/usr/bin/pwd","args":[],"timeout_seconds":4}}}
```

```sh
veyl oauth setup --root "$PWD" --profile "$HOME/.veyl-oauth-jobs" \
  --workspace-jobs --job-profiles "$HOME/job-profiles.json" --open-ui
veyl oauth run --profile "$HOME/.veyl-oauth-jobs" --workspace-jobs --open-ui
```

Stop the foreground setup before running the recovery command. Job profiles
run in an offline Bubblewrap sandbox with a writable workspace and mandatory
systemd user resource ceilings. Only explicit named profiles or their exact
configured argv are accepted; arbitrary commands and interactive processes
are not granted. Local approval displays the exact profiles. Jobs retain
separate durable ownership per OAuth grant family. Revocation denies new
remote admissions; the local dashboard retains job cancellation and logs.
Public ingress additionally requires the explicit experimental `--funnel-advanced` gate described below.

For a new, explicitly opted-in job profile, add `--workspace-commands`
to both setup and run. This adds arbitrary `exec_command` and `task_run`
inside the offline, writable workspace sandbox (maximum 300 seconds,
100% CPU, 256 MiB RAM and 64 KiB output per stream). Commands use only
the approved workspace root; no alternate cwd, ephemeral Git worktrees,
or implicit interactive sessions. A command may return a
still-running durable job after the bounded two-second wait; use
`job_status` and `job_logs` to inspect it. Existing named-job profiles
cannot silently acquire this grant by adding the flag on restart.

For interactive pipe or PTY sessions on approved interactive job profiles,
add `--workspace-interactive` alongside `--workspace-jobs` on both setup and
run. This grants `process_start`, `process_input`, `process_resize`,
`shell_status` and `shell_reset` within the same offline writable workspace
sandbox and resource ceilings (maximum 300 seconds, 100% CPU, 256 MiB RAM,
64 KiB output per stream and 4096-byte UTF-8 input frames). Interactive
sessions are owned by each OAuth grant family, revalidated on both the gateway
and detached runner against durable OAuth state across token refresh, expiry,
revocation and gateway restart. Public ingress requires `--funnel-advanced`.

For trusted local upstream MCP servers, opt in with
`--workspace-upstreams --upstream-manifest /absolute/path/to/upstreams.json`
on setup and `--workspace-upstreams` on run. The manifest contains exactly
`mcp_servers` and `allowed_server_tools`, for example:

```json
{"mcp_servers":{"local":{"transport":"http","url":"http://127.0.0.1:8123/mcp"}},"allowed_server_tools":{"local":["hello"]}}
```

This is a configuration example, not a running provider. The operator
must already have a trusted MCP server at the configured endpoint.
Only explicit tool grants, credential-free loopback HTTP or offline
trusted system stdio are supported by this OAuth profile. Providers may
have side effects and share application state across OAuth families.
Public upstream grants require `--funnel-advanced` as well as the explicit provider manifest.

The development candidate also implements `--funnel` on setup and run:
it selects an authorized free dedicated Tailscale HTTPS port (8443 or
10000), optionally pinned with `--funnel-port`, and owns the route only
for the foreground IPN-bus session. Restart recovers the saved issuer;
it refuses to silently migrate to another hostname or port. The dashboard
remains private. This path has passed independent disposable LocalAPI and native OAuth
integration tests, including the full advanced host-tmpfs suite. A live
preview also passed HTTPS discovery from the gateway host; external client
OAuth and tool invocation remain unverified.
The separate `--funnel-advanced` flag is required with `--funnel` and any
explicit jobs or upstream capability group, both on setup and recovery. It
grants no tools by itself. Local consent includes the exact public scope
and warnings about workspace writes and shared upstream state. Scoped jobs
enforce CPU, memory, runtime, output, zero swap and at most 128 tasks.
Public workspace edits and jobs require the root of a private tmpfs mount
owned by the gateway UID (mode 0700, nosuid,nodev), no nested mounts,
at most 256 MiB and 16384 inodes. The gateway checks these kernel limits
during setup, recovery, consent, admission and detached job launch.
This is a volatile preview backend, not persistent project storage. Mount
provisioning is the operator's responsibility; Veyl never mounts or formats
a filesystem automatically. Upstream providers remain separately trusted
and their external side effects are not bounded by this workspace limit.
Independent local/simulated security acceptance has passed. Public use
still requires explicit operator approval and the live client acceptance
checklist. Do not reuse durable authorizations after recreating a tmpfs
mount; persistent quota backends and aggregate host quotas are not implemented.

The standalone ChatGPT Plugin Creator package and hosted connector are
deferred optional experiments, not runtime dependencies or release gates.
The existing package generator is retained for future use; no plugin
installation is required for direct MCP.
Direct OAuth MCP onboarding (`veyl login`, `veyl logout`), per-connection
Standard/YOLO mode selection, and interactive/upstream controls are included in
the `0.7.0-beta` release candidate.
See [the direct remote plan](docs/development/DIRECT_REMOTE_PLAN.md).

## Dashboard and monitor

```sh
veyl ui
veyl tui
```

`veyl dashboard` is an alias for `veyl ui`, and `veyl monitor` is an alias
for `veyl tui`. Both pair automatically. The dashboard has sidebar views,
themes, structured diagnostics, and JSON detail dialogs. The terminal
monitor supports keyboard and mouse navigation, activity/job filtering,
Enter for readable Activity command/target details (d toggles JSON), and l for job logs. Use t on Activity (or the
local dashboard's Capture button) for a bounded, temporary command/response trace.
The durable audit remains metadata-only.

## Upgrading to 0.7.0-beta

Keep the verified single-executable bundle for forward recovery. Policy
migration is an audited local step and disables latent native authority
for disabled clients. It requires a schema-4-compatible executable
afterward. See [execution modes and recovery](docs/BROAD-YOLO.md).

## Daily use

Veyl 0.4.0-beta adds opt-in native text checkpoint history, preview and guarded restore. See [TimeShift](https://github.com/kmanisk/veyl/blob/v0.4.0-beta/docs/development/TIMESHIFT.md).

Veyl has two permission modes. Standard uses explicit scoped grants and
Linux sandboxing. YOLO uses native host-user execution after local
confirmation. Both support durable commands (`exec_command`, `task_run` with optional isolated worktrees),
persistent pipe/PTY sessions (`process_start`, `process_input`, `process_resize`,
`shell_status`, `shell_reset`), structured Git workflows, workspace context/rule/skill
helpers, extension/upstream management with verified one-click marketplace runtime
bundle installation (`veyl marketplace`), read-only runtime bundles
(`veyl mcp-servers add-bundle`), explicit read-only provider workspace folders
(`veyl mcp-servers workspace-folder` and the local dashboard), independent `stdout`/`stderr` log cursors, and
live local-timezone AM/PM millisecond monitoring. TimeShift covers opt-in native UTF-8 writes and patches with signed per-client history, preview, guarded restore and retention. Shell, Git and binary changes are not captured; autonomous Nightshift orchestration remains unimplemented.

| Command | Action |
| --- | --- |
| `veyl ui` / `veyl dashboard` | Open the browser dashboard |
| `veyl tui` / `veyl monitor` | Open the terminal monitor |
| `veyl ui --remote` | Open the private Tailscale dashboard |
| `veyl connect` | Copy your existing connector URL |
| `veyl service on` | Start and enable the user service |
| `veyl service status` | Inspect the service |
| `veyl portable` | Switch from service to foreground |
| `veyl mode` | List client modes |
| `veyl mode get` | Show the selected client's mode and enabled state |
| `veyl mode yolo --confirm-native` | Authorize native host-user execution and applicable tools |
| `veyl mode standard` | Select workspace-restricted access with explicit tool grants |
| `veyl goal list` | List durable development goals |
| `veyl mode disable` | Disable client access |
| `veyl mode enable` | Restore client access |
| `veyl help` | Show commands |

Mode changes take effect at the next admission. Disabling a client revokes
its native grant. Mode commands select the only configured client automatically
or prompt you to choose when several exist. Scripts must supply a client ID when
there is more than one. `veyl mode set CLIENT <mode>` is also supported.
See [execution modes and migration](docs/BROAD-YOLO.md) for existing policies,
explicit denials, and separate upstream MCP grants. Stop any foreground gateway
before starting the service.

## Documentation

[Linux and upgrades](docs/LINUX.md) · [Client setup](docs/CLIENTS.md) ·
[Dashboard](docs/DASHBOARD.md) · [Tailscale](docs/TAILSCALE.md) ·
[Skills](docs/SKILLS.md) · [Upstream MCP](docs/UPSTREAM-MCP.md) ·
[Execution modes](docs/BROAD-YOLO.md) · [Durable goals](docs/GOALS.md)

Veyl is a beta-stage Linux product. Core gateway functions, dashboards,
skills and durable jobs work; additional subsystem diagnostics, complete
BridgeDev parity and unattended multi-hour agent orchestration remain
under development. See [release notes](https://github.com/kmanisk/veyl/releases)
for version-specific verification and limitations.
