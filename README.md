# <img src="assets/veyl.svg" width="36" height="36" alt=""> Veyl

A lightweight Rust MCP gateway for your Linux machine. Give ChatGPT, Codex
and other MCP clients access to your development workspace, supervised
commands, durable jobs, native diagnostics, skills and upstream MCP servers.

**Linux · Native Rust · Local or Tailscale · Web dashboard + terminal monitor**

## Install

Install the Linux beta from crates.io (no manual clone or symlink):

```sh
cargo install veyl --version 0.2.5-beta --locked --bin veyl --bin veyl-monitor
```

Veyl is open source under the MIT license. Source code and prebuilt Linux
binaries are available on GitHub, and the crate is available on crates.io.

Requires Linux, Bubblewrap (`bwrap`) and Git. Add Tailscale for remote
access and a systemd user session for persistent service mode.
Cargo's bin directory must be on PATH.

## Connect a remote client

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

## Dashboard and monitor

```sh
veyl ui
veyl tui
```

`veyl dashboard` is an alias for `veyl ui`, and `veyl monitor` is an alias
for `veyl tui`. Both pair automatically. The dashboard has sidebar views,
themes, structured diagnostics, and JSON detail dialogs. The terminal
monitor supports keyboard and mouse navigation, activity/job filtering,
Enter for JSON details, and l for job logs. Use t on Activity (or the
local dashboard's Capture button) for a bounded, temporary command/response trace.
The durable audit remains metadata-only.

## Daily use

Veyl v0.2.5-beta includes unified permission modes (`Standard`, `YOLO` with
native tool preset and `deny_tools`, `FULL` with confirmation), confined ad-hoc
and durable commands (`exec_command`, `task_run` with optional isolated worktrees),
persistent pipe/PTY sessions (`process_start`, `process_input`, `process_resize`,
`shell_status`, `shell_reset`), structured Git workflows, workspace context/rule/skill
helpers, independent `stdout`/`stderr` log cursors, and live local-timezone AM/PM
millisecond monitoring.

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
| `veyl mode yolo` | Select sandboxed developer access and the native tool preset |
| `veyl mode standard` | Select workspace-restricted access with explicit tool grants |
| `veyl mode full --confirm-full` | Select unsandboxed host-user execution |
| `veyl mode disable` | Disable client access |
| `veyl mode enable` | Restore client access |
| `veyl help` | Show commands |

Mode changes take effect at the next admission. Disabling a client preserves
its selected mode. Mode commands select the only configured client automatically
or prompt you to choose when several exist. Scripts must supply a client ID when
there is more than one. `veyl mode set CLIENT <mode>` is also supported.
See [execution modes and migration](docs/BROAD-YOLO.md) for existing policies,
explicit denials, and separate upstream MCP grants. Stop any foreground gateway
before starting the service.

## Documentation

[Linux and upgrades](docs/LINUX.md) · [Client setup](docs/CLIENTS.md) ·
[Dashboard](docs/DASHBOARD.md) · [Tailscale](docs/TAILSCALE.md) ·
[Skills](docs/SKILLS.md) · [Upstream MCP](docs/UPSTREAM-MCP.md) ·
[Execution modes](docs/BROAD-YOLO.md)

Veyl is a beta-stage Linux product. Core gateway functions, dashboards,
skills and durable jobs work; additional subsystem diagnostics, complete
BridgeDev parity and unattended multi-hour agent orchestration remain
under development. See [release notes](https://github.com/kmanisk/veyl/releases)
for version-specific verification and limitations.
