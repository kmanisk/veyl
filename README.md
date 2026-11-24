# <img src="assets/veyl.svg" width="36" height="36" alt=""> Veyl

A lightweight Rust MCP gateway for your Linux machine. Give ChatGPT, Codex
and other MCP clients access to your development workspace, supervised
commands, durable jobs, native diagnostics, skills and upstream MCP servers.

**Linux · Native Rust · Local or Tailscale · Web dashboard + terminal monitor**

## Install

Install the Linux alpha from crates.io (no manual clone or symlink):

```sh
cargo install veyl --version 0.2.2-alpha --locked --bin veyl --bin veyl-monitor
```

The crate is licensed under MIT. The GitHub repository is currently private;
the crates.io package contains the installable source and user documentation.

Requires Linux, Bubblewrap (`bwrap`) and Git. Add Tailscale for remote
access and a systemd user session for persistent service mode.
Cargo's bin directory must be on PATH.

## Connect a remote client

1. Sign in to Tailscale once. Enable HTTPS, MagicDNS and Funnel for your
   node, and allow your user to manage Serve routes.
2. From your chosen workspace, run:

```sh
veyl setup --root "$PWD" --chatgpt-yolo
```

3. Paste the copied private connector URL into ChatGPT's custom MCP
   connection form using direct HTTP and **No authentication**.

Veyl creates the configuration, starts the user service, configures
the Funnel route and opens the paired dashboard. The URL is itself a
credential. Keep it private. YOLO enables host-wide developer access
with protected paths excluded. See [ChatGPT setup](docs/CHATGPT.md)
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
veyl monitor
```

Both pair automatically. The dashboard has sidebar views, themes and JSON
detail dialogs. The terminal monitor supports keyboard and mouse navigation,
activity/job filtering, Enter for JSON details and l for job logs.
Use t on Activity (or the local dashboard's Capture button) for a bounded,
temporary command/response trace. The durable audit remains metadata-only.

## Daily use

| Command | Action |
| --- | --- |
| `veyl ui --remote` | Open the private Tailscale dashboard |
| `veyl connect` | Recopy your existing connector URL |
| `veyl service on` | Start and enable the user service |
| `veyl service status` | Inspect the service |
| `veyl portable` | Switch from service to foreground |
| `veyl mode set CLIENT yolo` | Persistent YOLO |
| `veyl mode set CLIENT standard` | Workspace-scoped Standard |
| `veyl mode disable CLIENT` | Disable client access |

Replace `CLIENT` with your configured client ID. FULL mode requires explicit
confirmation. Stop any foreground gateway before starting the service.

## Short commands (next update)

The following commands are implemented in the local candidate and await
independent acceptance. They are not yet included in the published crate.

```sh
veyl setup --root "$PWD" --yolo
veyl mode
veyl mode yolo
veyl mode standard
veyl mode full --confirm-full
veyl mode disable
veyl mode enable
veyl help
```

Mode commands select the sole client automatically or prompt for a client
when several are configured. Append a client ID for noninteractive use.
Existing explicit commands remain compatible.

## Documentation

[Linux and upgrades](docs/LINUX.md) · [Client setup](docs/CLIENTS.md) ·
[Dashboard](docs/DASHBOARD.md) · [Tailscale](docs/TAILSCALE.md) ·
[Skills](docs/SKILLS.md) · [Upstream MCP](docs/UPSTREAM-MCP.md) ·
[Execution modes](docs/BROAD-YOLO.md)

Veyl is an alpha-stage Linux product. Core gateway functions, dashboards,
skills and durable jobs work; additional subsystem diagnostics, complete
BridgeDev parity and unattended multi-hour agent orchestration remain
under development. See [release notes](https://github.com/kmanisk/veyl/releases)
for version-specific verification and limitations.
