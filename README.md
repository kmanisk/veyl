# <img src="assets/veyl.svg" width="36" height="36" alt=""> Veyl

A lightweight Rust MCP gateway for your Linux machine. Give ChatGPT, Codex
and other MCP clients access to your development workspace, supervised
commands, durable jobs, native diagnostics, skills and upstream MCP servers.

**Linux · Native Rust · Local or Tailscale · Web dashboard + terminal monitor**

## Install

Cargo installation from the repository (no manual clone or symlink):

```sh
cargo install --git https://github.com/kmanisk/veyl --branch main --locked --bin veyl --bin veyl-monitor
```

The repository is currently private; GitHub access is required.
Crates.io publication is pending. Prebuilt Linux archives are available
on the [releases page](https://github.com/kmanisk/veyl/releases).

Requires Linux, Bubblewrap (`bwrap`) and Git. Add Tailscale for remote
access and a systemd user session for persistent service mode.
Cargo's bin directory must be on PATH.

## Connect ChatGPT

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

The web dashboard has individual sidebar views for clients, jobs, activity,
skills and upstream MCP servers. The native terminal monitor has live
activity, selectable jobs, logs and keyboard navigation. Both pair
automatically with the local gateway.

## Daily use

| Command | Action |
| --- | --- |
| `veyl ui --remote` | Open the private Tailscale dashboard |
| `veyl connect` | Recopy your existing connector URL |
| `veyl service on` | Start and enable the user service |
| `veyl service status` | Inspect the service |
| `veyl portable` | Switch from service to foreground |
| `veyl mode set chatgpt yolo` | Persistent YOLO |
| `veyl mode set chatgpt standard` | Workspace-scoped Standard |
| `veyl mode disable chatgpt` | Disable client access |

FULL mode requires explicit confirmation. Stop any foreground gateway
before starting the service.

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
