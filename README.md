# Veyl

A lightweight, Rust-native MCP gateway for local and remote AI agents. Connect
ChatGPT, Codex or other MCP clients to authorized files, commands, durable jobs,
system inspection, skills and upstream MCP servers on your Linux machine.

## Quick start (Linux x86-64)

The commands below require v0.2.1-alpha or newer. Download a verified
Linux archive from the [releases page](https://github.com/kmanisk/veyl/releases)
or build from source.

**Requirements:** Linux, Bubblewrap (`bwrap`), and Git for Git tools.
Tailscale is only needed for remote clients; systemd is optional.

Build from source with Rust 2024 or extract a verified Linux release archive.
For a source build:

```sh
cargo build --release --locked
install -Dm755 target/release/mcp-gateway ~/.local/bin/mcp-gateway
install -Dm755 target/release/veyl-monitor ~/.local/bin/veyl-monitor
ln -s mcp-gateway ~/.local/bin/veyl
```

For a downloaded archive, verify SHA-256 and install the two extracted
executables instead. Ensure `~/.local/bin` is on PATH. The symlink command
is for a fresh installation; do not overwrite an existing executable.

### ChatGPT in two steps

1. Log in to Tailscale once using the installed Tailscale client
   (`tailscale up` if needed). The tailnet must allow HTTPS certificates,
   MagicDNS and Funnel on port 443, and your local user must be authorized
   to manage Serve routes.
2. Run this from the workspace you want to grant:

```sh
veyl setup --root "$PWD" --chatgpt-yolo
```

Veyl generates its private configuration, creates separate local and
public credentials, discovers the Tailscale hostname, starts its user
service, publishes its own MCP route and opens the paired local dashboard.
On Wayland it copies one private connector URL to your clipboard.

Open ChatGPT's custom MCP/plugin creation form, choose direct Streamable
HTTP and No authentication, paste that URL once, then connect. The secret
URL itself authenticates the dedicated client. No manual JSON editing or
dashboard pairing code is required.

The public setup option explicitly selects network-enabled YOLO for the
dedicated ChatGPT client. The local `dev` client remains Standard. The
new-user public route uses port 443; it refuses collisions rather than
taking over existing services. Existing shared Funnel installations keep
their current routes and credentials. Do not rerun setup over an existing
installation. Use `veyl connect` to activate or recopy its configured
connector URL. On systems without `wl-copy`, the command identifies the
private connector URL file instead.

### Local-only or portable

```sh
veyl init --root "$PWD"
veyl run
```

The gateway runs in the foreground. From another terminal, run `veyl ui`
to open and pair your browser automatically. Ctrl+C ends foreground
operation. No systemd unit or Tailscale route is required.

For private tailnet-only access, use `veyl setup --root "$PWD" --tailscale`
after signing in to Tailscale. Use `veyl ui --remote` from a host that can
resolve and reach the private tailnet hostname.

## Daily commands

| Command | What it does |
| --- | --- |
| `veyl ui` or `veyl dashboard` | Open and pair the local dashboard |
| `veyl ui --remote` | Open and pair the private Tailscale dashboard |
| `veyl monitor` | Open the automatically paired terminal monitor |
| `veyl monitor --view health` | Print structured health JSON |
| `veyl diagnostics grant chatgpt` | Grant structured system inspection |
| `veyl diagnostics revoke chatgpt` | Revoke structured system inspection |
| `veyl connect` | Activate or recopy the configured public connector URL |
| `veyl service on` | Install, start and enable the matching user service |
| `veyl service status` | Inspect the service |
| `veyl portable` | Stop and disable the matching user service, then run in the terminal |
| `veyl run` | Run in the foreground without changing service activation |
| `veyl mode get chatgpt` | Inspect the client's mode |
| `veyl mode set chatgpt yolo` | Enable persistent YOLO |
| `veyl mode set chatgpt standard` | Return to Standard |
| `veyl mode disable chatgpt` | Disable access, retain selected mode |
| `veyl mode enable chatgpt` | Re-enable the client |

If a foreground gateway is running, stop it with Ctrl+C before
`veyl service on`. Portable switching deliberately leaves login startup
disabled until you restore service mode. Both modes use the same state.
Existing jobs are managed by the durable runner, not by the terminal.

Configuration defaults to `~/.local/state/veyl/clients.json`; existing
legacy configurations are discovered when unambiguous. All management
commands can take an explicit `--config PATH` where applicable. A fresh
local setup stores its MCP bearer in the owner-only `dev.bearer` file.
Never paste a bearer or private connector URL into chat or logs.

## Modes

| Mode | Files | Execution |
| --- | --- | --- |
| Standard | Workspace and explicit extra roots | Sandboxed, offline |
| YOLO | Host-wide authorized paths, protected state excluded | Sandboxed, network-enabled |
| FULL | Host-user access | Supervised, unsandboxed |

FULL requires `veyl mode set CLIENT full --confirm-full` and does not
grant root. Permissions persist until changed. Client activation and tool
grants are independent of the mode. For existing version 1/2 policies,
use the reviewed `veyl mode migrate --config PATH` before switching
to the version 3 schema.

## More capabilities

- [Dashboard and pairing](docs/DASHBOARD.md)
- [Linux install, service and rollback](docs/LINUX.md)
- [Local Codex and Gemini clients](docs/CLIENTS.md)
- [Private Tailscale access](docs/TAILSCALE.md)
- [ChatGPT connector](docs/CHATGPT.md)
- [Skills](docs/SKILLS.md)
- [External MCP servers](docs/UPSTREAM-MCP.md)
- [Mode migration and protection](docs/BROAD-YOLO.md)
- [BridgeDev parity](docs/PARITY.md)
- [Current implementation and verification](STATUS.md)
- [Protocol and implementation specification](SPEC.md)

Veyl's daemon, CLI and monitor are native Rust; dashboard assets are
embedded. The gateway stays on loopback, and only explicitly configured
MCP ingress is made public. The dashboard remains local or private
tailnet-only.
