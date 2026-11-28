# Veyl Linux x86-64

The archive contains the `mcp-gateway` daemon and CLI and the on-demand
`veyl-monitor` terminal client. Dashboard assets are embedded in the
daemon. Linux jobs and Git inspection need unprivileged user namespaces
and Bubblewrap. The Git tool also needs `/usr/bin/git`. Neither systemd
nor Tailscale is required for a foreground server.

## Install and run

Check the archive against its accompanying SHA-256 file, extract it into
a private directory and run `sha256sum -c SHA256SUMS` in the extracted
directory. Copy both executable files to a stable user-owned binary
directory if you plan to install the optional user unit.

Copy `clients.example.json` to your chosen private state directory. Create
the workspace, audit, job and skills directories before startup. Keep the
state root mode 0700 and the policy file mode 0600. Replace the illustrative
paths, provision a distinct random bearer for each client and set its
SHA-256 verifier and expiration. The example credential is unusable and
expired. Keep public tool grants minimal. The [mode guide](BROAD-YOLO.md)
covers dedicated state layout, limits, and the explicit opt-in for Broad
YOLO and FULL.

```sh
mcp-gateway service validate --config "$config"
mcp-gateway http --listen 127.0.0.1:7331 --config "$config"
mcp-gateway dashboard pair --config "$config"
```

Use the separately printed admin listener and its pairing form.
For MCP setup see [Codex and Gemini](CLIENTS.md). For private network
access see [Tailscale Serve](TAILSCALE.md).

## Optional user service

For unified deployments under `~/.local/state/veyl/`, install and control the
opt-in `veyl.service` user unit (`ExecStart="<abs-veyl>" serve`, `Restart=on-failure`,
inactive and disabled until explicitly started):

```sh
veyl service install               # writes ~/.config/systemd/user/veyl.service (remains disabled)
veyl service enable --now          # explicitly enables and starts veyl.service
veyl service status                # inspect veyl.service runtime state
veyl down                          # stops active veyl.service cleanly
veyl service uninstall             # verifies exact unit ownership and removes unit (data preserved)
```

If you want `veyl.service` to remain active after logout, run `loginctl enable-linger`
explicitly as your own operator action; Veyl never modifies linger state automatically.
If legacy `mcp-gateway.service` is active, stop and disable it before starting `veyl.service`.

Legacy `--config PATH` service management remains supported for isolated config paths:
Use the installed executable and repeat the same configuration path and
MCP listener on all legacy lifecycle commands. Previewing the unit or validating
the configuration leaves the service off. You can run
`systemd-analyze verify` on a saved copy of the rendered unit.

```sh
mcp-gateway service install --dry-run --config "$config"
mcp-gateway service install --confirm --config "$config"
mcp-gateway service start --confirm --config "$config"
mcp-gateway service status
mcp-gateway service diagnostics
```

Installing writes a private unit file. Starting and enabling at login are
separate operations. Use `service enable --confirm` only if you want login
activation, and `service disable --confirm` to remove it. Other lifecycle
actions are `restart` and `stop`. These commands verify the loaded unit's
path and reject shadowing units and drop-ins. The service stays under the
user manager and starts with memory, task and restart limits. The gateway
reconciles durable job receipts after restart, and the stop policy leaves
tracked detached runners in place for that recovery.

## Terminal monitor

```sh
mcp-gateway dashboard pair --config "$config" |
  veyl-monitor --listen 127.0.0.1:7332 --client dev
```

Press Enter after keyboard commands. Use 1–7 to change views, `p CLIENT`
to select a client's jobs, `l JOB` for logs, `x JOB` for confirmed
cancellation, `r` for refresh, and `q` to sign out. For scripted output,
provide `--view` and the matching identifiers. The monitor uses a
one-time pairing code through stdin and authenticates to the admin
listener. It does not open the gateway's policy, job or audit files.
Refresh is on demand and the monitor has no background process.

## Upgrade and rollback

Save the two binaries, the private configuration and audit and job data.
Check audit integrity before changing state. Stop issuing new work and
wait for detached jobs if you need to preserve a quiet snapshot. To remove
activation, roll back owned Serve routes first, stop and disable the
unit, then uninstall it with the same binary and configuration arguments.
Uninstall preserves data. Restart with the matching configuration and
binary, and pair clients again as necessary.

Older builds reject new configuration keys. Remove unsupported
`tailscale_serve` settings and new inspection grants before rolling back
to the Gate 3e checkpoint. Restore only state appropriate to that
checkpoint and review any revocations since the backup. The Gate 3d
execution-only archive is a separate, earlier rollback baseline.
