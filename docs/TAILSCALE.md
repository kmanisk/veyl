# Private access through Tailscale Serve

Veyl uses the existing tailscaled node and account. It leaves login,
operator privileges and tailnet access policy to Tailscale. Use a
device that already has MagicDNS, HTTPS certificates and an authorized
local Tailscale operator.

Give MCP and administration different HTTPS ports. A node can keep its
existing BridgeDev listener on 443. Merge these fields into Veyl's private
client configuration and replace the illustrative hostname with your node's
MagicDNS name:

```json
{
  "admin_listen": "127.0.0.1:7332",
  "tailscale_serve": {
    "hostname": "workstation.example.ts.net",
    "mcp_https_port": 8443,
    "admin_https_port": 9443
  }
}
```

The daemon still listens on IPv4 loopback. Restart it with the new settings
before making routes available. Keep authentication enabled on both listeners.
Use `--listen` consistently if you changed the default MCP port, 7331.

```sh
mcp-gateway serve plan --config "$config"
mcp-gateway serve validate --live --config "$config"
mcp-gateway serve inspect --config "$config"
```

The first command reads the local configuration. A read-only
`--state-file PATH` can supply a disposable Serve snapshot. Live validation
checks the running node, certificate eligibility and collisions without
requesting a certificate or altering the node. For an isolated LocalAPI
fixture, `--socket PATH` uses an explicitly chosen Unix socket.

After the operator authorizes activation, use:

```sh
mcp-gateway serve apply --confirm --config "$config"
```

Use the emitted URLs for MCP and browser access. MCP still requires the
client bearer. For the remote dashboard, open the dashboard in the
intended browser tab and enter a fresh code from
`mcp-gateway dashboard pair --config "$config"`. Remote pairing codes are
accepted through the form. The secure, HttpOnly cookie and an independent
origin-scoped browser proof are both required for remote API calls. This
proof is important because browser cookies do not distinguish the two
HTTPS ports on the same hostname. The browser uses Strict SameSite, exact
HTTPS Origin checking and CSRF protection. Veyl does not use forwarded
identity, proxy-protocol or forwarding headers to authenticate a request.
The dashboard rejects all Funnel traffic. The MCP listener rejects
Funnel by default. The separate [public MCP configuration and commands](CHATGPT.md)
enable an authenticated Funnel route on the owned MCP port.

Each Veyl route reserves its entire HTTPS port and has a private Serve
ownership marker. The owner-only local receipt survives restarts and
ambiguous outcomes. Conditional LocalAPI updates use tailscaled's ETag.
A concurrent update or conflicting TCP, web, foreground or Funnel
configuration is refused. Unrelated Serve and Funnel routes stay in the
same configuration. Mutating requests require an audit intent, and Veyl
checks the resulting route state before reporting success.

Use the same configuration path to remove the pair:

```sh
mcp-gateway serve rollback --confirm --config "$config"
```

`serve remove` is equivalent. If public MCP is active, run
`serve funnel-rollback` first. Roll back the recorded pair before changing
its ports, backend addresses or hostname. If another operator changes an
owned port, Veyl refuses to remove the conflicting configuration. Review
the effective Serve state before retrying an uncertain outcome. Keep
tailnet access rules scoped to the intended users and devices.

## Unified runtime and Cloudflare option (`veyl up` / `veyl serve`)

When using the unified gateway under `~/.local/state/veyl/`, `veyl up` (and
`veyl serve`) supervises the configured ingress automatically inside one foreground
or `veyl.service` process:

- Tailscale Funnel (`--tailscale`, default when Tailscale is available) acquires an
  owned foreground session lease and deletes only its own session on shutdown/SIGINT/SIGTERM.
- Explicit named Cloudflare Tunnels (`--cloudflare --cf-hostname HOST --cf-tunnel NAME --cf-credentials FILE`)
  run only with an operator-installed `cloudflared` binary and an explicit FQDN; ephemeral
  `.trycloudflare.com` quick tunnels are refused fail-closed, and `cloudflared` is never
  downloaded automatically.
- Local-only mode (`--local`) binds loopback with no public ingress.

### Migrating a legacy split-port installation

If the legacy static Funnel port differs from a saved OAuth issuer on the same
MagicDNS hostname, ordinary migration refuses the conflict. After stopping and
disabling the legacy service and reviewing/retiring only its owned routes using
the legacy configuration and ownership receipt, explicitly select
`veyl up --adopt-oauth-issuer`. This retains the saved dedicated OAuth HTTPS
port (8443 or 10000), drops the obsolete public static bearer configuration,
and retains the existing canonical policy in owner-only `clients.pre-unified.json`.
It does not remove any Tailscale routes itself. Hostname conflicts still fail
closed. Existing static credentials remain local; the default local MCP
listener is 127.0.0.1:7331 when static clients exist. Remote clients must use
OAuth at the newly selected endpoint. An explicit `--listen` remains available.
Do not restore the old policy over a migrated registry as a rollback procedure.

For a shared legacy `/veyl/` mount alongside an independent root proxy,
use the verified new executable **before** migrating the old policy:

```sh
veyl serve inspect --config "$config" --live
veyl serve funnel-retire-legacy --config "$config" --confirm
```

This command requires the old route receipt, the owned shared marker and an
independent HTTPS root proxy. It atomically removes the owned dedicated MCP
and dashboard routes (including any dedicated MCP Funnel permission) while
retaining the shared non-proxy tombstone and its ownership receipt. It never
removes the unrelated root proxy or its Funnel permission. A stale connector
URL cannot fall through to that root proxy. Conflicting ownership or an ETag
race is refused; inspect before retrying. The command is idempotent when the
same owned tombstone remains and both dedicated listeners are absent.
Do not use the ordinary `funnel-rollback` followed by `rollback` for this
shared case: ordinary rollback deliberately protects the shared marker's
receipt. Standalone legacy routes use their existing rollback procedure.

The lower-level `serve plan / validate / inspect / apply / rollback` commands documented
above remain available for manual static `tailscale_serve` route pairs.

Reference for the [Tailscale Serve CLI](https://tailscale.com/docs/reference/tailscale-cli/serve).
