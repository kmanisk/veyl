# Private access through Tailscale Serve

Veyl uses the existing tailscaled node and account. It does not log in,
request a new account, enable Funnel, change the operator, or modify tailnet
access policy. Use a device that already has MagicDNS, HTTPS certificates
and an authorized local Tailscale operator.

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
It rejects requests marked as Funnel traffic.

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

`serve remove` is equivalent. Roll back the recorded pair before changing
its ports, backend addresses or hostname. If another operator changes an
owned port, Veyl refuses to remove the conflicting configuration. Review
the effective Serve state before retrying an uncertain outcome. Keep
tailnet access rules scoped to the intended users and devices.

Reference for the [Tailscale Serve CLI](https://tailscale.com/docs/reference/tailscale-cli/serve).
