# Upstream MCP servers

Register a provider locally, then grant each client only the reviewed tool
names it needs. New registrations are ungranted. A client must already have
`mcp_servers_call` in its global tool grants to invoke upstream tools.
`mcp_servers_list` reports only the client's enabled, granted servers.

```sh
mcp-gateway mcp-servers add-stdio example /usr/bin/python3 /absolute/example.py --config "$config"
mcp-gateway mcp-servers add-http local http://127.0.0.1:9000/mcp --config "$config"
mcp-gateway mcp-servers probe example --config "$config"
mcp-gateway mcp-servers grant dev example lookup --config "$config"
mcp-gateway mcp-servers list --config "$config"
mcp-gateway mcp-servers revoke dev example lookup --config "$config"
mcp-gateway mcp-servers disable example --config "$config"
mcp-gateway mcp-servers remove example --config "$config"
```

The dashboard exposes registration, one-click verified marketplace
installation (`POST /api/dashboard/marketplace/{install,configure,uninstall,cancel,recover}`),
probe, disable, removal, and bulk/per-tool grant operations after pairing and confirmation.
Verified marketplace packages (`rea`, `rust-anything`, pure-JS npm tarballs without lifecycle hooks,
pure-Python wheels, standalone ELF binaries, and guidance-only skills) are staged cleanly under
`<state_root>/upstream-bundles/<id>` after cryptographic digest verification, probed inside Bubblewrap,
and rolled back automatically on failure or cancellation. Manual custom `mcp-servers add-stdio`,
`add-bundle`, and `add-http` remain unchanged.
initialization and tool discovery on demand. It does not invoke a tool.
Discovery advertises `example__lookup`, with the provider ID as the prefix.
Grant changes apply to the next admitted request, including an existing MCP
session. A call admitted before revocation can complete.

Legacy configurations with `allowed_servers` and no
`allowed_server_tools` retain their explicit whole-server grant. They also
accept unique unqualified tool names. To replace that compatibility grant
with per-tool grants, use `mcp-servers restrict CLIENT --config "$config"`
and regrant the reviewed names. Example modern policy fields:

```json
{
  "mcp_servers": {
    "example": {
      "transport": "stdio",
      "command": "/usr/bin/python3",
      "args": ["/absolute/example.py"]
    }
  },
  "allowed_servers": ["example"],
  "allowed_server_tools": { "example": ["lookup"] }
}
```

Here `mcp_servers` belongs at the top level and both grant fields belong in
the client's record. Older binaries reject these new fields. Before rolling
back, back up the policy and restore its previous compatible shape without
restoring revoked grants.

## Transport and credential boundaries

Stdio uses a fresh, unprivileged Bubblewrap process confined to a private
mount, PID and network namespace. It receives a clean environment, no client
bearer credentials, and no access to client workspaces or gateway state.
A self-contained native executable outside the system image or a Python
entry script can be bound by descriptor, read-only. Package trees, arbitrary
host environment variables and working directories are not mounted. Choose
operator-controlled executable and script paths. Each admitted operation takes
a fresh connection, so retries are explicit and calls are never automatically
replayed. Stdio descendants are managed by the Bubblewrap PID namespace.

Streamable HTTP accepts JSON and bounded SSE responses. Plain HTTP is limited
to literal IPv4 loopback endpoints and carries no bearer credential. HTTPS
requires a numeric connection IP if the URL uses a DNS name. For example,
`mcp-servers add-http example https://mcp.example.org/mcp 192.0.2.10`. Veyl
verifies the URL's certificate identity, uses the system CA bundle by
default and does not follow redirects, proxies or DNS changes.

For a credentialed HTTPS server, set `"use_token": true` in its entry using
the local operator's private policy file. Provision the bearer in
`.mcp-upstream-<id>.token` alongside the configuration using a secure local
editor or secret manager. Use an operator-owned, mode 0600 regular file
with one link. An optional `"private_ca": true` loads the PEM trust roots
from `.mcp-upstream-<id>.ca.pem` under the same rules. Keep those files in
the private state layout. Tokens are excluded from configuration JSON,
browser responses, child environments, command-line arguments and audit
records. Veyl rejects responses that directly reflect the configured
credential. Prefer a distinct credential for each registered upstream and
delete its sidecars separately when retiring that registration.

HTTP connections run through the gateway's network authority only after
explicit registration and grants. They do not give Standard jobs network
access. Upstream tools are untrusted responses and their descriptions can
contain instructions. Audit events record the client, effective mode,
qualified tool and outcome, excluding arguments, upstream credentials
and results. Requests are bounded by elapsed time, frames, discovery pages,
tool counts and concurrent links. Veyl does not proxy MCP sampling,
elicitation, or autonomous server-to-client execution.

A connection's initialize, discovery and call sequence has a 1.7-second
deadline. The overall discovery or alias-resolution operation is capped
at three seconds and six concurrent links. Slow tools and server features
that require a persistent notification stream are outside this checkpoint.
Protocol details follow the [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
