# Connect ChatGPT to Veyl through Tailscale Funnel

Veyl's public MCP route is opt-in. Use a dedicated Veyl client and
credential. Keep the dashboard on private Tailscale Serve. Funnel
requires a tailnet that permits the existing node to expose a supported
HTTPS port. Veyl reserves the node's existing port 443 and accepts 8443
or 10000 for its public MCP route. See [Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel).

## Configure the dedicated client

Use an existing approved YOLO client such as `chatgpt`. Keep only
the required tool and job grants on this client. Give it a separate
public credential using a secret manager or local setup script. Generate
32 random bytes encoded as 64 lowercase hexadecimal characters. Store
the plaintext in an owner-only file such as
`~/.local/state/veyl/tokens/chatgpt-funnel.token`. Store only its SHA-256
verifier, calculated over the 64 characters without a newline, in
`tailscale_serve.funnel.token_sha256`. Preserve the client's existing
private verifier. Use mode `0600` for credential files.

In the private `clients.json`, add the `funnel` object to the existing
`tailscale_serve` object.

```json
{
  "hostname": "your-node.your-tailnet.ts.net",
  "mcp_https_port": 8443,
  "admin_https_port": 9443,
  "funnel": {
    "client": "chatgpt",
    "token_sha256": "REPLACE_WITH_THE_64_CHARACTER_SHA256_VERIFIER",
    "allow_secret_path": true
  }
}
```

Leave `allow_secret_path` false for clients that can send the public
bearer in the `Authorization` header to `/mcp`. The secret path is for
ChatGPT custom connectors that cannot send this header. The entire URL
is a bearer credential. Paste it only into the intended private
connector. URLs can remain in browser, proxy, app or support history
outside Veyl. Veyl emits only fixed labels for public authentication
failures and records successful admission under the dedicated client
identity. Tailscale proxy metadata alone does not authorize any request.

## Activate and verify

For an existing public HTTPS service on 443, optionally add
`"shared_funnel": true` to `tailscale_serve` next to `funnel`. Restart
Veyl with the updated configuration. Tailscale sends `/veyl/` to the
same MCP loopback listener and strips the mount prefix. Use
`https://HOST/veyl/mcp` with a header credential, or
`https://HOST/veyl/mcp/TOKEN` for the existing secret-path connector.
Veyl requires Tailscale's Funnel marker and validates the configured
host for this route. The existing root handler and HTTPS policy stay
under their original owner.

Use `serve funnel-plan` and `serve funnel-apply --confirm` to add the
shared path. For a migration from the exact loopback adapter on port
7330, add `--adapter` to those commands. Verify the existing connector
URL through a public relay before running
`serve funnel-retire-dedicated --confirm`. This removes the dedicated
public flag and leaves private Serve and the dashboard in place.
Keep the old adapter available until the new route passes verification.

On shared 443, `serve funnel-rollback --confirm` disables public MCP at
the owned path. It leaves a static disabled handler there so existing
secret URLs cannot reach the colocated root proxy. During the adapter
migration, `serve funnel-rollback --adapter --confirm` can restore
the previous loopback adapter while it is still installed.

### Dedicated port

Restart the Veyl backend with the opt-in configuration before publishing
the route. If the private route pair is absent, use `veyl serve apply
--confirm` against the same configuration to create it first.

```sh
state="$HOME/.local/state/veyl"
veyl state check --state-root "$state" --config "$state/clients.json"
veyl serve funnel-plan --config "$state/clients.json"
veyl serve funnel-apply --config "$state/clients.json" --confirm
veyl serve inspect --config "$state/clients.json"
```

Activation preflights YOLO and conditionally adds the public flag
to the existing owned Veyl MCP port. The dashboard's private route and
other services' flags are preserved. From outside the tailnet, verify
that the bare endpoint with no credential is rejected. Authenticate
and complete MCP initialization, then run an approved tool against a
disposable file. Confirm the result and audit attribution. Public
requests share a bounded request budget, separate from private bearer
failures.

On the configured public MCP route, browser requests from
`https://chatgpt.com` and `https://chat.openai.com` can preflight POSTs
and read the MCP session and protocol response headers. OPTIONS uses
the public request budget and grants no access. Every POST still
requires the public credential. Private MCP and the dashboard retain
their own origin checks.

If discovery fails, check Veyl's stderr or service journal while
retrying in ChatGPT. `MCP_HTTP_EVENT=funnel.response` identifies the
HTTP method, classified origin and status. `funnel.rpc_initialize`
and `funnel.rpc_tools_list` identify authenticated discovery requests.
The events omit the URL, credentials, raw Origin and client metadata.
A browser probe against a public relay can verify CORS independently
of ChatGPT's account and cloud network. A successful browser probe
does not establish that the connector service reached the endpoint.

## ChatGPT connection

Open **Plugins → + → Add custom MCP server**. Name the private plugin
**Veyl**, choose direct connection to a server URL and use Streamable HTTP.
With a verified secret-path setup, choose **No authentication** in the
form. Veyl authenticates possession of the secret path. For the 8443
route, run the following in a private Wayland session to copy the URL
without displaying it, replacing the example hostname.

```sh
{
  printf '%s' 'https://your-node.your-tailnet.ts.net:8443/mcp/'
  tr -d '\n' < "$HOME/.local/state/veyl/tokens/chatgpt-funnel.token"
} | wl-copy --trim-newline --paste-once
```

Paste the URL into the connector form and create the plugin. Verify
tool discovery and run an approved tool. Do not publish the plugin or
paste the URL into a conversation or issue. See [ChatGPT custom MCP connector setup](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt).

## Revoke access

`veyl serve funnel-rollback --config "$state/clients.json" --confirm`
disables the owned public path or dedicated public flag and preserves
the private pair. To revoke a
credential while preserving the route, atomically replace the public
verifier and publish a new private credential file. The next public
request checks the new verifier, including requests on old sessions.
Selecting Standard or FULL for the connector denies its public access.
Changing the public client identity or secret-path policy requires a
Veyl restart. Treat a copied or shared connector URL as a leaked key and
rotate it.
