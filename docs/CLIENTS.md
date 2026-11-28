# Connect MCP clients

## Direct OAuth MCP and unified gateway

Use the same public HTTPS `/mcp` endpoint and OAuth discovery contract in
any compatible client. Start with `veyl up --root "$PWD"` to initialize or
reconcile unified state under `~/.local/state/veyl/` and run the single
gateway process serving both loopback static bearers and public OAuth
connections (legacy `veyl login` and `veyl oauth setup/run` compatibility
paths remain supported). See
[direct remote plan](development/DIRECT_REMOTE_PLAN.md) for onboarding,
per-connection Standard/YOLO selection, exact scope, sandbox constraints,
and acceptance. Choose Streamable HTTP, OAuth DCR, PKCE S256 and scope `mcp`.
Every newly registered OAuth connection uses the persisted `default_mode`
(`standard` by default, or `yolo` if switched globally via interactive
`veyl mode yolo` confirmation) as its dashboard consent preselection without
auto-authorizing access. Local operators can also switch individual clients
via `veyl mode yolo <CLIENT_ID> --confirm-native`, `veyl mode standard <CLIENT_ID>`,
`veyl clients revoke <ID|NAME>`, or legacy `veyl logout --client <ID>` / `--all`. Escalation revokes prior Standard grants and requires
fresh OAuth authorization; downgrade or revocation immediately denies
elevated admissions and job launches. No separate ChatGPT plugin, cloud relay
or Veyl account is required. Client-specific authentication and tool support
vary; verify read, write, commands, revoke and reconnect against the real
client before claiming compatibility. A mobile client can use a remote Linux
host only when the mobile client supports this connection; native Windows and
Android/Termux gateway support remains future work.

## Existing bearer-authenticated connections

Give each client an independent bearer and explicit tool grants. Connect
to the local MCP URL `http://127.0.0.1:7331/mcp`, or the dedicated HTTPS
MCP URL printed by `mcp-gateway serve plan` after private activation. The
dashboard address is separate.

## Shared mode selection

For policy version 4, a local operator can explicitly set the same mode for every enabled client:

```sh
veyl mode yolo --all --confirm-native
veyl mode standard --all
```

The batch is atomic and audited. Existing client identities, credentials, explicit denials, roots and upstream approvals remain independent. Disabled clients stay disabled. Future clients do not inherit elevation automatically. An interrupted batch fails closed; recover with `veyl mode standard --all`, which removes elevation from all entries including disabled clients while preserving disabled state. Older policy schemas require explicit migration first. A single-client mode change continues to affect only that client.

## Codex

Supply `VEYL_MCP_BEARER` from your local secret manager to the Codex process.
Register a Streamable HTTP server for the same account/profile that launches
Codex:

```sh
codex mcp add veyl --url http://127.0.0.1:7331/mcp \
  --bearer-token-env-var VEYL_MCP_BEARER
codex mcp get veyl
```

An actual disposable Codex app-server session completed authenticated tool
discovery and forwarded a custom upstream call through Veyl.

## Gemini CLI and Antigravity

For standalone Gemini CLI, add Veyl to the user-private `mcpServers` object
in `~/.gemini/settings.json` using Streamable HTTP. Keep the bearer in the
environment of that client process.

```json
{
  "mcpServers": {
    "veyl": {
      "httpUrl": "http://127.0.0.1:7331/mcp",
      "headers": { "Authorization": "Bearer ${VEYL_MCP_BEARER}" },
      "trust": false
    }
  }
}
```

For Antigravity, use the installed client's MCP settings to register the
same HTTP URL and Authorization header in its private profile. Keep
credentials out of command arguments, logs, and shared project settings.
The disposable Antigravity CLI verified gateway authentication and
upstream discovery. A Gemini model-driven call needs a separately
authenticated Google session. The standalone Gemini CLI configuration
follows the [Gemini CLI MCP documentation](https://geminicli.com/docs/tools/mcp-server/).
