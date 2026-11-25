# Connect MCP clients

Give each client an independent bearer and explicit tool grants. Connect
to the local MCP URL `http://127.0.0.1:7331/mcp`, or the dedicated HTTPS
MCP URL printed by `mcp-gateway serve plan` after private activation. The
dashboard address is separate.

## Shared mode selection

For policy version 3, a local operator can explicitly set the same mode for every enabled client:

```sh
veyl mode yolo --all
veyl mode standard --all
veyl mode full --all --confirm-full
```

The batch is atomic and audited. Existing client identities, credentials, explicit denials, roots and upstream approvals remain independent. Disabled clients stay disabled and retain their selected modes. Future clients do not inherit elevation automatically. An interrupted batch fails closed; recover with `veyl mode standard --all`, which removes elevation from all entries including disabled clients while preserving disabled state. Older policy schemas require explicit migration first. A single-client mode change continues to affect only that client.

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
