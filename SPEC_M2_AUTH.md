# Pass 1 — Authenticated loopback MCP HTTP

This specification applies to the `milestone2/service-contract` worktree.
[The service roadmap](SERVICE_ROADMAP.md) supersedes the earlier stdio-launcher
authentication proposal for this pass. The Milestone 1 foreground stdio CLI
and wire behavior remain supported.

## Scope and trust boundary

Add an explicitly started foreground Rust HTTP entrypoint on IPv4 loopback
with one `/mcp` endpoint. The local operator controls the bind address and the
protected credential-verifier configuration. The client supplies an
`Authorization: Bearer ...` header and MCP messages. The server derives
principal identity, expiry, granted tools and root solely from protected
local configuration. Request parameters, MCP metadata, forwarded headers
and session identifiers never establish or increase permissions.

The test contract uses
`mcp-gateway http --listen 127.0.0.1:0 --config /absolute/path/to/clients.json`
for a disposable listener. Report the bound endpoint without credentials to
stderr once the listener is ready. Reject non-loopback binding before
accepting requests. Validate `Host` against the listener and validate
`Origin` when present. Provide no browser CORS access or HTTP administration.
Loopback bearer admission is scoped to this local development pass. OAuth
discovery, remote HTTPS, and Tailscale integration require separate work.
[MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) ·
[MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

## Credentials and policy

- Use operator-provisioned independent random 256-bit bearer values. The
  fixture format uses 64 lowercase hexadecimal characters. The protected
  config stores SHA-256 verifiers for the ASCII bearer values, client IDs,
  exclusive Unix-second expiry, canonical absolute roots and explicit tool
  grants. Use a maintained digest implementation and constant-time verifier
  comparison. Reject duplicate identities or verifiers and fail startup on
  invalid or unprotected configuration. The fixture uses a JSON object with a
  `clients` array. Each entry contains `id`, `token_sha256`,
  `expires_at_unix_seconds`, `root` and `tools`. Use mode `0600` for
  Linux fixture files, with `tools: ["read_file"]` for a scoped reader.
- Recheck authorization on every request, including requests carrying a
  valid session ID. Authenticate before dispatch or body processing. Supply
  generic `401` responses for missing, malformed, incorrect, or expired
  credentials and rate-limit repeated admission failures with `429`.
  Keep bounded limiter state and use observed socket addresses.
- Keep tokens and verifiers out of URLs, argv, stdout, stderr, tool errors
  and request logs. Diagnostics can contain fixed event codes and safe
  outcome fields. Capture credential leak sentinels through independent tests
  for both admitted and denied requests.
- Reuse the existing trusted STANDARD decision function from
  `src/security/policy.rs`. Derive its identity, action, time, root and grant
  from authenticated server-side inputs. Provide evidence of a functioning
  secret-free admission diagnostic sink when setting its audit-availability
  input. Durable auditing belongs to Pass 3.
- Expose only the granted subset of the existing read-only tool. Reuse the
  scoped reader and retain its 65,536-byte and UTF-8 limits. Reject traversal,
  absolute paths and static symlink escapes. Roots are operator-controlled.
  Race-resistant containment remains a Pass 2 requirement.

## HTTP contract

Serve JSON MCP responses on authenticated POST and a bodyless `202` for an
accepted notification. Support the legacy `2025-11-25` initialize lifecycle
as the minimum compatibility target. If legacy session IDs are issued, bind
them to the admitted identity, bound their count, and reject cross-client
reuse. Accept compatible MCP client headers and validate the negotiated
protocol revision after initialization. Apply bounded bodies, deadlines and
concurrency limits. GET event streams, resumability and modern protocol
support require separate evidence before they can be advertised.

Pass 1 keeps stdio, HTTP transport, admission and authorization as separate
Rust concerns. There is no Pass 1 YOLO activation or privileged execution.
The tool and credential grant boundaries remain independent of eventual
persistent YOLO assignment.

## Independent acceptance before implementation

The external HTTP suite must be independently authored, locked and hashed
before changing gateway code. Run it against the current gateway in the
network-disabled verifier and confirm that missing HTTP behavior causes the
failure. A fixture or environment error is insufficient. Preserve the two
M1 suite hashes and the policy suite hash.

The HTTP suite should drive the real binary and cover:

- Correct credentials, initialization and scoped reads. An independent
  client with a different root fails to reuse the first client's authority.
- Missing, wrong, malformed and expired credentials. Denied requests release
  no file data even after a successful session has been established.
- Invalid origin or host, non-loopback bind rejection, bounded malformed
  input, repeated failures and rate-limit recovery.
- Secret-free stdout, stderr, diagnostics, and tool errors.
- Ungranted tools, cross-root reads, invalid paths and client attempts to
  request YOLO. Existing stdio and the locked policy behavior must pass.

Verify the selected dependency graph, advisory results, compatibility and
resource measurements before claiming Pass 1 acceptance. Preserve all
existing job receipts and stop for review after Pass 1.

### Current tested Pass 1 implementation (2026-11-21)

The foreground `mcp-gateway http` subcommand now provides the specified
IPv4 loopback-only HTTP endpoint, reading a mode-0600 JSON verifier config.
It uses `hyper` HTTP/1, single-thread Tokio, SHA-256 digest lookup with
constant-time comparison, 24-byte random session identifiers, bounded body
reads and a 32-connection/128-session limit. Per-client read roots and tool
grants are linked to the independent Rust STANDARD authorization policy.
Auth is rechecked per request, including on GET/unsupported methods; Host and
Origin are checked before method dispatch. Stdio remains unchanged.

The two HTTP suites were independently authored and locked **before their
respective changes**. The first 12 cases established a red baseline against
the missing `http` subcommand; the additional six were created after the
basic implementation and exposed two GET-ordering failures before correction.
All 18 now pass, alongside the 15 M1 cases and 10 policy cases. See
`PASS1_HTTP_REVIEW.md` for receipts and checksums.

This remains **legacy 2025-11-25 HTTP/1 JSON-response subset**: no GET SSE,
session DELETE, modern 2026-07-28 semantics, OAuth discovery, HTTP/2 or
public-facing access. No complete RustSec graph audit was available on the
host, so dependency safety remains a review gate. A runtime configuration
file change currently requires a service restart; dynamic revocation is not
yet implemented and is required before remote access.
