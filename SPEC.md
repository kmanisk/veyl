# Rust MCP Gateway — Milestone 1 Specification

## Scope and protocol contract

The **only** transport is a foreground subprocess on newline-delimited **stdio**.
Use a deliberately small JSON-RPC 2.0 adapter implemented with Rust standard
library and pinned `serde_json = "=1.0.154"`. The official Rust MCP SDK
(`rmcp`) is preferred for future expanded protocol/HTTP support, but is not
currently in the offline Cargo cache; replacing this adapter must preserve
these independent black-box tests.

Pin the **legacy MCP 2025-11-25 lifecycle**: `initialize` request,
`notifications/initialized` notification, then tool methods. One request per
line and exactly one JSON-RPC response per request, flushed promptly. Do not
respond to notifications. No prompts/resources, networking, auth, sessions,
audit ledger, filesystem mutation, or service-mode integration.

Invocation: `mcp-gateway --root /absolute/path/to/existing/directory`.
Canonicalize the root at startup and fail with a nonzero exit and stderr-only
diagnostic if invalid. Do not use the current working directory as an implicit
access root. Cleanly exit when stdin reaches EOF.

### `initialize`

Request `params.protocolVersion = "2025-11-25"`; accept a normal `clientInfo`
and `capabilities` object. Successful result must include:

```json
{
  "protocolVersion": "2025-11-25",
  "capabilities": { "tools": {} },
  "serverInfo": { "name": "mcp-gateway", "version": "0.1.0" }
}
```

Use ordinary JSON-RPC `id` echoing and `jsonrpc: "2.0"`. Implement method
dispatch for `initialize`, `notifications/initialized`, `tools/list`, and
`tools/call`. Unknown methods return JSON-RPC `-32601`; malformed requests
return protocol errors rather than panicking. No binary stdout greetings or
logging. Reject normal tool calls before completing initialization.

### `tools/list` — exactly one tool

The only advertised tool has this name and input schema:

```json
{
  "name": "read_file",
  "description": "Read a UTF-8 text file relative to the configured allowed root (max 65536 bytes)",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Relative file path inside the configured root"
      }
    },
    "required": ["path"],
    "additionalProperties": false
  },
  "annotations": { "readOnlyHint": true, "destructiveHint": false }
}
```

### `tools/call` — only `read_file`

Request:

```json
{ "name": "read_file", "arguments": { "path": "relative/file.txt" } }
```

Successful result:

```json
{ "content": [{ "type": "text", "text": "file contents" }], "isError": false }
```

Tool-level failures (missing file, traversal, symlink escape, oversize,
non-UTF-8, directory, invalid `path`) return the same content shape with
`isError: true` and a short safe human-readable text error. Never return data
from an escaped path. Reject absolute paths and any parent `..` component.

Security: canonicalize and compare resolved paths against the canonical root;
only open regular files; bound reads to **65,537** bytes and reject anything
over **65,536** bytes (no truncation). This is Milestone 1's symlink escape
check, not a claim of race-free `openat2` containment. Prefer UTF-8 decoding
with explicit error rather than lossy replacement.

## Black-box acceptance cases (locked outside this repo)

Source: `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`

1. MCP initialize response succeeds and advertises the tools capability.
2. `tools/list` lists precisely one `read_file` with the required schema.
3. Reading an in-root UTF-8 file returns exactly its bytes as text.
4. `../` traversal is rejected without leaking a sibling secret.
5. A symlink escaping the root is rejected without leaking the target.
6. A missing file returns a tool-level error, without a crash.
7. An oversized (65,537-byte) file returns an error, not truncated content.
8. An absolute path is rejected without leaking its target.

Verifier: `cargo build --offline --locked --quiet && python3
/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`

Before implementing, run this against the initial stub to establish a genuine
**red** baseline. Only the trusted harness executes the external verifier.
The coding agent should implement source modules to turn it **green**.

## Milestone acceptance and exclusions

All eight external black-box tests must pass with the same SHA-256 checksum
before and after; no modifications outside `src/*.rs`, no extra dependencies,
and no `unsafe`. Keep the passing output in a separate Git attempt branch,
inspect the entire patch, and stop at `READY_FOR_USER_REVIEW` without merging.

Deferred: durable authorization, sessions, write/patch tools, audit ledger,
Windows adapters, Tailscale Funnel, HTTPS/HTTP transport, full modern MCP
2026-07-28 support, race-free filesystem resolution, and dashboard/CLI polish.

## Current Pass 2 authenticated HTTP extension (2026-11-22)

The scope and exclusions above describe **Milestone 1 only**, not the current
Linux HTTP implementation. The accepted Pass 1 HTTP baseline is `b04989a`.
The Pass 2 review branch adds explicitly granted `write_file` and
`apply_patch` tools for authenticated HTTP clients. Stdio retains its original
`read_file` behavior.

- `write_file`: `{path, content, overwrite?: boolean}`; maximum **65,536
  UTF-8 encoded bytes**. Existing files require `overwrite: true`; new files
  are created with mode `0600`.
- `apply_patch`: `{path, expected_sha256, old, new}`; original SHA-256 must
  match and `old` must occur **exactly once**, with the final size bounded.
- Both require a per-client grant and a private, synced write-ahead audit
  intent **before** file modification. The outcome is synced before success;
  a failed post-mutation outcome is reported as uncertain, not successful.
- Linux-only handle-relative `openat2` containment, private same-directory
  staging, atomic rename and directory fsync; owner and ordinary mode bits
  are preserved on normal replacement, and outside-root symlinks are rejected.
- Unrelated hostile same-user writers, path moves, torn audit records and
  power loss remain open risks; a crash before rename can leave a staging file.
- No jobs, arbitrary command execution, YOLO, elevated OS access, remote
  ingress, installed Linux service or Windows adapter are present.

See `PASS2_TOOLS_JOBS_SPEC.md`, `PASS2_WRITE_PATCH_REVIEW.md` and `HANDOFF.md`
for independent test gates, details and remaining limits.