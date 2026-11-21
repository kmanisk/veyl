# Milestone 2 — Deny-by-default Rust policy foundation

Date: 2026-11-21. **Partially implemented: not connected to a running service.**

## Scope

- `src/lib.rs` exposes reusable Rust policy modules.
- `src/security/mod.rs` and `src/security/policy.rs` implement a pure,
  deterministic, allocation-free authorization decision function.
- `SERVICE_ROADMAP.md` records the revised six passes, permanent YOLO,
  and the service, auditing, remote access and lifecycle requirements.
- No new dependencies, `unsafe`, runtime permissions, sockets, background
  processes, YOLO grants, credential store or privileged helper were added.
- The original four Milestone 1 Rust source files remain unchanged.

## Verification

New independent external suite:
`~/Projects/rust-mcp-gateway-lab/acceptance_m2_policy/locked_standard_policy.rs`.

Pinned SHA-256: `76edbb613950fc66a0fbe9c68bed7d66a19c30a48f2af3d8de4cf1d9378f262b`.

The red baseline failed because the M1 gateway had no Rust library target.
After implementation, the trusted, **network-disabled Bubblewrap** verifier
independently reran all three locked suites:

| Independent suite | Result |
| --- | --- |
| Original M1 stdio | 8/8 passed, unchanged hash |
| M1 framing/edge | 7/7 passed, unchanged hash |
| New M2 policy | 10/10 passed, unchanged hash |

Clippy with warnings denied, formatting and Git whitespace checks passed.
The new external oracle is read-only (`0444` file, `0555` parent). It checks
identity/grant agreement, grant expiry, lexical root scoping, capability
allowlisting, audit-failure denial, and rejection of command/service/privileged
actions even if the caller merely requests YOLO mode.

## Security boundary — what this does **not** prove

`PolicyInput` is a contract for trusted inputs, **not** authentication. Its
fields are public test inputs. Future integration must derive identity, roots,
actions and timestamps from a separate, verified admission layer,
never from MCP JSON. This module does not verify signatures, token expiry,
replay counters or OS privileges. No security audit ledger is implemented.

The new library is **not wired into** the Milestone 1 foreground stdio binary,
nor is any HTTP/network gateway or privileged service enabled. The module
cannot grant YOLO operations in its current form, even if a grant lists them.

## Next development gate

Define a concrete Rust credential admission API and external black-box tests
covering missing, malformed, incorrect and expired credentials, cross-root
denial, rate limits and prevention of secret disclosure. The prior M2 auth
proposal and independent test plan remain uncommitted in the separate M1
review worktree; preserve them and reconcile during a future reviewed pass.

The current policy has legacy lease terminology in its denial API. The
locked tests retain that API and verify rejection of untrusted YOLO intent.
The new roadmap requires persistent local configuration for YOLO and a
separate audited authority for OS elevation. Both are Pass 3 work.

No commit, merge, deployment or host configuration modification was performed.

## Pass 1 revision (2026-11-21)

The note above that the library is not wired into a runtime is **historical**.
The new foreground HTTP path invokes the existing Rust authorization decision
for scoped read/list requests; ordinary stdio still works without auth as an
operator-launched local worker. All HTTP caller identities and roots come from
the operator-owned, SHA-256-verifier configuration, not client JSON.

Independent network-disabled tests: 15/15 stdio, 10/10 policy, and 18/18 HTTP
cases. The HTTP tests check cross-token session denial, expired/missing/wrong
tokens, 0600 config enforcement, non-loopback startup rejection, bad Host and
Origin, per-client roots, oversized body, rate limiting and absence of token
values in process diagnostics. See `PASS1_HTTP_REVIEW.md`.

The HTTP process is not installed as a service; a valid token only permits a
scoped read. Permanent YOLO and root/Administrator execution remain disabled
and unimplemented. Configuration reads are not fully race-resistant; tokens
cannot be revoked without a restart, and fixed-event stderr logs are not yet
tamper-evident durable audit receipts.
