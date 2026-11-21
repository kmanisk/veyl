# Pass 1 — Authenticated Loopback HTTP: Independent Review

Date: 2026-11-21. **Ready for human code review, not accepted for remote use or deployment.**

## Implemented in the isolated Rust worktree

Branch `milestone2/service-contract`, based on the accepted M1 commit
`54e1571245e5d19802b2a262ad44a19bbe3eec2d`:

- `src/http/admission.rs`: read protected mode-0600 JSON config, require
  non-symlink regular file, reject duplicate identities/verifiers and bad
  roots; SHA-256 bearer verifiers compared with `subtle` constant-time digest
  comparisons; per-client roots, grants and exclusive token expiry.
- `src/http/mod.rs`: foreground, explicit `mcp-gateway http --listen
  127.0.0.1:0 --config /absolute/clients.json`. Only IPv4 loopback binds;
  Hyper HTTP/1 with a single-thread Tokio runtime; fixed Host/Origin validation,
  authentication before body parsing and method dispatch, bounded reads
  (1 MiB), 5s request timeout, 32 max connections, 128 max sessions and
  30-minute idle expiry. Unauthenticated/expired tokens cannot reach MCP tools.
- Existing Rust policy module is invoked on authorized `read_file` and
  `tools/list` with **server-derived** identity, root, time and grants.
- The original four stdio Rust modules retain their M1 behavior and tests.
  No service unit, background daemon, privileged helper, public listener,
  YOLO capability, Node/Python runtime or other system configuration was added.

## Independently locked test results

All suites execute under the trusted network-disabled Bubblewrap verifier.
Test hashes are checked before and after execution, and none are available in
the coding agent's writable worktree. Two HTTP suites were authored and locked
separately; the first proved a real red baseline (missing HTTP subcommand).
The second exposed two GET authentication/Origin ordering failures before the
fix, then passed after the fix.

| Locked test suite | SHA-256 | Tests |
| --- | --- | --- |
| `acceptance_m1/locked_stdio_acceptance.py` | `0b9a680e155b156f65cbbb766dc7e9444bf494aeb45bfb4c43c596a55cdadc9f` | 8/8 |
| `acceptance_m1_edge/locked_stdio_edge_acceptance.py` | `5379e25caf867bd6db739a36fc21bc5c80ac4607b77ed7ebdd488d5122f76dde` | 7/7 |
| `acceptance_m2_policy/locked_standard_policy.rs` | `76edbb613950fc66a0fbe9c68bed7d66a19c30a48f2af3d8de4cf1d9378f262b` | 10/10 |
| `acceptance_m2_http/locked_http_acceptance.py` | `3d5f29e088275ab05ec3f8695e036a7cc5a78dde34a54049a09fb025cc07bcbd` | 12/12 |
| `acceptance_m2_http_edge/locked_http_security_edge.py` | `f6331f44e1b4f08f75f841a04f40430014d0e30494b8b60bcf15f5e7c72a8fbd` | 6/6 |

**43/43 independent tests passed** together through
`harness.acceptance.run_acceptance` (exit 0). The lab regression suite passed
**34/34**. Existing Rust unit suite passed **17/17**, and offline formatting,
Clippy with warnings denied and Git whitespace checks passed.

## Reused pinned dependencies and measured overhead

The implementation uses already-cached `hyper 1.12.0`, `hyper-util 0.1.21`,
`tokio 1.54.1`, `http-body-util 0.1.5`, `bytes 1.12.2`, `sha2 0.10.9`,
`subtle 2.6.1`, and `getrandom 0.3.4`, in addition to the original pinned
`serde_json 1.0.154`. No global system package was installed. Cargo's normal
dependency graph contained **37 distinct entries including the application**.
The host lacks `cargo audit`; a comprehensive RustSec check of the locked
dependency graph is therefore **still required before deployment**.

A single local debug-mode HTTP smoke probe in the isolated network namespace
recorded: startup-to-ready **0.92ms**, initialization **1.314ms**, 200 reused-
connection authenticated ping responses **0.086ms median**, **0.117ms p95**,
and approximately **4,192KiB RSS**. These are single-run observations, not
release-build or concurrent-load claims.

## Not yet complete / do not expose remotely

- HTTP currently implements the legacy `2025-11-25` POST+JSON/notification+
  session subset. GET returns 405 (no SSE stream); no session DELETE, OAuth
  discovery, modern `2026-07-28` stateless protocol, HTTP/2 or full real-client
  conformance has been validated.
- Credentials load once at startup; **rotation/revocation requires a controlled
  restart**. No hot reload/revocation has passed independent tests.
- Stderr contains only fixed event codes, **not** durable/tamper-evident audit.
- The scoped file reader still has known symlink TOCTOU exposure under hostile
  concurrent filesystem modification. It is not an OS privilege boundary.
- No persistent per-client YOLO, privileged execution, managed Linux/Windows
  service, Funnel exposure, update/rollback or administration UI.

Review changes in the isolated worktree before creating any commit. Product
`main`, production BridgeDev service and Tailscale remain untouched. Further
passes require new independent acceptance tests and explicit review.