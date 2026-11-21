# Gateway Milestone 1 — Working Handoff

This is a separate greenfield product, **not** the harness project and not
production BridgeDev. See `AGENTS.md` and `SPEC.md` for constraints.

Stage: initial skeleton and independently authored locked tests; no agent code
accepted yet. The initial `src/main.rs` deliberately returns an error.

- Protocol: stdio JSON-RPC 2.0, legacy MCP 2025-11-25 initialize lifecycle.
- Crates: std plus pinned serde_json 1.0.154; no SDK downloaded or installed.
- Locked black-box tests: `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`.
- Trusted harness: `/home/onyx/Projects/rust-mcp-gateway-lab/`.
- Expected terminal state for an accepted attempt: `READY_FOR_USER_REVIEW`.
- Agent is restricted to source files; do not alter manifests, specs or tests.

No commit/merge/deploy of generated code without a manual review. All updates,
verification receipts, constraints and blockers should be appended here.

## Current verified state (2026-11-21)

The original M1 skeleton note above is historical. Milestone 1 is now
committed on `milestone1/manual-stdio` at
`54e1571245e5d19802b2a262ad44a19bbe3eec2d` and passes 17 Rust unit
tests plus 15 externally locked black-box tests. The canonical `main` branch
is intentionally unchanged.

The isolated `milestone2/service-contract` worktree starts from that M1 commit.
`SERVICE_ROADMAP.md` defines permanent per-client YOLO, managed services, and
the revised six-pass roadmap. `SPEC_M2_AUTH.md` defines Pass 1 loopback HTTP.
`M2_SECURITY_STATUS.md` records a new, **not-yet-integrated** Rust policy
module with 10/10 independent policy tests and 15/15 M1 regression tests
passing in the trusted network-disabled verifier. No YOLO mode, privileged
execution, HTTP listener, systemd service, service install, or production
cutover has been activated.

## Pass 1 baseline and acceptance boundary

The existing worktree passed the offline build, 17 Rust unit tests,
8 original stdio cases, 7 edge cases, 10 locked STANDARD policy cases,
formatting and Clippy with warnings denied. The three locked hashes match
their recorded values. The trusted Bubblewrap verifier also established that
loopback bind and connect work in its isolated network namespace.

The next gate is an independently authored and locked HTTP suite and its
expected failing baseline. A diagnostic probe confirmed the proposed HTTP
command exits 2 with the stdio usage message. The HTTP entrypoint,
credentials and permissions are specified in [Pass 1](SPEC_M2_AUTH.md). The prior stdio-auth plan in the M1
worktree remains historical. The Rust policy module and its tests are
preserved, including its denial of client-requested YOLO.

A Linux debug stdio baseline measured startup to initialize response at
0.852 ms median and 0.995 ms p95 (12 launches). Ping round-trip was 0.019 ms
median and 0.028 ms p95 (1,200 requests). Three idle samples were
2,828–2,900 KiB RSS and recorded zero CPU ticks over one second each at
100 ticks/sec. These measurements cover the existing stdio process.

### Dependency review

The upstream `rmcp` 3.11.0 release advertises `2026-07-28` and legacy
`2025-11-25` compatibility. The advisory review included the RustSec
tool-schema cache and DNS rebinding advisories and the upstream legacy
session-table advisory. The candidate version is newer than the listed
fixes for those three issues. Recheck the exact selected graph and transport
configuration before adopting it.
[Release and version support](https://github.com/modelcontextprotocol/rust-sdk/blob/rmcp-v3.11.0/README.md) ·
[Tool-schema advisory](https://rustsec.org/advisories/RUSTSEC-2026-0461) ·
[DNS rebinding advisory](https://rustsec.org/advisories/RUSTSEC-2026-0189) ·
[Session-table advisory](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-9pj6-vhgr-3mwh)

A disposable Linux `cargo tree --edges normal` comparison found 21 packages
for Hyper 1.12.0 HTTP/1 with Tokio 1.54.1 and minimal adapters, 39 for Axum
0.8.9 HTTP/1 with JSON, and 88 for `rmcp` 3.11.0 Streamable HTTP with Axum.
All included the existing serde_json pin. These counts exclude the scratch
application itself and cover the transport candidates before application
credential storage and policy dependencies. The Hyper graph also resolved
offline from the existing cache, while the exact Axum and rmcp graphs needed
a disposable online cache. The product manifest and lockfile remain at
their Milestone 1 pins. An exact-version OSV query over 89 distinct packages
returned one informational finding in the rmcp candidate. Its transitive
`chrono` 0.4.45 is marked unmaintained. Review that dependency before
adopting rmcp. The final application graph requires a fresh advisory check.
[RustSec chrono advisory](https://rustsec.org/advisories/RUSTSEC-2026-0543)

### Loopback transport probes

These disposable release-mode probes used Rust 1.100.0 and a single-thread
Tokio runtime. Each row covers eight launches and 800 sequential POST pings
over reused connections in the trusted network-disabled sandbox. Startup was
measured from spawn to reporting the bound port. The Hyper and Axum probes
parsed JSON and returned the matching ID. The rmcp probe used its actual
Streamable HTTP handler with legacy stateless mode and JSON responses.
Authentication, authorization, file I/O and adversarial load remain outside
these transport-only measurements.

| Candidate | Startup median / p95 (ms) | Ping median / p95 (ms) | Idle RSS (KiB) |
| --- | ---: | ---: | ---: |
| Hyper HTTP/1 | 0.760 / 0.823 | 0.050 / 0.142 | 2,992 |
| Axum HTTP/1 | 0.835 / 1.248 | 0.047 / 0.131 | 3,284–3,288 |
| rmcp with Axum | 0.802 / 2.409 | 0.055 / 0.121 | 5,660–5,704 |

Each candidate recorded zero CPU ticks in two one-second idle samples
at 100 ticks/sec. The low sample count and different protocol work limit the
comparison. Repeat measurements on the selected authenticated gateway
before claiming Pass 1 performance.

## Pass 1 authenticated HTTP — 2026-11-21

`PASS1_HTTP_REVIEW.md` records the completed **foreground loopback** Rust
implementation, pinned dependency versions, external SHA-256 test receipts,
and remaining protocol/security limitations. The earlier "no HTTP test" note
above is now historical. All five trusted acceptance suites passed **43/43**;
the existing Rust unit suite passed **17/17**, and the harness passed 34/34
unit/regression checks. The supplemental HTTP suite caught two GET
authentication/Origin validation defects before the targeted fix.

No merge, push, production service, remote listener, root execution, YOLO
mode or Funnel modification was performed. Pass 1 awaits code review; new
locked tests must precede Pass 2 tools and jobs.
