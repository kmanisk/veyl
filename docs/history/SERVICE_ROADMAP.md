# Rust MCP Gateway — Service requirements and delivery gates

The gateway ships as a Rust executable. The external Python lab coordinates
development and independent tests. The Milestone 1 stdio baseline is commit
`54e1571245e5d19802b2a262ad44a19bbe3eec2d` on `milestone1/manual-stdio`.
The service worktree retains the STANDARD authorization policy and its ten
locked tests. See [the current security status](M2_SECURITY_STATUS.md).

## Permanent per-client permissions

- **STANDARD** grants explicit tools and scopes. New and unrelated clients
  default to STANDARD.
- **YOLO** enables the gateway's approved tool categories within the service
  user's operating-system permissions. Individual command confirmations are
  unnecessary within those categories. Audit every operation performed under
  YOLO. OS elevation has its own approval and audit boundary.
- The trusted local operator uses `gateway yolo on --client <id>`,
  `gateway yolo off --client <id>`, and `gateway yolo status --client <id>`.
  Without `--client`, `on` requires explicit local selection, `off` clears all
  YOLO assignments, and `status` lists assignments. Local OS authorization
  protects these commands and their backing store.
- Persist assignments atomically in a protected operator-owned location.
  An assignment survives service restarts and reboots and remains in effect
  until explicitly disabled. YOLO has no lease, TTL, renewal, signing
  ceremony, or recurring approval prompts.
- Only verified local configuration can activate YOLO. Treat
  `ExecutionMode::YoloRequested` as client intent. MCP, HTTP administration,
  and dashboards cannot mutate YOLO configuration.
- Validate credential expiry and revocation independently of permission
  assignment. A revoked or expired credential loses access even when that
  client's YOLO assignment persists.

## Local emergency disable

`gateway yolo off` must work while HTTP is down, hung, or unreachable. It
atomically publishes and durably stores STANDARD for the selected identity
or all identities when no selector is supplied.
A successful publication invalidates active YOLO authorization immediately.
Coordinate publication with capability admission and the final dispatch of
privileged work. Existing sessions must consult the current authorization
generation before starting an elevated operation.

Cancel queued YOLO work. Request bounded cancellation of running privileged
jobs and contain their descendants through the job supervisor or privileged
controller. Keep read-only STANDARD work subject to its own grants. Already
completed side effects require a separate recovery decision. If termination
cannot be verified, record that state and keep escalation blocked. If the
service cannot read or validate current policy, deny YOLO and privileged
dispatch until valid configuration is available. Local emergency disable must
work without a remote administration endpoint. Report persisted disable and
outstanding job containment separately when the latter cannot be confirmed.

Independently test a down or stalled HTTP listener, policy read and reload
failures, concurrent dispatch, cached sessions, cancellation of queued and
running jobs, and restart with the disabled state. A persistence failure must
be visible to the operator and must never be reported as a durable disable.

## Privileged execution

1. Service-user tools run with the operating-system identity of the gateway.
2. Linux elevation uses an explicitly installed restricted host controller or
   reviewed sudo policy with a narrow operation allowlist.
3. Windows elevation uses a separately approved Windows service or UAC
   boundary.

Privileged capabilities may remain enabled until locally disabled. They
require separate authorization and auditable dispatch and results.
Unrestricted sudoers rules and automatic elevation of the service account
are prohibited.

## Remote access

Use separate credentials and scopes for each client. Prefer Tailscale Serve
for private YOLO connectivity when the MCP client can reach the tailnet.
Public Funnel requires separate local approval of the exposure and strong,
independently provisioned bearer tokens. Store protected token verifiers.
Immediately revoke or rotate credentials, rate-limit authentication failures,
and audit remote tool execution. Keep administration off public listeners.
Public admission of a YOLO-enabled identity is separately configurable and
disabled by default. Production BridgeDev and its Funnel routes remain outside
development scope.

## Permanent service lifecycle

### Linux

Provide an opt-in native systemd user service. Required CLI commands are
`gateway service install`, `gateway service uninstall`,
`gateway service enable`, `gateway service disable`, `gateway start`,
`gateway stop`, `gateway restart`, `gateway status`, and `gateway logs`.
Explicitly enabled installations must start across reboots. Make user
lingering a separate local opt-in where required for unattended startup.

Use restart-on-failure with bounded restart pressure, resource limits, clean
shutdown, and verified versioned updates with rollback. Prefer socket
activation or on-demand startup when compatible with reliable remote
connectivity. Development checks use isolated fixtures and never install or
enable the user's service.

### Windows

Provide a native Windows service with explicit installation, optional
automatic startup, clean shutdown, protected state, and separate elevation.
Verify lifecycle and permission behavior natively on Windows.

### Android and Termux

Evaluate a portable Rust executable, `termux-services`, and Termux:Boot as
experimental targets. Detect unavailable filesystem and process operations
and return explicit errors. Assume ordinary Android app permissions.

## Dependencies and performance

Evaluate maintained `rmcp`, `tokio`, `axum` or `hyper`, `serde` and
`serde_json`, `clap`, `tracing`, and appropriate cryptography,
credential-storage and filesystem crates. Before selecting dependencies:

1. Check the released SDK, protocol revisions and enabled transport features
   against authoritative upstream sources.
2. Review RustSec and upstream advisories for direct and resolved transitive
   dependencies. Pin the chosen versions and preserve an offline build path.
3. Compare feature-minimized dependency graphs against alternatives.
4. Compare idle RSS and CPU, startup, and request latency on equivalent
   workloads. Include bounded-input and concurrency behavior.
5. Choose the simplest stack that satisfies the compatibility and security
   gates. Record what was measured and how to reproduce it.

The historical stdio debug smoke measurement was about 2,828 KiB RSS,
1.43 ms initialization, and 3.6 ms for 200 buffered pings. HTTP and service
results need their own measurements.

## Six functional passes

| Pass | Capability | Independent acceptance |
| --- | --- | --- |
| 1 | Authentication, per-client STANDARD grants, and loopback MCP HTTP with the existing stdio path | Missing, wrong, malformed and expired credentials, rate limits, scoped reads, origin and loopback checks, and M1/policy regressions |
| 2 | Modular tools, bounded filesystem operations, process execution, durable jobs, cancellation, timeouts and recovery | Race-resistant containment, quotas, job cancellation and crash recovery |
| 3 | Durable audit, permanent per-client YOLO, local emergency disable, and separate OS elevation | Persistence, per-client isolation, local CLI-only activation, remote mutation rejection, immediate disable, offline emergency disable, token revocation, audit and independent OS privilege tests |
| 4 | Native Linux service, lifecycle CLI, explicit boot startup, verified updates and rollback | Isolated service lifecycle, clean shutdown, failure recovery and release rollback |
| 5 | Optional Tailscale remote access, revocation, separate administration and explicit public exposure | Private and public routing controls, revocation and rotation, admin isolation, public YOLO disabled by default |
| 6 | Windows service, process and permission adapters | Native Windows service lifecycle, access-control and elevation tests |

Experimental Termux, dashboard and TUI improvements, soak testing, and final
release hardening follow these passes. Continue only
[Pass 1](SPEC_M2_AUTH.md) in this worktree.

**2026-11-21 Pass 1 implementation status:** a foreground Rust Hyper HTTP/1
gateway and protected per-client admission are implemented and pass independent
tests; they are not committed, merged or enabled as a service. See
`PASS1_HTTP_REVIEW.md` for pinned hashes, measurements and remaining
compatibility/security caveats. Do not start Pass 2 implementation until the
Pass 1 review and its source/dependency changes are independently accepted.

## Locked acceptance

An independent author owns each externally locked oracle. Record its hash and
an expected failing baseline before implementation. Verify the hash before
and after running the suite in the trusted, network-disabled verifier. Preserve
both M1 suites and the ten policy tests, including the cases denying an
unverified YOLO request. Pass 3 adds its own independently maintained suite
for the cases above.

Preserve existing worktrees, review branches, and job evidence. A passing
development gate does not authorize a merge, push, service install, startup
enablement, deployment, or production route change.
