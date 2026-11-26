# Veyl modular architecture — migration contract

Operator direction (2026-11-26): stop platform feature expansion until the common architecture is established. One product, one shared Rust core, separately versioned connection interface, native adapters per OS. This is a structural migration, not a rewrite or an authorization change.

## Dependency direction

```text
Client surfaces: CLI | TUI | dashboard | private MCP | reviewed public plugin
                               |
                        transport adapters
                    stdio / HTTP / connector
                               |
                       shared Rust core
                  credentials / MCP lifecycle
                  [next: capability and policy contracts]
                               |
                    authorized operation ports
                               |
                 Linux | Android | Windows adapters
```

Connector is a separate control plane, not an OS adapter and not a privileged execution backend. It owns account/device identity, pairing and the versioned remote wire interface; it cannot override device-side permission or sandbox policy. The device adapter owns actual execution. Transport adapters perform admission and invoke the core; portable core must not import transport, platform, host filesystem, process, or UI implementations. Keep the existing Cargo package and lockfile during migration; split independent crates only when dependencies/publication boundaries are demonstrably stable. Do not add an always-running component merely to achieve modularity.

## Actual first structural checkpoint

- `src/core/credential.rs`: shared token validation, digest encoding, verifier selection.
- `src/core/protocol.rs`: shared JSON-RPC validation, session initialization, request/notification handling, discovery and dispatch; only typed JSON values and caller-provided tool callbacks. Server identity is supplied by adapter. No filesystem, OS, HTTP, or privilege dependencies.
- `src/protocol.rs`: compatibility adapter supplying gateway file/inspection operations to the shared core. Linux and Android use this adapter; legacy stdio wire behavior and existing tests are preserved.
- `src/platform/linux/cli.rs`: Linux-only command routing, native services/jobs and legacy transport bootstrap. Existing Linux filesystem, jobs, policy, audit and dashboard modules remain at original paths to limit regression risk.
- `src/platform/android/http.rs`: Android-only HTTP admission and native operation wiring. `src/platform/private_workspace.rs` remains the existing tested native reader/mutator.
- `src/connector/`: separate connector implementation, foreground device agent, Linux preview registry store. `src/bin/veyl-connector.rs` is now an entry point only. Connector uses shared core MCP sessions and credentials, retaining owner-scoped device catalog, registry and heartbeat protocol. It now requires the complete MCP initialize payload (clientInfo and capabilities) like the native gateway; the existing valid clients are unaffected.
- `src/main.rs`, `src/legacy_main.rs`, `src/gateway_main.rs`: compatibility binaries and shared startup composition. Windows remains fail-closed.

## Actual second structural checkpoint

- `src/core/capability.rs`: shared Action and ExecutionMode identities and their existing classification/labels. Linux authorization re-exports these types; filesystem/path and lease enforcement remain in the existing security adapter.
- `src/core/tools.rs`: the existing 71 native tool names, action mappings, schema constructors and preset classifications, extracted without altering the Linux catalog. Native operation implementation stays outside the core.
- `src/core/workspace.rs`: explicit typed private-workspace grants and six portable Android-profile tool schemas, including the shared Linux read schema. Both Android stdio and HTTP use the same read-path argument contract; HTTP mutation semantics remain SHA-256 guarded and unchanged. Different Linux/Android write schemas remain intentionally distinct until the native enforcement contracts converge.
- `src/gateway_main.rs`, `src/protocol.rs`, `src/transport.rs`: legacy Linux file access and tools are gated to Linux; Android HTTP uses the shared Session directly. Linux-only legacy unit tests remain active on Linux; portable library and native integration tests cover Android. No warning suppression.
- `tests/linux_features.py`: corrected the repository-owned PTY test to assert command/target detail, d-key JSON, reverse toggle, mouse and keyboard navigation. External locked tests and pins are untouched.

## Actual third structural checkpoint (0.5.0-beta candidate)

- `src/core/session.rs`: shared owner/scope binding, monotonic idle expiry, touch and opaque random identifier generation. Linux retains its public/private scope and 48-character session IDs; Android and the connector retain their 64-character IDs. Linux rejects an ID collision rather than replacing an admitted session. Capacity, synchronization, admission and wire errors remain adapter-owned.
- `src/http_common.rs`: shared strict single-header lookup and exact bearer parsing. Linux uses the shared bearer parser; Android and connector use both. Endpoint-specific Host/Origin, content type, body limits, role checks, Funnel proofs, rate limits and policy revalidation remain separate. The dashboard consumes the shared session view and random generator without changing its cookie or CSRF format.
- `src/core/lifecycle.rs`: shared audit action/phase, job state and exit reason, and metadata-only operator activity types. Linux audit/receipt/activity adapters use these definitions directly. Android maps its existing journal outcome vocabulary (rejected versus Linux failure) without changing storage formats or definite-outcome checks. Linux serde encoding is unchanged; portable types compile without Linux-only serde dependencies.
- `src/core/timeshift.rs`: checkpoint identifier validation and typed line-region preview with unchanged JSON fields; consumed by Linux TimeShift. Signed checkpoint storage, stage proofs, native authorization and restore publication stay Linux-specific.
- Version 0.5.0-beta is operator-authorized for the candidate. The package contains four binaries; the existing native updater continues to manage the three original Linux executables. The connector is packaged separately as an optional, foreground-only preview. No connector service or public endpoint is installed.

These are shared contracts, not Android or Windows execution, audit-ledger, TimeShift or UI parity. Full locked acceptance, native Android verification and exact release approval remain separate gates.

## Contract preservation

Preserve executable names, all existing native tool names/schemas, Linux/Android local state formats, per-client mode/grants, credential formats and current release version. Core never interprets YOLO/FULL as root. Platform capability availability is not equivalent to authorization. Existing connector API 1, pairing identity, stored replay sequence and catalog remain compatible with accepted clients. Breaking state/API changes require explicit migration, rollback and tests. Keep stable connector identity separate from platform binary updates and preserve existing plugin URL. No public route or plugin submission in this architecture checkpoint.

## Remaining migration order

1. Complete shared permission/capability and typed tool invocation contracts; adapters supply existing local admission and actual operations. Start with read-only operations, then mutations, audit and jobs, preserving each platform's security semantics.
2. Isolate connector registry domain, transport and device wire protocol further; use shared version negotiation and admission; keep local admin separate from reviewed public operations.
3. Extract portable audit/event/job lifecycle data and UI status contracts from Linux-specific implementations. Linux remains reference, no weakened enforcement.
4. Establish Linux and native Android compatibility matrix (same protocol, same accepted schemas, native negative tests, full independently pinned Linux suite). No broad feature claims from host-only builds.
5. Resume Android features: command worker containment, jobs, PTY, and service lifecycle. Then stable authenticated HTTPS/account pairing, separate ChatGPT plugin and mobile smoke. Windows later.

No whole-tree rename merely for aesthetics. Each extraction must have an actual consumer, one source of truth, and regression evidence. Do not resume Android feature expansion until operator accepts the modular foundation and remaining dependency seams are recorded. The public connector is still an experimental local preview; native8 and previous accepted builds remain preserved.
