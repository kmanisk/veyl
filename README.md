# Rust MCP Gateway

A local MCP server with per-client tool grants, bounded file access, supervised
jobs, and a tamper-evident audit ledger. The HTTP server listens on loopback
and uses per-client bearer credentials. The foreground stdio server provides
read-only file access within an explicitly selected root.

## Build and run

Use Rust 2024 and Linux x86_64 for the supported HTTP and jobs configuration.
Managed job isolation also requires unprivileged Bubblewrap and Linux
namespaces. A cached dependency graph permits offline builds.

```sh
cargo build --release --offline --locked
target/release/mcp-gateway --help
target/release/mcp-gateway --root /absolute/path/to/workspace
target/release/mcp-gateway http --listen 127.0.0.1:7331 --config "$config"
```

Set `config` to an absolute path to an owner-only JSON client configuration.
Use a separate private directory for the audit ledger and job store. Store the
SHA-256 verifier of each independently generated bearer in the configuration.
Keep bearer values outside source, command arguments, and logs. See the
[configuration and profile contract](SPEC.md#phase-a-durable-supervised-jobs-on-linux).

## Client modes

| Mode | File tools | Job filesystem and network |
| --- | --- | --- |
| Managed Standard | Client root and explicit grants | Workspace sandbox, offline |
| Legacy scoped YOLO | Approved roots and explicit grants | Bubblewrap, approved roots, offline |
| FULL | Host-user access through granted tools | Supervised host execution using the gateway UID |
| Disabled | Denied | Denied |

Mode settings persist until a local operator changes them. Credential expiry
and grants remain separate from mode settings. FULL requires explicit
confirmation and a verifiable audit transition. FULL workloads have the same
Unix authority as the gateway operator and can compromise credentials, policy
and the ledger. Legacy unversioned configurations with operator-trusted job
profiles predate managed sandboxing.

```sh
mcp-gateway yolo status --client dev --config "$config"
mcp-gateway yolo enable --client dev --config "$config"
mcp-gateway yolo set --client dev --mode full --confirm-full --config "$config"
mcp-gateway yolo disable --client dev --config "$config"
mcp-gateway protected-paths list --config "$config"
mcp-gateway state check --state-root "$state" --config "$config"
mcp-gateway audit verify --config "$config"
```

Broad network-enabled YOLO remains gated. `yolo enable` selects scoped,
offline YOLO. The state checker inventories a proposed private layout, and the
protected-path CLI records desired rules for later enforcement. Neither command
starts a job or moves existing state.

## State and service

Job receipts survive the gateway process under the supervised runner.
The audit chain is local and can be rewritten by its owner. A retained
`audit export-head` checkpoint outside that owner's control can verify the
previously recorded prefix.

```sh
mcp-gateway service print-unit --config "$config"
mcp-gateway service install --dry-run --config "$config"
```

The service workflow prepares a systemd user unit. Installing a unit file is
explicit. Service activation is a separate operator action. Read the
[security and rollback notes](GATE3_BETA.md) before using a service.

The dashboard, skills, upstream MCP servers and terminal monitor remain
pending. See [checkpoint results and known gaps](STATUS.md).
