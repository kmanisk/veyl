# Veyl · Rust MCP Gateway

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
| Broad YOLO | Granted host-user file access with protected state | Bubblewrap, protected mounts, host IP networking |
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

Broad network-enabled YOLO uses a dedicated private state layout.
`yolo set --mode yolo` is the explicit opt-in. `yolo enable` still selects
scoped, offline YOLO. See the [broad mode and migration guide](docs/BROAD-YOLO.md).
AGY independently accepted 229 of 229 required cases for the separate Gate 3d execution-mode beta at commit `9d79200`.

## State and service

Job receipts survive the gateway process under the supervised runner.
The audit chain is local and can be rewritten by its owner. A retained
`audit export-head` checkpoint outside that owner's control can verify the
previously recorded prefix.

```sh
mcp-gateway service print-unit --config "$config"
mcp-gateway service install --dry-run --config "$config"
mcp-gateway service uninstall --confirm --dry-run --config "$config"
mcp-gateway serve plan --config "$config"
```

The service workflow prepares a systemd user unit. Installing a unit file is explicit. Uninstall removes only a matching gateway unit file and
leaves credentials, audit and jobs in place. The verified service supports
separate start, stop, restart, enable, disable and diagnostics commands. `serve plan` previews an MCP loopback route
without contacting or changing Tailscale. An optional `--state-file`
provides a read-only inventory of existing routes. Read the
[security and rollback notes](GATE3_BETA.md) before using a service.

## Local management and upstreams

Enable the optional [loopback dashboard](docs/DASHBOARD.md) to inspect
clients, jobs, resource usage, audit events, skills and external MCP
servers. Manage skills without executing package contents and expose
specific upstream tools to approved clients.

- [Skill import and per-client grants](docs/SKILLS.md)
- [Sandboxed stdio and Streamable HTTP upstream setup](docs/UPSTREAM-MCP.md)
- [Implementation checkpoints and verification status](STATUS.md)

The Linux candidate also includes the authenticated `veyl-monitor`,
bounded workspace search, read-only Git inspection, optional systemd
lifecycle and private Tailscale Serve configuration. See the
[Linux installation and rollback guide](docs/LINUX.md), the
[BridgeDev comparison](docs/PARITY.md) and [release evidence](STATUS.md).
