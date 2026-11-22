# Gate 3 partial Linux development build

This build is for local evaluation. It includes the Gate 2 rollback
baseline, Disabled-to-Standard recovery, confirmed FULL execution,
offline audit anchors, and systemd user-unit preparation. Independent
Gate 3 acceptance is pending. The gateway binds only to loopback.

## Execution modes

| Policy | Job filesystem | Job network | Job confinement |
| --- | --- | --- | --- |
| Managed Standard | Approved workspace | Offline | Bubblewrap, stripped capabilities and NoNewPrivileges |
| Legacy scoped YOLO | Approved workspace and explicit existing scopes | Offline | Gate 2 Bubblewrap policy |
| Broad YOLO | Unavailable | Unavailable | Explicit activation fails closed |
| Confirmed FULL | Host user permissions | Host default | Host execution with NoNewPrivileges and supervised jobs |

The unversioned Milestone 2 fixed-profile execution path is inherited
compatibility for trusted local operators. Migrate to managed policy
before admitting untrusted jobs. File tools remain scoped even for FULL.
Authentication, grants, expiry, audit and job ownership still apply.
Revocation affects subsequent admissions. A running job retains the
execution environment it was admitted with.

FULL code can read or alter the gateway's same-UID secrets, policy and
audit records. It requires local trust equivalent to the gateway owner.
The confirmation flag records deliberate activation. It provides no
kernel authority boundary against a FULL workload.

## Configuration and migration

Use an absolute private JSON config path, owner-only credentials, and a
private audit directory separate from workspaces. See the distributed
example and replace all example paths and the verifier placeholder
locally. Use the SHA-256 of the existing 64-character lowercase
hexadecimal bearer credential as its verifier. Keep the bearer credential
outside process arguments and logs.

Version 1 continues to interpret existing YOLO approvals as scoped and
offline. Legacy `yolo enable` keeps that behavior. Standard and Disabled
settings, grants, credentials and job receipts retain their established
meaning.

Version 2 records a confirmed FULL transition. Startup requires a
matching successful mode-specific audit record. A stale revision cannot
restore FULL after a later Standard transition.

```sh
./mcp-gateway http --listen 127.0.0.1:7331 --config "$config"
./mcp-gateway yolo status --client dev --config "$config"
./mcp-gateway yolo reset --client dev --config "$config"
./mcp-gateway yolo set --client dev --mode standard --config "$config"
./mcp-gateway audit verify --config "$config"
```

The high-trust operator workflow supports `yolo set --mode full
--confirm-full`. Review the client and its workload before granting it.
The current beta refuses `yolo set --mode yolo` until broad isolation is
verified. Mounting a writable host tree and masking individual paths is
insufficient. Synthetic probes demonstrated an unmasked hardlink and
loss of the mask after a same-directory atomic replacement. Directory
isolation, protected-object identity checks, persistence mounts and
direct file-tool parity remain pending.

## Audit checkpoints

```sh
./mcp-gateway audit export-head --config "$config" --out "$anchor"
./mcp-gateway audit verify --config "$config" --anchor "$anchor"
```

Export creates a new file and refuses replacement. Keep a copy of the
anchor outside the gateway user's write authority. The local
`.ledger-id` belongs with the audit history. Verification checks the
identity and anchored prefix across later appends and rotation. A
same-UID actor can still rewrite the whole local ledger and local anchor.

## Service planning

Use `service print-unit --config "$config"` or `service install --dry-run
--config "$config"` from the actual extracted binary. Use the printed
absolute executable and config paths. The distributed unit illustrates
the defaults. It requires adapting paths to the intended binary and
operator configuration.

The gateway drains HTTP on SIGTERM and preserves detached runner leases.
The unit limits restart bursts, memory and tasks. Its process-only stop
policy preserves existing runner behavior. `install --confirm` publishes
a non-replacing user unit file. Unit activation is a separate operator
action. This build was verified with temporary unit files and was never
installed or enabled.

## Requirements and rollback

The evaluated build targets Linux x86_64. Managed Standard and scoped
YOLO require an unprivileged Bubblewrap installation with the user,
mount, PID and network namespace capabilities used by Gate 2. Keep the
existing audit and job directories during binary replacement.

The local rollback tag is `gate2-scoped`. Gate 2 rejects policy schema 2.
For rollback, revoke FULL, stop the beta, and use a separately verified
version-1 policy backup that cannot resurrect revoked authority. Preserve
audit segments and receipts. Validate the effective client configuration
before resuming service. Keep subsequent audit approvals and independent
anchors as evidence. For a previously unversioned policy, verify the
approved legacy behavior explicitly before restarting any jobs.
