# Persistent process sessions

The isolated Linux candidate is based on `33e9f56`, version `0.2.5-beta`.
It preserves the operator-verified extended job implementation. Process
sessions keep one sandboxed process alive across MCP requests. A shell profile
therefore retains its working directory, exported variables and functions
until reset, timeout or exit.

## Personal verification

Run with Bubblewrap, an unprivileged systemd user manager and Linux devpts
available. The test starts its own loopback listeners and uses disposable
credentials, configuration, workspaces, scopes and audit files.

```sh
cd ~/.local/share/veyl-development/candidates/persistent-process.GgGwXhSb/source
MCP_GATEWAY_BIN="$PWD/.candidate-preview/sessions/mcp-gateway" python3 -B tests/process_sessions.py -v
```

The candidate also includes `.candidate-preview/sessions/veyl` and
`.candidate-preview/sessions/veyl-monitor`. Logs and binary checksums are in
`.candidate-preview/logs/`. See STATUS.md for exact gate results.

## Configure and use an owned session

A local operator adds named, interactive profiles under `job_profiles` in
the usual managed Veyl config. Each process tool needs a separate client tool
grant. The native YOLO preset does not include the process tools.

```json
{
  "shell_pipe": {
    "executable": "/usr/bin/sh",
    "args": ["-s"],
    "interactive": true,
    "extended_runtime": true,
    "timeout_seconds": 86400,
    "max_output_bytes": 65536
  },
  "shell_pty": {
    "executable": "/usr/bin/bash",
    "args": ["--noprofile", "--norc", "-i"],
    "interactive": true,
    "pty": true,
    "timeout_seconds": 300,
    "max_output_bytes": 65536
  }
}
```

The configured client runtime ceiling still applies. A profile and the client
must both authorize the full 86,400-second budget. `process_start` may request
a shorter timeout. The operator controls the program and arguments through the
profile. The gateway uses the client's configured working directory and
launches the existing signed runner, sandbox and systemd resource scope.

| MCP tool | Example arguments | Behavior |
| --- | --- | --- |
| `process_start` | `{"profile":"shell_pipe","timeout_seconds":30,"request_id":"dev-shell-1"}` | Starts the named profile. Returns `job_id` and `transport`. Repeating the same client-scoped request ID and admission fingerprint returns the same job. |
| `job_status` | `{"job_id":"<id>"}` | Reads the signed job status and transport. Wait for initial admission before sending input. |
| `process_input` | `{"job_id":"<id>","sequence":0,"data":"cd src\n"}` | Admits at most 4,096 UTF-8 bytes. Sequence starts at zero. Inspect the returned status and `next_sequence`. |
| `process_input` | `{"job_id":"<id>"}` | Reads the current input sequence and closed flag after reconnect or an uncertain response. |
| `process_input` | `{"job_id":"<id>","sequence":1,"eof":true}` | Closes the pipe writer. For PTY, closes the master and returns `hangup` with `stdin_closed:true`. Read terminal output first if needed. |
| `job_logs` | `{"job_id":"<id>","stdout_offset":0,"stderr_offset":0,"max_bytes":4096}` | Reads capped output at independent byte offsets. Advance each cursor from the corresponding next offset. |
| `job_cancel` | `{"job_id":"<id>"}` | Cancels the owned process tree using the existing runner. |
| `shell_reset` | `{"job_id":"<id>"}` | Reconciles termination and starts one fresh instance of the original profile. Returns a new job ID with sequence zero. Requires current start, reset and cancel authority. |

A duplicate sequence returns `sequence_consumed` without writing again.
`out_of_order` and `backpressure` leave the sequence unchanged. On an
uncertain exchange, query the runner before deciding whether to resend. Keep
one sequence allocator per job if multiple MCP sessions share it. A consumed
sequence means one request won that slot and does not identify its payload.
Kernel delivery or runner queue admission does not prove that the program
parsed or executed the bytes. A job that has ended refuses further input.

A pipe session has separate stdout and stderr, no TTY and actual pipe EOF.
The PTY profile allocates a kernel master/slave pair with a private resource
scope. The program receives a controlling terminal at 24 rows by 80 columns.
The combined terminal stream uses the stdout cursor. The terminal can echo
input into retained job output according to its line discipline. Output
excerpts are UTF-8 previews. Binary terminal streaming and window resizing
are outside this checkpoint. Use `exit\n` for a shell's normal exit, or
`eof:true` for an explicit terminal hangup.

## Security and recovery

- HTTP reauthorizes the authenticated owner on every operation. Input also
  requires the current start grant and the same signed mode, root identity,
  workspace mounts, protected policy and compatible profile/runtime limits.
  Disablement, expiry, grant revocation and restriction changes apply on
  subsequent admission. Previously admitted processes and input retain the
  original execution context until their normal exit, cancellation or limit.
- The detached scoped runner owns a bounded Linux abstract datagram endpoint.
  Requests and responses carry a MAC derived from the private receipt key,
  signed per-job launch nonce and job ID. The gateway verifies the peer on
  its connected socket before sending any input bytes. The runner verifies the current
  locked policy snapshot digest, credential expiration and monotonic request
  deadline at delivery. Scope, receipt and process identities are checked
  through existing job machinery. No pathname socket, FIFO or spool file
  must be mounted in the workload.
- The existing Standard and Broad YOLO sandboxes deny AF_UNIX socket creation
  and protect the job store and host process descriptors. The only workload
  input descriptor is its own pipe or terminal slave. PTY allocation opens
  the slave by ioctl from the pinned master descriptor. FULL and unmanaged
  sessions are unavailable because they cannot provide the same isolation.
  Independent same-UID host processes, including FULL workloads, retain
  their existing host-level authority over Veyl state. Keep them trusted.
- Pipe writes are bounded and nonblocking. A PTY has one bounded 4 KiB pending
  frame with a kernel-write cursor. Runner queues hold no durable input.
  The audit ledger records operation metadata, never input text or
  credentials. Job output remains available to its owner and may contain
  application output or terminal echo. Avoid entering reusable secrets.
- A gateway restart preserves the live runner, input sequence and process
  state. Reconnect with the same authorized identity and the signed job ID.
  A recovered receipt may say `uncertain` until the runner publishes a
  terminal record; a successful input query confirms the live channel.
  The gateway never recreates an exited runner or replays its input.

## BridgeDev comparison

BridgeDev `b21616a` separates sticky shell working-directory state in
`persistent-shell.ts` and `global-shell-state.ts` from background process
tracking in `src/tools/shell.ts`. Veyl provides live shell state per owned
session and reuses signed job status, incremental output, cancellation and
history. It does not share an implicit shell across unrelated calls, delete
signed history with `clear_processes`, or offer a root-controller equivalent.
