# Extended durable jobs — candidate acceptance

This candidate is based on main commit 33e9f56, version 0.2.5-beta.
No existing deployment or operator settings are changed.

## Policy

An operator-controlled version 3 client entry can opt into a maximum
runtime between 300 and 86400 seconds with `job_runtime_limit_seconds`.
Omitting this field preserves the existing 300-second maximum. Existing
exact grants, mode restrictions, protected paths, and job capacity rules
still apply. No MCP argument can change the configured limit.

For named job profiles, a timeout above 300 also requires
`"extended_runtime": true` in the profile. Both the selected client's
limit and the profile must permit the requested runtime. A named profile
is not required for `task_run`; the runtime field in its discovery schema
is specific to the client. `exec_command` remains capped at 300 seconds;
`run_command` keeps its two-second behavior. Changes to the client cap
apply at the next admission, without changing a previously admitted job.

Extended execution requires a working systemd user scope with the existing
CPU and memory ceilings and a supported kernel execution mode. The runner
enforces its signed deadline, and the manager receives the existing
RuntimeMaxSec backstop. Portable installations without a scope fail closed
for extended work. The resource ceilings (100% CPU and 256 MiB memory),
concurrency and retained log limits remain unchanged in this checkpoint.

Example synthetic version 3 client field:
```json
{"job_runtime_limit_seconds": 86400}
```

Example call, after the local operator permits the budget:
```json
{"command":"printf ready; sleep 30; printf done","timeout_seconds":7200,"wait_seconds":0,"request_id":"preview-1"}
```

Use job_status, job_logs with separate stream offsets, job_wait and
job_cancel to continue. An HTTP restart may report an active recovered job
as uncertain until the detached runner writes the terminal receipt; this is
intentional and does not authorize a duplicate launch.

## Personal acceptance

The isolated integration test starts its own temporary HTTP gateway and
state, with synthetic credentials and ephemeral loopback ports. It exercises
a two-hour caller-selected task and named profile, a 24-hour admitted job,
schema limits, log reads, duplicate request prevention, cross-client denial,
live limit reduction, gateway restart recovery and cancellation. These are
short-running tests of long-budget admission, not 24-hour endurance tests.

```sh
cd ~/.local/share/veyl-development/candidates/durable-budget.18J5Kerc/source
export MCP_GATEWAY_BIN="$PWD/../preview-bin/mcp-gateway"
export VEYL_MONITOR_BIN="$PWD/../preview-bin/veyl-monitor"
(cd ../preview-bin && sha256sum -c SHA256SUMS)
python3 -B tests/extended_jobs.py -v
```

The existing dynamic job and Linux integration suites are also applicable.
Independent AGY acceptance, the complete locked suite and operator
approval are required before promotion. Remaining parity gaps include
persistent stdin/PTY sessions, larger bounded log retention and resource
budget management, structured Git mutation/remote operations and Nightshift.
