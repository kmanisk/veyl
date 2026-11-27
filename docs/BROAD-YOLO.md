# Execution modes

| Mode | Authority |
| --- | --- |
| Standard | Explicit local tool and workspace grants. Command jobs use an offline Linux sandbox, fail closed when isolation is unavailable and retain scoped job limits. |
| YOLO | Native execution as the gateway user, normal host networking and host filesystem access. Locally confirmed selection activates the applicable development tools, subject to configured denials. |

Native commands can access files, local sockets, credentials, process state
and Veyl data visible to the gateway UID. Veyl disables privilege gains on
exec. Gateway authentication, client ownership, an audited local grant and
revocation protect MCP admission. Audit and private state are writable by
the same UID. Treat an approved native client as a remote shell for that
account. Choose Standard for clients that need workspace isolation.

## Upgrade and local confirmation

An older sandboxed YOLO entry has scoped Standard access on candidate
startup. Legacy preset tools and implicit scopes do not become native
grants. A valid audited FULL entry continues to receive native execution
with its explicit tools. This legacy selector has been retired.

```sh
veyl mode migrate --config /path/to/clients.json
veyl mode get CLIENT --config /path/to/clients.json
veyl mode yolo CLIENT --confirm-native --config /path/to/clients.json
veyl mode standard CLIENT --config /path/to/clients.json
```

Migration writes policy schema 4 under the local policy lock and records
the mode changes in the audit ledger. To recover an interrupted bulk
migration, use `veyl mode standard --all --config PATH` and review all
client grants before approving any native access. Disable revokes the
native grant. Enabling the same client restores Standard access. A
changed approval revision stops cooperating native job runners.

Managed OAuth uses the same native path. Choose YOLO during local consent
or use `veyl mode yolo CLIENT --managed --confirm-native` and reauthorize the
remote client. A legacy OAuth YOLO grant reads as Standard until the
operator gives fresh consent. Revocation and downgrade block admission
and stop cooperating native jobs, with an asynchronous check in the runner.

## Jobs and sessions

`exec_command` and `task_run` use the same signed detached runner, ownership,
cancellation, receipts and output limits. A returned job ID can be used
with `job_status`, `job_logs` and `job_cancel`. Use `request_id` on starts
that may be retried. A replay that differs in the command, scope or limits
fails. After gateway restart an active runner may appear uncertain until
it publishes a terminal receipt.

Newly confirmed clients can omit `timeout_seconds` to run until exit or
cancellation. For an explicit deadline, use seconds between 1 and the
client's configured maximum. Native dynamic jobs have optional CPU and
memory quotas. Enforcement of requested quotas needs the user systemd
manager. Output, concurrent jobs and retained receipts remain bounded.
With no available user manager, runners detach from the foreground process.
A service manager that kills the entire service cgroup can also stop such
a runner. Host reboot ends running Linux processes.

For native `process_start`, choose profile `shell` for a pipe session or
`pty` for a terminal. Use `process_input` with the documented sequence
number, and `process_resize` for PTY geometry. Local named profiles remain
available. Application output and goal progress are separate records.

See [durable goals](GOALS.md) and the [replacement acceptance contract](development/TWO_MODE_ACCEPTANCE.md).

## Recovery and rollback

Keep the verified 0.7.0-beta bundle and the updater's private backup. The
updater preserves policy bytes during executable replacement. Compatibility
is checked before restoring backup executables, and the updater refuses
rollback after policy bytes change since staging. After a compatible
installation succeeds, a private marker records the minimum executable
state format. A schema-4 policy, its audited migration intent, and a
managed OAuth profile also require a compatible reader. Older builds may
still verify the audit ledger and be unable to start the gateway.

For an interrupted policy migration, use the verified new executable to
run `veyl mode standard --all --config PATH`. This uses the current policy
under its lock, appends audit transitions, preserves disabled clients and
drops native grants. Review the recovered policy and verify the ledger
before restarting. Approve native access again separately.

When `update --recover` refuses the backup, keep the active journal and run
the recovery executable from a verified bundle:

```sh
/path/to/verified-bundle/veyl update --recover-forward /path/to/verified-bundle
```

Forward recovery installs a compatible executable while retaining the
current policy, audit history, jobs, credentials and goals. It resumes
the managed user service if the interrupted transaction recorded it as
active. Check `veyl service status`, `veyl audit verify --config PATH` and
an authenticated MCP initialization and read. If there is no active
journal, stop the failed managed service, reinstall the verified bundle
with `update --from-dir`, then start it and verify readiness.

Disabled legacy FULL clients migrate to disabled Standard. Re-enabling one
restores Standard. A separate `mode yolo --confirm-native` authorizes native
execution. Replaying an earlier activation state or a revoked native
approval fails audit verification.
