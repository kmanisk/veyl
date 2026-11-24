# Veyl execution modes and permissions

| Mode | Filesystem and execution | Tool grants |
| --- | --- | --- |
| Standard | Approved workspaces and offline sandboxed jobs | Explicit tool names |
| YOLO | Broad developer filesystem and networking inside Bubblewrap with mandatory protected paths | Native developer preset and explicit grants, subject to denials |
| FULL | Unconfined execution with the gateway user's Unix permissions | Explicit tool names. Requires `--confirm-full`. |

```sh
veyl state check --state-root "$state" --config "$state/clients.json"
veyl mode
veyl mode yolo dev
veyl mode get dev
veyl mode disable dev
veyl mode enable dev
veyl mode standard dev
```

Modes persist across restarts and apply to the next admitted request, including
requests on existing MCP sessions. The client's enabled state is independent.
Running jobs retain the profile recorded in their signed receipt. Credentials
retain their configured expiry. Use an unprivileged Linux account.

The YOLO preset enables native file, search, Git, context and diagnostic tools.
Job tools require a configured job store. Skill tools require a configured skill
store and reading a skill still needs an individual skill grant. Upstream MCP
still needs an explicit MCP tool grant and server/tool approval. A client can
set `"deny_tools": ["apply_patch", "system_inspect"]` in its trusted policy.
Denials take precedence over preset and manual grants. A deny also covers an
alias for the same action, such as `edit_file` for `apply_patch`.

### Upgrade an existing policy

`veyl mode migrate --config PATH` converts older policies to the current schema.
Canonical mode changes also migrate older policies when needed. An old scoped
authorization becomes Standard with its previously active, explicitly approved
workspace roots. Inferred sibling scopes and dormant legacy roots are discarded.
Previously approved broad authorizations retain their exact grants. Run
`veyl mode yolo CLIENT` to approve the native preset explicitly. Existing FULL
approvals, client identities, credentials and denials carry over. Historical
`veyl yolo` commands remain available for older automation, including the scoped
behavior of `yolo enable` on older schemas. They do not select the preset for
older policies.

## State and migration

Put the configuration directly in one dedicated `0700` state directory
owned by the gateway account. Put the audit ledger, job directory, keys
and related state beneath it. Use private regular files with exactly one
link. Keep workspaces outside that tree. The gateway rejects symlink
traversal, nested mounts within private state and visible alternate
mount aliases.

Keep executable helpers outside the state tree. For a Codex header
helper, use an owner-only directory such as `~/.codex/veyl-helpers/`,
which is covered by the YOLO mask. Keep the bearer it
reads in state. Update the helper path in the Codex client configuration
as part of the upgrade.

Prepare the state directory yourself. Stop admissions and let active
jobs finish. Keep a private rollback copy of the old configuration,
ledger segments, metadata, keys and receipts. Copy those objects into
the new directory, adjust the audit and job paths in the copied config,
and run the read-only state check on that layout. Activate broad YOLO
only after verifying the new layout. Veyl never moves existing state
during activation. Revoke broad authorization before reverting to a
binary that predates it. Preserve the audit history and use a policy
version supported by that binary.

## Sandbox and protected file tools

The supervisor assembles the broad filesystem inside Bubblewrap. It
makes selected host developer trees available under `/home`, `/tmp`,
`/var/tmp`, `/srv`, `/opt`, `/mnt` and `/media`. Runtime system trees
`/usr` and `/etc` are read-only. Ancestors of masked directories and
protected HOME paths are projected into a private tree. Existing safe
siblings remain available through descriptor-pinned mounts. Creation or
rename at a projected directory boundary stays in the sandbox. Create a
host workspace directory before sharing it with a job.

Veyl masks the entire private state directory, default sensitive HOME
directories, and configured optional masks. Existing default shell and
desktop persistence paths and ordinary Git hook directories at known
workspace roots are read-only. Custom Git hook paths and alternate
application startup mechanisms require explicit rules or separate
review. Files created at missing protected HOME paths remain sandbox
local. Unsafe or stale protected path identities fail closed.

Desktop directories can contain symbolic links. Veyl inventories links
without following them and checks real protected files for hardlink
aliases. A link inside a masked directory disappears with its containing
mount. A link inside a read-only directory cannot be replaced through
that mount. Its referent follows the policy for the referent's own
location. If a desktop mechanism loads a writable external referent,
protect that referent explicitly. Existing desktop socket entries are
accepted only beneath complete directory masks. Rules still reject
symlink roots and nested mount boundaries. The dedicated state tree
still rejects all symbolic links, sockets and executable regular files.

A guard executes after all mounts. It verifies the final masks, read-only
mounts, workspace identity, private PID and mount namespaces, non-root
UID, NoNewPrivileges, capability drop and descriptor checks before
executing the configured program. Broad file tools apply the same
mandatory path and object policy to descriptor-relative reads, writes
and patches. The gateway rechecks private state and hardlinks at job
admission and again in the runner. Runtime failure disables execution of
that job and never falls back to FULL.

## Threat model

Model A covers the untrusted job inside Bubblewrap, broad direct file
tools, and pre-existing symlink, hardlink and bind-mount aliases to
protected objects. The mounts protect the configured state and paths.
Independent copies and backups outside those trees remain ordinary
host files. Separate gateway instances sharing a Unix user need
coordinated protection rules.

Broad jobs share the host IP network. Localhost TCP and UDP services
remain reachable. The filter denies creation of AF_UNIX sockets, which
blocks pathname and abstract Unix connections from the job. Procfs runs
inside the private PID namespace. Veyl does not bind the host runtime
directory. It may bind the system resolver's individual file if needed.

A separately compromised same-UID host process outside the sandbox
is Model B. It can exercise the account's ordinary file authority,
including creating aliases after a preflight. It is outside the
containment claim. FULL is intentionally unsandboxed and carries that
authority. Use an audit anchor outside the gateway account to detect
rewriting of local ledger history.
