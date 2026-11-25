# TimeShift — 0.4.0-beta

Scope: native text mutation history. This is native text mutation history, not a filesystem snapshot or general-purpose backup system. Nightshift is out of scope.

## Authorization and use

TimeShift is opt-in per managed client. Grant `rewind` and `read_file` for capture and history. Grant `rewind_restore` and `write_file` for restore; grant `rewind_clear` and `write_file` for clearing retained history. The three rewind grants are excluded from the YOLO preset and dashboard bulk selection. Existing clients remain opted out until explicitly granted. FULL mode does not expose TimeShift. Current file scope, mode, protected paths, permissions and audit availability are checked by the normal gateway admission path.

- `rewind {"path":"src/example.rs","action":"list"}` lists the owner's retained checkpoints for a path; `status` returns the same metadata and total retained count/limit.
- `rewind {"path":"src/example.rs","action":"preview","checkpoint":"<id>"}` returns the original/current text, a changed-line region and a current checkpoint guard if restore is possible.
- `rewind_restore {"path":"src/example.rs","checkpoint":"<id>","current_checkpoint":"<guard>","confirm":true}` restores a retained pre-edit version. Use the guard from preview. The guard defaults to the requested checkpoint for immediate undo.
- `rewind_clear {"path":"src/example.rs","checkpoint":"<id>","confirm":true}` clears one retained checkpoint, not the source file.

The local dashboard's client grant section has a per-client retention setting (default 64, 1–256). Changing the setting does not delete existing history. At capacity, covered mutations and restore fail closed until the owner clears a checkpoint or the operator raises the limit.

## Persistence and security

Capture occurs within the native audited write path before publication. Records are HMAC-SHA256 authenticated with a private per-config/per-owner key. The store uses descriptor-relative, no-symlink/no-mount-crossing access, private directories/files, an exclusive advisory lock, bounded records and atomic publication. Snapshot content is stored as plaintext under the gateway's private state directory; the audit ledger receives metadata rather than file contents. Do not treat this as encryption or protection against the local account/root. Protect backups of the private state. Restart retains history; loss of an existing signing key fails closed. Interrupted private staging files are cleaned under the store lock.

Restore checks the current file against a signed post-write checkpoint (path, parent and inode identity, birth time, ownership, link count, mode/group where recorded, and content hash). Rewind uses the existing audited descriptor-pinned publication path and captures the version being replaced for redo. Stale guards, changed current contents, path escape, symlink/hardlink targets, foreign client records and tampering are rejected. Advisory locks and pre-publication identity checks do not eliminate the final race with a noncooperating external writer. Quiesce external writers before restoring.

## Coverage and limits

Automatic capture covers native UTF-8 `write_file`, `apply_patch`, `edit_file` and rewind restore when opted in. File sizes remain subject to existing native mutation and record size limits. New-file creation produces an inspection-only checkpoint; this beta does not delete files during rewind. Directory creation, shell commands, Git operations, binary changes and upstream provider mutations are not tracked. A version changed outside tracked tools cannot be restored until a valid tracked post-write guard exists. The preview is a changed-line region, not a complete unified diff. Retention is count-based, not time-based; no background worker or automatic eviction.

## Candidate verification

From the isolated source directory, with the adjacent optimized bundle:

```sh
(cd ../release-tui-bin && sha256sum -c SHA256SUMS)
MCP_GATEWAY_BIN="$PWD/../release-tui-bin/mcp-gateway" python3 -B tests/timeshift.py -v
```

No production upgrade, connector refresh, grant activation, commit or publication before exact-candidate operator approval.
