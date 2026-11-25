# Scoped upstream workspace inputs

The original workspace checkpoint was deployed at `2cf0ea0a96569e6952b9e161aebeb738e66aef36`. The provider-only folder editor is included in the verified 0.3.1-beta release.

## Job-enabled configuration

The strict job configuration deserializer accepts the same optional `upstream_workspace_roots` map as upstream admission. Job-enabled policies do not bypass root/provider/tool validation. Run `MCP_GATEWAY_BIN="$PWD/../release-bin/mcp-gateway" python3 -B tests/upstream_workspace_jobs.py -v` to verify exact 81-tool discovery, job execution, scoped calls, restart/reload, revocation and stale-root recovery.

## Operator configuration

Provider execution and tool grants remain separate from workspace delegation. Grant the native read and upstream-call capabilities and the reviewed upstream tool. The `workspace` command requires a folder inside an existing native client root (primary or explicitly permitted extra root). The separate, explicit `workspace-folder` command delegates a read-only folder without modifying any native root, job scope or execution mode. It requires managed policy, rejects another client's distinct primary workspace and protected paths, and persists the selected directory device/inode. An operator may deliberately grant a common parent of a shared native root (for example Projects). Explicit provider-only scope is independent of execution mode; revoke it separately when no longer required. A stale or removed folder denies its scoped calls across restart while the operator can still revoke or reapprove the grant. A workspace grant never inherits the entire broad YOLO filesystem.

Using the candidate executable and a **disposable** fixture configuration:

```sh
mcp-gateway mcp-servers workspace CLIENT rust-anything /absolute/approved/project --config /absolute/fixture/clients.json
mcp-gateway mcp-servers workspace CLIENT rea /absolute/approved/project --config /absolute/fixture/clients.json
mcp-gateway mcp-servers workspace-folder CLIENT rea /absolute/approved/projects --config /absolute/fixture/clients.json
mcp-gateway mcp-servers workspace-folder CLIENT rust-anything /absolute/approved/projects --config /absolute/fixture/clients.json
mcp-gateway mcp-servers unworkspace CLIENT rea --config /absolute/fixture/clients.json
```

The operator commands use the existing policy transaction and metadata-only audit. Each client may select one root per supported provider. Existing configurations have no delegation by default. Revoking a tool denies its calls even if the separate workspace grant remains; remove the workspace grant explicitly if no longer needed. Removing/uninstalling a provider removes its workspace grants. Provider discovery, health probes, and unrelated tools remain bundle-only. A provider fingerprint includes the selected workspace identity when a grant exists.

The local dashboard's Configured providers page provides a Workspace folders editor: client, provider, absolute host folder path, scope, explicit confirmation, current grant and revoke. The Custom integration page links to it and supports registering an already staged private runtime bundle. Browser directory upload is not used (it does not reliably expose absolute server paths). No new unauthenticated browsing endpoint is introduced. Folder mutations are local-dashboard-only, authenticated and CSRF/Origin checked. Arbitrary custom providers stay bundle-only until a read-only path schema is reviewed and implemented.

## Supported operations and limits

- Rust Anything `analyze(root)`: bounded read-only projection of a directory.
- REA `inspect_python_pyc(path)` and `inspect_rust_binary(path)`: a single selected regular file.
- Relative paths resolve against the grant, absolute host paths must be within it, and `/workspace` denotes the provider-side mount path. Explicit `/upstream/bundle` input retains old bundle-only behavior.
- Other provider tools (including commands, generated reports, SQLite/WAL, and WASM auxiliary inputs) do **not** receive host workspace access in this checkpoint.
- Root and selected paths are opened without symlinks. Workspace identity, operator ownership, explicit native or provider-only scope, configured protected paths, mount aliases and mandatory state exclusions are checked. The worker projects individual descriptor-pinned regular files, never a recursive host directory bind. Hardlinks, privileged file modes, and foreign-owner files fail closed; symlinks/special files are not projected. Dot entries, target, node_modules and __pycache__ are skipped in directory traversal. Explicit visible file selection can address build output. Limits: 256 files, 4096 visited entries, 32 levels, 128 MiB initial aggregate size. This is a live read-only projection, not an immutable snapshot: another authorized host process can still change source bytes. The provider may create ephemeral sandbox-local files, not alter host inputs.
- Only a valid authenticated session's scoped call can extend the outer HTTP timeout from five to at most thirteen seconds. Its worker gets an eight-second deadline; ordinary calls, discovery, probes and admin requests keep their previous deadlines. No automatic retries or permanent workers.
- An explicit workspace delegation trusts the selected provider to read the supplied input; operator review must consider non-hidden sensitive files in the selected project. No write delegation, networking, arbitrary host mount, or permission escalation is added.

## Verification

Run `MCP_GATEWAY_BIN="$PWD/../preview-bin/mcp-gateway" python3 -B tests/upstream_workspace.py -v` against the isolated candidate. The fixture simulates both providers to exercise read-only mounts, translation, traversal, alias denial, per-client separation, revocation, and scoped timeout behavior. Run actual pinned REA and Rust Anything against a disposable client-owned project in independent AGY acceptance; validate the protected-state and nested mount boundaries, stale identities, bounds, legacy configurations, and all locked tests. No production provider or policy changes are authorized by this document.
