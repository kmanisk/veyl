## Implemented onboarding and per-connection OAuth mode lifecycle

Users do not need to manage raw OAuth profile paths, JSON manifests, or
manual port selection. The supported front door is `veyl login`, `veyl logout`,
and `veyl mode`. Direct custom MCP remains the client connection mechanism;
login means local device onboarding and OAuth authorization, not a Veyl-hosted
account.

Implemented workflow:

- `veyl login`: interactive normal-user command, defaults new connections to
  Standard, supports interactive workspace selection (defaulting to CWD, or
  `--root DIR`), validates Tailscale login/MagicDNS/HTTPS/Funnel eligibility
  with actionable error guidance, allocates a free dedicated Funnel port
  (`8443` or `10000`), creates/resumes an owner-private managed profile at
  `~/.veyl-login/profile`, prints and copies the public `/mcp` URL to the
  clipboard when a display clipboard is available, and opens the paired local
  dashboard (`--no-ui` suppresses). Requires explicit operator confirmation
  before first public exposure; reuse saved issuer across restarts; refuse
  duplicate instances cleanly.
- Connection approval: Dashboard `#oauth` and local OAuth consent API show
  **Standard** selected by default and allow explicit local selection of
  **YOLO** (`BroadYolo` preset) with full mode-bound `scope_fingerprint`,
  masked/read-only protected paths, and resource ceilings (`<=300s`, `<=100%`
  CPU, `<=256 MiB` RAM, `MemorySwapMax=0`, `TasksMax=128`, `<=64 KiB` output)
  displayed before confirmation. No remote parameter or DCR metadata can select
  or elevate a mode.
- Per-connection mode switching (`veyl mode` & Dashboard `#oauth`):
  - `veyl mode` / `veyl mode list` lists registered OAuth clients and modes.
  - `veyl mode yolo [CLIENT | --all]` persists YOLO onto `oauth-state.json`
    and immediately revokes existing Standard grant families so escalation
    always requires fresh OAuth authorization + explicit local approval.
  - `veyl mode standard [CLIENT | --all]` persists Standard and downgrades
    active grant families immediately so elevated admissions and pre-spawn
    runner checks deny elevated operations immediately without waiting for
    token expiry.
  - Existing `--config PATH` native commands remain unchanged and compatible.
  - `FULL` remains strictly disabled over public OAuth.
- `veyl logout`: supports individual-client logout (`veyl logout --client ID`,
  interactive selector when >1 client connected on TTY, leaving other clients
  and gateway alive) and explicit all-client logout (`veyl logout --all`,
  stopping managed instance/Funnel route and revoking all registrations and
  grants cleanly on both live and offline profiles, recovering interrupted
  `.logout-pending`).
- Existing low-level `veyl oauth setup/run` remains compatible for isolated
  scoped and bounded-workspace profiles. Live external AI client acceptance
  still precedes production release.

## Active architecture and release contract (2026-11-27)

Operator decision: direct OAuth Streamable HTTP MCP over a public HTTPS
tunnel is the product path. Keep native Linux execution, existing permissions,
local consent, durable OAuth, resource bounds, jobs, dashboard/TUI and
upstreams independent of client branding. The current managed tunnel provider
is Tailscale Funnel. Other reverse proxies are future compatibility work,
not implicitly implemented. Hosted relay/accounts and a standalone plugin
package are deferred; preserve their experimental code without requiring
them for installation or release. Existing bearer/secret-path connections
remain compatible. Windows/Android native gateway ports are not implemented;
remote mobile client access is a separate client capability.

All local/simulated acceptance gates passed (AGY 293 locked/supplementary,
217 Rust, full advanced mounted Funnel 5/5; BridgeDev hashes and focused
regressions). Live HTTPS discovery from the host passed; a private package was
created but offered a desktop launch, and the browser custom MCP creation
form failed before successful DCR. Do not claim live ChatGPT interoperability.
Use a direct connection for the next test; a plugin package is not a gate.

Release checklist (real remote client, record client/platform/account):

1. Start an isolated read-only preview; verify discovery from outside the
   host where possible, OAuth DCR, exact local approval, and read a synthetic
   canary.
2. Provision a separate operator-approved bounded tmpfs fixture (64 MiB,
   4096 inodes, UID-owned mode 0700, nosuid,nodev). Use a new profile with
   explicit `--workspace-edit --workspace-jobs --job-profiles ABSOLUTE_FILE
   --funnel --funnel-advanced` and the approved named command profile;
   add dynamic commands only when explicitly needed. Use a free dedicated
   port, preserve existing routes. Run a real write tool, independently
   verify bytes, and run a harmless sandboxed command. Confirm tool
   availability in the user's actual ChatGPT account; never substitute
   simulated success for client support.
3. Stop/resume the same preview with exact flags, profile, issuer and mount;
   verify a real client reconnect and token refresh where supported. Revoke
   its grant locally, confirm the old authorization fails, and verify
   fresh approval restores only the intended scope. Never reuse credentials
   across a recreated tmpfs.
4. Test the user's Android client with the verified connection. Record
   unsupported/unavailable separately; optional Claude fallback requires its
   own real OAuth and tool tests. Do not make native mobile support a claim
   or introduce a hosted service merely to work around client limitations.
5. Record evidence and remaining client limitations. Operator approval of
   the exact candidate and explicit version instruction precede deployment
   under AGENTS.md. No additional full AGY rerun unless runtime changes or
   new security defects require it.

## Current checkpoint — resource-hardening (2026-11-26)

Public writable OAuth admission requires a verified dedicated, private UID-owned tmpfs mount with maximum 256 MiB and 16384 inodes; ordinary directories are rejected. Revalidation is performed at startup, consent, admission, recovery and signed worker launch. Job scopes verify memory.swap.max=0 and pids.max<=128 in addition to the existing CPU and memory controls. No persistent project quota backend, aggregate multi-profile resource limit or limit on trusted upstream side effects is implied. Read-only profiles remain available. Local pinned acceptance passed after the readiness correction, but independent acceptance of the exact final candidate, full mounted advanced positive test and real external OAuth/Plugin Creator test remain release gates. See STATUS.md.

## Current checkpoint — advanced capabilities implemented (2026-11-26)

The candidate now supports explicit `--funnel-advanced` with `--funnel` and separately selected job/upstream scopes. This supersedes the earlier local-only implementation checkpoint below, not the requirement for independent acceptance before live exposure. Durable grant publication and runner admission are serialized. The private ChatGPT packaging generator validates a real HTTPS OAuth discovery endpoint before packaging, with no embedded secrets. Simulated ingress tests pass; real external endpoint and ChatGPT installation are pending. Arbitrary workspace writes require a bounded test filesystem; disk quotas are not enforced by Veyl. See STATUS.md and HANDOFF.md for exact verification and release gates.

Operator direction, 2026-11-26: implement the direct-tunnel plan first. The hosted multi-user connector and universal official plugin are deferred; see PUBLIC_CONNECTOR_PLAN.md for that alternative. Preserve the verified 0.5.0-beta Linux service, existing private app, secret-path compatibility, grants, skills, upstream MCP, jobs, TimeShift, dashboard and TUI.

Web AI services need a reachable public HTTPS resource. Private Tailscale Serve is not public access. Funnel exposes a user's endpoint; it does not require the AI service to join the tailnet. Cloudflare named tunnels and operator-provided HTTPS reverse proxies are alternatives. Direct mode does not provide a universal public plugin identity or eliminate custom connector setup. No claim of unlimited free tunnel bandwidth.

## Current checkpoint: dedicated foreground Funnel provider

### Local OAuth upstream and dynamic-command capability gates

Fresh `--workspace-upstreams --upstream-manifest ABSOLUTE_FILE` setup and
`--workspace-upstreams` recovery copy strict duplicate-rejecting JSON
provider definitions into the isolated policy. One to four trusted
providers with 1–16 exact tools each; offline trusted system stdio,
no external script mounts or bundles, or credential-free IPv4 loopback
HTTP. No provider workspace mounts, inherited credentials or private CA.
Scope fingerprint covers exact definitions and per-tool grants; discovery
and calls use family-derived audit principals. New upstream connections
have fresh protocol sessions but shared provider application state is
explicitly disclosed. No public upstream grants. See STATUS.md for
208 Rust, 74 integrations, browser probes and 28 locked pin receipts.

Fresh `--workspace-jobs --workspace-interactive` setup and matching
recovery flags add persistent pipe/PTY process sessions (`process_start`,
`process_input`, `process_resize`, `shell_status`, `shell_reset`) reusing the
native `src/jobs/session.rs`, `channel.rs`, `terminal.rs`, and `runner.rs`
supervision path inside the offline writable workspace sandbox and mandatory
systemd user ceilings (maximum 300s, 100% CPU, 256 MiB RAM, 65536
bytes/stream, 4096-byte input frames, no `extended_runtime`, no public
`--funnel`). Runner-side datagram verification (`Channel::step` +
`verify_oauth_grant`) checks both the native policy snapshot
(`PolicyFile::input_snapshot` + `expires_at`) and sealed durable
`oauth-state.json` active family membership, client registration,
`access_until_ms`, and `family_until_ms` so OAuth revocation and token expiry
fail closed at the runner IPC boundary while token refresh and gateway
restart retain per-family ownership. Interactive tool calls record
metadata-only durable audit entries without logging raw stdin or bearer
tokens. Public Funnel activation remains on HOLD.

Fresh `--workspace-jobs ... --workspace-commands` setup and matching
recovery adds dynamic exec_command/task_run, with no implicit widening
of existing profiles. Operator consent explicitly shows arbitrary code
execution, offline writable workspace, root-only cwd, resource ceilings
(300s/100% CPU/256MiB/65536 bytes per stream), maximum two-second
synchronous wait, no ephemeral worktree or interactive execution.
Both APIs use the existing family-owned signed receipts and mandatory
resource-controlled sandbox. Scope unavailable denies launches; local
operator can still inspect and cancel jobs after remote revocation.

### Subsequent local named-job capability gate

The isolated OAuth candidate adds `--workspace-jobs --job-profiles ABSOLUTE_FILE` to fresh setup and `--workspace-jobs` to recovery. A trusted local JSON object containing job_profiles is strictly deserialized and normalized through the existing native Profile parser, with 1–16 named profiles, root-owned system executables under /usr/bin, no interactive/PTY/extended-runtime profiles, maximum 300s, 100% CPU, 256 MiB and 65536 output bytes. The JSON is copied into the new private policy; it is not read remotely or reused on restart. Setup and recovery explicitly refuse combining jobs with Funnel. Job profiles grant seven tools (run_command, job_start, job_status, job_logs, job_cancel, list_jobs, job_wait) plus the separately selected file tools. job_wait has an explicit timeout of 0–2 seconds. Native Standard policy and durable OAuth scope fingerprint still govern admission. The consent interface shows the named profiles and makes writable workspace access explicit, including when file editing tools are absent.

Each admitted job owner is a domain-separated SHA-256 identifier over native principal, OAuth registration and family identifier; no raw credential is stored. Signed receipts add an optional oauth_family marker, omitted for legacy receipts. All normal job APIs keep exact owner filtering; an authenticated local dashboard in this isolated profile aggregates family receipts and resolves the owner from the signed record for local logs/cancel, including revoked registrations. Existing native owner policy is unchanged. Job launch and runner independently reject hardlinks, special files, traversal limits and cross-mount workspace entries via descriptor-relative checks (16384 entries, depth 64, 2s each scan). Standard sandbox restricts mounts/network and the existing manager-side resource backstop is mandatory for new OAuth starts; without a valid user scope, new launches and new consent fail closed while job status/logs/cancel remain available. No guarantee against arbitrary concurrent outside same-UID mutations. Running jobs keep their admitted sandbox after token revocation until they end or are canceled locally. Existing bounded receipt retention applies; this is not infinite deduplication history. No dynamic shell, PTY, broad modes, public jobs or upstream grants in this checkpoint.

The isolated Linux OAuth candidate now integrates Tailscale discovery, capability/certificate-domain preflight, collision-free dedicated port selection, conditional LocalAPI configuration and foreground IPN-bus session ownership. `veyl oauth setup --funnel --root DIR --profile NEW_DIR` selects a public HTTPS issuer; `veyl oauth run --funnel --profile DIR` reuses the persisted issuer. Optional `--funnel-port 8443|10000` constrains selection. A changed hostname, unavailable saved port, invalid saved state, concurrent owner or missing capability refuses startup. This is a development interface, not an instruction to activate a public route before acceptance. No new daemon, dependency, persistent Serve config, admin forwarding or installed service is needed. Actual listener addresses and `OAUTH_FUNNEL_URL` are announced only after read-back verification and audit; this URL is not a claim of external reachability.

Implementation in `src/tailnet/oauth_provider.rs`: GET status/config and open the foreground `watch-ipn-bus?mask=18`; require a bounded initial running-state event with valid session ID; insert only that session's route using current ETag, verify the exact resulting route and collisions; on shutdown close the owning connection and check removal. Loss of the bus terminates the gateway. Proxy envelopes are checked, never authentication; private Serve traffic to the same HTTPS name must also complete OAuth. Public paths remain exact and local admin routes absent. Saved resource recovery is a routing hint only; full durable state/policy validation remains mandatory. Failure after an attempted transition is audited as uncertain; no blind retries or unrelated route rollback.

`tests/oauth_funnel.py` exercises real native HTTP OAuth against a disposable fake LocalAPI daemon: conflict and conditional-update refusal, exact route publication, OAuth registration/PKCE/local consent/native read, proxy boundaries, private Serve access, issuer stability on restart, revoke, graceful shutdown, SIGKILL cleanup and watcher disconnect. This models tailscaled foreground cleanup, not an actual live public tunnel. Installed Tailscale 1.104.7 read-only watch/ETag compatibility passed without changing existing Serve config. Live foreground cleanup, external HTTPS metadata/discovery, ChatGPT/Claude compatibility, independent locked acceptance and release remain open. Existing shared native job ownership must be explicitly separated by OAuth identity before granting command/job controls; do not infer authorization to change a native mode or enable a broader grant. Cloudflare/custom provider, systemd-managed public lifecycle, packaging and additional platform support remain separate work.

## Ordered implementation gates

1. HTTP baseline: already implemented loopback MCP at /mcp (JSON Streamable HTTP), separate private admin listener, exact Host/Origin and duplicate-header checks, bounded requests, admission/rate limits and audit. Existing Funnel ownership/ETag/rollback support is already present. Reuse rather than rewrite. New OAuth route allowlist is exact: /mcp, /.well-known/oauth-protected-resource (and /mcp suffix), /.well-known/oauth-authorization-server, /oauth/register, /oauth/authorize, /oauth/token. No wildcard /.well-known or /oauth exposure, no public approval, admin or secret URL in the new mode.
2. OAuth before new public exposure. Current sub-checkpoint implements an isolated in-memory grant lifecycle and bounded public-client registration/metadata contract. Next: real HTTP request/form parsing (strict duplicate rejection and size limits), method/Origin/Host/marker enforcement, authorization and token endpoint handlers, safe callback encoding, authenticated local approval and denial UI, explicit exact local client selection, owner-private atomic persistence, live policy admission and revocation, audited state transitions and rate limits. Test actual client flow and hostile negative cases before considering any public activation. Support the pinned MCP lifecycle; do not conflate transport protocol and OAuth version. DCR is a supported registration method, not the only one; test actual web-client interoperability and consider Client ID Metadata Documents or pre-registered clients separately. No implicit scope or mode elevation. OAuth grant expiry does not change persistent Standard/YOLO/FULL selection.
3. TunnelProvider: reuse the existing Tailscale LocalAPI owned-route machinery for Funnel; define detect/up/status/public_url/down with explicit plans, confirmation, conflict checks, no new persistent Veyl tunnel daemon. Implement Cloudflare named tunnel adapter only with verified DNS ownership/credentials and stable public HTTPS origin. Quick tunnel development only; custom URL adapter read-only or explicit operator action. Keep dashboard private and expose only exact approved routes. Verify reuse, external reachability, rollback and no accidental unrelated route changes.
4. Opt-in setup: preserve existing setup/connect CLI contracts. Guided provider detection, HTTPS prerequisites, local service lifecycle and public discovery check, connector URL (no secret path for OAuth). Prompt for each new OAuth client locally, never approve from the public side. No automatic production tunnel mutation during development.
5. Client guides: verify current ChatGPT and Claude plan/custom MCP requirements and actual authorization/discovery. Demonstrate system_context, cwd and MCP server listing only if granted. Never publish a personal endpoint or credential.
6. Security acceptance: real HTTP/tunnel negative controls, replay and revocation, restart/reconnect, expiry, invalid resource, redirect mismatch, cross-client isolation, local approval CSRF, rate limits/capacity, protected paths, audit and unchanged existing Linux regression suites. No public new mode until full acceptance. Existing direct secret-path route is not automatically removed.
7. Tag-driven GitHub Actions and Arch package, then Windows and Android/Termux native work (separate verified platform gates). Preserve signed/checksummed release and safe updates. Hosted connector and universal plugin last, only if chosen; hosting/cost and developer approval remain separate.

## Current implementation contract

src/core/oauth.rs: portable bounded grant lifecycle using the existing SHA-256, OS randomness, constant-time digest comparison and one pinned base64 dependency (0.22.1, already cached). No custom crypto. PKCE S256, pending local consent, exact client/redirect/resource binding, one-use authorization code, access and refresh tokens stored only as digests, rotation and replay-family revocation, local client revocation and caps. Prototype lifetimes: pending 5 min, code 60 s, access 15 min, fixed family 24 h, 128 entries and at most 256 refresh rotations. These are candidate choices, not production settings. Restart intentionally invalidates all prototype grants; durable storage and recovery remain pending.

src/http_common/oauth.rs: HTTP-specific validation lives outside portable core. Explicit HTTPS DNS origin, discovery/WWW-Authenticate values, exact route classification, bounded public-client registration, fixed mcp scope, strict exact HTTPS redirect and resource match, revoke registration plus its pending/active grant families. Preview accepts no callback query/fragment/userinfo, no loopback redirect, no CIMD, no confidential clients. These restrictions are intentional until real interoperability is tested. Registration snapshot v1 persists IDs, unverified display names, redirect allowlist and configured resource only.

src/connector/oauth_preview.rs: explicit Linux foreground-only HTTP fixture, not the hosted connector or native gateway. `veyl-connector oauth-preview PORT ADMIN_PORT HTTPS_ORIGIN [PRIVATE_STATE_DIR]` reads a synthetic operator_token (64 lowercase hex) and local_fixture_client label as JSON on stdin. Port 0 requests ephemeral loopback. The public-facing test socket serves the exact metadata/registration/authorization/token routes and a credential admission check at /mcp (401 for invalid/absent token; 503 even for a valid token because native execution is intentionally not wired). Requires an exact configured Host, rejects Origin and proxy markers; no public TLS or proxy trust. Browser approval page displays a random pending handle, polls by explicit link, and returns a one-use 303 code or access_denied callback with correctly encoded state. Separate loopback-only operator listener requires a separate bearer credential and exact local Host; /inspect, /approve, /deny, /revoke are absent on the public socket. Operator must verify untrusted registration identity and exact redirect; local_fixture_client is not native policy. Strict flat JSON/form duplicate rejection, bounds, rate budgets, connection limits, timeouts, no-store and no-referrer headers; fixed diagnostic event names, not yet durable audit.

Optional registration persistence: initialize a new absolute 0700 directory with `veyl-connector oauth-state-init DIR HTTPS_ORIGIN`, then pass DIR to the preview. Reuses existing descriptor-relative private Store, exclusive directory lock, canonical owner-only 0600 oauth-registry.json, atomic fsync publication and verification. A registration or revocation is acknowledged only after persistence succeeds; corruption/change detected on the next mutation latches the preview unavailable and clears in-memory grants. Startup rejects unsafe, noncanonical or invalid registry files and origin mismatch. Restart preserves registered client IDs and revocations, not pending consent, authorization codes, access or refresh token families. No secrets stored on disk. This is not persistent credential/session recovery. Same-UID outside modification remains out of scope; the running preview does not poll for external changes.

## Native read-only integration checkpoint

The previous connector HTTP implementation is now shared in `src/http_common/oauth_http.rs`; its descriptor-relative store moved to `src/platform/private_store.rs`. The connector command and registration-only persistence contract remain compatible. `src/http/oauth.rs` integrates the shared server into the actual Linux gateway. Opt-in command: `mcp-gateway http --listen 127.0.0.1:0 --config ABSOLUTE_CONFIG --oauth-preview-origin https://node.example:8443`; stdin is the same synthetic operator_token and local_fixture_client JSON object. The config must have ephemeral loopback admin listener, no tailnet settings, writable audit ledger and a pre-existing Standard client limited to read_file/list-tools, no extra roots. The preview accepts only reserved .example DNS origins and ephemeral ports. Operator bearer must differ from existing native client credentials. No normal HTTP or service launch enables OAuth.

The dedicated MCP listener accepts only OAuth admission in this mode. Separate operator endpoints are routed on the admin listener; existing dashboard routes remain separate. The OAuth family is bound to each MCP session (refresh retains its family, a new authorization creates a distinct family). Revalidate registered OAuth identity, native client ID, credential verifier, root, expiry, mode and allowed tools at initial admission and again at blocking tool-worker admission. Durable native ledger admission records are required; loss of audit binding denies new tool operations. This is real native read_file dispatch, not a mock. Existing native policy and safe path resolution remain authoritative; no grant or mode changes are performed by OAuth.

## Durable native OAuth checkpoint

Native preview can opt into persistent authentication by adding `state_dir` (absolute, existing owner-private 0700 directory) and `initialize_state` (true for first initialization only; false or omitted for recovery) to the existing stdin JSON. No implicit initialization or overwrite; separate state outside the client root, native config and audit directory, one pre-existing read-only Standard client, no jobs. Legacy volatile native preview and connector registration-only mode remain unchanged. No new native policy fields or permissions.

`src/core/oauth/persistence.rs` serializes only active families: exact client/redirect/resource binding, SHA-256 digests (canonical base64url) of authorization code, access token, refresh token and spent refresh verifiers, PKCE challenge, and absolute millisecond expiry deadlines. No raw codes, tokens, pending consent, browser state or PKCE verifier. Restore validates registry binding, local principal, cardinality, unique digests, TTL bounds, and saved wall time; expired families are discarded and expired access tokens remain expired. Refresh retains family identity; authorization code or consumed refresh replay invalidates its family even after restart. MCP sessions are intentionally process-local and must be initialized again.

`src/http_common/oauth_http/durable.rs` stores a sealed canonical snapshot (`oauth-state.json`, max 4 MiB, 0600, owner-private exclusive directory lock). Native binding includes the exact policy digest, canonical policy path, native client ID and workspace device/inode. Changes deny live native access and a mismatched binding refuses restart. Before lifecycle mutation, atomically fsync an interrupted-intent marker; then atomically fsync the updated registry/families and lifecycle receipt before returning a response, including invalid-grant results that remove replayed families. A dirty or corrupt snapshot blocks startup; retain it for investigation and require explicit new state with fresh local approval, never restore an older token snapshot to recover. In-process storage failure latches denial. External edits are detected at the next transition; no background watcher. The SHA-256 seal detects accidental corruption, not arbitrary same-UID malicious rewriting or rollback.

Bounded last 2048 lifecycle receipts, monotonically increasing sequence, UTC milliseconds, fixed operation, HTTP outcome and registered OAuth client ID where resolved (not raw request data). The existing durable native admission audit remains independently mandatory. Not a permanent append-only externally anchored audit log. Wall time at startup may not precede the last saved timestamp; monotonic expiry within a process and a 2-second wall/monotonic clock-step guard fail closed on detected discontinuity. Restart re-evaluates absolute deadlines; trustworthy system clock is required. Disk commits currently run synchronously under the preview state lock; move blocking persistence off the public HTTP runtime and measure capacity before any public use.

## Local dashboard and CLI consent checkpoint

The existing paired dashboard now exposes an OAuth connections tab only when the native OAuth preview is enabled. Local operators paste a pending handle, inspect the unverified client name, exact client ID, HTTPS callback, resource, native client and scope, and explicitly confirm approval or denial. Registration revocation requires explicit confirmation. The API `POST /dashboard/api/oauth` (also existing normalized API path) requires a live paired local session, singleton CSRF token, exact admin Origin, unambiguous cookie, no query or forwarding headers, and strict bounded JSON. Public MCP listener never routes this endpoint. Policy and audit availability are rechecked before approval; denial and revocation do not require native grant eligibility. The transaction uses existing durable lifecycle receipts when persistence is enabled. Registration names are rendered with textContent, never HTML. No polling or new daemon.

CLI: `veyl oauth list|inspect|approve|deny|revoke --listen 127.0.0.1:PORT --config ABSOLUTE_POLICY`. Requires explicit isolated preview policy with ephemeral admin port and no tailnet; supply the actual bound admin port. It issues a one-use dashboard pairing code using the owner policy, authenticates, makes the same consent request and signs out. As with existing dashboard pairing, a new pairing code supersedes an outstanding unredeemed code. Non-list commands read bounded JSON from stdin. Inspect input: `{"request":"PENDING_HANDLE"}`. Approve/deny input: request, exact client_id, redirect_uri, resource, local_client from inspection, and confirm:true. Revoke input: client_id and confirm:true. The CLI adds its action; do not include action in input. Never retry a timed-out mutation without inspecting state. The old separate bearer-authenticated operator API remains for isolated fixture compatibility; retire or consolidate it before public activation. Pending handles are not listed; the operator explicitly brings the handle from the authorization page.

## Automated local onboarding checkpoint

Operator requested onboarding before widening capabilities. `veyl oauth setup --root ABSOLUTE_EXISTING_WORKSPACE --profile ABSOLUTE_NEW_DIRECTORY [--open-ui]` creates a fresh isolated private profile and launches the foreground preview; `veyl oauth run --profile ABSOLUTE_EXISTING_DIRECTORY [--open-ui]` resumes with the same policy and existing durable token state. No stdin JSON required. Uses descriptor-relative no-follow creation and non-replacing publication, mode 0700 profile/audit/oauth directories and mode 0600 policy/state files. Parent must exist, be owned by the operator and not be group/world-writable; workspace must be separate. Existing profiles, overlapping roots and symlink parents are refused. No default production state adopted or changed. A failed or interrupted initialization retains partial state for inspection; it is never automatically removed, overwritten or reinitialized.

Fresh managed policy contains exactly one Standard read_file client, with a generated SHA-256 verifier whose plaintext native bearer is not retained, and a one-year native credential expiry. Internal per-launch operator token is generated but legacy bearer operator paths are disabled for onboarded runs; existing explicit fixture mode remains compatible. Persistent family expiry is unchanged. Both listeners use ephemeral IPv4 loopback ports, fixed synthetic origin https://veyl.example and no tailnet. The optional --open-ui flag issues the existing one-use pairing code and opens the local dashboard via xdg-open, using the fragment as in the existing dashboard open flow. If opening fails, local pairing instructions are available; no automatic client authorization.

Verify locally: `python3 -B tests/oauth_native.py /absolute/path/to/debug/mcp-gateway -v` (includes actual headless Chromium-family browser, CLI and automated setup/recovery) and `python3 -B tests/oauth_http_preview.py /absolute/path/to/debug/veyl-connector -v`. Onboarding tests additionally check real native read after approval, recovery, revocation, duplicate setup/run refusal, missing-state refusal and no persisted plaintext bearer. Public provider discovery, HTTPS prerequisites, service installation and externally verified real connector URL are still pending. The next gate remains broader native capabilities under existing policy and blocking persistence isolation, followed by tunnel provider and web-client acceptance. This does not deliver a universal official plugin. No production endpoint, version bump, native grant or tunnel change.

References: https://developers.openai.com/plugins/build/auth (current supported OAuth registration methods and PKCE); https://tailscale.com/docs/features/tailscale-funnel (public HTTPS, beta and bandwidth limits); RFC 7636 (PKCE), RFC 9728 (resource metadata), RFC 8414 (authorization server metadata).

## Scoped workspace-edit checkpoint

Fresh onboarding may explicitly add `--workspace-edit` (repeat on run of that profile). The profile grants only native read_file, write_file, apply_patch, edit_file under Standard. Default remains read-only. No directory creation, shell/process/job, Git, upstream or broad modes enabled. Existing durable exact policy digest and workspace inode binding remains authoritative. Local inspect returns native_scope and scope_fingerprint; edit approval must echo the inspected fingerprint in addition to the existing exact binding. Dashboard displays root and sorted tool grants, CLI accepts the fingerprint. OAuth file mutations use strict descriptor-scoped alias rejection; legacy native behavior unchanged. Existing create_directory path-based create_dir_all needs security review and fix before inclusion; do not assume all registered tools have identical path safety.

## Directory, blocking workers and expanded workspace checkpoint

The directory safety defect above is fixed: descriptor-relative mkdirat with symlink/mount refusal, identity revalidation and audited intent before mutation. Partial directory creation on error and arbitrary concurrent same-UID rename races remain limitations. OAuth state lifecycle and admission/audit blocking work now run outside the async reactor under bounded public (8) and operator (4) slots. Worker slots persist through cancelled HTTP requests; serialized commits and fail-closed persistence remain mandatory.

Fresh onboarding can now select `--workspace-tools` instead of `--workspace-edit`; repeat the same flag on recovery. Exactly nine Standard tools are allowed: read_file, write_file, apply_patch, edit_file, create_directory, list_directory, directory_tree, file_info and search_files. Read-only remains the default. Scope fingerprint confirmation is required, jobs and extra roots remain disabled. List/tree output bounded to 512 items/entries with traversal deadlines and truncation; file metadata hashing bounded to 1 MiB. Tests exercise real native dispatch, exact scope, symlink escape, ungranted commands, bounded traversal and recovery. See STATUS.md for 56 focused tests on expanded source and 208 Rust tests on immediately preceding worker checkpoint. Next review dedicated public origin/provider integration, separately gated native capability groups and real web-client compatibility. No public route activated.
