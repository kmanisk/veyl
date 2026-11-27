# Gateway Milestone 1 — Working Handoff

## Current gate: 0.6.0-beta released and running

Release tag `v0.6.0-beta` and published crate `veyl 0.6.0-beta` correspond to accepted code commit `f204dc257b1bdd8bde8c11811d84bf5b6e58a9cd`. The release assets and installed binaries match the approved bundle. The production service is active, all grants and audit history preserved, and the durable v2 checkpoint is verified against the pre-upgrade anchor. See STATUS.md for evidence. Earlier acceptance-pending sections below are historical. Next gate: real external-client interoperability, limited opt-in Veyl workflow trials, and measured BridgeDev parity. Preserve rollback and existing BridgeDev access.

## Current gate: Independent AGY acceptance PASS for 0.6.0-beta (`f204dc257b1bdd8bde8c11811d84bf5b6e58a9cd`); explicit operator acceptance required before release

Checkpoint: `fix/0.6.0-beta-durable-rollback` @ `f204dc257b1bdd8bde8c11811d84bf5b6e58a9cd` (plus final `STATUS.md` / `HANDOFF.md` evidence update)
Bundle: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/release-0.6.0-beta-final.KH9o63jx/`
(`SHA256SUMS`: `veyl`, `mcp-gateway`, `veyl-monitor`, `veyl-connector` verified)
Manifest: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/SOURCE_SHA256SUMS-0.6.0-beta-final.KH9o63jx` (215/215 PASS)
Tarball: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/veyl-0.6.0-beta-final.KH9o63jx-source.tar.gz`
Crate preflight: `/home/onyx/Projects/veyl/target/package/veyl-0.6.0-beta.crate` (189 files, `cargo package --offline --locked --no-verify` PASS)
Independent AGY verification summary (see `STATUS.md`):
- Clippy clean (0 warnings), Rust suite **228/228 PASS**, Locked + three-modes **293/293 PASS** (`28/28` pins, including `--features test-hooks` `locked_audit_chain.py` 13/13), bounded host `tmpfs` `oauth_funnel.py` **5/5 PASS** (0 skipped).
- Rollback & systemd upgrade (`../release-0.6.0-beta/` `v0.5.0-beta` -> `release-0.6.0-beta-final.KH9o63jx`): `durable_update_rollback.py` **3/3 PASS**, `durable_update_service.sh` **3/3 scenarios PASS** (legacy updater refused, post-migration failed startup restored `v0.5.0-beta` & `v1` head cleanly, successful upgrade), `durable_identity.py` **3/3 PASS**, `durable_identity_loopback.py` **PASS**, read-only prod `audit verify` (2,590 records) & `mode list` **PASS**, remaining 32 Python integration suites (**139/139** unittest cases) + `onboarding_browser.py` **PASS**.
Production PID `1012`, `~/.local/state/veyl`, `rollback-before-0.6.0-beta.Lf3fvq33`, and canonical `~/Projects/veyl` remain unchanged pending explicit operator acceptance under `AGENTS.md` to install locally via `release-0.6.0-beta-final.KH9o63jx/veyl update --from-dir ...`, verify production health & grants, fast-forward `main`, tag/publish `v0.6.0-beta`, and publish `veyl 0.6.0-beta` to `crates.io`.

## Historical gate: BridgeDev 0.6.0-beta durable identity + migration rollback checkpoint

Use `../release-0.6.0-beta-final.KH9o63jx/` (four optimized checksums in
`SHA256SUMS` and STATUS.md). Do not use the superseded earlier durable bundle
for installation. BridgeDev verified 33 focused cases, three isolated
systemd upgrade/rollback scenarios and all-target Clippy. The new updater's
journal preserves the current ledger tip and exact pre-update policy; an older
updater is refused before migration. Keep the new bundle for `update --recover`.
See STATUS.md for exact receipts, limitations and current release gate.

## Current gate: Veyl 0.6.0-beta durable-identity candidate (v0.6.0-beta) verified PASS; renewed operator release acceptance pending

Release candidate: `0.6.0-beta` (tag `v0.6.0-beta`, reboot-safe durable identity fix)
Original preserved bundle: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/release-0.6.0-beta/` (untouched)
Corrected staged binaries: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/release-0.6.0-beta-durable/`
(`SHA256SUMS` verified across `veyl`, `mcp-gateway`, `veyl-monitor`, `veyl-connector`)
Source manifest: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/SOURCE_SHA256SUMS-0.6.0-beta-durable`
Source tarball: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/veyl-0.6.0-beta-durable-source.tar.gz`
Crate preflight: `/home/onyx/Projects/veyl/target/package/veyl-0.6.0-beta.crate`
See `STATUS.md` for full verified results: Clippy clean, 228/228 Rust tests,
28/28 locked pins intact, 287/287 locked suite cases (`--features test-hooks`
`locked_audit_chain.py` 13/13 included) + 6/6 `locked_three_modes.py` (293/293),
`durable_identity.py` 3/3, `durable_identity_loopback.py` (Btrfs `st_dev`
renumbering + snapshot rejection, ext4 renumbering + FS substitution rejection,
volatile `tmpfs` strict `dev` check), read-only production `audit verify` (2,590
records) & `mode list` PASS, 5/5 bounded host-tmpfs `oauth_funnel.py` (0 skipped),
and 139 additional Python integration cases + `onboarding_browser.py`.
Production PID `1012`, `~/.local/state/veyl`, `rollback-before-0.6.0-beta.Lf3fvq33`,
and canonical `~/Projects/veyl` remain unchanged pending renewed explicit operator
acceptance before local upgrade (`veyl update`), `main` promotion, GitHub
`v0.6.0-beta` release, and `crates.io` publish.

## Historical gate: Veyl 0.6.0-beta pre-durable candidate; preserved in ../release-0.6.0-beta/

Original staged artifacts preserved at: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/release-0.6.0-beta/`

## Historical gate: direct OAuth onboarding v0.5.0-beta preview; superseded by 0.6.0-beta

## Historical gate: managed Standard lifecycle and native YOLO mask locally PASS

Latest evidence in STATUS.md. Use ../preview-managed-isolation.9MrrYGsG as
the staged candidate, not the earlier preview-managed-login binary.
38 integration cases passed, one advanced tmpfs case skipped; 28 pins
verified. New native broad mask has a genuine failing-old/passing-new
control. No remote OAuth YOLO or per-connection mode switching yet.
Next design/implement mode-bound grants and enforce native broad
protections without confusing them with bounded public Standard, plus
onboarding polish and actual client acceptance. Retain all existing artifacts
and preserve old connections. No AGY delegation by default, no production
promotion or GitHub main push from incomplete scope.

## Historical gate: managed login/logout draft; initial disk admission BLOCKED

See latest STATUS.md. New managed Standard CLI and logout recovery code
are uncompiled. Preserve preview-resource-final as the verified baseline.
Safely recover enough space for the 40 GiB guard, then guarded compile,
Clippy and ordinary-user tests/oauth_managed_login.py against the exact
new binaries. Verify control socket/lock ownership, interruption, duplicate
login, old-token denial, route cleanup and legacy transport regression.
Genuine broad OAuth YOLO and per-connection mode selection remain unfinished;
do not weaken existing scope and storage restrictions to implement them.
Routine verification through BridgeDev, no automatic AGY delegation.
Push only after successful testing and completion of the requested
workflow; production remains unchanged.

## Historical gate: simplified onboarding and OAuth mode lifecycle

Latest operator UX correction: implement `veyl login`, `veyl logout`,
Standard default and explicit local per-connection YOLO selection. See
DIRECT_REMOTE_PLAN.md for the new contract. Previous direct OAuth candidate
remains the verified baseline, not implementation of the new UX. Preserve
legacy CLI and accepted artifacts. Do not remove the native OAuth Standard
restriction or substitute a misleading YOLO label without a verified
security design. Keep all changes in the candidate; targeted independent
acceptance and real client testing before release.

## Current gate: direct OAuth MCP live acceptance (2026-11-27)

Latest operator direction supersedes earlier package-specific release gates:
direct custom MCP over HTTPS/OAuth only; hosted connector and standalone
plugin are deferred. Runtime remains the independently accepted
preview-resource-final candidate. Follow DIRECT_REMOTE_PLAN.md: actual
client consent, synthetic read, bounded writable profile write and command,
reconnect and revocation, then Android capability observation. No additional
full AGY matrix for documentation changes. Do not weaken the tmpfs or
trusted-executable restrictions. No version change, install, push, or public
release before exact candidate approval. Preserve existing production
connections and experimental package/connector artifacts.

## Current gate: all simulated acceptance PASS / live operator test pending

AGY full advanced host-tmpfs suite 5/5 and namespace launcher 1/1 PASS; BridgeDev verified raw log, unchanged audited artifacts, locked hashes and cleanup. See STATUS.md. No further full AGY matrix is needed on unchanged runtime. Next: explicitly authorized isolated read-only Funnel preview, verified external TLS/OAuth metadata, private ChatGPT Plugin Creator installation and operator OAuth consent/tool test. No production promotion until the operator accepts the exact release. Keep existing production grants and routes unchanged. Use fresh authorization profile after any recreated tmpfs; persistent quotas and cross-profile aggregate caps remain limitations.

## Current gate: independent local PASS / mounted advanced and live client HOLD

AGY's resource-hardening local/simulated PASS and clean 293-case log confirmed by BridgeDev (exact pre-edit tree and optimized hashes match). Only test launcher and documentation changed after that report; direct single-binary namespace invocation now passes. See STATUS.md. Keep optimized preview-resource-final unchanged. Do not rerun the full independent matrix just for the test launcher correction. Next independent acceptance is narrowly scoped to the full advanced positive test with a temporary operator-approved host tmpfs, preserving trusted root-owned executable checks. No privileged mount or live Funnel route without separate operator approval. Use new profile/authorization after any tmpfs recreation; immediate remount identity reuse is a known limitation pending explicit operator disposition. Real external HTTPS and private ChatGPT plugin acceptance still required before production promotion.

## Current AGY handoff — resource-hardening candidate (2026-11-26)

Supersedes the advanced candidate handoff below. Read the latest STATUS.md and DIRECT_REMOTE_PLAN.md. Inspect the exact dirty candidate, not canonical main. Restage via tests/prepare_locked_artifacts.py using the guarded shared build cache; independently verify 28 immutable pins, run every pinned suite (287 cases) and the six supplementary three-mode cases, resource cgroup checks, aggregate tmpfs capacity and inode exhaustion, full advanced bounded-workspace positive test, negative admission tests, updater lifecycle and OAuth regressions. Use the correct fixture umask 022. No host mount or privileged changes without operator authorization; report a blocked positive test rather than relaxing the gate. The file-only public simulated endpoint passed aggregate ENOSPC in a private mount namespace, but the full advanced case needs a dedicated bounded mount fixture. Review the final optimized artifacts and source-only test relocation after the previous pinned run. Report independent acceptance without changing implementation or locked tests. Real external HTTPS/ChatGPT acceptance and exact operator release approval remain outstanding. Do not deploy or publish.

## Current AGY handoff — advanced direct-remote candidate (2026-11-26)

Inspect the exact dirty candidate at `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/source`, not canonical main or an older checkpoint. Verify the candidate snapshot and optimized binaries in `../preview-advanced-release/` against SHA256SUMS before testing. Preserve implementation and independent acceptance ownership. Do not edit locked tests or candidate code; report defects with evidence. Run the complete locked acceptance matrix (28 pins), relevant adversarial OAuth lock/revocation, advanced opt-in, scope/family isolation, recovery, resource bounds, upstream and plugin packaging tests. Use the existing guarded build policy and ordinary-user isolated runtime for tests requiring namespaces. No live production routes, credentials, deployment or version changes. Report actual test counts and failures. The real HTTPS/Plugin Creator test requires an explicitly authorized isolated preview and a bounded writable workspace; no disk quota is currently enforced. See STATUS.md for evidence and remaining gates.

## Current gate: runner launch authorization hardening / local PASS / public HOLD

Candidate public-connector.b64EhS58/source; signed original launch revision/deadline, nonblocking native policy guard held through spawn, final durable family/deadline check. Guarded builds and normal-user runs: 215 Rust, 14 focused runtime, Clippy PASS, 28 pins intact. Exact preview ../preview-runner-launch with SHA256SUMS. Restricted system-job ENOSYS corrected by ordinary-user direct rerun, not by loosening host restrictions. Full locked and deterministic launch/revoke interleaving acceptance still outstanding. See STATUS.md. Production unchanged; AGY independently accepts.

## Current gate: takeover / guarded verification HOLD

ChatGPT implements directly in `public-connector.b64EhS58/source`; AGY owns independent acceptance. Existing debug binaries passed 14/14 targeted OAuth interactive, native sessions and dynamic-command integration cases; 28/28 pins intact. New candidate-only Cargo guard passed 6/6 tests and refused a live build below 40 GiB. See STATUS.md for receipts and the distinction between runner pre-spawn OAuth checks and native policy/expiry validation at the IPC boundary. Next: recover sufficient safe disk headroom, review and test the launch/revocation race, then guarded builds and full locked acceptance before any public capability expansion. No production changes or public activation.

## Current gate: OAuth interactive sessions PASS / public activation HOLD

Candidate `public-connector.b64EhS58/source` (dirty working tree preserved; no commit/push/deploy). Implements explicit `--workspace-interactive` (requires `--workspace-jobs`, refuses `--funnel` and non-interactive defaults) across `src/oauth_cli/onboarding.rs`, `src/http/{oauth,mod}.rs`, `src/http/dashboard/app.js`, `src/core/oauth.rs`, `src/core/oauth/persistence.rs`, `src/http_common/oauth_http{,/durable}.rs`, `src/platform/private_store.rs`, and `src/jobs/{mod,config,launch,runner,session,session/channel}.rs`. Reuses native pipe/PTY process-session infrastructure with OAuth family ownership, runner-side sealed `oauth-state.json` grant-family/expiry/revocation enforcement (`verify_active_family` + `Channel::step`), refresh/reconnect/restart recovery, operation sequencing/replay protection, metadata-only durable audit, offline workspace sandbox, and mandatory systemd ceilings (`300s`, `100%` CPU, `256 MiB`, `65536` bytes/stream, `4096`-byte input frames). Verified: `cargo clippy --all-targets -- -D warnings`, 213/213 Rust tests, 96/96 focused Python tests (including `tests/oauth_interactive.py` 2/2 and `tests/process_sessions.py` 10/10), both Chromium CDP browser probes, `node --check`, 28/28 locked hashes unchanged, and 13 applicable locked acceptance suites (`105/105`). See `STATUS.md`, `DIRECT_REMOTE_PLAN.md`, and `README.md`. Public Funnel activation and remaining full release/non-interactive locked suites remain out of scope pending operator review; ChatGPT resumes next milestone after review.

## Current gate: OAuth dynamic-command PASS / public activation HOLD

Candidate public-connector.b64EhS58/source. Prior upstream gate: 208 Rust + 74 focused integrations, browser probes, 28 pins PASS. Explicit local `--workspace-upstreams` with strict provider manifest; trusted providers may share state. New `--workspace-commands` extends explicit named jobs with root-only dynamic exec/task under bounded offline Standard sandbox. Final dynamic gate 208 Rust + 76 focused integration cases (including 2 dynamic OAuth cases), browser probes, Clippy/build, 28 pins PASS. Browser readiness race fixed without weakening fragment assertion. Interactive controls remain a separate runner-authentication gate. See STATUS.md and DIRECT_REMOTE_PLAN.md. No Codex, no production changes or public activation; AGY independent acceptance pending.

## Current gate: local OAuth named commands and jobs PASS / public activation HOLD

Same isolated candidate public-connector.b64EhS58/source; explicit named-profile jobs, family-scoped signed receipts, local dashboard recovery/cancel after revoke, offline workspace containment and mandatory resource ceilings. New `--workspace-jobs` and initial `--job-profiles ABSOLUTE_FILE` documented in README and DIRECT_REMOTE_PLAN.md. Public Funnel plus jobs refused; arbitrary command/interactive processes not yet granted. Final 208 Rust and 71 focused integrations, browser, build and 28 pins PASS. See latest STATUS.md for exact receipts and corrected non-job consent compatibility. Next implement explicit upstream capability group; then separately review dynamic commands, interactive sessions and public capability admission, actual HTTPS clients, independent AGY and release. No deployment or grant widening. ChatGPT implements directly, AGY independently verifies.

## Current gate: foreground Funnel provider / public activation HOLD

Candidate public-connector.b64EhS58/source now implements foreground-owned dedicated Funnel via LocalAPI, exact stored HTTPS issuer recovery, conditional updates, conflict checks, proxy admission and private local consent. 208 Rust + 59 focused integrations (including three full fake-LocalAPI/native-OAuth tunnel lifecycle tests), actual browser probe, Clippy/build and all 28 pin hashes passed. Read-only installed Tailscale 1.104.7 watch/ETag compatibility passed with unchanged Serve configuration. See STATUS.md and DIRECT_REMOTE_PLAN.md for receipts and limitations. Do not mistake disposable daemon cleanup for a live public route or external ChatGPT/Claude interoperability. Next separately scope commands/jobs and upstream grants; AGY independently accepts, actual external client acceptance and exact release approval required before production. No Codex, no routine confirmation pauses.

## Current gate: bounded workers and expanded scoped workspace tools / public activation HOLD

Candidate public-connector.b64EhS58/source. Directory safety and bounded OAuth blocking workers passed 208 Rust + 55 focused tests at that checkpoint. Expanded `--workspace-tools` now adds mkdir, list/tree/metadata/search to the existing four scoped file tools. Expanded build and 56 focused tests, browser probes and 28 locked pins PASS. Full Rust rerun on expanded source, full locked acceptance and public interoperability pending. See latest STATUS.md for receipts. Next dedicated fixed-origin tunnel provider and separately reviewed native capability groups; no production activation or policy widening. ChatGPT implements directly, AGY verifies independently; no routine confirmation pauses during development.

## Operator workflow correction (2026-11-26)

ChatGPT implements directly using BridgeDev; AGY independently verifies.
No further Codex tasks. The earlier directory-creation draft finished in
the isolated codex-next-u2xixsy6 clone before the correction. ChatGPT
reviewed its three code/test file changes, checked all 193 baseline entries,
and imported only those files into public-connector.b64EhS58/source.
Independent local verification is required before acceptance; the historical
draft is not authoritative. Production and locked suites remain untouched.

## Current gate: scoped OAuth workspace edit / public activation HOLD

Candidate public-connector.b64EhS58/source: explicit onboarded --workspace-edit profile, native read/write/patch/edit only, exact scope review/fingerprint and strict multiply-linked mutation denial. 203 Rust + 55 focused integrations PASS, 28 pins unchanged, browser/lint/build PASS. No changes to legacy grants, production or public routes. Source review flags create_directory path-based create_dir_all; next fix and independently test that boundary, then isolate blocking persistence and incrementally broaden capability groups. AGY full locked acceptance pending. See STATUS.md and DIRECT_REMOTE_PLAN.md.

## Current gate: automated local OAuth onboarding / public activation HOLD

Candidate public-connector.b64EhS58/source: `veyl oauth setup --root DIR --profile NEW_DIR --open-ui` provisions and launches isolated private state, and `veyl oauth run --profile DIR --open-ui` recovers it without manual JSON or bearer input. 203 Rust + 54 focused integrations and existing first-run browser probe PASS, 28 pins unchanged. Onboarded legacy bearer operator routes disabled. Synthetic origin and Standard read_file only; no real tunnel, official plugin, installed service or broader grants. Next extend native permission-preserving capabilities and isolate blocking persistence, then actual tunnel/provider and cloud-client acceptance. Production 0.5.0-beta remains untouched. See STATUS.md and DIRECT_REMOTE_PLAN.md.

## Current gate: local OAuth consent UI and CLI / public activation HOLD

Candidate public-connector.b64EhS58/source: paired local dashboard OAuth connections tab and `veyl oauth` CLI, exact binding confirmation, local Origin/session/CSRF checks and live policy/audit eligibility. 203 Rust + 52 focused integrations PASS (13 native OAuth including real Brave browser and CLI); 28 pins unchanged, Clippy and builds PASS. New interfaces remain read-only Standard preview; old bearer operator fixture API retained for compatibility, retire/consolidate before exposure. Next broaden native capabilities under existing policy, isolate blocking persistence, real web-client and tunnel acceptance. Preserve deployed 0.5.0-beta. See DIRECT_REMOTE_PLAN.md and STATUS.md.

## Current gate: durable native OAuth / public activation HOLD

Candidate public-connector.b64EhS58/source: optional private native OAuth family recovery and atomic lifecycle receipts. 203 Rust + 47 focused integration tests PASS, 28 locked pins unchanged, all-target Clippy/build PASS. Clean-commit restart/replay/revocation, expiry, policy/workspace binding and fail-closed dirty/corrupt state verified. Native MCP sessions and unfinished consent remain volatile, connector registration-only mode unchanged. Preview only, bounded 2048-receipt audit, synchronous disk commits; no full locked acceptance or real cloud-client interoperability. Next authenticated local dashboard/CLI consent and reviewed broader native grants. Preserve production 0.5.0-beta. See DIRECT_REMOTE_PLAN.md and STATUS.md.

## Current gate: native read-only OAuth integration / public activation HOLD

Candidate public-connector.b64EhS58/source: shared OAuth server and actual native Standard read_file execution behind explicit ephemeral loopback fixture. 200 Rust + 43 focused integrations PASS (4 new native OAuth cases); all-target Clippy and builds pass. Grant-family MCP session binding, live native policy/worker revalidation and durable native admission audit verified. Native OAuth state volatile; no public activation. Next durable hashed token state/expiry/replay recovery, durable OAuth lifecycle audit, authenticated dashboard/CLI consent, then wider capability and cloud-client acceptance. Preserve verified 0.5.0-beta production. See DIRECT_REMOTE_PLAN.md and STATUS.md.

## Current gate: direct remote OAuth HTTP preview / native admission HOLD

Candidate public-connector.b64EhS58/source has actual loopback OAuth HTTP flow and optional persistent registered-client state. Final 200 Rust + 39 focused integrations PASS, 28 locked pins unchanged. Reproduce with tests/oauth_http_preview.py and candidate ../target/debug/veyl-connector. Separate authenticated operator API is fixture-only, not a production dashboard; valid token deliberately returns 503 at /mcp. All token families currently lost on restart. Next share handlers with native HTTP adapter, wire live policy/session binding, local approval UI, durable hashed token state and audit; no public OAuth activation until full end-to-end acceptance. Details in DIRECT_REMOTE_PLAN.md and STATUS.md.

## Current gate: direct remote OAuth domain checkpoint / public activation HOLD

Latest operator direction supersedes hosted-first roadmap. Read DIRECT_REMOTE_PLAN.md. Candidate public-connector.b64EhS58/source contains real S256 grant lifecycle, bounded registered-client and resource validation, metadata and path allowlist primitives. 199 Rust and 31 focused integration tests passed; 28 locked pins intact, no complete locked battery rerun. No live OAuth routes or persistent grant store yet. Next implement HTTP authorization/token/registration flow with private operator consent and live native admission, persistent secure state and audit. Keep existing Funnel and 0.5.0-beta production unchanged.

## Current gate: 0.5.0-beta Linux release — DEPLOYED AND PUBLISHED

Release commit a3a8df21259510844fcab93d4ea1364ad883fcd6, GitHub v0.5.0-beta and crates.io veyl 0.5.0-beta verified. Direct BridgeDev acceptance: 186 Rust, 287 locked + 6 modes, 48 focused integration and lifecycle tests PASS. Both Low defects fixed. All six managed binary copies and production gateway match the release. Policy unchanged; rollback and artifacts recorded in STATUS.md. Native Android/Termux remains unverified for this tag; do not claim cross-platform acceptance. Next gate: native Termux verification of the exact release source, then resume platform feature development after operator direction.

## Current gate: checkpoint 3 security hardening / 0.5.0-beta — HOLD

Both AGY Low findings fixed in separate checkpoint3-hardening/source worktree. See latest STATUS.md. Original platform-foundation.l7Ge9o1L source and binaries remain unchanged. New optimized build 7280bd4c47234a62 and forced collision test 5d1a327497f04add both exit 0; 54/54 focused checks passed. Verify ../SOURCE_SHA256SUMS-0.5.0-beta and ../release-0.5.0-beta/SHA256SUMS, then AGY independently reruns locked acceptance, targeted negatives and native Termux when available. No release promotion before exact candidate acceptance.

## Current gate: architecture checkpoint 3 / 0.5.0-beta candidate — HOLD

Direct BridgeDev implementation (no Codex) of shared session/admission, portable audit/job/activity/TimeShift contracts complete. 184/184 Rust and 46/46 focused integration cases passed on the versioned debug candidate; see latest STATUS.md and ARCHITECTURE.md. Operator will ask AGY to independently test. Source remains isolated/uncommitted: verify ../SOURCE_SHA256SUMS-0.5.0-beta, use ../veyl-0.5.0-beta-source.tar.gz for a disposable independent copy. Optimized build job 294162ea8eaa4389; verify exit and ../release-0.5.0-beta/SHA256SUMS. Native Android pending (Waydroid stopped); prior native previews retained. AGY owns locked acceptance and adversarial checks; do not modify locked tests/pins. No promotion until exact optimized candidate and independent verification are accepted. Existing production and three managed binaries remain 0.4.0-beta; separate connector is optional preview.

## Current gate: architecture checkpoint 2 / HOLD

Both AGY P0 defects fixed; shared capability/tool identities and typed workspace grants implemented. Native Android compiler -D warnings and Linux features 16/16 pass. Read latest STATUS.md and ARCHITECTURE.md. Exact previews ../architecture2-preview-bin and ~/veyl-termux-architecture2/bin. Continue common HTTP/session and portable audit/job/TimeShift/UI contracts before version 0.5.0-beta and full independent acceptance. Preserve production and old candidates. No promotion.


## Current gate: architecture migration checkpoint 1 / HOLD

Read ARCHITECTURE.md. Shared MCP protocol and credentials, platform-specific entry points and separate connector module implemented; host regression passed. Continue modular migration before new Android, Windows or public connector features. Preserve production and prior guest builds. Full native and locked acceptance pending. See STATUS.md for exact binary hashes and tests.


## Current gate: separate connector persistent pairing / native8

Linux isolated registry and native Android heartbeat pass; real reconnect across Linux connector restart verified. Run python3 -B tests/connector_persistence.py ../connector-pairing-bin/veyl-connector -v from candidate source. Guest binary ~/veyl-connector-native8/bin/veyl-connector. See STATUS.md and receipts. Cloud endpoint, OAuth and ChatGPT plugin registration remain pending; no public route or production promotion.


## Current gate: separate connector preview / HOLD

Standalone local preview veyl-connector passes 2/2 HTTP cases. See STATUS.md. Test with python3 -B tests/connector_preview.py ../connector-preview-bin/veyl-connector -v in candidate source. Cloud endpoint, persistent pairing, OAuth and account plugin creation remain blocked/pending; preserve existing gateway and native7. No marketplace listing or promotion.


## Current gate: shared core extraction 1 / native7

Read SHARED_CORE.md. Native6 personally verified; native7 shares credential primitives and passes host and native tests. Personal preview: ~/veyl-termux-native7/bin/mcp-gateway and tests/android_http.py. Preserve existing connector and grants. Public marketplace relay and OAuth remain proposals, not deployed. Windows paused.

## Current gate: Android native6 audited text mutations — HOLD

Native5 personally accepted (6/6); native6 development tests 7/7. Exact guest binary ~/veyl-termux-native6/bin/mcp-gateway. Test: cd ~/veyl-termux-native6; python3 -B tests/android_http.py "$PWD/bin/mcp-gateway" -v. See latest STATUS.md for hashes and limits. Existing grants preserved. No root or command execution, public route, or production promotion. Continue with worker isolation and authenticated HTTPS remote MCP in separate checkpoints.


## Current gate: native Android HTTP preview (HOLD)

Native5 authenticated loopback MCP passes 4/4 HTTP and 2/2 stdio on ordinary Termux UID. See latest STATUS.md. Personal test: cd ~/veyl-termux-native5; python3 -B tests/android_http.py "$HOME/veyl-termux-native/target/debug/mcp-gateway" -v. No persistent service or actual remote ChatGPT route configured. Local CLI android-init, android-add-client and android-serve provide explicit read-only operator preview. Preserve native5 source and logs; no promotion before acceptance. Windows paused.


## Current gate: Android native foundation PASS, further development HOLD

ADB authorized, ordinary Termux UID 10156 with native Android/Bionic toolchain. Native3 source and debug binaries verified; actual 2/2 MCP smoke and 3/3 Rust workspace tests pass. See latest STATUS.md and native-receipts. Guest source ~/veyl-termux-native3, binaries ~/veyl-termux-native/target/debug/. Native reader uses descriptor-relative openat with per-component procfs mount identity, no symlinks, private ownership and bounded reads. Android seccomp rejects the previous openat2 path (SIGSYS); Linux production containment unchanged. Next build the native credential boundary and authenticated loopback read-only MCP, then add audited mutations separately. No root changes or permission escalation; no release or promotion yet. Windows paused.


## Current gate: Android/Termux first

Windows paused by operator. Use existing isolated platform-foundation candidate; native Termux installed but ADB authorization denied. See STATUS.md and PLATFORMS.md for the expanded private-workspace read/list/info implementation and host-only verification. Native Bionic build and SELinux tests are next; no production changes or publication.

## Current gate: native platform bootstrap

Use isolated `platform-foundation.l7Ge9o1L/source` based on `0335e36`; [PLATFORMS.md](PLATFORMS.md) records the Notion requirements and exact test entry points. Linux production remains 0.4.0-beta. Native Windows and Android builds are blocked pending guest/toolchain availability; user must authorize Waydroid ADB and Windows VM preparation must preserve a consistent checkpoint. Do not bypass Android authentication with root or use GNU/Linux executable on Bionic. Run Android under the Termux app UID. Windows probe intentionally exposes only platform_info; secure Windows handle/ACL/junction adapter is next. Android native private read needs real Bionic/SELinux acceptance before broader capabilities. Preserve independent Linux acceptance pins and do not deploy/publish before exact-candidate approval. Nightshift remains separate.


## Current gate: 0.4.0-beta deployed; Nightshift next

Release `7da68e4ae3fb2aefb25183432d2268963cdc197e` is deployed locally and published to GitHub and crates.io. See the latest STATUS.md entry for receipts, rollback and limitations. Existing ChatGPT grants remain unchanged; separately authorize TimeShift tools if desired. Begin Nightshift only in a new isolated candidate. Follow AGENTS.md: exact-candidate operator approval now covers local upgrade, canonical main/GitHub release and matching crates.io publication, subject to verification and no silent permission expansion. Older HOLD entries below are historical.

## Current gate: revised TimeShift 0.4.0-beta with Activity details — APPROVED for promotion

Use `../release-tui-bin/` (not the earlier `../release-bin/`) for the next personal preview/promotion. Activity Enter shows captured commands and d toggles JSON. The original gateway and CLI checksums are unchanged. See STATUS.md for focused verification. Verify the revised `../SOURCE_SHA256SUMS` and `../release-tui-bin/SHA256SUMS`; do not install or publish until the operator explicitly approves the revised candidate. Existing permissions and production service remain unchanged.


## Current gate: TimeShift 0.4.0-beta — HOLD for operator confirmation

Candidate `~/.local/share/veyl-development/candidates/timeshift-native.4VQ4Pbv1/source`, base `84a1b4d`. Native UTF-8 checkpoints, owner-scoped signed history, preview, guarded restore/redo and retention complete. See STATUS.md for verified results, receipts and exact hashes; see TIMESHIFT.md for limitations and permission controls. Verify `../SOURCE_SHA256SUMS` from source and `../release-bin/SHA256SUMS` from release-bin before promotion. Explicit operator confirmation required; do not publish or upgrade before then. Preserve all existing production permissions, provider workspace grants and jobs, and save rollback. Separately ask before enabling new TimeShift grants. No Nightshift work in this checkpoint.


## 0.3.1-beta release acceptance

The operator requested GitHub promotion and a version bump. Exact versioned optimized build, 168 Rust cases, 287 locked cases, 6 three-mode cases, 33 focused integration cases, browser checks, and all 28 locked hashes passed. See current STATUS.md and the candidate's verification receipts. Publish the verified Linux x86_64 beta bundle, preserve rollback, and validate the operator-requested Projects workspace grants after local upgrade. TimeShift and Nightshift remain out of scope.

## Previous gate: provider-only folder dashboard preview

Previous workspace fix `2cf0ea0` is deployed and pushed. New candidate `workspace-dashboard.d9ELDmvu/source` contains folder grant CLI, local dashboard editor, custom staged bundle registration and visual refresh. Focused optimized 19/19, browser and real Projects provider tests passed. See STATUS.md and UPSTREAM_WORKSPACE.md; full locked/Rust process receipt unavailable, so complete that gate with fresh exact-release verification before operator approval. Personal preview: `python3 -B tests/dashboard_preview.py` (synthetic read-only UI at localhost:7333); functional fixture: `MCP_GATEWAY_BIN="$PWD/../release-bin/mcp-gateway" python3 -B tests/workspace_dashboard.py -v`. After approval, use native updater and audited `workspace-folder chatgpt rea /home/onyx/Projects` and `workspace-folder chatgpt rust-anything /home/onyx/Projects` commands. Preserve existing native roots, YOLO mode, other client grants, and provider restrictions; validate live ChatGPT calls. No new candidate promotion or production root grant performed yet.

## Next gate: personal preview and exact-candidate operator approval

Corrected candidate `upstream-workspace.Dx2gWMVJ/source`, base `79f5d79`, passed direct BridgeDev verification: 168 Rust cases, 287 locked cases, six three-mode cases, 17 focused release regressions, and both real-provider/boundary acceptance cases (using a separately corrected non-locked fixture). See STATUS.md for receipts, fixture corrections and exact release checksums. Use `../release-bin/` for isolated preview; verify manifests. The operator may personally run `MCP_GATEWAY_BIN="$PWD/../release-bin/mcp-gateway" python3 -B tests/upstream_workspace_jobs.py -v` or the separate `python3 -B ../bridge-acceptance.py -v` real-provider acceptance fixture. Explicit personal approval of this exact candidate is required for deployment and promotion. Do not alter production or begin TimeShift/Nightshift before the approval gate.

## Previous gate: AGY re-verification of job-enabled upstream workspace correction (historical)

HOLD: no deployment or promotion. Same candidate and base. Missing JobClient schema field fixed; focused release tests 17/17 and unchanged real-provider 81-tool test_01 on debug passed. Verify fresh manifests and corrected release binaries in `../release-bin/`. AGY's unchanged test_02 reached line 338 but its mock attempts UTF-8 decoding of a binary .pyc; confirm and fix its fixture within AGY's own independent non-locked harness. Re-run both job-enabled cases, the locked battery and Rust tests on the exact corrected candidate. See current STATUS.md. Retain operator approval gate; do not start TimeShift or Nightshift.

## Previous gate: AGY upstream workspace acceptance (pre-fix)

Use the isolated `upstream-workspace.Dx2gWMVJ/source` candidate at base `79f5d79`; preserve the dirty source and verify the adjacent candidate manifests before building. See [UPSTREAM_WORKSPACE.md](UPSTREAM_WORKSPACE.md) and STATUS.md. Local focused tests passed 14/14. AGY must independently test real pinned REA and Rust Anything against disposable approved workspace files, protected state and mount aliases, stale root identity, file/tree limits, revocation, cross-client and timeout cases, then run the full locked battery and verify release binaries. Do not alter the locked tests or production; request exact-candidate operator approval before any promotion. No TimeShift or Nightshift changes are part of this checkpoint.

## 0.3.0-beta accepted for production promotion (2026-11-25)

Candidate `~/.local/share/veyl-development/candidates/timeshift.o89oyRsF/source` (`candidate/0.3.0-beta`, version `0.3.0-beta`) passed independent AGY acceptance: 158/158 Rust tests, 287/287 locked cases across 28/28 unchanged pins + 6/6 three-mode cases, all 17 Python/JS/shell suites, Brave CDP browser checks, real REA + Rust Anything runtime bundle execution, delegated systemd & updater E2E suites, and offline RustSec advisory evaluation (47 advisories, 0 matches). Approximate BridgeDev parity is an 86% functional-domain estimate (6 of 7 domains implemented); TimeShift (`rewind`) and autonomous Nightshift remain unimplemented. Canonical `~/Projects/veyl` `main` push and crates.io publication require explicit separate authorization.

## 0.3.0-beta candidate

Continue in `~/.local/share/veyl-development/candidates/timeshift.o89oyRsF/source`. The disconnected FUSE sibling preflight issue is corrected and 25 debug integration cases passed. Preserve existing parity-86 and live-status sources and previous binaries. The versioned release does not contain TimeShift or Nightshift. Verify the exact release binaries and independent locked suites, then deliver an isolated personal preview before promotion. Do not claim final parity.

## 86% Parity Candidate Ready for Personal Acceptance (2026-11-25)

Candidate source: `~/.local/share/veyl-development/candidates/parity-86.hjODQIAS/source`
Branch: `dev/parity-86` (base `0e2cf55`), version `0.2.5-beta` (unchanged until push/release approval).
Shared build cache: `CARGO_TARGET_DIR=/home/onyx/Projects/veyl/target`.

Completed in this candidate:
1. Native updater fix & integration (`src/update_cli.rs`, `src/service_cli.rs`, `tests/updater_lifecycle.{sh,py}`) with crashed-unit rollback `reset-failed`, recovery journal, and `--recover`.
2. Persistent processes + durable budgets (`process_resize`, `shell_status`, `job_logs` base64/utf8, `cpu_percent`, `memory_bytes`, `max_output_bytes`, `job_retention_count`, `task_run` `ephemeral_worktree: true`).
3. 12 structured Git tools (`git_status` .. `git_push`) and BroadYolo `.git/hooks` workspace cwd preservation.
4. System & context tools (`processes` section, `network` rates, wake-safe NVIDIA telemetry, `load_path_rules`, `remember`, `chezmoi_inspect`, `list_skills`, `load_skill`).
5. Extension, skill validation & upstream workflows (`extensions_search`, `extensions_list`, `extensions_info`, `skills_validate`, `mcp_list`, `mcp_status`, `mcp_info`, `mcp_test`, 8 inert `*_propose_*` tools, dashboard `/api/dashboard/requests`).

All checks passed after the final edit (157 Rust tests, 287/287 locked cases across 28/28 unchanged pins + 6/6 three-mode suite, Python feature/E2E suites, Brave CDP browser verification, delegated systemd & updater lifecycles, zero-test-hooks release build, Clippy, rustfmt, JS syntax). Production service, `~/.local/bin`, `~/.cargo/bin`, and GitHub `main` remain untouched awaiting operator personal verification and explicit push approval.

To personally verify in isolated preview mode without touching production:
```sh
cd ~/.local/share/veyl-development/candidates/parity-86.hjODQIAS/source
python3 -B tests/dashboard_preview.py --source "$PWD"
```

## Persistent process sessions — ready for personal verification

Continue in
`~/.local/share/veyl-development/candidates/persistent-process.GgGwXhSb/source`
at base `33e9f56`. Leave the existing production process and other candidates
alone. The current binaries are copies in `.candidate-preview/sessions/`.
Run the command in [Process sessions](PROCESS_SESSIONS.md) before handing
the same source and binary manifests to AGY. All final local gates and
100 relevant locked cases passed. Use the dedicated hook binary only for
the audit suite. See [STATUS](STATUS.md) for logs, revisions and remaining
limitations. Preserve the separately verified extended-runtime implementation.

## Extended-runtime candidate

Continue from the isolated durable-budget candidate documented in STATUS.md
and EXTENDED_JOBS.md. Require independent acceptance and personal testing
before merge or install. Do not treat a 24-hour budget test as a 24-hour soak.
Complete persistent process I/O, durable log/resource budgets, structured Git,
context/chezmoi inspection and extensions before expanding into Nightshift.
Updater stays isolated at its prior repair checkpoint.

## Current continuation checkpoint

Main and origin/main are synchronized at 2d1bd03 before the retention-docs
checkpoint. TUI compatibility fixes verified; production still runs the
previous personally accepted build. Historical target references now resolve
relative to `~/.local/share/veyl-development/artifacts/2d1bd03/legacy-target/`.
Use `~/.local/share/veyl-development/candidates/updater-fix.QogvnTli/source`
for remaining updater work. Six focused tests per CLI and Clippy passed;
independent integration and crash recovery are still required. Do not merge
or install that candidate yet. Next parity work is owned persistent processes,
then longer durable jobs, Git workflows and Nightshift. Version stays 0.2.5-beta.

## TUI regression correction

The two AGY TUI blockers below are resolved in the corrected candidate;
Linux 16/16, dynamic jobs 4/4 and monitor 9/9 pass. Keep the exact operator
preview/approval gate for any new deployment. The updater is a separate
unaccepted security-sensitive candidate.

## Independent verification handoff for `7c2db86` and pending updater (2026-11-25)

- **Push status**: Local `main` (`7c2db86`) was **NOT** pushed to `origin/main`
  (`2ba71c1`) because `tests/linux_features.py::test_monitor_pairing_views_and_keyboard`
  failed on reverse video `\x1b[1;7m` (must inherit terminal background with
  `\x1b[1;4;33m`) and filter text `/ <query>` vs `Filter: <query>`. Fix those
  in an isolated candidate, re-verify via `veyl-monitor` preview + full
  `linux_features.py`, and obtain operator acceptance before pushing.
- **Development preview**: `tests/dashboard_preview.py` and `tests/test_dashboard_preview.py`
  passed full Brave CDP verification (HTML/CSS/JS live reload, 9 diagnostic views,
  marketplace icons, theme toggle, isolation/mutation rejection, port conflicts,
  stop/restart recovery). Keep the runnable preview workflow mandatory for all
  future changes (see `docs/development/PREVIEW.md`).
- **Pending updater (`target/update-ui.RH8qSZQf/source`)**: Held from merge/release.
  Codex must resolve: Cargo `st_nlink=2` rejection breaking `--from-dir target/release`,
  `update_stop()` aborting rollback when a crashed unit stays in `ActiveState=failed`,
  `.veyl-update-<nonce>` stage directory cleanup, multi-dir `mcp-gateway`/`veyl-monitor`
  coverage + non-systemd `--from-dir` support + prerelease/version tag handling,
  and add isolated end-to-end updater + rollback integration tests.
- **Parity matrix**: Updated `docs/PARITY.md` against current BridgeDev source
  (`persistent-shell.ts`, `shell.ts`, `git.ts`, `checkpoint.ts`, `rewind.ts`,
  `chezmoi.ts`, `context.ts`, `extensions.ts`, `host-controller.ts`). Next parity
  work remains persistent shell/process supervision, structured Git mutations,
  multi-hour/checkpoint/rewind Nightshift execution, chezmoi drift guard, project
  skill/rule/memory loading, and extension proposals.

## Approved TUI and preview checkpoint

The operator approved the compact TUI and selection fix. See STATUS.md and
PREVIEW.md. All subsequent changes must be personally testable before
promotion. Source preview is on-demand and does not connect to production
APIs. Keep the version unchanged and the updater candidate isolated.

## Same-version dashboard checkpoint

See STATUS.md for the compact dashboard, nine subsystem views and marketplace
icons. Public release v0.2.5-beta remains immutable; development deployments
retain this version until the operator authorizes a bump. The updater is
isolated in `target/update-ui.RH8qSZQf/source`, pending independent security
review after AGY quota exhaustion. Do not overwrite that candidate.

## v0.2.5-beta operator UI release checkpoint

Source and verification receipts: `target/operator-ui.hRrNjrGW/source`.
See STATUS.md and release-025-{acceptance,retest,agy-review}.log. AGY static
security review passed; BridgeDev executed the locked acceptance and release
integration suites. Bulk mode is explicit and does not alter existing grants
on upgrade. Keep BridgeDev available for the next parity milestone.

## 2026-11-25 — v0.2.4-beta production handoff

Production upgrade was authorized and completed by AGY. The matching
`veyl`, `veyl-monitor` and `mcp-gateway` binaries are installed in both
local-bin and Cargo-bin. BridgeDev independently compared all six files and
the running gateway executable to the release build. Gateway PID 283899 was
active and enabled with no unexpected restarts at verification time.

Executable rollback backups belong outside the validated state tree:
`~/.local/share/veyl-backups/pre-v0.2.4-beta/{local-bin,cargo-bin}`.
The prior location inside the state tree was rejected by the layout guard;
AGY moved the backups and validation passed. Verify saved hashes before
any rollback, and do not restart production with active jobs.

Production smoke tests through actual Funnel, loopback, private HTTPS and
a real terminal passed; see STATUS.md. The public Funnel check must resolve
public ingress rather than the node's tailnet address. Preserve mandatory
Funnel admission markers. Raw local trace is disabled after verification.

Next feature work: persistent interactive processes and shells, bounded
multi-hour execution, structured authorized Git operations and Nightshift
agent orchestration. Preserve the release checkpoint and all independent
test pins. No new permission expansion or production changes for parity
development.

## Independent verification, GitHub integration, and rollback-safe upgrade procedure (2026-11-25)

Candidate `target/parity-monitor.ZWQdxYaI` (manifest SHA-256
`9ebc7a2ea11c5181e02f92760ac8300590190d1af4a7827d51cd19ee7391d602`) passed full
independent acceptance (105 Rust tests, 28/28 locked suites / 287 cases with 28/28
original pins, 37 Python integration tests, Brave CDP, PTY TUI, private systemd
lifecycle, offline release build without `test-hooks`, and 4 adversarial probes)
and was integrated into `/home/onyx/Projects/veyl` with existing canonical docs preserved.

### Production provenance & PATH
- `PATH` resolves `~/.local/bin` before `~/.cargo/bin`.
- `mcp-gateway.service` executes `~/.local/bin/mcp-gateway` (currently older PID `212410`).
- `~/.cargo/bin/veyl-monitor` and `~/.cargo/bin/mcp-gateway` hold even older copies. Do not mix an updated CLI/monitor against the older gateway daemon.

### Rollback-safe upgrade procedure (historical; v0.2.4-beta upgrade completed)
1. Back up all existing binaries across both `~/.local/bin` and `~/.cargo/bin` into separate private directories **outside** Veyl's validated state tree. For future upgrades, choose a new backup directory; do not overwrite the existing v0.2.4-beta rollback copies.
   ```sh
   install -d -m 700 "$HOME/.local/share/veyl-backups"
   backup=$(mktemp -d "$HOME/.local/share/veyl-backups/pre-upgrade.XXXXXXXX")
   mkdir -m 700 "$backup/local-bin" "$backup/cargo-bin"
   cp -a ~/.local/bin/{veyl,veyl-monitor,mcp-gateway} "$backup/local-bin/"
   cp -a ~/.cargo/bin/{veyl,veyl-monitor,mcp-gateway} "$backup/cargo-bin/"
   ```
   Never store executable backups under `~/.local/state/veyl`: the state-layout validator rejects them. Before restoring, verify backup hashes against a trusted record; same-UID backups outside protected state are not an independent integrity anchor.
2. Build release binaries in `/home/onyx/Projects/veyl`:
   ```sh
   cargo build --offline --locked --release
   ```
3. Stage and atomically replace all three binaries together (using `install -m 755` into temp paths then `mv -T`, updating both `~/.local/bin` and `~/.cargo/bin` so no stale copy remains on `PATH`):
   ```sh
   for bin in veyl veyl-monitor mcp-gateway; do
     install -m 755 "target/release/$bin" "$HOME/.local/bin/.${bin}.new"
     mv -T "$HOME/.local/bin/.${bin}.new" "$HOME/.local/bin/$bin"
     install -m 755 "target/release/$bin" "$HOME/.cargo/bin/.${bin}.new"
     mv -T "$HOME/.cargo/bin/.${bin}.new" "$HOME/.cargo/bin/$bin"
   done
   ```
4. Restart the user service cleanly and verify health + active binaries:
   ```sh
   systemctl --user restart mcp-gateway.service
   systemctl --user status mcp-gateway.service
   veyl service status
   ```
5. Rollback (if needed): copy saved binaries back with `mv -T` and re-run `systemctl --user restart mcp-gateway.service`. Existing signed job receipts and audit ledger are backward-compatible.

### Next functional parity milestone
- Interactive persistent shell & supervised process tools (`shell_status`/`shell_reset`, `start_process`/`process_status`/`process_output`/`stop_process`/`clear_processes`)
- Structured Git mutation workflow tools (`git_status`/`git_diff`/`git_commit`/`git_branch`/etc.)
- Operator-approved multi-hour task budgets and autonomous Nightshift loop checkpoints/rewind
- Repository skill discovery (`load_path_rules`, `remember`), `chezmoi_inspect` drift guard, and upstream/REA transport support

---

## Combined permission and activity candidate (2026-11-25)

Use the frozen snapshot named in `target/activity-candidate.path`. It retains
the unified mode rules and AGY's permission and UI changes. Activity tracks
individual HTTP MCP tool calls and uses `call_id` to fetch optional trace
details. The Activity table never merges audit sequences or job IDs. The
security ledger and durable job status have separate views. Code in
`src/http/activity.rs` owns live counters and retention. The original
`/dashboard/api/audit` endpoint and `veyl-monitor --view audit` keep ledger
inspection available without synthesizing elapsed durations.

The initial production snapshot reproduces the running gateway exactly.
`target/activity-production-reproduction.log` identifies its source digest
and installed artifacts. New source and binary hashes are recorded separately
in `target/activity-candidate-digests.log`. The live connector was probed
read-only with no credential output. Production Funnel returned 28 tool
schemas in fresh sessions. Establish the ChatGPT application's state before
classifying the old 16-tool observation as a cache issue.

Use `tests/activity_features.py` for live overlap, timing, disconnect,
timeout and redaction regressions. `tests/linux_features.py` covers the
Funnel filter and actual monitor PTY. `tests/onboarding_browser.py` drives
Brave through CDP and exercises real Activity rows, pairing and navigation.
All 287 locked cases passed with the 28 pins unchanged. AGY and then
BridgeDev each verified the candidate digests and passed nine focused cases.
BridgeDev's initial Broad YOLO spawn failure did not reproduce with either
the old or new build. See STATUS for logs and the production provenance.
The installed service and binaries are outside this checkpoint.

## UI improvement, activity correlation, and Broad YOLO verification handoff (2026-11-24)

### Completed items
1. **Activity Monitor and Web Dashboard correlation**:
   - Both TUI (`src/bin/monitor_tui/mod.rs`) and web dashboard (`src/http/dashboard/app.js`, `index.html`, `style.css`) now correlate tool intent and outcome events by `job_id` or sequence key into clean, unified rows.
   - Replaced fragmented rows with columns: `TIME | TOOL / EVENT | CLIENT | STATUS | DURATION | TARGET / SUMMARY`.
   - Local timezone formatting (`11:12:48 PM`) using system timezone offset.
   - Elapsed duration rendered in milliseconds, seconds, or minutes.
   - Operation summaries extracted from command, path, sections, job ID, profile, or working directory.
   - Semantically colored status pills: RUNNING (cyan), SUCCESS (green), FAILED (red), CANCELED (yellow), TIMED_OUT (bright red).
   - Filtered out repetitive `funnel_admission` entries.
   - Header status line displays live count of active MCP calls and execution mode per client (`chatgpt: YOLO, codex: STANDARD, agy: STANDARD`).
   - Access & Security layout refreshed with responsive cards and tables for State, Masked user files, and Read-only system paths.

2. **Broad YOLO and Tool Availability**:
   - `JobClient` in `src/jobs/config.rs` deserializes `_deny_tools` and `_native_tool_preset`.
   - `chatgpt` configured with `native_tool_preset: true` in `~/.local/state/veyl/clients.json`.
   - `veyl mode set chatgpt yolo` outputs `client=chatgpt client_state=enabled mode=yolo effective_policy=yolo native_tool_preset=true tool_grants=28`.
   - Full 28 native tools discoverable via MCP `tools/list`.
   - Initial hypothesis was a cached ChatGPT connector schema. Fresh Funnel probes later confirmed 28 tools, with the frontend cause still unverified.

3. **Durable Jobs and Lifecycle**:
   - Long-running tasks verified with background profiles: asynchronous execution, incremental streamed output via `job_logs`, cross-session recovery via persistent job IDs, clean cancellation via `job_cancel`, and process tree reaping (SIGTERM).

4. **Structured System Internals JSON**:
   - Native structured inspection (`system_inspect`) verified across CPU, RAM (including Linux PSI pressure metrics), GPU, storage, network, audio, Bluetooth, Sway, desktop, and systemd services.

5. **Systemd Startup and Unattended Execution**:
   - Verified `systemctl --user is-enabled mcp-gateway.service` (`enabled`), `is-active` (`active`), and `loginctl show-user "$USER" -p Linger` (`Linger=yes`). Unattended execution runs before login and persists across sessions.

---

## Unified permission architecture and AGY UI coordination

The permission checkpoint changes the CLI, policy admission, job schema
compatibility and dashboard status data. UI assets, TUI rendering and the
sandbox implementation stay with the concurrent checkpoint. The dashboard
API now emits `mode: standard|yolo|full`, a separate `disabled` boolean,
`native_tool_preset`, and exact effective native/tool-wrapper names in
`grants`. Display Standard, YOLO and FULL as the three user-facing modes.
Use enabled state as a separate badge. Treat a false preset on an older YOLO
approval as retained explicit grants. Read-only status remains read-only.

Test the current patch from `~/Projects/veyl` with `cargo fmt --all --check`,
`cargo clippy --offline --locked --all-targets -- -D warnings`,
`cargo test --offline --locked`, and `python3 -B tests/permission_modes.py`
after an offline debug build. The four integration cases cover interactive
selection, legacy migration, binding the new preset to the audit approval,
explicit denies, protected state, existing sessions and restart persistence.
On older schemas, `veyl yolo standard` and `yolo reset` recover to enabled
Standard. Version 3 uses `mode enable` to restore client access.
Canonical `veyl mode standard` changes the selected mode, and
`mode enable` or `mode disable` changes the independent enabled state.
An interrupted client update can be recovered to restricted, disabled
Standard using `mode disable CLIENT`.

The 28 external pins and all 287 locked cases passed in the isolated source
snapshot. AGY reran six focused checks against the candidate in
`target/permission-candidate.path` with digests in
`target/permission-candidate-digests.log`. Its execution receipt is
`target/permission-agy-execution.log`. Use that same snapshot when integrating
with the UI checkpoint. Production configuration and services were untouched
during implementation and testing.

## Production release v0.2.3-beta and next milestone roadmap (2026-11-24)

### 1. Release status

The v0.2.3-beta Linux beta release has been independently accepted and published:
- Version: `0.2.3-beta`
- Exact per-tool grant enforcement and job_start argument sanitization verified across 27 locked acceptance suites (27/27 PASS).
- All 94 Rust tests, Clippy, formatting, Linux subsystem tests (16/16), product integration tests (9/9), and browser CDP tests passed.
- Concise CLI verbs (`veyl mode <verb>`, `veyl ui`/`veyl dashboard`, `veyl tui`/`veyl monitor`, `veyl setup --root "$PWD" --yolo`) verified.

### 2. Next milestone roadmap: BridgeDev parity and Nightshift orchestration

To reach complete parity with `/home/onyx/Projects/bridge-dev`, implement the following modular components:

1. **Chezmoi Inspection and Drift Guard (`chezmoi_inspect`)**:
   - Reference: `bridge-dev/src/tools/chezmoi.ts` and `bridge-dev/src/lib/chezmoi-guard.ts`.
   - Read-only tool that resolves live target paths to canonical `~/.local/share/chezmoi` source files.
   - Detects templates (`.tmpl`), dirty Git status, unmanaged files, and outside destinations.
   - Prevents AI clients from directly mutating live managed dotfiles without going through chezmoi source.

2. **Interactive Process and Persistent Shell Session**:
   - Reference: `bridge-dev/src/tools/shell.ts` and `bridge-dev/src/lib/persistent-shell.ts`.
   - Persistent shell session with stateful cwd across calls (`run_command`, `shell_status`, `shell_reset`).
   - Process supervision: `start_process`, `process_status`, `process_output`, `stop_process`, `clear_processes`.

3. **Structured Git Tooling**:
   - Reference: `bridge-dev/src/tools/git.ts`.
   - Discrete, structured tools (`git_status`, `git_diff`, `git_log`, `git_add`, `git_commit`, `git_branch`, `git_checkout`, `git_restore`, `git_push`, `git_pull`, `git_stash`, `git_reset`) returning typed JSON instead of raw text.
   - Replaces token-heavy shell parsing for agents.

4. **Project Skill Discovery and Instruction Packs**:
   - Reference: `bridge-dev/src/tools/context.ts` and `bridge-dev/src/lib/instruction-context.ts`.
   - Discovery of repository-local skills in `.claude/skills`, `.agents/skills`, or `.gemini/skills`.
   - Path-scoped rule loader (`load_path_rules`) for `.claude/rules/*.md`.
   - Auto-memory note tool (`remember`) for session persistence.

5. **Extension Management and Proposal Workflows**:
   - Reference: `bridge-dev/src/tools/extensions.ts`.
   - Operator review request tools (`extensions_propose_add`, `skills_propose_add`, `mcp_propose_add`).

6. **Durable Nightshift Loop Orchestration**:
   - Reference: `bridge-dev/src/lib/checkpoint.ts` and `bridge-dev/src/tools/rewind.ts`.
   - Beyond single-step `task_run` and `job_wait`: full unattended loop orchestration.
   - Automatic Git state checkpointing before each major iteration, structured progress logging, stall detection, and verified rollback (`rewind`).

---

## Next independent acceptance — context, live diagnostics, marketplace

Use ~/Projects/veyl, main; see latest STATUS.md and docs/PARITY.md.
Build in a fresh target directory, review prior local UI changes together
with new context and diagnostic tools. Check protected-file alias and
mount boundaries, explicit grants, malformed/bounded inputs, missing
desktop dependencies, fixed argv/environment, loopback-only diagnostic
endpoint and CSRF, browser skills and marketplace workflows. Verify all
external pins, run trusted acceptance without rewriting its oracles;
review archived harness repository binding first. Test actual Nightshift
primitives, but do not certify autonomous overnight execution. On failure,
return a reproducible finding to implementation owner; only promote
the exact independently accepted commit. No version bump or crate publish.

## Current product and UI checkpoint

Use ~/Projects/veyl on main. Development documents live in
docs/development; historical reports in docs/history. MIT license
authorized. See STATUS.md and ../DASHBOARD.md for the local trace and
operator UI changes. Review trace session boundaries and bounded memory
in independent acceptance; keep durable audit metadata-only. The
BridgeDev marketplace, packs, instruction management and remaining tool
parity are separate unfinished features.

## Product packaging checkpoint

The current checkout is ~/Projects/veyl. The package is named veyl,
with native veyl and veyl-monitor install targets; mcp-gateway remains
available for compatibility. The README documents a direct GitHub Cargo
installation. Historical reports are now under docs/history. See STATUS.md
for the package, install and regression receipts. Confirm a public
software license before publishing to crates.io and keep the GitHub
repository private unless the operator requests otherwise. Continue
independent acceptance before promoting the alpha to a stable release.

## Current checkout and terminal refinement (2026-11-24)

Use `~/Projects/veyl` for all new development. See AGENTS.md for archived
lab and historical worktree paths. The current checkout preserves the
development branch and pending changes. The terminal monitor now has
theme-native dim panel borders, a footer separator and an amber active tab.
See STATUS.md for targeted verification and installed binary identity.
The full independent acceptance of v0.2.2-alpha remains pending.

## UI/diagnostics candidate (2026-11-24)
v0.2.2-alpha is locally installed for operator review. The latest
STATUS.md entry records verification and rollback. AGY must independently
review the new terminal handling, admin tab navigation, job metadata
and explicitly granted system_inspect capability before release
promotion. Existing connector URL and BridgeDev remain operational.
The next substantive parity checkpoint is project/system context,
Sway/PipeWire diagnostics, interactive process tools and Nightshift
orchestration. Do not claim the new kernel inventory covers those yet.


## Current production checkpoint (2026-11-24)

v0.2.1-alpha is installed and verified via the existing ChatGPT
connection. See the latest STATUS.md entry for evidence and rollback.
Next implement bounded native structured Linux diagnostics and
project context using the current BridgeDev parity matrix; independently
verify schema, scope, resource limits, and failures before granting new
tools to production clients. Nightshift primitives have passed the
disposable demonstration, but unattended multi-hour model execution
still needs verification. Keep BridgeDev available.

## Release Candidate v0.2.1-alpha Verification Complete (2026-11-24)

Base commit: `364e954701a950dbaced6dec3dc1678388016c5c` (v0.2.0-alpha).
All independent verification, onboarding hardening, and BridgeDev Nightshift parity objectives are complete.

- **Rust Suite:** 52/52 tests passing (`cargo test` clean).
- **Clippy:** Passed with zero warnings (`cargo clippy --all-targets -- -D warnings`).
- **Locked Suites:** All 28 external pins match; `locked_three_modes.py` passed 6/6.
- **Integration Probes:** 15/15 Linux probes passed; 5/5 product probes passed; `tests/systemd_lifecycle.sh` passed 7/7.
- **Browser Pairing:** Resolved disposable profile stall via `--incognito`; `tests/onboarding_browser.py` passed (`FIRST_RUN_BROWSER_PAIRING_PASS`).
- **Descriptor Cleanliness:** Sealed leaked file descriptors in sandbox preflights using `sys_close_range(3, 1024, 0)`.
- **Nightshift Demo:** Validated in `examples/nightshift_demo/demo.py` covering system diagnostics, ephemeral Git worktrees, request idempotency, durable job streaming, and clean process tree cancellation.
- **Release Artifacts:** Packaged in `dist/v0.2.1-alpha/` with verified SHA-256 sums:
  - `veyl-linux-x86_64.bin`: `500680a212b35d72dd9d15f6036e9994a9e25b0cc27cd49bea452adb927e7fc5`
  - `veyl-monitor-linux-x86_64.bin`: `7b9e7e33f0cd442853e67d55e2e7293f84857dfdd89288f7605329c0a61a734f`
  - `veyl-linux-x86_64.tar.gz`: `2f9c579dbfe4407c9046d2ec4b644ee80be534ac934ab17b2f01bd9419e9da59`
- **Safety Invariant:** Production binaries and GitHub remote remain unchanged pending explicit user authorization.


This is a separate greenfield product, **not** the harness project and not
production BridgeDev. See `AGENTS.md` and `SPEC.md` for constraints.

Stage: initial skeleton and independently authored locked tests; no agent code
accepted yet. The initial `src/main.rs` deliberately returns an error.

- Protocol: stdio JSON-RPC 2.0, legacy MCP 2025-11-25 initialize lifecycle.
- Crates: std plus pinned serde_json 1.0.154; no SDK downloaded or installed.
- Locked black-box tests: `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`.
- Trusted harness: `/home/onyx/Projects/rust-mcp-gateway-lab/`.
- Expected terminal state for an accepted attempt: `READY_FOR_USER_REVIEW`.
- Agent is restricted to source files; do not alter manifests, specs or tests.

No commit/merge/deploy of generated code without a manual review. All updates,
verification receipts, constraints and blockers should be appended here.

## Current verified state (2026-11-21)

The original M1 skeleton note above is historical. Milestone 1 is now
committed on `milestone1/manual-stdio` at
`54e1571245e5d19802b2a262ad44a19bbe3eec2d` and passes 17 Rust unit
tests plus 15 externally locked black-box tests. The canonical `main` branch
is intentionally unchanged.

The isolated `milestone2/service-contract` worktree starts from that M1 commit.
`SERVICE_ROADMAP.md` defines permanent per-client YOLO, managed services, and
the revised six-pass roadmap. `SPEC_M2_AUTH.md` defines Pass 1 loopback HTTP.
`M2_SECURITY_STATUS.md` records a new, **not-yet-integrated** Rust policy
module with 10/10 independent policy tests and 15/15 M1 regression tests
passing in the trusted network-disabled verifier. No YOLO mode, privileged
execution, HTTP listener, systemd service, service install, or production
cutover has been activated.

## Pass 1 baseline and acceptance boundary

The existing worktree passed the offline build, 17 Rust unit tests,
8 original stdio cases, 7 edge cases, 10 locked STANDARD policy cases,
formatting and Clippy with warnings denied. The three locked hashes match
their recorded values. The trusted Bubblewrap verifier also established that
loopback bind and connect work in its isolated network namespace.

The next gate is an independently authored and locked HTTP suite and its
expected failing baseline. A diagnostic probe confirmed the proposed HTTP
command exits 2 with the stdio usage message. The HTTP entrypoint,
credentials and permissions are specified in [Pass 1](SPEC_M2_AUTH.md). The prior stdio-auth plan in the M1
worktree remains historical. The Rust policy module and its tests are
preserved, including its denial of client-requested YOLO.

A Linux debug stdio baseline measured startup to initialize response at
0.852 ms median and 0.995 ms p95 (12 launches). Ping round-trip was 0.019 ms
median and 0.028 ms p95 (1,200 requests). Three idle samples were
2,828–2,900 KiB RSS and recorded zero CPU ticks over one second each at
100 ticks/sec. These measurements cover the existing stdio process.

### Dependency review

The upstream `rmcp` 3.11.0 release advertises `2026-07-28` and legacy
`2025-11-25` compatibility. The advisory review included the RustSec
tool-schema cache and DNS rebinding advisories and the upstream legacy
session-table advisory. The candidate version is newer than the listed
fixes for those three issues. Recheck the exact selected graph and transport
configuration before adopting it.
[Release and version support](https://github.com/modelcontextprotocol/rust-sdk/blob/rmcp-v3.11.0/README.md) ·
[Tool-schema advisory](https://rustsec.org/advisories/RUSTSEC-2026-0461) ·
[DNS rebinding advisory](https://rustsec.org/advisories/RUSTSEC-2026-0189) ·
[Session-table advisory](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-9pj6-vhgr-3mwh)

A disposable Linux `cargo tree --edges normal` comparison found 21 packages
for Hyper 1.12.0 HTTP/1 with Tokio 1.54.1 and minimal adapters, 39 for Axum
0.8.9 HTTP/1 with JSON, and 88 for `rmcp` 3.11.0 Streamable HTTP with Axum.
All included the existing serde_json pin. These counts exclude the scratch
application itself and cover the transport candidates before application
credential storage and policy dependencies. The Hyper graph also resolved
offline from the existing cache, while the exact Axum and rmcp graphs needed
a disposable online cache. The product manifest and lockfile remain at
their Milestone 1 pins. An exact-version OSV query over 89 distinct packages
returned one informational finding in the rmcp candidate. Its transitive
`chrono` 0.4.45 is marked unmaintained. Review that dependency before
adopting rmcp. The final application graph requires a fresh advisory check.
[RustSec chrono advisory](https://rustsec.org/advisories/RUSTSEC-2026-0543)

### Loopback transport probes

These disposable release-mode probes used Rust 1.100.0 and a single-thread
Tokio runtime. Each row covers eight launches and 800 sequential POST pings
over reused connections in the trusted network-disabled sandbox. Startup was
measured from spawn to reporting the bound port. The Hyper and Axum probes
parsed JSON and returned the matching ID. The rmcp probe used its actual
Streamable HTTP handler with legacy stateless mode and JSON responses.
Authentication, authorization, file I/O and adversarial load remain outside
these transport-only measurements.

| Candidate | Startup median / p95 (ms) | Ping median / p95 (ms) | Idle RSS (KiB) |
| --- | ---: | ---: | ---: |
| Hyper HTTP/1 | 0.760 / 0.823 | 0.050 / 0.142 | 2,992 |
| Axum HTTP/1 | 0.835 / 1.248 | 0.047 / 0.131 | 3,284–3,288 |
| rmcp with Axum | 0.802 / 2.409 | 0.055 / 0.121 | 5,660–5,704 |

Each candidate recorded zero CPU ticks in two one-second idle samples
at 100 ticks/sec. The low sample count and different protocol work limit the
comparison. Repeat measurements on the selected authenticated gateway
before claiming Pass 1 performance.

## Pass 1 authenticated HTTP — 2026-11-21

`PASS1_HTTP_REVIEW.md` records the completed **foreground loopback** Rust
implementation, pinned dependency versions, external SHA-256 test receipts,
and remaining protocol/security limitations. The earlier "no HTTP test" note
above is now historical. All five trusted acceptance suites passed **43/43**;
the existing Rust unit suite passed **17/17**, and the harness passed 34/34
unit/regression checks. The supplemental HTTP suite caught two GET
authentication/Origin validation defects before the targeted fix.

No merge, push, production service, remote listener, root execution, YOLO
mode or Funnel modification was performed. Pass 1 awaits code review; new
locked tests must precede Pass 2 tools and jobs.

## Pass 2 scoped write and patch — review state

On `milestone2/tools-jobs` at `432507e`, recovered the audit API from
`f93923f` and replaced its pathname-based open with checked Linux directory
and file handles. HTTP now offers `write_file` and `apply_patch` only for
clients with explicit grants. The existing stdio and HTTP `read_file`
behavior retains its regression coverage. The locked write/patch contract
uses `apply_patch` and a 65,536-byte limit.

A mutation grant requires an available private audit log at startup. At
runtime a failed or changed audit binding stops further mutations. Durable
intent precedes staging. The tool records a synced outcome after publication
or rejection and returns an uncertain result if publication or its audit
outcome cannot be verified. Audit records contain only principal, tool,
phase, and time.

The writer rejects symlinks and mount crossings beneath the configured root.
Parents are opened with `openat2` and checked against their pinned handles.
Writes use a private same-directory staging file, fsync, atomic rename, and
directory fsync. New files are 0600. Replacements preserve owner, group, and
ordinary permission bits. Existing extended ACLs and special mode bits cause
rejection. A per-directory advisory lock serializes cooperating mutations.
A patch checks the original digest, requires one exact match, and rechecks
the file identity and metadata before publication.

Trusted Bubblewrap verification passed the following locked suites with
their recorded SHA-256 values before and after execution.

| Suite | Result | SHA-256 |
| --- | ---: | --- |
| `acceptance_m1/locked_stdio_acceptance.py` | 8/8 | `0b9a680e155b156f65cbbb766dc7e9444bf494aeb45bfb4c43c596a55cdadc9f` |
| `acceptance_m1_edge/locked_stdio_edge_acceptance.py` | 7/7 | `5379e25caf867bd6db739a36fc21bc5c80ac4607b77ed7ebdd488d5122f76dde` |
| `acceptance_m2_policy/locked_standard_policy.rs` | 10/10 | `76edbb613950fc66a0fbe9c68bed7d66a19c30a48f2af3d8de4cf1d9378f262b` |
| `acceptance_m2_http/locked_http_acceptance.py` | 12/12 | `3d5f29e088275ab05ec3f8695e036a7cc5a78dde34a54049a09fb025cc07bcbd` |
| `acceptance_m2_http_edge/locked_http_security_edge.py` | 6/6 | `f6331f44e1b4f08f75f841a04f40430014d0e30494b8b60bcf15f5e7c72a8fbd` |
| `acceptance_pass2_audit/locked_audit_contract.rs` | 6/6 | `88f268f3cb60c684c037381a4a729a5b995944db15bf252a43b81fe90f8801c2` |
| `acceptance_pass2_files/locked_file_mutation.py` | 9/9 | `8b26c330e203b5417357dd72ee90badfb8dceb4c13c90ef70c24550a9ce6ca2e` |

A separate independently locked fail-closed HTTP audit suite was unavailable.
Project-local tests cover audit-directory replacement during a live session,
injected intent and outcome failures, atomic replacement, stale snapshots,
concurrent patches, grants, and encoded-byte limits. This receipt supports
review and leaves the independent integration gate open.

The Linux normal graph grew from 32 to 35 packages including the gateway.
The only new direct dependency is `rustix` 1.1.6. An exact-version OSV
query returned no matches for the 48 registry entries in the lockfile.
`cargo-audit` and `cargo-deny` were unavailable. A five-launch debug HTTP
sample with mutation grants had idle RSS of 4,200–4,308 KiB, median
4,236 KiB, in the isolated network namespace.

The tool roots and audit configuration require operator-controlled
directories. The mutation protocol serializes participating writers.
An unrelated local writer can still change a target between its last check
and rename. Host-side changes to the directory tree can also invalidate a
pinned path. The append-only log lacks a tamper-evident chain or crash
reconciliation. Durable filesystem calls run synchronously on the local
HTTP runtime.

## Independent HTTP audit-failure gate — 2026-11-22

The earlier statement that an independent HTTP fail-closed suite was
unavailable is now historical. An external, independently authored suite is:
`/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_pass2_failclosed/locked_http_audit_failclosed.py`.
It is mode `0444` in a mode `0555` directory, SHA-256
`de520c15c57cb7a76326a0d4497c85cbe448445f8eece85d70bfe879781b3c20`.

The trusted network-disabled verifier ran **8/8** new end-to-end cases:
synced intent/outcome order without content/secret logging, audit-file removal,
insecure permissions, audit-file symlink swap, audit-directory replacement,
directory-permission widening, audit inode substitution, and rejected patch
preserving bytes and generating intent/failure records. The hash matched
before and after execution. The original five MCP suites (43/43), independent
audit suite (6/6), and scoped write/patch suite (9/9) also passed unchanged:
**66/66 total independent acceptance cases** passed in this session.
Offline Cargo build/tests, formatting, Clippy with denied warnings and Git
whitespace checks passed. All Rust changes remain uncommitted.

This new suite was explicitly supplied as an external locked test; it is **not
automatically mandatory** in `harness/acceptance.py`, which was left unchanged.
Its coverage does not imply mid-operation storage fault, power-loss,
noncooperating local writer, or crash-reconciliation guarantees. Jobs and
process execution remain out of scope and unavailable.

## Pass 2 committed review and verified mandatory gates

The Linux scoped `write_file` / `apply_patch` increment was committed to
`milestone2/tools-jobs` as
`46e4f94155aab1cfc2c5cac1fd3a59928a270904`.
A separate clean clone of that commit passed all **68/68 external locked
cases**, 25 Rust tests, offline build, formatting and Clippy. All test hashes
were unchanged and the clean clone was removed after verification. The
trusted harness now automatically requires nine suites for this commit and
descendants; only the original five suites apply to historical M1/Pass 1
branches. The previous statement that the audit failure suite was not
mandatory is historical. Harness tests: **35/35** regression and **6/6**
hardening.

Mutation faults bypassing audit intent and combined containment safeguards
were independently detected. SIGKILL before the same-directory rename left
the original file intact and one orphaned stage; ordinary post-staging
failure left no stage. Source, test and limitations are in
`PASS2_WRITE_PATCH_REVIEW.md`.

Direct RustSec `cargo-audit 0.23.0` on the committed lockfile passed with
exit **0** (49 packages, zero vulnerabilities or warnings). The tool was
installed only under the lab's `tools/cargo-audit/` directory; the JSON
receipt is `~/Projects/rust-mcp-gateway-lab/review_reports/pass2_cargo_audit_20261122.json`.
The next increment is separate supervised jobs, beginning with locked tests,
not a production service or YOLO.

## Phase A attempt 1 on `milestone2/jobs-supervisor`

Implemented grant-scoped durable job start, cancel, status, logs, list and
short synchronous execution in the isolated worktree. The runner is a
one-job process in the same binary. It uses an atomic signed receipt, a
private per-job lease, bounded stream logs and verified process-group
cleanup. The gateway can restart while the runner continues. An unfinished
job whose runner is lost receives an uncertain outcome with no replay.
The verified cgroup path uses transient user scopes. The unscoped path
reports CPU and memory ceilings as unavailable.

An offline build, formatting, Clippy, Git whitespace checks and both new
Rust unit tests passed. Local loopback lifecycle, process-tree, output,
audit and ownership probes passed in scoped and unscoped modes.
Project-local RustSec found zero vulnerabilities or warnings. The 11
locked suite hashes were unchanged. The trusted verifier stopped at its
Bubblewrap bind setup, before the 78 external cases could run. Five
existing mutation tests failed here and on the unchanged baseline.
See [the Phase A gate](PASS2_JOBS_GATE.md) for evidence, RSS and remaining
checks. The change remains on this worktree for review.

## Phase A trusted operator verification (supersedes restricted-job results)

After Codex attempt 1 completed, the trusted operator ran the unchanged
68-case Pass 2 acceptance baseline plus the nine-case durable-jobs suite and
one-case output-cap suite in an actual **network-disabled Bubblewrap
environment**. Results: inherited **68/68**, jobs **8/9**, output **1/1**:
**77/78 overall**. This is **not accepted**. All 11 pinned file hashes
matched before and after. Host-side offline build, Clippy, format and
`cargo test` passed (23 unit and 4 mutation integration tests), as did
`git diff --check`. The earlier verifier and mutation test failures inside
Codex were caused by the transient job's NoNewPrivileges environment.

Remaining locked failure: case 08 of
`acceptance_pass2_jobs/locked_durable_jobs.py` (lines 254–260) incorrectly
fails when the canceled grandchild PID has **already disappeared**; its
`while Path(...).exists() ... else: fail` condition treats correct reaping
as failure unless the process remains a zombie. The operator reproduced
this under Bubblewrap with a diagnostic-only callback and saw `GONE`
for the child PID exactly when the locked method raised the failure.
The code must **not** intentionally retain zombies to satisfy that test.
Request independent oracle correction and SHA-256 re-locking; no acceptance
runner or locked test was changed.

Source corrections, outside the Codex attempt, provide a safe 4096-byte
per-stream output default, expected `completed`/`canceled` API states,
conservative `uncertain` reporting for a preexisting live detached runner,
and `lost` for proven vanished runner+child without final receipt. Audit
records now include ID, principal, argv hash, cwd, limits, state and output
byte counts while excluding tokens/argv/output. A real signed-credential
fixture verified those fields and secret absence.

Actual `cargo-audit 0.23.0 --no-fetch --deny warnings`: exit 0, no
vulnerabilities or warnings among 49 lockfile dependencies. One new direct
crate (`serde =1.0.229`, default features off) and one added feature on
the existing `rustix` crate; no production packages or services installed.
The full receipt, one-agent-call model usage, resource measurements and
remaining limitations are in `PASS2_JOBS_GATE.md`. Keep this branch
**uncommitted** until all immutable acceptance gates pass. Part B is skipped
because the independent audit-chain test and recorded hash do not exist.


## Milestone 3 — Independent Acceptance Gate

**Date:** 2026-11-22
**Role:** AGY (Independent Security and Acceptance-Test Engineer)
**Status:** **BLOCKED — DO NOT START CODEX** (Prerequisite Gate 0: Milestone 2 implementation uncommitted)

### Repository state
- **Current branch:** `milestone2/jobs-supervisor`
- **Current worktree:** `/home/onyx/Projects/rust-mcp-gateway-lab/worktrees/m2-jobs-supervisor`
- **Base commit:** `ec2d4e75b01e73e35e8ffdea748581a88b19c1f5` (on top of `46e4f94155aab1cfc2c5cac1fd3a59928a270904`)
- **Working tree state:** **DIRTY / UNCOMMITTED**
  - Modified tracked files: `Cargo.lock`, `Cargo.toml`, `HANDOFF.md`, `SPEC.md`, `src/file_access.rs`, `src/http/admission.rs`, `src/http/mod.rs`, `src/main.rs`, `src/protocol.rs`, `src/security/audit.rs`, `src/security/linux_fs.rs`, `src/security/policy.rs`, `src/tools/mutation.rs`, `src/tools/registry.rs`
  - Untracked files: `src/jobs/` (all 11 modules: `api.rs`, `config.rs`, `launch.rs`, `logs.rs`, `mod.rs`, `process.rs`, `receipt.rs`, `recovery.rs`, `resources.rs`, `runner.rs`, `store.rs`), `PASS2_JOBS_GATE.md`, `PHASE_A_EXECUTION_BRIEF.md`
- **Prerequisite Gate 0 Blocker:** The Milestone 2 jobs supervisor implementation must be committed by the operator before branching `milestone3/yolo-service`. AGY owns tests only and must not create Rust implementation commits.

### Jobs gate (Milestone 2 Verification)
- **Corrected case 08 result:** **PASS** (3.56s). All 9 jobs cases pass.
- **Root cause of false negative:** In `acceptance_pass2_jobs/locked_durable_jobs.py`, lines 254–260 originally used `while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline: ... else: self.fail("child process survived...")`. In Python, a `while...else` construct executes `else:` when the loop condition evaluates to False without a `break`. Because the gateway runner implements subreaper cleanup (`clean_adopted_children`) and successfully reaped the canceled grandchild process, `/proc/{pid}` disappeared immediately, causing the loop condition to evaluate to False and triggering `self.fail`.
- **Exact test correction:**
  1. Establishes that the grandchild actually exists, is running `/usr/bin/sleep 20`, and records its `start_ticks` and `pgid` before issuing cancellation.
  2. Bounded wait checks termination: passes when `/proc/{pid}` disappears, when `start_ticks` changes (PID reuse), or when state is `Z` (zombie). Fails only if the original process survives.
  3. Verifies process group termination via `os.killpg(pgid, 0)` raising `ProcessLookupError`.
  4. Also verifies child process tree termination on timeout.
- **Proof of mutation failure (Mutation 1):** Tested in an isolated disposable copy where process-group termination was omitted (`process::kill_process` instead of `process::kill_process_group` and disabled `clean_adopted_children`). The corrected test failed as expected with `AssertionError: child process survived canceled owned job`.
- **Jobs suite case count:** 9 cases.
- **Previous SHA-256:** `6f9cd819a1fc6d8f7907beea51fa27cb80a16658a8db20195909d2981e7da338`
- **Corrected SHA-256:** `ec71c4966f2639e34c6bbe7357d78a4b7adca8f38f84dd08ce43ae59dc04ee55`
- **Output-limits suite:** 1 case PASS (`acceptance_pass2_jobs_limits/locked_output_caps.py`, SHA-256 `597bb1e3c5b936941dfee5d1b31271b9607e52c1f29594d561feca1abbe1be70`).
- **Milestone 2 total:** **78/78 cases passing** (68 inherited + 9 jobs + 1 output limits).

### Audit-chain suite (Milestone 3 New)
- **Full path:** `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_pass3_auditchain/locked_audit_chain.py`
- **Actual case count:** 13 cases (`test_01` to `test_13`).
- **SHA-256:** `31cf5bf0bbd9945a791177fca04a074169d2456416e19c237de4c5692e4ee2ef`
- **Red-baseline result on M2 codebase:** **1 PASS / 12 FAIL** (Expected red baseline).
  - Passing: `test_13_sensitive_data_exclusion` (existing M2 audit excludes secrets).
  - Failing: `test_01`–`test_12` (missing `prev_hash` cryptographic link, missing `audit verify` CLI, missing torn-tail recovery, missing multi-segment rotation, missing audit size cap enforcement, missing `.mcp-stage-*` cleanup).
- **Known test limitations:** Tests verify contract through CLI `mcp-gateway audit verify [--config <path> | --log <path>]` and handle-relative file structures.

### YOLO/CLI suite (Milestone 3 New)
- **Full path:** `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_pass3_yolo/locked_yolo_service.py`
- **Actual case count:** 11 cases (`test_01` to `test_11`).
- **SHA-256:** `0db6754f9f74b1e9767b8acf98310609441a08df9a005b72ef4cfb8dbd3a21eb`
- **Red-baseline result on M2 codebase:** **3 PASS / 8 FAIL** (Expected red baseline).
  - Passing: `test_02_local_cli_operator_ownership_and_mcp_denial` (MCP tools and spoofed headers denied), `test_08_secret_redaction_in_operator_cli` (secrets not printed), `test_10_os_security_boundaries_service_user_permissions` (mode 0000 access denied by OS).
  - Failing: `test_01`, `test_03`, `test_04`, `test_05`, `test_06`, `test_07`, `test_09`, `test_11` (missing `yolo enable/disable/status` CLI, root bypass denied by STANDARD policy, missing immediate dynamic reload, missing `yolo: true` audit flag, missing config/audit directory containment check, missing gateway-launched job kernel isolation).
- **Kernel isolation coverage:** `test_11_gateway_launched_job_kernel_isolation` verifies positive workspace IO, `/proc` namespace isolation, and negative blocking of config, operator secret key, audit log, symlink traversal, and host process descriptors. Test oracle validated via disposable reference fixtures and unconfined mutation failure.

### Dashboard suite (Milestone 3 New)
- **Full path:** `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_pass3_dashboard/locked_dashboard_acceptance.py`
- **Actual case count:** 15 cases (`test_01` to `test_15`).
- **SHA-256:** `5148a3814e7030fabb4ce6794151c1cfcad27fd1dd4d423744f98346341f8cab`
- **Red-baseline result on M2 codebase:** **0 PASS / 15 FAIL** (Expected red baseline).
  - Failing: `test_01`–`test_15` (missing `dashboard pair` CLI, missing `/dashboard` web interface, missing pairing redemption, missing session management, missing CSRF enforcement, missing browser smoke test).
- **Browser smoke coverage:** `test_15_real_browser_dashboard_smoke_test` launches headless Brave (`/home/onyx/.local/bin/brave`), connects via stdlib Chrome DevTools Protocol (CDP) WebSocket, navigates to pairing URL, verifies DOM rendering, queries UI elements, captures PNG screenshot evidence, and verifies `HttpOnly` / `SameSite` session cookie scoping.

### Service/Network suite (Milestone 3 New)
- **Full path:** `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_pass3_service_network/locked_service_network.py`
- **Actual case count:** 12 cases (`test_01` to `test_12`).
- **SHA-256:** `bb23f8929709b967de5f4c67498c01ac3acce26b29bf289c56dd88b2a6036f49`
- **Red-baseline result on M2 codebase:** **5 PASS / 7 FAIL** (Expected red baseline).
  - Passing: `test_02_loopback_binding_and_remote_denial`, `test_03_tls_support_on_configured_endpoints`, `test_04_session_timeout_and_activity_tracking`, `test_08_dns_rebinding_host_header_validation`, `test_11_no_privilege_escalation_or_extra_daemons`.
  - Failing: `test_01`, `test_05`, `test_06`, `test_07`, `test_09`, `test_10`, `test_12` (missing systemd user unit generation, service management CLI `service install/start/stop/status`, and unmanaged lingering daemon checks).

### Harness integration
- **Trusted manifest location:** `/home/onyx/Projects/rust-mcp-gateway-lab/harness/acceptance.py`
- **Branch registration:** Target branch `milestone3/yolo-service` and descendant branches registered to require all 15 suites (129 total cases).
- **Protected test locations:** Mode `0444` files in mode `0555` directories outside agent writable worktrees:
  - `acceptance_m1/` (8 cases)
  - `acceptance_m1_edge/` (7 cases)
  - `acceptance_m2_policy/` (10 cases)
  - `acceptance_m2_http/` (12 cases)
  - `acceptance_m2_http_edge/` (6 cases)
  - `acceptance_pass2_audit/` (6 cases)
  - `acceptance_pass2_files/` (9 cases)
  - `acceptance_pass2_failclosed/` (8 cases)
  - `acceptance_pass2_containment/` (2 cases)
  - `acceptance_pass2_jobs/` (9 cases, corrected)
  - `acceptance_pass2_jobs_limits/` (1 case)
  - `acceptance_pass3_auditchain/` (13 cases, new)
  - `acceptance_pass3_yolo/` (11 cases, new)
  - `acceptance_pass3_dashboard/` (15 cases, new)
  - `acceptance_pass3_service_network/` (12 cases, new)
- **Hash verification:** All 15 suite hashes verified matching manifest.
- **Codex write protection:** Codex sandbox runs with `--clearenv` and unprivileged Bubblewrap; lab acceptance test directories are mounted strictly read-only and cannot be altered or substituted by the coding agent.

### Codex implementation gate
Codex may begin Phase 3 now that all prerequisite gates are met:
1. **[PASSED]** Milestone 2 jobs implementation committed by human operator (`76cafa0a5c0a8efc894366cd6ccf89ca4de74d3a` on `milestone2/jobs-supervisor`).
2. **[PASSED]** Milestone 2 baseline passes 78/78 cases across 11 suites.
3. **[PASSED]** Corrected jobs suite passes (9/9).
4. **[PASSED]** Output-limit suite passes (1/1).
5. **[PASSED]** Audit-chain suite exists, is locked (`31cf5bf0...`), and red baseline recorded (1 pass, 12 fail).
6. **[PASSED]** YOLO/CLI suite exists, is locked (`0db6754f...`), and red baseline recorded (3 pass, 8 fail).
7. **[PASSED]** Dashboard suite exists, is locked (`5148a381...`), and red baseline recorded (0 pass, 15 fail).
8. **[PASSED]** Service/Network suite exists, is locked (`bb23f892...`), and red baseline recorded (5 pass, 7 fail).
9. **[PASSED]** All 15 suite hashes registered in `harness/acceptance.py`.
10. **[PASSED]** Test oracle validation verified via `scripts/verify_yolo_job_isolation_oracle.py`.
11. **[PASSED]** Harness regression (37/37) and hardening verification (6/6) pass.
12. **[PASSED]** Phase 3 worktree `worktrees/m3-yolo-service` is clean and ready.

**Phase 3 Implementation Gate Verdict:** **READY FOR CODEX PHASE 3**

## Milestone 2 jobs baseline verification

The preceding uncommitted-state note describes AGY's earlier review. Under
explicit operator authorization, Codex reviewed the jobs implementation and
ran the trusted network-isolated harness on `milestone2/jobs-supervisor`.
All 78 locked cases passed (68 inherited, nine corrected jobs, one output
cap). All 13 existing suite hashes matched before and after the run. The
audit-chain and YOLO suites were checked for hash integrity only during
this run. Their implementation remains gated.

Formatting, offline locked build, Clippy with warnings denied, Cargo tests
(23 unit and four integration), and Git whitespace checks passed.
Project-local `cargo-audit --no-fetch --deny warnings` exited zero for the
49 lockfile dependencies. [The earlier Phase A execution brief](PHASE_A_EXECUTION_BRIEF.md)
records the original task and its historical limits.

The jobs profile is restricted to operator-configured executables and
arguments and runs under the gateway UID. It does not provide a separate
sandbox or authorize arbitrary YOLO execution. AGY independently owns all
locked tests, including the dashboard and service/network gates required
before Phase 3 implementation.

## Beta 1 Gate 1 working state before the corrected oracle

Branch `milestone3/yolo-service` remains at base
`76cafa0a5c0a8efc894366cd6ccf89ca4de74d3a` with uncommitted Gate 1
source. The inherited 78 cases passed before and after the changes. The
working tree contains the independently prepared readiness notes above.

### Audit and interrupted writes

The Linux ledger uses canonical JSONL, SHA-256 links, a stable interprocess
lock, and a checkpoint published by syncing a temporary file, renaming it,
and syncing the directory. The checkpoint identifies the active segment and
last committed record. Startup verifies earlier committed records before
recovering an incomplete final append. Rotation preserves links across
segments. A deleted or replaced active ledger, a complete malformed record,
and missing committed history fail closed. A privileged operator with
control over the whole directory can still rewrite the history.

Set `max_audit_file_bytes` for the segment limit and
`max_audit_dir_bytes` for the total retained record bytes. The defaults are
4 MiB and 32 MiB respectively. Rotation retains history and cannot relieve
the total cap by deleting it. The active log, rotated segments and private
checkpoint belong in the same backup. Preserve legacy unchained logs
separately and initialize a new log explicitly. A nonempty legacy log
without a valid checkpoint is refused without altering its records.

`mcp-gateway audit verify|status|inspect|rotate --config /absolute/clients.json`
and `--log /absolute/events.jsonl` operate on the same ledger. Read-only
verification reports the first broken sequence where it can identify one.
Inspection returns bounded, local JSON. Explicit rotation can also be
performed while a cooperating gateway is running.

Mutation staging requires Linux `O_TMPFILE`, file birth time, and linking a
pinned anonymous inode through procfs. The visible staging name is created
only after the sync of its exact intent. Startup cleanup validates the
principal, authorized root, parent directory identity, and staged inode
identity and metadata. It takes the same parent lock used by a live writer
and commits an intent and outcome around a confirmed removal. Read and job
behavior otherwise retains the Milestone 2 security profile.

### Verification and blocker

- `cargo fmt --all --check`, offline locked Clippy with denied warnings,
  build, and Cargo tests passed (24 unit, four integration).
- The trusted verifier ran all 15 suites with matching hashes before and
  after. It returned 98/129. Gate 1 passed 12/13 audit cases, and later
  unimplemented gates reported their expected baseline failures.
- The actual HTTP binary started against a stage created by a process that
  exited after committing its intent and linking the file. Startup preserved
  a foreign lookalike, removed the proven stage, and produced a valid
  three-record chain. A separate test verified that a locked parent is
  preserved while its writer is active.
- Locked audit case 12 requires cleanup after writing an unverifiable
  genesis record with a fabricated hash and an unconfigured principal. AGY
  independently confirmed the contradiction with fail-closed startup.
  The gateway refuses that history and preserves the files. Only AGY can
  repair and re-lock the fixture with explicit authorization. Keep its
  cleanup and preservation assertions.

Local receipts are under `target/beta-receipts/`. The locked suite files,
runner, and trusted manifest were preserved. Gate 1 is uncommitted, and
Gates 2 through 8 remain pending.

## Beta 1 Gate 1 accepted

The corrected audit suite passed 13/13 with SHA-256
`8172a3cfef07b4b71099f48807fbb1b69325eee5d8d9afc7e723b0e90940d258`.
Case 12a observed a genuine staged write with a synced intent before
SIGKILL, then verified that restart removed it and recorded the cleanup.
Case 12b preserved unprovenanced staging names and foreign lookalikes. All
78 inherited cases passed using the normal build. All 15 locked suite hashes
matched the trusted manifest before and after the runs.

The opt-in Cargo feature `test-hooks` compiles the pre-rename pause at the
durability boundary before final validation and publication. In that build,
`MCP_TEST_AUDIT_PRE_RENAME_HOOK` specifies a fresh marker path. The hook
syncs `ready` and waits up to 30 seconds. The pinned audit suite uses the
test-only switch `MCP_TEST_PRE_RENAME_PAUSE=1` and observes the linked stage
directly. The test build releases the HTTP session lock and dispatches its
tool work on a blocking worker. A separate authenticated HTTP probe observed
the marker before SIGKILL and completed an unrelated read during the pause.
An expiry probe verified the diagnostic and successful audited publication.

The default release artifact is `target/release/mcp-gateway`. Its
`strings` scan for both controls and the expiry diagnostic returned no
matches. A real audited HTTP write completed with both variables set without
creating a marker. The test artifact was built separately at
`/tmp/mcp-gateway-test-hooks-target/debug/mcp-gateway`. Formatting, default
and feature-enabled Clippy with warnings denied, offline locked debug and
release builds, 24 unit tests, four integration tests, whitespace checks,
and project-local RustSec audit all passed. Local receipts are under
`target/gate1-close/`.

### Whole-ledger rewrite risk

A YOLO process running as the audit owner could delete or replace both the
ledger and its local checkpoint and then reconstruct a consistent chain.
Mode `0400` under that same Unix owner offers no independent trust anchor.
The owner can change permissions and can replace the file through a writable
parent directory.

1. Export signed or independently verifiable audit heads to another device or
   remote destination outside the gateway UID's control. Verification
   against retained heads covers history through the latest exported head.
2. Place ledger custody and append authorization under a separate UID that
   owns the audit sink.
3. Accept the limitation temporarily for Beta 1 and disclose that a process
   with the audit owner's authority can rewrite the whole history.

The external checkpoint is the lowest-overhead option because it can run
on demand without adding a resident process. Gate 1 leaves this threat
unresolved.

## Beta 1 Gate 2 authorization and execution

Gate 2 extends the existing private client JSON with `policy_version: 1`
and per-client `mode`. Omitted mode means Standard. `disabled` rejects the
client's bearer requests, including requests on existing MCP sessions.
`yolo` requires a policy revision that matches the client's latest
successful mode transition in the audit chain. The local CLI owns these
transitions. A YOLO setting has no TTL. Credential expiry and tool grants
continue to apply in every mode.

```sh
mcp-gateway yolo status --client codex --config /absolute/operator/clients.json
mcp-gateway yolo enable --client codex --config /absolute/operator/clients.json
mcp-gateway yolo disable --client codex --config /absolute/operator/clients.json
```

The Linux config owner and a non-group-writable operator directory define
the local administration boundary. The HTTP transport has no operator
tool or route. The CLI and HTTP admission coordinate through an advisory
file lock. The CLI syncs the audit intent, publishes and syncs a pending
marker, atomically replaces and syncs the config, records the successful
outcome, and removes and syncs the marker. Admission reads the private
file under a shared lock and rechecks the bearer and current policy at
tool dispatch. Identical bytes in a replaced or edited file are
revalidated against audit. Changes to audit or job-store settings require
a restart.

An interrupted transition quarantines the configuration. Restore a
healthy audit ledger first if it is unavailable. Then run `yolo disable`
for the affected client to publish a safe policy and record the recovery.
Restoring an old YOLO configuration over a later recorded revocation is
rejected. A verified owner-read-only active audit segment permits
degraded startup. Mutation, job execution and YOLO operations remain
denied until the operator restores a writable ledger and restarts.

Use per-client `yolo_roots` to authorize existing canonical directories
outside the primary root. Only the selected client's granted tools can
access them, and explicit extra roots can be included in that client's
isolated jobs. An empty array opts out of extra roots. For an existing
file-only config with no `yolo_roots`, explicit CLI enablement can approve
a snapshot of eligible owner-only sibling directories in the private
operator workspace collection. The collection must be mode `0700` and
contain the client's primary root as a direct child. The snapshot
excludes hidden directories, other client roots, and known gateway state.
Those implicit shares are file-tool only. No future sibling is picked up
automatically. Prefer explicit roots for real deployments.

Linux HTTP file tools use pinned root handles and kernel path resolution.
Configuration, audit and job-store paths are kept outside approved
scopes. On legacy read-only configurations that keep credentials in the
client root, the file path and policy companions are excluded explicitly.
File tools run in the trusted gateway process and enforce path policy
through Linux file descriptors. Job execution has a separate kernel
boundary.

Managed execution uses Bubblewrap for both detached jobs and
`run_command`. On Linux x86_64 it creates user, mount, PID, IPC, UTS and
network namespaces. It drops capabilities, disables nested user
namespaces, clears the environment, mounts fixed system binaries and
libraries read-only, and exposes the selected workspace directories
through pinned handles. Seccomp denies socket creation, file-handle opens,
and io_uring setup. The runner rejects unexpected inheritable descriptors
before job publication and again at runner entry. Commands use a fixed
operator profile. Profiles can call a system interpreter with an
approved workspace script. Job roots containing nested mounts and
unavailable kernel prerequisites fail closed.

Unversioned Milestone 2 configurations retain the legacy, operator-trusted
fixed host profiles. They carry the gateway user's OS authority. Treat
their executables, arguments and inputs as trusted. The first managed
transition refuses while a legacy job is active or has an uncertain
outcome. After migration, both Standard and YOLO jobs remain confined
even after the last YOLO client is downgraded. The local actor controlling
the operator UID and files remains trusted.

Revocation applies at the next tool admission. A job already admitted can
finish inside its original immutable sandbox or be canceled through the
owner's granted job tool. Restart reconciles the signed receipt without
replaying the command. An active detached runner may be reported as
uncertain while it finishes. Cancellation becomes terminal only after
cleanup is reconciled.

YOLO intents and outcomes use the Gate 1 ledger. Protected job logs stay
in the job store. The local hash chain still cannot independently prove
history against someone with the audit owner's authority. Anchoring a
signed or verifiable audit head off the device remains the lowest
overhead option.

### Gate 2 verification

The trusted verifier passed 102/102 cases across 13 suites. The 78
inherited cases and the 11 YOLO cases used the normal build. The audit
suite used a separate `test-hooks` build and passed all 13 cases.
The trusted combined command has a quoting defect for the audit Python
path. For audit, the unchanged trusted extra-test entry point ran the
same pinned file read-only with the isolated hook-enabled binary.
All 15 registered suite pins matched before and after verification.
Dashboard and service/network were hash-checked only.

| Suite | Passed | SHA-256 |
| --- | ---: | --- |
| Stdio | 8 | `0b9a680e155b156f65cbbb766dc7e9444bf494aeb45bfb4c43c596a55cdadc9f` |
| Stdio edge | 7 | `5379e25caf867bd6db739a36fc21bc5c80ac4607b77ed7ebdd488d5122f76dde` |
| Standard policy | 10 | `76edbb613950fc66a0fbe9c68bed7d66a19c30a48f2af3d8de4cf1d9378f262b` |
| HTTP | 12 | `3d5f29e088275ab05ec3f8695e036a7cc5a78dde34a54049a09fb025cc07bcbd` |
| HTTP edge | 6 | `f6331f44e1b4f08f75f841a04f40430014d0e30494b8b60bcf15f5e7c72a8fbd` |
| Audit contract | 6 | `88f268f3cb60c684c037381a4a729a5b995944db15bf252a43b81fe90f8801c2` |
| File mutation | 9 | `8b26c330e203b5417357dd72ee90badfb8dceb4c13c90ef70c24550a9ce6ca2e` |
| Audit fail-closed | 8 | `de520c15c57cb7a76326a0d4497c85cbe448445f8eece85d70bfe879781b3c20` |
| Parent symlink | 2 | `ac5683be0d218381af585332d1a7a62e607deff17ca9d6e1f760f09b647736ba` |
| Durable jobs | 9 | `ec71c4966f2639e34c6bbe7357d78a4b7adca8f38f84dd08ce43ae59dc04ee55` |
| Output caps | 1 | `597bb1e3c5b936941dfee5d1b31271b9607e52c1f29594d561feca1abbe1be70` |
| Audit chain | 13 | `8172a3cfef07b4b71099f48807fbb1b69325eee5d8d9afc7e723b0e90940d258` |
| YOLO and CLI | 11 | `29140f94276ac9999958c2ce70decb059f6a9d16f3479fa2b3fbea5731edee19` |

All 13 suite invocations exited zero. Case 11 ran an authenticated gateway
job through the normal supervisor and checked the isolated namespace,
workspace I/O, protected paths and terminal receipt. Supplemental probes
used both the detached and synchronous execution paths. They also checked
inheritable descriptors, host process paths, symlinks, operator CLI access,
child environment and off-root workspace mounts. A detached grandchild
with a new session was verified alive before cancellation and timeout.
The timeout case included a gateway SIGKILL and restart. A separate
SIGKILL targeted the interval after policy config replacement and before
the audit outcome. The next startup refused the ambiguous policy and
the local disable command recovered it. Restoring a revoked policy
revision was denied both in the active session and on restart.

Formatting, default and hook-enabled Clippy, offline locked debug and
release builds, 24 unit and four integration tests, and whitespace checks
passed. A clean local clone with the reviewed source diff built offline in
debug and release. The dependency manifests and dependency graph were
unchanged. RustSec audited 49 locked dependencies using 1,555 advisory
records and exited zero with warnings denied. The normal release excluded
both Gate 1 crash controls. The independent harness's regression and
hardening tests passed 37/37.

### Gate 2 performance

A matched local release run built Milestone 2 and Gate 2 from source and
used the same private job-enabled fixture and environment for both.
Startup and shutdown are medians of nine launches. The idle sample
spanned five seconds. RSS is the gateway process only.

| Metric | Milestone 2 | Gate 2 Standard |
| --- | ---: | ---: |
| Idle RSS | 3,700 KiB | 3,980 KiB |
| Idle CPU ticks in five seconds | 0 | 0 |
| Startup to listener | 62.85 ms | 64.13 ms |
| SIGTERM to exit | 0.37 ms | 0.57 ms |
| Job-start request | 1.70 ms | 2.54 ms |
| Gateway RSS with five jobs | 3,912 KiB | 4,212 KiB |

The absolute startup measurements differ from the older supplied
Milestone 2 baseline. The table uses a fresh measurement for both builds
in the same environment. The YOLO fixture recorded 11.25 ms median
isolated job-start latency, 4,176 KiB gateway RSS with five jobs, and
210.60 ms median synchronous isolated command completion. The matched
legacy synchronous command on the Gate 2 binary took 232.36 ms median.
Synchronous samples include the inherited runner's wait and cleanup.
The pure policy evaluator took approximately 0.18 microseconds for
Standard and 0.09 microseconds for YOLO on a separate microbenchmark.
Authorized read round trips were 0.66 ms and 1.01 ms respectively.

Gate 2 logs and reproducible local probes are under `target/gate2/`.
These supplemental artifacts are outside the tracked change set. No
dashboard, Tailscale settings, service installation, or root provisioning
is part of Gate 2.

The disposable mutation run detected all 11 changes. YOLO cases 01, 02,
04, 05, 06, 08 and 11 caught ignored revocation, remote operator tool
success, global YOLO, stale authorization, missing audit flags, verifier
disclosure and a mount that exposed the operator configuration. Inherited
jobs case 08 caught loss of process-group signaling. Supplemental tests
caught a job running in the host mount namespace, direct calls to a hidden
command, and replay of a revoked configuration when the file-identity
comparison was removed. Each mutant compiled and its intended test exited
one. The disposable source was restored and compared with the real
worktree.


## Gate 3d broad YOLO implementation

The broad activation, guarded supervisor, runtime filesystem and direct
file-tool parity are implemented. The completed beta archive remains
gated on Permanent Permissions 17, whose split-state fixture conflicts
with mandatory dedicated-state containment. See [STATUS.md](STATUS.md)
for the pinned run evidence and [the broad mode guide](docs/BROAD-YOLO.md)
for the threat model, tested usage, state migration and rollback.

## Final Product Security Acceptance (Gate 3e / Milestone 3 Final)

- Acceptance status: AGY PASS.
- Verified commit: `a9317036a359367ed602be1c241ef64888d37659` on `milestone3/broad-yolo`.
- Locked suite pins: 28/28 verified matching disk before and after execution.
- Acceptance suite battery: 287/287 passing across all 28 registered suites (0 failures, 0 missing).
- Rust tests: 36 passed (25 unit, 7 operator integration, 4 mutation integration).
- Formatting and linting: `cargo fmt --all --check` clean; `cargo clippy --offline --locked --all-targets -- -D warnings` clean.
- Product integration probes (`tests/product_features.py`): 5/5 passed.
- Clean clone build and package smoke tests: verified from clean clone; binary SHA-256 `f117ac52c234203cff569895a7ab6f16d9492fcd80c778b1fda27e747045fe71`; archive SHA-256 `e70ac8502938bb00f78207356a8d002368a66d8e0705fe431af72ad71fbb29f4`.
- Audit ledger: valid hash chaining verified via `mcp-gateway audit verify`.
- External integration notes: Gemini interactive login requirement recorded as cloud provider auth constraint, not a Veyl defect.
- Checkpoint is marked READY for BridgeDev second independent verification.

## Linux implementation handoff

The next Linux candidate extends the accepted product checkpoint with
private Serve ownership and validation, the systemd user lifecycle,
`veyl-monitor` and audited workspace inspection grants. See
[STATUS.md](STATUS.md) for the verification receipt and
[docs/PARITY.md](docs/PARITY.md) for scope and evidence.

The Gate 3e executable still matches the AGY hash above. The reported
Gate 3e archive was absent from the worktree, acceptance lab, and checked
temporary paths. A preserved copy of the accepted executable is under
ignored `dist/gate3e-checkpoint/`. The new Linux archive has its own
manifest and must be reviewed against its own source commit and hashes.

AGY owns the next independent consolidated security acceptance.
BridgeDev then verifies the same commit and extracted package. Live
Tailscale activation, production unit installation and private publication
remain separate approval gates.

## v0.1.1-beta independent review

Review the candidate diff against `v0.1.0-beta`. The strict state checks
still apply to the gateway state root. Pay particular attention to
descriptor-relative desktop traversal, aliases, public credential and
session separation, and conditional route ownership and rollback.
Use the disposable auth, rollback, mount alias and desktop tests in
`tests/linux_features.py`. The actual-HOME probe and consolidated
locked results are indexed in [STATUS.md](STATUS.md).

Production promotion requires AGY acceptance and BridgeDev verification
of this candidate. Publish the private prerelease only after the
deployment and external MCP call pass. Preserve the prior release and
BridgeDev's port 443 route.

## v0.1.2-beta CORS review

Review the change against `v0.1.1-beta` and run
`LinuxFeatures.test_funnel_cors_preflight_and_authenticated_session`
plus the existing public-authentication and private dashboard tests.
Check that allowed Origins and OPTIONS are limited to validated public
MCP requests, that POST credentials and public/private session separation
still apply, and that telemetry omits URLs and raw headers.
Use the deployment checks in [STATUS.md](STATUS.md). The Brave
production probe exercises browser CORS, while ChatGPT connector
discovery must be observed separately.

## v0.1.3-beta shared-route verification

The shared path is isolated from the existing 443 root. Test adoption,
descendant collisions, conditional updates, adapter restoration and
rollback to a static disabled handler. Keep the adapter running during
the migration until a public client initializes and exercises the
existing URL through the native backend. Retire only the dedicated
Funnel flag on 8443 and preserve private Serve.

The production failure and disposable dashboard and client evidence
are indexed in [STATUS.md](STATUS.md). Use the same candidate for AGY
acceptance, BridgeDev verification and production.

## Veyl Linux v0.2.0-alpha release handoff

Milestone completed by AGY under direct authorization.

Base: `6615c5061dc5cae83500d4c829ebc2652d37989a`.
Branch: `milestone3/broad-yolo`
Target Repository: `https://github.com/kmanisk/veyl`

### Summary of Completed Milestones

1. Three-Mode Execution Architecture:
   - Full implementation of Standard, YOLO, and FULL execution modes.
   - Independent disabled state management (`mode enable`, `mode disable`).
   - Version 3 policy migration via `veyl mode migrate --config PATH` upgrading legacy scoped and broad YOLO policies to version 3.
   - Refusal of deprecated `yolo enable` on version 3 policies.
   - 6/6 locked acceptance tests passing.

2. BridgeDev Feature Parity Tools:
   - Native Rust developer tools added to MCP tools catalog: `list_directory`, `directory_tree`, `file_info`, `create_directory`, `edit_file`, `exec_command`.
   - Inspection, mutation, and command execution contracts fully enforced with sandboxing.

3. Durable Nightshift Primitives:
   - Idempotent `request_id` handling for duplicate prevention across disconnections.
   - Bounded `job_wait` with server-side timeout up to 60s.
   - Incremental offset-based `job_logs` pagination (`offset`, `max_bytes`).
   - Structured `task_run` with optional ephemeral git worktrees and auto-commit checkpoints.

4. Production Usability and Verification:
   - 46/46 Rust tests passing across unittests, operator tests, pass2 mutation, and parity/nightshift tests.
   - Systemd user service `mcp-gateway.service` active and operational.
   - Local dashboard (`http://127.0.0.1:7332/dashboard`) and private Tailscale dashboard (`https://onyx.tail646579.ts.net:9443/dashboard`) verified.
   - `veyl monitor` CLI subcommand and `veyl-monitor` verified with live health and client views.
   - Tailscale Funnel on port 443 path `/veyl/mcp/...` verified live with active ChatGPT session, discovery of all 25 tools, and execution.

# TimeShift handoff (2026-11-25; incomplete)

TimeShift and autonomous Nightshift remain unimplemented. BridgeDev exposes a
single `rewind` tool with list, status, preview, restore and clear actions;
its description excludes shell changes. The requested Veyl design also needs
owner isolation, separately granted operations, confirmation, current-scope
revalidation and durable signed snapshots. In particular, review the gap
between an advisory directory lock plus check-before-rename and protection
against non-cooperating concurrent writers before promising no clobber.
Directory creation currently uses pathname-based `create_dir_all`; do not
include it in checkpoint coverage without descriptor-confined handling.

The focused mutation integration tests could not start their loopback gateway
in this sandbox; direct IPv4 socket creation returned EPERM. See STATUS for the
observed result. Preserve the existing dirty candidate, independent test pins,
and production approval gate when continuing.

# Marketplace installer acceptance handoff (2026-11-25)

Candidate implemented cleanly on `0.3.0-beta` (from base `329b9d53ccdc86dd1ef3121a91d0bd031bdf6f95`):
- One-click verified marketplace installer (`src/upstream/installer.rs`), `veyl marketplace` CLI, `/api/dashboard/marketplace/*` and `/api/dashboard/clients/grants` endpoints, Verified Providers UI grid, live progress/cancel controls, crash recovery (`recover`), automatic rollback on probe failure, and bulk/per-tool client & upstream grant controls in the web dashboard.
- Independently verified across 28/28 locked suites (287/287 cases, 28/28 SHA-256 unchanged), 6/6 three-mode checks, all Rust/Clippy/fmt checks, Brave CDP UI tests, and `tests/marketplace_install.py` (adversarial archives, integrity failures, loopback registry closures, cancellation, rollback, crash recovery, and live `rea` 6.10.1 + `rust-anything` 4.1.0 E2E execution).


