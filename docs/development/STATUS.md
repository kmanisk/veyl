# Gate 3d status

## 2026-11-27 — 0.6.1-beta single-executable release deployed and published

Operator explicitly accepted bundle `single-binary.WbADoDZC/release-0.6.1-beta` (veyl SHA-256 `b534c40338a9a52e2d9e7805ee551051bbb88ce0655cbffdc23d37b9ffea9a39`). BridgeDev verified 214 source manifest entries, 28 locked pins, 13 focused integration cases and four isolated migration/rollback scenarios against this exact ELF. AGY reported 153 Rust and 293 locked/supplementary cases passing and warning-denied Clippy clean. One privileged host-tmpfs Funnel case was skipped; external ChatGPT and Android remain unverified.

Production upgrade process `mwz1z62j-s8a6ej` exit 0: 0.6.1-beta installed in both managed bin directories, each containing one regular `veyl` executable and relative `mcp-gateway` and `veyl-monitor` symlinks. Existing unit and configuration hashes unchanged. Service active PID 26100, all 2590 audit records verify against pre-upgrade anchor, ChatGPT YOLO/Codex Standard/AGY Standard grants unchanged. Updater rollback bundle `~/.veyl-update-backups/938f20130c352c2eb26eff80e0ab10d4` retained; private deployment receipts and prior binaries in candidate parent `production-upgrade-0.6.1-beta.Fukd25vv`.

Accepted source committed and promoted to main at `ac2c3f8cb9fdf21e1b2858fafeeecaf11c95e7db`, tag `v0.6.1-beta` published. GitHub Latest API confirms v0.6.1-beta; exactly two uploaded assets (`veyl`, `SHA256SUMS`), both remote SHA-256 digests verified, with automatic GitHub source archives. Historical releases preserved. Crates.io 0.6.1-beta published and confirmed by registry search from a clean detached checkout of accepted commit (`cargo publish --locked --no-verify` after independent full acceptance). Final deployment/publication verification `mwz20mtx-7b6rai` exit 0; no active update journal. Existing TUI processes may require reopening. Next gate: real client interoperability and opt-in BridgeDev replacement trials.

## 2026-11-27 — Independent AGY acceptance PASS on `0.6.1-beta` single-executable candidate (`single-binary.WbADoDZC`); operator release acceptance pending

Completed independent verification, code/security audit, version bump to `0.6.1-beta`, guarded rebuild, and release staging in candidate `single-binary.WbADoDZC/source` (base `46527bfd94974703a30237b2df71d2cdaec9d54e`, dirty candidate working tree with single-ELF changes + `0.6.1-beta` bump) and optimized single-ELF bundle `../release-0.6.1-beta/`:
- Single-executable distribution & integrity: `cargo metadata --no-deps --offline --locked` reports `veyl 0.6.1-beta` with exactly one binary target `veyl` (`src/main.rs`) and library `mcp_gateway` (`src/lib.rs`). `../release-0.6.1-beta/` contains only `veyl` (`11462664` bytes, SHA-256 `b534c40338a9a52e2d9e7805ee551051bbb88ce0655cbffdc23d37b9ffea9a39`) and `SHA256SUMS` (`sha256sum -c` PASS). Invoking `veyl --version`, `veyl monitor --version`, and `veyl connector --version` prints `veyl 0.6.1-beta`, `veyl-monitor 0.6.1-beta`, and `veyl-connector 0.6.1-beta`.
- Code & security audit (`src/gateway_main.rs`, `src/monitor.rs`, `src/connector/mod.rs`, `src/local_cli.rs`, `src/platform/linux/cli.rs`, `src/service_cli.rs`, `src/update_cli.rs`): verified internal `veyl-monitor`/`--monitor-worker` and `veyl-connector`/`connector` dispatch, relative compatibility symlink validation (`is_alias` requiring exact target `veyl`, `st_uid == geteuid()`, `st_nlink == 1`, rejecting foreign symlinks), alias-aware `PrivateStage`, rollback journal (`original_alias`), `clean_private_dir` cleanup, and preserved legacy systemd unit matching via `render_existing`/`verified_gateway_alias`.
- Clippy & Rust suite (`tests/guarded_cargo.py`): `clippy --all-targets -- -D warnings` PASS (0 warnings); `test -- --test-threads=1` **153/153 PASS** (0 failed, 0 ignored: `lib` 43, `veyl` 86, `bridgedev_parity_and_nightshift` 3, `gate3_operator` 11, `onboarding` 6, `pass2_mutation` 4).
- Locked acceptance (`tests/prepare_locked_artifacts.py` + `rust-mcp-gateway-lab`): **28/28** locked test pins verified intact before and after execution; all 28 pinned suites **287/287 PASS** (including `--features test-hooks` `locked_audit_chain.py` **13/13** crash-injection `case 12a`) plus `locked_three_modes.py` **6/6 PASS** (**293/293 locked/supplementary cases**, 0 failed, 0 skipped; temporary staging dir removed).
- Upgrade, rollback, systemd, durable identity & OAuth/gateway integration (`../release-0.6.1-beta/veyl` with temporary harness aliases removed after runs):
  - `tests/durable_update_service.sh ... single-binary` (`0.6.0-beta` `release-0.6.0-beta-final.KH9o63jx` -> `release-0.6.1-beta`): **PASS** (`SINGLE_ELF_LEGACY_MIGRATION_PASS`, `SINGLE_ELF_REINSTALL_PASS`, `SINGLE_ELF_FAILED_START_ALIAS_ROLLBACK_PASS`, `SINGLE_ELF_FOREIGN_SYMLINK_REFUSED_PASS`).
  - `tests/durable_update_rollback.py` (`0.5.0-beta` -> `release-0.6.1-beta`): **3/3 PASS**.
  - `tests/systemd_lifecycle.sh`: **PASS**; `tests/updater_lifecycle.sh`: **PASS** (4/4 lifecycle stages); `tests/gate3_runtime.py ... full`: **PASS**; `tests/test_guarded_cargo.py`: **6/6 PASS**.
  - `tests/durable_identity.py`: **3/3 PASS**; `tests/durable_identity_loopback.py`: **PASS** (Btrfs `126 -> 127`, ext4 `1792 -> 1793`, tmpfs strict `st_dev`).
  - Private-namespace `tests/oauth_bounded_workspace.py`: **1/1 PASS**; `tests/oauth_funnel.py` (host UID 1000): **4 PASS, 1 skipped** (`test_funnel_advanced_exact_consent_and_family_boundary` skipped without privileged `VEYL_TEST_BOUNDED_WORKSPACE` host tmpfs mount, as non-privileged userns remaps root `/usr/bin` to overflowuid).
  - OAuth & browser: `oauth_yolo_cross_gateway` **2/2**, `oauth_yolo_lifecycle` **3/3**, `oauth_managed_login` **2/2**, `managed_login_yolo` **1/1**, `oauth_native` **17/17**, `oauth_jobs` **3/3**, `oauth_commands` **2/2**, `oauth_interactive` **4/4**, `oauth_upstreams` **3/3**, `onboarding_browser.py` (`FIRST_RUN_BROWSER_PAIRING_PASS`, `DASHBOARD_TABS_AND_KEYBOARD_PASS`).
  - Connector, dashboard & core feature suites: `oauth_http_preview` **6/6**, `connector_preview` **2/2**, `connector_persistence` **2/2**, `platform_probe` **2/2**, `product_features` **9/9**, `permission_modes` **5/5**, `dynamic_jobs` **5/5**, `extended_jobs` **3/3**, `job_streams` **1/1**, `linux_features` **16/16**, `activity_features` **3/3**, `context_and_system` **3/3**, `git_tools` **3/3**, `process_sessions` **10/10**, `timeshift` **9/9**, `extensions_and_proposals` **3/3**, `workspace_dashboard` **2/2**, `upstream_workspace` **4/4**, `upstream_workspace_jobs` **3/3**, `marketplace_install` **4/4**, `runtime_bundles` **2/2**, `direct_remote_boundary` **2/2**, `http_header_hardening` **2/2**, `test_dashboard_preview` **1/1**, `test_chatgpt_plugin_package` **3/3** (`android_http.py` 5/5 is Termux/Android target only).
- Packaging & credentials preflight: `cargo package --offline --locked --allow-dirty --no-verify` verified cleanly (`veyl-0.6.1-beta.crate`), `gh auth status` (`kmanisk`) and `~/.cargo/credentials.toml` present.
- Release gate (`AGENTS.md`): production `mcp-gateway` and canonical `~/Projects/veyl` remain untouched pending explicit operator acceptance of `../release-0.6.1-beta/` before local upgrade, production verification, `main` promotion, GitHub `v0.6.1-beta` release (`veyl` + `SHA256SUMS` only, marked Latest), and `crates.io` publication.

## 2026-11-27 — Single-executable distribution candidate (not yet released)

Operator requested a single Veyl binary and correct GitHub Latest metadata. Published `v0.6.0-beta` was marked a regular GitHub release with Latest explicitly set; API confirms `v0.6.0-beta`. Its tag and verified assets remain unchanged for legacy updater compatibility.

Isolated source `single-binary.WbADoDZC/source` at base `46527bfd94974703a30237b2df71d2cdaec9d54e`: one Cargo binary target, internal monitor/connector dispatch, test-only copies with legacy invocation names for the pinned lab, single-ELF bundle support, strict relative compatibility symlinks (`mcp-gateway`, `veyl-monitor` -> `veyl`) within each existing managed bin directory, alias-aware transactional backup/recovery, and exact legacy systemd unit compatibility. Fresh source installs build one executable. Old published updater refuses the new layout before mutation; first upgrade must use the verified new bundle CLI. No production changes.

Guarded optimized build `90862329657440a7` exit 0, preview `../single-elf-preview.x1SxkMfo/veyl` SHA-256 `a74f1582742afbd0034b0e145f61c8beafbe9a9fac2a5919a51cf8ea8cca0e8b`. `mwz04ytp-an8pw5`: four isolated service scenarios passed (legacy migration, reinstall, failed-start alias rollback, foreign symlink refusal), then incorrect connector test invocation failed. `mwz06jq1-rkz550`: connector, permission and product checks passed, then incomplete compatibility fixture lacked sibling `veyl`. Corrected fixture rerun `mwz07mfc-caymnz` exit 0: OAuth cross-gateway 2, lifecycle 3, connector preview 2, persistence 2, permission modes 5, product features 9, dynamic jobs 5, Linux features 16 (44 cases). `mwz08uqd-2t4h26` exit 0: live paired `veyl monitor --view health` with only single bundle ELF, Cargo metadata exactly one binary, all 28 locked pins intact, Latest API verified. Production PID 48528 unchanged. No full Rust/locked acceptance on this refactor yet; free space below 40 GiB admission threshold, guard not bypassed. Pruned only inspected inactive Veyl package build cache under shared lock after verifying accepted bundle; no production files removed.

Next: authorize a new version (suggest 0.6.1-beta), full guarded acceptance and exact candidate approval before publishing. Do not replace already published version or remove legacy release assets needed by old updaters. New release should upload only `veyl` and `SHA256SUMS`; GitHub generates source archives. Set Latest explicitly and keep beta in version/title.

## 2026-11-27 — 0.6.0-beta deployed and published

Operator explicitly accepted source `f204dc257b1bdd8bde8c11811d84bf5b6e58a9cd` and bundle `release-0.6.0-beta-final.KH9o63jx`. BridgeDev repeated the rollback, durable identity, and cross-gateway tests (8/8), plus three isolated systemd scenarios; verified 28 locked pins and 287 locked case receipts. AGY's full acceptance was 228 Rust, 293 locked/supplementary and 150 Python cases. The verified new updater completed production installation; all six installed binary copies match, service active, policy and unit byte-identical, existing ChatGPT YOLO/Codex Standard/AGY Standard grants unchanged, audit head v2 and all 2,590 records verified against the pre-upgrade anchor. Rollback bundles retained. Main fast-forwarded, tag `v0.6.0-beta` resolves to the accepted commit, GitHub prerelease published with all eight asset digests verified, and crates.io `veyl 0.6.0-beta` published and confirmed by registry search. Packaging used a clean detached checkout and `--no-verify` after full independent acceptance, avoiding ignored bytecode files. Deployment receipts retained privately under the accepted commit's artifacts directory. Next: actual external-client interoperability and BridgeDev parity trials; do not retire BridgeDev yet. No host reboot or Android verification performed.

## 2026-11-27 — Independent AGY final acceptance PASS on 0.6.0-beta (`f204dc257b1bdd8bde8c11811d84bf5b6e58a9cd`); operator release acceptance pending

Completed full independent verification and security audit of `fix/0.6.0-beta-durable-rollback` at commit `f204dc257b1bdd8bde8c11811d84bf5b6e58a9cd` and optimized bundle `../release-0.6.0-beta-final.KH9o63jx/`:
- Manifest & checksum integrity: 215/215 files in `../SOURCE_SHA256SUMS-0.6.0-beta-final.KH9o63jx` (`sha256sum -c` PASS), all four binary digests in `../release-0.6.0-beta-final.KH9o63jx/SHA256SUMS` PASS (`veyl` `ad75f7985f2bfc8b302a62c3ac8d38773104f13bec37f42a9aa3914481102002`, `mcp-gateway` `be8b7ad89bc8218ead7987109c27bd4c9b67229b13a33ed7c260fb209cfd90dc`, `veyl-monitor` `7ecebd5ca3d4776a38fd9d4ab6025335f4abf9de3bc28402631eed3359fa6933`, `veyl-connector` `0b5b18758f42f0798e524b5fc4b4f53c7387a5482e4ac541d0ef5f34badd41e6`), `veyl --version` / `mcp-gateway --version` report `0.6.0-beta`, 28/28 locked pins intact.
- Independent rollback & migration audit (`src/update_cli.rs`, `src/security/audit/ledger.rs`, `src/http/mod.rs`, `src/service_cli.rs`): verified legacy updater refusal before unsafe migration (`startup_transaction` rejects missing `legacy_audit` when `.head` is `v1`), verified prefix & `policy_sha256` checking in `restore_legacy_audit` / `restore_legacy_tip` (never rewrites tip backwards or drops history, rejects `staging.fs` and open stages), exclusive `PolicyFile::lock`, listener binding + admission delay while `active.json` is present, and clean service restart recovery. Confirmed zero remaining defects; note operational packaging detail that running `tests/*.py` without `-B` creates untracked `tests/__pycache__` (`rm -rf tests/__pycache__` keeps clean `cargo package` tree).
- Clippy & Rust suite: `cargo clippy --all-targets -- -D warnings` PASS (0 warnings); `cargo test -- --test-threads=1` **228/228 PASS** (0 failed, 0 ignored: `lib` 43, `mcp_gateway` 75, `veyl` 75, `veyl-monitor` 11, `bridgedev_parity_and_nightshift` 3, `gate3_operator` 11, `onboarding` 6, `pass2_mutation` 4).
- Rollback, systemd, durable-identity, loopback & bounded-tmpfs integration (`../release-0.6.0-beta-final.KH9o63jx/`):
  - `tests/durable_update_rollback.py` (against preserved `release-0.5.0-beta`): **3/3 PASS** (interrupted migration recovery, wrong-prefix refusal, changed-policy refusal, YOLO grant preserved).
  - `tests/durable_update_service.sh` (isolated nested `systemd --user` + network namespace): **PASS** (`LEGACY_UPDATER_REFUSED_UNSAFE_MIGRATION_PASS`, `FAILED_START_AFTER_MIGRATION_ROLLBACK_PASS` after induced post-migration startup failure restoring `v0.5.0-beta` and `v1` head cleanly, `SUCCESSFUL_LEGACY_UPGRADE_PASS`).
  - `tests/durable_identity.py`: **3/3 PASS**; `tests/durable_identity_loopback.py`: **PASS** (real kernel Btrfs `118 -> 119` remount recovery, Btrfs snapshot subvolume rejection, ext4 `1792 -> 1793` remount & copied-FS rejection, volatile `tmpfs` strict `st_dev` check; all mounts cleaned).
  - Production read-only verification (untouched `~/.local/state/veyl/clients.json`, PID `1012`): `audit verify` PASS (`VERIFY_RESULT=VALID records=2590 segments=1 bytes=844995`), `mode list` PASS (`chatgpt yolo`, `codex standard`, `agy standard`).
  - Disposable 64 MiB / 4096-inode host `tmpfs` `tests/oauth_funnel.py`: **5/5 PASS** (0 skipped, cleanly unmounted).
  - Remaining 32 Python integration suites (`oauth_yolo_cross_gateway` 2, `oauth_yolo_lifecycle` 3, `oauth_native` 17, `oauth_interactive` 4, `timeshift` 9, `upstream_workspace` 4, `permission_modes` 5, etc.): **139/139 unittest cases PASS** (150 total unittest cases in integration run) plus `tests/onboarding_browser.py` (`FIRST_RUN_BROWSER_PAIRING_PASS`, `DASHBOARD_TABS_AND_KEYBOARD_PASS`).
- Locked acceptance (`tests/prepare_locked_artifacts.py`): **28/28** pin hashes intact; all 28 suites **287/287 PASS** (`locked_audit_chain.py` 13/13 with `--features test-hooks`), plus `locked_three_modes.py` **6/6 PASS** (**293/293 locked/supplementary total**, 0 skipped, staging dir cleaned).
- Packaging & release readiness preflight: `cargo package --offline --locked --no-verify` succeeded on clean commit `f204dc257b1bdd8bde8c11811d84bf5b6e58a9cd` (`veyl-0.6.0-beta.crate`, 189 files, 598.9 KiB compressed); `gh auth status` (`kmanisk`) and `~/.cargo/credentials.toml` verified present.
- Release gate (`AGENTS.md`): local installation using `../release-0.6.0-beta-final.KH9o63jx/`, production verification, `main` promotion, GitHub `v0.6.0-beta` release, and `crates.io` publication await explicit operator acceptance of this exact verified candidate.

## 2026-11-27 — 0.6.0-beta migration rollback checkpoint PASS (BridgeDev focused verification)

Implemented the missing legacy audit rollback transaction after the independent
review in `../DURABLE_ROLLBACK_REVIEW-2026-11-27.md`. The updater captures the
verified v1 prefix and policy SHA-256 in its private journal before stopping
the service, validates the complete current ledger and compatible history on
rollback, and atomically restores the legacy head format with the current tip.
It never copies an old head over newer records. Recovery rejects changed policy,
wrong prefixes, incompatible staging proofs, and unresolved staging records
without restoring old executables. Both failed-start rollback and explicit
`update --recover` use this path. Legacy updater startup is refused before
incompatible migration; the new service binds its listener but delays request
admission until the pending update journal is cleared. Use the verified new
bundle CLI for the one-time upgrade and retain it for recovery.

Final optimized bundle `../release-0.6.0-beta-final.KH9o63jx/`:
- veyl: ad75f7985f2bfc8b302a62c3ac8d38773104f13bec37f42a9aa3914481102002
- mcp-gateway: be8b7ad89bc8218ead7987109c27bd4c9b67229b13a33ed7c260fb209cfd90dc
- veyl-monitor: 7ecebd5ca3d4776a38fd9d4ab6025335f4abf9de3bc28402631eed3359fa6933
- veyl-connector: 0b5b18758f42f0798e524b5fc4b4f53c7387a5482e4ac541d0ef5f34badd41e6

Guarded release build `0c3f9ed3a3d242bf` exit 0; warning-denied all-target
Clippy `7adb551a29684235` exit 0. Process `mwyyfvz4-53lp8a` exit 0:
33/33 focused unittest cases (rollback 3, durable identity 3, cross-gateway 2,
YOLO lifecycle 3, native OAuth 17, permission modes 5) plus three real isolated
systemd scenarios: old updater refused/old service restored, new startup fails
after actual audit migration/old service restored, successful new updater
upgrade. Existing YOLO authorization verified with actual v0.5.0-beta binaries
in the ordinary-user recovery fixture; nested service fixture uses Standard
because nested broad isolation probing is unavailable. Negative control
`mwyyfg1q-kt0cjb` fails against the prior build lacking the old-updater guard.
All 28 locked hashes intact. Prior AGY 228 Rust/293 locked/real loopback results
apply to the earlier durable candidate, not a fresh full acceptance of this
checkpoint. No real reboot or production migration performed. Older binaries
cannot read v2 metadata outside the validated upgrade rollback contract.
If recovery detects incompatible new state, it fails closed for operator review.

Production v0.5.0-beta PID 1012 and canonical main remain unchanged. Operator
requested a push; publish this tested source on the separate
`fix/0.6.0-beta-durable-rollback` branch. Main promotion and version publication
require acceptance of the exact updated artifact and remaining release checks.

## 2026-11-27 — Veyl 0.6.0-beta reboot-safe durable identity blocker resolved and verified; renewed operator acceptance pending

Resolved the Btrfs reboot `st_dev` blocker identified in `../AUDIT_REBOOT_HANDOFF-2026-11-27.md` (`st_dev` `58 -> 56 -> 58` while inode `20901595` remained unchanged) while retaining the original `../release-0.6.0-beta/` bundle untouched and staging the corrected candidate separately in `../release-0.6.0-beta-durable/`:
- Shared reboot-stable filesystem identity (`src/security/durable_id.rs`, `src/security/mod.rs`): added safe `DurableFs` (`Persistent { fs_type, fsid }` vs `Volatile { fs_type, device }`) and `DurableObjectId` under `#![forbid(unsafe_code)]` via `fstatfs` and `fstatvfs`. Supported persistent filesystems (`btrfs`, `ext2/3/4`, `xfs`, `f2fs`, `bcachefs`, `jfs`, `reiserfs`, `zfs`) with non-zero `f_fsid` survive reboot device-number renumbering, while Btrfs `f_fsid` folds the subvolume `treeid` so snapshot/subvolume substitutions fail closed; volatile mounts (`tmpfs`, `ramfs`, `overlayfs`) and zero-`f_fsid` filesystems remain strictly bound to live `st_dev`. Same-boot descriptor/race/session/job/updater/tmpfs guards retain strict `(st_dev, st_ino)`.
- Audit ledger & explicit recovery (`src/security/audit/ledger.rs`, `src/security/audit.rs`, `src/audit_cli.rs`, `src/http/operator.rs`): versioned `Head` `v2` stores `durable: DurableObjectId` alongside `active: [st_dev, st_ino]` and exact `tip`. Same-`st_dev` `open()` safely upgrades legacy `v1` checkpoints to `v2` after full genesis-to-`tip` verification without modifying records or resetting history; mismatched-`st_dev` `v1` fails closed until explicit `veyl audit recover-identity --config PATH | --log PATH`, which requires a persistent FS, exact `inode` match, and 100% intact cryptographic hash chain, upgrades `.head` to `v2`, and logs `audit_identity_recovery`. Corrupted ledgers, inode mismatches, `tmpfs` remounts, and already-`v2` mismatches are rejected.
- Persistent bindings & migrations across other subsystems: updated `Rule` (`src/protected_paths.rs`, plus audited `veyl protected-paths migrate` in `src/protected_cli.rs`), durable OAuth `veyl-native-oauth-v2` root binding with safe exact-`dev` `v1 -> v2` migration (`src/http/oauth.rs`, `src/http_common/oauth_http.rs`, `src/http_common/oauth_http/durable.rs`), provider-only `upstream_workspace_roots` grants (`src/upstream/workspace.rs`, `src/upstream/admin.rs`), and optional `StageProof.fs` (`src/tools/filesystem.rs`, `src/tools/timeshift.rs`).
- Verified against separate candidate `../release-0.6.0-beta-durable/` (`veyl` `f5458e8d24cf1a9f835f1feb2cf5cdc179d96dc69adc06136f704984d790f3a0`, `mcp-gateway` `5af26d6f182fdb1f9ed2df7cbeadbdfe79adb4c50455c89af4a4482e8fdba89c`, `veyl-monitor` `7ecebd5ca3d4776a38fd9d4ab6025335f4abf9de3bc28402631eed3359fa6933`, `veyl-connector` `d8ef920fe99a82c82f8c62854b97ab15c54c07c3717b366d462f05e247355c2`):
  - `cargo clippy --all-targets -- -D warnings`: pass (0 warnings).
  - `cargo test -- --test-threads=1`: 228/228 pass, 0 failed, 0 ignored.
  - `tests/durable_identity.py`: 3/3 pass (`v2` device tolerance, `v1` stale rejection & `audit recover-identity`, `protected-paths migrate`, `mcp-servers workspace-folder` durable grant).
  - `tests/durable_identity_loopback.py`: pass across real kernel loop mounts (Btrfs `st_dev` `118 -> 119` remount recovery, Btrfs snapshot subvolume substitution rejection, ext4 `1792 -> 1793` remount recovery & copied-FS rejection, volatile `tmpfs` strict `st_dev` rejection; all disposable mounts cleanly unmounted).
  - Production read-only compatibility check (untouched `~/.local/state/veyl/clients.json` & PID `1012`): `audit verify` passed (`VERIFY_RESULT=VALID records=2590 segments=1 bytes=844995`) and `mode list` confirmed existing grants intact (`chatgpt yolo`, `codex standard`, `agy standard`).
  - Disposable 64 MiB/4096-inode host `tmpfs` `tests/oauth_funnel.py`: 5/5 pass, 0 skipped, clean unmount verified.
  - All 32 additional Python integration suites + `onboarding_browser.py`: 139/139 unittest cases + browser probe pass (147 unittest cases total + loopback + browser probe).
  - Locked acceptance via `tests/prepare_locked_artifacts.py`: 28/28 pin hashes verified; all 28 suites 287/287 pass (`locked_audit_chain.py` 13/13 with `--features test-hooks`), plus `locked_three_modes.py` 6/6 pass (293/293 locked/supplementary total, 0 skipped, staging dir cleaned).
  - Crate & release preflight: `cargo package --offline --locked --allow-dirty --no-verify`, `../SOURCE_SHA256SUMS-0.6.0-beta-durable`, and `../veyl-0.6.0-beta-durable-source.tar.gz` verified; `gh auth status` (`kmanisk`) and `~/.cargo/credentials.toml` ready.
- Operator acceptance gate (`AGENTS.md`): local `veyl update` / install, production restart, canonical `~/Projects/veyl` `main` promotion, GitHub `v0.6.0-beta` release, and `crates.io` publish await renewed explicit operator acceptance of `../release-0.6.0-beta-durable/`.

## 2026-11-27 — Veyl 0.6.0-beta candidate verified (OAuth YOLO state isolation, re-consent clamp, 293/293 locked + bounded tmpfs PASS); release HOLD

Prepared and verified release candidate `0.6.0-beta` (target tag `v0.6.0-beta`) in
`public-connector.b64EhS58/source` and staged optimized binaries in `../release-0.6.0-beta/`:
- Cross-gateway state isolation (`src/protected_paths.rs`, `src/jobs/broad.rs`, `src/http/oauth.rs`, `src/skills.rs`): added `CONTROL_PLANE_DIRS` (`.veyl-login`, `.local/state/veyl`, `.local/state/mcp-gateway`, `.config/mcp-gateway`, `.veyl-update-backups`) and `.veyl-update.lock` to mandatory protection (`is_mandatory`) and `Broad::prepare` masking, plus top-down `--dir` creation in `Broad::command` for absent ancestor directories before `bwrap --tmpfs` binds. Added `is_mandatory_for_skills` so `Skills::parse` preserves the default sibling `~/.local/state/veyl/skills` store initialized by `veyl init` / `veyl setup` while keeping raw file tools, git, upstreams, and protected-path rules blocked across all control-plane dirs.
- Privilege resurrection prevention (`src/http_common/oauth_http.rs`, `src/core/oauth.rs`): `operator("/approve")` now calls `state.grants.downgrade_oauth_client(&oauth_client_id)` when approving `ConnectionMode::Standard`, permanently clamping all earlier grant families for that client so subsequent fresh `Yolo` approvals cannot resurrect old family privileges. Added unit test `reconsent_to_standard_clamps_old_yolo_families_across_later_yolo_grant`.
- Version bump and preflight (`Cargo.toml`, `Cargo.lock`, `README.md`): bumped `veyl` package version to `0.6.0-beta`; verified `cargo package --offline --locked --allow-dirty --no-verify` (`veyl-0.6.0-beta.crate`, 193 files) and release credentials presence (`gh auth status`, `~/.cargo/credentials.toml`).
- Verified against `../release-0.6.0-beta/` (`veyl` `74e49fbc89432144ad6ed196cf49fdb1726ea1f616ed86d7a06c0fd8c1ebc244`, `mcp-gateway` `005a248ac1f6df38384499b86c2efa3538cf28978098317118bbe254ddf7f3c8`, `veyl-monitor` `7ecebd5ca3d4776a38fd9d4ab6025335f4abf9de3bc28402631eed3359fa6933`, `veyl-connector` `64f719f780818375d5f70932fcfea333477f4d0f15f8322e707f38835c8446a`):
  - `cargo clippy --all-targets -- -D warnings`: pass (0 warnings).
  - `cargo test -- --test-threads=1`: 222/222 pass, 0 failed, 0 ignored.
  - `tests/oauth_yolo_cross_gateway.py`: 2/2 pass (`test_native_state_is_masked`, `test_reconsent_never_revives_old_yolo`).
  - `tests/oauth_yolo_lifecycle.py`: 3/3 pass.
  - Disposable host `tmpfs` (64 MiB, 4096 inodes, UID/GID 1000, mode 0700, `nosuid,nodev`) `VEYL_TEST_BOUNDED_WORKSPACE` run of `tests/oauth_funnel.py`: 5/5 pass, 0 skipped, clean unmount/removal verified.
  - Locked acceptance via `tests/prepare_locked_artifacts.py`: 28/28 pin hashes verified; all 28 suites 287/287 pass (`locked_audit_chain.py` 13/13 with `--features test-hooks`), plus `locked_three_modes.py` 6/6 pass (293/293 locked/supplementary total, 0 skipped, staging dir cleaned after run).
  - Remaining Python integration suites: 134/134 unittest cases plus `onboarding_browser.py` (`FIRST_RUN_BROWSER_PAIRING_PASS`, `DASHBOARD_TABS_AND_KEYBOARD_PASS`) across 31 suites against `../release-0.6.0-beta/` (total 144 Python unittest cases across 34 scripts + browser probe passing).
  - Explicit non-applicable/held checks: `tests/android_http.py` requires `target_os = "android"` (Termux); `tests/updater_lifecycle.py` stops at the foreground live-instance guard because production `mcp-gateway` PID `1042` remains untouched.
- Operator acceptance gate (`AGENTS.md`): local `~/.local/bin` install, production service restart, canonical `~/Projects/veyl` `main` promotion, GitHub tag/release `v0.6.0-beta`, and `crates.io` publish await explicit operator approval of this exact verified candidate.

## 2026-11-27 — Direct OAuth onboarding, genuine per-connection YOLO, mode switch, and selective logout PASS; external-client HOLD

Completed the remaining direct OAuth onboarding and per-connection permission
architecture in candidate `public-connector.b64EhS58/source`:
- Simplified `veyl login` (`src/oauth_cli/managed.rs`, `src/oauth_cli/onboarding.rs`, `src/tailnet/oauth_provider.rs`, `src/http/mod.rs`): interactive TTY workspace selector (default CWD, validated outside `~/.veyl-login`), actionable Tailscale MagicDNS/HTTPS/Funnel prerequisite guidance, automatic `--managed-login` job profile initialization (`Standard` read-only default), best-effort MCP URL clipboard copy (`wl-copy`/`xclip`/`xsel`), and `--no-ui` control.
- Per-connection mode persistence & genuine OAuth Broad YOLO (`src/core/oauth.rs`, `src/core/oauth/persistence.rs`, `src/http_common/oauth.rs`, `src/http_common/oauth_http{,/durable}.rs`, `src/http/{admission,oauth,mod}.rs`, `src/jobs/{mod,broad,launch,runner,receipt,session,api}.rs`): new DCR registrations and approvals default to `Standard`; local approval (Dashboard `#oauth` and `veyl oauth`) allows explicit `YOLO` (`BroadYolo`) bound to mode-specific `scope_fingerprint`. Fixed `Broad::command` masked-ancestor containment check (`src/jobs/broad.rs`) so `~/.veyl-login/profile` inside masked `~/.veyl-login` validates properly. OAuth `BroadYolo` reuses `Tool::in_yolo_preset`, `Broad::prepare` protected-path masking/read-only binds, native audit logging (`oauth-job-v1-...`), and systemd job resource ceilings (`MemorySwapMax=0`, `TasksMax=128`, `CPUQuota<=100%`, `256 MiB`, `300s`), enforced pre-spawn under `.oauth-admission-lock` via `active_family_guard_with_mode(..., required_yolo)`. `FULL` remains disabled over OAuth.
- Persistent mode switching & selective logout (`src/mode_cli.rs`, `src/local_cli.rs`, `src/oauth_cli.rs`, `src/oauth_cli/managed.rs`, `src/http/dashboard/app.js`, live `control.sock` IPC): `veyl mode` (`list`, `get`, `standard`, `yolo`), `veyl oauth mode`, and Dashboard `#oauth` persist mode changes atomically. Escalation (`standard -> yolo`) revokes existing Standard grant families and requires fresh OAuth authorization; downgrade (`yolo -> standard`) immediately clamps active families and denies elevated operations. `veyl logout` supports live and offline single-client (`--client ID`, TTY disambiguation) and explicit `--all` revocation.

Verified cleanly on optimized candidate artifacts in `../preview-oauth-yolo/` (`SHA256SUMS` all 4 OK: `veyl`, `mcp-gateway`, `veyl-monitor`, `veyl-connector`):
- Clippy `--all-targets -- -D warnings`: PASS (exit 0).
- Rust suite (`guarded_cargo test -- --test-threads=1`): 221 passed, 0 failed (`mcp_gateway` lib 38, `mcp-gateway` 74, `veyl` 74, `veyl-monitor` 11, `bridgedev_parity_and_nightshift` 3, `gate3_operator` 11, `onboarding` 6, `pass2_mutation` 4).
- New & existing Python integration suites: `tests/oauth_yolo_lifecycle.py` 3/3, `tests/oauth_managed_login.py` 2/2, `tests/managed_login_yolo.py` 1/1, `tests/oauth_funnel.py` 4/4 + 1 skipped (dedicated host tmpfs), `tests/oauth_native.py` 17/17, `tests/oauth_http_preview.py` (`veyl-connector`) 6/6, `tests/oauth_jobs.py` 3/3, `tests/oauth_commands.py` 2/2, `tests/oauth_interactive.py` 4/4, `tests/oauth_upstreams.py` 3/3, `tests/permission_modes.py` 5/5, `tests/direct_remote_boundary.py` 2/2, `tests/dynamic_jobs.py` 5/5, `tests/process_sessions.py` 10/10, `tests/git_tools.py` 3/3, `tests/timeshift.py` 9/9, `tests/context_and_system.py` 3/3, `tests/product_features.py` 9/9, `tests/test_dashboard_preview.py` 1/1, `tests/test_guarded_cargo.py` 6/6, `tests/runtime_bundles.py` 2/2, `tests/platform_probe.py` 2/2, `tests/onboarding_browser.py` PASS. (`tests/updater_lifecycle.py` stopped on live production PID 1042 guard as expected.)
- Locked acceptance: 28/28 pin hashes verified intact; 21 applicable non-hooked locked Python suites passed 209/209 cases; `locked_audit_chain.py` passed 12/13 (subcase `12a_genuine_interrupted_write` requires `--features test-hooks`).
- Canonical `~/Projects/veyl` clean; production PID `1042` untouched; no version bump, commit, or push.

## 2026-11-27 — Managed login/logout and native YOLO isolation PASS; release HOLD

Operator authorized continued compilation and isolated YOLO testing. Reclaimed
only inspected inactive dev build intermediates (361.2 MiB and 1.3 GiB logical);
verified release backups and left the 40 GiB build guard unchanged. First build
found a String error conversion, fixed; optimized build 9e86da1c5933410a passed.
Staged preview-managed-login.xtuheNeW passed 37 integration cases, one advanced
bounded tmpfs positive case skipped. Additional security review found that
native broad YOLO could read the new managed OAuth directory. New regression
tests/managed_login_yolo.py failed against that earlier binary at the intended
read-denial assertion. Added mandatory managed state mask to Broad and path
conflict checks. Guarded optimized build 8050e43db3134ce8 exited 0. Exact
artifacts: ../preview-managed-isolation.9MrrYGsG; all four SHA256SUMS pass.
BridgeDev ordinary-user regression mwy2s57n-sr7h0b exited 0: 38 passed,
one skipped (dedicated bounded tmpfs needed). Managed login/logout 2/2,
native permission modes 5/5, dynamic YOLO confinement 1/1, new managed-state
isolation 1/1 (direct read/write denial, command mask including socket),
native OAuth 17/17, Funnel 4/4 + one skip, boundary 2/2, OAuth HTTP 6/6.
28 locked pins verified; pre-doc tree fe6eb1095802dd4051780cc3588f65fed7fc47dc2048699005aa1946908c08a9.
Production PID 1042 unchanged; canonical main clean. No AGY delegation,
public route, version bump, commit or push. Native YOLO tests are NOT proof of
remote OAuth YOLO. The managed Standard profile remains read-only; real
per-connection mode selection and broad OAuth admission are unimplemented.
Do not run sensitive managed profiles alongside an unpatched native broad
gateway; previously admitted old jobs and explicitly broad/full native roots
need separate migration review. Actual external client acceptance, full
new-candidate acceptance and exact operator approval remain pending.

## Historical — Managed login/logout draft; initial compile BLOCKED

Implemented a managed Standard-only CLI lifecycle in src/oauth_cli/managed.rs,
a private same-UID Unix shutdown listener in the existing foreground runtime,
and exclusive stopped-profile durable revoke-all with interrupted-revoke
recovery. Managed path ~/.veyl-login/profile; first login uses cwd or --root
and explicit public confirmation, later login resumes the saved issuer.
Logout stops only the managed runtime, waits for its lifetime lock, revokes
registrations and grants under the durable store lock, preserves workspace
and audit, and clears the pending marker after successful revocation.
Added tests/oauth_managed_login.py for duplicate login, live and offline
logout, interrupted durable revoke, and reconnect. Genuine OAuth YOLO and
per-connection mode changes, interactive workspace selection, Tailscale
login guidance and clipboard automation remain unimplemented.

rustfmt parsed/formatted the new module, Python AST parse and git diff
--check passed, all four previous optimized checksums passed (mwy2dy6c-tnl24u).
Guarded compile e5fb9f690c0642b4 refused admission (exit 75, 39.91 GiB free).
New Rust code has not been compiled or runtime-tested; do not deploy.
No cache deletion, version bump, commit or push. Operator requested routine
implementation and verification through BridgeDev, not automatic AGY
delegation; candidate AGENTS.md updated accordingly.

## 2026-11-27 — Onboarding UX correction requested (historical)

Operator wants one-command login/logout and easy per-connection mode
selection, with Standard default and explicit local YOLO selection.
See the new onboarding checkpoint in DIRECT_REMOTE_PLAN.md. Live CLI inspection
confirms only low-level oauth setup/run and local consent/list/revoke currently
exist; native OAuth explicitly rejects non-Standard policy. Existing native
mode CLI is not proof of OAuth mode support. No Rust code, binaries or
production settings changed for this design correction. Do not release the
old workflow as the final onboarding experience. Next implement managed
profile lifecycle, local consent/mode selection and safe revocation; preserve
existing broad YOLO semantics, resource boundaries and client independence.
Independent acceptance of changed security paths and live-client tests remain
required.

## 2026-11-27 — Direct OAuth release scope confirmed; live acceptance HOLD

Operator chose the existing client-independent direct OAuth MCP architecture.
Hosted relay and standalone plugin packaging are deferred, not release
gates. Existing experimental artifacts are preserved; no Rust or runtime
change is needed for this scope decision. Direct live preview HTTPS discovery
passed from the host. The private package was created but offered desktop
launch; web custom creation failed before successful OAuth client registration.
Actual read/write/command, revocation/reconnect and Android client checks remain
unverified. See DIRECT_REMOTE_PLAN.md for the short concrete acceptance matrix.
Preserve 293 locked/supplementary, 217 Rust and full mounted 5/5 independent
acceptance evidence; do not rerun the full suite for documentation only.
BridgeDev regained access; HEAD 66995f1c6e700dcf19e57fd5086df69648fe83f5,
all four preview-resource-final checksums passed, canonical main clean,
production mcp-gateway PID 1042 observed, 41 GiB available (mwy1tseh-9xi26n).
No isolated preview process was observed in the process list. Production
promotion remains on HOLD until live acceptance and operator release approval.

## Advanced mounted acceptance — independent PASS; live client HOLD

AGY completed the outstanding full advanced simulated Funnel suite against unchanged preview-resource-final binaries, with a disposable operator-authorized 64 MiB/4096-inode host tmpfs (UID/GID 1000, mode 0700, nosuid,nodev). Full 5/5 PASS, zero skips; fixed bounded namespace launcher 1/1 PASS. Raw evidence: ~/.gemini/antigravity-cli/brain/dccf4a3e-1235-47ad-b36b-6285659d2393/scratch/advanced_funnel_host_tmpfs.log. BridgeDev independently verified that log, exact pre-documentation-update tree e56eeaed59c7563a8a37cabba39e6678b5915b0980c27e91e4f7dcdb65cb5028, all four binary hashes, 28 pins, fixture absence and no remaining mount (mwxxg1rd-n9y7p2). Production PID 203133 unchanged; canonical main clean, 41 GiB available. All local/simulated gates closed; actual isolated HTTPS/DCR/Plugin Creator operator test remains, then exact release approval and versioned deployment. No new host mount or public route authorized by this report.

## AGY resource-hardening acceptance — local/simulated PASS; promotion HOLD

AGY report accepted locally, not for live public promotion. BridgeDev verified the exact pre-edit tree SHA-256 3b68480fffd08500fca86722ee47003e589333e1712935e2e7daf2be8d734fac, HEAD 66995f1c6e700dcf19e57fd5086df69648fe83f5, 28 pins, all four optimized checksums and raw clean 293-case log (~/.gemini/antigravity-cli/brain/dccf4a3e-1235-47ad-b36b-6285659d2393/scratch/locked_293_clean.log). Test-only fix moves private namespace re-exec before fixture import to preserve the binary argument. Direct invocation with one binary argument passed; 12 focused tests passed (bounded workspace 1, interactive 4, Funnel 4, plugin packaging 3), full mounted advanced positive case skipped (mwxx6aeg-wg4cho exit 0). Runtime code/binaries unchanged. No rebuild or complete locked rerun required for this test-only correction, but new working tree identity differs. AGY found immediate tmpfs remount can reuse device/inode: do not reuse durable authorization across a recreated mount; fresh profile/authorization required as operator precaution; automated mount-generation binding remains unimplemented. Root-owned executable checks must not be weakened to accommodate user namespace overflow UID. A temporary operator-authorized host tmpfs and exact full advanced simulated test are outstanding, followed by real isolated HTTPS and private plugin connection, then release approval. No live route, host mount, version change, install or publication performed.

## 2026-11-26 — Resource-hardening checkpoint: local PASS; promotion HOLD

Implemented zero swap and a maximum of 128 tasks in verified systemd job scopes; public writable OAuth profiles now require a private dedicated tmpfs (at most 256 MiB/16384 inodes, nosuid,nodev, UID-owned mode 0700). Admission, consent, recovery and signed detached job receipts enforce the bounded workspace. This is volatile storage; no persistent quota-backed workspace or global multi-profile resource quota is implemented. Trusted upstream effects are outside the workspace limit.

Local evidence: 217 Rust tests passed (before readiness correction and test-module relocation); after the readiness correction all 28 unchanged pinned suites passed, 287 cases, plus six supplementary three-mode cases. Receipt: ../locked-resource-final/receipt.json; pinned run: ../locked-resource-final-results.log. Targeted OAuth: 13 passed, one full advanced mounted-workspace positive case skipped; guard 6/6, packaging 3/3. Private namespace 1 MiB aggregate ENOSPC positive test passed twice, including staged binary. Four updater lifecycle scenarios passed. First nested namespace invocation failed ENOSPC; direct ordinary-user unshare passed. Locked permission fixture required its intended umask 022 instead of inherited 077; no locked tests changed. Readiness record partial-write race fixed. Clippy passed after test-only module relocation; the final guarded release build completed with exit 0 (job dcd1322e085b4028; optimized compile 2m20s). Four exact optimized executables preserved and SHA256SUMS verified in ../preview-resource-final/; previous preview checksums still pass. Documentation-only updates followed the runtime build. The final source needs independent AGY restaging, including the full bounded advanced positive test. Actual external OAuth and ChatGPT Plugin Creator acceptance, operator review of exact candidate and promotion authorization remain required. Production unchanged.

## 2026-11-26 — Advanced direct-remote candidate: implementation PASS; release HOLD

Candidate: `/home/onyx/.local/share/veyl-development/candidates/public-connector.b64EhS58/source` (uncommitted; canonical main unchanged). Optimized preview: `../preview-advanced-release/`; all four SHA256SUMS entries verified.

- Durable OAuth admission lock serializes grant writes with worker spawn and IPC input admission; deterministic real-worker denial/positive-control regression passed.
- Explicit `--funnel-advanced` with `--funnel` and selected job/upstream grants enables managed Standard capabilities with exact local consent and matching recovery flags. Existing defaults unchanged. Simulated Funnel passed; no live route opened.
- Private ChatGPT package generator: `tests/chatgpt_plugin_package.py`, with strict HTTPS discovery/issuer/resource/PKCE/DCR validation, no credentials, and fixture tests. Actual Plugin Creator upload awaits a verified live preview endpoint and operator authorization.
- Final Rust: 215/215; focused Python: 98/98 across 19 suites; guard/package: 9/9; browser pairing and dashboard keyboard/tabs passed; Clippy all-targets -D warnings and optimized build passed. First regression process disconnected after 71 integration cases; remaining suites rerun separately. All 28 locked hashes matched; full independent locked execution is not claimed.
- Evidence: `../final-advanced-regressions.log`; tail process `mwxuradv-rri5i0` exit 0; compilation job `df1964b6f0a742c6`, release `6742e933333c474c`, Clippy `a65e3e86670f43bb`. Logs under ~/.local/state/chatgpt-local-coder/jobs/. Disk 40.08 GiB free; do not bypass guarded build thresholds.
- Remaining gates: AGY independently verifies exact candidate, including complete locked acceptance; operator-approved isolated actual HTTPS/ChatGPT OAuth private plugin test; then explicit release version approval, production deployment and rollback verification. Arbitrary writable workspace has no disk quota: use a bounded dedicated workspace/filesystem before live advanced testing. Trusted upstreams may have side effects/shared state. No live endpoint, plugin creation, version bump, commit, push or production change.

## Runner launch authorization hardening — local PASS / public HOLD (2026-11-26)

Added optional signed receipt `oauth_launch` with original native policy revision and access/native credential deadline; legacy/noninteractive receipts omit it and stable session identity is unchanged. Before spawning an OAuth interactive workload, the runner requires this authority, acquires the nonblocking native policy snapshot lock and holds it through spawn, verifies durable family again, and rechecks the deadline. Missing authority, stale policy, active writer, expired deadline or invalid family fail closed. A revocation after the last durable family read is revocation of an already-admitted workload; the read and spawn are not an atomic OAuth transaction. Existing running sessions retain their admitted sandbox and fresh IPC authorization. No public scope widened.

Storage: removed only inspected obsolete compiler intermediates in canonical and candidate targets, actual +3.47 GiB available; original candidate executables' four hashes verified. Guarded single-job builds used shared canonical cache, no incremental/debug info. First process record mwxtijho-kquc8y disappeared after compilation. Recoverable job 918bbaa4c48b4aeb compiled and new negative control passed; 8 unrelated filesystem tests returned ENOSYS in restricted system-job execution (exit 101). Ordinary UID1000 rerun mwxtl8p1-u2qfgt: 73/73 PASS. Full guarded `test --no-run` job 34f8596f8f6a4d32 exit 0; ordinary direct execution mwxtncvi-u84uqn all nine targets 215/215 PASS (34+73+73+0+11+3+11+6+4). Runtime process mwxtlgka-aooeou: OAuth interactive 2/2, native sessions 10/10, OAuth commands 2/2 PASS; parity 3/3 separately mwxtm6y6-ci3npe. Clippy all-targets warnings denied job b1ff5ec9f17f498e exit 0. All 28 locked hashes and diff check PASS (mwxtofuh-lnmyqf); production PID 203133 still installed binary, main clean. Durable build logs ~/.local/state/chatgpt-local-coder/jobs/{918bbaa4c48b4aeb,34f8596f8f6a4d32,b1ff5ec9f17f498e}.log.

Preserved exact fresh debug executables and SHA256SUMS in `../preview-runner-launch/` (copy receipt mwxtornv-tbv367). No release build or complete locked battery rerun in this checkpoint; independent AGY acceptance pending. New negative test directly exercises launch authority check (current policy, stale revision, expired deadline, busy exclusive writer); it does not deterministically interleave live worker spawn with OAuth revocation. Next: targeted worker race control and full locked acceptance, then separately reviewed public capability admission. No commit/push/install/routes/grants changed.

## Takeover checkpoint — focused runtime verification PASS / full build HOLD (2026-11-26)

ChatGPT/BridgeDev rechecked the dirty candidate at base `66995f1c6e700dcf19e57fd5086df69648fe83f5` without rebuilding: existing debug binary passed OAuth interactive 2/2 (process mwxszzpr-09p9q1), legacy process sessions 10/10 and OAuth dynamic commands 2/2 (mwxt3kit-41tqnf); all 28 locked pins verified unchanged (mwxt3pyj-y56cbo). These are focused integration reruns, not independent AGY acceptance or a fresh build-to-source receipt. The previous 213 Rust, 96 focused and 105 locked cases remain reported historical results; 15 locked suites and optimized release are still outstanding.

Added candidate-only `tests/guarded_cargo.py` and `tests/test_guarded_cargo.py`, plus candidate AGENTS.md guidance. Six guard tests PASS and live preflight refused a build at 37.08 GiB free (mwxt350w-5rkdyl, exit 0 for the verification wrapper). The guard serializes cooperating builds via a shared lock, selects canonical target/build cache, uses one Cargo job, disables incremental/dev/test debug symbols, puts scratch on that disk, refuses below 40 GiB and stops its own process group below 15 GiB. It is not a filesystem quota and does not control unguarded processes. No Rust rebuild, production change, public activation, deletion, commit or push.

Source review clarification: runner pre-spawn checks durable OAuth family and sandbox/receipt/resource conditions; the native policy revision and request deadline are checked in Channel::step on signed IPC. The runner launch record does not carry the native revision/credential deadline, so the prior report's claim of both checks at both boundaries is not established. Review the admitted-launch/revocation race and add a targeted negative control before considering public interactive admission. Durable OAuth snapshot integrity is an unkeyed SHA-256 checksum, not a MAC or a defense against arbitrary outside same-UID processes. Public activation remains HOLD.

## Direct remote MCP — local OAuth interactive sessions PASS / public activation HOLD (2026-11-26)

Explicit `--workspace-interactive` on fresh setup and recovery alongside `--workspace-jobs` adds persistent pipe and PTY process sessions (`process_start`, `process_input`, `process_resize`, `shell_status`, `shell_reset`) in the existing offline, writable Standard workspace sandbox with mandatory systemd resource ceilings (`300s` max runtime, `100%` CPU, `256 MiB` RAM, `65536` bytes per stream, `4096`-byte UTF-8 input frames, no `extended_runtime`, no public `--funnel`). Reuses native `src/jobs/session.rs`, `src/jobs/session/channel.rs`, `src/jobs/session/terminal.rs`, and `src/jobs/runner.rs` without adding a parallel execution engine. Each session is bound to its OAuth grant family (`oauth-job-v1-<sha256>`), `Channel::step` and runner preflight validate both native `clients.json` (`PolicyFile::input_snapshot` + `expires_at`) and sealed durable `oauth-state.json` (`verify_active_family`: client registration, active family digest, `access_until_ms`, `family_until_ms`, non-interrupted snapshot), and OAuth interactive calls record metadata-only durable audit entries without logging raw stdin or bearer credentials. Non-interactive `--workspace-jobs` and `--workspace-commands` defaults remain unchanged (interactive/PTY profiles and `process_*`/`shell_*` tools still refused without explicit `--workspace-interactive`).

Verification (`CARGO_INCREMENTAL=0 -j 2`, `../target/debug/{veyl,mcp-gateway,veyl-connector,veyl-monitor}`): `cargo clippy --all-targets --offline --locked -- -D warnings` PASS; `rustfmt --check` on touched Rust files and `node --check src/http/dashboard/app.js` PASS; `cargo test --offline --locked -- --test-threads=1` 213/213 PASS (including 5 new tests across `durable.rs`, `jobs/config.rs`, and `jobs/session.rs`); 19 focused Python suites (`tests/oauth_interactive.py` 2/2 plus `oauth_commands.py`, `oauth_upstreams.py`, `oauth_jobs.py`, `oauth_native.py` with Chromium CDP, `oauth_funnel.py`, `oauth_http_preview.py`, `connector_preview.py`, `connector_persistence.py`, `direct_remote_boundary.py`, `http_header_hardening.py`, `linux_features.py`, `product_features.py`, `dynamic_jobs.py`, `extended_jobs.py`, `job_streams.py`, `process_sessions.py`, `permission_modes.py`, `activity_features.py`) totaling 96/96 PASS; `tests/onboarding_browser.py` (`FIRST_RUN_BROWSER_PAIRING_PASS`, `DASHBOARD_TABS_AND_KEYBOARD_PASS`) PASS; 28/28 locked SHA-256 pins intact; 13 applicable locked acceptance suites (`105/105`, including `locked_durable_jobs.py`, `locked_output_caps.py`, `locked_mode_suites.py`, `locked_three_modes.py`, `locked_dashboard_acceptance.py`, `locked_managed_job_cleanup.py`, `locked_protected_path_blockers.py`) PASS. Remaining 15 locked suites (e.g. `locked_audit_chain` requiring `test-hooks`, stdio/HTTP legacy M1/network suites) and optimized `--release` builds were not run in this incremental pass. Production `~/Projects/veyl` and live services untouched; public Funnel interactive access remains disabled.

## Direct remote MCP — local OAuth dynamic-command PASS / public activation HOLD (2026-11-26)

Explicit `--workspace-commands` on fresh setup and recovery, in addition to `--workspace-jobs`, permits exec_command/task_run in the existing offline, writable Standard workspace sandbox. Exact profile opt-in and consent fingerprint, family job ownership, durable receipts and mandatory systemd resource ceilings retained. Dynamic execution uses workspace root only, no ephemeral worktree or alternate roots, maximum 300s/100% CPU/256MiB/65536 bytes per stream, at most 2s synchronous wait. New launches fail closed when systemd scope is unavailable. Interactive sessions remain excluded pending separate runner-side authorization review. No public jobs or broader mode.

Build d25d0b2522e64aa8 exit 0, ~/.local/state/chatgpt-local-coder/jobs/d25d0b2522e64aa8.log: fmt, JS syntax, Clippy all-targets, four binaries, nine Rust test executables. New tests/oauth_commands.py 2/2 PASS (mwxqyifp-rx8ixk), real commands, durable family isolation, workspace escape/socket/alias denial, resource limits, explicit restart option, no-scope launch refusal. Consolidated ../oauth-command-final.log verified 208/208 Rust and 8/8 initial command/upstream/jobs integrations; native browser test then failed because optional chaining readiness was true when DOM nodes did not exist. Fixed the readiness predicate to require both elements present and visible, retaining the exact pairing-fragment removal assertion. Reran interrupted and remaining 68/68 cases using ../verify-command-tail.py (mwxr0cl3-tsfb9h exit 0, ../oauth-command-tail.log). Total 76/76 focused integrations, both browser probes and all 28 pinned hashes PASS. Locked lab unchanged. Full independent locked acceptance and external public HTTPS clients remain untested. Next interactive process gate; signed runner IPC admission must preserve OAuth family ownership and grant expiry/revocation semantics. Production unchanged; no deployment or permission expansion.

## Direct remote MCP — local OAuth upstream providers PASS / public activation HOLD (2026-11-26)

Explicit local `--workspace-upstreams --upstream-manifest ABSOLUTE_FILE` for setup and `--workspace-upstreams` on run. Strict unique JSON manifest, owner-controlled file, 1–4 configured providers with 1–16 named tools each. Offline trusted system stdio without external script mounts or runtime bundles; credential-free loopback HTTP only. No provider workspace mounts, private CA or inherited credentials. Exact consent scope and durable policy bind each grant; upstream discovery/calls audited under family-derived principal. Fresh upstream transport sessions are not provider-side tenant isolation; trusted providers may share application state and have side effects. Existing non-upstream consent contract unchanged. Public upstream grants remain disabled.

Build 5c59a0d46958442e exit 0, four binaries, Clippy all-targets, nine test executables. Native upstream tests 3/3 (mwxqgrx1-g51qnx). Consolidated ../oauth-upstream-final.log records 208/208 Rust and 74/74 focused integrations, including 3 upstream cases, previous 71 regression cases. Tracker disappeared after integration total; after verifying no remaining test process, separate ../oauth-upstream-browser.log confirms both real browser probes, all 28 locked hashes and diff check PASS. Actual upstream stdio and loopback HTTP invocation, exact grants, refresh/restart, revocation and policy change tested. No independent full locked acceptance, external client interoperability or live public route. Production unchanged; no release or permission expansion.

## Direct remote MCP — local OAuth named commands and jobs PASS / public activation HOLD (2026-11-26)

New explicit local `--workspace-jobs --job-profiles ABSOLUTE_FILE` onboarding and recovery with `--workspace-jobs`. Seven named command/job tools, exact profile consent fingerprint, writable offline workspace, bounded profiles and mandatory systemd CPU/memory/runtime backstop; no arbitrary shell/interactive tools or public jobs. Domain-separated per-family job owner, signed receipt marker, exact job/list/log/cancel ownership and local authenticated operator aggregate recovery after revocation. Descriptor-scoped workspace scan before admission and runner launch rejects multiply-linked regular files, special files and mount crossing within bounded traversal; external same-UID races remain out of scope. Existing job receipts omit new field for legacy mode, and non-job OAuth consent response is unchanged. No production permission change.

Initial implementation build mwxpnevd-p5h4lr and two OAuth job cases passed. Hardened resource-ceiling variant build f02219ad7f3d45f5 passed; test initially referenced an incorrect status key, corrected to assert exact resource_ceilings. 3/3 new tests passed (mwxpyxec-c15fao). Regression exposed additional fields in non-job consent scope, fixed without weakening old tests. Final build 161836e041224523 exit 0, log ~/.local/state/chatgpt-local-coder/jobs/161836e041224523.log: fmt/diff/Clippy all-targets -D warnings, four binaries and all nine Rust test executables. Final exact-source run mwxq4fsu-wwl2wv exit 0: ../verify-jobs-compat-final.py and ../oauth-jobs-compat-final.log record 208/208 Rust, 71/71 focused integrations (3 new OAuth jobs, 17 native OAuth, 3 Funnel, 14 connector/HTTP, 16 Linux, 9 product, 5 dynamic jobs, 3 extended jobs, 1 job-stream), browser pairing/tabs, all 28 locked hashes intact. No full independent locked acceptance or actual external OAuth/TLS test. Next explicit upstream capability group and independent review before adding broader dynamic commands or public jobs. No Codex delegation.

## Direct remote MCP — foreground Funnel provider PASS (fixture) / public activation HOLD (2026-11-26)

Implemented dedicated foreground Tailscale LocalAPI provider, explicit `oauth setup/run --funnel`, authorized free 8443/10000 port detection, ETag conditional update and exact foreground ownership/read-back, private dashboard boundary and lease-driven teardown. Existing route configuration is preserved. Restart recovers the exact persisted issuer and refuses a different hostname or port; local-only profiles cannot silently switch origins. Native OAuth remains mandatory regardless of proxy metadata, including private Serve clients using the same hostname. No production changes, extra grants, new daemon or dependencies. Real external TLS and actual live-daemon route cleanup remain unverified; test fixture models that behavior.

Final fmt, Clippy all targets -D warnings and four debug binary build passed (mwxo5fnt-hxlvyw exit 0). Final exact source regression: 208/208 Rust tests and 20/20 native OAuth/Funnel cases (../oauth-funnel-final.log; process tracker disappeared only after these completed). After verifying no leftover test process, unfinished 39/39 integration cases plus real browser pairing/tabs and all 28 locked pin hashes passed (mwxoets7-wjdrzz exit 0, ../oauth-funnel-tail.log). Total 59/59 focused integrations. Installed Tailscale 1.104.7 read-only IPN initial event and strong conditional config version compatibility: mwxo5uv1-vhq93f exit 0, ../verify-real-ipn-readonly.py; actual Serve configuration digest unchanged before/after. No public route was created on the real daemon. Existing production service PID 203133 observed unchanged. Full independent locked acceptance, actual external client OAuth and exact release approval remain outstanding. Next native capability expansion must preserve per-OAuth-family job ownership and explicit operator approval; do not automatically enable broad execution or upstream grants.

## Direct remote MCP — scoped workspace-tools PASS / public activation HOLD (2026-11-26)

After the directory safety and bounded-worker gate, added explicit `--workspace-tools` on fresh `veyl oauth setup` and matching `veyl oauth run`. This grants exactly nine native Standard tools: read_file, write_file, apply_patch, edit_file, create_directory, list_directory, directory_tree, file_info, search_files. Default read-only and previous four-tool workspace-edit remain unchanged. Exact scope fingerprint, durable policy/root binding, local consent and strict mutation admission remain mandatory. Wrong restart profile and ungranted exec are denied. No jobs, extra roots or broad modes enabled. Shared inspection now bounds list output to 512 items and scans to 16384 entries/deadline; tree visits to 512 entries/deadline, with explicit truncation; file_info hashing to 1 MiB with no-follow, nonblocking open and size/link checks. No guarantee against arbitrary concurrent same-UID file changes.

Build mwxnewnz-tmn1oq exit 0: all-target Clippy -D warnings and four debug binaries. Native OAuth 17/17 (mwxnicwo-ai3lku, ../oauth-workspace-tools-initial.log), Linux 16/16 and product 9/9 plus browser probes (mwxnj5p3-v38jxl, ../oauth-workspace-tail.log), remaining connector/HTTP 14/14 (mwxnk7hj-d0dka9, ../oauth-workspace-http.log). Total 56/56 focused integration cases for expanded source; 28/28 locked hashes verified unchanged. Previous bounded-worker checkpoint 208/208 Rust unit/integration harness tests; not rerun in full after workspace expansion. No full locked acceptance or public web-client acceptance yet.

Next implementation: fixed-origin dedicated tunnel provider with ownership receipts, collision checks and disposable activation/rollback fixtures; review separate job/command and upstream capability groups with per-registration/family ownership before exposure. Public activation remains on hold until actual HTTPS OAuth interoperability and AGY acceptance. Existing production remains untouched. ChatGPT implements directly; AGY independently verifies. Operator requested continuous implementation without routine confirmation pauses.

## Direct remote MCP — directory safety and bounded OAuth workers PASS (2026-11-26)

Directory gate mwxmvpes-ynmn50 exit 0: two focused native Rust tests plus real HTTP parity (1/1), including symlink escape and audit checks. Prior draft reviewed/imported with 193-entry manifest. Same-UID external rename race and partial creation on error remain documented; no claim of atomic recursive mkdir.

Moved OAuth HTTP mutex acquisition and durable lifecycle commits to bounded spawn_blocking work (8 public, 4 operator slots per server). Native pre-body policy, credential and durable admission audit and dashboard consent use the same slots; tool dispatch retains its existing separate bounded workers. Permits owned by actual workers survive request cancellation, and state remains serialized with commit-before-response and fail-closed storage. No new service or dependency. A slow transaction can still delay serialized OAuth operations; admin has reserved worker capacity, not independent state. A timed-out admitted transaction may finish, so inspect before retrying.

Build mwxn4rxm-gz6wvp exit 0: fmt, all-target Clippy -D warnings, nine test executables, four binaries. ../verify-blocking-final.py and ../oauth-blocking-final.log record 208/208 Rust (zero ignored/failed) and 30 completed focused integration cases (16 native OAuth, 6 connector OAuth HTTP, 2 connector preview, 2 connector persistence, 2 direct boundary, 2 header hardening). Tracker disappeared during Linux suite; verified no process remaining and reran only missing cases with ../verify-blocking-tail.py (mwxncqcb-13picu), ../oauth-blocking-tail.log confirms 16 Linux + 9 product + real browser onboarding PASS, 28 pins intact. Total 55/55 focused integrations. No full locked suite or public acceptance yet. Next expand explicit scoped filesystem tools with bounded inspection and verify before broader commands/jobs. ChatGPT implements, AGY independently accepts; no Codex.

## Operator workflow correction and directory safety review (2026-11-26)

Only ChatGPT via BridgeDev implements and integrates; AGY alone independently
verifies. No further Codex delegation. Earlier separately launched Codex
directory draft had already exited 0 before this instruction. Original
193-entry baseline was verified and only src/tools/filesystem.rs,
src/tools/mutation.rs and tests/bridgedev_parity_and_nightshift.rs were
reviewed/imported (process mwxmv2a5-2z5a95 exit 0). Directory creation now
uses descriptor-relative mkdirat, no-symlink/no-mount-crossing opens,
identity revalidation and audit intent before mutation. OAuth grants still
exclude create_directory. Outside same-UID rename races and partial trees
on error remain documented limitations. Normal-user focused tests:
process mwxmvpes-ynmn50; local acceptance is pending until its actual exit
and output are inspected. Existing production remains unchanged.

## Direct remote MCP — scoped workspace-edit OAuth PASS / public activation HOLD (2026-11-26)

Added explicit `--workspace-edit` to fresh onboarded setup and repeat on run. Default stays read_file-only. Edit profile permits only read_file/write_file/apply_patch/edit_file under Standard, no extra roots, no jobs; legacy raw operator fixture stays read-only. Exact durable policy/root binding retained. Local consent displays native workspace, Standard mode and sorted tool list, and edit approval requires matching scope_fingerprint from inspection. Dashboard sends it; CLI accepts it with the existing exact binding fields. No new dependency or mode escalation.

Negative control on initial build exposed legacy Standard atomic hardlink detach accepted by write_file. New OAuth-only strict_alias_scope reopens and checks pinned workspace identity and rejects multiply-linked mutation targets via the existing descriptor-relative target metadata guard; legacy behavior untouched. New tests exercise real write/patch/edit, traversal, absolute, symlink and hardlink denial (including patch/edit), unchanged outside content and inode, missing/wrong fingerprint, denied create_directory/exec, restart flag and durable revoke. Source review also identified create_directory's path-based create_dir_all as an unresolved symlink/race risk; not enabled for OAuth, needs independent disposable reproduction and descriptor-relative fix before wider exposure.

Initial build 1d4d2aaaf60545bd exit 0; initial integration 15 passed, one expected negative failed (hardlink); fixed as above. Final build 37cc2f7ec88041f4 exit 0 (log ~/.local/state/chatgpt-local-coder/jobs/37cc2f7ec88041f4.log), all-target Clippy, fmt, JS syntax, four debug binaries and nine test executables. Ordinary process mwxk01ia-zhoah7 exit 0, ../oauth-edit-final.log and ../verify-edit-final.py record 203/203 Rust, 55/55 focused integrations (16 native OAuth), existing browser pairing/tabs PASS, 28 locked pins verified. Full locked acceptance battery and cloud interoperability pending. Production inspected active PID 203133 NRestarts=0; no installation, version bump, grants or network changes.

Candidate public-connector.b64EhS58/source, base 66995f1, uncommitted. Next independent Codex task: safely fix scoped directory creation and test aliases/renames without widening OAuth; then blocking persistence isolation, additional capability groups, real tunnel/provider integration and client acceptance. AGY independently audits frozen candidate; BridgeDev verifies and owns subsequent integration. See DIRECT_REMOTE_PLAN.md.

## Direct remote MCP — automated local onboarding PASS / public activation HOLD (2026-11-26)

Operator prioritized onboarding ahead of wider native capabilities. Added `veyl oauth setup --root ABSOLUTE_EXISTING_WORKSPACE --profile ABSOLUTE_NEW_DIRECTORY [--open-ui]` and `veyl oauth run --profile ABSOLUTE_EXISTING_DIRECTORY [--open-ui]`. Fresh descriptor-relative non-replacing private profile creation, existing parent ownership and no-follow checks, mode 0700 directories/0600 state, separate workspace, one managed Standard read_file client, generated native credential verifier (raw token not retained), private audit, durable OAuth state, internally generated per-launch operator credential. Both listeners ephemeral loopback, fixed synthetic https://veyl.example origin, no tailnet; optional existing one-use dashboard pairing via xdg-open. Onboarded runs disable legacy bearer operator routes, while explicit older fixture mode remains compatible. Restart uses existing state only; duplicate setup, concurrent run, unsafe paths and missing state fail closed. Partial initialization is retained for inspection, never automatically overwritten/deleted. No service or public route enabled.

Implementation in src/oauth_cli/onboarding.rs, src/oauth_cli.rs, src/http/{mod,oauth,dashboard}.rs; user-facing README and DIRECT_REMOTE_PLAN.md updated. Build b1bd5a37641a478f exit 0: fmt, diff check, all-target Clippy -D warnings, four binaries. Initial 15/15 native OAuth integration PASS, including automated setup/browser opener argument capture and paired approval, real native read, restart/revoke, no raw bearer, no default state adoption, refusal of unsafe/duplicate/missing state. Final test build 6e27107363c44b77 exit 0; logs ~/.local/state/chatgpt-local-coder/jobs/{b1bd5a37641a478f,6e27107363c44b77}.log. Ordinary UID1000 process mwxjk3w5-ercchs exit 0, ../verify-onboarding-final.py and ../oauth-onboarding-final.log record 203/203 Rust, 54/54 focused integrations (15 native OAuth, 6 connector OAuth HTTP, 2 connector preview, 2 connector persistence, 2 direct boundary, 2 header hardening, 16 Linux, 9 product), existing first-run real-browser pairing and dashboard keyboard/tab probe PASS, 28/28 locked pins intact. Full locked acceptance suite not rerun. No new dependencies, version bump, production installation, service restart, route changes or production grant changes.

Candidate public-connector.b64EhS58/source, base 66995f1, uncommitted. Local onboarding is complete for isolated read-only preview; actual web-client onboarding is still blocked by broader capability review, blocking persistence isolation, tunnel provider integration and cloud interoperability. No official plugin or public connector URL created. See DIRECT_REMOTE_PLAN.md.

## Direct remote MCP — local dashboard and CLI OAuth consent PASS / public activation HOLD (2026-11-26)

Added local OAuth connections dashboard tab, exact binding inspection and explicit approve/deny/revoke UI, and Linux `veyl oauth list|inspect|approve|deny|revoke --listen 127.0.0.1:PORT --config ABSOLUTE_POLICY`. Both new interfaces use existing one-use dashboard pairing/session/CSRF controls, exact local admin Origin, singleton CSRF and cookie validation, strict bounded JSON, no query/forwarding markers. Native policy read lock held through consent transaction; approval revalidates live policy/root/audit. Denial and revocation remain possible after policy becomes ineligible. No mode or grants created. CLI auto-pairs using explicit preview config, accepts operation details over stdin and signs out. New CLI pairing supersedes an outstanding unredeemed pairing code, consistent with existing pairing semantics. UI uses textContent for unverified names, clears review on input change/logout and confirms exact ID/callback/resource/native client. Disabled on normal gateway startup; public MCP cannot access admin OAuth endpoint. Legacy separate bearer operator fixture endpoints remain isolated and must be consolidated/retired before public exposure.

Implementation in src/http_common/oauth_http.rs, src/http/oauth.rs, src/http/dashboard.rs, dashboard/index.html and app.js, src/oauth_cli.rs and Linux CLI dispatch. Initial build 535b0c2c573e4b3a exit 0; initial integration found a test expected 404 where public Origin enforcement returns 403; corrected test and added no-Origin 404 assertion. Second 11/11 native and 12/12 with real disposable Brave browser PASS. Final build a4f270c6d8a0419b exit 0 (log ~/.local/state/chatgpt-local-coder/jobs/a4f270c6d8a0419b.log), fmt, JS syntax, all-target Clippy -D warnings, nine test binaries and all four debug executables. Final ordinary UID1000 process mwxj8zol-jr5r4p exit 0; ../oauth-consent-final.log and ../verify-consent-final.py record 203/203 Rust and 52/52 focused integration tests (13 native OAuth including real browser, 6 connector OAuth HTTP, 2 connector preview, 2 connector persistence, 2 direct boundary, 2 header hardening, 16 Linux, 9 product); 28/28 locked pins unchanged and diff check. New tests cover local pairing/CSRF, exact binding, denied cross-origin/proxy/duplicate headers, policy change, CLI confirmation, real browser cancel/approve/deny/revoke/logout and untrusted names, durable revoke and default-disabled behavior. Full locked suite not rerun. Production inspected active PID 203133 NRestarts=0; no new dependencies, version bump, installation, service/tunnel changes or grants.

Candidate public-connector.b64EhS58/source, base 66995f1, uncommitted. Next expand native OAuth tool capability admission incrementally under existing per-client grants and modes, with negative controls and policy/session invalidation; consolidate fixture operator paths and move blocking persistence off async loop before cloud-client/tunnel acceptance. See DIRECT_REMOTE_PLAN.md.

## Direct remote MCP — durable native OAuth PASS / public activation HOLD (2026-11-26)

Added src/core/oauth/persistence.rs and src/http_common/oauth_http/durable.rs, owner-private native oauth-state.json support in src/platform/private_store.rs, and opt-in state_dir/initialize_state stdin fields in src/http/oauth.rs. No implicit initialization or overwrite. Persistent active families retain only SHA-256 digests, exact registered resource/client/redirect binding, absolute expiry and spent refresh history; pending consent, unredeemed codes, browser state, raw credentials and MCP sessions remain volatile. Restart restores unexpired access/refresh families, not expired access or family TTL. Revocation and invalid-grant replay removal persist. Native binding uses exact policy digest/path, native client and root device/inode; changes deny live calls and mismatched recovery. Requires isolated state dir, one pre-existing Standard read-only client and no jobs; prior volatile native and connector registration-only modes remain compatible.

State changes use durable interrupted-intent publication followed by atomic commit with the bounded last 2048 lifecycle receipts (operation/status/time/sequence and resolved client ID). Dirty or malformed state refuses startup; storage failures latch denial. Recovery after a dirty intent requires fresh explicit state and approval, not replaying a previous snapshot. Clock rollback before saved time rejected; detected >2s wall/monotonic discrepancy fails closed, restart uses absolute deadlines. Checksum is corruption detection, not defense against arbitrary same-UID rewriting/rollback. Native tool admission still separately requires existing audit ledger. Blocking fsync under preview state lock and bounded audit retention are intentional development limitations; no production exposure before moving persistence off the async loop, reviewing audit/recovery behavior and interoperability.

Initial build bebc58e3670645b3 exit 0, 31 library tests, all-target Clippy and bins. Initial normal-process tracker lost; checked no remaining process. Attempt via system_job 7e151769cb5e4e28 failed because NoNewPrivileges service context rejects native root fixture; not a candidate pass. Reran using ordinary UID1000 process mwxih3qs-h1ub4f, durable-oauth-http-initial.log records 7 native + 6 HTTP connector tests exit 0. Final build d7c695776b534043 exit 0, log ~/.local/state/chatgpt-local-coder/jobs/d7c695776b534043.log: formatting, all-target Clippy warnings denied, nine test executables and four debug bins. Final ordinary process mwxin0nr-j0ixyc exit 0; ../durable-oauth-final.log and ../verify-durable-final.py record strict totals 203/203 Rust and 47/47 integrations (8 native OAuth, 6 HTTP OAuth, 2 connector preview, 2 connector persistence, 2 direct boundary, 2 header hardening, 16 Linux, 9 product), 28/28 locked pins and diff check. Native tests include abrupt termination after acknowledged rotation, replay/revocation persistence, pending/session loss, valid receipt history/no raw secrets, dirty intent, corruption and write-failure latch, policy/credential/root replacement denial and no implicit reset; core tests include synthetic expiry, rollback, duplicate digest and code replay. Full locked suite not rerun. Production 0.5.0-beta PID 203133 active NRestarts=0 at inspection; no dependency, version, install, grant, tunnel or release changes.

Candidate public-connector.b64EhS58/source, base 66995f1, uncommitted. Next: authenticated local dashboard and CLI consent with CSRF and exact client/redirect confirmation, then broaden native capabilities under existing policy, test actual web-client flow and only then tunnel providers. See DIRECT_REMOTE_PLAN.md.

## Direct remote MCP — native read-only OAuth integration PASS / public activation HOLD (2026-11-26)

Moved shared HTTP authorization server to src/http_common/oauth_http.rs and private descriptor-relative store to src/platform/private_store.rs; existing connector preview CLI and durable registration behavior preserved. Added src/http/oauth.rs and explicit Linux-only `http --oauth-preview-origin https://node.example:8443` fixture mode. Requires both loopback listener ports ephemeral, no tailnet settings, reserved .example origin, pre-existing Standard read-only client with no extra roots, distinct operator bearer, available native audit ledger. Dedicated MCP listener in this mode uses OAuth only; local operator endpoints remain separate on admin listener. No mode/grant creation or widening.

Actual native read_file dispatch now works. Session scope includes stable per-authorization grant-family identity, surviving refresh but rejecting separate families even with same OAuth registration and native client. Live native policy (identity, credential verifier, root, expiry, mode, grants) and OAuth bearer revalidated at admission and blocking worker. Native audit intent/success required at each admission; detached ledger causes 503 before further reads. Native preview still volatile; registration persistence remains connector-only. No durable OAuth token family recovery, durable OAuth transition audit, dashboard consent UI, real cloud-client interoperability, or new public tunnel.

Final build 9c3ba2290d484f35 exit 0, log ~/.local/state/chatgpt-local-coder/jobs/9c3ba2290d484f35.log: fmt, warning-denied all-target Clippy, nine Rust test executables and four debug binaries. Final process mwxi3f5b-53tkk7 exit 0: 200/200 Rust, zero ignored/failed, 43/43 focused integration (4 native OAuth, 6 OAuth HTTP, 2 connector preview, 2 connector persistence, 2 direct boundary, 2 header hardening, 16 Linux, 9 product). Native positive real scoped file read plus traversal/symlink/write denial, cross-family session denial, refresh/replay/revoke, live native credential change, distinct operator secret, startup guards, detached audit ledger rejection. Initial Rust guard-borrow and Clippy errors corrected; initial fixture rejected overlapping audit/client root, fixture corrected without relaxing policy. Full locked acceptance battery not rerun; 28 original pins verified unchanged before final tests. Production remained PID 203133, active, NRestarts=0 at pretest inspection. No new dependency, version bump, deployment, tunnel change or grant change.

Candidate public-connector.b64EhS58/source, base 66995f1, uncommitted. Next implement durable owner-private hashed token-family state/replay recovery and OAuth lifecycle audit, then authenticated dashboard/CLI approval and reviewed broader tool capabilities. Keep native preview isolated and production unchanged. See DIRECT_REMOTE_PLAN.md.

## Direct remote MCP — HTTP OAuth preview + durable registration PASS / native admission HOLD (2026-11-26)

Added Linux-only explicit foreground `veyl-connector oauth-preview PORT ADMIN_PORT HTTPS_ORIGIN [PRIVATE_STATE_DIR]` and `oauth-state-init DIR HTTPS_ORIGIN`. Two loopback listeners: exact public-facing OAuth discovery, DCR, authorization/code or access_denied callback, token exchange/rotation, admission check; separate bearer-authenticated local inspect/approve/deny/revoke endpoints. Strict JSON/form duplicate and malformed input rejection, exact Host, no Origin/proxy trust, bounded bodies/connections/rate budgets, no-store/referrer/CSP headers, fixed diagnostic labels. Fixture client label is NOT a native grant. Valid OAuth access reaches deliberate 503 at /mcp; no actual MCP execution or public TLS/tunnel enabled.

Registration v1 snapshot persists client IDs, names, HTTPS redirects and exact resource in separate canonical owner-private oauth-registry.json. Reused Store descriptor-relative opening, exclusive directory lock, mode 0600/single-link check, atomic fsync and readback; no token or consent handle stored on disk. Revocation persists across restarts; all token families intentionally invalidated on restart. External state modification detected on next registration/revocation mutation latches failure; startup rejects unsafe, malformed, noncanonical or wrong-origin state. Active token persistence and durable security audit still pending. First HTTP test run found case-sensitive test header lookup and incorrect duplicate-approval status; corrected both. Added standard access_denied callback and safe state encoding.

Final build job 1ab4465d7599492d exit 0, ~/.local/state/chatgpt-local-coder/jobs/1ab4465d7599492d.log: fmt, all-target Clippy -D warnings, nine Rust test binaries, four debug executables. Final ordinary UID1000 process mwxhgh9p-v0a9tp captured 200/200 Rust (zero ignored/failed) and complete six OAuth HTTP + two connector preview + two connector persistence + two direct boundary + two HTTP hardening cases. Tracking record lost during Linux integration; verified no surviving process before rerunning only Linux and product suites (mwxhhja2-2jj0am exit 0, 16/16 + 9/9). Total final focused integration 39/39; full locked battery not rerun, all 28 locked hashes verified unchanged (mwxheqgr-8olxwe). Existing production active PID 203133 NRestarts=0. No new dependency this checkpoint, version bump, installation, service/tunnel change or release.

Next: extract preview handlers into shared HTTP auth adapter, wire live native admission and per-OAuth-grant MCP session identity/revalidation, authenticated dashboard/CLI approval, durable hashed token families and audit; prove actual native tool calls and revocation/reconnect before any tunnel. Candidate remains public-connector.b64EhS58/source, base 66995f1, uncommitted. See DIRECT_REMOTE_PLAN.md.

## Direct remote MCP — OAuth domain checkpoint PASS / public activation HOLD (2026-11-26)

Operator changed priority to self-hosted direct OAuth and tunnel first, hosted connector last. See DIRECT_REMOTE_PLAN.md; PUBLIC_CONNECTOR_PLAN.md retained as deferred alternative. Existing loopback MCP, separate dashboard, bounded admission, audit and owned Funnel routing already meet the transport baseline; no rewrite or new public route.

Added src/core/oauth.rs: bounded in-memory S256 authorization-code lifecycle, explicit local approval/denial transition, exact client/redirect/resource binding, one-use codes, hashed access/refresh tokens, rotation, replay-family invalidation, per-native-client revocation and expiry/capacity. Added src/http_common/oauth.rs: explicit HTTPS origin, exact route allowlist, metadata/challenge construction, bounded public-client registration, exact callback and resource matching, fixed mcp scope, local registration revocation. HTTP-specific URI parsing stays outside portable core. Added only cached base64 0.22.1 to manifest/lock. No version bump. Preview defaults: 5 min pending, 60 s code, 15 min access, 24 h fixed family, 128 entries, 256 rotations; not final production settings. Strict HTTPS DNS callback subset, no callback query, no CIMD or confidential registration. Current objects are not wired to live handlers and do not authorize tools. Storage is in memory and restart invalidates grants; persistent mode/grant policy remains unchanged.

Direct BridgeDev build d2489e5c2bae4e75 exit 0, log ~/.local/state/chatgpt-local-coder/jobs/d2489e5c2bae4e75.log: fmt, all-target Clippy -D warnings, all nine Rust test binaries compiled and four debug executable builds passed offline/locked. Initial OAuth core run 23/23 (8 new); registry run 28/28 (5 additional) before two Clippy findings (collapsible if and argument count), corrected with let chain and typed AuthorizationParameters. Final ordinary UID 1000 process mwxgnstu-5n3pra exit 0: all 199 Rust tests (13 new, zero ignored/failed) and 31/31 focused Python cases (2 direct boundary, 2 header hardening, 16 Linux, 9 product, 2 connector preview). New boundary test uses disposable dedicated and shared Funnel fixtures and confirms incomplete OAuth routes and public dashboard are rejected, existing bearer handshake works. 28/28 original locked hashes verified; full 287 locked cases not rerun on this development checkpoint. No production restart, tunnel alteration, app update, package publication or grant change.

Candidate ~/.local/share/veyl-development/candidates/public-connector.b64EhS58/source, base 66995f1, uncommitted. Next gate: implement HTTP parsing/handlers, authenticated local approval, durable owner-private state/audit and live policy admission in disposable instances, then test real OAuth web client interoperability. No OAuth public exposure before complete end-to-end security acceptance. Existing 0.5.0-beta remains deployed.

## 0.5.0-beta — LINUX DEPLOYED AND PUBLISHED (2026-11-26)

Operator explicitly authorized direct BridgeDev acceptance and release without another AGY run. Exact release commit `a3a8df21259510844fcab93d4ea1364ad883fcd6` matches the 178-file hardened source manifest; GitHub tag v0.5.0-beta resolves to that commit. All six prerelease assets match GitHub SHA-256 digests. Both prior Low findings fixed. Cargo publish --locked -j 1 completed (job ec9d6d9fac504f82 exit 0); cargo info independently downloaded veyl 0.5.0-beta. Downloaded crate embeds the exact release commit and all 152 non-generated/non-normalized files match the candidate source; archive SHA-256 c410a680e984f4b64680fc065b81ab16298539bfa2b175bf20ab9664e4e4a167. Direct crates API returned 403, so verification used Cargo's downloaded archive instead.

Exact hardened candidate: fmt, warning-denied all-target Clippy, 186/186 Rust cases, 287/287 locked cases across all 28 unchanged pins plus 6/6 three-mode, 48/48 focused integration, JS syntax, updater lifecycle (including active-job block, interrupted recovery and broken-service rollback), isolated systemd lifecycle all PASS. Direct strict locked runner rejects skips/expected failures; Python group 264 cases (includes six modes), build-dependent group 29. Fresh test-hooks binary used only for locked audit chain. Rust acceptance process mwxdweg3-twjx2p exit 0; locked groups mwxdw0cb-bagem4 and mwxdwu92-ntmf1e exit 0; integration mwxdxavo-s28jw3 exit 0; corrected systemd lifecycle mwxdykhf-9zgikb exit 0. Initial acceptance tracker was lost during compile; recovered compilation job b72c42357eba4088 exit 0; corrected legacy fixture binary path and systemd script argument without modifying source or locked tests. Previous AGY report is for the earlier checkpoint 3 candidate, not independent certification of these hardening changes.

Local native updater succeeded (mwxe0i88-k21omh), all three managed binaries in both ~/.local/bin and ~/.cargo/bin equal the optimized release; running gateway PID 203133, active, NRestarts=0; exact original policy checksum unchanged; updater blocked active jobs by design and retained rollback bundle ~/.veyl-update-backups/4e2d594df03b0c710497bf8ca2c69ec8. Existing live MCP service_status and system_info passed. Artifacts, locked receipts, source manifest, optimized binaries, published crate and build/publish logs in ~/.local/share/veyl-development/artifacts/a3a8df2/. No grant widening or connector service installation.

Linux x86_64 beta only. Native Android/Termux 0.5.0-beta remains unverified (Waydroid stopped, ADB absent), and Windows remains unverified/fail-closed. Connector is optional foreground preview, not automatically installed by managed updater. These limits are explicit in the GitHub release notes. No fresh AGY acceptance requested by operator. Previous HOLD sections are historical and superseded for the Linux release.

## 0.5.0-beta checkpoint 3 hardening — focused PASS / release HOLD (2026-11-26)

AGY accepted the previous Linux candidate (184 Rust, 287 locked, 6 mode, 46 focused integration cases) with two Low findings; BridgeDev verified the prior source and four optimized binary hashes, reran 37 cases, reproduced duplicate Authorization (200/401 depending on order) and confirmed the dashboard collision defect. Operator requested both fixes. This separate detached worktree was copied from all 177 verified files of platform-foundation.l7Ge9o1L, preserving the original source/archive/binaries.

Linux HTTP now uses shared exact-singleton header parsing for Authorization, Content-Type, Mcp-Session-Id and Mcp-Protocol-Version; duplicate credentials pass through existing denial/rate-limit handling, duplicate session/version return 400 and duplicate content type returns 415. Public proof, admission order, body limits and policy revalidation remain unchanged. Dashboard rejects a live session ID collision under its mutex before pairing-code redemption. The deterministic test forces a collision, asserts no redemption or cookie and unchanged existing session, and confirms fresh-ID success. No new dependency, grant, version bump or native feature expansion.

New tests/http_header_hardening.py failed against original optimized binary (four assertion failures, expected negative control mwxd2pk2-hecqe4). Hardened optimized four-binary build, fmt and all-target Clippy -D warnings passed (job 7280bd4c47234a62, exit 0). Forced dashboard collision test passed (job 5d1a327497f04add, exit 0). Optimized integration 29/29 (2 new header, 16 Linux, 9 product, 2 connector preview; mwxd7jvw-doz7wq exit 0); 24/24 locked HTTP/mode tests and all 28 pins verified (mwxd7r24-byi3ze exit 0). Total focused checks 54/54. Original manifest remained intact. No full 287-case rerun on the hardened candidate yet.

Candidate: ~/.local/share/veyl-development/candidates/checkpoint3-hardening/source. Optimized bundle ../release-0.5.0-beta/SHA256SUMS, source manifest ../SOURCE_SHA256SUMS-0.5.0-beta and archive ../veyl-0.5.0-beta-source.tar.gz. Durable build/test logs ~/.local/state/chatgpt-local-coder/jobs/{7280bd4c47234a62,5d1a327497f04add}.log. AGY must independently verify this new exact candidate (including mutation sensitivity, full locked battery, updated Rust test counts and native Android). Android was unavailable at prior verification; no guest changes. Production 0.4.0-beta remains active; no promotion, install, commit or publication.

## 0.5.0-beta architecture checkpoint 3 — implementation PASS / release HOLD (2026-11-26)

Operator explicitly requested direct BridgeDev implementation, no Codex, and will request AGY independent acceptance. Shared session/HTTP primitives, audit phase/action, job state/exit reason, activity records, TimeShift checkpoint IDs and typed preview regions now have actual Linux/Android/connector consumers. See ARCHITECTURE.md. Linux public/private scope and old ID lengths remain unchanged; collisions fail closed. Linux admission, native job/audit/TimeShift storage and enforcement, Android guarded journal, connector role/replay checks remain adapter-owned. No new dependencies, grants, platform execution claims or service. Manifest/lock version 0.5.0-beta; optional fourth connector binary, existing updater manages original three. README documents this distinction.

Direct verification under UID 1000: format/diff check, all-target Clippy -D warnings and 184/184 Rust cases (15 library, 67 each gateway entrypoint, 11 monitor, 3 parity, 11 operator, 6 onboarding, 4 mutation) passed, no ignores/failures, process mwxbuj7s-3sq6b0. Exact versioned debug binaries report 0.5.0-beta. Focused integration 46/46 across Linux features 16, product 9, activity 3, workspace jobs 3, TimeShift 9, connector preview 2, connector persistence 2 and platform probe 2 across processes mwxbxbjf-8lv69d, mwxbyfrw-tjkfw7, mwxbz3fe-xvo47r. Two repository-owned fixture corrections: tool-name source path moved to core/tools.rs (68/81/84 inventory assertions unchanged), native connector runtime version expectation now reads Cargo.toml (old replay message retained). Initial TimeShift fixture failures and stale 0.4.0-beta expectation reproduced before correction. No locked suite or pin modified. Previous checkpoint's tests also passed but are not substituted for versioned acceptance.

Initial shared-cache build linked old library metadata; isolated target ../target-architecture3 solved it without cache deletion. Restricted system_job caused connector persistence fixture filesystem denials; ordinary unprivileged start_process rerun passed. Volatile release build tracker mwxbuj7s-3sq6b0 was lost after all Rust tests passed; checked no cargo/rustc process and no release binaries before recoverable retry. Optimized build/staging job 294162ea8eaa4389, log ~/.local/state/chatgpt-local-coder/jobs/294162ea8eaa4389.log, expected ../release-0.5.0-beta/{veyl,mcp-gateway,veyl-monitor,veyl-connector,SHA256SUMS}; check status and hashes before use, not yet certified. Source manifest ../SOURCE_SHA256SUMS-0.5.0-beta and archive ../veyl-0.5.0-beta-source.tar.gz to be generated after this documentation update.

Waydroid session STOPPED, no ADB devices; no new native Android build, no guest changes. Prior native architecture2 binaries preserved. AGY must independently verify exact source manifest, all 28 locked pins and 287 cases + six mode cases, security negatives, optimized integration and lifecycle, native Android when available. No commit, promotion, install, publication, production restart or grant change. Windows, public connector hosting and Android feature expansion remain paused.

## Architecture checkpoint 2 — native and host PASS / release HOLD (2026-11-26 IST)

Operator approved continuing toward 0.5.0-beta. Fixed AGY's stale repository-owned TUI test (command/target, d JSON toggle, reverse toggle, mouse/keyboard); focused original release test reproduced before fix and passed after. Extracted unchanged Linux 71-tool metadata into src/core/tools.rs, Action/ExecutionMode into src/core/capability.rs, typed private-workspace tools/grants/read argument contract into src/core/workspace.rs. Linux policy enforcement and native mutations remain separate. Gated Linux legacy file/tools modules and their tests to Linux, Android HTTP directly consumes shared Session; no lint suppression or new grants. See ARCHITECTURE.md. Initial Android-only refactor syntax error fixed before native build.

Host all-target warning-denied Clippy, 8 library tests and 67 gateway tests passed (mwx046ty-wgz2nf exit 0). Android ordinary Termux UID: cargo rustc --offline --locked --bin {veyl,mcp-gateway,veyl-connector} -- -D warnings all passed; native lib 8/8, stdio 2/2, HTTP 5/5, connector 2/2 passed (mwx067ys-yw6sne, native receipt ../native-receipts/architecture2-build.log). Exact guest directory ~/veyl-termux-architecture2/bin; hashes veyl b80781dba93f4fa5fc9e0a6653e8caf446ed89b6b90e879f26f9d5aaaf2c0435, gateway 692194bdefc16bddb4b3a9eb0c2628737d8c46b6faa7d2fec091a810d0017fe6, connector 368070d526c421a1db773fcf8a414ef2bd4ca5edb3fd97cfe40e81ee8a598626. Archive 01aaec044a9953d99893458fa10813860b3ba8f880ab00400003a6f705b9cb65, 173 source files. Native Clippy itself not run; compiler warnings denied. ADB reverse removed.

Fresh Linux four debug binaries built, staged and checksum-verified in ../architecture2-preview-bin (recoverable build ab4e19db7d7b4c95 exit 0, log ~/.local/state/chatgpt-local-coder/jobs/ab4e19db7d7b4c95.log; earlier volatile process record lost, confirmed no build running before retry). Against exact new binaries: Linux features 16/16, product 9/9, connector preview 2/2, persistence 2/2, platform probe 2/2, locked three modes 6/6 passed (mwx09ich-ztd4nm exit 0). No locked test/pin changed. Full 287 locked cases, release optimization, native cross-device reconnect and independent AGY rerun pending for this checkpoint. Version remains 0.4.0-beta in source pending completion. Remaining: common HTTP/session admission, portable audit/jobs/TimeShift/UI contracts, release packaging/update lifecycle and full acceptance. No deployment, GitHub push, crate publication, root or permission change. Android/Windows feature development and public plugin hosting paused. Prior verified builds retained.


## Architecture migration checkpoint 1 — host PASS / HOLD (2026-11-26 IST)

Operator paused Android feature expansion and plugin work to establish one modular architecture. See [ARCHITECTURE.md](ARCHITECTURE.md) for dependency direction, actual layout, compatibility contracts and staged remaining migration. Extracted portable MCP session lifecycle and dispatch into src/core/protocol.rs; Linux and Android gateway adapters and standalone connector now consume this shared implementation, alongside shared credentials. Kept legacy gateway tool callbacks and Linux state/policy enforcement intact. Linux CLI native routing moved to src/platform/linux/cli.rs; Android HTTP moved to src/platform/android/http.rs; connector code moved into src/connector/{mod,agent,store}.rs with thin binary entry point. No new dependencies, package split, version bump, permission expansion or public route. Connector now requires complete MCP initialize parameters (capabilities and clientInfo), consistent with gateway. Preserve existing native7/native8 guest binaries and production.

Host all-target Clippy -D warnings and fmt passed (mwwyyvu8-6uxhul; later test/build process record was lost, so actual idle state checked before bounded rerun). Library 6/6, gateway 67/67, debug builds passed (mwwz0ur2-flcvqz exit 0); connector preview 2/2, persistence 2/2, platform probe 2/2 and Linux product 9/9 passed (mwwz1fcw-kr4n4n exit 0). Exact binaries ../architecture-preview-bin/mcp-gateway SHA256 9d044f637a4d9a397920aa35e2a67b57d3953d7cada3344b7a60df28eb30da08 and veyl-connector SHA256 2c7255f3c6bc5e8cd19abcc16fcbe48ac3b84fe14d0219edc5784b5b64ff5bec. Initial unused-import and redundant-closure lint defects corrected. Native Android compile/regressions and full independently locked Linux suite not rerun for this refactor yet; no completion or parity claim. Next: shared authorization/capability contracts, connector domain/transport separation, job/audit lifecycle boundaries, then native regression and operator review. Android/Windows feature work and hosting paused.


## Separate connector pairing checkpoint — native8 PASS / HOLD (2026-11-26 IST)

Operator requested continuation toward separate plugin. Added Linux-only persistent connector registry (src/bin/connector/store.rs): explicit owned mode-0700 directory, descriptor-relative openat2, exclusive state flock, owned singly-linked mode-0600 registry, bounded JSON, synced staged snapshots, no-clobber initialization, atomic replacement, fail-closed uncertain persistence. Local state-init/state-pair/state-revoke commands, explicit account-to-device mapping; revocation requires stopping the connector first. Persist last accepted heartbeat sequence before acknowledgment, restore counters but not online sessions at restart. New cross-platform foreground heartbeat client (src/bin/connector/agent.rs) reads token on stdin, retrieves current sequence from authenticated device-only endpoint, reports compiled native OS/runtime version, bounded request/response and 10-second deadline. Still loopback-only; no arbitrary forwarding, shell, root, background agent, OAuth, public endpoint, user-facing pairing codes or cloud account integration. Registry provisioning uses local operator-supplied verifier hashes, not consumer self-service pairing. Existing gateway and native7 unaffected.

Linux preview regression 2/2, persistent registry integration 2/2, connector-only Clippy/fmt/build passed (mwwyo2bx-ylg1f8, mwwyoo0u-fmxl62 exit 0). Real Termux x86_64 native connector build passed, SHA256 9633b9a74b50a5182a069cdf70b2cfb632f2eefe615ad078ce9ce96f9a60a8ff (guest ~/veyl-connector-native8/bin/veyl-connector). Linux candidate ../connector-pairing-bin/veyl-connector SHA256 0201beb4418cf5324460f15afd63cd34e0b3670c80a78600e87b1d8a0f1aa80a. Real Android-to-Linux authenticated heartbeat, restart and reconnect with persistent sequences 1 then 2 passed (mwwyr9ev-774d3y exit 0); isolated test owner/device, temporary ADB reverse and disposable credentials only, both forwarding rules removed and test server stopped. Initial process handle lost after BridgeDev/ADB interruption; inspected actual guest build receipt and reconnected instead of rebuilding blindly. Native8 source archive and manifest retained. Same-UID interference outside threat model; no durable audit/migration/recovery protocol for connector yet. No full locked battery or ARM64/Windows tests. Plugin hosting still unavailable; no fake endpoint, account plugin, public route, production restart or publication. Next: operator preview, stable HTTPS hosting, review-compatible OAuth and real account pairing, then separate private ChatGPT plugin creation and mobile smoke. Windows paused.


## Separate Veyl Connector preview — local PASS / plugin registration BLOCKED (2026-11-26 IST)

Operator requested a separate plugin first. Added standalone experimental binary src/bin/veyl-connector.rs, independent of the existing local gateway, reusing shared credential verification. Connector preview binds only 127.0.0.1, accepts a bounded disposable registry over stdin (separate account/device verifier hashes and explicit owner mapping), authenticates both roles independently, accepts typed version-1 device heartbeats with monotonically increasing sequences, and exposes a stable MCP catalog of list_devices and device_health. No file access, execution, arbitrary URL relay or permission changes. Device visibility and MCP session ownership are account-scoped, no online assertion before a valid heartbeat, 30-second heartbeat freshness, 30-minute idle sessions, bounded requests/connections. In-memory heartbeat/session state; no durable pairing, OAuth, real device agent, public route or cross-restart replay protection yet. API version separate from native runtime version. Tests simulate device agents using two independent HTTP clients, not actual paired hardware.

Host connector build, warning-denied Clippy, formatting and 2/2 HTTP integration cases passed (mwwyd6l8-jy4wm6 and mwwydp5v-4ka7d5 exit 0); covered authentication role separation, cross-tenant device/session denials, offline initial status, incompatible API/replayed sequence rejection, malicious Host/Origin, oversized messages, unsupported command denial and stable tool schemas after simulated runtime update. Exact debug binary ../connector-preview-bin/veyl-connector SHA256 7a69d73822c7fab3a60b4de2f82cdaaa6ba781970d7d8b81ea09ab431aec1556. Test command: python3 -B tests/connector_preview.py ../connector-preview-bin/veyl-connector -v. Local preview only; protocol duplication must be reconciled with shared protocol before production. Plugin creator can create a private package but cannot host the new endpoint; Sites backend unavailable. No fictitious endpoint, placeholder account plugin, public exposure or marketplace submission performed. Next: stable hosted HTTPS + OAuth and actual outbound native device pairing, then private plugin registration and mobile verification. Existing Linux production PID 76586 unchanged, no version bump or promotion; native7 preserved. Full locked battery and native compilation of new connector binary not run. Windows paused.


## Shared core extraction 1 — native7 PASS / HOLD (2026-11-26 IST)

Operator personally verified native6 HTTP 5/5 and requests stable mobile marketplace plugin and one common core for all OSes. Design recorded in [SHARED_CORE.md](SHARED_CORE.md). Extracted shared credential token validation, SHA-256 verifier decode/digest and constant-time all-verifier selection in src/core/credential.rs; Linux and Android admission use it, preserving existing on-disk format, local grants, Linux expiry and Android enabled semantics. Ambiguous active matches now fail closed. No new dependency, no permissions/endpoint migration. Host library 5/5, gateway 67/67, all-target Clippy/fmt passed (mwwy2rzc-v6pqxr exit 0). Actual Termux native7 compilation, 2/2 stdio, 5/5 HTTP, 5/5 library tests passed (mwwy4iua-q38dyj exit 0). Guest source ~/veyl-termux-native7, exact bin/veyl SHA256 84747b04fac32ca445b52e02e2ed97e4e281e75c8f653b39274b1139e4d91793, bin/mcp-gateway 2e784b1d3f5da7ceabea0b0cc1ea0dbfcc05ab63eda731a4c912b1f2040829c3. Source archive 47a9b17e0b7b5468b1d41bc2f577d0c023589ba183d1375e6f3132ebb09656ac, manifest ../SOURCE_SHA256SUMS-core1. Prior personally verified native6 remains in its own bin directory. Six existing Android warnings, no full locked battery rerun. Marketplace relay/pairing, OAuth, approved mobile connector, full shared policy/job/UI extraction not implemented. Public listing eligibility unconfirmed; review-compatible narrow catalog and isolated demo proposed, not direct exposure of private admin gateway. No public endpoint, root change, Linux production restart, version bump, push, or publication. Windows remains paused.


## Android native6 audited text mutation — PASS / HOLD (2026-11-26 IST)

Operator personally ran native5 stdio 2/2 and HTTP 4/4 (screenshots), now requests Android connector and execution; logged into ChatGPT in Waydroid. Native6 adds explicit HTTP write_file and apply_patch grants, exclusive creation with null expected_sha256, guarded replacement with exact prior SHA-256, and unique literal replacement. Private descriptor-relative paths, no hidden mutation targets, symlink/hardlink and mount checks; bounded UTF-8, staged sync, exclusive link publication for new files and rename for existing files, directory sync. Per-client private intent/outcome records persist operation IDs, hashes, metadata without raw contents/tokens, maximum 128 pairs, fail closed on malformed, unpaired or uncertain records. No automatic eviction or recovery CLI. State lock excludes a second server or CLI add-client during service. Audit is not a signed/hash-chain ledger, and same-UID external races remain out of scope. Existing read-only clients do not gain grants; older state requires separate explicit audit setup for new write clients. No command execution, job sandbox, root, public routing, or remote ChatGPT endpoint added; YOLO/FULL must not imply automatic root (existing permission contract).

Host all-target cargo check, formatting and source integrity passed (mwwxqd66-wc3f65); native Android/Bionic compilation and stdio 2/2 + HTTP 5/5 passed (mwwxrmux-q11211 exit 0). New test covers positive exclusive creation, guarded patch/replace, stale hash, path escape, symlink/hardlink, client denial, durable audit after restart, orphan fail-closed and competing server denial. Six existing dead-code warnings per bin; no new locked Linux suite, full Clippy or Android ARM64 acceptance. Exact native6 archive SHA256 df4d82149c9fbb21e3fbbc8edcae8f449989f8fa79ad279d8dcbfd5641a0b803. Guest ~/veyl-termux-native6/bin/{veyl,mcp-gateway}, hashes 8214056784276d4d521d14237935b082cf1c7bffe2ca7de0a6f23f353ad10069 and 21fd562d51569a36053c531689522f3752fe18a0a73c0c4109f136be8fa9496d respectively. Prior native5 preserved in ~/veyl-termux-native5/verified-bin. Source ../SOURCE_SHA256SUMS-native6; guest log /sdcard/Download/veyl-termux-native6-build.log. No Linux production or published release change. Next: Android worker isolation and separately authenticated HTTPS remote connector, actual mobile smoke before enabling broader permissions. Windows paused.


## Android authenticated loopback MCP — native5 PASS / HOLD (2026-11-26 IST)

Implemented Android-only foreground HTTP transport (src/android_http.rs), explicit operator-created private state and per-client private workspace/grant files. New CLI: android-init veyl-android-NAME; android-add-client STATE CLIENT TOOL[,TOOL]; android-serve STATE PORT. Credentials are random 256-bit bearer tokens displayed only by local client-add; stored as SHA-256 hashes in owned 0600 singly-linked files. State/workspaces are private directories. Policy is loaded at startup; local changes require restart, not dynamic reload. No silent grants, no public bind, no Linux mode parity. Session IDs random and owner-bound, 32 sessions max with 30-minute idle expiry, 16 concurrent connections, 10-second connection deadline, 64 KiB HTTP request body bound. Exact loopback Host and no Origin required; POST JSON and DELETE sessions; SSE, OAuth, TLS, public routing and external MCP not yet accepted. Existing native descriptor reader reused. Local policy files are exclusively created and synced; interrupted partial creation fails closed, no atomic policy-update/recovery CLI yet. Same-UID local interference remains outside the threat model. No durable audit or mutations/jobs.

Host fmt, all-target Clippy and 3/3 reader unit tests passed (mwwk0psn-odunhc). Native4 built both binaries and passed 2/2 stdio plus 3/4 HTTP tests; fourth failed only because Android Python lacks os.link. Native5 changed only that new test fixture to actual Termux ln plus nlink==2 assertion; 4/4 native HTTP tests and 2/2 stdio passed (mwwk39ko-6pdye7), gateway SHA256 c8fe3f1bcc489d3f6c38dddd63ed5327754598b01d327a44b30cd5b92dc74556. Exact source archive SHA256 e8aee8c64c1379aa8377e44e044e1a7927153193344f603a2dbb1ac8b87d2f42, guest ~/veyl-termux-native5, build cache ~/veyl-termux-native/target/debug/. Source manifest ../SOURCE_SHA256SUMS-native5. Prior native 3/3 security tests passed before HTTP addition; no fresh native lib suite or full Linux locked rerun for this narrow checkpoint. Six existing native dead-code warnings per binary. Test servers stopped and disposable test states cleaned, temporary ADB reverse removed. ChatGPT login not necessary for local tests; actual remote connector/Tailscale and ARM64 acceptance pending. No public route, root changes, Linux production upgrade, version bump, push or release. Next: operator personal preview; then audited mutations and remote transport acceptance in separate gates. Windows remains paused.


## Android native first build — PASS / HOLD (2026-11-26 IST)

Waydroid ADB authorized at 192.168.240.112:5555, Android 13 API 33 x86_64, Termux app UID 10156 (non-root). Operator provided native Rust/Cargo 1.96.0, Clang 21.1.8 targeting Android API 30, Python 3.13.13. ADB run-as denied by Android. Transfer verified source archive using a one-shot loopback HTTP response through ADB reverse, removed forwarding after transfer. Initial shared Downloads archive was unreadable due scoped storage; no permissions changed. Build and tests invoked in foreground Termux app via ADB input, not as shell/root. Serial build, locked dependencies. First native compile found Linux-only HTTP policy reference; compile HTTP and legacy CLI only on Linux, no Android remote service. Native2 compiled both binaries but optional workspace test terminated SIGSYS (-31). Native3 replaces openat2 in experimental private workspace adapter with bounded O_NOFOLLOW descriptor component walk, procfs mount-ID checks on each scoped component, UID and permission checks, regular-inode reopen. Linux production adapter unaffected. This is a separate Android-specific security boundary, not equivalent to the Linux openat2 atomic path resolution; outside same-UID concurrent relocation remains out of scope. Native3 passes actual MCP protocol, private read/list/info, traversal/symlink/unsupported tool denials 2/2 and native Rust security tests 3/3 (hardlinks, FIFO, oversized data, bounded listing, pinned root). Host 3/3 and all-target Clippy pass. Native compile has six dead-code warnings per binary because Linux registry/legacy helpers remain compiled; no native warnings-denied or full locked suite rerun, release build, ARM64 device, remote authentication or writes tested. Exact native3 archive SHA256 fa5f433389b301139a6328ac2c11d5b00ddbae5a33ba430852f940c124ca7e6b; gateway SHA256 c7a4cd382f81ebb9711f97b0b975cc395a115e83ce1aa8240ea94da3a42b714e. Source in Termux ~/veyl-termux-native3; shared private build cache ~/veyl-termux-native/target/debug/{veyl,mcp-gateway}. Source manifest ../SOURCE_SHA256SUMS-native3 and native logs ../native-receipts. No root/config/package installation, production restart, push or publication. Host production active PID 76586, NRestarts=0, canonical main clean. Next: native credential storage and authenticated loopback read-only MCP; native remote and write/job capabilities remain disabled. Windows paused.


## Android-first refinement — HOLD

Operator prioritized Termux; Windows paused. Termux app com.termux confirmed installed in running Waydroid, but ADB still unauthorized. Added descriptor-relative private HOME child selection, bounded list_directory and file_info with native Android smoke assertions. Host verification: 3/3 workspace security unit tests, 2/2 platform smoke tests, 9/9 Linux product integration tests, Clippy and formatting passed (mwwia0vu-4lhbaw, exit 0). Android target/runtime not compiled or tested. Linux-only debug candidate in ../termux-stage2-host-bin; do not transfer this executable to Android. No package, root, service, version or release changes. Next gate: authorize Waydroid ADB and inspect actual Termux app UID/toolchain; run native tests/platform_termux.sh.

## Windows / Android foundation — development checkpoint, HOLD

Operator requested both ports using the Notion roadmap, Waydroid and the existing Windows test environment. Isolated candidate `~/.local/share/veyl-development/candidates/platform-foundation.l7Ge9o1L/source`, base `0335e36f9bcce549dd8c09bc481f78468cb3f3cf`. No version bump. Shared native platform capability CLI and restricted foreground MCP probe implemented; Android private workspace read adapter uses pinned descriptors and fails closed, Windows file and job adapters not yet implemented. Non-Linux legacy root and HTTP entry points deliberately refuse startup until native security acceptance. See [PLATFORMS.md](PLATFORMS.md) for native build scripts, requirements and limitations. Linux production 0.4.0-beta remains unchanged.

Host Rust 1.100.0 has only Linux x86_64 standard libraries; both Android targets and Windows GNU/MSVC targets are absent. Waydroid active; ADB connection to current Waydroid endpoint failed authorization (do not bypass using root). Windows native compiler/runner not verified. The native guest scripts are authored, not executed; no Android/Windows binary or parity claim. Host Clippy all targets, formatting, debug build and two kernel reader unit tests passed (process `mwwhv0pq-a452d4`). The first platform smoke test contained a Python true/True typo; fixed only the new test fixture, then 2/2 smoke cases passed against Linux (process `mwwhxoox-zmf8a2`). The corrected run also passed 67/67 gateway Rust tests, 9/9 Linux product integration tests, shell syntax and diff checks (exit 0). No locked acceptance suite or pin changed; the full locked battery has not been rerun for this bootstrap. Nightshift deferred to separate checkpoint.


## 0.4.0-beta — DEPLOYED AND PUBLISHED (2026-11-25)

Operator explicitly approved the revised TimeShift + Activity details candidate and authorized local upgrade, GitHub and crates.io publication. Release commit `7da68e4ae3fb2aefb25183432d2268963cdc197e`; GitHub tag `v0.4.0-beta` resolves to that commit, prerelease contains five verified assets. Cargo `publish --locked -j 1` verified the packaged crate, uploaded it and confirmed registry availability (job `df392a8b75254165`, exit 0); independent `cargo info veyl@0.4.0-beta --registry crates-io` downloaded the published crate. Local updater installed all three approved binaries in both ~/.local/bin and ~/.cargo/bin, running gateway PID 76586, active, NRestarts=0, all installed hashes match. Original policy file checksum unchanged, valid state layout, all jobs idle before upgrade. Native service_status, Node Utils SHA-256 and Rust Anything repository analysis passed through the existing ChatGPT connector (81 authorized tools). TimeShift grants remain opt-in, not automatically enabled. Standalone systemd lifecycle passed; updater lifecycle passed with the required fresh debug >32 MiB fixture, including interruption recovery, active-job blocking and broken-service rollback. The first updater probe used an incorrectly small optimized fixture; the full corrected rerun passed without source/test changes. Original release binaries and receipts in ~/.local/share/veyl-development/artifacts/7da68e4/; native rollback ~/.veyl-update-backups/e56230a2f12f0f2ca5043f833d123313. Initial transient Cargo publish tracker was lost; verified no active process and absent registry version before successful recoverable retry. Previous sections describe historical candidate states, not current production. Nightshift remains next.

## Activity command detail refinement — approved for promotion (2026-11-25)

Operator requested a TUI improvement before approving 0.4.0-beta. Activity Enter now opens a readable command/target detail view with status, client, local time, duration, call ID, captured command or exact argv, requested working directory, configured profile or file target where available. d toggles full JSON. Escape restores the selected activity. Missing/expired traces and non-command operations are labeled explicitly. Existing opt-in local trace, TTL, retention, permissions and metadata-only audit are unchanged; interactive process input remains uncaptured. No dependency or version changes.

Monitor-specific Clippy, Rustfmt, 11/11 monitor Rust tests and 5/5 dynamic job tests (including actual optimized-monitor PTY command capture, Enter, JSON toggle, trace disable and selection restore) passed, process `mwwgnrfq-5gbn6p`, receipt `../verification/tui-command-details.json`. Optimized monitor SHA-256 `733f4146bea6dc33c7c9192fcd2ddb795c49456415d963593b748fd3ccaa51bb`. The gateway and CLI are byte-identical to the prior verified candidate. Revised bundle `../release-tui-bin/`; previous `../release-bin/` preserved. Previous gateway acceptance remains attributable to its unchanged binaries; the full locked battery was not rerun for the monitor-only change. Production remains untouched and exact revised candidate approval required.


## TimeShift 0.4.0-beta — verified candidate; HOLD (2026-11-25)

Isolated worktree `~/.local/share/veyl-development/candidates/timeshift-native.4VQ4Pbv1/source`, base `84a1b4d784861f993f32c805b8a4dde0e7afdfa5`, detached/uncommitted. Version 0.4.0-beta selected for the new native feature; no new dependencies. See [TIMESHIFT.md](TIMESHIFT.md) for the exact interface, permission opt-in, snapshot format, retention, security assumptions and limitations. 71 native tools; 84 including the previous 13 upstream tools in the all-granted fixture. Existing client grants unchanged. Nightshift not started.

Verification against this candidate:
- Rustfmt, JS syntax, all-target Clippy with warnings denied, debug build and TimeShift 9/9 passed (process `mwwg0584-xhep0r`, observed exit 0 before BridgeDev tracker restart).
- All three optimized 0.4.0-beta binaries built offline/locked, serially (job `17609d6c5feb47d4`, exit 0, log `~/.local/state/chatgpt-local-coder/jobs/17609d6c5feb47d4.log`); exact release SHA256SUMS in `../release-bin/`.
- 168/168 Rust cases, 287/287 locked cases across 28 original suites, 6/6 three-mode cases, and 86/86 focused Python integration cases (18 unittest suites, including TimeShift 9/9), actual browser onboarding and all three gate3 runtime probes passed. Exact release used for Python integration and locked Python tests except the fresh test-hooks binary for locked_audit_chain; Rust suites use fresh compiled code. No ignored/skipped tests in the counted suites. Persistent logs and per-suite receipts in `../verification/`. This is direct implementation-side verification, not fresh independent AGY certification. Standalone systemd_lifecycle and updater_lifecycle end-to-end scripts not rerun for this checkpoint.
- Initial process receipts lost due BridgeDev tracker restarts; confirmed no remaining owned processes before reruns. Locked permanent-permissions negative control initially failed because the inherited umask 0077 transformed its intended 0755 test directory into 0700; corrected only the disposable runner umask to 0022, not host permissions, source assertions or hash pins. All 28 original pins verified unchanged before/after batches. Initial marketplace browser timeout passed on isolated rerun and full 4/4 rerun; real REA/Rust Anything passed. Initial gate3 probe incorrectly received -v instead of a binary path; corrected explicit optimized binary and full/standard/legacy probes all exited 0. Original failed logs retained.
- Release hashes: mcp-gateway `b0eb638d3c911922c003a27ce507886c40fce0bf9ba46e8a1db59c5a8f6d1ceb`; veyl `0065476d044e06f5ea662a889506c00d8e4399ff4d3c2d4603b951fd40192092`; veyl-monitor `f1639035ba0c8b0f92287debd7fa4343e5b5cea42d7c74a0ff654ebc35ee6b66`.

HOLD for explicit operator approval. Production remains 0.3.1-beta, PID 58394, zero service restarts during this checkpoint. No production grants/config/state change, canonical source change, commit, push or deployment. Approve the exact candidate before promotion and verify the rollback and connector after deployment. TimeShift is opt-in after deployment; never bulk-enable restore or clear.


## 0.3.1-beta versioned release verification (2026-11-25)

Operator explicitly requested promotion and a new GitHub release. Selected patch beta 0.3.1-beta; no dependency changes. Exact release binaries in adjacent `release-0.3.1-beta-verified/` with SHA256SUMS: mcp-gateway `165bc98354bd9010ed64ee6dac94f84ad55806fea8f392acdd88927133da0f6c`, veyl `eadad41b29ae0ad983b4aaa22d7b91ba25949f58dce9c37c3fbaef4d1f7aaaec`, veyl-monitor `3e9c484d43ac2a924c804e129debf9eb9f34c7bcc6dbda0ef1dc6788163964b5`. All report 0.3.1-beta; no test-hooks marker. Formatting, JS syntax, all-target Clippy and offline locked optimized build passed. Temporary process tracker lost during initial compile; recoverable job `3b15138645e2494e` built all release binaries successfully but six Rust cases returned ENOSYS in its restricted environment. Normal UID1000 process `mwwf1dhj-txdfiz` reran all 168 Rust cases successfully, no skips. Exact versioned debug library/test-hook build `mwwf3cj5-ksgtbr` passed; the hook binary is used only for locked audit-chain cases. Three bounded locked batches `mwwf3w30-gv2xaf`, `mwwf47l7-ervjke`, `mwwf4ruc-a9w94q` exited zero: 287/287 locked cases plus 6/6 modes, all 28 hash pins unchanged before and after each batch. Persistent per-suite logs and receipts in `../verification-0.3.1-beta-verified/`. Exact release focused regression process `mwwf57on-cmpr35` verified 19 cases and browser pairing/tab/keyboard. Additional release process `mwwf5uum-vvla4k` passed 14/14 (runtime bundles 2, modes 5, extensions 3, marketplace 4 including real REA/Rust Anything and browser). Total focused 33/33. No security check was relaxed.

## Provider-only Projects scope and dashboard editor (2026-11-25) — historical pre-version checkpoint

Operator approved the preceding checkpoint; deployed/pushed `2cf0ea0a96569e6952b9e161aebeb738e66aef36` to canonical and GitHub main. Native updater installed all six expected user executable paths; running mcp-gateway SHA-256 `53a4d1d10850fb5c9df3a8a15e20ca40e163cf3d1a837588c4128c1cdcd74f77`, PID 35773, zero restarts, state valid, ChatGPT 81 tools and Node Utils invocation verified. Rollback `~/.veyl-update-backups/68d3b7ec6d4e5c90d9ffb4175ac338cf`, archived artifacts `~/.local/share/veyl-development/artifacts/2cf0ea0/`.

Follow-up isolated worktree `~/.local/share/veyl-development/candidates/workspace-dashboard.d9ELDmvu/source`, base `2cf0ea0`: audited `workspace-folder` command adds a distinct provider-only read-only folder grant, with persisted device/inode, no native root or mode change, protected-path checks, and stale-root revocation. The older `workspace` remains native-root-scoped. Local dashboard adds Workspace folders editor (absolute path entry, scope, grant, revoke, current folder), Custom integration link and staged bundle transport, responsive visual refresh and updated browser assertions. Only reviewed REA/Rust Anything path schemas receive projected files; generic custom providers remain bundle-only. No production workspace grants applied yet because the existing shared client root is a descendant of Projects and native extra-root overlap is forbidden.

Verified debug and optimized: 19/19 focused cases (folder editor 2, job-enabled workspace 3, workspace 4, product 9, dashboard preview 1); real Chromium pairing/tab/keyboard and new editor UI assertions; all-target Clippy, fmt, JS syntax, optimized build. Receipts `mwwehx96-l8falo`, `mwwekpl3-lok8c6`. Real provider disposable instance granted actual `/home/onyx/Projects`: Rust Anything analyzed 20 units under veyl/tests; REA inspected a unique synthetic .pyc created and cleaned under Projects; 81 discovery and unchanged native scope verified on debug and optimized (processes `mwwejv9r-0nachb`, `mwweoaiw-wpuz3t`). Full Rust/locked rerun process `mwweny54-41ih11` became unavailable in BridgeDev; process and cargo/rustc no longer running, no exit receipt, not certified. Do not silently reuse earlier acceptance for this new source. Release SHA-256: mcp-gateway `94cb6f2db7da5e33ada85cc980319ffc0363df6a887e3c019432403972c1d104`, veyl `42304449ad90c290e80a74532e49f334d9c5c90bd51d011a45e99e703d012d54`, veyl-monitor `4261ac966a449831b6c355299c4955d13307fa065612676322aa0d7f68584126`. No test-hooks marker in release. Full locked/Rust verification and explicit exact-candidate approval remain before new promotion. Production stays at 2cf0ea0; no version bump, unrelated config or service change.

## Upstream workspace acceptance (2026-11-25) — PASS, operator approval pending

At operator direction, ChatGPT performed the remaining verification through BridgeDev under UID 1000, without requesting another AGY run. Corrected release binaries unchanged. Rust tests 168/168; locked battery 287/287 across 28 unchanged pins plus six three-mode cases; focused release regressions 17/17 (preceding checkpoint). The locked runner used the exact corrected release executable, with a fresh test-hooks build only for locked_audit_chain.py. Process `mwwdwcf4-upds4f`, exit 0. Real-provider job-enabled 81-tool acceptance passed on corrected release in `mwwdwwvw-v61xey` (test_01); test_02 subsequently passed in `mwwdy0mv-s2tazl`, exit 0.

The separate `../bridge-acceptance.py` copy preserves the independent original and its assertions, corrects binary mock decoding, saves the actual process handle, allows the client to observe the gateway timeout, and removes v3-only YOLO metadata when constructing the v2 Standard legacy fixture. Added assertions verify recovered byte content and actual timeout duration. The first copied run failed at legacy fixture startup; the corrected fixture passed. No locked suites or pins were edited. Logs are retained in `../bridge-acceptance-receipt.json`. This is direct verification by the implementing assistant, not a fresh independent AGY certification.

Release SHA-256 remains `53a4d1d10850fb5c9df3a8a15e20ca40e163cf3d1a837588c4128c1cdcd74f77` for mcp-gateway. Personal isolated preview and explicit exact-candidate operator approval are still required before production promotion, GitHub push or publication. No change to production or version was performed.

## Upstream workspace job-schema correction (2026-11-25) — historical pre-acceptance checkpoint

The initial workspace candidate was blocked by AGY: the strict `JobClient` deserializer rejected `upstream_workspace_roots` when job_profiles were present. Reproduced before the fix using a new disposable 81-tool job-enabled fixture (process `mwwdod8b-8vq6zt`, exit 1 at workspace grant with the reported exit 2). Fixed only the job schema in `src/jobs/config.rs`, accepting an optional typed map while retaining deny_unknown_fields and upstream admission validation. Added `tests/upstream_workspace_jobs.py`: 81 exact tool names, grant/reload/restart/revoke, real native command plus synthetic read-only upstream calls, invalid grant denial, Broad YOLO stale inode denial and restored-inode recovery.

Corrected debug: all 17 focused cases passed across runs (processes `mwwdopu7-k9yeun`, `mwwdroyl-otysj3`). Corrected release: 17/17 focused cases passed in one run; all-target Clippy with warnings denied, formatting, git diff check, and offline locked optimized build of all three binaries passed (process `mwwdpj0j-0dsjzs`). AGY's unchanged test_01 with real pinned providers and 81-tool discovery passed against corrected debug (process `mwwdq6tl-wb8wgd`). Unchanged test_02 reached the restored-inode assertion at line 338 but failed: the mock PEER reads a binary .pyc via read_text(); a separate binary decoding probe reproduced UnicodeDecodeError (`mwwds0l9-5hlxak`). Our distinct text-canary stale-inode test passed in debug and release; AGY must independently resolve its fixture and rerun test_02. No independent acceptance file was edited. Previous 287 locked cases and 168 Rust tests apply to the pre-fix candidate; repeat acceptance on corrected artifacts.

Corrected preview SHA-256: `01bfdc6caaa0d1b2ecda1b164d0c5f7adbd09d50786b13d6e192fd9309fc2235`. Optimized binaries are in `../release-bin/`: mcp-gateway `53a4d1d10850fb5c9df3a8a15e20ca40e163cf3d1a837588c4128c1cdcd74f77`, veyl `eb0213186610048b7a070f0d3685cb54fd806fb64fed73a0f67b23cc2a091ea4`, veyl-monitor `4261ac966a449831b6c355299c4955d13307fa065612676322aa0d7f68584126`. Verify adjacent SOURCE_SHA256SUMS, BINARIES_SHA256SUMS (preview) and RELEASE_SHA256SUMS (release). Production PID 1044, zero restarts, original executable hash, canonical main clean. No deployment, promotion, commit, policy edit, or version change.

## Upstream workspace corrective candidate (2026-11-25) — historical pre-fix checkpoint

Base `79f5d797f8b5e09b0e843c64baf9ab89d1a4f253`, isolated worktree `~/.local/share/veyl-development/candidates/upstream-workspace.Dx2gWMVJ/source`. Direct BridgeDev implementation: explicit per-client provider root grants, descriptor-pinned read-only file projection, reviewed path translation, mount-alias and protected-state checks, local grant/revoke CLI, and bounded authenticated scoped-call timeout extension. See [UPSTREAM_WORKSPACE.md](UPSTREAM_WORKSPACE.md) for limitations and fixture invocation.

Local verification against `../preview-bin/mcp-gateway`: workspace 4/4, runtime bundle 2/2, permission mode 5/5, extensions/proposals 3/3; 14/14 total, no skips. Debug build, focused Clippy with warnings denied, cargo fmt and git diff checks passed. Process receipts: `mwwcqfu7-dlq8vf`, `mwwcrp65-o6a3hh`. Debug executable SHA-256 `6558f45c928d1aa4a1f18e32b1518cd9e9c6115259c6d891c747f68d016f43ed`. Real pinned providers, adversarial independent acceptance, complete locked battery, optimized build and operator approval remain pending. No version, production config, installed executable, GitHub, or service changes. Production remained PID 1044 with original binary hash and zero restarts. No commit was made.

## 0.3.0-beta final independent acceptance (2026-11-25)

Candidate `~/.local/share/veyl-development/candidates/timeshift.o89oyRsF/source` (branch `candidate/0.3.0-beta`, base `0e2cf55`, version `0.3.0-beta`). Includes the parity-86 capability surface (68 native MCP tools, ~86% functional-domain estimate across 6 of 7 BridgeDev domains), opt-in read-only runtime bundles (`veyl mcp-servers add-bundle`), compact live TUI MCP status, and the verified `ENOTCONN` FUSE sibling projection skip in Broad YOLO. TimeShift (`rewind` checkpoints) and autonomous Nightshift orchestration are NOT implemented and remain excluded from `0.3.0-beta`.

Independent AGY verification (UID 1000):
- Trusted harness fix: corrected `harness/acceptance.py` `GATEWAY_GIT_DIR` from missing `rust-mcp-gateway/.git` to `~/Projects/veyl/.git`, added explicit error on missing canonical repository so relocation cannot silently return zero suites, and supported `refs/remotes/origin/` milestone resolution (`harness/tests`: 37/37 PASS; `candidate/0.3.0-beta` selects all 28/28 locked suites).
- Formatting & lints: `cargo fmt --check`, `cargo clippy --offline --locked --all-targets -- -D warnings`, and `node --check src/http/dashboard/app.js` PASS; zero emojis in code/docs/tests.
- Rust suite (`cargo test --offline --locked -- --test-threads=1`): 158/158 PASS (lib 0, legacy_main 62, main 62, veyl-monitor 10, bridgedev_parity_and_nightshift 3, gate3_operator 11, onboarding 6, pass2_mutation 4; zero `#[ignore]`).
- Locked acceptance: 28/28 original SHA-256 pins verified unchanged before and after execution; 28/28 locked suites (**287/287** cases) PASS; `acceptance_pass4_three_modes/locked_three_modes.py` **6/6** PASS against `preview-bin/mcp-gateway` (`test-hooks` binary used only for `locked_audit_chain.py`).
- Integration, browser, provider & lifecycle suites (all PASS under UID 1000 against candidate binaries): `process_sessions.py` 10/10, `extended_jobs.py` 3/3, `dynamic_jobs.py` 5/5 (real PTY `veyl-monitor`), `git_tools.py` 3/3, `context_and_system.py` 3/3, `extensions_and_proposals.py` 3/3, `runtime_bundles.py` 2/2, `bundled-provider-probe.py` (REA 11,133 files / 27 tools + `inspect_python_pyc`, Rust Anything 22 tools + `analyze`), `linux_features.py` 16/16, `product_features.py` 9/9, `permission_modes.py` 5/5, `activity_features.py` 3/3, `job_streams.py` 1/1, `test_dashboard_preview.py` 1/1, `gate3_runtime.py`, `onboarding_browser.py` + `dashboard_tabs.mjs` (Brave CDP), `systemd_lifecycle.sh`, `updater_lifecycle.sh` (all 4 delegated systemd phases).
- Advisory scan: `cargo-audit` binary unavailable; offline RustSec check against `~/.cargo/advisory-db` (`55e1c3dfbd834237a05bbbf7b50ba3b5be27b662`, 2026-11-21) evaluated all 86 crates.io lockfile packages across 47 non-withdrawn advisories with 0 vulnerability matches and 0 informational matches.

## 0.3.0-beta release candidate (2026-11-25)

Candidate `~/.local/share/veyl-development/candidates/timeshift.o89oyRsF/source`, base `0e2cf55`. Includes the previously operator-tested parity-86 and live-status/runtime-bundle candidates. TimeShift and Nightshift are NOT implemented and are excluded from this release scope.

Broad YOLO preflight diagnosis: a disconnected FreeRDP FUSE mount in `/tmp` returned ENOTCONN; basic Bubblewrap isolation succeeded. A diagnostic-only stderr probe reproduced the exact failure. The final fix skips only ENOTCONN in unprotected projection siblings; all other lookup errors, protected paths, required ancestors and cwd identity remain fail-closed. No host mount or security configuration changed. The diagnostic stderr change was reverted. Debug regression suites passed: extensions 3/3, dynamic jobs 5/5, runtime bundles 2/2, process sessions 10/10, permission modes 5/5 (process `mwvy466n-g00d92`).

Manifest and lockfile version bumped to 0.3.0-beta. Previous parity-86 release executables preserved under `~/.local/share/veyl-development/artifacts/parity-86-0e2cf55/release-bin/`, with verified checksums. The production version remains 0.2.5-beta pending the exact versioned candidate gate.

## 86% parity milestone & native updater integration (`parity-86`, 2026-11-25)

Base `0e2cf55da417d2bc580c786a7d0e784fdec8cb9f` on branch `dev/parity-86`, version `0.2.5-beta`.
Candidate source: `~/.local/share/veyl-development/candidates/parity-86.hjODQIAS/source`.
Production service (`mcp-gateway.service`), canonical `main`, and crates version remain unchanged pending operator approval.

Integrated verified capabilities:
- Native updater (`src/update_cli.rs`, `src/service_cli.rs`) with `reset-failed` on crashed-unit rollback, `REMOTE_LIMIT` (32 MiB) vs `LOCAL_LIMIT` (128 MiB), `~/.veyl-update-backups/active.json` recovery journal, `--recover`, and 4-phase delegated systemd E2E suite (`tests/updater_lifecycle.sh`).
- Persistent processes & durable execution budgets: `process_resize`, `shell_status`, `job_logs` `encoding` (`utf8`/`base64`), configurable `cpu_percent` / `memory_bytes` / `max_output_bytes` (up to 16 MiB) / `job_retention_count`, and `task_run` `ephemeral_worktree: true`.
- 12 native structured Git tools (`git_status` .. `git_push`) with hardened git worker (`--tmpfs /repo/.git/hooks`, RO `.git/config` memfd mask), exact per-tool grants, explicit `confirm: true` destructive/network confirmation, and fixed BroadYolo `.git/hooks` workspace cwd inode preservation (`src/jobs/broad.rs`).
- System & context inspection: `system_inspect` 10th subsystem `processes` + top processes in `resources`, TX/RX interface rate sampling in `network`, wake-safe `nvidia-smi` telemetry in `gpu` (invoked only when PCI NVIDIA GPU `power/runtime_status == "active"`), plus `load_path_rules`, `remember`, `chezmoi_inspect`, `list_skills`, `load_skill`.
- Extensions, validation & upstream workflows: `extensions_search` (offline 106-entry catalog), `extensions_list`, `extensions_info`, `skills_validate`, `mcp_list`, `mcp_status`, `mcp_info` (`provider_fingerprint`), fingerprint-bound `mcp_test`, 8 inert `*_propose_*` operator-review tools, and dashboard `GET/POST /api/dashboard/requests`.

Independent verification results (2026-11-25, release + debug + test-hooks builds):
- `cargo fmt --check`: PASS.
- `cargo clippy --offline --locked --all-targets -- -D warnings`: PASS (0 warnings).
- `cargo test --offline --locked -- --test-threads=1`: 157 tests PASS (lib 0, legacy_main 62, main 62, monitor 9, bridgedev_parity_and_nightshift 3, gate3_operator 11, onboarding 6, pass2_mutation 4; zero failures).
- Release build (`cargo build --offline --locked --release --bins`): PASS; zero `test-hooks:` symbols confirmed (`mcp-gateway` `2a94fd0e...`, `veyl` `52eca707...`, `veyl-monitor` `ece4de60...`).
- Locked acceptance battery: 28/28 original SHA-256 pins unchanged before and after; 28/28 locked suites (287/287 cases) PASS; `acceptance_pass4_three_modes/locked_three_modes.py` 6/6 PASS.
- Feature & runtime suites (all PASS): `process_sessions.py` 10/10, `extended_jobs.py` 3/3, `dynamic_jobs.py` 5/5 (including real PTY monitor timing), `git_tools.py` 3/3, `context_and_system.py` 3/3, `extensions_and_proposals.py` 3/3, `linux_features.py` 16/16, `product_features.py` 9/9, `permission_modes.py` 5/5, `activity_features.py` 3/3, `job_streams.py` 1/1, `test_dashboard_preview.py` 1/1, `gate3_runtime.py` PASS, `onboarding_browser.py` + `dashboard_tabs.mjs` (Brave CDP on release binary) PASS, `systemd_lifecycle.sh` PASS, `updater_lifecycle.sh` (all 4 delegated systemd phases) PASS.
- JS syntax: `node --check src/http/dashboard/app.js` PASS.
- Release benchmark: idle RSS `6348` KiB (`6464` KiB post-calls), 1 s idle CPU `0` ticks, `read_file` median latency `0.164 ms` (`p95 = 0.324 ms`).
- Security advisory limitation: `cargo-audit` is unavailable in this environment (`error: no such command: audit`).

## Persistent process sessions — isolated candidate (2026-11-25)

Base `33e9f56cd2b51dc4f0878237b7971592b9e8c1ff`, version `0.2.5-beta`.
Candidate source remains uncommitted. The previous pass left closed stdin
and the operator-verified extended-runtime code. This checkpoint preserves
that code and adds separately granted `process_start`, `process_input` and
`shell_reset`, reusing signed job status, logs, cancellation and resource
scopes. Standard and Broad YOLO pass real pipe and PTY probes. The runner
accepts sequenced input through MAC-authenticated Unix datagrams with a
peer proof before input, current policy and expiry checks, bounded writes,
backpressure, EOF or terminal hangup, and reconnect across gateway restart.

The final build passed formatting, Clippy with warnings denied, offline
builds and 115 Rust tests. Process sessions 9/9 (13.655 s), extended jobs
2/2, dynamic jobs 4/4, product 9/9 and Linux 16/16 passed. Ten selected
locked suites passed 100/100, including 13/13 audit cases with the dedicated
hook executable. All 28 manifest pins matched. The first locked permission
run inherited umask 077, which turned its intended 0755 negative fixture
into 0700. Under umask 022, both the old and current binaries reject the
actual 0755 fixture, and the final permission suite passed 17/17. Suites
and harness files were unchanged.

Binary and source manifests and raw logs are under `.candidate-preview/logs/`.
`mcp-gateway` SHA-256 `dec223ef6dc9f09293ea9fa01e980f2d9a24f163b19dfd75e80fc38e072abe68`.
Source-manifest SHA-256 `f5e86b51ab299d6fdd19ab2c606c7f5eb4156dd5cbfbf36b6e9aafd02f55358a`.
Final logs are `cargo-session-peer-proof.log`, `peer-proof-*.log`,
`locked-jobs-peer-proof.log`, `locked-audit-chain-peer-proof.log` and
`abstract-peer-binding.log`. The final verification commands exited zero.
See [Process sessions](PROCESS_SESSIONS.md) for the runnable personal check.

FULL interactive sessions are unavailable. PTY uses a fixed 24×80 terminal,
a merged UTF-8 output preview and hangup for EOF. The 24-hour budget was
admitted and exercised without a full-day soak. Personal verification and
AGY acceptance are pending. No commit, deployment, production restart,
push, or version change occurred.

## Extended durable execution — isolated candidate (2026-11-25)

Base 33e9f56; source `~/.local/share/veyl-development/candidates/durable-budget.18J5Kerc/source`.
Explicit managed per-client job runtime limit up to 86400 seconds, optional
extended named profile opt-in and client-specific task_run schema. Default
300-second budget, short exec/run limits, exact grants and confinement remain.
Extended jobs require the existing systemd scope and signed runner.
Final debug build, formatting, Clippy, extended job integration 2/2,
dynamic jobs 4/4 and Linux 16/16 passed (`extended-jobs-final-retry.log`).
Tested actual job execution, cross-client denial, limit reduction, session
and gateway restart recovery, logs and cancellation with extended budgets;
not a full-day soak. See EXTENDED_JOBS.md for isolated personal acceptance.
No production configuration or service change, commit, push or version bump.
The independent locked suite and AGY acceptance remain pending. Other partial
parity domains and updater repairs remain separate, unaccepted checkpoints.

## Artifact retention and updater repair checkpoint (2026-11-25)

`2d1bd03` was pushed and remote main verified. Both TUI regressions passed
Linux 16/16, dynamic jobs 4/4 and monitor 9/9. No production installation of
the correction occurred. Historical target receipts and source worktrees
were moved to `~/.local/share/veyl-development/artifacts/2d1bd03/legacy-target/`;
only confirmed inactive generated profiles were removed. `target` reduced
from 31 GiB to 4.2 GiB, archive 90 MiB, filesystem available 42 to 47 GiB.
Cargo's missing cache-marker refusal was resolved by inspecting individual
Cargo profile contents, not by fabricating a marker. Preserve the archive
and installed rollback backups. See PREVIEW.md for retention rules.

The repaired updater candidate is
`~/.local/share/veyl-development/candidates/updater-fix.QogvnTli/source`,
based on 2d1bd03. Trusted bundle hardlinks are accepted while installation
and backup hardlinks remain rejected; failed stopped units with MainPID=0
permit rollback; private staging cleanup, separate rollback manifest,
pinned directory rename operations, all-directory discovery, supported
alpha/beta/rc selection and three-binary version checks are implemented.
Rollback attempts each restoration even if one fails. Six focused tests per
CLI (12 total), formatting and Clippy passed (process `mwvpd795-4padz0`).
Not merged or deployed: portable no-manager behavior, debug size bounds,
interrupted transaction recovery and isolated service/job rollback acceptance
remain open. The original updater source remains in the legacy archive.

Next functional parity checkpoint after updater acceptance: owned persistent
process sessions with bounded incremental I/O, cancellation and recovery;
then operator-approved multi-hour task budgets, structured Git and Nightshift.

## TUI regression correction (2026-11-25)

BridgeDev independently confirmed AGY's two compatibility failures and fixed
only the active-tab palette and filter label. The existing Linux integration
suite is unchanged; the new selection regression asserts the restored label.
Exact candidate: `~/.local/share/veyl-development/candidates/tui-regression.Ee2eTBot/source`.
Offline build, formatting, Clippy, monitor unit tests 9/9, Linux 16/16 and
dynamic jobs 4/4 passed (BridgeDev process `mwvp1hf7-pxsz3f`). AGY's prior
287 locked passes apply to 7c2db86, not a fresh full run of this correction.
Operator authorized source push; no new binary installed or version bumped.
Updater remains blocked; next parity milestone is persistent process and
durable execution.

## AGY independent verification of TUI, preview and updater (2026-11-25)

Target checkout: local `main` at `7c2db86edff8a51a090dc9ba582170a7935d3c56`
(version `0.2.5-beta`). Production remains untouched (`mcp-gateway` and `veyl`
at `2ba71c1`, `veyl-monitor` at `7c2db86`, `mcp-gateway.service` PID `330421`,
`chatgpt=yolo` with 28 tool grants, `codex=standard`, `agy=standard`).
`origin/main` was NOT updated because `7c2db86` fails `tests/linux_features.py`.

1. **TUI independent acceptance (`target/agy-7c2db86-tui.log`) — PARTIAL / BLOCKED FROM PUSH:**
   - Real PTY verification passed: simplified masthead (`Veyl  0.2.5-beta` and
     `Veyl / preview` with `LIVE`), responsive sizing (`10x28`/`10x40` resize
     banner, `18x50`, `36x160`), keyboard/tab/`Tab`/mouse tab switching,
     contextual footer shortcuts, Health `Recent MCP sessions` (30-min expiry)
     vs `Open MCP connections`, Clients `recent=` count, opening Details (`Enter`)
     and Logs (`l`) from the 3rd entry with scrolling and `Esc` preserving
     selection, filter and record identity, and selection stability across
     concurrent MCP calls and jobs.
   - **Blocking regression (`tests/linux_features.py` 15/16, 1 FAIL, `target/agy-7c2db86-linux.log`):**
     `test_monitor_pairing_views_and_keyboard` fails on two incompatibilities
     introduced in `7c2db86`: (a) `src/bin/monitor_tui/mod.rs:779` switches the
     active tab to `\x1b[1;7m` (reverse video), violating the terminal palette
     invariant (`allowed = {0,1,2,4,31,32,33,36,39}`) and removing
     `\x1b[1;4;33m`; (b) `src/bin/monitor_tui/mod.rs:803-805` renders `/ <query>`
     instead of `Filter: <query>`, breaking the PTY filter assertion.

2. **Development preview pipeline (`target/agy-7c2db86-preview-cdp.log`) — PASS:**
   - `tests/test_dashboard_preview.py` (1/1) plus isolated Brave CDP check of
     `tests/dashboard_preview.py` passed: `DEVELOPMENT PREVIEW` banner, live
     auto-reload on HTML, CSS and JS changes, all 9 diagnostic subsystems,
     marketplace bundled SVG icons (zero external images), theme toggle, POST
     and invalid Host rejection (403), hidden file refusal (404), port conflict
     handling, and clean restart recovery.

3. **Pending native updater (`target/update-ui.RH8qSZQf/source`) — BLOCKED (DO NOT MERGE):**
   - Audit + probes (`target/agy-updater-probe.log`, `target/agy-updater-systemd.log`)
     found blocking defects: (a) Cargo hardlinks `target/release/veyl` (`nlink=2`),
     causing `read_owned()` (`st_nlink != 1`) to fail `README.md`'s `--from-dir
     target/release` workflow (`Refusing linked, unsafe or non-owned file`);
     (b) `systemctl --user stop` leaves a crashed `failed` unit in
     `ActiveState=failed`, causing `service_cli::update_stop()` (`!= "inactive"`)
     to abort automatic rollback before `change.restore()` runs;
     (c) `.veyl-update-<nonce>` stage dirs in `~/.local/bin` / `~/.cargo/bin` are
     never cleaned up on failure or success; (d) `install()` only scans dirs
     containing `veyl`, requires active `systemd --user` even for non-service
     `--from-dir`, rejects >32 MiB debug builds, and `/releases/latest` +
     `version_key` exclude GitHub prereleases and `-alpha`/`-rc` tags;
     (e) no integration test covers `install()`, service restart, active-job
     blocking, or partial rollback.

4. **Regression, 28 tools & 9 diagnostics:**
   - Clean: `cargo fmt -- --check`, `cargo clippy --all-targets -- -D warnings`,
     `node --check`, 28/28 locked SHA-256 pins and 287/287 locked cases
     (`target/agy-7c2db86-locked-28.log`), draft three-mode suite 6/6
     (`target/agy-7c2db86-pass4.log`), `product_features.py` 9/9,
     `permission_modes.py` 5/5, `activity_features.py` 3/3, `dynamic_jobs.py`
     4/4, `job_streams.py` 1/1, `systemd_lifecycle.sh` PASS, and
     `onboarding_browser.py` PASS using `MCP_GATEWAY_BIN=target/debug/mcp-gateway`
     (note `target/release/mcp-gateway` on disk is stale 0.2.4-beta).
   - Rust `cargo test --offline --locked`: first run hit a transient Bubblewrap
     error in `tests/onboarding.rs::mode_transitions_and_full_confirmation_workflow`
     (108/109, `target/agy-7c2db86-rust-test.log`); rerun passed 109/109
     (`target/agy-7c2db86-rust-test-2.log`).
   - Verified all 28 advertised MCP tools and all 9 `system_inspect` subsystems
     on an isolated YOLO+jobs+skills gateway (`target/agy-7c2db86-tui.log`).

## TUI preview and mandatory operator acceptance (2026-11-25)

Candidate `target/dev-preview.oTcBcNyB/source`, based on 2ba71c1.
All future changes require a runnable preview and personal operator acceptance
before promotion. See AGENTS.md and PREVIEW.md in this candidate.

TUI detail/log overlays preserve the list selection, records and filter;
trace expiry restores the list without retaining raw details. Live refresh
retains call/job identity where still present. Compact title and LIVE/STALE
status, highlighted tabs, contextual shortcuts; client modes, listener, RSS
and session count removed from masthead. Health identifies MCP sessions as
recent sessions with 30-minute idle expiry, distinct from open connections.

Checks: formatting, Clippy (warnings denied), debug monitor build, 9/9
monitor unit tests, and real PTY regression (filtered third entry, detail
scroll, Escape, same selection) passed. Initial PTY assertion raced the
activity refresh; revised test waits for the filtered list before movement.
Operator personally accepted the TUI and authorized merge/deployment.
Final optimized monitor build, 9 unit tests, Clippy, formatting, preview
HTTP contract and real PTY regression passed (tui-promotion-validation.log).
Monitor SHA-256: 4916f91130b8d20c1f83813480d120108fbb7d0630ec645df2f7da072aebddd1.
Promote only the monitor binary: the gateway and CLI are unchanged, so no
service restart or client policy change is necessary. AGY independent review
and browser auto-reload acceptance were not repeated in this checkpoint.

## Development preview candidate (2026-11-25)

Source-only, on-demand loopback dashboard preview at `localhost:7333` with
visible-tab reload on source asset hash change. Clearly marked synthetic data,
no production API access or mutation. See `docs/development/PREVIEW.md` for
preview, test, build, authorized deployment and runtime identity gates.
HTTP contract test passed; real browser auto-reload not yet independently
verified. Production remains commit 2ba71c1, version 0.2.5-beta.
Refreshed ChatGPT connector exposes 28 tools; live system_inspect returned all
nine subsystems. NVIDIA busy/VRAM values remain unavailable. Updater review
still pending. No version bump or publication.

## 2026-11-25 — same-version dashboard refinement

Operator authorized source push and local deployment without a version bump.
The dashboard now renders structured diagnostic cards for all nine subsystems,
with memory/swap/VRAM meters when telemetry exists, compact pressure rows,
explicit unavailable states and expandable complete JSON. Header removes
operations, client-mode and live-status text; theme and local trace use
accessible icon controls. Automatic visibility-aware refresh, paired-local
trace opt-in and expiry, and read-only probes remain unchanged. Marketplace
uses bundled category SVG icons, not third-party images.

Only dashboard assets and browser assertions are included in this checkpoint;
backend permissions and service/job logic retain the accepted 0.2.5-beta code.
The separate updater candidate remains at
`target/update-ui.RH8qSZQf/source`: AGY hit its quota before independent
security acceptance of the updater. Do not merge or install that mechanism
until reviewed. No release tag, published assets or crate version are changed.
UI validation receipt: `target/dashboard-only.fCGg9qGY/source/ui-validation.log`.

## 2026-11-25 — operator UI and explicit shared mode candidate

Isolated worktree `target/operator-ui.hRrNjrGW/source` at release base
`dcd0bf513bac76531a102debcd13385c32fc3c05`. No production changes.

- Browser refresh is automatic: activity/jobs every second, status every
  five seconds, selected diagnostics every ten seconds while visible.
  Diagnostics load on entry/selection and expose readable summaries plus
  complete JSON; hidden browser tabs stop polling.
- Compact Activity controls, aligned Skills form, readable protection
  cards, and grouped connection settings. Mode header groups clients by
  their actual effective modes.
- Local trace control available across dashboard views and from TUI Jobs
  and Activity. Successful job launch traces associate returned job IDs
  with the authenticated owner. Job rows and JSON details show captured
  command/argv/profile when available; file targets remain bounded and
  file content stays excluded. Metadata-only default, existing 24-call
  and ten-minute session-owned trace boundary retained. Historical raw
  commands and configured profile argv not captured cannot be recovered.
- Local CLI `veyl mode MODE --all` performs one audited atomic v3
  configuration transition for all enabled clients. FULL still requires
  confirmation. Per-client grants/denials, credentials, roots, upstream
  approvals and enabled state preserved. Explicit per-client changes
  remain independent. Disabled entries skip ordinary bulk mode selection.
  Interrupted bulk update is recovered by explicit bulk Standard, dropping
  elevation from all entries while preserving disabled state.
- Verification: full 109 Rust test executions on the initial UI/bulk build;
  final offline rebuild, formatting, Clippy with warnings denied, JS syntax,
  5 permission tests (including bulk negative controls and interrupted
  marker recovery), 4 dynamic job tests (including real PTY job command
  preview/detail and clearing), 3 activity tests, Brave CDP pairing and
  dashboard navigation/automatic diagnostics all passed. Earlier browser
  invocation used a nonexistent release binary; final run explicitly used
  the isolated debug binaries. Receipts: operator-ui-final.log and
  operator-ui-final-exact.log (exit 0). Locked acceptance suites not rerun
  for this new candidate. No claims of final independent acceptance.

Release v0.2.5-beta authorized by the operator. BridgeDev reran 109 Rust
executions, 287 locked cases (28/28 pins unchanged), six draft mode cases,
and all 38 Python probes on optimized binaries plus Brave CDP and PTY.
AGY independently reviewed bulk mode and trace security: static PASS,
not an independent test execution. An initial permission probe failed
closed with Bubblewrap's missing /proc/self/fd source error; a synthetic
unlinked-source test reproduced that error and the focused and full release
probe reruns passed. Original cause not established; no sandbox weakening.
Receipts: release-025-acceptance.log, release-025-retest.log,
release-025-agy-review.log. Persistent process and Nightshift parity remain open.

## 2026-11-25 — v0.2.4-beta release verification and live upgrade

AGY upgraded the production gateway, CLI and monitor to 0.2.4-beta after
the accepted checkpoint `cadda0c5b3d384faeec7a12579804eb6d2983401`.
Release changes: version bump, installation documentation and explicit
legacy YOLO deprecation wording; no permission expansion.

BridgeDev resumed the interrupted live smoke test and verified the running
gateway PID 283899, all six installed binaries against the release build,
and valid Broad YOLO state layout. Executable rollback backups were moved
outside the state tree by AGY to
`~/.local/share/veyl-backups/pre-v0.2.4-beta/{local-bin,cargo-bin}`.
Do not store executable backups inside the validated state directory.

Live checks passed: two fresh public Funnel sessions (28 tools each,
with and without ChatGPT Origin), private HTTPS dashboard, local dashboard
and verified audit status, structured system inspection, protected-path
confinement, independent stream offsets, live detached-job timing and
cancellation, and real PTY TUI command/file-target previews with local
AM/PM and increasing elapsed duration (508 to 1016 ms). Trace was disabled
and cleared after the probe. No credentials, grants or routes changed
during BridgeDev continuation. No additional production restart.

Independent release verification:
- Formatting, Clippy with warnings denied, Rust tests (105 executions).
- 28/28 original locked pins before and after, 287/287 cases, and the
  additional three-mode draft suite 6/6.
- 37/37 Python integration probes on release binaries, JS syntax, real PTY,
  and excluded test hooks. AGY also ran Brave CDP and private systemd
  lifecycle before the interruption.
- Initial locked-suite failure was a fixture issue: inherited umask 0077
  made the requested insecure 0755 directory actually 0700. The unchanged
  negative control and full battery passed with test-only umask 0022.
- Cargo audit remains unavailable; no dependency advisory refresh claimed.
- ChatGPT connector still exposed 16 tools at the last catalog observation,
  despite 28 advertised by fresh public sessions.

Receipts: `target/release-live-resume-final.log`,
`target/release-024-verification.log` (initial fixture failure retained),
`target/release-024-controlled-acceptance.log`,
`target/release-024-package.log`. Release artifacts in `dist/v0.2.4-beta/`.

Release SHA-256:
- gateway: `baab7b6268285eae860bac0560404dc79210db35ae32c42eff2f0a55e7ab68b2`
- CLI: `52903a7ffbfbf15f87f155bd2b862c9c94f66df9fac1079b999035895e6266ff`
- monitor: `25e94be68623bfec6434c44c24ed99cf3e03b2b2a7cb2e789367868e225d8400`

Next: persistent interactive process management, structured Git,
operator-approved multi-hour budgets, and durable orchestration.
Full BridgeDev functional parity is not yet achieved.

## 2026-11-25 — AGY independent verification and GitHub integration

Independently verified and integrated candidate `target/parity-monitor.ZWQdxYaI`
(source manifest SHA-256
`9ebc7a2ea11c5181e02f92760ac8300590190d1af4a7827d51cd19ee7391d602`, 86/86 files
matched byte-for-byte in `/home/onyx/Projects/veyl`) while preserving existing
canonical documentation and worktree edits.

Independent verification results from a clean isolated offline build
(`/tmp/veyl_verify_Z`):
- Formatting (`cargo fmt -- --check`): PASS.
- Clippy (`cargo clippy --offline --locked --all-targets -- -D warnings`): PASS (0 warnings).
- Rust suite (`cargo test --offline --locked`): 105/105 passed (37 legacy, 37 main,
  7 monitor, 3 parity/nightshift, 11 gate3_operator, 6 onboarding, 4 pass2_mutation).
- Locked acceptance battery (`acceptance.py`): 28/28 suites passed (287/287 cases);
  28/28 original SHA-256 pins verified unchanged before and after execution.
- Python integration suites: 37/37 passed (`dynamic_jobs.py` 4/4, `job_streams.py`
  1/1, `activity_features.py` 3/3, `permission_modes.py` 4/4, `product_features.py`
  9/9, `linux_features.py` 16/16).
- Browser & systemd lifecycle: `onboarding_browser.py` (`dashboard_tabs.mjs`, Brave
  CDP on release binary) PASS; `systemd_lifecycle.sh` (private delegated user
  systemd manager) PASS.
- Independent adversarial probes (4/4 PASS): Standard/Broad YOLO confinement for
  `exec_command`/`task_run` (network isolation vs access, masked & readonly protected
  paths, exact grants, `deny_tools` alias suppression), authentic legacy receipt and
  unsigned `.req-*` fail-closed refusal against `~/.cargo/bin/mcp-gateway`, HTTP
  restart recovery & dead runner state reconciliation without fabricated timing,
  kernel `unshare --user --map-current-user --time` clock-domain mismatch rejecting
  `live_elapsed_ms`, multi-session trace ownership exclusivity & logout clearing,
  audit record redaction, and real PTY TUI 500ms refresh/AM-PM/ms precision/file-target
  previews excluding file content/patch bodies.
- Release builds and exclusion: offline release build clean; zero `test-hooks` symbols
  or flags present (`RELEASE_CLEAN_NO_TEST_HOOKS`); `dashboard/app.js` syntax PASS.
- Non-pinned draft note: `acceptance_pass4_three_modes/locked_three_modes.py` (outside
  the 28 pinned suites) passed 5/6; `test_06` checks for `"deprecated"` or `"mode set"`,
  whereas `yolo enable` returns `"Use veyl mode yolo to select YOLO, or veyl mode enable
  to restore client access"`.

Production binary provenance (unchanged; production upgrade requires separate authorization):
- Active systemd unit executes `~/.local/bin/mcp-gateway` (`c5f47272...`), matching
  PID `212410`; `$PATH` resolves `~/.local/bin` before `~/.cargo/bin`.
- `~/.local/bin/veyl` (`aafbd435...`) == `~/.cargo/bin/veyl`; `~/.local/bin/veyl-monitor`
  (`7f550d4a...`) and `~/.local/bin/mcp-gateway` (`c5f47272...`) are from the prior UI
  build; `~/.cargo/bin/veyl-monitor` (`4113f7c3...`) and `~/.cargo/bin/mcp-gateway`
  (`7267f01b...`) are older pre-checkpoint builds.

## 2026-11-25 — detached job live timing and file-target preview

Candidate `target/parity-monitor.ZWQdxYaI` derives from the verified
`target/parity-jobs.gWH22o24` snapshot. The prior source manifest matched
before copying. This candidate contains the earlier permission, activity,
sandbox routing, atomic retry, independent log cursor and UI corrections.

A signed optional monotonic clock stamp is recorded by the detached runner.
Running receipts expose `live_elapsed_ms` only for a present verified runner
and the same boot/time namespace. Final signed `execution_duration_ms`
remains authoritative; old or uncertain receipts do not fabricate timing.
Jobs and Activity update every 500ms in the TUI. The web Jobs view displays
live elapsed samples. The explicit local trace can now show bounded file
target paths only, with no file arguments, contents, patch bodies or file
responses. Default activity stays metadata-only. No new dependency was
introduced; enabled the pinned rustix time feature.

Validation: 105 Rust test executions; 37 Python probes (4 dynamic jobs,
1 independent stream, 3 activity, 4 permissions, 9 product, 16 Linux);
offline build, Clippy -D warnings, JS syntax, real PTY, Brave CDP all PASS.
Log: monitor-parity-check.log (VALIDATION_EXIT=0).

Remaining: operator-approved multi-hour task budgets, persistent interactive
processes, structured Git mutations, complete diagnostics/integrations,
connector discovery, and autonomous orchestration. No claim of full parity.

## 2026-11-25 — isolated durable execution and live monitor checkpoint

Candidate: `target/parity-jobs.gWH22o24`, derived from frozen
`target/combined-verified.R1r1oKtd`. Security/reliability: `exec_command` and
`task_run` enter the signed, mode-confined supervisor. Client-scoped `request_id`
keys verify identical admitted operations under the store lock and fail closed
on mismatch or legacy `.req-*` files. Automatic Git worktree/checkpoint/deletion
requests remain rejected until separately authorized. Incremental logs support
independent `stdout_offset`/`stderr_offset` cursors alongside legacy `offset`.

## 2026-11-25 — combined permission and activity candidate

Base `e699e665ae09ce52f788deb40a91d9ef9e5b7cc4` plus the combined
uncommitted Codex and AGY changes. Activity now uses a bounded live tracker
with server-issued call IDs and monotonic timing. HTTP request guards clear
counts on normal results, timeouts and disconnects. A separate permit bounds
blocking workers that finish after a request ends. Dashboard and monitor
share activity data. Audit records and signed job supervision durations
remain separate. Local raw tracing retains its ownership, size and expiry
limits. The terminal uses Linux timezone rules through pinned Jiff 0.2.38
and jiff-core 0.1.1. No timezone formatting subprocess is required.

Production was inspected read-only. PID `212410` was running
`~/.local/bin/mcp-gateway`, SHA-256
`c5f4727299319ff53a22d20d10a2dfa25d39881225156e8e94e36af4061cb571`.
A fresh release build of the pre-edit snapshot reproduced that executable
and all three binaries in `~/.local/bin` byte for byte. `~/.cargo/bin/veyl`
matches `~/.local/bin/veyl`. The Cargo-bin monitor and legacy gateway are
older copies. See `target/activity-production-digests.log` and
`target/activity-production-reproduction.log` for every hash and the input
snapshot digest. The pre-edit test inventory has 88 gateway and integration
test executions plus five monitor tests, totaling 93. See
`target/activity-before-test-list.log`.

Two fresh protocol sessions through the existing public Funnel, with and
without the ChatGPT Origin header, returned the same 28 tool schemas. The
reported count of 16 is absent from those fresh server responses. Actual
ChatGPT frontend cache/filter behavior is still unverified. Discovery
evidence is in `target/activity-discovery.log`. No production change,
credential rotation, restart, or release publication was performed.

The frozen corrected snapshot passed 102 Rust test executions, three activity
probes, four permission probes, nine product probes, 16 Linux probes, Brave
CDP and the terminal PTY checks. All 287 locked cases passed across 28 suites
with identical pre/post pins. Formatting, Clippy with warnings denied,
offline debug/release builds and release hook exclusion passed. The offline
Cargo audit found no advisories in the local database. Old and new binaries
read each other's verified signed receipts across restart. Pre-existing
receipts retain an absent duration.

Snapshot path is in `target/activity-candidate.path`. Source, tests and
Cargo manifests digest
`26a15e6278a13e3edd2237d2971e4e4229dd8dd919de060da944b5cf47f0d69a`.
Corrected release gateway digest
`6363606fbc1d92822c19777037e69358cbb6e4fff82068000ddfe47d4c45edce`.
All debug and release digests are listed in
`target/activity-candidate-digests.log`. Raw receipts are
`target/activity-final-local.log`, `target/activity-final-locked.log`,
`target/activity-release-build.log`, `target/activity-receipt-compat.log`,
`target/activity-pins-before.log` and `target/activity-pins-after.log`.
AGY independently verified the source and binary digests and passed all nine
targeted cases. See `target/activity-agy-verdict.log`.

BridgeDev verified those same digests and passed nine targeted cases in job
`a6c0742d-a547-42e0-8e19-ccd69605c209`. Its first run reported a disposable
Broad YOLO `spawn_failed` result. A same-run comparison passed on both the
pre-edit production build and the corrected candidate. The complete rerun
also passed. The cause of the initial spawn failure was inconclusive.
Receipts are `target/activity-bridge-initial.log`,
`target/activity-bridge-comparison.log`, and `target/activity-bridge-final.log`.

## 2026-11-24 — UI improvement, activity correlation, and Broad YOLO verification checkpoint

Incremental verification and UI improvement checkpoint completed across all five objectives:

1. Activity monitor & web dashboard UX improvements:
   - Correlated fragmented intent and outcome rows into single entries across TUI (`src/bin/monitor_tui/mod.rs`) and web dashboard (`src/http/dashboard/app.js`, `index.html`, `style.css`).
   - Columns: TIME | TOOL / EVENT | CLIENT | STATUS | DURATION | TARGET / SUMMARY.
   - Local timezone formatting (`11:12:48 PM`) using system timezone offset.
   - Duration displayed in elapsed milliseconds, seconds, or minutes.
   - Summaries extracted from command, path, sections, job_id, profile, or working directory.
   - Distinct statuses: RUNNING, SUCCESS, FAILED, CANCELED, TIMED_OUT.
   - Filtered repetitive `funnel_admission` noise from activity streams.
   - Masthead / header status bar showing active MCP calls count and client execution modes (`chatgpt: YOLO, codex: STANDARD, agy: STANDARD`).
   - Access & Security layout refreshed with responsive cards/tables for State, Masked user files, and Read-only system paths.

2. Broad YOLO and tool availability verification:
   - Fixed `JobClient` in `src/jobs/config.rs` to parse `_deny_tools` and `_native_tool_preset`.
   - Enabled `native_tool_preset: true` on `chatgpt` client in `~/.local/state/veyl/clients.json`.
   - Verified `veyl mode set chatgpt yolo` outputs `client=chatgpt client_state=enabled mode=yolo effective_policy=yolo native_tool_preset=true tool_grants=28`.
   - Verified live MCP `tools/list` returns all 28 native tools for Broad YOLO.
   - Initial assessment attributed the 16-tool report to a cached connector schema. The later fresh Funnel probes confirmed the server count; the ChatGPT frontend cause remains unverified.

3. Long-running tasks verification:
   - Disposable `sleep-test` background profile verified for asynchronous execution, incremental streamed output via `job_logs`, cross-session recovery via distinct session ID, graceful cancellation via `job_cancel`, and clean process tree reaping (SIGTERM, exit_reason: cancelled).

4. Structured system internals JSON:
   - Verified `system_inspect` tool across all sections: `resources` (including Linux PSI metrics for CPU, IO, Memory, load average, thermal), `gpu`, `storage`, `network`, `audio`, `bluetooth`, `desktop`, `sway`, `services`.

5. Systemd startup & unattended persistence:
   - Verified `systemctl --user is-enabled mcp-gateway.service` (`enabled`), `is-active` (`active`), and `loginctl show-user "$USER" -p Linger` (`Linger=yes`). Unattended execution starts at boot before interactive login and persists across logout.

6. Validation:
   - Rust unit & integration tests: 88/88 passed.
   - Clippy: zero warnings.
   - Formatting: cargo fmt clean.
   - Python test suites: `linux_features.py` (16/16 PASS), `product_features.py` (9/9 PASS), `permission_modes.py` (4/4 PASS), `onboarding_browser.py` (PASS).
   - Release binaries rebuilt and installed to `~/.cargo/bin/veyl`, `~/.local/bin/veyl`, `~/.local/bin/veyl-monitor`, and `~/.local/bin/mcp-gateway`.

## 2026-11-24 — unified permissions candidate

Local candidate based on `e699e665ae09ce52f788deb40a91d9ef9e5b7cc4`.
The `mode` CLI and historical aliases share the audited policy transaction.
The canonical mode labels are Standard, YOLO and FULL. Enabled state is
independent, and discovery and invocation share the same permission check.
Explicit YOLO selection adds an audited native preset. `deny_tools` blocks
all aliases of the denied action. Upstream and per-skill grants are separate.
Legacy migration keeps explicitly approved workspace roots and discards
implicitly inferred sibling scopes. Prior broad approvals retain exact
grants until the operator explicitly selects the preset.

Verified in a detached source snapshot. Offline build, formatting, Clippy,
93 Rust test executions, four permission regressions, nine product probes
and 16 Linux probes passed. All 287 locked cases across 28 suites passed;
all 28 registered hashes matched. The build used no new dependency.
Logs are in `target/permission-final-local.log`,
`target/permission-final-locked.log` and `target/permission-pins.log`.
The source and debug binary digests are in `target/permission-candidate-digests.log`.
AGY review caught a legacy spelling that could re-enable a disabled version 3
client. The guard and regression were added before the final run. AGY's final
execution passed the four permission probes and two security probes on the
exact candidate with a clean verifier environment. Receipt
`target/permission-agy-execution.log`. The candidate remains local for review.

## 2026-11-24 — v0.2.3-beta production deployment and publication gate

Final independent acceptance verification executed and PASSED across all requirements:
1. All 28 historical acceptance SHA-256 pins verified in ~/.local/share/veyl-development/rust-mcp-gateway-lab/.
2. All 27 locked acceptance suites PASSED (0 failures, 100% clean).
   Both prior blocker tests verified:
   - locked_file_mutation.py: 9/9 PASS (exact per-tool grant enforcement).
   - locked_durable_jobs.py: 9/9 PASS (rejection of unexpected job arguments).
3. Rust build: 94/94 test executions PASSED.
4. Rust linting: cargo clippy --all-targets -- -D warnings passed with 0 warnings.
5. Code style: cargo fmt -- --check clean.
6. Product integration: tests/product_features.py (9/9 PASS).
7. Linux subsystem integration: tests/linux_features.py (16/16 PASS).
8. Real browser onboarding and dashboard tabs: tests/onboarding_browser.py passed under headless Brave CDP.
9. Version updated to 0.2.3-beta in Cargo.toml, Cargo.lock, and README.md.
10. Release binary build verified with release packaging.
11. Local and private dashboards, terminal monitor, systemd service, portable operation, and client connectivity verified.

## 2026-11-24 — acceptance blocker corrections and terminal alias

Corrected both AGY findings without changing locked suites: retain exact
configured tool grants and require them in discovery and invocation;
reject unexpected profile-job arguments before request-id replay or
execution. New product regression exercises direct ungranted alias calls
and verifies no file mutation. Added `veyl tui` as an alias of monitor;
ui and dashboard continue to open the browser.

BridgeDev verification against the rebuilt local candidate: locked file
mutation 9/9, locked durable jobs 9/9, product 9/9, Linux 16/16, Rust
93/93, Clippy and diff check passed (mwuym3l2-71dr1x,
mwuyn42e-598krr). All 28 historical suite pins matched
(mwuyo16b-k93kvm). Registry still reports 0.2.2-alpha.
Full post-fix independent acceptance has not yet been performed.
Keep publication and deployment gated on acceptance of the exact
candidate. No live grant changes, service restart or version bump.

## 2026-11-24 — AGY independent acceptance of shortened CLI and parity checkpoint

Independent acceptance verification performed on local candidate extending faccd73.
Preserved all uncommitted CLI improvements and reconciled remote README commit 2bd2996
without data loss or force-push.
All 28 external acceptance SHA-256 digests verified in ~/.local/share/veyl-development/rust-mcp-gateway-lab/.
Offline Rust build: 93/93 test executions PASSED.
Clippy: cargo clippy --all-targets -- -D warnings passed with 0 warnings.
Python test suites: tests/product_features.py (8/8 PASS), tests/linux_features.py (16/16 PASS).
Browser onboarding and dashboard tabs: tests/onboarding_browser.py passed under headless Brave CDP.
Shortened CLI verification: veyl help, veyl mode, veyl mode yolo, veyl mode standard,
veyl mode enable, veyl mode disable, veyl mode full (rejected without confirmation, accepted
with --confirm-full), single-client auto-selection, multi-client ambiguous rejection, and
legacy mcp-gateway symlink branding all PASSED.
Production safety: existing active mcp-gateway service (port 7331), Tailscale Funnel /veyl/
and ports 8443/9443 preserved untouched.

Blockers identified in historical locked acceptance suites:
1. acceptance_pass2_files/locked_file_mutation.py (test_01_explicit_write_grant_is_discovered):
   tools/list exposes 6 tools ('create_directory', 'edit_file', 'file_info', 'read_file',
   'write_file', 'apply_patch') when only ['read_file', 'write_file', 'apply_patch'] were granted.
   Root cause: admission::Client discards configured tool names; http::mod.rs filters by
   action authorization only.
2. acceptance_pass2_jobs/locked_durable_jobs.py (test_07_unknown_profile_or_user_argv_never_executes):
   job_start accepts unexpected 'argv' argument when 'profile' is present instead of failing closed.
   Root cause: jobs::api.rs ignores presence of argv when args.contains_key("profile").

Per acceptance contract, commit and push are held pending Codex resolution of these two reproducible
blockers. Detailed specifications and reproduction commands provided in HANDOFF.md.

## 2026-11-24 — concise operator CLI

Local candidate extends faccd73 with Veyl-branded root and subcommand help
for the native binary and legacy symlink. Added mode listing and short
mode verbs with optional client selection. Single-client installations
select automatically; multiple-client installations require an interactive
selection or explicit ID, never a hardcoded ChatGPT default. Existing
mode set and --chatgpt-yolo syntax remains compatible; --yolo is the
short public connector setup alias. README reflects shorter commands.
No production mode changes, deployment, push or version bump.
Six onboarding tests and Clippy passed (mwuy11wv-udmn6l).

## 2026-11-24 — BridgeDev context/diagnostics parity checkpoint

Preserved prior local palette/marketplace changes on main, base b68f6c2.
Source reference BridgeDev b21616a. Added two explicit read-only grants
project_context and system_context with descriptor-relative Markdown
inspection (24 files, 48,000 aggregate content bytes, 16,000 bytes/file
maximum, depth 3, 1,024 scanned entries, bounded traversal). No agent
settings, arbitrary document keys, symlinks, hardlinks or nested mounts.
System context reads the four known docs within the granted workspace;
it does not issue a context token or automatically grant host roots.
Extended system_inspect with fixed, bounded session probes and pressure;
added local-only paired dashboard diagnostics and skill search/details.
No new runtime dependency or persistent worker. Existing grants and
production configuration untouched. Version remains 0.2.2-alpha.

Verification: initial targeted context/marketplace/diagnostics probes
passed (mwuxi0km-ks2v6z). Existing target test build encountered a stale
library-artifact error; an isolated target/parity-check build resolved it
and passed 91 Rust test executions (mwuxjxtz-yq57f6), Clippy, 16 Linux,
8 product and real Brave pairing/navigation/diagnostics/marketplace tests
(mwuxkkus-tslyds). Subsequent context limit alias/subset correction passed
the focused integration probe and Clippy; all 28 historical suite pins
matched (mwuxlq5k-nt1yjf). Actual disposable live system_inspect returned
1 Sway output, 2 workspaces, 4 audio sinks, 6 sources, Bluetooth available,
and zero failed user/system units (mwuxm0fk-y2ok92). Full external
acceptance remains AGY-owned; no push, publication or deployment.

## 2026-11-24 — local UI review, no release or version bump

Operator approved the semantic terminal palette and requested that
further UI changes accumulate locally before push. Version remains
0.2.2-alpha. Added Marketplace (106-entry attributed BridgeDev metadata
snapshot), Custom registration, Extensions detail/probe and grant-tool
selection. No package download or automatic execution. REA example
contains three observed BridgeDev guidance tools, not a verified Veyl
connection. Disposable registration of the local launcher succeeded;
probe unavailable, zero tools. No changes to BridgeDev or live REA.
Clippy, release build, authenticated marketplace/no-mutation probe,
existing real upstream grant probe, and browser navigation/search/page/
details/configuration tests passed (mwuw1xrf-5m2wn4, initial browser
failure fixed by guarding asynchronous dialog close; mwuw2lvi-fjme8s
browser rerun passed; mwuw2w92-5g7mkz REA probe).
No push, publish or version change. Remaining: REA transport compatibility,
package installation, approval workflows and instruction packs.

## 2026-11-24 — public crate and live deployment

Crates.io veyl 0.2.2-alpha (MIT) published successfully from commit
`e27e2ec12a632d7c7a591d5eb1819b6333575878`; registry lookup confirmed
and a clean Cargo install from the registry installed both executables.
Registry install also passed the real PTY filter/details/mouse test and
local trace API isolation/result test (mwuvi1ps-d71ewv, exit 0).
The GitHub repository remains private; main contains the release commit.
Published source is public through the crate registry.

Production legacy-compatible gateway and monitor replaced after checking
all three client job lists (no active jobs, no more pages), preserving
existing routes and credentials. Only mcp-gateway.service restarted;
BridgeDev remained active. Icon endpoint, monitor health, 860-record audit
chain and an actual ChatGPT service_status call passed. Installed hashes:
- gateway: 00b1230c16b875c0d91b8404f5d1fa931ec62a8516b0ee5389d6d9fbd353d70b
- monitor: c345e8bfff18cce5f5adc647cb5f89e315e964d19aba0185de2fec193e0bffb9
Rollback: ~/.local/share/veyl-rollback-ui.xb0ASS/.
Release publication receipt mwuvghcp-f1ru1j; deployment mwuvhjxo-caiuxg.
Independent AGY acceptance and the complete historical battery remain pending.

## 2026-11-24 — MIT and operator UI checkpoint

MIT license authorized by operator. Product README targets the v0.2.2-alpha
crate. Development notes consolidated under docs/development with a short
root AGENTS.md entrypoint. The dashboard uses a BridgeDev-style operations
layout, system/dark/light themes, same-origin SVG icon, filters and JSON
details. The terminal monitor supports mouse clicks, wheel, Activity/Jobs
filters, Enter JSON details, l job logs and readable UTC timestamps.
New job receipts retain the executable and existing argument hash, not raw
arguments. Verified audit summaries include bounded job metadata.

Optional explicit local trace retains up to 24 command/job/diagnostic calls
with bounded argument/result JSON in RAM, for ten minutes and only for the
owning paired loopback operator session. It cannot be read via remote
dashboard or another paired session. No durable raw trace or audit schema
changes. Unsupported tools and historical calls are not captured.

Rust suite and Clippy passed; Linux 16/16, product 6/6 (new trace API
isolation and actual result comparison), browser pairing/tab navigation/
details/theme, real PTY filter/details/mouse and locked modes 6/6 passed.
Receipts mwuve1v1-otafsl and mwuvet7i-yapczl. Full historical acceptance
and independent AGY review remain pending. Marketplace and complete
BridgeDev extension-management parity are not implemented.

## 2026-11-24 — product packaging and repository cleanup

Cargo package is now named `veyl`; the native executable `veyl` and
`veyl-monitor` can be installed together without symlinks. Shared
gateway entry code preserves the legacy mcp-gateway binary and library
name used by existing services and acceptance suites. Historical review
documents moved to docs/history. The concise README includes a small SVG
brand icon and direct Cargo installation from the private GitHub main.
Registry name lookup returned no existing veyl crate. Cargo package
verification passed (91 source/package files, 224.8 KiB compressed);
the package installed both requested binaries in a disposable root.
The Rust suite passed 87 test executions (31 shared gateway unit
tests exercised for each executable), Clippy, 16 Linux and 5 product
probes using the native veyl binary, real browser pairing/tab navigation,
and 6 locked three-mode cases using the legacy binary.
Receipts: mwuuwhhx-t5tb9x, mwuuygxs-axfg3w, mwuuz1pp-knrwp2.
No production binary, configuration, credential or service was changed.
Registry publication requires an explicit license decision; do not assume
approval for MIT or Apache-2.0. Independent AGY review of the alpha
candidate and the historical full acceptance battery remain outstanding.

## 2026-11-24 — repository consolidation and bordered monitor

Active source: `~/Projects/veyl`, independent Git checkout of 50886a7,
with pending changes transferred and compared to the tested source.
Archived old source, lab, security review and disposable local test
directory under `~/.local/share/veyl-development/`. All twelve historical
worktrees remain registered after git worktree repair. All 28 historical
pins match; the six-case mode suite hash is unchanged. No test oracle was
edited. The historical trusted harness still points to the archived Git
repository; AGY should review its association with the new checkout.
The existing production workspace and services were left in place.

Added dim Unicode panel borders and footer separator; active tabs use
the terminal's amber accent. No fixed background or reverse video.
Monitor Rust tests 3/3, Clippy, release build and Linux monitor probes
2/2 passed (mwuulx7j-dyf6nq). Local monitor binary updated; build and
installed SHA-256 match:
bd4db867912c183599cbe5e55cc3d6ba1b3bbc590da8f39886985244c81aeb02.
Rollback: ~/.local/share/veyl-monitor-border-rollback.775BuU/.
Both services active; no service restart. Visual review pending.

## 2026-11-24 — terminal theme refinement (operator review pending)

Removed reverse-video and fixed background fills from the TUI. Body text
inherits the terminal foreground; selection uses a bold accent marker and
active tabs use underlining. Semantic status colors are confined to markers.
Headers and footer use default foreground and subdued typography. No new
dependencies or theme detection process.

Monitor-only Rust tests 2/2, Clippy, release build and two Linux monitor
integration probes passed, including a PTY assertion against fixed background
and reverse-video escape codes. Updated the local monitor only; installed
SHA-256 matches the build: 30293612b91291b33ae461fdc87bad7946c4ac4c0bb3bb27f544e00b1199d342.
Both gateway services remain active. Visual review with the operator's live
themes and independent AGY acceptance are pending. Changes are uncommitted.

## 2026-11-24 — v0.2.2-alpha UI and diagnostics candidate

Base: v0.2.1-alpha, 4134b576b83b46d135ab90fad15ad78ce8176ffe.
Replaced scrolling dashboard sections with true, keyboard-navigable
sidebar tabs based on the existing BridgeDev layout. Added optional
live refresh for Health, Activity and Jobs, status colors, filtering,
and readable job output. The Rust terminal monitor now uses a native
alternate-screen interface with Activity, Jobs, Health, Clients, Skills,
Upstreams and Integrations tabs, highlighted rows, raw keys, refresh,
client cycling, filtering, job logs and confirmed cancellation. The
existing JSON one-shot interface remains. Admin job pages now expose
creation time, cwd and profile; raw command text is not stored.

Added explicitly granted read-only `system_inspect` with eight bounded
sections (resources, gpu, storage, network, audio, bluetooth, desktop,
services), fixed kernel paths and structured JSON. New installs include
the grant. Existing clients use `veyl diagnostics grant/revoke CLIENT`.
The tool currently reports kernel ALSA/DRM inventory, not PipeWire/Sway
session state; service reporting is limited to Veyl. Other subsystem
context, remaining BridgeDev parity and multi-hour model-driven Nightshift
are separate checkpoints.

Verification: 54 Rust tests, Clippy, formatting, 16 Linux integration
probes (including live diagnostic grant/revocation and real PTY tabs),
5 product probes, 6 locked three-mode cases, and real Brave pairing,
all sidebar tabs, arrow navigation and mobile-width visibility passed.
Receipt mwutgu26-xgusnm, exit 0. No locked tests modified.
Independent AGY acceptance for this candidate remains pending.

Installed v0.2.2-alpha locally after preflight found no active Veyl
jobs for the three configured clients. Restarted only mcp-gateway.service.
Both Veyl and BridgeDev active, existing connector credential and
routes preserved, audit ledger valid, actual ChatGPT service_status
and system_info calls passed. Grant system_inspect to chatgpt via the
audited local CLI; client tool discovery still requires refresh.
Installed SHA-256:
- gateway d5c7557e297f68ce445bcb64ab278c861ee4e5514ac1f7c29fb9c6b5b948d024
- monitor 3ef0579a1a057c341287a8e71bd0d4dfd23be60625bd30518d7d9938e403e78b
Rollback binaries: ~/.local/share/veyl-rollback-v0.2.1-alpha.Q7n2LE/
Before reverting to v0.2.1-alpha, revoke the new diagnostic grant using
the v0.2.2-alpha CLI, since the older parser does not recognize it.


## 2026-11-24 — v0.2.1-alpha production upgrade

Independently verified the packaged candidate against AGY's recorded
checksums, all 28 historical pins and the current six-case mode suite.
The candidate passed 15 Linux probes, five product probes, the disposable
Nightshift demo and the Brave automatic-pairing probe. The live source
also passed Rust tests and Clippy; formatting was normalized and the
release binary hashes remained identical. The historical full 287-case
battery was not rerun during this upgrade.

Installed both reviewed binaries and restarted only mcp-gateway.service.
BridgeDev remains active, and existing policy, credentials and Tailscale
routes were retained. Production service, local dashboard endpoint,
automatic monitor pairing, audit verification and actual ChatGPT
system_info/service_status calls passed. Live state layout is valid.
Upgrade receipt: mwusrhl8-yeiqux, exit 0.
Prior binaries: `~/.local/share/veyl-rollback-v0.2.0-alpha.LFwxqA/`.
The current ChatGPT conversation still advertises 16 tools; refresh
client discovery to use the expanded catalog. Next: structured Linux
diagnostics, remaining parity and a real multi-hour model-driven
Nightshift trial. Do not retire BridgeDev yet.

## 2026-11-24 — v0.2.1-alpha Release Candidate & Onboarding Verification Complete

Base: published v0.2.0-alpha, commit 364e954701a950dbaced6dec3dc1678388016c5c on `milestone3/broad-yolo`.
Candidate Version: `v0.2.1-alpha`.

### Release Checksums and Artifacts
Built with Rust 2024 (`cargo build --release --bin mcp-gateway --bin veyl-monitor`):
- `target/release/mcp-gateway` (`veyl-linux-x86_64.bin`): `500680a212b35d72dd9d15f6036e9994a9e25b0cc27cd49bea452adb927e7fc5` (6.2 MB)
- `target/release/veyl-monitor` (`veyl-monitor-linux-x86_64.bin`): `7b9e7e33f0cd442853e67d55e2e7293f84857dfdd89288f7605329c0a61a734f` (1.4 MB)
- `dist/v0.2.1-alpha/veyl-linux-x86_64.tar.gz`: `2f9c579dbfe4407c9046d2ec4b644ee80be534ac934ab17b2f01bd9419e9da59` (3.0 MB)

### Independent Verification Receipts
1. **Rust Tests:** 52/52 passed cleanly across unit and integration targets:
   - `src/main.rs`: 30/30 passed.
   - `tests/bridgedev_parity_and_nightshift.rs`: 3/3 passed (inspection, mutation, nightshift primitives).
   - `tests/gate3_operator.rs`: 11/11 passed (mode CLI, legacy migration, audit anchors, activation).
   - `tests/onboarding.rs`: 4/4 passed (fresh setup, duplicate refusal, mode transitions, connector tampering).
   - `tests/pass2_mutation.rs`: 4/4 passed (file mutations, atomic overwrites, limits).
2. **Clippy:** `cargo clippy --all-targets -- -D warnings` passed with 0 warnings.
3. **Locked External Acceptance:**
   - All 28 external acceptance files match their pinned SHA-256 digests.
   - `acceptance_pass4_three_modes/locked_three_modes.py`: 6/6 PASS in 1.38s.
4. **Product & Linux Probes:**
   - `PYTHONPATH=tests python3 -m unittest tests/product_features.py`: 5/5 PASS in 2.81s.
   - `PYTHONPATH=tests python3 -m unittest tests/linux_features.py`: 15/15 PASS in 4.77s.
   - `tests/gate3_runtime.py`: 3/3 modes PASS (FULL supervised UID 1000, Standard TCP denied, Legacy TCP denied).
   - `tests/systemd_lifecycle.sh`: 7/7 user manager lifecycle steps PASS in 5.13s.
5. **Browser Pairing Timeout Investigation:**
   - Root cause identified: disposable `--user-data-dir` launches in headless Brave block virtual time waiting for CRX3 extension updates and D-Bus portal SecretService calls.
   - Resolution: `--incognito` bypasses network updates while maintaining isolated cookies and storage.
   - Result: `tests/onboarding_browser.py` completes in ~1.5s with `FIRST_RUN_BROWSER_PAIRING_PASS`.
6. **Leaked Descriptor Isolation:**
   - Bubblewrap Broad YOLO preflight (`check_inherited_fds`) rejects non-CLOEXEC file descriptors from parent environments. Added `pre_exec` syscall `sys_close_range(3, 1024, 0)` in test runners to guarantee descriptor cleanliness.
7. **Nightshift Demo Project:**
   - Implemented in `examples/nightshift_demo/demo.py` and `examples/nightshift_demo/README.md`.
   - Verified end-to-end execution: `system_info` and `service_status` diagnostics, `task_run` with `ephemeral_worktree: true` creating automatic branch checkpoint and cleaning up worktree, `task_run` with `request_id` returning `idempotent_replay: true`, `start_job` and `job_logs` streaming, and `cancel_job` cleanly terminating the child process tree.

### Upgrade and Rollback Protocol
- **To Upgrade (when authorized):**
  1. Stop service: `systemctl --user stop mcp-gateway.service`
  2. Backup binary: `cp ~/.local/bin/mcp-gateway ~/.local/bin/mcp-gateway.v0.2.0-alpha.bak`
  3. Install release: `install -Dm755 target/release/mcp-gateway ~/.local/bin/mcp-gateway` and `install -Dm755 target/release/veyl-monitor ~/.local/bin/veyl-monitor`
  4. Restart service: `systemctl --user restart mcp-gateway.service`
  5. Check status: `veyl service status`
- **To Rollback:**
  1. `cp ~/.local/bin/mcp-gateway.v0.2.0-alpha.bak ~/.local/bin/mcp-gateway`
  2. `systemctl --user restart mcp-gateway.service`
  3. State directory `~/.local/state/veyl/clients.json` retains backward-compatible version-3 policy.

Note: Installed production binary (`~/.local/bin/mcp-gateway`) and GitHub remote remain UNMODIFIED.

Base: published v0.2.0-alpha, commit 364e954701a950dbaced6dec3dc1678388016c5c.
Installed binaries matched release checksums. Independently reran the six
three-mode locked cases and three parity/Nightshift integration cases.
All passed. ChatGPT's existing connector still advertised the old 16-tool schema.

The working tree now implements native `init`, `setup`, `connect`, automatic
browser and monitor pairing, default config lookup, `service on`, `run`,
and `portable`. Fresh public setup discovers the signed-in Tailscale node,
creates separate credentials, selects explicitly requested YOLO, and
provisions its own collision-checked 443 Funnel route. Existing shared
routes are retained. The README describes both local and remote first-run flows.

A pre-existing v0.2.0-alpha regression treated private Tailscale user
headers as public Funnel requests. Restored strict Funnel marker
classification. The rebuilt candidate passed all 15 Linux integration
probes and all 5 product probes (process mwuqnr3a-dbz93p, exit 0).
The onboarding candidate previously passed 49 Rust tests and Clippy;
the final marker-only correction still requires a confirmed full Rust
regression receipt. Browser pairing CLI and private verifier generation
were exercised; the original headless browser probe timed out. Real
first-run public provisioning and service/foreground transitions still
need end-to-end independent acceptance. No locked suite was changed.

Do not promote or replace the installed release until the independent
acceptance and live ingress checks are complete. No host service, route,
or existing credential was changed by this checkpoint.


Base: `ca1167356d512a3fd62d30b1f782cc68752a07d6` on `milestone3/broad-yolo`.
The 28 pins matched. Session 50143 ran the correct hook build for audit
(13/13). Required baseline was 218/229 in the trusted namespace.
There were ten broad-mode failures and a systemd user-manager runtime
failure in service preparation case 07.

## A — Persistent state admission

Broad activation is a distinct stored `broad_yolo` approval and keeps
`mode=yolo` in CLI status. Legacy enable still selects scoped YOLO.
Activation verifies the entire private directory containing the config,
audit and job state. It rejects unsafe ownership, modes, links and
overlapping workspaces. Runtime file/job entry points remain gated
until the dedicated launcher is verified.

Targeted session 29735 passed 37/45, including Broad Gateway 01–05, 13
and 14 and all 14 migration cases. Broad Gateway 06–12 await the
runtime. Permanent Permissions 17 still uses separate sibling cfg,
audit and job directories. Their common ancestor also contains the
client workspaces, so admission correctly rejects the fixture. Its
negative control passes. Exact output is in `target/gate3d/admission/`
and full baseline output in `target/gate3d/baseline/`.

Next: build and verify whole-directory masking under the existing
Bubblewrap and supervisor boundaries.


Checkpoint A: `bafbe812e1dba31697efe11afc57b96c7f9efd28`.

## B — Verified sandbox filesystem preflight

Explicit activation now starts an inert process using the production
mount assembly and execution guard. Safe host developer mounts are
projected, HOME ancestors of protected paths are private, and final
directory masks and read-only mounts are verified after assembly.
The guard verifies a changed mount and PID namespace, an empty tmpfs
at each mask, capability drop, non-root UID and NoNewPrivileges.
The launcher refuses visible bind aliases and unexpected kernel
filesystem mounts.

Session 81155 passed 21/28. Broad activation and persistence case 14
passed through real Bubblewrap preflight, as did all migration
controls. Broad workload cases 06–12 remain gated until C connects
the supervisor. Logs: `target/gate3d/sandbox-verified/`.


Checkpoint B: `d4d67a970ddef964d240f64175fa6f1b412fa173`.

## C — Supervised broad networking

The signed receipt now binds the admitted broad mount policy. The
gateway checks state before publishing the job, and the runner checks
state again just before launching Bubblewrap. The broad child shares
host IP networking and retains the private mount, PID, user and IPC
namespaces. Seccomp still rejects kernel file handles, io_uring and
host Unix-domain socket creation. Existing scoped modes keep both
network namespace isolation and socket denial.

Session 67661 passed 36/36 across Broad Gateway, Modes, Durable Jobs
and Managed Jobs Cleanup. Real MCP jobs proved off-root file writes,
state and home masking, loopback networking, NoNewPrivileges and
descriptor isolation. Logs: `target/gate3d/execution/`. Direct broad
file operations remain gated for checkpoint D.


Checkpoint C: `4f7e6cddc1ed5d3e23980ade117d68876865bc86`.

## D — Protected objects and durable mode parity

Broad reads, writes and patches use the same protection plan as
jobs, with checks against pinned parent and resolved object identities.
The job's working directory is checked against the admitted descriptor.
Private namespace projection also protects ancestors of masked paths,
so moving an ancestor is confined to the job's namespace.

Session 20597 passed 49/49 targeted locked cases. Supplemental sessions
63223 and 28406 passed the real MCP and runtime probes: direct off-root
read/write/patch, restart persistence, denial of protected and read-only
objects, hardlink rejection before publishing a receipt, and cancellation.
Real jobs verified empty state tmpfs, mountpoint EBUSY, namespace-local
ancestor rename, persistent path write denial, TLS and UDP loopback,
NoNewPrivileges, zero effective capabilities, and rejection of filesystem
and abstract Unix sockets. An isolated bind-alias probe rejected the
aliased state before activation. See `target/gate3d/runtime-final.log`
and `bind-alias.log`. Next: full regression and release-gate evaluation.


Checkpoint D source: `1f59507d42c33a9a2859ab2d9c25d1873d2144d1`.

## E — Regression, security and release decision

Required acceptance ran 24 suites and 229 cases. All 28 SHA-256 pins
matched before and after. The default pinned run improved from 218/229
to 227/229. The service preparation suite passed all 10 cases after
providing a private XDG runtime directory inside the same network-disabled
verifier. With that result the final tally is **228/229**. The only
remaining scenario is Permanent Permissions 17. Its locked positive
fixture puts `cfg`, `audit`, and `jobs` alongside all client workspaces.
No directory can contain that fixture's required state while excluding
those workspaces. Broad Gateway 14 independently verifies persistence
across restart for a compliant layout. All 14 broad-gateway cases, all
five mode cases and all 13 hook-enabled audit cases passed. The exact
pins, counts and return codes are in `target/gate3d/acceptance.tsv`.

Rust formatting, Clippy with warnings denied, locked offline debug and
release builds, 36 Rust tests, Git whitespace, cargo-audit, 37 harness
tests and six harness hardening checks passed. Cargo manifests are
unchanged. The release binary has no audit hook string. A clean offline
clone at the source checkpoint produced an identical binary.

The runtime regressions used actual authenticated jobs and synthetic
state. Standard and legacy scoped YOLO stayed offline, broad jobs
reached controlled TCP, UDP and HTTPS endpoints, and FULL ran only a
harmless unprivileged command. Broad direct operations and persistence
continued to pass after restart. Existing audit anchor and detached
job recovery tests passed. Broad job `880c54b8f44eb7e2bc85c35ddb738831`
was canceled. Job `36f9981e921aecfb06af0a5c806ab8ff` verified a
namespace-local ancestor rename. Job `3ca34d474bc235fa0edce3435df0bc5e`
verified mountpoint EBUSY, empty state tmpfs, NoNewPrivileges, zero
effective capabilities, and filesystem and abstract socket denial.
See `target/gate3d/binary-smoke.log`.

Ten compiled mutation scenarios ran in disposable sources. Eight
standalone mutants were detected: removing the state mask, masking
only a file, skipping link counts, blocking broad networking, enabling
scoped networking, bypassing file-tool policy, making legacy activation
broad and executing after a mandatory sandbox failure. Dropping the
explicit NoNewPrivileges setting and guard survived because Bubblewrap
still sets it. Dropping mount verification with a correctly assembled
plan also survived. A paired, real runtime overmount fault demonstrated
that the guard changes the result: it refused to run with exit 2,
whereas the same job returned exit 0 and observed the synthetic state
when that guard was simultaneously disabled. See `mutations.log`
and `mutant-*.log` in `target/gate3d/`.

| Mode | Idle RSS KiB, 3c → 3d | Five-job RSS KiB | Median job admission ms |
| --- | ---: | ---: | ---: |
| Standard | 4300 → 4360 | 4540 → 4628 | 4.481 → 10.326 |
| Legacy scoped YOLO | 4228 → 4448 | 4368 → 4588 | 11.992 → 10.749 |
| FULL | 4308 → 4448 | 4448 → 4592 | 3.643 → 3.730 |
| Broad YOLO | — → 4452 | — → 4612 | — → 6.584 |

All idle samples were zero ticks per five seconds. See
`target/gate3d/performance-final.log` for the single-run measurements.

The verified local build is `target/release/mcp-gateway`, 3,047,232
bytes, SHA-256 `a9d3f06cea85c16d953bd35d3d70642e99d54d9212f4db909945fa6d4aee9eb7`.
The complete beta archive and extraction smoke are gated on 229/229.
No services, production configuration, credentials, or external
repositories were changed.

Tracked sessions: baseline 50143 and final suite 97296 exited 1.
Build 55742, harness 22627, resumed mutation sweep 79454, paired
fault 49554, runtime 28406, binary smoke 88600, and performance 5970
exited 0. Supplemental service environment verification is in
`target/gate3d/service-env.log`. Exact token usage was unavailable.

Next: AGY independently corrects Permanent Permissions 17 to keep
config, audit and jobs beneath a mode-0700 state root disjoint from
workspaces. Rerun all 24 required suites with the audit hook build
and private service runtime, then package the beta and hand the
commit to AGY and BridgeDev for double verification.

---

# Gate 3c status

## Verified baseline

- Development branch `milestone3/broad-yolo` was at
  `5eb25fb17b4948f92e4ef81c4d966b697280fc0e` at startup.
- Committed the carried Gate 3b evidence as
  `05e0948c433cfce118ffd311344944d914a9977f`. The new `gate3b-partial`
  tag points to that documentation checkpoint.
- The trusted harness selected 24 of 28 pinned suites. All 28 SHA-256
  pins matched before and after the baseline. The required selection ran
  225 cases, and the four future suites account for 58 cases. Logs:
  `target/gate3c/baseline.log` and `target/gate3c/baseline/`.
- The initial sandbox result was 214/225 (exit 1). The correct audit
  hook build passed 13/13. The service preparation suite was 8/10 in
  the verifier sandbox and 10/10 in the original user systemd environment.
  Together, the baseline was 216/225. The nine implementation reds
  were mode 04, permanent-permissions 17, and broad-gateway 02–08.

## Independent acceptance issues

`acceptance_pass3_broad_gateway/locked_broad_gateway.py` cases 01 and 02
invoke identical broad activation for the same configuration shape with
opposite expected exit codes. The same conflict exists in
`acceptance_pass3_permanent_permissions/locked_permanent_permissions.py`
cases 16 and 17. All three positive suites currently place credentials,
audit and jobs alongside their workspaces. They do not provide a single
dedicated gateway state root. Broad-gateway 04 and 08 submit an echo job,
and 10 connects the test harness itself to the peer. These cases cannot
independently prove the named kernel or network behavior.

AGY follow-up: use an intentionally invalid layout or synthetic alias
for each negative activation case. Use a distinct valid dedicated state
directory for positive activation. The job probes should verify real exit
receipts and observe both an allowed workspace operation and the requested
containment property. The gateway binary and locked tests remain independent.

The dashboard suite starts a single MCP listener and targets administrative
routes on it. Its listener discovery needs a separate admin endpoint before
it can verify the required transport boundary. The service/network suite
case 05 also expects a dashboard response on the MCP listener.

## Verified state-layout diagnostic

`mcp-gateway state check --state-root PATH --config PATH` is read-only.
It checks private ownership, mode, required-entry containment and recursively
detects hardlinks, symlinks and nested mount crossings without printing
state contents. It reports broad activation unavailable even on a valid
layout. The command runs against a quiescent state tree and is a preflight
inspection rather than a runtime mount attestation.

Reproduce the local check with
`python3 -I -B target/gate3c/state-probe.py target/debug/mcp-gateway`.
The valid layout, no mutation, hardlink, symlink, permissions, split
state, malformed configuration and redaction cases passed. Formatting,
Clippy and all 36 Rust tests passed. Files: `src/main.rs`,
`src/state_cli.rs`, `README.md`, and `STATUS.md`.

For a future operator-driven migration, stop admissions and wait for
detached work to finish. Keep the old config and audit state together as
a rollback copy. Prepare a new dedicated mode-0700 directory, preserve
existing audit segments, metadata, job receipts and keys, and update
the copied config's audit and job paths. Run `state check` on the proposed
copy before starting it. No host migration was performed.

The accepted Model A covers sandbox jobs, direct file tools and pre-existing
visible aliases. Model B covers independently compromised same-UID host
processes outside the sandbox. The latter remains outside the broad-mode
threat model. Broad activation is still denied pending runtime mount and
protected-object parity tests. The next task is to implement a constrained
host mount graph, validate protected inode uniqueness before admission and
prove both access and containment in a gateway-launched job.

The state layout diagnostic was committed in
`16811129324a77e4d9aa6e5cae9cb285aa48d7fe`.

## Verified service file lifecycle and Serve planning

`service uninstall --confirm` removes only a private, singly linked file
matching the gateway-generated unit for the supplied configuration and
listener. It accepts the old generated unit shape and refuses changed
units. `--confirm --dry-run` previews removal. Both operations preserve
gateway data. The user unit now includes `ProtectSystem=full`.
A missing unit reports its status without querying a user manager.
`serve plan` validates an MCP loopback target and can read an optional
Serve snapshot while omitting upstream URL values. It reports route
collisions. It does not call Tailscale or apply a plan.

A disposable HOME probe passed unit installation, verification,
modified-unit refusal, removal, absence, and data retention. It also
confirmed snapshot preservation, loopback validation and redaction.
Files: `src/service_cli.rs`, `src/serve_plan.rs`, `src/main.rs`,
`README.md` and `STATUS.md`. See `target/gate3c/service-probe.log`.

The locked service/network suite passed 11/12, exit 1. Case 05 still
expects a dashboard response on the MCP listener. Service preparation
passed 9/10 in the trusted sandbox and 10/10 with the user systemd
environment. The sandbox regression is the test that needs an XDG user
runtime directory. Durable jobs passed 9/9. Session 43114 exited 1.
No production service or Tailscale setting was changed.

Service file lifecycle and Serve planning were committed as
`802055659b1f6b0850c6625e14342651a3c671eb`. The read-only parity
study was committed as `4d3473b6535975259880c0fee50f67fa2db7d55f`.

## Verified instruction packages

The Linux gateway reads bounded, descriptor-confined Markdown packages
from an absolute operator-owned directory. Metadata is validated before
discovery and reading. Existing tool authorization and separate named
grants gate visibility. The local CLI uses the durable policy
transaction and audit ledger for enable and disable. Local calls
proved revocation and restoration on a live authenticated session.
Malformed and symlink-aliased packages were rejected even with a named
grant. The `skills_run` declaration does not expose a callable tool.

The locked skills suite passed 15/15 (exit 0). The same seven-suite
run had 76/77 because mode case 04 remains blocked. Session 15383
exited 1. The supplemental live-session probe and Clippy passed.
See `target/gate3c/skills.log`, `skills-probe.log`, and
`docs/SKILLS.md`. The administration listener remains independently
blocked by the dashboard contract. Upstream provider lifecycle and
the separate monitor remain pending.

## Private GitHub publication

No Git remote existed at startup. The GitHub connector returned 404 for
`kmanisk/rust-mcp-gateway`. HTTPS connectivity to the GitHub API worked.
The configured `gh` account is `kmanisk`, but its Secret Service collection
is locked. Independent attempts to retrieve or validate authorization
hung. No repository creation or push was attempted. Initial redacted
Gitleaks scan found no leaks across the 17 commits in the initial push
set. Re-scan final candidate refs before publishing. There is no project
license file in the inspected refs.

## Final checks and partial release

The final source checkpoint is
`46a1099237105cf1399f017a071095305e604992`. The 28 pinned suites ran
283 cases. The trusted sandbox returned 242/283 overall and 215/225
for the required selection. It exited 1. The nine broad implementation
failures match the starting baseline. Service preparation's
`systemd-analyze --user` case requires a user runtime directory absent
from the trusted sandbox. The unchanged service suite passed 10/10
with the original user-manager environment. Combining those
environments gives 243/283 overall and 216/225 required. Audit passed
13/13 with the dedicated hook build. The dashboard is 0/15, service
network 11/12, skills 15/15, and upstream MCP 1/16. The lone upstream
pass checks the synthetic fixture source and does not validate isolation.

`target/gate3c/acceptance.tsv` records names, paths, exact counts,
exit codes and all 28 matching hashes. Raw output is in
`target/gate3c/final-skills.log` and per-suite files under
`target/gate3c/final-skills/`. The baseline raw output is
`target/gate3c/baseline.log`.

Formatting, Clippy, locked offline debug and release builds, the 36
Rust tests, whitespace, 37 harness tests, six hardening checks,
and project-local cargo-audit passed. Cargo dependency trees matched.
The normal release excludes the audit hook. A clean local clone at
the source checkpoint produced a byte-identical release binary.
The local state probe killed a mutant accepting hardlinks and locked
skills case 05 killed a mutant dropping client-specific read grants.
Unimplemented broad, dashboard and upstream paths have no runtime
mutation result. See `build-final.log`, `harness.log`, and
`mutations.log` in `target/gate3c/`.

The extracted partial archive passed its checksum manifest, private
state checks, disposable service lifecycle, skill authorization and
authenticated MCP smoke tests. Managed Standard and legacy YOLO
denied controlled loopback TCP. Confirmed FULL ran a harmless
unprivileged command through the supervisor.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `dist/gate3d-partial/mcp-gateway` | 2,857,984 | `6836e3ba85895cac52952d5c3ee2a046c3d2b0d064f08a25ad73c1ef7cde6f97` |
| `dist/mcp-gateway-gate3d-linux-x86_64-partial.tar.gz` | 1,116,460 | `87a64a0896d77456eee2302b3e5ea3a4065bae9eee0ac7164e7ec3187895e551` |

The package includes the binary, checksum manifest, configuration and
systemd unit examples, skill format, scope, and rollback documentation.
All distribution files are Git-ignored. See
`target/gate3c/archive-smoke.log`.

Matched release measurements, gate3-partial → current:

| Mode | Idle RSS KiB | Five-job RSS KiB | Startup ms | Shutdown ms | Median job admission ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Standard | 4096 → 4300 | 4368 → 4568 | 1.457 → 1.548 | 1.426 → 1.410 | 9.288 → 9.022 |
| Legacy scoped YOLO | 4164 → 4316 | 4316 → 4464 | 1.393 → 1.375 | 1.284 → 1.215 | 9.871 → 9.725 |
| FULL | 4196 → 4296 | 4328 → 4436 | 1.417 → 1.421 | 1.279 → 1.016 | 3.298 → 3.204 |

All idle samples had zero CPU ticks over five seconds. Single-run
measurements are in `target/gate3c/performance.log`. Broad-mode,
dashboard and upstream overhead are unavailable.

Tracked sessions: 69949 baseline and 9049 final suite matrix (both
exit 1); 94755 build, 54889 harness, 21692 mutations, 34860 archive
smoke, and 25871 benchmark (all exit 0). Exact token usage was not
available.

## Continuation

1. Have AGY distinguish the negative and positive broad fixtures
   and pin their updated versions. Keep the positive state tree
   disjoint from the workspaces. Preserve all independently scoped
   tests. Then validate a pinned host mount graph that avoids nested
   bind aliases, hides the complete state directory, and denies
   protected object identities in direct file tools. Verify it
   through a real supervised networked job before enabling broad.
2. Have AGY discover the separate authenticated admin listener in
   dashboard and service tests, then implement paired admin
   sessions and the live dashboard under that transport.
3. Implement bounded, authorized upstream MCP transport and tool
   namespacing, then add the separate monitor if resources permit.
4. When the existing GitHub credential store is unlocked, verify
   authenticated `gh` identity and destination ownership and
   visibility. Confirm the repository is private before any push.
   The full redacted history scan and tracked filename review
   found no secrets or generated artifacts. The local primary
   branch remains `main`, independent from the development branch.

No service activation, live network changes, production BridgeDev
changes, deployment, publication, or push occurred.

---

# Gate 3b status

Branch `milestone3/broad-yolo` starts at
`093c4a514a7c73264213a04e3926ff3e7023ed74`, tagged locally as `gate3-partial`.
The `milestone3/modes-service` worktree and `gate2-scoped` tag remain available
for rollback.

## Preflight

The trusted runner matched all 24 pins before and after running the 22
required suites. It executed 195 cases. 181 passed and 14 failed in the
sandbox. Twelve failures were expected: modes 04, Suite A 03–05, and
Suite F 01–07 and 11. The two additional failures were service preparation
07 (no systemd user runtime directory) and 09 (no user manager bus). The
unchanged service suite passed 10/10, exit 0, in the same host user-manager
environment used in AGY's raw report. The combined baseline is 183/195 with
that independently recorded environment distinction. No service was
installed, activated or modified.

The detailed baseline log and pin comparisons are under
`target/gate3b/baseline/`. The primary command was
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD" python3 worktrees/m3-broad-yolo/target/gate3b/run.py baseline`
from the lab root. The driver invokes the existing trusted verifier per
suite and records each exit code. Session 71383 exited 1 with the expected
red cases and the two environment-dependent failures. The read-only
service rerun used `python3 -I -B ../../acceptance_pass3_service/locked_service_preparation.py`
from the worktree.

### Suite D boundary review

All eight cases ran in the verifier namespace. None invokes the gateway,
activates Broad or scoped YOLO, tests gateway admission or mounts a protected
directory. Their 8/8 result characterizes the synthetic fixtures and
demonstrates some failure modes. It provides no positive kernel-masking
acceptance.

| Case | Actual assertion and coverage |
| --- | --- |
| 01 | A hardlink in another directory resolves to the protected inode and reveals its synthetic data. No mask is installed. |
| 02 | An ordinary atomic rename replaces content in an unmounted directory. No file mask or namespace transition is tested. |
| 03 | An ordinary parent lookup exposes a replacement directory. No active mountpoint is replaced. |
| 04 | A swapped symlink resolves to the protected directory. No gateway or sandbox denial is attempted. |
| 05 | CLOEXEC is set on a test descriptor. The child cannot read a descriptor already closed by the fixture, so live gateway FD inheritance is untested. |
| 06 | A standalone Python child returns a nonempty procfs FD listing. It does not check which descriptors are exposed. |
| 07 | A test-side link count predicate rejects a doubly linked file. No gateway admission or runtime inventory is exercised. |
| 08 | A same-UID actor creates an alias after an initial link-count check. No gateway startup or post-check enforcement is exercised. |

## Checkpoint 1 — FULL direct file tools

The existing authenticated tool dispatcher now resolves FULL file targets
against a pinned host parent directory. The existing read, atomic
replacement, hash-guarded patch, staging and audit code is reused. A FULL
overwrite requires kernel write access to the original inode as well as
the parent directory. FULL supports absolute host paths with the existing
regular-file safety constraints. Symlinks, unsafe path components and
incompatible metadata remain rejected. Only the FULL branch can use a
host parent, and it rejects root execution.

Host-parent proof is optional in the ledger format, so older records remain
valid. Recovery uses the proven identity and the existing parent lock even
if the operator revoked the client since the write. FULL is intentionally
same-UID authority and can access state readable by the gateway owner.

Files changed: `src/http/mod.rs`, `src/security/audit.rs`,
`src/tools/filesystem.rs`, `src/tools/mutation.rs`, `src/tools/write.rs`,
`STATUS.md`. Checkpoint commit message:
`fix(files): honor confirmed full mode in direct file tools`.

Session 96084 exited 0. Suite A passed 8/8. File mutations, parent symlinks,
audit chain, scoped YOLO and migration passed 49/49. Logs and pins are
under `target/gate3b/full/`. The supplemental authenticated probe passed
invalid token, missing grant, symlink denial, live revocation, non-root
identity and FULL audit intent/outcome. Reproduce it with
`python3 -B target/gate3b/full-probe.py target/debug/mcp-gateway`.

Checkpoint 1 commit: `590fba650e6aa32660e01d28b0b010821e84975a`.

## Checkpoint 2 — Protected-path policy administration

The local CLI implements list, add, remove and validate, with Suite F's
`--mandatory`, `--optional` and `--readonly` selectors. Config, its
companions, the audit directory and job state are mandatory. The CLI
lists built-in default templates and manages custom entries. Optional
masks accept directories. Read-only rules accept directories or
singly-linked regular files. Descriptor-based validation rejects
symlink components and leaf mount crossings. Saved device and inode
identity detect replaced entries during follow-up validation. These
rules are staged for broad YOLO and have no effect on established
Standard, legacy YOLO or FULL authority.

Rules live in a versioned section of the private policy document. A
policy lock, durable transaction marker and hashed-path audit records
guard edits. Recovery requires repeating the exact local command.
File-only configurations can now reserve a private job-state path.
A directory path alone does not configure job profiles or grant jobs.
Older binaries reject the new rule field. A supported rollback must
restore the matching configuration or remove custom rules first.

Files changed: `src/main.rs`, `src/protected_cli.rs`,
`src/protected_paths.rs`, `src/http/admission.rs`, `src/http/operator.rs`,
`src/http/scope.rs`, `src/jobs/config.rs`, `src/security/audit.rs`,
`STATUS.md`. Checkpoint commit message:
`feat(cli): add durable protected-path management`.

Session 64288 exited 1 on the fixture's file-only state declaration.
The implementation now reserves that path while requiring actual
profiles for every job grant. Session 79112 exited 0 with 70/70,
including Suite F 15/15. Clippy passed. Logs and pin comparisons are
in `target/gate3b/protected-v2/`. Two supplemental local checks verified
audit intent/outcome, mandatory-path rejection, alias rejection, stale
identity, exact command recovery and unchanged policy on audit failure. The
Suite F remote check is a no-op and its audit assertion is tautological.
The local probes do not constitute independent acceptance.

Next: record the verified same-UID architecture blocker and finish
regressions of the independently shippable checkpoints.


Checkpoint 2 commit and current implementation HEAD:
`5eb25fb17b4948f92e4ef81c4d966b697280fc0e`.

## Checkpoint 3 — Broad YOLO remains fail-closed

The disposable directory-mask probe used a 0700 synthetic state directory,
a separate mount namespace, a host network namespace, Bubblewrap
`--new-session --cap-drop ALL --die-with-parent`, zero effective
capabilities and NoNewPrivs 1. Direct accesses and symlink aliases
returned ENOENT. Renaming the mounted directory returned EBUSY.
A same-UID process outside the sandbox then created a hardlink in an
exposed directory after the startup check. The sandbox read the original
protected inode through the alias. After an atomic host-side replacement,
a second alias exposed the new contents. The direct path stayed masked.
Reproduce using `/usr/bin/python3 -I -B target/gate3b/mask-probe.py`.
Evidence is in `target/gate3b/architecture/directory-mask.log`.

A preflight link count check cannot close this race. A 0700 directory
sharing the execution UID cannot exclude that UID under normal DAC.
Existing subordinate UID ranges are delegated to the same operator and
do not by themselves provide independent control-plane ownership from
host code running as that operator. FULL intentionally exposes same-UID
state. Broad activation, state migration, the `state check` command,
Git-hook protections, runtime mount enforcement for the new rules and
a gateway-launched broad socket probe remain pending. There was no
broad-mode fallback. No checkpoint 3 source changes were committed.

Next engineering task is to agree and verify a control-plane storage
boundary independently owned from the broad job UID. The operator
path and job launcher must authenticate the boundary. Protected links,
replace/rename, mounts, inherited descriptors and daemon-mediated
access need positive and negative runtime tests. Isolation of
localhost applications and abstract Unix sockets needs a separate
network policy if required. Host networking would keep both reachable
subject to application authentication and local policy.

AGY review request: add a positive-control fixture that proves the
gateway launched a genuinely broad job with off-root access and
controlled networking, then exercises protected directories, pre- and
post-admission aliases, atomic replacement, mount aliases, and direct
file-tool protections. Keep Suite D's synthetic evidence distinct.
Suite F 10 and 12 require genuine remote-denial and audit assertions
before they can independently establish those guarantees.

## Final verification of completed checkpoints

All 24 pins match before and after. The 22 selected suites contain
195 cases. Trusted sandbox: 192 passed, 3 failed, exit 1. Mode 04
stops at the explicit broad activation denial. Service Preparation 07
and 09 require the user systemd runtime and bus. They pass in AGY's
original environment, where the unchanged suite passed 10/10, exit 0.
The combined result is 194/195. Dashboard and service/network
integration are hash-checked only.

Suite A 8/8, Suite F 15/15, inherited Milestone 2 78/78, audit chain
13/13, scoped YOLO 11/11, migration 14/14, jobs cleanup 8/8, Suite D
8/8 synthetic, persistence 8/8, audit anchors 17/17. See
`target/gate3b/final/acceptance.tsv` for every suite and exact digest,
`acceptance.log` for process IDs and per-suite exits, and
`pins-before.tsv` and `pins-after.tsv` for the raw pin verification.

Formatting, Clippy with denied warnings, offline debug and release
builds, 36 Rust tests, Git whitespace, clean-clone release, 37 harness
tests, six hardening checks and project-local cargo-audit all exited 0.
The dependency trees matched and there were no dependency changes.
The normal release string scan returned no hook match, grep exit 1.
The supplementary crash probe used the separate audit hook binary
until SIGKILL at the ready marker. The release then recovered the
unpublished off-root FULL stage after revocation and verified its
cleanup events and audit chain. The release CLI probe verified reset,
FULL confirmation, broad rejection, rule persistence, bind-alias
denial, append-compatible anchors and a disposable systemd unit.
Whole-ledger rewriting remains possible for the audit owner or FULL.
Retain audit anchors beyond that UID's control to detect rewriting.

Four disposable mutations compiled and were detected. Suite A 03–05
detected FULL remaining scoped. Suite F 08 detected a false success
for mandatory removal. Migration 03 and 04 detected legacy enable
redirected to FULL, an expansion surrogate because broad is absent.
Modes 04 caught networking enabled in the shared offline launcher via
its legacy negative control. Modes 02 did not catch the latter under
the trusted runner's offline network namespace. The separate real
Standard job probe detected it with a controlled TCP peer. Broad
masking, NNP, networking, hardlink and direct file-policy mutations
could not reach an unimplemented mode. See `mutations.log` and
`mutant-*.log` under `target/gate3b/final/`.

Matched release measurements, baseline → current, with five confirmed
running synthetic jobs and one idle sample per mode:

| Mode | Idle RSS KiB | Five-job gateway RSS KiB | Startup ms | Shutdown ms | Median admission ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Standard | 4160 → 4204 | 4436 → 4476 | 1.109 → 1.217 | 0.933 → 1.251 | 9.142 → 3.424 |
| Legacy | 4184 → 4224 | 4328 → 4372 | 1.385 → 1.100 | 1.174 → 0.921 | 9.234 → 9.081 |
| FULL | 4204 → 4112 | 4336 → 4248 | 1.339 → 1.330 | 1.207 → 1.001 | 3.331 → 3.558 |

Idle CPU was zero ticks per five seconds throughout. Broad YOLO
latency is unavailable. The single-run differences do not establish
a performance improvement.

The runnable, partial Linux build is `target/release/mcp-gateway`
(2,746,240 bytes), SHA-256
`5451bdc6fcbe73de49b3ae6d6350695fa3874f928df63e6c9ad5a1d0bda35809`.
A clean local clone at the same HEAD produced a byte-identical binary.
The Gate 3b beta archive was gated on zero mandatory failures.
No installation, activation, deployment, merge or push occurred.

Tracked execution sessions, all finished: 71383 baseline (exit 1),
96084 FULL suites (0), 64288 first protected-path run (1), 79112 fixed
protected-path run (0), 97288 Rust verification followed by the
trusted acceptance matrix (combined exit 1), 11403 harness tests (0),
17326 hardening (0), 98923 clean clone (0), 68659 mutations (0), and
24405 performance (0). Exact Codex usage was unavailable. Only this
final STATUS update is pending in the worktree. Production changes are
committed through checkpoint 2.

---

# Gate 3 status

**Blocked at Checkpoint 1, acceptance compatibility.**
Branch `milestone3/modes-service` starts at Gate 2 commit
`7a666d3c42c17fc4a8e0506005b3ec9ac258c15c`, also tagged locally as
`gate2-scoped`. This is the last green implementation checkpoint.

## Preflight evidence

Ran `agent-context system`, reviewed the project instructions, Gate 2
handoff, current implementation, Git refs and worktrees, and the locked
assertions. The modes suite directory contains the suite file and has no
README. No separate execution-allowance readout was available.

The trusted `harness.acceptance.run_acceptance` built the exact Gate 2
source archive offline and ran the current pinned suites in an isolated
verifier. Only the audit suite used the separate `test-hooks` binary.

| Suite group | Passed | Failed | Exit |
| --- | ---: | ---: | ---: |
| Milestone 2 inherited, including jobs 9/9 and output caps 1/1 | 78 | 0 | 0 |
| Gate 1 audit chain | 13 | 0 | 0 |
| Gate 2 YOLO and CLI, including SEC-04 | 11 | 0 | 0 |
| Gate 3 execution modes | 2 | 3 | 1 |

The inherited suites ran as one group and exited zero. The baseline
total is 104/107. Mode cases 02 and 03 passed. Case 01 retained
`mode=disabled`, case 04 returned exit 101 for the job, and case 05
could not report `mode=full`. These results match the expected red/green
split. They do not resolve the fixture contract conflicts below.

All 16 pinned files matched before and after. Dashboard and service/network
were hash-checked only. Full pins, timings and exits are under
`/home/onyx/Projects/rust-mcp-gateway-lab/gate3-preflight-oSpfqO/` in
`verification.log`, `gate2-102.log`, and `gate3-modes.log`.
Execution session `85273` completed. The inherited and mode verifier
invocations returned 0 and 1 respectively.

## Acceptance compatibility

Paths below are relative to the acceptance root.

| Assertion | Classification | Proposed independent AGY action |
| --- | --- | --- |
| Authentication, grants, audit, job ownership and cleanup, output caps, and receipt recovery in the inherited suites | Still valid | Retain assertions. Keep cleanup checks tied to a live descendant with verified identity before cancellation and timeout. |
| `acceptance_pass3_yolo/locked_yolo_service.py` cases 03–06, 10 and 11 use the legacy enable command, scoped filesystem fixtures, runtime YOLO audit flags and a distinct mount namespace | Legacy scoped YOLO where the established scope or activation command is assumed. Audit and protected-state checks remain valid for sandboxed policies. | Preserve legacy behavior and add separate fixtures for explicit broad activation. The legacy suite makes no universal offline assertion about future modes. |
| `acceptance_m2_http/locked_http_acceptance.py` scoped path denials and `acceptance_pass3_modes/locked_mode_suites.py` case 02 | Valid for Standard | Retain the root and offline assertions. |
| `acceptance_pass2_jobs/locked_durable_jobs.py:35–60,242–253,319–327`. The unversioned Standard fixture launches a script outside its declared root and requires a PID file there, then uses that PID in the verifier's own process namespace. | Contradicts mandatory sandboxed, workspace-confined Standard. | Put the script and marker in the granted workspace and observe the live descendant from the verifier across namespaces using a unique test marker and process start identity. Retain both cancellation and timeout proofs. |
| `acceptance_pass3_modes/locked_mode_suites.py:218–229`. Case 01 tries a local Standard command and expects an enabled Standard client. | Still valid as an outcome. Command spelling needs independent review. | Exercise the specified `yolo reset` entry point and verify that revoked elevated or full authority cannot return. |
| `acceptance_pass3_modes/locked_mode_suites.py:332–357`. Case 03 uses legacy enable on a version-1 fixture and only asserts that protected files stay hidden. | Unclear for broad YOLO. Its green result demonstrates the existing scoped sandbox. | Explicitly opt in to broad YOLO, confirm the effective profile, and add an approved off-root positive control alongside the protected-path negative controls. |
| `acceptance_pass3_modes/locked_mode_suites.py:82,363–406`. Case 04 calls legacy enable on a version-1 fixture and requires an IPv4 UDP connect to a public address to return 0. The verifier creates an offline network namespace. | Contradicts legacy offline activation and lacks a controlled network endpoint. | Verify legacy denial first. Exercise `yolo set --mode yolo` explicitly and use a disposable loopback peer inside the verifier's network namespace. |
| `acceptance_pass3_modes/locked_mode_suites.py:435,448–457,468–469`. Case 05 writes `"mode":"full"` directly, then demands status and unsandboxed job success without an operator transition. | Contradicts mandatory `--confirm-full` and durable audit approval. | Require direct configuration and unconfirmed activation to fail. Enable FULL via the confirmed audited CLI and verify genuine unsandboxed execution only against synthetic files in a disposable environment. |

## Worktree and resumption

Created the requested branch, rollback tag, and this worktree. Added the
release-directory ignore rule. The pending worktree changes are
`.gitignore` and `STATUS.md`. No Rust source, Cargo manifests, locked
tests, runner, or harness changed. No checkpoint commit was made.

Next actionable task is an independent AGY compatibility review and
re-pinned acceptance fixtures. Once available, rerun the preflight before
starting migration and SEC-01. For an exact rerun, create a disposable Git
archive of `gate2-scoped`, import `harness.acceptance` from the lab, and call
`run_acceptance(snapshot, None, "true", suites, 100)` with the inherited
plus audit and YOLO suites as one group and the modes suite as a separate
group. Use `verify_locked_tests` against all registered pins before and
after. The historical manifests and logs identify the exact files.

Checkpoints 2–8 remain pending. Audit-head export, service generation,
release artifacts, new mutation checks, and Gate 3 measurements have
not been produced. Any additional security coverage needs independent
acceptance before a final Gate 3 claim. Existing same-UID whole-ledger
rewrite risk remains. No service installation, deployment, push, or
host configuration change occurred.

## Checkpoint 2 resumed, verified locally

The earlier stop decision above records the original preflight. Work
resumed on the same branch. `Mode::ScopedYolo` makes the legacy policy
explicit internally and retains the exact version-1 JSON and audit wire
label. Local reset and explicit Standard selection now recover Disabled
to Standard. They use the existing atomic policy and audit transaction.
Legacy enable still activates only the old scoped policy. The resume
handoff is in `AGY_GATE3_TEST_HANDOFF.md`.

Four local integration checks passed, covering credentials and grants,
the version-1 scoped approval and replay denial, pending-state recovery,
and malformed state. Clippy passed. The existing YOLO suite passed
11/11. The modes suite passed 3/5, including SEC-01. Cases 04 and 05
retain the independently disputed expectations. Sessions 25553, 51061
and 11058 completed. Logs are under `target/gate3/` and
`/tmp/mcp-gate3-checkpoint2-cargo.log`.

Next task is explicit confirmed mode approval and supervised FULL
execution. Broader YOLO remains unavailable until its required isolation
can be verified. Audit anchors and service preparation are separate
implementation checkpoints.

## Explicit FULL approval and supervised execution

Gate 3 stores confirmed FULL in policy schema 2. A mode-specific chain
approval is required at startup and refresh. Existing Gate 2 version-1
scoped YOLO approvals are recognized without rewriting configurations.
Missing confirmation, old schema, forged mode/approval combinations,
Disabled-to-FULL activation, and replay after reset are rejected. The
legacy enable command never selects FULL or broad networked YOLO.

FULL job admission uses the normal grants, audit, signing and supervisor.
It selects the existing host execution branch with inherited
NoNewPrivileges, scrubbed environment, owned process supervision and the
gateway UID. Direct file tools remain scoped. FULL jobs carry the host
UID's file and network permissions and may access or alter same-UID
control-plane state, including audit history. Keep FULL disabled for
clients that lack local-operator trust. Gate 2 refuses schema 2 during
rollback. Retain the older file separately and never use stale approvals
to recover an active policy.

Local tests passed 6/6 and Clippy passed. The synthetic FULL probe ran
`id -u` through authenticated MCP and returned UID 1000, a signed
unconfined receipt, and FULL runtime audit intent and outcome. It used
a throwaway HOME for the controller and ran only the harmless id command.
The pinned legacy YOLO suite passed 11/11. The pinned modes suite passed
3/5, with only the disputed cases 04 and 05 failing. Execution sessions
11724 and 68027 completed. Broad YOLO remains fail-closed.

## Audit anchors locally verified

`audit export-head --out PATH` and `audit verify --anchor FILE` are
implemented and locally tested. The first export assigns a private,
persistent random ledger ID. The verified export is published atomically
without replacement. Verification authenticates the requested prefix
against the whole verified chain, across appends and segment rotation.
Local tests cover wrong ledger, hash, sequence, format, archived tampering,
and existing output. The audit-chain suite passed 13/13 and Clippy passed.
Session 78620 completed. Local evidence is awaiting independent acceptance.
The retained anchor must be outside FULL's write authority for independent
whole-log rewrite detection. Next task is Linux service preparation.

## Linux service preparation locally verified

Unit generation and dry-run passed local checks, including escaped
systemd values, fixed loopback binding, and `systemd-analyze --user verify`
in a temporary directory. Dry-run wrote no unit. Confirmed installation
is file-only, atomic and non-replacing. It leaves activation to the
operator. This run did not execute installation or activation.

Unix SIGTERM and SIGINT stop accepting connections and drain in-flight
HTTP work within a bound. Detached jobs retain their runner leases.
The unit uses `KillMode=process` to preserve that behavior, and sets
restart, memory and task limits. The existing Tokio dependency enables
its signal feature, which adds locked signal-hook-registry 1.4.8
(MIT OR Apache-2.0). Local checks passed 25 unit and 11 integration
tests, Clippy, the supervised FULL probe and unit validation.
Sessions 13057 and 58092 completed. Service work awaits independent
acceptance.

## Partial release verification

The final Rust implementation checkpoint is `2ddd40c`, after scoped
compatibility and SEC-01 (`42315e6`), confirmed FULL (`cb17b8c`), and
audit anchors (`633f915`). `GATE3_BETA.md` gives mode semantics, operator
commands, service planning and rollback instructions.

All original 102 cases pass. The Gate 3 mode suite remains 3/5 with only
the disputed networking and raw FULL cases. The inherited jobs suite
passed 9/9 on its original unversioned compatibility profile. All 16
locked pins matched. The hardening script passed 6/6, and the harness
regression run passed 36/37. Its sole failure expects four Pass 3
registrations but the trusted manifest now contains five. The handoff
records this separate review item. No independent files were edited.

Formatting, Clippy, locked debug and release builds, all 36 Rust tests,
and RustSec audit of 50 crates passed. The release excluded both audit
crash-hook controls. Controlled loopback was denied in Standard and
scoped YOLO. FULL ran supervised as the gateway UID. Seven disposable
mutants compiled and were detected by local assertions. These covered
confirmation, reset, audit anchors, FULL confinement and audit mode, and
network isolation for Standard and scoped YOLO. These local oracles
await independent review.

Broad YOLO activation stays fail-closed. A synthetic writable-mount probe
demonstrated that masking a single path leaves an existing hardlink
visible and can lose the mask after atomic replacement. Mandatory
control-plane protection, persistence mounts, optional protection CLI,
direct file-tool parity, and broad socket probes are unfinished.
Next smallest implementation task is a protected-directory mount design
and local alias/replacement tests that prove the boundary before any
networked host-write profile is admitted.

Matched single-run release measurements, without the user systemd
manager, use the same disposable fixture. Idle samples measured zero CPU
ticks over five seconds for every tested policy.

| Policy | Gate 2 RSS KiB | Partial Gate 3 RSS KiB | Gate 2 admission ms | Partial Gate 3 admission ms |
| --- | ---: | ---: | ---: | ---: |
| Managed Standard | 3944 | 4068 | 10.282 | 10.457 |
| Legacy scoped YOLO | 4088 | 4168 | 11.038 | 12.502 |
| Confirmed FULL | — | 4068 | — | 3.139 |

Partial Gate 3 startup/shutdown samples were 2.272/0.882 ms for Standard,
2.479/1.089 ms for scoped YOLO and 3.272/0.412 ms for FULL. Gate 2
returned signal termination under the same shutdown probe. Five-job RSS
was not sampled. Broad YOLO was unavailable for measurement.

Receipts and reproducible local probes are in `target/gate3/`. Sessions
22086, 54244, 79044, 17318 and 33805 completed. Only source, tests and
documentation belong in the commits. Release artifacts belong in ignored
`dist/`. No persistent service or host changes were made.

## Packaged partial release

A clean local clone of `afa56e9c0c0d3b4b746b59ce004b1137884b1f9a`
built offline in debug and release. The archive uses that release
binary. The extraction smoke passed checksums, help and version, a
disposable generated systemd unit, authenticated managed Standard and
scoped YOLO network-denial probes, and supervised FULL running as UID
1000. All gateway probes exited zero after SIGTERM. A separate extracted
CLI smoke confirmed Disabled reset, FULL confirmation enforcement,
anchor export, verification after a later append, and a side-effect-free
service dry-run. The example configuration uses placeholders and is
deliberately disabled with an expired credential until locally edited.

- Binary `dist/gate3-beta/mcp-gateway` SHA-256
  `189df235d6d6a7eb3c1b5924641bed9bc05decc6532ae062c6cdb38461d8227f`.
- Archive `dist/mcp-gateway-gate3-linux-x86_64.tar.gz` SHA-256
  `077a2dc0b5ec93aabb815f3303b2a589ab6917b1ecc0a2508ed0231ff96597e0`.
- Release session 51379 completed with exit 0. See
  `target/gate3/release.log` and `target/gate3/release-cli.log`.
- Final independent pin check matched all 16 files. Packaging created
  only ignored artifacts. This receipt is documentation-only.

## Local dashboard, skills and upstream MCP

The execution-mode baseline is `9d792001d82959ae33ef216358507fb20b473d56`.
AGY independently accepted its 229 required cases. The separately preserved
Linux x86_64 beta in `dist/gate3d-beta/` is built from that baseline.
The complete archive is `dist/mcp-gateway-gate3d-linux-x86_64.tar.gz`
(1,171,899 bytes), SHA-256
`c7e0a7052a43187b2af20193e925d8fef936e8ddde62785ad6914e1f0ae80feb`.
The packaged executable SHA-256 is
`a9d3f06cea85c16d953bd35d3d70642e99d54d9212f4db909945fa6d4aee9eb7`.
Extraction, the included checksum manifest and four runtime smoke probes
passed. The product candidate uses the regular build output and has no
release archive.

The candidate enables a separate loopback admin listener, authenticated
browser sessions, job views and cancellation, audited skill import and
grants, and upstream registration, discovery and forwarding. Stdio
upstreams use a fresh Bubblewrap sandbox. Streamable HTTP supports JSON
and SSE. TLS verifies the registered hostname and supports a dedicated
owner-only credential and trust bundle. See the three operator guides
in `docs/` for configuration and rollback.

Verification on the local candidate:

| Check | Result |
| --- | --- |
| Gate 3d inherited | 229/229 |
| Dashboard with isolated Brave | 15/15 |
| Skills | 15/15 |
| External MCP | 16/16 |
| Service and networking | 12/12 |
| Total registered | 287/287 across 28 suites |
| Additional product probes | 5/5 |
| Rust tests | 36 passed |
| Harness regression and hardening | 37/37 and 6/6 |

All 28 pins match before and after. The browser suite was run with only
the installed Brave runtime and a synthetic launcher added read-only to
the offline verifier environment. The unaugmented runner cannot find
Brave. The audit suite used the separate hook-enabled build. Normal
release hook exclusion, formatter, Clippy, offline builds, whitespace
checks and project-local cargo-audit passed. An offline release built from a fresh clone. A separate readable-browser
probe confirmed the real cookie attributes, protected content and desktop
and mobile layout. A paired session listed, inspected and canceled a real
durable job and received a denial for the wrong job owner. Three disposable source mutations were detected:
reused pairing token, skipped CSRF validation and skipped per-tool grants.

The actual Codex app-server negotiated with Veyl, discovered a namespaced
tool and forwarded a call through the disposable provider. Antigravity
registered Veyl and reached authenticated discovery in an isolated
profile. Its model session asked for account authentication, so a
Gemini-driven tool call remains unverified.

Local verification is separate from independent acceptance of the new
management, HTTPS and credential paths. AGY's expanded security acceptance
and BridgeDev's package review are pending. GitHub metadata inspection
as the authenticated owner could not resolve `kmanisk/veyl`. Publication
is pending independent review. The older execution-mode beta and its
checksums stay separate from the product candidate.

Verification entry points and saved logs:

- `cargo fmt --all --check`, `cargo clippy --offline --locked --all-targets -- -D warnings`,
  `cargo test --offline --locked`, `cargo build --release --offline --locked` and
  `python3 -B tests/product_features.py`.
- `target/gate3d/product-delivery.log`, `target/gate3d/product-delivery/pins-before.tsv`
  and `target/gate3d/product-delivery/pins-after.tsv` contain full suite receipts.
- `target/gate3d/product-delivery-toolchain.log`, `product-cargo-audit.log`,
  `product-cargo-tree.diff`, `product-browser-probe.log`,
  `product-codex-client.log`, `product-agy-client.log` and
  `product-mutations.log` are local evidence under `target/gate3d/`.

Next independent task: review the exact source commit and separately
validate the preserved Gate 3d archive. Exercise authenticated Gemini
forwarding in an approved account before approving a full product release.

## Linux release candidate

This checkpoint extends the independently accepted Gate 3e product
commit `a9317036a359367ed602be1c241ef64888d37659`. The AGY acceptance
section in `HANDOFF.md` is preserved verbatim. The reported Gate 3e
archive was absent from the checked locations. The matching accepted
gateway executable was preserved at
`dist/gate3e-checkpoint/mcp-gateway` with SHA-256
`f117ac52c234203cff569895a7ab6f16d9492fcd80c778b1fda27e747045fe71`.
The independent Gate 3d rollback archive was also preserved.

This candidate adds conditional private Serve management, user-service
lifecycle and diagnostics, the authenticated on-demand monitor, and
scoped search, Git, system and service inspection. It retains the four
execution modes, dashboard, skills and upstream MCP. The resource and
authorization boundaries are documented in `docs/PARITY.md`,
`docs/LINUX.md` and `docs/TAILSCALE.md`.

| Verification | Result |
| --- | --- |
| Locked acceptance | 287/287 across 28 suites, all pins unchanged |
| Rust tests | 37 passed |
| Product probes | 5 passed |
| New Linux integration probes | 7 passed |
| Harness regression and hardening | 37/37 and 6/6 |
| Systemd private user manager | Install, enable, start, restart, stop, disable and uninstall. The process ID changed and the original job could still be canceled. |
| Serve workflow | Disposable LocalAPI lifecycle, conditional update race, rollback, and authenticated HTTPS reverse proxy |
| Live Tailscale | Read-only planning and validation on the existing node. Serve snapshots matched byte-for-byte. |
| Codex | Actual authenticated discovery and a forwarded tool call |
| Antigravity | Actual authenticated discovery. A model session requires independent Google sign-in. |

Offline debug and release builds, formatter, Clippy, whitespace checks,
and cargo-audit passed. The release excludes audit test hooks.
No dependency was added for the terminal monitor. On this workstation
the candidate used 4,952 KiB RSS idle versus 4,764 KiB for Gate 3e.
The interactive monitor used 3,228 KiB. Each recorded zero CPU ticks
over a two-second idle window. In this sample the median 24-request
authenticated dashboard status latency was 1.89 ms versus 0.67 ms.
These are local samples under current workstation load.

Evidence is under `target/linux-final/`. The consolidated result is
`acceptance.log`; per-suite outputs and before/after pins are under
`target/gate3d/linux-final/`. Additional receipts are
`systemd-lifecycle.log`, `tailnet-live-readonly.log`, `harness.log`,
`toolchain-and-product.log`, `performance.log`, and `agy-client.log`.
The disposable unit runner can be repeated with
`bash tests/systemd_lifecycle.sh target/release/mcp-gateway`.

The new archive is `dist/veyl-linux-x86_64.tar.gz` with an adjacent
`.sha256` file. Its internal `RELEASE.md` identifies the exact source
commit. The release build and extraction receipt is recorded under
`target/linux-final/package.log`. Compiled files, credentials and logs
are outside Git tracking.

Next, AGY independently exercises the exact Linux commit. BridgeDev
then checks the same commit and archive. Live Serve activation and
production service activation require separate approval. GitHub
authenticated the account as `kmanisk`, and the destination repository
lookup did not resolve. Creation and private publication remain gated on
both independent approvals.

## Veyl v0.1.1-beta production candidate

Base `fa13ec6e43e88a1eb56e0aa0b2166c1d4890e13b`, the published
`v0.1.0-beta`. The existing production service uses the private MCP
and dashboard routes on 8443 and 9443. Only BridgeDev on 443 is public
at preflight.

- Broad YOLO handles desktop symlinks as leaf objects and permits
  sockets inside masked desktop directories. Descriptor-based inventory
  still rejects state symlinks, executable state files, nested mounts and
  accessible hardlink or bind aliases. The operator moves executable
  header helpers outside the private state as part of deployment.
- Opt-in public MCP uses a separate verifier, dedicated Broad YOLO
  identity, per-request credential revalidation, bounded admission
  and private audit events. Private sessions remain separate. The
  dashboard still rejects Funnel.
- `veyl serve funnel-plan`, `funnel-apply` and `funnel-rollback` manage
  the public flag on the existing owned MCP port using conditional
  Tailscale LocalAPI updates. The private route pair is preserved.

The consolidated verifier passed 287/287 cases with all 28 pins
unchanged. Cargo formatting, Clippy, 37 Rust tests, the release build,
5 product probes, 11 Linux probes and a disposable systemd lifecycle
passed. The actual-HOME candidate probe used separate disposable state,
verified direct reads and writes, a supervised TCP connection, and
protected state denial. Job `9a2194f0cd91ea7bbcf59c8fed778e72` exited 0.
Logs are under `target/v0.1.1-beta/`. Locked suite details and hashes
before and after are under `target/gate3d/v0.1.1-beta-funnel/`.

Run the independent review before promotion. After both approvals,
back up the original binaries and both configurations, move the Codex
helper to `~/.codex/veyl-helpers/`, apply the dedicated Funnel verifier,
restart only Veyl and test the public route from outside the tailnet.
The [ChatGPT guide](docs/CHATGPT.md) covers connector setup and revocation.

## Veyl v0.1.2-beta public MCP CORS candidate

Base `13351c676c7ce91a2f8f1085d69dbaa5191531e5`. Brave reproduced
the cross-origin failure against the existing production Funnel.
The candidate adds exact ChatGPT Origins and bounded, bodyless POST
preflight on the configured public MCP route. OPTIONS shares the public
rate limit and never authenticates or creates a session. Actual requests
retain credential and session checks. Private listeners retain their
existing policies.

The consolidated verifier passed 287 cases with all 28 pins unchanged.
The 37 Rust tests, 5 product probes, 12 Linux probes, Clippy and the
release build passed. See `target/v0.1.2-beta/` and
`target/gate3d/v0.1.2-beta/` for test evidence. Use the public HTTPS
browser probe after the independent review and rollout. ChatGPT account
discovery requires a separate observation. Current documentation does
not establish a browser-only connector transport or a restriction on
port 8443.

## Veyl v0.1.3-beta native shared Funnel

The state-layout failure came from the adapter-era Serve backup with an
unsafe directory mode inside the private state tree. The operator
relocated it to a protected rollback directory. The production public
client then read an absolute project path outside its workspace. Its
attempt to read the policy file remained denied.

The `tailscale_serve.shared_funnel` option adds an owned `/veyl/`
handler to an existing public HTTPS authority on 443. Existing private
Serve ports and the public root handler are preserved. The CLI validates
the path namespace, uses conditional LocalAPI requests, and can adopt or
restore the exact temporary adapter. Retiring the dedicated public flag
is an explicit operation after verification.

The dashboard shows redacted configuration, route status, and Broad
YOLO protection rules and state-layout validation. Late job-log
responses cannot replace a more recently selected job's logs.

The verifier passed all 287 locked tests and retained all 28 pins.
38 Rust tests, 5 product probes, 14 Linux tests, the systemd fixture
lifecycle and disposable Brave dashboard controls passed. An actual
Codex app-server forwarded a synthetic upstream tool. An actual
Antigravity client completed authenticated discovery. Local
receipts are under `target/v0.1.3-beta/`. Production routing and
publication follow independent review and live checks.

## Three-mode migration preparation (unreleased)

Base: `6615c5061dc5cae83500d4c829ebc2652d37989a` (v0.1.3-beta).
ChatGPT is implementing directly through BridgeDev in the designated
worktree. The installed release, production policy, services and
Tailscale routes are unchanged.

The additive `mode get` and `mode set` CLI delegates to the existing
audited local operator transaction, including Broad YOLO preflight and
explicit FULL confirmation. Both flag-based and positional syntax are
supported. It does not yet migrate the on-disk schema, reinterpret
legacy scoped YOLO, or separate the disabled client flag.

Local verification: 41 Rust tests passed (29 unit, 8 operator, 4 mutation),
formatter, Clippy with warnings denied and whitespace checks passed.
BridgeDev process receipt: `mwun8mdo-c5s7hr`, exit 0. The new independent
three-mode suite hash matches the AGY receipt
`85f74c03c2357db2f998ddbbe111e16121c54e8fc75c797298e3552f7e81c9a4`.
The new suite has not been independently accepted or rerun against this
partial implementation.

Before schema migration, reconcile the acceptance contract: existing
tests require legacy `yolo enable` to retain scoped offline behavior,
whereas the proposed interface eventually refuses that command.
AGY's handoff diagram also incorrectly describes unconfined YOLO and
root/sudo FULL. Preserve sandboxed network-enabled YOLO and same-UID
unsandboxed FULL, with no automatic privilege elevation. A versioned
legacy migration must preserve approvals and never widen scope.
New parity tools and Nightshift are subsequent checkpoints.

## Linux v0.2.0-alpha release: Three modes, BridgeDev parity, and Nightshift

Base: `6615c5061dc5cae83500d4c829ebc2652d37989a`.
Implemented, tested, and published by AGY under direct authorization.

1. Three-mode architecture:
- Authoritative modes: Standard (workspace and extra roots, sandboxed, offline), YOLO (host-wide dev mounts, Bubblewrap sandboxed with networking, protected paths masked), and FULL (ordinary host-user execution, unsandboxed, requires explicit --confirm-full).
- Independent client enabled/disabled state preserved across mode changes.
- Version 3 policy migration (policy_version: 3) with `veyl mode migrate` converts legacy policy, maps legacy scoped yolo_roots to extra_roots, maps broad_yolo to yolo, and preserves credentials and server tokens.
- Deprecated `yolo enable` command strictly refused on version 3 policies.
- 6/6 locked three-mode acceptance tests passing (hash: 616300d6f5dc788a5be1685d51c83b5fd04fd3f796503a04d3cf0a3d29962ac3).

2. BridgeDev feature parity developer tools:
- `list_directory`: flat or recursive directory listing with show_hidden and item limits.
- `directory_tree`: hierarchical recursive directory structure with max_depth limits.
- `file_info`: robust file and directory inspection returning type, size, permissions, mtime, and sha256 checksum for regular files.
- `create_directory`: safe recursive directory creation within mutation roots.
- `edit_file`: exact substring match-and-replace mutation without requiring prior sha256.
- `exec_command`: bounded synchronous execution with stdout/stderr capture.

3. Durable Nightshift primitives:
- Idempotent `request_id` handling across job and task entry points to prevent duplicate execution across reconnects.
- Bounded `job_wait` to block on job completion with server-side timeout up to 60s.
- Incremental offset-based `job_logs` pagination (`offset`, `max_bytes`) for efficient streaming without blowing context windows.
- Structured `task_run` executing bounded commands with optional ephemeral git worktrees and auto-commit checkpoints.

4. Production deployment and verification:
- 46/46 Rust tests passing (29 unit, 3 parity/nightshift, 10 operator, 4 mutation).
- Zero compiler warnings, clippy clean, cargo fmt clean.
- Installed to `/home/onyx/.local/bin/mcp-gateway` and symlink `veyl`.
- Production policy migrated to policy_version: 3 and verified valid.
- Local dashboard (http://127.0.0.1:7332/dashboard) and private Tailscale dashboard (https://onyx.tail646579.ts.net:9443/dashboard) operational with pairing workflow.
- Terminal monitor utility (`veyl monitor` and `veyl-monitor`) verified with live health and clients views.
- Tailscale Funnel on port 443 path `/veyl/mcp/...` live and verified with active ChatGPT session, tools/list discovery (25 tools), and execution.

# TimeShift investigation (2026-11-25; incomplete)

The candidate at base `0e2cf55` retains its prior uncommitted changes. No
TimeShift or autonomous Nightshift implementation was added in this pass.
The existing file publisher checks a snapshot before rename under an advisory
directory lock, which does not exclude non-cooperating writers. A restore
cannot claim the requested no-clobber guarantee solely by reusing that check.
`create_directory` currently uses `create_dir_all` on a pathname and is not a
descriptor-confined basis for checkpointing directory creation.

The focused `pass2_mutation` integration test compiled but all four cases
failed at gateway startup with `gateway should bind loopback: Disconnected`.
A direct Python IPv4 socket creation failed with `PermissionError: [Errno 1]
Operation not permitted` in this execution sandbox. This is distinct from the
previously recorded Broad YOLO preflight failure; it does not establish a
mutation regression. No isolation or host settings were changed. No new
personal preview is available for the unimplemented feature.

# Verified marketplace installer & grant controls (2026-11-25)

Independently implemented and verified on `0.3.0-beta` candidate from base `329b9d53ccdc86dd1ef3121a91d0bd031bdf6f95`:

- **Verified installer engine (`src/upstream/installer.rs`)**:
  - Built-in pinned recipes for `rea` (`rea-agents@6.10.1`, npm tarball SRI `sha512-3AWrfFEX...`, bundled dependencies, `/usr/bin/env REA_MCP_TOOL_FAMILIES=artifact /usr/bin/node /upstream/bundle/scripts/rea.mjs mcp`), `rust-anything` (`v4.1.0`, official GitHub release asset SHA-256 `12c2426d...`, ELF verification staged into `upstream-bundles/rust-anything/bin/rust-anything`), reviewed pure-JS npm packages, pure-Python `.whl` packages, standalone ELF binaries, and guidance-only skills (`skills.rs` `upsert`/`remove`).
  - Zero global host-install copying, zero npm install lifecycle script execution, zero `setup.py` execution; external HTTPS enforcement plus isolated `127.0.0.1` loopback mock support for offline tests; pure-Rust USTAR/PAX/GNU tar parser + zero-write Python ZIP reader + `openat2` extraction with traversal/symlink/hardlink/size/count/bomb rejection.
  - Async operation progress, live PID cancellation, transactional `.journal-*` crash recovery, and automatic probe-failure rollback preserving prior working bundles and `clients.json` configuration.
  - `src/state_cli.rs` preserves `0o7177 == 0` across gateway state and permits `0o7077 == 0` verified ELF binaries strictly inside `upstream-bundles/<id>/bin/`, keeping Broad YOLO admission intact (`MAX_ENTRIES=131072`).
- **Dashboard & grant controls**:
  - Added `/api/dashboard/marketplace/{state,install,configure,uninstall,cancel,recover}`, `/api/dashboard/clients/grants`, `all_tools` status metadata, `veyl marketplace` CLI, Verified Providers card grid, progress/cancel bar, Configured Providers bulk/per-tool grant matrix, and Client native tool bulk/per-tool grant editor while preserving `marketplace.json` (`106` entries), `dashboard_tabs.mjs` contracts, and manual Custom MCP.
- **Verification**:
  - `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `node --check src/http/dashboard/app.js`, and all Rust tests (`67+67+10+3+11+6+4`) PASS.
  - 28/28 locked acceptance suites (`287/287` cases, `28/28` SHA-256 unchanged) + `locked_three_modes.py` (`6/6`) PASS against release binary without `test-hooks`.
  - All 18 Python/Brave CDP/shell suites (`test_dashboard_preview.py`, `onboarding_browser.py`, `marketplace_install.py` `4/4` including real `rea` 6.10.1 & `rust-anything` 4.1.0 + Brave CDP UI checks, `systemd_lifecycle.sh`, `updater_lifecycle.sh`, plus `linux_features.py`, `process_sessions.py`, `product_features.py`, `runtime_bundles.py`, etc.) PASS.
  - Offline RustSec audit: `0` vulnerabilities / `0` informational across `47` advisories and `86` package versions.


