# Public Veyl plugin, device connector and release roadmap

**Deferred alternative (operator direction 2026-11-27):** direct client-independent OAuth MCP over public HTTPS is the release target. The hosted relay, universal public plugin and standalone Plugin Creator package are optional future work, not release dependencies. See DIRECT_REMOTE_PLAN.md. Preserve the existing experimental connector baseline and package generator without activating or expanding them.

Planning checkpoint — 2026-11-26. Base: 66995f1c6e700dcf19e57fd5086df69648fe83f5.
Production remains the verified Linux 0.5.0-beta release. This document is a plan, not a claim of implemented functionality or approval to expose production.

## Product contract

One public Veyl plugin with a stable universal HTTPS MCP endpoint; install the native Veyl runtime, sign into a Veyl account in a browser, locally authorize pairing, then connect that account in ChatGPT. No pasted secret URL or per-user custom plugin. Keep local/stdio, direct Tailscale and self-hosted paths supported. Tailscale is optional for the new outbound connector. Keep the runtime and self-hosted connector MIT-licensed; no required Veyl subscription or OpenAI API key. Users retain their own ChatGPT plan and upstream provider terms. Public service capacity is bounded; free hosting, custom domain and unlimited bandwidth are not assumed.

The existing connector API 1 is a loopback foreground preview: bounded users/devices, hashed static credentials, owner-scoped list_devices/device_health, heartbeat and persisted sequence. No OAuth, public TLS, dynamic pairing, device call transport or remote execution. Preserve this baseline and production Linux behavior.

## Architecture and authority

- Separate control-plane crate/module boundaries: identity/accounts, device registry, pairing, authorization, session/call routing, durable state and transport. Keep the Rust shared gateway core and native adapter execution. Avoid gratuitous dependencies and always-running components.
- Stable HTTPS MCP origin and separate authenticated outbound device transport. Devices connect out over TLS (prototype bounded long-poll or persistent stream; choose from measured resource, latency and hosting constraints). Never require public inbound host access or a user-supplied forwarding URL. No production listener on the laptop.
- OAuth 2.1 via a standards-compliant identity provider/authorization implementation, MCP discovery, audience/issuer/scope validation, authorization-code PKCE, OpenAI client registration and transport identity as supported by current guidelines. Do not invent crypto or assume ChatGPT account credentials are available to Veyl.
- Pairing: device creates key/nonce, short-lived one-use code, sign-in, explicit local owner approval, bind immutable account and device identity; secure storage, token renewal, revoke/unpair, rate limits and replay protection. Account identity is independent of device and local MCP credential.
- Server routes only authenticated account-owned devices. Device independently checks live binding, scoped client grants, mode, protected paths, tool availability and request freshness. No cloud access to local credential files; never let relay requests elevate modes or change local grants. Default new device grant narrowly scoped; remote operations require explicit operator policy. Review broker compromise threat model, device credential lifecycle, limits and privacy before public deployment.
- Stable public tool contracts, explicit device selection, no arbitrary generic tool proxy as a substitute for review. Return bounded typed results; guard duplicate requests, retries, cancellation, timeout, reconnect and stale results. Use existing local job supervisor; no silent replay of mutations. Local audit authoritative; cloud metadata minimal, no durable file contents or command output by default. Relay transports data to ChatGPT: disclose this accurately; no unproven end-to-end encryption or zero-knowledge claim.
- Expose approved existing Linux tools progressively: read-only workspace and system inspection first, then gated mutations, durable jobs/tasks/logs/cancellation, Git, TimeShift, skills, REA, Rust Anything, other locally installed upstream MCP providers with their separate explicit grants. Keep local dashboard/TUI working; device status and revocation UI. No unattended Nightshift parity claim. Public plugin review may require narrower surface than local private MCP.

## Checkpoints and acceptance gates

P0 (this checkpoint): plan and source baseline; no production changes.

P1: isolate connector account/device registry, identity and wire protocol modules; preserve API 1 preview. Add bounded typed envelope with version, request ID, account/device binding, scope, expiry and replay handling; schema and persistent-state migration tests. Test cross-account denial, role separation, malformed/duplicate headers, stale and repeated requests, restart and corruption. No network exposure or execution.

P2: local disposable OAuth-compatible auth and device pairing flow using established libraries/provider, secure enrollment and revocation. Tests for PKCE/state, token audience and expiry, code reuse, concurrent pairing, ownership, revoke/reconnect, credential leakage. No secrets in source or logs.

P3: Linux outbound transport, read-only end-to-end real device invocation with two accounts/two devices. Integrate actual existing gateway policy, not a synthetic execution service. Verify bounded queues, offline/timeout, replay and account isolation. Then incrementally introduce approved mutation/job/provider operations with same native permission boundaries and audit.

P4: UI/onboarding, public tool catalog, device picker, local dashboard/TUI integration. Preserve legacy setup/connect and direct MCP; introduce opt-in hosted pairing without breaking CLI scripts. Native upstream tool schemas and skill permission checks; test real REA/Rust Anything with explicit grants. Review destructive/open-world/read-only hints and user consent. Verify idle CPU/RAM and reconnect under network loss.

P5: choose sustainable zero-paid-tier or donated infrastructure after capacity/terms review; stable domain with HTTPS, isolated relay, encrypted credential state, backups, abuse quotas and recovery. Do not host on the production laptop or spend money without authorization. No public deployment before adversarial and privacy acceptance. OpenAI developer identity verification, domain verification, compliant listing, privacy/terms/support, isolated reviewer demo account, positive and negative test cases, tool scan and review. Initial submission is manual/approval-gated; package/listing/skill changes may need resubmission. Never publish the owner's existing personal app reference or credential URL.

P6: tag-driven release CI and safe updates (can develop in parallel after P1). Public repository standard GitHub Actions runners; pin actions, least-privileged credentials, protected environments, provenance, checksums and signatures. Build native matrix with gated tests; only publish supported artifacts. Single versioned GitHub release and crates.io version; publish only after required acceptance, do not republish existing immutable versions. Stable connector origin, protocol compatibility window (at least current and previous verified runtime), negotiate capabilities, staged relay rollout/rollback. Automatic server fixes and eligible reviewed schema updates via OpenAI continuous scans; package metadata/skills still require approved update. User device upgrades opt-in or explicitly enabled, verify signed manifests, idle-job gate and rollback, preserve policy/grants and configuration. No forced reboot/restart or privilege escalation.

P7: Android native Termux validation of current release, then Android adapter jobs/PTY/service/capabilities. Later native Windows build, ACL/reparse containment, Job Objects/ConPTY, service/updater and permissions tests. Neither platform advertised as supported until its native acceptance passes.

## Release artifacts: three platform families, not three unsafe promises

- Linux now: verified x86_64 (later aarch64) portable tar bundle, RPM for Fedora/RHEL after packaging tests, Debian package as appropriate, Arch-native package/PKGBUILD later. Cargo install remains supported. RPM is not the correct default package for Arch/CachyOS.
- Windows later: native signed .exe installer/portable bundle after platform acceptance. Signing availability and cost are separate gates.
- Android later: Termux-native Bionic binaries/package first, tested ARM64 and x86_64 where available. APK requires an actual Android app/packaging and lifecycle design; do not relabel a Termux binary as an APK. Android signing keys controlled by publisher.

A single release page groups Linux, Windows and Android downloads plus shared SHA256SUMS, signed release manifest, provenance and optional portable/source assets. Missing unsupported platforms are omitted with clear status. No version bump selected yet.

## Release and security criteria

Preserve the full locked Linux suite and pins, Rust warnings-denied Clippy, new targeted tests and existing integration/lifecycle acceptance. Build from the exact reviewed commit. Use disposable accounts/devices/fixtures and synthetic secrets; test revoked credentials, cross-tenant calls, stale tokens, replay, disconnected device, duplicate mutation, protected-path denial, permission changes during calls, bounded outputs and queue pressure, rollback and old-client compatibility. Test actual data path and negative controls before declaring completion. Independent review preferred for public exposure; operator can direct additional verification workflow. Production remains unchanged until exact candidate approval.

## Sources consulted

- Existing repository docs/development/ARCHITECTURE.md, STATUS.md, HANDOFF.md, README.md, docs/CHATGPT.md and docs/TAILSCALE.md, src/connector/{mod.rs,agent.rs}.
- https://developers.openai.com/plugins/deploy/submission — public submission and continuous review.
- https://developers.openai.com/plugins/deploy/app-review — compatibility during held updates.
- https://developers.openai.com/plugins/build/auth — OAuth and transport identity requirements.
- https://github.com/desktop-commander/remote-desktop-commander — comparable remote MCP endpoint/pairing model, not a code dependency.
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners — standard public repository runners.

Next: P1 local-only connector domain and typed wire contract, keeping all existing functionality and no production changes.
