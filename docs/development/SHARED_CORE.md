# Cross-platform core and stable ChatGPT connector (design checkpoint)

Operator direction, 2026-11-26: one shared Rust core, OS-specific implementations behind platform interfaces, one stable plugin for web/mobile and multiple paired devices. Android native6 personal test 5/5 confirmed; preserve that exact guest binary. Windows remains paused. Existing Linux production and custom connector are unchanged.

## Architecture

One Cargo package initially. Organize modules before considering additional crates. The portable library owns protocol and tool contracts, authorization decisions, credential verification, session ownership, normalized audit events, durable job lifecycle/state, upstream tool naming and schema negotiation, compatibility versions and update manifests. Each OS supplies the actual secure operations. The core never assumes that a path check, a process group, Android application UID, Windows Job Object or a particular permission mode is a complete sandbox.

- Linux: existing descriptor containment, Bubblewrap, process supervision, PTY, systemd. Preserve current tool schemas, policy formats and independently pinned acceptance tests.
- Android: Termux/Bionic filesystem and native app UID, secure descriptor walk, tested mutation journal, foreground execution and eventual dedicated worker boundary; Android root must never be inferred from YOLO/FULL.
- Windows: native handles/ACL/reparse checks, Job Objects, ConPTY, service lifecycle. Implement only after native security acceptance.
- Transport: stdio and authenticated HTTP as adapters over one admission/dispatch contract. Never let transport, relay or client request grant local permissions. Tool availability is the intersection of supported runtime capabilities and explicit local grants. Do not advertise unsupported tools as implemented.
- Dashboard/TUI: consume shared status and audit data; privileged administration remains local. Upstream MCP providers and skills stay per-device and per-client.

First extraction: src/core/credential.rs shares existing lowercase 64-hex token shape, SHA-256 verifier decoding and all-verifier constant-time matching between Linux and Android. Existing Linux expiry and disabled checks and Android enabled checks remain adapter-specific inputs. Reject ambiguous active identities. No policy file migration, token rotation or new grant.

## Public plugin architecture (proposed, not implemented)

Stable publisher-owned HTTPS MCP endpoint, independent of any one laptop/phone IP or binary version. A small connector service authenticates the user (review-compatible OAuth), maintains user-to-device pairing and forwards only authorized typed requests over an authenticated outbound device connection. The device agent is still the final policy authority. No arbitrary URL forwarding, no unauthenticated relay, no credential-in-URL, no public administrative listener. Bind each connection and response to the authenticated user, selected device, permitted tool and request ID; bounded messages, replay protection, cancellation, disconnected-device response, explicit device revocation. Store device identity and grants independently of binary updates; no secret or actual machine data in reviewer accounts. Minimize relay storage and retention, no raw tokens in logs. No implicit cloud command queue while device offline.

Stable public catalog should expose explicit reviewable operations (paired device list, health, authorized workspace list/read, narrowly scoped edits when accepted). Public tool schemas stay stable across platform releases, with explicit device selection and capability reporting. No arbitrary shell, root, unrestricted filesystem, or dynamically imported unreviewed upstream tools through public listing; keep private development connector separate. No hidden alternate path to disallowed functionality. Confirm public eligibility with OpenAI before investing in a general device-control listing; directory approval is not guaranteed. Keep local CLI/private custom MCP complete for operator use.

Connection compatibility: independent connector API version, runtime version and persisted-state version; additive changes negotiated, breaking changes require explicit migration/rollback and review where applicable. Rebuild OS-native binaries from same core; preserve device ID, endpoint, credentials, policy and job state. Reconnect after update without re-pairing where compatible; do not promise zero downtime or unchanged catalog for breaking updates. No new persistent service until separately accepted.

## OpenAI submission requirements (checked 2026-11-26)

- Custom MCP connections added on web only: https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt
- Public submission and review: https://developers.openai.com/plugins/deploy/submission and https://developers.openai.com/plugins/deploy/app-review
- Plugin guidelines: https://developers.openai.com/plugins/plugin-guidelines
- Auth: https://developers.openai.com/plugins/build/auth
- Review stable public HTTPS endpoint, publisher identity verification, package, website/support/privacy/terms, isolated sample account and data, five positive/three negative cases, video walkthrough, desktop/mobile testing. A public listing is not automatic mobile approval for every capability. OpenAI guidance flags local execution/arbitrary file/hardware access for partner consultation in relevant plugin submission guidance: https://developers.openai.com/plugins/guides/submit-claude-plugin. Confirm eligibility of Veyl's intended use before submission.

## Gates

1. Shared credential extraction; host tests and real native Android auth regression. Preserve existing endpoint and grants.
2. Extract protocol session, typed tool schemas and capability/permission admission in small increments; migrate Linux without behavior regression (all locked acceptance pins); native Android acceptance. Use compatibility tests across both adapters.
3. Extract job/audit/state and UI contracts; native Android worker isolation, jobs and PTY before exposing execution. Windows later.
4. Build paired-device connector locally with two disposable devices/users; verify cross-tenant isolation, replay, revocation, offline behavior, version/upgrade compatibility and no arbitrary remote URL routing. Select hosting/domain only with operator authorization. Use a safe public tool catalog separate from private administration.
5. Build submission materials and dedicated demo environment; test web/mobile after approval. No publishing, public routing, credentials, hosting expense or production changes without exact-candidate approval and applicable review.

Native6 remains the last personally verified Android checkpoint until later native tests and personal acceptance.
