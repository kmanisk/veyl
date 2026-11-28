# Veyl development instructions

Read [development rules](docs/development/AGENT_RULES.md),
[specification](docs/development/SPEC.md), [handoff](docs/development/HANDOFF.md)
and [status](docs/development/STATUS.md) before working.

Active repository: `~/Projects/veyl`, branch `main`.
Historical lab and locked acceptance suites remain external, under
`~/.local/share/veyl-development/`. Preserve all independent test pins.
Historical paths in the archived documents are historical, not active paths.
Run the required system/project context bootstrap before host work.
Do not change unrelated services, credentials or policy grants.

Operator instruction (2026-11-27): implementation and routine verification
are owned by ChatGPT through BridgeDev. Do not automatically delegate every
checkpoint to AGY or Codex. Run relevant regression, negative-control and
locked acceptance checks directly; distinguish BridgeDev verification from
independent AGY acceptance. Seek separate independent review only where
requested or genuinely necessary for an unresolved high-risk security gate.
Preserve historical drafts and independent locked evidence. Never claim an
untested change passed. This supersedes earlier agent workflow notes.

Operator approval gate (all changes, not just web UI): deliver a runnable
isolated candidate and exact verification evidence before production promotion.
The operator must be able to inspect and personally test new behavior (web,
TUI, CLI, tools, backend) using candidate builds or an isolated instance.
Explicit approval of that exact candidate is required before installing,
restarting production, pushing main or publishing. A passing agent test is
not operator acceptance. Never bump the version without explicit instruction.
See docs/development/PREVIEW.md.

Release workflow (operator instruction, 2026-11-25): when the operator explicitly approves an exact tested release candidate for update, that approval includes local Veyl upgrade (all three binaries in the managed user and Cargo bin directories), fast-forward promotion to canonical main, GitHub push and versioned GitHub release, and publication of the matching crate to crates.io. Carry out all of these without separate repeated approval, subject to preflight, tests, credentials, rollback, and post-upgrade verification. Preserve client grants, modes, upstream roots, unrelated packages/services and existing jobs; approval never authorizes FULL escalation or new tool grants. Report any blocked destination, not an assumed success.

Artifact retention: put pending worktrees under
`~/.local/share/veyl-development/candidates/`, reuse the explicit shared
`~/Projects/veyl/target` Cargo cache for serial builds, and store receipts in
`~/.local/share/veyl-development/artifacts/<commit>/`. After operator-approved
promotion, retain the accepted source commit, verified rollback binaries and
receipts. Prune only inspected, inactive, reproducible build caches. Never
clean an active or unaccepted source tree, the locked lab, or rollback data.

Build safety (2026-11-26 disk-exhaustion incident): use the on-demand
`python3 -B tests/guarded_cargo.py <build|test|check|clippy> ...` wrapper for
agent Cargo verification. It serializes cooperating builds with a shared
lock, uses the canonical shared target/build cache, disables incremental and
dev/test debug symbols, refuses admission below 38 GiB free (operator-approved
2026-11-28 revision from 40 GiB), and stops its
own process group below 15 GiB. No permanent watcher or automatic cleanup.
Coordinate with other agents; unguarded builds and instantaneous disk spikes
are not contained by this cooperative guard. Do not bypass a storage refusal.
