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

Operator approval gate (all changes, not just web UI): deliver a runnable
isolated candidate and exact verification evidence before production promotion.
The operator must be able to inspect and personally test new behavior (web,
TUI, CLI, tools, backend) using candidate builds or an isolated instance.
Explicit approval of that exact candidate is required before installing,
restarting production, pushing main or publishing. A passing agent test is
not operator acceptance. Never bump the version without explicit instruction.
See docs/development/PREVIEW.md.
