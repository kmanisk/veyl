# Instruction packages

Configure an absolute, operator-owned `skills_dir` outside the served
workspace, job and audit roots. Each package lives in a child directory
named after the skill. Use lower-case letters, digits and hyphens in the
name. The gateway reads only that directory's UTF-8 `SKILL.md` and limits
it to 64 KiB.

```markdown
---
name: code-review
description: Review a proposed change for correctness and security
version: 1.0.0
---
# Review procedure

Read the changed source and report findings with relevant code references.
```

The metadata supports plain, single-line `name`, `description` and
optional `version` values. The name must match the directory. The
metadata must close before the Markdown body starts.

Grant the client `skills_list` and `skills_read` through its ordinary
`tools` list, and list each approved name in the client's `skills` array.
Discovery returns metadata for authorized, enabled and valid packages.
`skills_read` takes a `name` argument and returns the Markdown as text.
Malformed, missing, aliased or ungranted packages are unavailable.
The audit ledger records the authenticated client and request outcome.

```sh
mcp-gateway skills disable code-review --config "$config"
mcp-gateway skills enable code-review --config "$config"
```

Availability changes persist and affect the next request in an existing
session. Enabling a globally disabled skill preserves the original
per-client grants. An interrupted local update must be completed by
repeating the same command. Skills never execute, alter the authorization
mode, or grant new tools. A configured `skills_run` declaration has no
runtime capability.
