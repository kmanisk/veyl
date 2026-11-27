# Standard and YOLO acceptance contract

Standard is the default and requires explicit scoped grants. YOLO is a durable
local decision to allow native commands as the gateway UID. The OS still
controls privileges. The gateway must never elevate itself. Same-UID native
commands can inspect or modify user data and Veyl state, including credentials
and audit files. Audit and ownership checks protect the MCP interface and do
not form a security boundary against an authorized native process.

| Case | Required observation |
| --- | --- |
| Standard | Deny tools without grants. Deny escaping file paths. Execute granted commands inside the offline workspace sandbox. Fail closed if isolation is unavailable. |
| Legacy sandboxed YOLO | Opening old state never authorizes native execution. Only a locally confirmed, audited transition creates a native grant. |
| Legacy FULL | A valid prior audited FULL grant continues to receive its existing native access and explicit tools. Migration records the retained authority without elevating other clients. |
| Native YOLO | Execute an ordinary-user command without Bubblewrap, use a sibling path outside the workspace, access a local network fixture and run a real Git operation. |
| OAuth | Reject remote self-escalation. Legacy OAuth consent never acquires native access. Verify explicit local approval, fresh authorization, reconnect, downgrade and revocation. |
| Runners | Verify native pipe and PTY, deadline and optional quotas, bounded output, duplicate request handling, cancellation, and recovery across gateway exit. |
| Goals | Exercise persistent roadmap, handoff, evidence, linked jobs, transitions, authentication and cross-client denial through actual MCP, CLI and operator views. |
| Persistence | Reject ambiguous and corrupt records. Simulate interruption before and after atomic publication and reconcile delivery retries. |
| Distribution | Verify one optimized ELF, isolated updater rollback, unchanged production and operator acceptance of the exact checksum. |

The external three-mode gate assumes separately selectable FULL, sandboxed
broad YOLO, and legacy scoped YOLO promotion. Its assertions about a separate
FULL selector, YOLO namespace protection, network and path masks, and automatic
availability of sandboxed YOLO are historical. The independent files and their
pins remain immutable. AGY owns the replacement locked acceptance gate. This
specification and repository regression tests are implementation evidence.

## Legacy gate disposition

Run the pinned tests against the staged candidate without editing their
inputs. Retain the receipts for their applicable assertions and report the
remaining red cases explicitly.

- The supplementary three-mode gate requires schema 3 migration, the FULL
  selector, the sandboxed YOLO selector, preservation of native mode across
  disable/enable, and older selector-specific messages. Schema 4 and
  explicit native confirmation replace those assertions.
- The pinned mode, FULL, migration, persistence, permanent-permission and
  broad-gateway suites exercise the retired selectors or assumed masks.
  Preserve their checks of authentication, client isolation, fail-closed
  admission, and ordinary OS permissions in the replacement suite.
- The old audit-anchor suite seeds its ledger through the retired
  `yolo enable` command. The repository operator regression independently
  verifies the anchor through current commands, including append, rotation,
  different ledgers, modified records, and tampering.
- The old durable-jobs process-tree fixture writes a PID in the workspace's
  parent. That write conflicts with required Standard confinement. The
  replacement cancellation scenario must use in-workspace observation for
  Standard and a separate native process-tree cancellation proof for YOLO.

Independent AGY review must exercise the exact candidate artifact and own
new locked test inputs. The in-repository tests and the developer-run legacy
suite are implementation receipts.

## Recovery gate for 0.7.0-beta

Verify migration from an actual 0.6.1-beta FULL grant. An enabled grant
retains its explicit tools and native scope. A disabled grant remains
disabled in Standard, and re-enable alone must never activate native
execution. Replay both an old native revision and an enabled Standard
snapshot after revocation.

Exercise interruption with the pending marker on each side of policy
publication. Require audited Standard recovery and fresh authenticated
MCP initialization. Simulate a real user-service startup failure after
schema 4, refuse the actual 0.6.1-beta backup even for a historical journal
without a separate policy digest, and run forward recovery with the
candidate. Confirm the saved audit anchor, exact policy and job receipt
bytes, and persisted goal revision after authenticated readiness.

For the old assertion-by-assertion analysis, see [Legacy failures](LEGACY_FAILURES.md).
