# Review of the 65 red legacy cases

This review uses the original candidate's failure logs and the immutable
external inputs. It follows the failing assertion or its setup to the
current contract. A red case still needs replacement evidence when the
security or reliability requirement survives the change. This review is
separate from the new independent gate.

| Suite and case | Disposition |
| --- | --- |
| three_modes 01 legacy scoped migration | Retired setup and schema-3 expectation. Preserve explicit local approval and audit replay resistance. |
| three_modes 02 CLI and FULL confirmation | Separate FULL selector retired. Native YOLO confirmation replaces it. |
| three_modes 03 disabled state | Retaining native authority across disable and enable is superseded. The independent review found the disabled legacy FULL path still did so. Covered by the new migration regression. |
| three_modes 04 mode isolation | Three-mode matrix retired. Standard confinement and ordinary-user native execution still require tests. |
| three_modes 05 mode persistence | Old selector failed before restart. Explicit native grant persistence still applies. |
| three_modes 06 legacy enable refusal | Refusal remains required. The fixture expects an obsolete three-choice help message. |
| mode_suites 01 disabled transition | Unqualified legacy recovery command failed on the old schema. Explicit migration and current revocation are required. |
| mode_suites 03 Protected-path masking | Native YOLO no longer masks gateway or home state. Standard isolation remains required. |
| mode_suites 04 network allowed | Legacy Broad activation failed before probing the network. Current native loopback and offline Standard need positive and negative controls. |
| mode_suites 05 unsandboxed FULL | The old CLI error string and selector are retired. Restrictions at the OS UID remain applicable. |
| durable_jobs 08 cancel process tree | The child tries to write its PID outside the scoped workspace. The replacement uses an in-workspace heartbeat for Standard and a host PID for native YOLO. Both exercise process cleanup. |
| persistence_policy 08 ambient persistence | The old FULL selector failed before native access. Same-UID exposure remains documented and must be understood at consent. |
| yolo_service 01 lifecycle | Old status spelling and mutation CLI. Current durable local mode transitions still apply. |
| yolo_service 03 root escape | The old scoped-YOLO setup failed. Current tests exercise denied Standard paths and authorized native paths. |
| yolo_service 04 client isolation | Legacy status spelling hid the isolation assertion. Owner isolation remains required. |
| yolo_service 05 immediate updates | Old selector did not publish a grant. Current downgrade and revocation must affect admission immediately. |
| yolo_service 06 audit logging | No legacy YOLO grant was created, so the expected read audit entries were absent. Native operations still require audit. |
| yolo_service 11 kernel isolation | Old YOLO selector and sandbox expectation. Kernel isolation belongs to Standard in the new contract. |
| migration_safety 02 disabled retention | The older CLI expected `mode=disabled`. The activation flag remains separate. Test the disabled flag and bearer denial. |
| migration_safety 03 scoped mode | Retired scoped-YOLO setup. Legacy grant must never silently become native. |
| migration_safety 04 offline mode | Retired scoped-YOLO setup. Legacy grants resolve to offline Standard. |
| migration_safety 09 explicit upgrade | The attempted Broad transition uses the retired selector. Native now requires explicit local confirmation. |
| migration_safety 10 Broad unavailable | Obsolete sandbox preflight and error text. Standard still fails closed when isolation is unavailable. |
| migration_safety 11 downgrade | Old activation failed first. Current downgrade must remove native authorization and survive restart. |
| migration_safety 13 interrupted policy | Legacy reset invocation cannot recover a schema-4 transition. Current tests quarantine and recover before and after replacement, then perform an authenticated MCP handshake. |
| migration_safety 14 replay | The fixture ignores failure from legacy grant creation and revocation. It replayed an ordinary unmodified policy. The invariant is applicable. New tests replay actual revoked native, pre-migration FULL, and enabled Standard snapshots. |
| permanent_permissions 01 FULL selector | Selector and confirmation string are retired. Fresh local native confirmation remains required. |
| permanent_permissions 02 restart | Old FULL setup failed. Confirmed native execution must survive gateway restart. |
| permanent_permissions 03 recreation | Old setup failed. Owner can reconnect and recover existing jobs and goals. |
| permanent_permissions 04 simulated reboot | Old FULL label was expected. Test native policy persistence separately from Linux process lifetime. |
| permanent_permissions 06 renewal | Old FULL setup failed. The explicit native mode remains persistent and authentication expiry still applies. |
| permanent_permissions 07 downgrade | Old FULL label was expected. No implicit elevation after migration or client re-enable. |
| permanent_permissions 09 explicit disable | Legacy activation failed first. Current tests check denial and replay after disable. |
| permanent_permissions 11 reset disabled | Legacy reset CLI retired. Re-enable restores Standard access. |
| permanent_permissions 12 expiry | Old FULL label was expected. Authorization and bearer expiry remain separate. |
| permanent_permissions 14 file matrix | Old FULL setup failed. Native file access and OS protections still apply. |
| permanent_permissions 17 Broad persistence | Retired Broad activation. Native consent persists across restart. |
| audit_anchors 01 export | Retired setup command produced no ledger. Export integrity still applies. |
| audit_anchors 02 schema | No exported checkpoint due to setup. Anchor encoding still applies. |
| audit_anchors 03 identity | No exported checkpoint due to setup. Verify ledger identity. |
| audit_anchors 04 sequence | No exported checkpoint due to setup. Verify sequence binding. |
| audit_anchors 05 hash | No exported checkpoint due to setup. Verify hash binding. |
| audit_anchors 06 append | Retired setup and append commands failed. Verify anchored prefix after appending current transitions. |
| audit_anchors 07 earlier checkpoint | No fixture anchor. Earlier anchors must remain verifiable. |
| audit_anchors 08 modified record | No fixture anchor. Tampered anchored records must still fail. |
| audit_anchors 10 wrong identity | No fixture anchor. Different ledger identity must fail. |
| audit_anchors 11 wrong hash | No fixture anchor. Modified hash must fail. |
| audit_anchors 12 absent sequence | No fixture anchor. Malformed schema must fail. |
| audit_anchors 14 future sequence | No fixture anchor. Out-of-range sequence must fail. |
| audit_anchors 15 no credentials | No fixture anchor. Export must omit verifier and secret data. |
| audit_anchors 16 overwrite controls | Initial export failed due to setup. Existing-file protection remains applicable. |
| full_file_tools 02 scoped YOLO containment | Retired legacy setup. Standard continues to confine files. |
| full_file_tools 03 outside read | Old FULL selector failed before opening the file. Native host reads remain applicable. |
| full_file_tools 04 outside write | Old FULL selector failed before mutation. Native host writes require audit and OS permission. |
| full_file_tools 05 outside patch | Old FULL selector failed before mutation. Native patch validation remains applicable. |
| full_file_tools 06 Unix permissions | Old FULL selector failed first. Native execution still runs as an ordinary user. |
| full_file_tools 07 revoked FULL | Old FULL setup failed. Revoked native grants must fail current admission and replay checks. |
| broad_gateway 06 real job admission | Retired Broad selector. Native command execution and Standard job confinement still apply. |
| broad_gateway 07 host files | Retired Broad selector. Native host file access still applies. |
| broad_gateway 08 state masking | Superseded explicitly. Native access can reach same-UID state. |
| broad_gateway 09 user path masking | Superseded explicitly. Standard remains scoped. |
| broad_gateway 10 process isolation | PID namespace expectation superseded for native jobs. `NoNewPrivs` remains required. |
| broad_gateway 11 inherited descriptors | Old Broad selector failed first. Descriptor hygiene remains a runner invariant. |
| broad_gateway 12 network | Old Broad selector failed first. Native network access tested with a controlled loopback socket. |
| broad_gateway 14 restart | Old Broad selector failed first. Current persistence checked through a fresh session. |

Newly confirmed defects were executable rollback across an incompatible
schema, stale authorization after a disabled FULL client re-enabled, and
re-admission by replaying an enabled Standard policy after an audited
disable. The development regressions cover each directly. Neither this
case list nor the replacement development tests stand in for AGY's gate.
