# Gate 3 independent fixture review requested

Implementation will preserve the confirmation boundary, legacy offline
policy and process containment. The three cases below need independent
review. The current pins matched before and after preflight.

| Locked fixture | Case | SHA-256 |
| --- | --- | --- |
| `acceptance_pass3_modes/locked_mode_suites.py` | `test_04_yolo_mode_network_allowed` and `test_05_full_mode_no_sandbox_nothing_masked` | `f627919da7ed0f9412be808f349fb75c19404387f1e17588e598239b88081972` |
| `acceptance_pass2_jobs/locked_durable_jobs.py` | `test_08_cancel_kills_child_process_tree` | `ec71c4966f2639e34c6bbe7357d78a4b7adca8f38f84dd08ce43ae59dc04ee55` |
| `acceptance_pass3_yolo/locked_yolo_service.py` | Legacy regression controls, including SEC-04 and job isolation | `f45bdfd48c386a7d07e3ac9fe15d1884de6e4cdbb1f61bd3900f63e093f482d6` |

- **FULL case 05, lines 435, 448–457 and 468–469.** The fixture writes raw
  mode state and expects unsandboxed execution without an audited transition.
  Start from Standard. Prove raw FULL and missing confirmation are rejected.
  Use the confirmed local CLI against synthetic data and a throwaway HOME.
  Verify durable approval, restart, host namespace behavior, same-UID access
  to a synthetic marker and real job supervision. The old commit should
  fail the positive control. Mutants that drop confirmation or keep the
  sandbox must fail the corresponding assertion.
- **Network case 04, lines 82 and 363–406.** The fixture invokes legacy
  enable on version 1 and expects an IPv4 route to a public address in an
  offline verifier. Use a disposable loopback listener in the verifier.
  Require denial for Standard and legacy scoped YOLO, including after
  restart. Require connectivity after explicit broad opt-in. Case 03
  also needs explicit broad activation and a positive off-root operation
  to prove its masking assertion applies to the intended profile.
  Gate 2 must fail the broad positive control. Mutants that enable
  networking or widen roots for the legacy profile must fail.
- **Jobs case 08, lines 35–60, 242–253 and 319–327.** The fixture executes a
  script and expects a PID marker outside its Standard workspace, then
  treats the child's namespace-local PID as the verifier's PID. Move the
  script and marker inside the granted workspace. Establish a unique live
  descendant from the verifier and match kernel start identity before and
  after both cancellation and timeout. Use an approved output marker for
  the positive control, and probe a synthetic path just outside the root
  for the negative control. The old commit should fail any newly required
  namespace or out-of-root denial assertions. A mutant omitting group and
  descendant cleanup must fail with a surviving descendant.

For SEC-01, run the named local reset command and prove it returns Disabled
to Standard without restoring prior grants. Gate 2 must fail that positive
control. Preserve the remote authorization denial and add a mutant that
restores the old mode.

Please independently record the old and new pins, genuine red baselines,
positive and negative controls, and mutation outcomes. Re-lock accepted
changes in the trusted harness. Migration rollback, protected object
aliases, persistence mounts, socket exposure, audit anchors and service
planning need their own independent evidence. This handoff leaves the
locked suites and harness untouched.

The trusted harness's own
`test_pass3_suites_pinned_and_required_on_m3_branch` currently fails on
`5 != 4`. Its fixed Pass 3 suite count predates the fifth registered suite.
Please reconcile the harness regression assertion with the actual intended
registry during independent review. This is separate from the locked case
results and does not require a gateway code change.
