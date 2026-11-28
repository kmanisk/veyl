# Durable development goals

A goal stores a client's objective, roadmap, acceptance criteria, active task,
decisions, findings, blockers, evidence, linked jobs and resumable checkpoints.
State and revisions persist across gateway restart. The client or workspace
that created a goal can retrieve it in a new MCP session. OAuth goals are
bound to the same grant family and survive refresh, while a new authorization
family receives its own namespace. The paired local dashboard and CLI provide
operator access.

## Continue through MCP

1. Use `goal_create` with a description, a stable `request_id`, acceptance
   criteria and a roadmap. Reuse that ID only for identical creation inputs.
2. Read `goal_next` to find the current or next incomplete task. Use
   `goal_update` with the latest revision to record progress, mark completed
   tasks and attach owned durable job IDs.
3. Use `goal_checkpoint` with the latest revision and a compact handoff. Note
   completed work, outstanding work, files, commits, linked jobs, verification
   results and the next action. `goal_next` returns the latest handoff.
4. To resume in a later MCP session, use `goal_list`, `goal_get` and
   `goal_next`. Use `goal_resume` after a pause. To clear blockers, update the blocker list and state together.
5. Record evidence for each criterion and complete the roadmap before calling
   `goal_complete`. Use `goal_cancel` to terminate a goal or `goal_update`
   with state `failed` to record a failed attempt.

Manual continuation uses turns supplied by the connected client. Each linked
job has independent controls. The operator may separately start the bounded
foreground adapter below to supply automatic turns.

In Standard, grant the `goal_*` tools by name. Newly confirmed YOLO includes
them when a private audit ledger is available. The goal registry is a
private atomic snapshot alongside the policy, with 128 goals, a 2 MiB store
limit and up to twelve recent checkpoints per goal. Each goal is limited
to 48 KB. The caller can reread the current revision after interrupted
delivery. Malformed records fail closed.

## Operator access

```sh
veyl goal list
veyl goal get GOAL_ID
veyl goal pause GOAL_ID
veyl goal resume GOAL_ID
veyl goal cancel GOAL_ID
```

Use `goal create --client CLIENT` with the MCP creation JSON on stdin. Use
`goal update` or `goal checkpoint` with the corresponding JSON on stdin.
Open Goals in the paired local dashboard for controls, roadmap, checkpoint
history and linked logs. In the terminal monitor, press `8` for Goals, Enter
for details, `l` for linked logs, `P` to pause, `R` to resume, or `C` to cancel.


During executable recovery, the goal registry stays alongside the current
policy. Verify a recovered goal with `veyl goal get GOAL_ID --config PATH`.
Its revision and linked job IDs should match the checkpoint recorded
before recovery.

## Run a goal from the terminal

```sh
veyl goal create 'Implement and verify the parser change' \
  --client dev --request-id parser-change \
  --criterion 'Run and pass the focused parser tests'
veyl goal list
veyl goal get GOAL_ID
veyl goal pause GOAL_ID
veyl goal resume GOAL_ID
veyl goal cancel GOAL_ID
```

The CLI uses the unified registry by default. Omit `--client` when only one
eligible static client exists. An explicit `--request-id` is recommended for
delivery retries. Without it, CLI creation deduplicates the same objective and
criteria within the same owner and workspace. The JSON forms remain available.

The manual MCP workflow runs through the client's own model session, including
for OAuth. To run automatically from a terminal, explicitly choose a local
adapter that can request one model turn and grant the goal's static owner native
YOLO access. Veyl does not discover or configure model credentials.

```sh
veyl goal run GOAL_ID --runner /absolute/path/to/approved-adapter \
  --confirm-runner --iterations 8 --seconds 900 --retries 2
```

The controller runs in the foreground. The currently admitted turn is a signed
durable job in the owner's workspace, so exiting the controller leaves that
turn supervised. Repeat `goal run` with the same adapter to reconcile the
original receipt and continue the remaining budget. One controller may operate
a goal at a time. If delivery cannot be proved, Veyl stops and records the
uncertainty. Review the workspace, receipts and logs before explicitly using
`goal retry` to authorize a fresh run. The same command accepts a new runner or
budget after exhaustion, stagnation or a failed goal. A pause ends the current
turn. Reconcile it, then use `goal resume` and `goal run` for the remaining
budget. Resolve blockers with an update that clears them and sets state to
running. Cancelling stops the active runner, while independently linked jobs
retain their own controls.

Veyl stops automatically on recorded acceptance and completed roadmap,
a blocker, three consecutive turns without additional verified work, excessive
runner failures, time or iteration budget exhaustion, or cancellation. Defaults
are eight turns, 900 seconds and up to two retries after failed turns. Each run
allows at most 16 turns and 86,400 seconds. The goal retains up to 16 recent
turns and up to 32 job links. The controller never reruns a completed turn when it
can reconcile the signed receipt. Neither Veyl nor the adapter can guarantee
exactly-once external side effects after an interrupted command.

### Adapter contract

Veyl invokes the configured executable in the goal workspace using the
existing native job supervisor. It sends one UTF-8 JSON request split across
argv elements. Concatenate the elements in order with no separators. The
`veyl-goal-turn-v1` object includes the objective, iteration, criteria,
roadmap, active task, last handoff and prior attempt. Context is limited to
8 KB. Never put credentials in goal fields or argv. The adapter writes one
JSON object to stdout and returns 0. Send diagnostic logs to stderr. The
optional fields below use the same shapes as the MCP goal tools.

```json
{
  "progress": "Reproduced the failure with a focused test",
  "roadmap": [
    {"id": "fix", "description": "Repair the parser", "completed": false},
    {"id": "check", "description": "Run the focused tests", "completed": false}
  ],
  "findings": ["The parser rejected a valid input"]
}
```

The result may also contain `acceptance_criteria`, `blockers`, `decisions`,
`evidence` and `checkpoint`. Preserve criterion text, existing criterion
evidence, and completed tasks. Attach test evidence to each completed criterion.
Veyl validates record structure and completion requirements. The adapter is
responsible for executing verification and accurately reporting its results.
Operator inspection remains part of release acceptance.

A Codex adapter can use `codex exec --sandbox workspace-write --ephemeral
--ignore-user-config --output-last-message FILE -` with the assembled prompt on
stdin. Provision a dedicated `CODEX_HOME` and model access explicitly inside
the adapter. Review Codex's workspace trust and provider settings before use.
Direct Codex console output to stderr and return the validated final JSON file.
An AGY adapter can use its installed `--print`, `--sandbox`, `--mode
accept-edits` and bounded `--print-timeout` options with an operator-provisioned
account. Inspect the final response format of the selected CLI before adding
it. Veyl launches neither provider until an operator selects and confirms its
adapter. Use a small, private adapter that keeps credentials out of logs and
budgets provider spend separately from Veyl's time and turn limits.
