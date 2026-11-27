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
   `goal_next`. Use `goal_resume` after a pause or after clearing blockers.
5. Record evidence for each criterion and complete the roadmap before calling
   `goal_complete`. Use `goal_cancel` to terminate a goal or `goal_update`
   with state `failed` to record a failed attempt.

Pause and cancel affect the goal. Each shell job has its own lifetime and
cancellation control. Veyl stores state for AI clients between sessions.
The connected client supplies model turns and decides when to save a handoff.
There are no model calls or automatic reasoning sessions built into goals.

In Standard, grant the `goal_*` tools by name. Newly confirmed YOLO includes
them when a private audit ledger is available. The goal registry is a
private atomic snapshot alongside the policy, with 128 goals, a 2 MiB store
limit and up to twelve recent checkpoints per goal. Each goal is limited
to 48 KB. The caller can reread the current revision after interrupted
delivery. Malformed records fail closed.

## Operator access

```sh
veyl goal list --config /path/to/clients.json
veyl goal get GOAL_ID --config /path/to/clients.json
veyl goal pause GOAL_ID REVISION --config /path/to/clients.json
veyl goal resume GOAL_ID REVISION --config /path/to/clients.json
veyl goal cancel GOAL_ID REVISION --config /path/to/clients.json
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
