# Nightshift Demo for Veyl

This standalone demo validates BridgeDev parity and Nightshift autonomous primitives against a running Veyl gateway instance:

1. **Host & Service Diagnostics:** `system_info` and `service_status` tool queries.
2. **Ephemeral Worktree Isolation:** Runs commands in a transient Git worktree (`task_run` with `ephemeral_worktree: true`) and commits checkpoints automatically.
3. **Idempotency & Replay:** Prevents duplicated task executions via client-provided `request_id`.
4. **Durable Background Jobs:** Submits, monitors, and streams output chunks with `start_job`, `job_wait`, and `job_logs`.
5. **Process Cancellation:** Cleanly signals and terminates running jobs via `cancel_job`.

## Running the Demo

```sh
python3 examples/nightshift_demo/demo.py [PATH_TO_MCP_GATEWAY_BINARY]
```

By default, the script looks for `target/debug/mcp-gateway` relative to the repository root.
