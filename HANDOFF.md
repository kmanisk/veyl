# Gateway Milestone 1 — Working Handoff

This is a separate greenfield product, **not** the harness project and not
production BridgeDev. See `AGENTS.md` and `SPEC.md` for constraints.

Stage: initial skeleton and independently authored locked tests; no agent code
accepted yet. The initial `src/main.rs` deliberately returns an error.

- Protocol: stdio JSON-RPC 2.0, legacy MCP 2025-11-25 initialize lifecycle.
- Crates: std plus pinned serde_json 1.0.154; no SDK downloaded or installed.
- Locked black-box tests: `/home/onyx/Projects/rust-mcp-gateway-lab/acceptance_m1/locked_stdio_acceptance.py`.
- Trusted harness: `/home/onyx/Projects/rust-mcp-gateway-lab/`.
- Expected terminal state for an accepted attempt: `READY_FOR_USER_REVIEW`.
- Agent is restricted to source files; do not alter manifests, specs or tests.

No commit/merge/deploy of generated code without a manual review. All updates,
verification receipts, constraints and blockers should be appended here.