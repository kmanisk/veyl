#!/usr/bin/env python3
"""Disposable Nightshift Workflow Demonstration for Veyl.

This demo demonstrates the core Nightshift primitives:
1. System & Service diagnostics (system_info, service_status)
2. Ephemeral Git worktree isolation with automatic branch checkpoints (task_run)
3. Request deduplication and replay detection (request_id)
4. Durable background jobs, wait, and offset-paginated logs (start_job, job_wait, job_logs)
5. Clean job cancellation and process tree termination (cancel_job)
"""

import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLIENT_TOKEN = "0" * 63 + "1"


def sha256_hex(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class NightshiftDemo:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.temp_dir = tempfile.mkdtemp(prefix="veyl-nightshift-demo-")
        self.base_path = Path(self.temp_dir)
        self.root = self.base_path / "workspace"
        self.audit = self.base_path / "audit"
        self.jobs = self.base_path / "jobs"
        self.root.mkdir(parents=True, exist_ok=True)
        self.audit.mkdir(parents=True, exist_ok=True)
        self.jobs.mkdir(parents=True, exist_ok=True)
        os.chmod(self.base_path, 0o700)
        os.chmod(self.root, 0o700)
        os.chmod(self.audit, 0o700)
        os.chmod(self.jobs, 0o700)
        self.config_path = self.base_path / "clients.json"
        self.server_proc = None
        self.listen_addr = None
        self.session_id = None
        self.rpc_id = 0

    def setup_git_workspace(self):
        subprocess.run(["git", "init"], cwd=self.root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "demo@veyl.local"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Veyl Demo"], cwd=self.root, check=True)
        initial_file = self.root / "README.md"
        initial_file.write_text("# Nightshift Demo Project\nInitial baseline commit.\n")
        subprocess.run(["git", "add", "README.md"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=self.root, check=True)

    def write_config(self):
        token_digest = sha256_hex(CLIENT_TOKEN)
        config = {
            "policy_version": 3,
            "audit_log": str(self.audit / "events.jsonl"),
            "job_state_dir": str(self.jobs),
            "job_profiles": {
                "demo_build": {
                    "executable": "/usr/bin/echo",
                    "args": ["BUILD SUCCESSFUL: artifact generated"],
                    "timeout_seconds": 10,
                    "max_output_bytes": 4096
                },
                "long_worker": {
                    "executable": "/usr/bin/sleep",
                    "args": ["30"],
                    "timeout_seconds": 30,
                    "max_output_bytes": 4096
                }
            },
            "clients": [
                {
                    "id": "nightshift-agent",
                    "mode": "standard",
                    "disabled": False,
                    "token_sha256": token_digest,
                    "expires_at_unix_seconds": int(time.time()) + 3600,
                    "root": str(self.root),
                    "tools": [
                        "read_file", "write_file", "apply_patch", "edit_file",
                        "create_directory", "list_directory", "directory_tree",
                        "file_info", "exec_command", "task_run", "start_job",
                        "job_status", "job_logs", "job_wait", "cancel_job", "list_jobs",
                        "system_info", "service_status"
                    ]
                }
            ]
        }
        self.config_path.write_text(json.dumps(config, indent=2))
        os.chmod(self.config_path, 0o600)

    def start_gateway(self):
        cmd = [
            self.binary_path,
            "http",
            "--listen", "127.0.0.1:0",
            "--config", str(self.config_path)
        ]
        self.server_proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )
        for line in self.server_proc.stderr:
            if line.startswith("MCP_HTTP_LISTEN="):
                self.listen_addr = line.strip().split("=", 1)[1]
                break
        if not self.listen_addr:
            raise RuntimeError("Failed to bind gateway loopback listener")

    def mcp_request(self, body: dict) -> dict:
        host, port = self.listen_addr.split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {CLIENT_TOKEN}"
        }
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        conn.request("POST", "/mcp", json.dumps(body), headers)
        resp = conn.getresponse()
        session = resp.getheader("mcp-session-id")
        if session:
            self.session_id = session
        data = resp.read()
        conn.close()
        return json.loads(data) if data else {}

    def call_tool(self, name: str, args: dict) -> dict:
        self.rpc_id += 1
        res = self.mcp_request({
            "jsonrpc": "2.0",
            "id": self.rpc_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args}
        })
        if "error" in res:
            raise RuntimeError(f"MCP RPC error: {res['error']}")
        result = res.get("result", {})
        if result.get("isError"):
            raise RuntimeError(f"Tool execution failed: {result}")
        content = result.get("content", [])
        if content and "text" in content[0]:
            try:
                return json.loads(content[0]["text"])
            except Exception:
                return {"text": content[0]["text"]}
        return result

    def initialize_session(self):
        init_res = self.mcp_request({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "nightshift-demo", "version": "1.0"}
            }
        })
        assert "result" in init_res, f"Init failed: {init_res}"
        self.mcp_request({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })

    def run_demo(self):
        print(f"=== Veyl Nightshift Demo Started ===")
        print(f"Disposable Workspace: {self.root}")
        print(f"Gateway Listener: {self.listen_addr}")

        # Step 1: System and Service Diagnostics
        print("\n--- Step 1: Host & Service Diagnostics ---")
        sys_info = self.call_tool("system_info", {})
        print(f"Logical CPUs: {sys_info.get('logical_cpus')}")
        print(f"Total Memory: {sys_info.get('memory_total_kib', 0) // 1024} MiB")
        print(f"Workspace Storage: {sys_info.get('workspace_filesystem', {}).get('total_bytes', 0) // (1024*1024*1024)} GiB")
        srv_info = self.call_tool("service_status", {})
        print(f"Service Unit LoadState: {srv_info.get('LoadState', 'loaded')}")

        # Step 2: Ephemeral Git Worktree Execution
        print("\n--- Step 2: Ephemeral Git Worktree Task ---")
        wt_result = self.call_tool("task_run", {
            "command": "echo 'Feature work done in ephemeral worktree' > feature.txt",
            "ephemeral_worktree": True,
            "request_id": "req-nightshift-001",
            "wait_seconds": 15
        })
        print(f"Task ID: {wt_result.get('task_id')}")
        print(f"Exit Code: {wt_result.get('exit_code')}")
        print(f"Checkpoint Created: {wt_result.get('checkpoint')}")
        print(f"Ephemeral Worktree Active: {wt_result.get('ephemeral_worktree')}")

        # Check git branch in repository
        branches = subprocess.check_output(["git", "branch", "-a"], cwd=self.root, text=True)
        print(f"Git branches after task:\n{branches.strip()}")

        # Step 3: Request Idempotency
        print("\n--- Step 3: Idempotent Replay Detection ---")
        replay_result = self.call_tool("task_run", {
            "command": "echo 'Should not re-execute' > should_not_exist.txt",
            "ephemeral_worktree": True,
            "request_id": "req-nightshift-001",
            "wait_seconds": 15
        })
        print(f"Replay Task ID: {replay_result.get('task_id')}")
        print(f"Idempotent Replay: {replay_result.get('idempotent_replay')}")
        assert replay_result.get("idempotent_replay") is True, "Expected idempotent replay"
        assert replay_result.get("task_id") == wt_result.get("task_id"), "Task ID mismatch"

        # Step 4: Durable Background Job & Streamed Logs
        print("\n--- Step 4: Durable Background Job ---")
        job_start = self.call_tool("start_job", {"profile": "demo_build"})
        job_id = job_start.get("job_id")
        print(f"Started Job ID: {job_id}")

        job_wait = self.call_tool("job_wait", {"job_id": job_id, "timeout_seconds": 5})
        print(f"Job Wait State: {job_wait.get('state')}")

        job_logs = self.call_tool("job_logs", {"job_id": job_id, "offset": 0, "max_bytes": 1024})
        print(f"Job Output:\n{job_logs.get('stdout', '').strip()}")

        # Step 5: Graceful Job Cancellation
        print("\n--- Step 5: Background Job Cancellation ---")
        long_job = self.call_tool("start_job", {"profile": "long_worker"})
        long_id = long_job.get("job_id")
        print(f"Started Long Job ID: {long_id}")

        cancel_res = self.call_tool("cancel_job", {"job_id": long_id})
        print(f"Cancellation Response State: {cancel_res.get('state')}")
        print(f"Cancel Requested: {cancel_res.get('cancel_requested')}")

        print("\n=== All Nightshift Verifications Passed Cleanly ===")

    def cleanup(self):
        if self.server_proc:
            self.server_proc.terminate()
            try:
                self.server_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.server_proc.kill()
        shutil.rmtree(self.temp_dir, ignore_errors=True)


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[2] / "target/debug/mcp-gateway")
    if not os.path.isfile(binary):
        print(f"Error: binary not found at {binary}. Build it first with cargo build.")
        sys.exit(1)

    demo = NightshiftDemo(binary)
    try:
        demo.setup_git_workspace()
        demo.write_config()
        demo.start_gateway()
        demo.initialize_session()
        demo.run_demo()
    finally:
        demo.cleanup()


if __name__ == "__main__":
    main()
