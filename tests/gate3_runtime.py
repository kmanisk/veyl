#!/usr/bin/env python3
"""Local regression probe for supervised FULL using only synthetic state."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

token = "a" * 64
binary = Path(sys.argv[1]).resolve()

with tempfile.TemporaryDirectory(prefix="mcp-gate3-full-") as tmp:
    root = Path(tmp)
    for child in ("home", "workspace", "audit"):
        (root / child).mkdir(mode=0o700)
    config = root / "clients.json"
    config.write_text(json.dumps({
        "policy_version": 1,
        "audit_log": str(root / "audit" / "ledger"),
        "job_state_dir": str(root / "jobs"),
        "job_profiles": {"id": {
            "executable": "/usr/bin/id", "args": ["-u"], "timeout_seconds": 4,
        }},
        "clients": [{
            "id": "fixture", "root": str(root / "workspace"),
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "expires_at_unix_seconds": 4294967295, "tools": ["run_command"],
        }],
    }))
    config.chmod(0o600)
    child_env = {**os.environ, "HOME": str(root / "home")}
    child_env.pop("XDG_RUNTIME_DIR", None)
    subprocess.run([binary, "yolo", "set", "--mode", "full", "--confirm-full",
                    "--client", "fixture", "--config", config],
                   env=child_env, capture_output=True, check=True, timeout=5)
    start = time.monotonic_ns()
    server = subprocess.Popen([binary, "http", "--listen", "127.0.0.1:0",
                               "--config", config], env=child_env, stderr=subprocess.PIPE)
    try:
        assert select.select([server.stderr], [], [], 5)[0], "listener unavailable"
        line = server.stderr.readline().decode().strip()
        port = int(line.removeprefix("MCP_HTTP_LISTEN=127.0.0.1:"))
        startup = (time.monotonic_ns() - start) / 1e6
        session = None

        def rpc(method, params=None, notify=False):
            packet = {"method": method, "jsonrpc": "2.0"}
            if params is not None:
                packet["params"] = params
            if not notify:
                packet["id"] = 1
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            if session:
                headers["Mcp-Session-Id"] = session
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request("POST", "/mcp", json.dumps(packet), headers)
                res = conn.getresponse()
                body = res.read()
                assert res.status in (200, 202), res.status
                return res.getheader("Mcp-Session-Id"), json.loads(body) if body else {}
            finally:
                conn.close()

        session, _ = rpc("initialize", {"protocolVersion": "2025-11-25",
                         "capabilities": {}, "clientInfo": {"name": "local", "version": "1"}})
        rpc("notifications/initialized", notify=True)
        _, denied = rpc("tools/call", {"name": "yolo_set", "arguments": {"mode": "full"}})
        assert "error" in denied or denied.get("result", {}).get("isError")
        _, response = rpc("tools/call", {"name": "run_command", "arguments": {"profile": "id"}})
        assert not response["result"]["isError"], response
        status = json.loads(response["result"]["content"][0]["text"])
        assert status["exit_code"] == 0, status
        receipt = next((root / "jobs").glob("*/receipt.json"))
        stored = json.loads(receipt.read_text())
        assert stored["full"] and not stored.get("isolated"), stored
        uid = (receipt.parent / "stdout.log").read_text().strip()
        assert uid == str(os.getuid()) and uid != "0", uid
        audit = [json.loads(line) for line in (root / "audit" / "ledger").read_text().splitlines()]
        assert {"intent", "success"} <= {
            event["phase"] for event in audit
            if event.get("job_id") == status["job_id"] and event["effective_mode"] == "full"
        }
        print(f"FULL supervised id run exited 0 as uid {uid}, receipt isolated=false")
    finally:
        stop = time.monotonic_ns()
        server.terminate()
        server.communicate(timeout=5)
    assert server.returncode == 0, server.returncode
    print(f"Loopback startup {startup:.3f} ms, SIGTERM shutdown {(time.monotonic_ns() - stop) / 1e6:.3f} ms")
