#!/usr/bin/env python3
"""Local regression probe for supervised FULL using only synthetic state."""

import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import threading
import time

token = "a" * 64
binary = Path(sys.argv[1]).resolve()
mode = sys.argv[2] if len(sys.argv) > 2 else "full"
assert mode in ("full", "standard", "legacy")
benchmark = "--benchmark" in sys.argv
reference = "--reference" in sys.argv
assert not reference or mode != "full"


class Peer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass

with tempfile.TemporaryDirectory(prefix="mcp-gate3-full-") as tmp:
    root = Path(tmp)
    for child in ("home", "workspace", "audit"):
        (root / child).mkdir(mode=0o700)
    peer = None
    profiles = {"id": {"executable": "/usr/bin/id", "args": ["-u"], "timeout_seconds": 4}}
    if mode != "full":
        peer = HTTPServer(("127.0.0.1", 0), Peer)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        (root / "workspace" / "network.py").write_text(
            "import socket, sys\n"
            "try:\n"
            f"    with socket.create_connection(('127.0.0.1', {peer.server_port}), 0.5) as s:\n"
            "        s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\n"
            "        assert b'200' in s.recv(128)\n"
            "except OSError:\n"
            "    sys.exit(42)\n"
        )
        profiles["network"] = {"executable": "/usr/bin/python3", "args": ["network.py"], "timeout_seconds": 4}
    config = root / "clients.json"
    config.write_text(json.dumps({
        "policy_version": 1,
        "audit_log": str(root / "audit" / "ledger"),
        "job_state_dir": str(root / "jobs"),
        "job_profiles": profiles,
        "clients": [{
            "id": "fixture", "root": str(root / "workspace"),
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "expires_at_unix_seconds": 4294967295, "tools": ["run_command", "job_start", "job_status"],
        }],
    }))
    config.chmod(0o600)
    child_env = {**os.environ, "HOME": str(root / "home")}
    child_env.pop("XDG_RUNTIME_DIR", None)
    def cli(*args):
        return subprocess.run([binary, "yolo", *args, "--client", "fixture", "--config", config],
                              env=child_env, capture_output=True, timeout=5)

    if mode == "full":
        cli("set", "--mode", "full", "--confirm-full").check_returncode()
    elif mode == "legacy":
        cli("enable").check_returncode()
        if not reference:
            assert b"effective_policy=legacy_scoped_yolo" in cli("status").stdout
        before = config.read_bytes()
        assert cli("set", "--mode", "yolo").returncode != 0
        assert config.read_bytes() == before
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
        if benchmark:
            def usage():
                stat = Path(f"/proc/{server.pid}/stat").read_text().rsplit(")", 1)[1].split()
                rss_line = next(line for line in Path(f"/proc/{server.pid}/status").read_text().splitlines()
                                if line.startswith("VmRSS:"))
                return int(stat[11]) + int(stat[12]), int(rss_line.split()[1])
            ticks, rss = usage()
            time.sleep(5)
            print(f"{mode} idle {rss} KiB RSS, {usage()[0] - ticks} CPU ticks / 5 s")
            samples = []
            for _ in range(5):
                began = time.monotonic_ns()
                _, admitted = rpc("tools/call", {"name": "job_start", "arguments": {"profile": "id"}})
                assert not admitted["result"]["isError"], admitted
                samples.append((time.monotonic_ns() - began) / 1e6)
            print(f"{mode} idle-fixture median job admission {sorted(samples)[2]:.3f} ms")
            time.sleep(0.6)
        profile = "id" if mode == "full" else "network"
        _, response = rpc("tools/call", {"name": "run_command", "arguments": {"profile": profile}})
        assert not response["result"]["isError"], response
        status = json.loads(response["result"]["content"][0]["text"])
        assert status["exit_code"] == (0 if mode == "full" else 42), status
        receipt = root / "jobs" / status["job_id"] / "receipt.json"
        stored = json.loads(receipt.read_text())
        if mode == "full":
            assert stored["full"] and not stored.get("isolated"), stored
            uid = (receipt.parent / "stdout.log").read_text().strip()
            assert uid == str(os.getuid()) and uid != "0", uid
            audit = [json.loads(line) for line in (root / "audit" / "ledger").read_text().splitlines()]
            assert {"intent", "success"} <= {
                event["phase"] for event in audit
                if event.get("job_id") == status["job_id"] and event.get("effective_mode") == "full"
            }
            print(f"FULL supervised id run exited 0 as uid {uid}, receipt isolated=false")
        else:
            assert stored["isolated"] and not stored.get("full"), stored
            assert bool(stored.get("yolo")) == (mode == "legacy"), stored
            print(f"{mode} authenticated job denied controlled TCP loopback, receipt isolated=true")
    finally:
        stop = time.monotonic_ns()
        server.terminate()
        server.communicate(timeout=5)
        shutdown_ms = (time.monotonic_ns() - stop) / 1e6
        if peer is not None:
            peer.shutdown()
            peer.server_close()
    assert server.returncode == (-15 if reference else 0), server.returncode
    print(f"Loopback startup {startup:.3f} ms, SIGTERM shutdown {shutdown_ms:.3f} ms")
