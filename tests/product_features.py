#!/usr/bin/env python3
"""Local product integration probes. Independent locked acceptance lives in AGY's lab."""

import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

BIN = Path(os.environ.get("MCP_GATEWAY_BIN", "target/debug/mcp-gateway")).resolve()
TOKEN = "ec" * 32
OTHER_TOKEN = "a7" * 32

STDIO_PEER = """
import json, os, pathlib, socket, sys
for line in sys.stdin:
    req = json.loads(line)
    match req["method"]:
        case "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fixture", "version": "1"}}
        case "notifications/initialized":
            continue
        case "tools/list":
            result = {"tools": [{"name": name, "inputSchema": {"type": "object"}}
                                for name in ("probe", "unapproved")]}
        case "tools/call":
            status = pathlib.Path("/proc/self/status").read_text()
            assert "NoNewPrivs:\\t1" in status
            assert "CapEff:\\t0000000000000000" in status
            assert not any("TOKEN" in key for key in os.environ)
            assert str(os.getpid()) != "1"
            assert not pathlib.Path(req["params"]["arguments"]["protected"]).exists()
            try:
                socket.socket()
                raise RuntimeError("sandbox unexpectedly allows sockets")
            except PermissionError:
                pass
            result = {"content": [{"type": "text", "text": req["params"]["arguments"]["msg"]}]}
    print(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}), flush=True)
"""


class ProductFeatures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="veyl-product-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.config = self.base / "clients.json"
        self.audit = self.base / "audit" / "audit.jsonl"
        self.audit.parent.mkdir(mode=0o700)
        self.audit.touch(mode=0o600)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.skills = self.base / "skills"
        self.skills.mkdir(mode=0o700)
        self.doc = {
            "audit_log": str(self.audit),
            "admin_listen": "127.0.0.1:0",
            "skills_dir": str(self.skills),
            "clients": [
                {
                    "id": fallback, "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                    "root": str(self.workspace), "expires_at_unix_seconds": int(time.time()) + 180,
                    "tools": ["read_file", "skills_list", "skills_read", "mcp_servers_list", "mcp_servers_call"],
                    "allowed_servers": [],
                }
                for fallback, token in [("primary", TOKEN), ("secondary", OTHER_TOKEN)]
            ],
        }
        self.write_config()

    def write_config(self):
        self.config.write_text(json.dumps(self.doc))
        self.config.chmod(0o600)

    def cli(self, *args):
        return subprocess.check_output([BIN, *args, "--config", self.config], text=True, timeout=5)

    def start(self):
        env = dict(os.environ, HOME=str(self.base), VEYL_TEST_TOKEN_CANARY="SYNTHETIC_NO_LEAK")
        log = (self.base / "gateway.log").open("wb")
        self.addCleanup(log.close)
        process = subprocess.Popen([BIN, "http", "--listen", "127.0.0.1:0", "--config", self.config],
                                   env=env, stderr=log, stdout=subprocess.DEVNULL)
        self.addCleanup(self.stop, process)
        for _ in range(200):
            trace = (self.base / "gateway.log").read_text()
            admin = re.search(r"ADMIN_HTTP_LISTEN=127\.0\.0\.1:(\d+)", trace)
            mcp = re.search(r"MCP_HTTP_LISTEN=127\.0\.0\.1:(\d+)", trace)
            if admin and mcp:
                self.admin, self.mcp = int(admin[1]), int(mcp[1])
                return
            if process.poll() is not None:
                break
            time.sleep(.015)
        self.fail(f"Gateway did not start: {trace}")

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def request(self, port, method, path, body=None, **headers):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
        try:
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, path, None if body is None else json.dumps(body), headers)
            response = connection.getresponse()
            data = response.read()
            return response.status, response.headers, data
        finally:
            connection.close()

    def rpc(self, method, key, token=TOKEN, params=None):
        headers = {"Authorization": "Bearer " + token}
        if key is not None:
            headers["Mcp-Session-Id"] = key
        request = {"jsonrpc": "2.0", "method": method}
        if not method.startswith("notifications/"):
            request["id"] = 1
        if params is not None:
            request["params"] = params
        code, headers, body = self.request(self.mcp, "POST", "/mcp", request, **headers)
        self.assertIn(code, (200, 202), body)
        return headers, json.loads(body) if body else None

    def connect(self, token=TOKEN):
        headers, _ = self.rpc("initialize", None, token, {"protocolVersion": "2025-11-25",
            "capabilities": {}, "clientInfo": {"name": "product-fixture", "version": "1"}})
        session = headers["Mcp-Session-Id"]
        self.rpc("notifications/initialized", session, token)
        return session

    def call(self, name, args, session, token=TOKEN):
        return self.rpc("tools/call", session, token, {"name": name, "arguments": args})[1]["result"]

    def pair(self):
        output = self.cli("dashboard", "pair").strip()
        token = output.removeprefix("PAIRING_TOKEN=")
        baseline = self.request(self.mcp, "GET", "/dashboard")[0]
        self.assertEqual(baseline, 404)
        origin = f"http://127.0.0.1:{self.admin}"
        status, headers, data = self.request(self.admin, "POST", "/api/dashboard/pair",
                                              {"pairing_token": token}, Origin=origin)
        self.assertEqual(status, 200, data)
        for attribute in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/dashboard"):
            self.assertIn(attribute, headers["Set-Cookie"])
        self.assertEqual(self.request(self.admin, "POST", "/api/dashboard/pair",
                                      {"pairing_token": token}, Origin=origin)[0], 401)
        return {"Cookie": headers["Set-Cookie"].split(";")[0], "Origin": origin,
                "X-CSRF-Token": json.loads(data)["csrf"]}

    def test_local_trace_session_isolation_and_command_response(self):
        self.doc["clients"][0]["tools"].append("system_info")
        self.write_config()
        self.start()
        headers = self.pair()
        other = self.pair()
        path = "/api/dashboard/trace"
        self.assertEqual(self.request(self.admin,"GET",path)[0],401)
        self.assertEqual(self.request(self.admin,"GET",path,Cookie=headers["Cookie"])[0],403)
        self.assertEqual(self.request(self.admin,"POST",path,{"enabled":True,"confirm":False},**headers)[0],403)
        self.assertEqual(self.request(self.admin,"POST",path,{"enabled":True,"confirm":True},**headers)[0],200)
        self.assertEqual(self.request(self.admin,"POST",path,{"enabled":True,"confirm":True},**other)[0],409)
        session = self.connect()
        result = self.call("system_info",{},session)
        self.assertFalse(result["isError"],result)
        status,_,body = self.request(self.admin,"GET",path,**headers)
        self.assertEqual(status,200)
        events=json.loads(body)["events"]
        self.assertEqual(len(events),1)
        self.assertEqual(events[0]["client"],"primary")
        self.assertEqual(events[0]["tool"],"system_info")
        self.assertEqual(events[0]["arguments"],{})
        self.assertEqual(events[0]["response"],result)
        self.assertEqual(json.loads(self.request(self.admin,"GET",path,**other)[2])["events"],[])
        self.assertEqual(self.request(self.admin,"GET","/dashboard/icon.svg")[0],200)
        self.assertEqual(self.request(self.mcp,"GET","/dashboard/icon.svg")[0],404)
        self.assertEqual(self.request(self.admin,"POST",path,{"enabled":False,"confirm":True},**headers)[0],200)
        self.assertEqual(json.loads(self.request(self.admin,"GET",path,**headers)[2])["events"],[])

    def test_admin_skills_import_grant_and_revoke(self):
        self.start()
        session = self.connect()
        headers = self.pair()
        package = self.base / "example-skill"
        package.mkdir(mode=0o700)
        doc = "---\nname: example-skill\ndescription: Fixture instructions\n---\nRead-only instructions.\n"
        (package / "SKILL.md").write_text(doc)
        (package / "run.sh").write_text("exit 99")
        payload = {"action": "import", "source": str(package), "confirm": True}
        wrong = dict(headers, **{"X-CSRF-Token": "wrong"})
        self.assertEqual(self.request(self.admin, "POST", "/api/dashboard/skills", payload, **wrong)[0], 403)
        no_confirmation = dict(payload, confirm=False)
        self.assertEqual(self.request(self.admin, "POST", "/api/dashboard/skills", no_confirmation, **headers)[0], 403)
        status, _, body = self.request(self.admin, "POST", "/api/dashboard/skills", payload, **headers)
        self.assertEqual(status, 200, body)
        self.assertEqual(list((self.skills / "example-skill").iterdir()), [self.skills / "example-skill" / "SKILL.md"])
        corrupt = self.skills / "corrupt"
        corrupt.mkdir()
        (corrupt / "SKILL.md").symlink_to(package / "SKILL.md")
        catalog = json.loads(self.cli("skills", "list"))["skills"]
        self.assertEqual([row["name"] for row in catalog if row["validation_error"]], ["corrupt"])
        self.assertTrue(self.call("skills_read", {"name": "example-skill"}, session)["isError"])
        self.cli("skills", "grant", "primary", "example-skill")
        self.assertEqual(self.call("skills_read", {"name": "example-skill"}, session)["content"][0]["text"], doc)
        revoke = {"action": "revoke", "client": "primary", "name": "example-skill", "confirm": True}
        self.assertEqual(self.request(self.admin, "POST", "/api/dashboard/skills", revoke, **headers)[0], 200)
        self.assertTrue(self.call("skills_read", {"name": "example-skill"}, session)["isError"])

    def test_admin_reads_and_cancels_real_job(self):
        state = self.base / "jobs"
        state.mkdir(mode=0o700)
        self.doc["job_state_dir"] = str(state)
        self.doc["policy_version"] = 2
        self.doc["job_profiles"] = {"sleep": {
            "executable": "/usr/bin/sleep", "args": ["10"],
            "timeout_seconds": 12, "max_output_bytes": 4096,
        }}
        self.doc["clients"][0]["tools"].append("job_start")
        self.write_config()
        self.start()
        session = self.connect()
        headers = self.pair()
        result = self.call("job_start", {"profile": "sleep"}, session)
        self.assertFalse(result.get("isError", False), result)
        job = json.loads(result["content"][0]["text"])["job_id"]
        status, _, body = self.request(self.admin, "GET", "/api/dashboard/jobs?client=primary", **headers)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["jobs"][0]["job_id"], job)
        path = f"/api/dashboard/jobs/{job}/logs"
        self.assertEqual(self.request(self.admin, "GET", path + "?client=secondary", **headers)[0], 404)
        status, _, body = self.request(self.admin, "GET", path + "?client=primary", **headers)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["job_id"], job)
        request = {"client": "primary", "job_id": job, "confirm": True}
        status, _, body = self.request(self.admin, "POST", "/api/dashboard/jobs/cancel", request, **headers)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["state"], "canceled")

    def test_upstream_sandbox_and_per_tool_grants(self):
        probe = self.base / "probe.py"
        probe.write_text(STDIO_PEER)
        self.start()
        headers = self.pair()
        add = {"action": "add-stdio", "id": "local", "command": "/usr/bin/python3",
               "arguments": [str(probe)], "confirm": True}
        status, _, body = self.request(self.admin, "POST", "/api/dashboard/servers", add, **headers)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(self.cli("mcp-servers", "probe", "local"))["health"], "ready")
        self.cli("mcp-servers", "grant", "primary", "local", "probe")
        first, second = self.connect(), self.connect(OTHER_TOKEN)
        args = {"protected": str(self.config), "msg": "FIRED"}
        self.assertEqual(self.call("local__probe", args, first)["content"][0]["text"], "FIRED")
        for name, session, token in [
            ("local__unapproved", first, TOKEN),
            ("local__probe", second, OTHER_TOKEN),
            ("probe", first, TOKEN),
        ]:
            self.assertTrue(self.call(name, args, session, token)["isError"])
        self.cli("mcp-servers", "revoke", "primary", "local", "probe")
        self.assertTrue(self.call("local__probe", args, first)["isError"])
        self.assertIn("local__probe", self.audit.read_text())
        self.assertNotIn("FIRED", self.audit.read_text())

    def test_upstream_timeout_reaps_descendants(self):
        probe = self.base / "waiting.py"
        source = STDIO_PEER.replace(
            '            status = pathlib.Path("/proc/self/status").read_text()',
            '            os.fork()\n            while True:\n                __import__("signal").pause()',
        )
        probe.write_text(source)
        marker = "veyl_upstream_probe_" + secrets.token_hex(16)
        self.cli("mcp-servers", "add-stdio", "waiting", "/usr/bin/python3", probe, marker)
        self.cli("mcp-servers", "grant", "primary", "waiting", "probe")
        self.start()
        session = self.connect()
        result = []
        caller = threading.Thread(target=lambda: result.append(self.call("waiting__probe", {}, session)))
        caller.start()

        def matching():
            processes = []
            for entry in Path("/proc").iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    cmd = (entry / "cmdline").read_bytes().split(b"\0")
                except (ProcessLookupError, FileNotFoundError, PermissionError):
                    continue
                if b"/upstream/server.py" in cmd and marker.encode() in cmd and b"--" not in cmd:
                    processes.append(entry.name)
            return processes

        child_observed = False
        try:
            deadline = time.monotonic() + 1.2
            while time.monotonic() < deadline:
                if len(matching()) > 1:
                    child_observed = True
                    break
                time.sleep(.015)
        finally:
            caller.join(timeout=5)
        self.assertTrue(child_observed, "provider did not fork the disposable descendant")
        self.assertFalse(caller.is_alive())
        self.assertTrue(result[0]["isError"], result)
        self.assertIn("timed out", result[0]["content"][0]["text"])
        deadline = time.monotonic() + .8
        while matching() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertEqual(matching(), [], "sandbox descendants survived the upstream timeout")

    def test_https_upstream_private_ca_bearer_and_sse(self):
        ca, leaf, key, csr = (self.base / name for name in ("ca.pem", "leaf.pem", "leaf.key", "leaf.csr"))
        extensions = self.base / "extensions"
        extensions.write_text("subjectAltName=DNS:veyl.fixture\nextendedKeyUsage=serverAuth\n")
        def openssl(*args):
            subprocess.run(["openssl", *args], check=True, timeout=6, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, cwd=self.base)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Veyl Fixture CA",
                "-keyout", "ca.key", "-out", ca)
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=veyl.fixture",
                "-keyout", key, "-out", csr)
        openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", "ca.key", "-CAcreateserial",
                "-days", "1", "-extfile", extensions, "-out", leaf)
        seen = []
        credential = "UPSTREAM_ONLY_BEARER_TEST_FIXTURE"

        class Peer(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, body=b"", content_type=None, session=None):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                if content_type:
                    self.send_header("Content-Type", content_type)
                if session:
                    self.send_header("Mcp-Session-Id", session)
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                if self.headers.get("Authorization") != f"Bearer {credential}" or self.path != "/mcp":
                    self.reply(401)
                    return
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                method = request["method"]
                if method != "initialize" and self.headers.get("Mcp-Session-Id") != "fixture-session":
                    self.reply(400)
                    return
                seen.append(method)
                if method == "notifications/initialized":
                    self.reply(202)
                    return
                value = {
                    "initialize": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                                   "serverInfo": {"name": "HTTPS fixture", "version": "1"}},
                    "tools/list": {"tools": [{"name": "hello", "inputSchema": {"type": "object"}}]},
                    "tools/call": {"content": [{"type": "text", "text": "verified HTTPS forwarding"}]},
                }[method]
                result = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": value}).encode()
                if method == "tools/call":
                    self.reply(200, b"id: 1\r\ndata:\r\n\r\nid: 2\r\ndata: " + result + b"\r\n\r\n", "text/event-stream")
                else:
                    self.reply(200, result, "application/json", "fixture-session")
            def do_DELETE(self):
                seen.append("delete")
                self.reply(204)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        for suffix, text in [("token", credential), ("ca.pem", ca.read_text())]:
            file = self.base / f".mcp-upstream-tls.{suffix}"
            file.write_text(text)
            file.chmod(0o600)
        self.doc["mcp_servers"] = {"tls": {"transport": "http", "url": f"https://veyl.fixture:{server.server_port}/mcp",
            "connect_ip": "127.0.0.1", "private_ca": True, "use_token": True}}
        self.write_config()
        self.cli("mcp-servers", "grant", "primary", "tls", "hello")
        self.start()
        session = self.connect()
        result = self.call("tls__hello", {}, session)
        self.assertEqual(result["content"][0]["text"], "verified HTTPS forwarding", seen)
        self.assertEqual(seen, ["initialize", "notifications/initialized", "tools/list", "tools/call", "delete"])
        self.assertNotIn(credential, self.audit.read_text())
        self.assertNotIn(credential, self.cli("dashboard", "servers"))
        self.assertTrue(self.call("tls__hello", {}, self.connect(OTHER_TOKEN), OTHER_TOKEN)["isError"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
