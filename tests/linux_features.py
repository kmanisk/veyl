#!/usr/bin/env python3
"""Disposable Linux integration probes. This file is not an AGY acceptance oracle."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import ssl
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import secrets
import socket
import socketserver
import subprocess
import struct
import termios
import threading
import time
import unittest

import product_features as product

GATEWAY = product.BIN
MONITOR = Path(os.environ.get("VEYL_MONITOR_BIN", GATEWAY.with_name("veyl-monitor"))).resolve()
TAIL = {"hostname":"node.demo.ts.net", "mcp_https_port":8443,"admin_https_port":9443}
BRIDGE = {
    "TCP":{"443":{"HTTPS":True}},
    "Web":{"node.demo.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}},
    "AllowFunnel":{"node.demo.ts.net:443":True},
}


class LocalAPI(socketserver.UnixStreamServer):
    def __init__(self,path):
        self.configuration = copy.deepcopy(BRIDGE)
        self.serial = 0
        self.posts = 0
        self.race = False
        self.funnel_ports = "443,8443,10000"
        super().__init__(path, TailscalePeer)


class TailscalePeer(BaseHTTPRequestHandler):
    def log_message(self,*_):
        pass

    def reply(self, status, data=None):
        payload = b"" if data is None else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Length",str(len(payload)))
        self.send_header("ETag",f'"fixture-{self.server.serial}"')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.headers["Host"] != "local-tailscaled.sock":
            self.reply(400)
        elif self.path == "/localapi/v0/status?peers=false":
            self.reply(200,{"BackendState":"Running","Self":{"DNSName":TAIL["hostname"]+".",
                        "CapMap":{"funnel":None,"https://tailscale.com/cap/funnel-ports?ports="+self.server.funnel_ports:None}},
                        "CertDomains":[TAIL["hostname"]]})
        elif self.path == "/localapi/v0/serve-config":
            self.reply(200,self.server.configuration)
        else:
            self.reply(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.posts += 1
        if self.server.race:
            self.server.configuration["TCP"]["10000"]={"TCPForward":"127.0.0.1:10100"}
            self.server.race=False
            self.server.serial+=1
        if self.headers.get("If-Match") != f'"fixture-{self.server.serial}"':
            self.reply(412)
            return
        self.server.configuration=body
        self.server.serial+=1
        self.reply(200)


class LinuxFeatures(unittest.TestCase):
    def setUp(self):
        self.f=product.ProductFeatures()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def cli(self,*args, env=None):
        return subprocess.run([GATEWAY,*args,"--config",self.f.config],capture_output=True,text=True,timeout=10,env=env)

    def start(self):
        self.f.start()

    def test_broad_desktop_links_and_state_aliases(self):
        home = self.f.base
        state = home / "private-state"
        state.mkdir(mode=0o700)
        self.f.config = state / "clients.json"
        audit = state / "audit.jsonl"
        audit.touch(mode=0o600)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        desktop = home / ".codex"
        desktop.mkdir()
        secret = desktop / "credential"
        secret.write_text("masked canary")
        (desktop / "internal").symlink_to(secret.name)
        (desktop / "dangling").symlink_to("missing")
        socket_path = desktop / "session.sock"
        desktop_socket = socket.socket(socket.AF_UNIX)
        self.addCleanup(desktop_socket.close)
        desktop_socket.bind(str(socket_path))
        readonly = home / ".local/bin"
        readonly.mkdir(parents=True)
        tool = readonly / "program"
        tool.write_text("read-only canary")
        (readonly / "current").symlink_to(tool.name)
        systemd = home / ".config/systemd"
        systemd.mkdir(parents=True)
        (systemd / "disabled.service").symlink_to("/dev/null")
        outside_alias = home / "desktop-alias"
        outside_alias.symlink_to(secret)
        outside = home / "outside-workspace"
        outside.write_text("outside canary")
        self.f.doc.update(policy_version=2, audit_log=str(audit), job_state_dir=str(jobs))
        self.f.doc["job_profiles"] = {
            "desktop": {"executable": "/usr/bin/python3",
                        "args": ["-c",
                                 "from pathlib import Path; import sys\n"
                                 "assert all(not Path(p).exists() for p in sys.argv[1:5])\n"
                                 "assert Path(sys.argv[5]).read_text() == 'read-only canary'\n"
                                 "try: Path(sys.argv[5]).write_text('unexpected write')\n"
                                 "except OSError: pass\n"
                                 "else: raise AssertionError('read-only mount writable')\n"
                                 "print('desktop-probe-ok')",
                                 str(self.f.config), str(secret), str(outside_alias),
                                 str(socket_path), str(readonly / "current")],
                        "timeout_seconds": 6, "max_output_bytes": 4096},
        }
        self.f.doc["clients"][0]["tools"].extend(["write_file", "job_start", "job_logs", "job_status"])
        self.f.write_config()
        env = dict(os.environ, HOME=str(home))
        # Executables and symlinks still invalidate the dedicated state tree.
        invalid = state / "helper"
        invalid.write_text("synthetic")
        invalid.chmod(0o700)
        check = ("state", "check", "--state-root", state)
        self.assertNotEqual(self.cli(*check, env=env).returncode, 0)
        invalid.unlink()
        invalid.symlink_to(outside)
        self.assertNotEqual(self.cli(*check, env=env).returncode, 0)
        invalid.unlink()
        self.assertEqual(self.cli(*check, env=env).returncode, 0)
        enable = self.cli("yolo", "set", "--client", "primary", "--mode", "yolo", env=env)
        self.assertEqual(enable.returncode, 0, enable.stderr)
        self.start()
        session = self.f.connect()
        self.assertFalse(self.f.call("read_file", {"path": str(outside)}, session).get("isError"))
        for target in (self.f.config, secret, outside_alias):
            self.assertTrue(self.f.call("read_file", {"path": str(target)}, session).get("isError"))
        self.assertTrue(self.f.call("write_file", {
            "path": str(readonly / "current"), "content": "unexpected",
        }, session).get("isError"))
        started = self.f.call("job_start", {"profile": "desktop"}, session)
        self.assertFalse(started.get("isError"), started)
        job = json.loads(started["content"][0]["text"])["job_id"]
        deadline = time.monotonic() + 8
        while True:
            receipt = self.f.call("job_status", {"job_id": job}, session)
            self.assertFalse(receipt.get("isError"), receipt)
            result = json.loads(receipt["content"][0]["text"])
            if result["state"] not in ("queued", "running", "starting"):
                break
            self.assertLess(time.monotonic(), deadline, result)
            time.sleep(.05)
        self.assertEqual(result["exit_code"], 0, result)
        logs = self.f.call("job_logs", {"job_id": job}, session)
        self.assertIn("desktop-probe-ok", json.dumps(logs))
        hardlink = home / "hardlink-alias"
        os.link(secret, hardlink)
        self.assertTrue(self.f.call("read_file", {"path": str(hardlink)}, session).get("isError"))
        self.assertTrue(self.f.call("job_start", {"profile": "desktop"}, session).get("isError"))

    @contextmanager
    def tail_peer(self):
        path=self.f.base/"tailscaled.sock"
        with LocalAPI(str(path)) as peer:
            thread=threading.Thread(target=peer.serve_forever,daemon=True)
            thread.start()
            try:
                yield path,peer
            finally:
                peer.shutdown()
                thread.join()

    def test_conditional_tailscale_apply_remove_and_collision(self):
        self.f.doc["tailscale_serve"]=TAIL
        self.f.doc["admin_listen"]="127.0.0.1:7332"
        self.f.write_config()
        with self.tail_peer() as (socket,peer):
            self.assertNotEqual(self.cli("serve","apply","--socket",socket).returncode,0)
            self.assertEqual(peer.posts,0)
            plan=self.cli("serve","plan","--live","--socket",socket)
            self.assertEqual(plan.returncode,0,plan.stderr)
            self.assertEqual(json.loads(plan.stdout)["mcp"],"https://node.demo.ts.net:8443/mcp")
            self.assertEqual(peer.posts,0)
            self.assertFalse((self.f.base/".clients.json.policy-lock").exists())
            peer.race=True
            result=self.cli("serve","apply","--confirm","--socket",socket)
            self.assertNotEqual(result.returncode,0)
            self.assertIn("concurrently",result.stderr)
            self.assertEqual(peer.configuration["Web"],BRIDGE["Web"])
            self.assertIn("10000",peer.configuration["TCP"])
            owned=self.cli("serve","apply","--confirm","--socket",socket)
            self.assertEqual(owned.returncode,0,owned.stderr)
            self.assertEqual(peer.posts,2)
            self.assertEqual(peer.configuration["AllowFunnel"],BRIDGE["AllowFunnel"])
            self.assertEqual(peer.configuration["Web"]["node.demo.ts.net:443"],BRIDGE["Web"]["node.demo.ts.net:443"])
            self.assertEqual(peer.configuration["Web"]["node.demo.ts.net:9443"]["Handlers"]["/"]["Proxy"],"http://127.0.0.1:7332")
            self.assertEqual(self.cli("serve","apply","--confirm","--socket",socket).returncode,0)
            self.assertEqual(peer.posts,2)
            inspected=self.cli("serve","inspect","--socket",socket)
            self.assertEqual(inspected.returncode,0,inspected.stderr)
            self.assertEqual(json.loads(inspected.stdout)["owned_before"],[True,True])
            removed=self.cli("serve","rollback","--confirm","--socket",socket)
            self.assertEqual(removed.returncode,0,removed.stderr)
            self.assertEqual(peer.posts,3)
            self.assertEqual(peer.configuration["Web"],BRIDGE["Web"])
            peer.configuration["TCP"]["8443"]={"HTTPS":True}
            self.assertNotEqual(self.cli("serve","apply","--confirm","--socket",socket).returncode,0)
            self.assertEqual(peer.posts,3)

    def prepare_public_client(self, *, allow_secret_path=True, shared=False):
        state = self.f.base / "private-state"
        state.mkdir(mode=0o700)
        self.f.config = state / "clients.json"
        self.f.audit = state / "audit.jsonl"
        self.f.audit.touch(mode=0o600)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        token = secrets.token_hex(32)
        self.f.doc.update(policy_version=2, audit_log=str(self.f.audit), job_state_dir=str(jobs))
        self.f.doc["job_profiles"] = {"probe": {
            "executable": "/usr/bin/true", "args": [], "timeout_seconds": 3, "max_output_bytes": 1024,
        }}
        self.f.doc["tailscale_serve"] = {**TAIL, "funnel": {
            "client": "primary",
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "allow_secret_path": allow_secret_path,
        }}
        if shared:
            self.f.doc["tailscale_serve"]["shared_funnel"] = True
        self.f.write_config()
        env = dict(os.environ, HOME=str(self.f.base))
        enable = self.cli("yolo", "set", "--client", "primary", "--mode", "yolo", env=env)
        self.assertEqual(enable.returncode, 0, enable.stderr)
        self.f.doc = json.loads(self.f.config.read_text())
        return token, env

    def test_funnel_authentication_boundary_rotation_and_budget(self):
        token, _ = self.prepare_public_client()
        marker = {"Tailscale-Funnel-Request": "?1"}
        authority = f"{TAIL['hostname']}:{TAIL['mcp_https_port']}"
        public = {**marker, "Host": authority, "Origin": "https://" + authority}
        self.start()
        outside = self.f.base / "public-canary"
        outside.write_text("funnel-broad-yolo-canary")
        params = {"protocolVersion": "2025-11-25", "capabilities": {},
                  "clientInfo": {"name": "funnel-fixture", "version": "1"}}
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}

        def post(path, payload=init, **headers):
            return self.f.request(self.f.mcp, "POST", path, payload, **headers)

        path = "/mcp/" + token
        self.assertEqual(post("/mcp", **public)[0], 404)
        self.assertEqual(post("/mcp", **public, Authorization="Bearer " + product.TOKEN)[0], 404)
        self.assertEqual(post("/mcp", **public, **{"Tailscale-User-Login": "fixture"})[0], 404)
        self.assertEqual(post(path, Host=authority)[0], 404)
        self.assertEqual(post(path, **marker)[0], 403)
        self.assertEqual(post(path + "?extra=1", **public)[0], 403)
        self.assertEqual(post(path, **public, Authorization="Bearer " + token)[0], 404)
        self.assertEqual(post("/dashboard/api/status", **public)[0], 404)
        dashboard_host = f"{TAIL['hostname']}:{TAIL['admin_https_port']}"
        self.assertEqual(self.f.request(self.f.admin, "GET", "/dashboard", Host=dashboard_host,
                                        **marker)[0], 400)
        self.assertEqual(post("/mcp", **public, Authorization="Bearer " + token)[0], 200)
        code, headers, _ = post(path, **public)
        self.assertEqual(code, 200)
        session = headers["Mcp-Session-Id"]
        session_headers = {**public, "Mcp-Session-Id": session}
        notify = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.assertEqual(post(path, notify, **session_headers)[0], 202)
        call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": str(outside)}}}
        status, _, result = post(path, call, **session_headers)
        self.assertEqual(status, 200)
        self.assertIn(b"funnel-broad-yolo-canary", result)
        self.assertEqual(post("/mcp", call, **{"Mcp-Session-Id": session,
                                              "Authorization": "Bearer " + product.TOKEN})[0], 403)
        replacement = secrets.token_hex(32)
        self.f.doc["tailscale_serve"]["funnel"]["token_sha256"] = hashlib.sha256(replacement.encode()).hexdigest()
        candidate = self.f.config.with_suffix(".new")
        candidate.touch(mode=0o600)
        candidate.write_text(json.dumps(self.f.doc))
        candidate.replace(self.f.config)
        self.assertEqual(post(path, call, **session_headers)[0], 404)
        self.assertEqual(post("/mcp/" + replacement, call, **session_headers)[0], 200)
        self.assertEqual(self.cli("yolo", "disable", "--client", "primary").returncode, 0)
        self.assertEqual(post("/mcp/" + replacement, call, **session_headers)[0], 404)
        limited = False
        for _ in range(61):
            if post("/mcp", **public)[0] == 429:
                limited = True
                break
        self.assertTrue(limited)
        self.assertEqual(post("/mcp", Authorization="Bearer " + product.TOKEN)[0], 200)
        logs = (self.f.base / "gateway.log").read_text() + self.f.audit.read_text()
        self.assertIn("funnel_admission", logs)
        self.assertNotIn(token, logs)
        self.assertNotIn(replacement, logs)

    def test_funnel_route_ownership_and_selective_rollback(self):
        _, env = self.prepare_public_client(allow_secret_path=False)
        self.f.doc["admin_listen"] = "127.0.0.1:7332"
        self.f.write_config()
        with self.tail_peer() as (socket, peer):
            def command(action, *args):
                return self.cli("serve", action, "--socket", socket, *args, env=env)

            self.assertNotEqual(command("funnel-apply", "--confirm").returncode, 0)
            result = command("apply", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            paired = copy.deepcopy(peer.configuration)
            self.assertEqual(paired["AllowFunnel"], BRIDGE["AllowFunnel"])
            self.assertNotEqual(command("funnel-apply").returncode, 0)
            result = command("funnel-plan")
            self.assertEqual(result.returncode, 0, result.stderr)
            peer.funnel_ports = "443,10000"
            self.assertNotEqual(command("funnel-apply", "--confirm").returncode, 0)
            peer.funnel_ports = "443,8443,10000"
            public_key = f"{TAIL['hostname']}:{TAIL['mcp_https_port']}"
            private_key = f"{TAIL['hostname']}:{TAIL['admin_https_port']}"
            peer.configuration["AllowFunnel"][private_key] = True
            self.assertNotEqual(command("funnel-apply", "--confirm").returncode, 0)
            peer.configuration["AllowFunnel"].pop(private_key)
            result = command("funnel-apply", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(peer.configuration["AllowFunnel"], {**BRIDGE["AllowFunnel"], public_key: True})
            self.assertEqual(peer.configuration["Web"], paired["Web"])
            result = command("inspect")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)["private"])
            result = command("funnel-rollback", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(peer.configuration, paired)

    def test_funnel_cors_preflight_and_authenticated_session(self):
        token, _ = self.prepare_public_client()
        self.start()
        authority = f"{TAIL['hostname']}:{TAIL['mcp_https_port']}"
        public = {"Host": authority, "Tailscale-Funnel-Request": "?1"}
        origin = "https://chatgpt.com"
        browser = {**public, "Origin": origin}
        headers = {"Access-Control-Request-Method": "POST",
                   "Access-Control-Request-Headers": "authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version"}
        path = "/mcp/" + token
        audit_before = self.f.audit.read_bytes()
        for source in (origin, "https://chat.openai.com"):
            for route in ("/mcp", path, "/mcp/" + secrets.token_hex(32)):
                status, response, body = self.f.request(
                    self.f.mcp, "OPTIONS", route, **public, Origin=source, **headers)
                self.assertEqual((status, body), (204, b""))
                self.assertEqual(response["Access-Control-Allow-Origin"], source)
                self.assertEqual(response["Access-Control-Allow-Methods"], "POST")
                vary = ",".join(response.get_all("Vary")).lower()
                self.assertIn("origin", vary)
                self.assertIn("access-control-request-headers", vary)
                self.assertIsNone(response["Access-Control-Allow-Credentials"])
                self.assertIsNone(response["Mcp-Session-Id"])
        self.assertEqual(self.f.audit.read_bytes(), audit_before)
        for field, value in [("Access-Control-Request-Method", "DELETE"),
                             ("Access-Control-Request-Headers", "X-Unapproved"),
                             ("Access-Control-Request-Headers", "accept," * 40 + "accept")]:
            status, response, _ = self.f.request(
                self.f.mcp, "OPTIONS", path, **browser, **{**headers, field: value})
            self.assertEqual(status, 403)
            self.assertIsNone(response["Access-Control-Allow-Methods"])
        self.assertEqual(self.f.request(self.f.mcp, "OPTIONS", path, {"unexpected": True},
                                        **browser, **headers)[0], 403)
        self.assertEqual(self.f.request(self.f.mcp, "OPTIONS", "/mcp/malformed",
                                        **browser, **headers)[0], 404)

        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "cors-fixture", "version": "1"},
        }}
        for rejected in ["https://chatgpt.com.evil.invalid", "http://chatgpt.com",
                         "https://chatgpt.com/", "null"]:
            status, response, _ = self.f.request(self.f.mcp, "POST", path, init,
                                                 **public, Origin=rejected)
            self.assertEqual(status, 403)
            self.assertIsNone(response["Access-Control-Allow-Origin"])
        connection = http.client.HTTPConnection("127.0.0.1", self.f.mcp, timeout=5)
        self.addCleanup(connection.close)
        connection.putrequest("OPTIONS", "/mcp", skip_host=True)
        for name, value in {**browser, **headers}.items():
            connection.putheader(name, value)
        connection.putheader("Origin", "https://chat.openai.com")
        connection.endheaders()
        duplicate = connection.getresponse()
        self.assertEqual(duplicate.status, 403)
        self.assertIsNone(duplicate.getheader("Access-Control-Allow-Origin"))
        duplicate.read()
        self.assertEqual(self.f.request(self.f.mcp, "OPTIONS", "/mcp",
                                        Host=authority, Origin=origin, **headers)[0], 403)
        admin_host = f"{TAIL['hostname']}:{TAIL['admin_https_port']}"
        _, admin, _ = self.f.request(self.f.admin, "OPTIONS", "/dashboard",
                                     **{**browser, "Host": admin_host}, **headers)
        self.assertIsNone(admin["Access-Control-Allow-Origin"])
        for bad, extra in [("/mcp", {"Authorization": "Bearer " + product.TOKEN}),
                           ("/mcp/" + secrets.token_hex(32), {})]:
            status, response, _ = self.f.request(self.f.mcp, "POST", bad, init, **browser, **extra)
            self.assertEqual(status, 404)
            self.assertIsNone(response["Mcp-Session-Id"])
        status, response, _ = self.f.request(self.f.mcp, "POST", path, init, **browser)
        self.assertEqual(status, 200)
        self.assertEqual(response["Access-Control-Allow-Origin"], origin)
        self.assertEqual(response["Mcp-Protocol-Version"], "2025-11-25")
        exposed = response["Access-Control-Expose-Headers"].lower()
        self.assertIn("mcp-session-id", exposed)
        self.assertIn("mcp-protocol-version", exposed)
        session = {**browser, "Mcp-Session-Id": response["Mcp-Session-Id"],
                   "Mcp-Protocol-Version": response["Mcp-Protocol-Version"]}
        notice = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.assertEqual(self.f.request(self.f.mcp, "POST", path, notice, **session)[0], 202)
        listing = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        status, _, content = self.f.request(self.f.mcp, "POST", path, listing, **session)
        self.assertEqual(status, 200)
        self.assertIn("read_file", [tool["name"] for tool in json.loads(content)["result"]["tools"]])
        log = (self.f.base / "gateway.log").read_text()
        self.assertIn("funnel.response method=OPTIONS origin=chatgpt status=204", log)
        self.assertIn("funnel.response method=POST origin=rejected status=403", log)
        self.assertIn("funnel.rpc_tools_list", log)
        self.assertNotIn("evil.invalid", log)
        self.assertNotIn(token, log)

    def test_shared_funnel_adoption_collision_and_selective_rollback(self):
        _, env = self.prepare_public_client(shared=True)
        self.f.doc["admin_listen"] = "127.0.0.1:7332"
        self.f.write_config()
        authority = TAIL["hostname"] + ":443"
        dedicated = TAIL["hostname"] + ":8443"
        with self.tail_peer() as (socket, peer):
            def command(action, *args):
                return self.cli("serve", action, "--socket", socket, *args, env=env)

            self.assertEqual(command("apply", "--confirm").returncode, 0)
            handlers = peer.configuration["Web"][authority]["Handlers"]
            handlers["/veyl/"] = {"Proxy": "http://127.0.0.1:7330"}
            handlers["/veyl-other"] = {"Text": "another app"}
            peer.configuration["AllowFunnel"][dedicated] = True
            before = copy.deepcopy(peer.configuration)
            self.assertNotEqual(command("funnel-apply", "--confirm").returncode, 0)
            handlers["/veyl/conflict"] = {"Text": "collision"}
            self.assertNotEqual(command("funnel-apply", "--adapter", "--confirm").returncode, 0)
            handlers.pop("/veyl/conflict")
            self.assertEqual(peer.configuration, before)
            peer.race = True
            self.assertNotEqual(command("funnel-apply", "--adapter", "--confirm").returncode, 0)
            self.assertEqual(peer.configuration["Web"], before["Web"])
            before = copy.deepcopy(peer.configuration)
            result = command("funnel-apply", "--adapter", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            native = copy.deepcopy(peer.configuration)
            self.assertEqual(native["TCP"], before["TCP"])
            self.assertEqual(native["AllowFunnel"], before["AllowFunnel"])
            self.assertEqual(native["Web"][authority]["Handlers"]["/"], BRIDGE["Web"][authority]["Handlers"]["/"])
            self.assertEqual(native["Web"][authority]["Handlers"]["/veyl/"], {"Proxy": "http://127.0.0.1:7331"})
            self.assertEqual(json.loads(command("inspect").stdout)["mcp"], "https://node.demo.ts.net/veyl/mcp")
            result = command("funnel-rollback", "--adapter", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(peer.configuration, before)
            self.assertEqual(command("funnel-apply", "--adapter", "--confirm").returncode, 0)
            result = command("funnel-retire-dedicated", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(peer.configuration["AllowFunnel"], BRIDGE["AllowFunnel"])
            private = f"{TAIL['hostname']}:9443"
            self.assertEqual(peer.configuration["Web"][private], before["Web"][private])
            self.assertEqual(command("funnel-rollback", "--confirm").returncode, 0)
            self.assertEqual(peer.configuration["Web"][authority]["Handlers"]["/veyl/"],
                             {"Text": "Veyl public MCP disabled"})
            self.assertEqual(peer.configuration["Web"][authority]["Handlers"]["/"], BRIDGE["Web"][authority]["Handlers"]["/"])
            self.assertEqual(peer.configuration["Web"][authority]["Handlers"]["/veyl-other"], {"Text":"another app"})
            self.assertNotEqual(command("funnel-retire-dedicated", "--confirm").returncode, 0)

    def test_standalone_funnel_first_run_and_rollback(self):
        _, env = self.prepare_public_client(shared=True)
        self.f.doc["tailscale_serve"]["standalone_funnel"] = True
        self.f.doc["admin_listen"] = "127.0.0.1:7332"
        self.f.write_config()
        authority = TAIL["hostname"] + ":443"
        with self.tail_peer() as (socket, peer):
            def command(action, *args):
                return self.cli("serve", action, "--socket", socket, *args, env=env)
            # A fresh Veyl installation must not rely on a BridgeDev proxy.
            peer.configuration = {}
            result = command("apply", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            private = copy.deepcopy(peer.configuration)
            result = command("funnel-apply", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(peer.configuration["AllowFunnel"], {authority: True})
            self.assertEqual(peer.configuration["Web"][authority]["Handlers"]["/veyl/"], {"Proxy": "http://127.0.0.1:7331"})
            self.assertEqual(json.loads(command("inspect").stdout)["mcp"], "https://node.demo.ts.net/veyl/mcp")
            posts = peer.posts
            self.assertEqual(command("funnel-apply", "--confirm").returncode, 0)
            self.assertEqual(peer.posts, posts)
            result = command("funnel-rollback", "--confirm")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(peer.configuration, private)
            self.assertEqual(command("rollback", "--confirm").returncode, 0)
            self.assertFalse(peer.configuration.get("Web"))

    def test_shared_funnel_host_requires_marker_public_proof_and_origin(self):
        token, _ = self.prepare_public_client(shared=True)
        self.start()
        origin = "https://chatgpt.com"
        public = {"Host": TAIL["hostname"], "Tailscale-Funnel-Request": "?1", "Origin": origin}
        init = {"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"shared-fixture","version":"1"}}}
        path = "/mcp/" + token
        self.assertEqual(self.f.request(self.f.mcp, "POST", path, init, Host=TAIL["hostname"])[0], 404)
        self.assertEqual(self.f.request(self.f.mcp, "POST", path, init, **{**public, "Host":"other.demo.ts.net"})[0], 403)
        self.assertEqual(self.f.request(self.f.mcp, "POST", path, init, **{**public, "Origin":"https://other.demo.ts.net"})[0], 403)
        self.assertEqual(self.f.request(self.f.mcp, "POST", "/mcp", init,
                                        **public, Authorization="Bearer " + product.TOKEN)[0], 404)
        status, headers, _ = self.f.request(self.f.mcp, "OPTIONS", path,
                                            **public, **{"Access-Control-Request-Method":"POST"})
        self.assertEqual(status, 204)
        self.assertEqual(headers["Access-Control-Allow-Origin"], origin)
        for host in (TAIL["hostname"], TAIL["hostname"] + ":443"):
            status, headers, _ = self.f.request(self.f.mcp, "POST", path, init, **{**public, "Host":host})
            self.assertEqual(status, 200)
            session = {"Mcp-Session-Id":headers["Mcp-Session-Id"]}
            self.assertEqual(self.f.request(self.f.mcp,"POST",path,
                {"jsonrpc":"2.0","method":"notifications/initialized"},**public,**session)[0], 202)
            self.assertEqual(self.f.request(self.f.mcp,"POST",path,
                {"jsonrpc":"2.0","id":2,"method":"tools/list"},**public,**session)[0], 200)

    def test_broad_rejects_visible_mount_alias_and_nested_mount(self):
        _, env = self.prepare_public_client()
        state = self.f.config.parent
        outside = self.f.base / "mountpoint"
        outside.mkdir()
        nested = state / "nested"
        nested.mkdir(mode=0o700)

        def check(*extra_mount, inventory_only=False):
            # Namespace-local bind mounts disappear with the command.
            command = ["state", "check", "--state-root", state] if inventory_only else [
                "yolo", "set", "--client", "primary", "--mode", "yolo",
            ]
            return subprocess.run(
                ["/usr/bin/bwrap", "--bind", "/", "/", *extra_mount, "--", GATEWAY,
                 *command, "--config", self.f.config],
                env=env, capture_output=True, text=True, timeout=12,
            )

        control = check(inventory_only=True)
        self.assertEqual(control.returncode, 0, control.stderr)
        alias = check("--bind", state, outside)
        self.assertNotEqual(alias.returncode, 0)
        self.assertIn("A visible mount aliases protected state", alias.stderr)
        inside = check("--bind", outside, nested)
        self.assertNotEqual(inside.returncode, 0)
        self.assertIn("without following links or crossing mountpoints", inside.stderr)

    def test_remote_host_origin_bearer_and_browser_proof(self):
        self.f.doc["tailscale_serve"]=TAIL
        self.f.write_config()
        self.start()
        remote=f"{TAIL['hostname']}:{TAIL['admin_https_port']}"
        tail_origin="https://"+remote
        local=f"127.0.0.1:{self.f.admin}"
        headers={"Host":remote,"Origin":tail_origin,"X-Forwarded-Proto":"https","Tailscale-User-Login":"fixture"}
        endpoint="/dashboard/api/"
        token=self.f.cli("dashboard","pair").strip().removeprefix("PAIRING_TOKEN=")
        pair={"pairing_token":token}
        wrong={**headers,"Origin":f"http://{local}"}
        self.assertEqual(self.f.request(self.f.admin,"POST",endpoint+"pair",pair,**wrong)[0],403)
        self.assertEqual(self.f.request(self.f.admin,"GET",endpoint+"status",**headers)[0],401)
        status, response, body=self.f.request(self.f.admin,"POST",endpoint+"pair",pair,**headers)
        self.assertEqual(status,200,body)
        cookie=response["Set-Cookie"].split(";")[0]
        csrf=json.loads(body)["csrf"]
        headers["Cookie"]=cookie
        self.assertEqual(self.f.request(self.f.admin,"GET",endpoint+"status",**headers)[0],401)
        headers["X-CSRF-Token"]=csrf
        self.assertEqual(self.f.request(self.f.admin,"GET",endpoint+"status",**headers)[0],200)
        self.assertEqual(self.f.request(self.f.admin,"GET",endpoint+"status",**{**headers,"Host":local})[0],401)
        funnel={**headers,"Tailscale-Funnel-Request":"?1"}
        self.assertEqual(self.f.request(self.f.admin,"GET",endpoint+"status",**funnel)[0],400)
        init={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}
        api=f"{TAIL['hostname']}:{TAIL['mcp_https_port']}"
        self.assertEqual(self.f.request(self.f.mcp,"POST","/mcp",init,Host=api,**{"Tailscale-User-Login":"fixture"})[0],401)
        self.assertEqual(self.f.request(self.f.mcp,"POST","/mcp",init,Host=api,Origin="https://"+api,Authorization="Bearer "+product.TOKEN)[0],200)
        self.assertEqual(self.f.request(self.f.mcp,"POST","/mcp",init,Host=api,Origin="http://"+api,Authorization="Bearer "+product.TOKEN)[0],403)
        self.assertEqual(self.f.request(self.f.mcp,"POST","/mcp",init,Host=api,Authorization="Bearer "+product.TOKEN,**{"Tailscale-Funnel-Request":"?1"})[0],403)

    def test_authenticated_mcp_through_disposable_https_proxy(self):
        self.f.doc["tailscale_serve"]=TAIL
        self.f.write_config()
        self.start()
        fixture=self.f
        class ProxyPeer(BaseHTTPRequestHandler):
            def log_message(self,*_):
                pass
            def do_POST(self):
                body=self.rfile.read(int(self.headers["Content-Length"]))
                downstream=http.client.HTTPConnection("127.0.0.1",fixture.mcp,timeout=3)
                try:
                    # Model the reverse proxy preserving the original Host.
                    headers={k:self.headers[k] for k in ("Host","Content-Type","Authorization") if self.headers.get(k)}
                    headers["X-Forwarded-Proto"]="https"
                    headers["Tailscale-User-Login"]="synthetic-tailnet-user"
                    downstream.request("POST",self.path,body,headers)
                    response=downstream.getresponse()
                    payload=response.read()
                    self.send_response(response.status)
                    self.send_header("Content-Length",str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                finally:
                    downstream.close()
        cert,key=self.f.base/"tls.crt", self.f.base/"tls.key"
        subprocess.run(["/usr/bin/openssl","req","-new","-newkey","rsa:2048","-x509","-nodes",
                        "-keyout",key,"-out",cert,"-days","1","-subj","/CN=Veyl Test Proxy",
                        "-addext","subjectAltName=IP:127.0.0.1"],
                        check=True,capture_output=True,timeout=6)
        server=ThreadingHTTPServer(("127.0.0.1",0),ProxyPeer)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert,key)
        server.socket=ctx.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        tls=ssl.create_default_context(cafile=str(cert))
        body={"jsonrpc":"2.0","id":1,"method":"initialize",
              "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"tls-fixture","version":"1"}}}
        for token,expected in ((None,401),(product.TOKEN,200)):
            headers={"Host":f"{TAIL['hostname']}:{TAIL['mcp_https_port']}","Content-Type":"application/json"}
            if token is not None:
                headers["Authorization"]="Bearer "+token
            client=http.client.HTTPSConnection("127.0.0.1",server.server_port,context=tls,timeout=6)
            try:
                client.request("POST","/mcp",json.dumps(body),headers)
                response=client.getresponse()
                payload=response.read()
                self.assertEqual(response.status,expected,payload)
                if expected==200:
                    self.assertIn("result",json.loads(payload))
            finally:
                client.close()

    def test_scoped_search_git_and_resource_grants(self):
        client=self.f.doc["clients"][0]
        client["tools"] += ["search_files","git_inspect","system_info","service_status"]
        self.f.write_config()
        workspace=self.f.workspace
        old="approved text"
        file=workspace/"notes.txt"
        file.write_text(old+"\n")
        def git(*args):
            return subprocess.check_output(["/usr/bin/git","-C",workspace,*args],env={"HOME":str(self.f.base),"PATH":"/usr/bin","GIT_CONFIG_NOSYSTEM":"1"},stderr=subprocess.DEVNULL,text=True)
        git("init","-q")
        git("add","notes.txt")
        git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid","commit","-q","-m","Initial synthetic commit")
        file.write_text("changed approved text\n")
        outside=self.f.base/"private"
        outside.write_text("SENSITIVE outside")
        (workspace/"link.txt").symlink_to(outside)
        os.link(outside,workspace/"alias.txt")
        git("config","core.fsmonitor","/nonexistent/unsafe-helper")
        self.start()
        session=self.f.connect()
        def payload(tool,args):
            value=self.f.call(tool,args,session)
            self.assertFalse(value.get("isError"),value)
            return json.loads(value["content"][0]["text"])
        hits=payload("search_files",{"query":"approved","content":True})
        self.assertEqual([hit["path"] for hit in hits["matches"]],["notes.txt"])
        self.assertEqual(payload("search_files",{"query":"SENSITIVE","content":True})["matches"],[])
        self.assertTrue(self.f.call("search_files",{"query":"SENSITIVE","path":".."},session)["isError"])
        self.assertIn("M notes.txt",payload("git_inspect",{"operation":"status"})["output"])
        self.assertIn("+changed",payload("git_inspect",{"operation":"diff"})["output"])
        self.assertIn("Initial synthetic commit",payload("git_inspect",{"operation":"history"})["output"])
        self.assertIn("true",payload("git_inspect",{"operation":"info"})["output"])
        self.assertGreater(payload("system_info",{})["memory_total_kib"],0)
        self.assertIn("LoadState",payload("service_status",{}))
        foreign=self.f.connect(product.OTHER_TOKEN)
        for tool in ("search_files","git_inspect","system_info","service_status"):
            self.assertTrue(self.f.call(tool,{},foreign,product.OTHER_TOKEN)["isError"])
        self.assertIn('"tool":"git_inspect"',self.f.audit.read_text())

    def test_structured_system_inspection_requires_grant_and_valid_sections(self):
        self.start()
        session=self.f.connect()
        self.assertTrue(self.f.call("system_inspect",{},session)["isError"])
        self.assertIn("system_inspect=false",self.f.cli("diagnostics","show","primary"))
        self.assertIn("system_inspect=true",self.f.cli("diagnostics","grant","primary"))
        reply=self.f.call("system_inspect",{"sections":["resources","gpu","storage","network","audio","bluetooth","desktop","services"]},session)
        self.assertFalse(reply["isError"],reply)
        data=json.loads(reply["content"][0]["text"])
        self.assertTrue(data["read_only"])
        self.assertGreater(data["sections"]["resources"]["memory_total_kib"],0)
        self.assertEqual(len(data["sections"]),8)
        self.assertIsInstance(data["sections"]["gpu"]["items"],list)
        self.assertIn("LoadState",data["sections"]["services"]["veyl"])
        self.assertIn("user_failed",data["sections"]["services"])
        self.assertIn("system_failed",data["sections"]["services"])
        self.assertIn("pressure",data["sections"]["resources"])
        self.assertIn("session",data["sections"]["audio"])
        self.assertIn("session",data["sections"]["bluetooth"])
        sway=self.f.call("system_inspect",{"sections":["sway"]},session)
        self.assertFalse(sway["isError"],sway)
        self.assertIn("sway",json.loads(sway["content"][0]["text"])["sections"])
        for invalid in ({"sections":["unknown"]},{"sections":["gpu","gpu"]},{"path":"/etc/shadow"}):
            self.assertTrue(self.f.call("system_inspect",invalid,session)["isError"])
        foreign=self.f.connect(product.OTHER_TOKEN)
        self.assertTrue(self.f.call("system_inspect",{},foreign,product.OTHER_TOKEN)["isError"])
        self.assertIn("system_inspect=false",self.f.cli("diagnostics","revoke","primary"))
        self.assertTrue(self.f.call("system_inspect",{},session)["isError"])

    def test_monitor_pairing_views_and_keyboard(self):
        self.f.doc["clients"][0]["tools"].append("system_info")
        self.f.write_config()
        self.start()
        reply = self.f.call("system_info",{},self.f.connect())
        self.assertFalse(reply["isError"],reply)
        def pair():
            return self.f.cli("dashboard","pair")
        cmd=[str(MONITOR),"--listen",f"127.0.0.1:{self.f.admin}"]
        for view in ("health","clients","audit","skills","upstreams","integrations"):
            result=subprocess.run([*cmd,"--view",view],input=pair(),text=True,capture_output=True,timeout=8)
            self.assertEqual(result.returncode,0,result.stderr)
            value=json.loads(result.stdout)
            self.assertNotIn("csrf",value)
        self.assertNotEqual(subprocess.run([*cmd,"--view","health"],input="1"*48,text=True,capture_output=True,timeout=8).returncode,0)
        token=pair().encode()
        read,write=os.pipe()
        pid,terminal=pty.fork()
        if pid==0:
            os.environ["TERM"]="xterm-256color"
            fcntl.ioctl(1,termios.TIOCSWINSZ,struct.pack("HHHH",32,132,0,0))
            os.close(write)
            os.dup2(read,0)
            os.close(read)
            os.execv(cmd[0],cmd)
        os.close(read)
        try:
            os.write(write,token)
            os.close(write)
            result=bytearray()
            deadline=time.monotonic()+8
            stage=0
            sent_quit=False
            while time.monotonic()<deadline:
                readable,_,_=select.select([terminal],[],[],.2)
                if not readable:
                    continue
                try:
                    chunk=os.read(terminal,8192)
                except OSError:
                    break
                if not chunk:
                    break
                result.extend(chunk)
                screen=result.rsplit(b"\x1b[H\x1b[2J",1)[-1]
                if stage==0 and b"Veyl / audit" in screen and b"system_info" in screen:
                    os.write(terminal,b"/system_info\r")
                    stage=1
                elif stage==1 and b"Filter: system_info" in screen and b"system_info" in screen:
                    os.write(terminal,b"\r")
                    stage=2
                elif stage==2 and b"Details & Parameters (JSON)" in screen:
                    self.assertIn(b'"tool": "system_info"',screen)
                    os.write(terminal,b"\x1b")
                    stage=3
                elif stage==3 and b"Veyl / audit" in screen and b"system_info" in screen:
                    os.write(terminal,b"\x1b[<0;8;7M")
                    stage=4
                elif stage==4 and b"Details & Parameters (JSON)" in screen:
                    os.write(terminal,b"4")
                    stage=5
                if b"Veyl / clients" in result and not sent_quit:
                    os.write(terminal,b"q")
                    sent_quit=True
            self.assertIn(b"Veyl / clients",result)
            self.assertEqual(stage,5)
            self.assertIn(b"\x1b[?1006h",result)
            self.assertIn(b"\x1b[?1006l",result)
            self.assertIn(b"primary",result)
            self.assertIn(b"\x1b[?1049h",result)
            self.assertIn(b"\x1b[?1049l",result)
            self.assertIn(b"SESSIONS / GRANTS",result)
            # The live interface must inherit the terminal background. No
            # reverse video, fixed black/white fills or RGB backgrounds.
            styles = re.findall(rb"\x1b\[([0-9;]*)m", result)
            self.assertTrue(styles)
            allowed = {b"0", b"1", b"2", b"4", b"31", b"32", b"33", b"36", b"39"}
            self.assertTrue(all(part in allowed for style in styles for part in style.split(b";")), styles)
            self.assertIn(b"\x1b[1;4;33m",result)
            self.assertIn("╭".encode(),result)
            self.assertIn("╯".encode(),result)
        finally:
            os.close(terminal)
            found,status=os.waitpid(pid,os.WNOHANG)
            if not found:
                os.kill(pid,15)
                os.waitpid(pid,0)

    def test_monitor_lists_reads_and_cancels_owned_job(self):
        state=self.f.base/"jobs"
        state.mkdir(mode=0o700)
        self.f.doc["job_state_dir"]=str(state)
        self.f.doc["policy_version"]=2
        self.f.doc["job_profiles"]={"sleep":{"executable":"/usr/bin/sleep","args":["10"],
                                           "timeout_seconds":12,"max_output_bytes":4096}}
        self.f.doc["clients"][0]["tools"].append("job_start")
        self.f.write_config()
        self.start()
        job=self.f.call("job_start",{"profile":"sleep"},self.f.connect())
        self.assertFalse(job.get("isError"),job)
        job=json.loads(job["content"][0]["text"])["job_id"]
        def command(*args):
            return subprocess.run([MONITOR,"--listen",f"127.0.0.1:{self.f.admin}",*args],
                input=self.f.cli("dashboard","pair"),capture_output=True,text=True,timeout=8)
        listing=command("--client","primary","--view","jobs")
        self.assertEqual(listing.returncode,0,listing.stderr)
        self.assertEqual(json.loads(listing.stdout)["jobs"][0]["job_id"],job)
        denied=command("--client","secondary","--view","logs","--job",job)
        self.assertNotEqual(denied.returncode,0)
        logs=command("--client","primary","--view","logs","--job",job)
        self.assertEqual(logs.returncode,0,logs.stderr)
        self.assertEqual(json.loads(logs.stdout)["job_id"],job)
        refused=command("--client","primary","--cancel",job)
        self.assertNotEqual(refused.returncode,0)
        ended=command("--client","primary","--cancel",job,"--confirm")
        self.assertEqual(ended.returncode,0,ended.stderr)
        self.assertEqual(json.loads(ended.stdout)["state"],"canceled")

    def test_systemd_dry_run_validation_and_isolated_files(self):
        home=self.f.base/"isolated-home"
        home.mkdir(mode=0o700)
        env={"HOME":str(home),"PATH":"/usr/bin","XDG_RUNTIME_DIR":str(home/"no-manager")}
        unit=home/".config/systemd/user/mcp-gateway.service"
        valid=self.cli("service","validate",env=env)
        self.assertEqual(valid.returncode,0,valid.stderr)
        for command in ["install","enable","disable","start","stop","restart"]:
            plan=self.cli("service",command,"--dry-run",env=env)
            self.assertEqual(plan.returncode,0,plan.stderr)
            self.assertIn("activation=none",plan.stdout)
            self.assertFalse(unit.exists())
            self.assertFalse((self.f.base/".clients.json.policy-lock").exists())
        installed=self.cli("service","install","--confirm",env=env)
        self.assertEqual(installed.returncode,0,installed.stderr)
        self.assertTrue(unit.exists())
        self.assertIn("UNCHANGED",self.cli("service","install","--confirm",env=env).stdout)
        check=subprocess.run(["/usr/bin/systemd-analyze","verify",unit],capture_output=True,text=True,timeout=10)
        self.assertEqual(check.returncode,0,check.stderr)
        refused=self.cli("service","start","--confirm",env=env)
        self.assertNotEqual(refused.returncode,0)
        self.assertTrue(unit.exists())
        result=self.cli("service","uninstall","--confirm",env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(unit.exists())
        self.assertTrue(self.f.audit.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
