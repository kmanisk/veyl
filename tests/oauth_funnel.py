#!/usr/bin/env python3
"""Native OAuth through disposable Tailscale LocalAPI foreground leases.

No live tailscaled calls or public network. The fake daemon models ETag CAS
and connection-owned route cleanup; HTTP admission uses the real gateway.
"""
import copy
import http.server
import json
import os
import pathlib
import secrets
import socket
import socketserver
import subprocess
import threading
import time
import unittest

import oauth_native as native

preview = native.preview
HOST = "fixture.tailtest.ts.net"
PORT = 10000
AUTHORITY = f"{HOST}:{PORT}"
ORIGIN = "https://" + AUTHORITY
API = "/localapi/v0/serve-config"
WATCH = "/localapi/v0/watch-ipn-bus?mask=18"
STATUS = "/localapi/v0/status?peers=false"
ENVELOPE = [("Tailscale-Funnel-Request","?1"),("X-Forwarded-Host",AUTHORITY),
            ("X-Forwarded-Proto","https"),("X-Forwarded-For","192.0.2.7")]


class FakeDaemon(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path):
        super().__init__(str(path), Handler)
        self.lock = threading.Lock()
        self.initial = {"TCP":{"443":{"HTTPS":True},"8443":{"HTTPS":True}},
                        "Web":{f"{HOST}:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7330"}}},
                               f"{HOST}:8443":{"Handlers":{"/":{"Text":"unrelated"}}}},
                        "AllowFunnel":{f"{HOST}:443":True},
                        "Foreground":{"other-owner":{"TCP":{"9443":{"HTTPS":True}}}}}
        self.state = copy.deepcopy(self.initial)
        self.revision = 1
        self.sessions = {}
        self.posts = 0
        self.reject_post = False
        self.no_etag = False
        self.funnel_allowed = True
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.state)

    def own_ids(self):
        with self.lock:
            return list(self.sessions)

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)

    def disconnect(self):
        with self.lock:
            for conn in self.sessions.values():
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send_json(self, status, value, etag=None):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data)))
        self.send_header("Connection","close")
        if etag is not None:
            self.send_header("ETag",etag)
        self.end_headers()
        self.wfile.write(data)
        self.close_connection=True

    def do_GET(self):
        s=self.server
        if self.path == STATUS:
            caps={"funnel":[], "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000":[]}
            if not s.funnel_allowed:
                caps={}
            self.send_json(200,{"BackendState":"Running","Self":{"DNSName":HOST+".","CapMap":caps},"CertDomains":[HOST]})
        elif self.path == API:
            with s.lock:
                self.send_json(200,s.state,None if s.no_etag else f'"{s.revision}"')
        elif self.path == WATCH:
            sid=secrets.token_hex(16)
            with s.lock:
                s.sessions[sid]=self.connection
            try:
                self.send_response(200)
                self.send_header("Content-Type","application/json")
                self.send_header("Connection","close")
                self.end_headers()
                self.wfile.write(json.dumps({"State":6,"SessionID":sid}).encode()+b"\n")
                self.wfile.flush()
                self.connection.settimeout(15)
                while self.connection.recv(1024):
                    pass
            except (OSError, TimeoutError):
                pass
            finally:
                with s.lock:
                    s.sessions.pop(sid,None)
                    if sid in s.state.get("Foreground",{}):
                        del s.state["Foreground"][sid]
                        s.revision+=1
                self.close_connection=True
        else:
            self.send_json(404,{})

    def do_POST(self):
        s=self.server
        if self.path!=API:
            self.send_json(404,{})
            return
        data=json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with s.lock:
            s.posts+=1
            if s.reject_post or self.headers.get("If-Match")!=f'"{s.revision}"':
                self.send_json(412,{})
                return
            added=set(data.get("Foreground",{}))-set(s.state.get("Foreground",{}))
            if len(added)!=1 or not added.issubset(s.sessions):
                self.send_json(400,{})
                return
            prior=copy.deepcopy(data)
            for sid in added:
                del prior["Foreground"][sid]
            if prior!=s.state:
                self.send_json(400,{})
                return
            s.state=data
            s.revision+=1
            self.send_json(200,{})


class Funnel(native.NativeOAuth):
    def setUp(self):
        super().setUp()
        self.socket_path=self.base/"fake-tailscale.sock"
        self.daemon=FakeDaemon(self.socket_path)
        self.addCleanup(self.daemon.close)
        # Gateway must stop before the fixture daemon is destroyed.
        self.addCleanup(self.f.cleanup_server)
        old=(preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL)
        self.addCleanup(lambda:setattr(preview,"ORIGIN",old[0]))
        self.addCleanup(lambda:setattr(preview,"HOST",old[1]))
        self.addCleanup(lambda:setattr(preview,"RESOURCE",old[2]))
        self.addCleanup(lambda:setattr(preview,"LOCAL",old[3]))
        preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL=ORIGIN,AUTHORITY,ORIGIN+"/mcp","oauth-preview"
        self.raw_request=self.f.request
        def request(method,path,body=None,*,admin=False,headers=(),**kwargs):
            if not admin:
                headers=list(ENVELOPE)+list(headers)
            return self.raw_request(method,path,body,admin=admin,headers=headers,**kwargs)
        self.f.request=request
        self.profile=self.base/"funnel-profile"

    def command(self,action="setup",extra=()):
        return self.onboarding_args(action,self.profile,self.root if action=="setup" else None)+["--funnel","--funnel-socket",str(self.socket_path)]+list(extra)

    def wait_for(self,predicate):
        end=time.monotonic()+5
        while time.monotonic()<end:
            if predicate():
                return
            time.sleep(.02)
        self.fail("condition not reached")

    def start_funnel(self,action="setup"):
        self.launch(self.command(action))
        self.config=self.profile/"clients.json"
        self.wait_for(lambda:len(self.daemon.snapshot()["Foreground"])==2)
        state=self.daemon.snapshot()
        keys=set(state["Foreground"])-{"other-owner"}
        self.assertEqual(len(keys),1)
        route=state["Foreground"][keys.pop()]
        self.assertEqual(route,{"TCP":{str(PORT):{"HTTPS":True}},
            "Web":{AUTHORITY:{"Handlers":{"/":{"Proxy":f"http://127.0.0.1:{self.f.public}"}}}},
            "AllowFunnel":{AUTHORITY:True}})
        self.assertEqual(self.f.request("GET","/mcp")[0],401)

    def stop_funnel(self,kill=False):
        proc=self.f.proc
        if kill:
            proc.kill()
        else:
            proc.terminate()
        proc.wait(timeout=10)
        if not kill:
            self.assertEqual(proc.returncode,0,proc.stderr.read())
        self.f.cleanup_server()
        self.wait_for(lambda:self.daemon.snapshot()==self.daemon.initial)

    def test_funnel_real_oauth_and_lease_cleanup(self):
        self.start_funnel()
        status,headers,body=self.f.request("GET","/mcp")
        self.assertEqual(status,401)
        self.assertIn(ORIGIN+"/.well-known/oauth-protected-resource/mcp",headers["www-authenticate"])
        status,_,body=self.f.request("GET","/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)["resource"],ORIGIN+"/mcp")
        for path in ("/dashboard","/dashboard/api/oauth","/inspect","/oauth/approve","/mcp/secret","/mcp/","/veyl/mcp","/%6dcp"):
            self.assertEqual(self.f.request("GET",path)[0],404,path)
        self.assertEqual(self.raw_request("GET","/mcp")[0],403)
        # A tailnet browser sees the same issuer through private Serve.
        # Its proxy identity must not be mistaken for an OAuth credential.
        private=ENVELOPE[1:]+[("Tailscale-User-Login","fixture-user")]
        self.assertEqual(self.raw_request("GET","/mcp",headers=private)[0],401)
        self.assertEqual(self.raw_request("GET","/.well-known/oauth-authorization-server",headers=private)[0],200)
        for bad in [("X-Forwarded-Host","evil.example"),("X-Forwarded-Proto","http"),("Tailscale-Funnel-Request","?0"),
                    ("Origin","https://evil.example"),("Tailscale-User-Login","operator")]:
            self.assertEqual(self.f.request("GET","/mcp",headers=[bad])[0],403,bad)
        self.assertEqual(self.f.request("GET","/mcp",host="evil.example")[0],403)
        client=self.f.register()
        handle=self.f.pending(client)
        info=self.cli("inspect",{"request":handle})
        data=self.exact("approve",handle,info)
        data.pop("action")
        self.assertTrue(self.cli("approve",data)["approved"])
        tokens=self.f.capture_tokens(self.f.exchange(client,self.delivered(handle)))
        token=tokens["access_token"]
        self.assertIn("native-read-canary",json.dumps(self.read(token,self.connect(token),"canary.txt")))
        self.stop_funnel()
        # Even if a different allowed port becomes available, the original
        # durable OAuth origin must be recovered, not silently migrated.
        with self.daemon.lock:
            self.daemon.state["TCP"].pop("8443")
            self.daemon.state["Web"].pop(f"{HOST}:8443")
            self.daemon.initial=copy.deepcopy(self.daemon.state)
            self.daemon.revision+=1
        refused=subprocess.run(self.command("run",extra=["--funnel-port","8443"]),capture_output=True,text=True,timeout=10,env=dict(os.environ,HOME=str(self.base)))
        self.assertNotEqual(refused.returncode,0)
        self.assertEqual(self.daemon.posts,1)
        self.start_funnel("run")
        self.assertIn("native-read-canary",json.dumps(self.read(token,self.connect(token),"canary.txt")))
        self.assertTrue(self.cli("revoke",{"client_id":client,"confirm":True})["revoked"])
        self.assertEqual(self.rpc(token,"initialize",params=native.INIT)[0],401)
        self.stop_funnel(kill=True)
        self.assertEqual(self.daemon.posts,2)

    def test_funnel_collisions_and_conditional_failure(self):
        env=dict(os.environ,HOME=str(self.base))
        result=subprocess.run(self.command(extra=["--funnel-port","8443"]),capture_output=True,text=True,timeout=10,env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.profile.exists())
        self.assertEqual(self.daemon.posts,0)
        self.daemon.funnel_allowed=False
        result=subprocess.run(self.command(),capture_output=True,text=True,timeout=10,env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.profile.exists())
        self.daemon.funnel_allowed=True
        self.daemon.reject_post=True
        result=subprocess.run(self.command(),capture_output=True,text=True,timeout=10,env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn("OAUTH_FUNNEL_URL",result.stderr)
        self.assertEqual(self.daemon.posts,1)
        self.wait_for(lambda:not self.daemon.own_ids())
        self.assertEqual(self.daemon.snapshot(),self.daemon.initial)

    def test_funnel_unbounded_writable_profiles_are_refused(self):
        definitions = self.base / "bounded-profiles.json"
        definitions.write_text(json.dumps({"job_profiles": {
            "pwd": {"executable": "/usr/bin/pwd", "args": [], "timeout_seconds": 4},
        }}))
        definitions.chmod(0o600)
        env = dict(os.environ, HOME=str(self.base))
        for extra in (["--workspace-edit"], ["--workspace-tools"],
                      ["--funnel-advanced", "--workspace-jobs", "--job-profiles", str(definitions)]):
            result = subprocess.run(self.command(extra=extra), capture_output=True, text=True, timeout=10, env=env)
            self.assertNotEqual(result.returncode, 0, result)
            self.assertIn("private dedicated tmpfs mount", result.stderr)
            self.assertFalse(self.profile.exists())
            self.assertEqual(self.daemon.posts, 0)

    def test_funnel_advanced_exact_consent_and_family_boundary(self):
        from oauth_jobs import OAuthJobs
        from oauth_interactive import OAuthInteractive
        from oauth_upstreams import CHUNKS

        definitions = self.base / "job-profiles.json"
        definitions.write_text(json.dumps({"job_profiles": {
            "pwd": {"executable": "/usr/bin/pwd", "args": [], "timeout_seconds": 4},
            "shell": {"executable": "/usr/bin/sh", "args": ["-s"],
                      "interactive": True, "timeout_seconds": 30},
            "pty_shell": {"executable": "/usr/bin/bash", "args": ["--noprofile", "--norc", "-i"],
                          "interactive": True, "pty": True, "timeout_seconds": 30},
        }}))
        definitions.chmod(0o600)
        manifest = self.base / "providers.json"
        manifest.write_text(json.dumps({
            "mcp_servers": {"stdio": {"transport": "stdio", "command": "/usr/bin/python3",
                "args": ["-c", "import sys;exec(''.join(sys.argv[1:]))", *CHUNKS]}},
            "allowed_server_tools": {"stdio": ["probe"]},
        }))
        manifest.chmod(0o600)
        flags = ["--workspace-jobs", "--workspace-commands", "--workspace-interactive",
                 "--workspace-upstreams", "--workspace-tools"]
        inputs = ["--job-profiles", str(definitions), "--upstream-manifest", str(manifest)]
        env = dict(os.environ, HOME=str(self.base))
        for denied in (self.command(extra=flags + inputs),
                       self.command(extra=["--funnel-advanced"]),
                       self.onboarding_args("setup", self.profile, self.root) + flags + inputs
                           + ["--funnel-advanced"]):
            result = subprocess.run(denied, capture_output=True, text=True, timeout=10, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.profile.exists())
            self.assertEqual(self.daemon.posts, 0)

        # The full positive control now requires an operator-provisioned,
        # empty dedicated bounded tmpfs. Never weaken the live admission gate
        # or mount/format a filesystem from this test.
        fixture = os.environ.get("VEYL_TEST_BOUNDED_WORKSPACE")
        if not fixture:
            self.skipTest("requires dedicated bounded tmpfs; negative controls run separately")
        root = pathlib.Path(fixture)
        self.assertEqual(root.resolve(), root)
        self.assertTrue(root.is_mount())
        self.assertEqual(root.stat().st_uid, os.getuid())
        self.assertEqual(root.stat().st_mode & 0o7777, 0o700)
        self.assertFalse(list(root.iterdir()), "fixture must be empty")
        self.root = root
        canary = root / "canary.txt"
        escape = root / "escape.txt"
        canary.write_text("native-read-canary")
        escape.symlink_to(self.base / "outside.txt")
        self.addCleanup(canary.unlink, missing_ok=True)
        self.addCleanup(escape.unlink, missing_ok=True)
        self.addCleanup(self.f.cleanup_server)
        self.launch(self.command(extra=flags + inputs + ["--funnel-advanced"]))
        self.config = self.profile / "clients.json"
        self.wait_for(lambda: len(self.daemon.snapshot()["Foreground"]) == 2)
        self.assertEqual(self.f.request("GET", "/mcp")[0], 401)
        self.assertEqual(self.f.request("GET", "/dashboard/api/oauth")[0], 404)
        def approve(client=None):
            client = client or self.f.register()
            handle = self.f.pending(client)
            info = self.cli("inspect", {"request": handle})
            self.assertTrue(info["eligible"], info)
            scope = info["native_scope"]
            for field in ("funnel_advanced", "workspace_jobs", "workspace_commands",
                          "workspace_interactive", "workspace_upstreams"):
                self.assertTrue(scope[field], scope)
            self.assertTrue(scope["public_capability_limits"]["workspace_disk_quota_enforced"])
            self.assertEqual(scope["bounded_workspace"]["backend"], "tmpfs")
            args = self.exact("approve", handle, info)
            args.pop("action")
            self.cli("approve", args, success=False)
            self.cli("approve", dict(args, scope_fingerprint="0"*64), success=False)
            args["scope_fingerprint"] = info["scope_fingerprint"]
            self.assertTrue(self.cli("approve", args)["approved"])
            return client, self.f.capture_tokens(self.f.exchange(client, self.delivered(handle)))
        client, a = approve()
        _, b = approve(client)
        at, bt = a["access_token"], b["access_token"]
        sa, sb = self.connect(at), self.connect(bt)
        def call(token, session, name, args, ok=True):
            return OAuthJobs.call(self, token, session, name, args, ok)
        named = call(at, sa, "run_command", {"profile": "pwd"})
        self.assertEqual(named["exit_code"], 0, named)
        self.assertEqual(named["logs"]["stdout"].strip(), str(self.root))
        dynamic = call(at, sa, "exec_command", {"command": "printf public-fixture", "cwd": "."})
        self.assertEqual(dynamic["exit_code"], 0, dynamic)
        self.assertEqual(dynamic["stdout"], "public-fixture")
        call(at, sa, "exec_command", {"command": "true", "cwd": ".."}, False)
        status, _, body = self.rpc(at, "tools/call", sa, {"name": "stdio__probe",
            "arguments": {"protected": str(self.config), "msg": "upstream-fixture"}})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["result"]["content"][0]["text"], "upstream-fixture")
        call(at, sa, "mcp_servers_call", {"name": "stdio__hidden", "arguments": {}}, False)
        pipe = call(at, sa, "process_start", {"profile": "shell"})["job_id"]
        self.wait_for(lambda: call(at, sa, "job_status", {"job_id": pipe})["state"] == "running")
        call(bt, sb, "process_input", {"job_id": pipe, "sequence": 0, "data": "printf denied"}, False)
        value = call(at, sa, "process_input", {"job_id": pipe, "sequence": 0, "data": "printf pipe-ok\n"})
        self.assertEqual(value["status"], "accepted")
        self.wait_for(lambda: call(at, sa, "job_logs", {"job_id": pipe})["stdout"] == "pipe-ok")
        pty = call(at, sa, "process_start", {"profile": "pty_shell"})["job_id"]
        self.wait_for(lambda: call(at, sa, "job_status", {"job_id": pty})["state"] == "running")
        call(at, sa, "process_resize", {"job_id": pty, "rows": 32, "cols": 100})
        status = call(at, sa, "shell_status", {"job_id": pty})
        self.assertEqual((status["rows"], status["cols"]), (32, 100))
        for job in (pipe, pty):
            call(at, sa, "job_cancel", {"job_id": job})
        self.stop_funnel()
        refused = subprocess.run(self.command("run", extra=flags), capture_output=True,
                                 text=True, timeout=10, env=env)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(self.daemon.posts, 1)
        self.launch(self.command("run", extra=flags + ["--funnel-advanced"]))
        self.config = self.profile / "clients.json"
        self.wait_for(lambda: len(self.daemon.snapshot()["Foreground"]) == 2)
        self.assertIn("native-read-canary", json.dumps(self.read(at, self.connect(at), "canary.txt")))
        self.assertTrue(self.cli("revoke", {"client_id": client, "confirm": True})["revoked"])
        self.assertEqual(self.rpc(at, "initialize", params=native.INIT)[0], 401)
        self.stop_funnel()
        self.assertEqual(self.daemon.posts, 2)

    def test_funnel_watch_disconnect_stops_gateway(self):
        self.start_funnel()
        self.daemon.disconnect()
        self.f.proc.wait(timeout=10)
        self.assertNotEqual(self.f.proc.returncode,0)
        self.f.cleanup_server()
        self.wait_for(lambda:self.daemon.snapshot()==self.daemon.initial)
        self.assertEqual(self.daemon.posts,1)


if __name__=="__main__":
    suite=unittest.TestSuite(Funnel(name) for name in unittest.defaultTestLoader.getTestCaseNames(Funnel) if name.startswith("test_funnel_"))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
