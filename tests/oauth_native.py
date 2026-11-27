#!/usr/bin/env python3
"""Real native read-only OAuth admission with independent grant families."""
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.parse

import oauth_http_preview as preview

BIN = preview.BIN
NATIVE_TOKEN = "b5" * 32
INIT = {"protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "native-oauth-fixture", "version": "1"}}


class NativeOAuth(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="veyl-native-oauth-")
        self.addCleanup(tmp.cleanup)
        self.base = pathlib.Path(tmp.name)
        self.root = self.base / "workspace"
        self.root.mkdir(mode=0o700)
        (self.root / "canary.txt").write_text("native-read-canary")
        (self.base / "outside.txt").write_text("outside-denied-canary")
        (self.root / "escape.txt").symlink_to(self.base / "outside.txt")
        self.audit = self.base / "audit" / "audit.jsonl"
        self.audit.parent.mkdir(mode=0o700)
        self.audit.touch(mode=0o600)
        self.config = self.base / "clients.json"
        self.doc = {"audit_log": str(self.audit), "admin_listen":"127.0.0.1:0",
                    "clients":[{"id":preview.LOCAL,
                                "token_sha256": hashlib.sha256(NATIVE_TOKEN.encode()).hexdigest(),
                                "root":str(self.root), "expires_at_unix_seconds": int(time.time())+300,
                                "tools":["read_file"]}]}
        self.write_config()
        self.f = preview.OAuthHttpPreview()
        self.f.secret = secrets.token_hex(32)
        self.f.sensitive = [self.f.secret]
        self.f.proc = None
        self.state_dir = None
        self.initialize_state = False
        self.addCleanup(self.f.cleanup_server)

    def write_config(self):
        path = self.config.with_suffix(".new")
        path.write_text(json.dumps(self.doc))
        path.chmod(0o600)
        path.replace(self.config)

    def args(self, origin=preview.ORIGIN, listen="127.0.0.1:0", enabled=True):
        args=[str(BIN), "http", "--listen", listen, "--config", str(self.config)]
        return args+["--oauth-preview-origin", origin] if enabled else args

    def input(self):
        config = {"operator_token": self.f.secret, "local_fixture_client":preview.LOCAL}
        if self.state_dir is not None:
            config.update(state_dir=str(self.state_dir), initialize_state=self.initialize_state)
        return json.dumps(config)

    def start(self, enabled=True):
        self.launch(self.args(enabled=enabled),self.input() if enabled else None)

    def launch(self,args,config=None,env=None):
        self.f.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, env=env or dict(os.environ, HOME=str(self.base)))
        if config is not None:
            self.f.proc.stdin.write(config)
        self.f.proc.stdin.close()
        import select
        # Read stderr directly (unbuffered os.read) to avoid select/readline
        # buffering when both listener lines arrive in one write.
        data = b""
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            if not select.select([self.f.proc.stderr], [], [], .25)[0]:
                continue
            block = os.read(self.f.proc.stderr.fileno(), 4096)
            if not block:
                break
            data += block
            admin = re.search(rb"ADMIN_HTTP_LISTEN=127\.0\.0\.1:(\d+)", data)
            mcp = re.search(rb"MCP_HTTP_LISTEN=127\.0\.0\.1:(\d+)", data)
            if admin and mcp:
                self.f.admin, self.f.public = int(admin[1]), int(mcp[1])
                self.assertNotEqual(self.f.admin, self.f.public)
                return
        self.fail("native preview did not start: "+data.decode(errors="replace"))

    def refuse(self, **kwargs):
        result = subprocess.run(self.args(**kwargs), input=self.input(), capture_output=True,
            text=True, timeout=5, env=dict(os.environ, HOME=str(self.base)))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("MCP_HTTP_LISTEN", result.stderr)
        self.assertNotIn(self.f.secret, result.stderr)

    def issue(self, client=None):
        client = client or self.f.register()
        code = self.f.approve(self.f.pending(client))
        return client, self.f.capture_tokens(self.f.exchange(client,code))

    def rpc(self, token, method, session=None, params=None):
        data = {"jsonrpc":"2.0","method":method}
        if not method.startswith("notifications/"):
            data["id"] = 1
        if params is not None:
            data["params"] = params
        headers = [] if session is None else [("Mcp-Session-Id", session)]
        return self.f.request("POST","/mcp",data,auth=token,headers=headers)

    def connect(self, token):
        status, headers, body = self.rpc(token, "initialize",params=INIT)
        self.assertEqual(status,200,body)
        self.assertEqual(json.loads(body)["result"]["protocolVersion"],INIT["protocolVersion"])
        session = headers["mcp-session-id"]
        self.f.sensitive.append(session)
        self.assertEqual(self.rpc(token,"notifications/initialized",session)[0],202)
        return session

    def read(self, token, session, path):
        status, _, body = self.rpc(token,"tools/call",session,{"name":"read_file","arguments":{"path":path}})
        self.assertEqual(status,200,body)
        return json.loads(body)["result"]

    def test_native_scope_refresh_and_family_isolation(self):
        self.start()
        client, a = self.issue()
        # A separate consent family for the same OAuth registration and
        # same native principal must still not use the other MCP session.
        _, b = self.issue(client)
        at, bt = a["access_token"], b["access_token"]
        session = self.connect(at)
        status, _, body = self.rpc(at,"tools/list",session)
        self.assertEqual(status,200)
        self.assertEqual({t["name"] for t in json.loads(body)["result"]["tools"]},{"read_file"})
        result = self.read(at,session,"canary.txt")
        self.assertFalse(result.get("isError",False))
        self.assertIn("native-read-canary",json.dumps(result))
        for path in ("../outside.txt",str(self.base/"outside.txt"),"escape.txt"):
            result = self.read(at,session,path)
            self.assertTrue(result.get("isError"),result)
            self.assertNotIn("outside-denied-canary",json.dumps(result))
        status, _, body = self.rpc(at,"tools/call",session,
            {"name":"write_file","arguments":{"path":"canary.txt","content":"unexpected"}})
        self.assertEqual(status,200)
        self.assertTrue(json.loads(body)["result"]["isError"])
        self.assertEqual((self.root/"canary.txt").read_text(),"native-read-canary")
        self.assertEqual(self.rpc(bt,"tools/list",session)[0],403)
        own = self.connect(bt)
        self.assertIn("native-read-canary",json.dumps(self.read(bt,own,"canary.txt")))
        self.assertEqual(self.rpc(NATIVE_TOKEN,"initialize",params=INIT)[0],401)
        renewed = self.f.capture_tokens(self.f.refresh(client,a["refresh_token"]))
        self.assertEqual(self.rpc(at,"tools/list",session)[0],401)
        self.assertEqual(self.rpc(renewed["access_token"],"tools/list",session)[0],200)
        self.assertEqual(self.f.refresh(client,a["refresh_token"])[0],400)
        self.assertEqual(self.rpc(renewed["access_token"],"tools/list",session)[0],401)
        self.assertEqual(self.rpc(bt,"tools/list",own)[0],200)
        self.assertEqual(self.f.local("/revoke",{"client_id":client})[0],200)
        self.assertEqual(self.rpc(bt,"tools/list",own)[0],401)
        self.assertIn("oauth_admission",self.audit.read_text())
        self.assertIn("oauth_worker_admission",self.audit.read_text())
        for value in self.f.sensitive:
            self.assertNotIn(value,self.audit.read_text())

    def test_live_native_credential_and_grant_change(self):
        self.start()
        client, issued = self.issue()
        access = issued["access_token"]
        session = self.connect(access)
        self.assertIn("native-read-canary",json.dumps(self.read(access,session,"canary.txt")))
        # Removal of the native credential must invalidate OAuth admission
        # even while the OAuth access token itself is unexpired.
        self.doc["clients"][0]["token_sha256"] = hashlib.sha256(b"replacement").hexdigest()
        self.write_config()
        self.assertIn(self.rpc(access,"tools/list",session)[0],(401,503))
        self.assertEqual(self.f.local("/revoke",{"client_id":client})[0],200)
        self.assertEqual(self.rpc(access,"tools/list",session)[0],401)

    def test_audit_binding_failure_denies_native_reads(self):
        self.start()
        _, issued = self.issue()
        access = issued["access_token"]
        session = self.connect(access)
        self.assertIn("native-read-canary",json.dumps(self.read(access,session,"canary.txt")))
        # Only the disposable test ledger is moved. The native audit sink
        # must reject its now-unbound ledger before any new tool admission.
        self.audit.rename(self.audit.with_suffix(".detached"))
        status, _, body = self.rpc(access,"tools/call",session,{"name":"read_file","arguments":{"path":"canary.txt"}})
        self.assertEqual(status,503)
        self.assertNotIn(b"native-read-canary",body)

    def test_startup_guards_and_admin_boundary(self):
        self.refuse(origin="https://real.example.com")
        self.refuse(listen="127.0.0.1:7331")
        saved = self.f.secret
        self.f.secret = NATIVE_TOKEN
        self.refuse()
        self.f.secret = saved
        self.doc["clients"][0]["tools"].append("write_file")
        self.write_config()
        self.refuse()
        self.doc["clients"][0]["tools"] = ["read_file"]
        self.write_config()
        self.start()
        self.assertEqual(self.f.request("GET","/dashboard")[0],404)
        self.assertEqual(self.f.request("POST","/approve",{"request":"a"*64},auth=self.f.secret)[0],404)
        self.assertEqual(self.f.local("/inspect",{"request":"a"*64},auth=None)[0],401)
        self.assertEqual(self.f.local("/inspect",{"request":"a"*64},
                            headers=[("Origin",preview.ORIGIN)])[0],403)

    def durable_start(self):
        self.state_dir = self.base / "oauth-state"
        self.state_dir.mkdir(mode=0o700)
        self.initialize_state = True
        self.start()
        self.initialize_state = False
        return self.state_dir / "oauth-state.json"

    def restart(self):
        self.f.cleanup_server()
        self.start()

    def test_durable_native_restart_replay_revocation(self):
        path = self.durable_start()
        client, a = self.issue()
        other, b = self.issue()
        access = a["access_token"]
        old_session = self.connect(access)
        rotated = self.f.capture_tokens(self.f.refresh(client,a["refresh_token"]))
        pending = self.f.pending(client)
        # Crash after an acknowledged clean commit, not a graceful shutdown.
        self.f.proc.kill()
        self.restart()
        self.assertEqual(self.rpc(access,"initialize",params=INIT)[0],401)
        self.assertEqual(self.rpc(rotated["access_token"],"tools/list",old_session)[0],404)
        session = self.connect(rotated["access_token"])
        self.assertIn("native-read-canary",json.dumps(self.read(rotated["access_token"],session,"canary.txt")))
        self.assertEqual(self.f.local("/approve",{"request":pending,"local_client":preview.LOCAL})[0],400)
        self.assertEqual(self.f.refresh(client,a["refresh_token"])[0],400)
        self.assertEqual(self.rpc(rotated["access_token"],"tools/list",session)[0],401)
        self.restart()
        self.assertEqual(self.f.refresh(client,rotated["refresh_token"])[0],400)
        self.assertEqual(self.rpc(rotated["access_token"],"initialize",params=INIT)[0],401)
        self.assertIn("native-read-canary",json.dumps(self.read(b["access_token"],self.connect(b["access_token"]),"canary.txt")))
        self.assertEqual(self.f.local("/revoke",{"client_id":other})[0],200)
        self.restart()
        self.assertEqual(self.rpc(b["access_token"],"initialize",params=INIT)[0],401)
        self.assertEqual(self.f.refresh(other,b["refresh_token"])[0],400)
        snapshot = json.loads(path.read_text())["payload"]
        self.assertEqual(snapshot["families"],[])
        self.assertIsNone(snapshot["interrupted"])
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        receipts = snapshot["audit"]
        self.assertGreater(len(receipts), 10)
        self.assertEqual([r["sequence"] for r in receipts],list(range(1,len(receipts)+1)))
        self.assertTrue(any(r["operation"]=="refresh" and r["status"]==400 for r in receipts))
        self.assertTrue(any(r["operation"]=="revoke" and r["status"]==200 and r["client"]==other for r in receipts))
        for raw in self.f.sensitive+[NATIVE_TOKEN]:
            self.assertNotIn(raw,path.read_text())

    def test_durable_fail_closed_on_corruption_and_interrupted_intent(self):
        path = self.durable_start()
        client, a = self.issue()
        self.f.cleanup_server()
        raw = path.read_bytes()
        original = json.loads(raw)
        # Simulate a valid durable intent from an interrupted transition.
        original["payload"]["interrupted"] = "refresh"
        payload = json.dumps(original["payload"],sort_keys=True,separators=(",",":"),ensure_ascii=False)
        original["sha256"] = hashlib.sha256(payload.encode()).hexdigest()
        path.write_text(json.dumps(original,sort_keys=True,separators=(",",":"),ensure_ascii=False))
        self.refuse()
        path.write_bytes(raw)
        self.start()
        # The same owner can damage its own store; a subsequent transition
        # must not issue tokens or silently overwrite external changes.
        path.write_text("{}")
        self.assertEqual(self.f.refresh(client,a["refresh_token"])[0],503)
        self.assertEqual(self.rpc(a["access_token"],"initialize",params=INIT)[0],503)
        self.f.cleanup_server()
        self.refuse()

    def test_durable_policy_binding_and_no_implicit_initialization(self):
        path = self.durable_start()
        self.issue()
        self.f.cleanup_server()
        self.initialize_state = True
        self.refuse()  # Existing state must not be reset.
        self.initialize_state = False
        self.doc["clients"][0]["token_sha256"] = hashlib.sha256(b"changed").hexdigest()
        self.write_config()
        self.refuse()
        self.doc["clients"][0]["token_sha256"] = hashlib.sha256(NATIVE_TOKEN.encode()).hexdigest()
        self.write_config()
        path.rename(path.with_suffix(".missing"))
        self.refuse()
        self.state_dir = self.root
        self.initialize_state = True
        self.refuse()  # State must not be within the granted read root.

    def test_durable_root_replacement_denies_live_and_recovered_access(self):
        self.durable_start()
        _, issued = self.issue()
        access = issued["access_token"]
        session = self.connect(access)
        self.assertIn("native-read-canary",json.dumps(self.read(access,session,"canary.txt")))
        self.root.rename(self.base/"old-workspace")
        self.root.mkdir(mode=0o700)
        (self.root/"canary.txt").write_text("replacement-root-canary")
        status, _, body = self.rpc(access,"tools/call",session,{"name":"read_file","arguments":{"path":"canary.txt"}})
        self.assertIn(status,(401,503))
        self.assertNotIn(b"replacement-root-canary",body)
        self.f.cleanup_server()
        self.refuse()

    def pair_code(self):
        result = subprocess.run([str(BIN),"dashboard","pair","--config",str(self.config)],
            capture_output=True,text=True,timeout=5,env=dict(os.environ,HOME=str(self.base)))
        self.assertEqual(result.returncode,0,result.stderr)
        code=result.stdout.strip().removeprefix("PAIRING_TOKEN=")
        self.assertRegex(code,r"^[a-f0-9]{48}$")
        self.f.sensitive.append(code)
        return code

    def pair_dashboard(self):
        origin=f"http://127.0.0.1:{self.f.admin}"
        code=self.pair_code()
        status,headers,body=self.f.request("POST","/dashboard/api/pair",
            {"pairing_token":code},admin=True,headers=[("Origin",origin)])
        self.assertEqual(status,200,body)
        cookie=headers["set-cookie"].split(";")[0]
        csrf=json.loads(body)["csrf"]
        self.f.sensitive.extend([cookie.split("=",1)[1],csrf])
        return [("Origin",origin),("Cookie",cookie),("X-CSRF-Token",csrf)]

    def consent(self,data,headers,path="/dashboard/api/oauth",method="POST",**kwargs):
        return self.f.request(method,path,data,admin=True,headers=headers,**kwargs)

    def exact(self,action,handle,info):
        return dict(action=action,request=handle,confirm=True,
            **{k:info[k] for k in ("client_id","redirect_uri","resource","local_client")})

    def delivered(self,handle,denied=False):
        status,headers,_=self.f.request("GET","/oauth/authorize?request="+handle)
        self.assertEqual(status,303)
        callback=urllib.parse.urlsplit(headers["location"])
        self.assertEqual(callback.scheme+"://"+callback.netloc+callback.path,preview.CALLBACK)
        fields=urllib.parse.parse_qs(callback.query)
        self.assertEqual(fields["state"],[preview.STATE])
        if denied:
            self.assertEqual(fields,{"error":["access_denied"],"state":[preview.STATE]})
            return
        self.assertEqual(set(fields),{"code","state"})
        code=fields["code"][0]
        self.f.sensitive.append(code)
        return code

    def test_dashboard_exact_consent_and_csrf(self):
        self.durable_start()
        client=self.f.register()
        handle=self.f.pending(client)
        origin=f"http://127.0.0.1:{self.f.admin}"
        self.assertEqual(self.consent({"action":"list"},[("Origin",origin)])[0],401)
        headers=self.pair_dashboard()
        self.assertEqual(self.consent({"action":"list"},headers)[0],200)
        self.assertEqual(self.f.request("POST","/dashboard/api/oauth",{"action":"list"},headers=headers)[0],403)
        self.assertEqual(self.f.request("POST","/dashboard/api/oauth",{"action":"list"})[0],404)
        self.assertEqual(self.consent({"action":"list"},headers[:-1])[0],403)
        self.assertEqual(self.consent({"action":"list"},headers+[headers[-1]])[0],403)
        self.assertEqual(self.consent({"action":"list"},headers+[headers[1]])[0],403)
        self.assertEqual(self.consent({"action":"list"},[headers[0],("Cookie",headers[1][1]+"; "+headers[1][1]),headers[2]])[0],403)
        self.assertEqual(self.consent({"action":"list"},[("Origin",f"http://127.0.0.1:{self.f.public}")]+headers[1:])[0],403)
        self.assertEqual(self.consent({"action":"list"},[("Origin","https://evil.example")]+headers[1:])[0],403)
        self.assertIn(self.consent({"action":"list"},headers+[("Tailscale-Funnel-Request","?1")])[0],(400,403))
        self.assertEqual(self.consent({"action":"list"},headers+[("X-Forwarded-Host","evil.example")])[0],403)
        self.assertEqual(self.consent(b'{"action":"list","action":"revoke"}',headers)[0],400)
        self.assertEqual(self.consent({"action":"list"},headers+[("Content-Type","application/json")])[0],400)
        self.assertEqual(self.consent({"action":"list"},headers,path="/dashboard/api/oauth?x=1")[0],403)
        status,_,body=self.consent({"action":"inspect","request":handle},headers)
        self.assertEqual(status,200,body)
        info=json.loads(body)
        self.assertEqual(info["client_id"],client)
        self.assertEqual(info["redirect_uri"],preview.CALLBACK)
        self.assertEqual(info["resource"],preview.RESOURCE)
        self.assertTrue(info["eligible"])
        approval=self.exact("approve",handle,info)
        for key in ("client_id","redirect_uri","resource","local_client","confirm"):
            wrong=dict(approval)
            wrong[key]="wrong" if key!="confirm" else False
            self.assertEqual(self.consent(wrong,headers)[0],400)
        self.assertEqual(self.consent(approval,headers)[0],200)
        self.assertEqual(self.consent(approval,headers)[0],400)
        tokens=self.f.capture_tokens(self.f.exchange(client,self.delivered(handle)))
        session=self.connect(tokens["access_token"])
        self.assertIn("native-read-canary",json.dumps(self.read(tokens["access_token"],session,"canary.txt")))
        self.assertEqual(self.consent({"action":"revoke","client_id":client,"confirm":False},headers)[0],400)
        self.assertEqual(self.consent({"action":"revoke","client_id":client,"confirm":True},headers)[0],200)
        self.assertEqual(self.rpc(tokens["access_token"],"tools/list",session)[0],401)
        self.assertEqual(self.consent({},headers,path="/dashboard/api/logout")[0],200)
        self.assertEqual(self.consent({"action":"list"},headers)[0],401)
        self.restart()
        self.assertEqual(self.rpc(tokens["access_token"],"initialize",params=INIT)[0],401)

    def test_dashboard_live_policy_denies_approval_but_allows_denial(self):
        self.durable_start()
        client=self.f.register()
        handle=self.f.pending(client)
        headers=self.pair_dashboard()
        info=json.loads(self.consent({"action":"inspect","request":handle},headers)[2])
        self.doc["clients"][0]["token_sha256"]=hashlib.sha256(b"changed").hexdigest()
        self.write_config()
        self.assertEqual(self.consent(self.exact("approve",handle,info),headers)[0],403)
        self.assertFalse(json.loads(self.consent({"action":"inspect","request":handle},headers)[2])["eligible"])
        self.assertEqual(self.consent(self.exact("deny",handle,info),headers)[0],200)
        self.delivered(handle,denied=True)
        self.assertEqual(self.consent({"action":"revoke","client_id":client,"confirm":True},headers)[0],200)

    def cli(self,action,data=None,success=True,listen=None):
        command=[str(BIN.with_name("veyl")),"oauth",action,"--listen",
            listen or f"127.0.0.1:{self.f.admin}","--config",str(self.config)]
        result=subprocess.run(command,input=json.dumps(data) if data is not None else "",
            text=True,capture_output=True,timeout=15,env=dict(os.environ,HOME=str(self.base)))
        for secret in self.f.sensitive:
            self.assertNotIn(secret,result.stdout+result.stderr)
        if success:
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode,0)

    def test_cli_paired_consent_deny_and_revoke(self):
        self.durable_start()
        client=self.f.register()
        handle=self.f.pending(client)
        self.assertEqual(self.cli("list")["registrations"][0]["client_id"],client)
        info=self.cli("inspect",{"request":handle})
        self.assertTrue(info["eligible"])
        data=self.exact("approve",handle,info)
        data.pop("action")
        self.cli("approve",dict(data,redirect_uri=preview.CALLBACK+"/wrong"),success=False)
        self.assertTrue(self.cli("approve",data)["approved"])
        tokens=self.f.capture_tokens(self.f.exchange(client,self.delivered(handle)))
        self.assertIn("native-read-canary",json.dumps(self.read(tokens["access_token"],self.connect(tokens["access_token"]),"canary.txt")))
        handle=self.f.pending(client)
        info=self.cli("inspect",{"request":handle})
        data=self.exact("deny",handle,info)
        data.pop("action")
        self.assertTrue(self.cli("deny",data)["denied"])
        self.delivered(handle,denied=True)
        self.cli("revoke",{"client_id":client},success=False)
        self.assertTrue(self.cli("revoke",{"client_id":client,"confirm":True})["revoked"])
        self.assertEqual(self.rpc(tokens["access_token"],"initialize",params=INIT)[0],401)
        self.cli("list",success=False,listen="192.0.2.1:1234")
        self.assertEqual(self.cli("list")["registrations"],[])

    def test_real_browser_dashboard_consent(self):
        browser=os.environ.get("VEYL_TEST_BROWSER") or shutil.which("brave") or shutil.which("chromium")
        self.assertIsNotNone(browser,"Browser required for explicit OAuth dashboard acceptance")
        self.durable_start()
        registration=self.f.registration()
        registration["client_name"]='<img src=x onerror="alert(1)">'
        status,_,body=self.f.request("POST","/oauth/register",registration)
        self.assertEqual(status,201)
        approve_id=json.loads(body)["client_id"]
        deny_id=self.f.register()
        revoke_id=self.f.register()
        approve=self.f.pending(approve_id)
        deny=self.f.pending(deny_id)
        data=dict(url=f"http://127.0.0.1:{self.f.admin}/dashboard/login#pair={self.pair_code()}",
                  approve=approve,deny=deny,approve_id=approve_id,deny_id=deny_id,revoke_id=revoke_id,
                  callback=preview.CALLBACK,resource=preview.RESOURCE,local=preview.LOCAL)
        result=subprocess.run(["node",str(pathlib.Path(__file__).with_name("oauth_dashboard_browser.mjs")),browser],
            input=json.dumps(data),text=True,capture_output=True,timeout=50)
        self.assertEqual(result.returncode,0,result.stderr[-1000:])
        self.assertIn("OAUTH_DASHBOARD_BROWSER_PASS",result.stdout)
        tokens=self.f.capture_tokens(self.f.exchange(approve_id,self.delivered(approve)))
        self.assertIn("native-read-canary",json.dumps(self.read(tokens["access_token"],self.connect(tokens["access_token"]),"canary.txt")))
        self.delivered(deny,denied=True)
        self.assertEqual(self.f.begin(revoke_id)[0],400)

    def test_consent_is_not_enabled_by_default(self):
        self.start(enabled=False)
        headers=self.pair_dashboard()
        status,_,body=self.f.request("GET","/dashboard/api/status",admin=True,headers=headers)
        self.assertEqual(status,200,body)
        self.assertFalse(json.loads(body)["oauth_preview"])
        self.assertEqual(self.consent({"action":"list"},headers)[0],404)
        self.cli("list",success=False)

    def onboarding_args(self,action,profile,root=None,open_ui=False):
        args=[str(BIN.with_name("veyl")),"oauth",action,"--profile",str(profile)]
        if root is not None:
            args+=["--root",str(root)]
        if open_ui:
            args+=["--open-ui"]
        return args

    def onboarding_refuse(self,action,profile,root=None):
        result=subprocess.run(self.onboarding_args(action,profile,root),input="",text=True,
            capture_output=True,timeout=5,env=dict(os.environ,HOME=str(self.base)))
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn("MCP_HTTP_LISTEN",result.stderr)

    def test_automated_onboarding_and_restart(self):
        profile=self.base/"new-profile"
        old=(preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL)
        def restore():
            preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL=old
        self.addCleanup(restore)
        preview.ORIGIN="https://veyl.example"
        preview.HOST="veyl.example"
        preview.RESOURCE=preview.ORIGIN+"/mcp"
        preview.LOCAL="oauth-preview"
        # Capture the browser opener's argument in disposable private storage.
        # Do not open a real desktop window or print the pairing fragment.
        shim=self.base/"opener"
        shim.mkdir(mode=0o700)
        opener=shim/"xdg-open"
        opener.write_text('#!/bin/sh\numask 077\nprintf "%s" "$1" > "$VEYL_TEST_URL"\n')
        opener.chmod(0o700)
        url_file=self.base/"opener-url"
        env=dict(os.environ,HOME=str(self.base),PATH=str(shim)+os.pathsep+os.environ["PATH"],
                 VEYL_TEST_URL=str(url_file))
        self.launch(self.onboarding_args("setup",profile,self.root,True),env=env)
        self.config=profile/"clients.json"
        config_bytes=self.config.read_bytes()
        cfg=json.loads(config_bytes)
        self.assertEqual(cfg["clients"][0]["id"],preview.LOCAL)
        self.assertEqual(cfg["clients"][0]["tools"],["read_file"])
        self.assertEqual(cfg["clients"][0]["mode"],"standard")
        self.assertEqual(cfg["admin_listen"],"127.0.0.1:0")
        self.assertNotIn("tailscale_serve",cfg)
        self.assertNotIn("job_state_dir",cfg)
        self.assertEqual(len(cfg["clients"]),1)
        state=profile/"oauth/oauth-state.json"
        for directory in (profile,profile/"audit",profile/"oauth"):
            self.assertEqual(directory.stat().st_mode&0o777,0o700)
        for file in (self.config,state):
            self.assertEqual(file.stat().st_mode&0o777,0o600)
        self.assertEqual(list(profile.rglob("*.bearer")),[])
        self.assertNotIn("operator_token",state.read_text())
        self.assertFalse((self.base/".local/state/veyl").exists())
        deadline=time.monotonic()+5
        while not url_file.exists() and time.monotonic()<deadline:
            time.sleep(.05)
        url=url_file.read_text()
        origin=f"http://127.0.0.1:{self.f.admin}"
        self.assertTrue(url.startswith(origin+"/dashboard/login#pair="))
        pairing=url.split("#pair=",1)[1]
        self.assertRegex(pairing,r"^[a-f0-9]{48}$")
        self.f.sensitive.append(pairing)
        code,headers,body=self.f.request("POST","/dashboard/api/pair",{"pairing_token":pairing},
            admin=True,headers=[("Origin",origin)])
        self.assertEqual(code,200,body)
        cookie=headers["set-cookie"].split(";")[0]
        csrf=json.loads(body)["csrf"]
        self.f.sensitive.extend([cookie.split("=",1)[1],csrf])
        headers=[("Origin",origin),("Cookie",cookie),("X-CSRF-Token",csrf)]
        self.assertEqual(self.f.request("GET","/.well-known/oauth-protected-resource/mcp")[0],200)
        client=self.f.register()
        handle=self.f.pending(client)
        self.assertNotEqual(self.f.local("/approve",{"request":handle,"local_client":preview.LOCAL})[0],200)
        status,_,body=self.consent({"action":"inspect","request":handle},headers)
        self.assertEqual(status,200,body)
        info=json.loads(body)
        self.assertEqual(info["local_client"],preview.LOCAL)
        self.assertEqual(self.consent(self.exact("approve",handle,info),headers)[0],200)
        tokens=self.f.capture_tokens(self.f.exchange(client,self.delivered(handle)))
        access=tokens["access_token"]
        session=self.connect(access)
        self.assertIn("native-read-canary",json.dumps(self.read(access,session,"canary.txt")))
        previous=state.read_bytes()
        self.onboarding_refuse("setup",profile,self.root)
        self.onboarding_refuse("run",profile)
        self.assertEqual(state.read_bytes(),previous)
        self.assertEqual(self.config.read_bytes(),config_bytes)
        self.f.cleanup_server()
        self.launch(self.onboarding_args("run",profile))
        self.assertIn("native-read-canary",json.dumps(self.read(access,self.connect(access),"canary.txt")))
        self.assertEqual(self.cli("list")["registrations"][0]["client_id"],client)
        self.assertTrue(self.cli("revoke",{"client_id":client,"confirm":True})["revoked"])
        self.assertEqual(self.rpc(access,"initialize",params=INIT)[0],401)
        self.f.cleanup_server()
        state.rename(state.with_suffix(".missing"))
        self.onboarding_refuse("run",profile)
        self.assertFalse(state.exists())

    def test_onboarding_rejects_unsafe_or_existing_profile(self):
        existing=self.base/"existing"
        existing.mkdir(mode=0o700)
        canary=existing/"keep"
        canary.write_text("untouched")
        self.onboarding_refuse("setup",existing,self.root)
        self.assertEqual(canary.read_text(),"untouched")
        self.onboarding_refuse("setup",self.root/"profile",self.root)
        self.assertFalse((self.root/"profile").exists())
        self.onboarding_refuse("setup",self.base/"profile",self.base)
        self.assertFalse((self.base/"profile").exists())
        alias=self.base/"alias"
        alias.symlink_to(existing)
        self.onboarding_refuse("setup",alias/"profile",self.root)
        self.assertFalse((existing/"profile").exists())
        self.onboarding_refuse("run",self.base/"nonexistent")
        self.assertFalse((self.base/"nonexistent").exists())

    def test_workspace_edit_requires_explicit_profile_and_scope(self):
        profile=self.base/"edit-profile"
        old=(preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL)
        def restore():
            preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL=old
        self.addCleanup(restore)
        preview.ORIGIN="https://veyl.example"
        preview.HOST="veyl.example"
        preview.RESOURCE=preview.ORIGIN+"/mcp"
        preview.LOCAL="oauth-preview"
        self.launch(self.onboarding_args("setup",profile,self.root)+["--workspace-edit"])
        self.config=profile/"clients.json"
        client=self.f.register()
        handle=self.f.pending(client)
        headers=self.pair_dashboard()
        status,_,body=self.consent({"action":"inspect","request":handle},headers)
        self.assertEqual(status,200,body)
        info=json.loads(body)
        self.assertEqual(info["native_scope"],{"mode":"standard","root":str(self.root),
            "tools":["apply_patch","edit_file","read_file","write_file"],"workspace_edit":True})
        approval=self.exact("approve",handle,info)
        self.assertEqual(self.consent(approval,headers)[0],400)
        self.assertEqual(self.consent(dict(approval,scope_fingerprint="0"*64),headers)[0],400)
        approval["scope_fingerprint"]=info["scope_fingerprint"]
        self.assertEqual(self.consent(approval,headers)[0],200)
        tokens=self.f.capture_tokens(self.f.exchange(client,self.delivered(handle)))
        access=tokens["access_token"]
        session=self.connect(access)
        status,_,body=self.rpc(access,"tools/list",session)
        self.assertEqual(status,200)
        self.assertEqual({t["name"] for t in json.loads(body)["result"]["tools"]},
            {"read_file","write_file","apply_patch","edit_file"})
        def call(name,args,success):
            status,_,body=self.rpc(access,"tools/call",session,{"name":name,"arguments":args})
            self.assertEqual(status,200,body)
            result=json.loads(body)["result"]
            self.assertEqual(not result.get("isError",False),success,(name,args,result))
        call("write_file",{"path":"new.txt","content":"before"},True)
        call("apply_patch",{"path":"new.txt","expected_sha256":hashlib.sha256(b"before").hexdigest(),"old":"before","new":"after"},True)
        call("edit_file",{"path":"new.txt","target":"after","replacement":"final"},True)
        self.assertEqual((self.root/"new.txt").read_text(),"final")
        outside=self.base/"outside.txt"
        before=outside.read_bytes()
        os.link(outside,self.root/"hardlink.txt")
        for path in ("../outside.txt",str(outside),"escape.txt","hardlink.txt"):
            call("write_file",{"path":path,"content":"forbidden","overwrite":True},False)
        call("apply_patch",{"path":"hardlink.txt","expected_sha256":hashlib.sha256(before).hexdigest(),
            "old":before.decode(),"new":"forbidden"},False)
        call("edit_file",{"path":"hardlink.txt","target":before.decode(),"replacement":"forbidden"},False)
        self.assertEqual(outside.read_bytes(),before)
        self.assertEqual((self.root/"hardlink.txt").stat().st_ino,outside.stat().st_ino)
        call("create_directory",{"path":"not-created"},False)
        self.assertFalse((self.root/"not-created").exists())
        call("exec_command",{"command":"true"},False)
        self.f.cleanup_server()
        self.onboarding_refuse("run",profile)
        self.launch(self.onboarding_args("run",profile)+["--workspace-edit"])
        session=self.connect(access)
        self.assertIn("final",json.dumps(self.read(access,session,"new.txt")))
        self.assertTrue(self.cli("revoke",{"client_id":client,"confirm":True})["revoked"])
        self.assertEqual(self.rpc(access,"tools/list",session)[0],401)


    def test_extended_workspace_tools_and_bounds(self):
        profile=self.base/"workspace-tools-profile"
        old=(preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL)
        def restore():
            preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL=old
        self.addCleanup(restore)
        preview.ORIGIN="https://veyl.example"
        preview.HOST="veyl.example"
        preview.RESOURCE=preview.ORIGIN+"/mcp"
        preview.LOCAL="oauth-preview"
        self.launch(self.onboarding_args("setup",profile,self.root)+["--workspace-tools"])
        self.config=profile/"clients.json"
        client=self.f.register()
        handle=self.f.pending(client)
        info=self.cli("inspect",{"request":handle})
        expected={"read_file","write_file","apply_patch","edit_file","create_directory",
            "list_directory","directory_tree","file_info","search_files"}
        self.assertEqual(set(info["native_scope"]["tools"]),expected)
        args=self.exact("approve",handle,info)
        args.pop("action")
        self.cli("approve",args,success=False)
        args["scope_fingerprint"]=info["scope_fingerprint"]
        self.assertTrue(self.cli("approve",args)["approved"])
        token=self.f.capture_tokens(self.f.exchange(client,self.delivered(handle)))["access_token"]
        session=self.connect(token)
        status,_,body=self.rpc(token,"tools/list",session)
        self.assertEqual(status,200)
        self.assertEqual({t["name"] for t in json.loads(body)["result"]["tools"]},expected)
        def call(name,args,success=True):
            status,_,body=self.rpc(token,"tools/call",session,{"name":name,"arguments":args})
            self.assertEqual(status,200,body)
            result=json.loads(body)["result"]
            self.assertEqual(not result.get("isError",False),success,(name,args,result))
            return result["content"][0]["text"]
        self.assertIn("directory_created",call("create_directory",{"path":"nested/child"}))
        self.assertIn("directory_created",call("create_directory",{"path":"nested/child"}))
        self.assertTrue((self.root/"nested/child").is_dir())
        call("write_file",{"path":"nested/child/record.txt","content":"unique-workspace-needle"})
        self.assertIn("record.txt",call("list_directory",{"path":"nested/child"}))
        self.assertIn("record.txt",call("directory_tree",{"path":"nested","max_depth":3}))
        info=json.loads(call("file_info",{"path":"nested/child/record.txt"}))
        self.assertEqual(info["sha256"],hashlib.sha256(b"unique-workspace-needle").hexdigest())
        self.assertIn("unique-workspace-needle",call("search_files",{"query":"unique-workspace-needle","content":True}))
        outside=self.base/"outside-dir"
        outside.mkdir()
        (outside/"outside.txt").write_text("outside-search-canary")
        (self.root/"dir-alias").symlink_to(outside,target_is_directory=True)
        os.link(outside/"outside.txt",self.root/"file-alias.txt")
        for path in ("dir-alias","dir-alias/escaped","../outside-dir/escaped",str(outside/"escaped")):
            call("create_directory",{"path":path},False)
        for name in ("list_directory","directory_tree","search_files"):
            args={"path":"dir-alias"}
            if name=="search_files": args["query"]="outside"
            call(name,args,False)
        call("file_info",{"path":"dir-alias/outside.txt"},False)
        self.assertIsNone(json.loads(call("file_info",{"path":"file-alias.txt"}))["sha256"])
        self.assertNotIn("outside-search-canary",call("search_files",{"query":"outside-search-canary","content":True}))
        self.assertFalse((outside/"escaped").exists())
        for i in range(520):
            (self.root/"nested/child"/f"entry-{i:04d}").touch()
        result=json.loads(call("list_directory",{"path":"nested/child","max_items":100000}))
        self.assertLessEqual(result["count"],512)
        self.assertTrue(result["truncated"])
        tree=json.loads(call("directory_tree",{"path":"nested/child"}))
        self.assertTrue(tree["truncated"])
        self.assertLessEqual(len(tree["children"]),512)
        call("exec_command",{"command":"true"},False)
        self.f.cleanup_server()
        result=subprocess.run(self.onboarding_args("run",profile)+["--workspace-edit"],input="",text=True,
            capture_output=True,timeout=5,env=dict(os.environ,HOME=str(self.base)))
        self.assertNotEqual(result.returncode,0)
        self.launch(self.onboarding_args("run",profile)+["--workspace-tools"])
        session=self.connect(token)
        self.assertIn("unique-workspace-needle",json.dumps(self.read(token,session,"nested/child/record.txt")))


if __name__ == "__main__":
    unittest.main()
