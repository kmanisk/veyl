#!/usr/bin/env python3
"""Native OAuth upstream capabilities, exact grants and fresh transport sessions."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import subprocess
import threading
import unittest
import oauth_native as native

preview=native.preview
# Compact inline fixture: no host script or workspace is mounted.
STDIO = """import json,sys,os,socket,pathlib
for line in sys.stdin:
 r=json.loads(line); m=r['method']
 if m=='notifications/initialized':continue
 if m=='initialize':v={'protocolVersion':'2025-11-25','capabilities':{'tools':{}},'serverInfo':{'name':'peer','version':'1'}}
 elif m=='tools/list':v={'tools':[{'name':n,'inputSchema':{'type':'object'}} for n in ('probe','hidden')]}
 else:
  a=r['params']['arguments'];assert not pathlib.Path(a['protected']).exists()
  assert 'NoNewPrivs:\\t1' in pathlib.Path('/proc/self/status').read_text()
  try:
   socket.socket();raise RuntimeError('socket permitted')
  except PermissionError:pass
  assert not any('TOKEN' in k for k in os.environ)
  v={'content':[{'type':'text','text':a['msg']}]}
 print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':v}),flush=True)
"""
# The native argv cap is 512 bytes per argument. Split code into immutable
# configured arguments; the peer never executes remote argument text.
CHUNKS=[STDIO[i:i+400] for i in range(0,len(STDIO),400)]

class OAuthUpstream(native.NativeOAuth):
    def setUp(self):
        super().setUp()
        old=(preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL)
        def restore():
            preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL=old
        self.addCleanup(restore)
        preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL="https://veyl.example","veyl.example","https://veyl.example/mcp","oauth-preview"
        self.profile=self.base/"upstream-profile"
        self.manifest=self.base/"upstreams.json"
        self.seen=[]
        self.sessions=set()
        self.calls=[]
        fixture=self
        class Peer(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def reply(self,status,body=b"",session=None):
                self.send_response(status)
                self.send_header("Content-Length",str(len(body)))
                if body:self.send_header("Content-Type","application/json")
                if session:self.send_header("Mcp-Session-Id",session)
                self.end_headers()
                self.wfile.write(body)
            def do_POST(self):
                if self.path!="/mcp" or self.headers.get("Authorization") is not None:
                    self.reply(401);return
                req=json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                method=req["method"]
                sid=self.headers.get("Mcp-Session-Id")
                if method=="initialize":
                    sid=secrets.token_hex(16)
                    fixture.sessions.add(sid)
                    v={"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"peer","version":"1"}}
                elif sid not in fixture.sessions:
                    self.reply(400);return
                elif method=="notifications/initialized":
                    self.reply(202);return
                elif method=="tools/list":
                    v={"tools":[{"name":n,"inputSchema":{"type":"object"}} for n in ("hello","hidden")]}
                elif method=="tools/call":
                    fixture.calls.append((sid,req["params"]["name"]))
                    v={"content":[{"type":"text","text":req["params"]["arguments"]["msg"]}]}
                else:
                    self.reply(400);return
                fixture.seen.append((method,sid))
                self.reply(200,json.dumps({"jsonrpc":"2.0","id":req["id"],"result":v}).encode(),sid)
            def do_DELETE(self):
                fixture.sessions.discard(self.headers.get("Mcp-Session-Id"))
                self.reply(204)
        self.http=ThreadingHTTPServer(("127.0.0.1",0),Peer)
        thread=threading.Thread(target=self.http.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.addCleanup(self.f.cleanup_server)
        self.defs={"mcp_servers":{
            "stdio":{"transport":"stdio","command":"/usr/bin/python3","args":["-c","import sys;exec(''.join(sys.argv[1:]))",*CHUNKS]},
            "http":{"transport":"http","url":f"http://127.0.0.1:{self.http.server_port}/mcp"}},
            "allowed_server_tools":{"stdio":["probe"],"http":["hello"]}}
        self.write_manifest(self.defs)
    def write_manifest(self,value):
        self.manifest.write_text(json.dumps(value))
        self.manifest.chmod(0o600)
    def setup_args(self):
        return self.onboarding_args("setup",self.profile,self.root)+["--workspace-upstreams","--upstream-manifest",str(self.manifest)]
    def launch_upstreams(self,action="setup"):
        args=self.setup_args() if action=="setup" else self.onboarding_args("run",self.profile)+["--workspace-upstreams"]
        self.launch(args)
        self.config=self.profile/"clients.json"
    def authorize(self,client=None):
        client=client or self.f.register()
        handle=self.f.pending(client)
        info=self.cli("inspect",{"request":handle})
        self.assertTrue(info["eligible"])
        scope=info["native_scope"]
        self.assertTrue(scope["workspace_upstreams"])
        self.assertTrue(scope["upstream_shared_state"])
        self.assertEqual(scope["upstream_providers"]["http"]["url"],self.defs["mcp_servers"]["http"]["url"])
        self.assertEqual(scope["upstream_providers"]["stdio"]["allowed_tools"],["probe"])
        self.assertEqual(scope["upstream_providers"]["stdio"]["args"],self.defs["mcp_servers"]["stdio"]["args"])
        data=self.exact("approve",handle,info);data.pop("action")
        self.cli("approve",data,success=False)
        self.cli("approve",dict(data,scope_fingerprint="0"*64),success=False)
        data["scope_fingerprint"]=info["scope_fingerprint"]
        self.assertTrue(self.cli("approve",data)["approved"])
        return client,self.f.capture_tokens(self.f.exchange(client,self.delivered(handle)))
    def call(self,token,session,name,args,ok=True):
        status,_,body=self.rpc(token,"tools/call",session,{"name":name,"arguments":args})
        self.assertEqual(status,200,body)
        result=json.loads(body)["result"]
        self.assertEqual(not result.get("isError",False),ok,(name,result))
        return result["content"][0]["text"]
    def test_upstreams_real_discovery_and_invocation(self):
        self.launch_upstreams()
        client,a=self.authorize()
        _,b=self.authorize(client)
        at,bt=a["access_token"],b["access_token"]
        sa,sb=self.connect(at),self.connect(bt)
        status,_,body=self.rpc(at,"tools/list",sa)
        self.assertEqual(status,200,body)
        names={t["name"] for t in json.loads(body)["result"]["tools"]}
        self.assertEqual(names,{"read_file","mcp_servers_list","mcp_servers_call","stdio__probe","http__hello"})
        self.assertEqual(self.call(at,sa,"stdio__probe",{"protected":str(self.config),"msg":"stdio-canary"}),"stdio-canary")
        self.assertEqual(self.call(at,sa,"http__hello",{"msg":"http-canary"}),"http-canary")
        self.assertEqual(self.call(bt,sb,"mcp_servers_call",{"name":"http__hello","arguments":{"msg":"other-canary"}}),"other-canary")
        self.assertEqual(len(self.calls),2)
        self.assertNotEqual(self.calls[0][0],self.calls[1][0])
        self.assertFalse(self.sessions)
        for denied in ("http__hidden","stdio__hidden","hello","unknown__hello","exec_command"):
            self.call(at,sa,denied,{},False)
        self.call(at,sa,"mcp_servers_call",{"name":"http__hidden","arguments":{}},False)
        self.assertEqual(len(self.calls),2)
        self.assertEqual(self.rpc(bt,"tools/list",sa)[0],403)
        renewed=self.f.capture_tokens(self.f.refresh(client,a["refresh_token"]))
        at=renewed["access_token"]
        self.f.cleanup_server()
        self.launch_upstreams("run")
        sa=self.connect(at)
        self.assertEqual(self.call(at,sa,"http__hello",{"msg":"restart-canary"}),"restart-canary")
        self.assertTrue(self.cli("revoke",{"client_id":client,"confirm":True})["revoked"])
        self.assertEqual(self.rpc(at,"tools/list",sa)[0],401)
        log=(self.profile/"audit/events.jsonl").read_text()
        self.assertIn("http__hello",log)
        self.assertIn("stdio__probe",log)
        self.assertGreaterEqual(len(set(__import__("re").findall(r"oauth-job-v1-[0-9a-f]{64}",log))),2)
        for secret in (at,bt,"stdio-canary","restart-canary","other-canary","http-canary"):
            self.assertNotIn(secret,log)
    def test_upstream_manifest_refuses_widening_and_restart_without_opt_in(self):
        for extra in (["--funnel"],):
            r=subprocess.run(self.setup_args()+extra,capture_output=True,text=True,timeout=5,env=dict(os.environ,HOME=str(self.base)))
            self.assertNotEqual(r.returncode,0)
            self.assertFalse(self.profile.exists())
        variants=[]
        for field,value in [("use_token",True),("private_ca",True),("url","https://127.0.0.1:443/mcp"),("enabled",False)]:
            v=copy.deepcopy(self.defs);v["mcp_servers"]["http"][field]=value;variants.append(v)
        v=copy.deepcopy(self.defs);v["allowed_server_tools"].pop("http");variants.append(v)
        v=copy.deepcopy(self.defs);v["allowed_server_tools"]["http"]=[];variants.append(v)
        v=copy.deepcopy(self.defs);v["mcp_servers"]["stdio"]["runtime_bundle"]=True;variants.append(v)
        v=copy.deepcopy(self.defs);v["mcp_servers"]["stdio"]["args"]=[str(self.root/"mut.py")];variants.append(v)
        v=copy.deepcopy(self.defs);v["upstream_workspace_roots"]={"stdio":str(self.root)};variants.append(v)
        for v in variants:
            self.write_manifest(v)
            r=subprocess.run(self.setup_args(),capture_output=True,text=True,timeout=5,env=dict(os.environ,HOME=str(self.base)))
            self.assertNotEqual(r.returncode,0,v)
            self.assertFalse(self.profile.exists())
        self.manifest.write_text('{"mcp_servers":{},"mcp_servers":{},"allowed_server_tools":{}}')
        r=subprocess.run(self.setup_args(),capture_output=True,text=True,timeout=5,env=dict(os.environ,HOME=str(self.base)))
        self.assertNotEqual(r.returncode,0)
        self.assertFalse(self.profile.exists())
        self.write_manifest(self.defs)
        self.launch_upstreams()
        self.f.cleanup_server()
        r=subprocess.run(self.onboarding_args("run",self.profile),capture_output=True,text=True,timeout=5,env=dict(os.environ,HOME=str(self.base)))
        self.assertNotEqual(r.returncode,0)
    def test_upstream_live_policy_change_blocks_old_grants(self):
        self.launch_upstreams()
        _,issued=self.authorize()
        token=issued["access_token"]
        session=self.connect(token)
        self.assertEqual(self.call(token,session,"http__hello",{"msg":"before"}),"before")
        doc=json.loads(self.config.read_text())
        doc["clients"][0]["allowed_server_tools"]["http"].append("hidden")
        changed=self.config.with_suffix(".new")
        changed.write_text(json.dumps(doc));changed.chmod(0o600);changed.replace(self.config)
        self.assertEqual(self.rpc(token,"tools/list",session)[0],401)
        self.assertEqual(len(self.calls),1)
        self.f.cleanup_server()
        r=subprocess.run(self.onboarding_args("run",self.profile)+["--workspace-upstreams"],capture_output=True,text=True,timeout=5,env=dict(os.environ,HOME=str(self.base)))
        self.assertNotEqual(r.returncode,0)
if __name__=="__main__":
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(OAuthUpstream) if n.startswith("test_upstream")]
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(OAuthUpstream(n) for n in names)).wasSuccessful())
