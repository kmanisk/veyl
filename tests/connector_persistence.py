#!/usr/bin/env python3
"""Disposable real Linux connector and native device client tests."""
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import tomllib
import unittest

BIN=Path(sys.argv.pop(1)).resolve()
VERSION=tomllib.loads((Path(__file__).resolve().parents[1]/"Cargo.toml").read_text())["package"]["version"]
def digest(t):return hashlib.sha256(t.encode()).hexdigest()
class Persistent(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="veyl-connector-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.a,self.b,self.x,self.y=[secrets.token_hex(32) for _ in range(4)]
        self.config={"users":[{"id":"a","token_sha256":digest(self.a)},{"id":"b","token_sha256":digest(self.b)}],"devices":[]}
        self.p=None
        self.addCleanup(self.stop)
        self.cli("state-init",str(self.root),data=self.config)
        self.cli("state-pair",str(self.root),data={"id":"linux","owner":"a","token_sha256":digest(self.x)})
        self.cli("state-pair",str(self.root),data={"id":"android","owner":"b","token_sha256":digest(self.y)})
        self.assertEqual((self.root/"registry.json").stat().st_mode & 0o777,0o600)
    def cli(self,*args,data=None,ok=True):
        p=subprocess.run([str(BIN),*args],input=json.dumps(data) if data is not None else "",capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode==0,ok,p.stderr)
        return p
    def start(self):
        self.p=subprocess.Popen([str(BIN),"serve","0",str(self.root)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        line=self.p.stdout.readline()
        self.assertTrue(line.startswith("CONNECTOR_PREVIEW 127.0.0.1:"),line)
        self.port=int(line.rsplit(":",1)[1])
    def stop(self):
        if self.p is None:return
        if self.p.poll() is None:
            self.p.terminate()
            try:self.p.wait(timeout=3)
            except subprocess.TimeoutExpired:self.p.kill();self.p.wait()
        self.p.stdout.close();self.p.stderr.close();self.p=None
    def req(self,token,msg,route="/mcp",session=None):
        h={"Authorization":"Bearer "+token,"Content-Type":"application/json","Accept":"application/json,text/event-stream"}
        if session:h["Mcp-Session-Id"]=session
        c=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        try:
            c.request("POST",route,body=json.dumps(msg),headers=h)
            r=c.getresponse();raw=r.read()
            return r.status,r.getheader("Mcp-Session-Id"),json.loads(raw) if raw else None
        finally:c.close()
    def init(self,token):
        status,s,_=self.req(token,{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}})
        self.assertEqual(status,200)
        self.assertEqual(self.req(token,{"jsonrpc":"2.0","method":"notifications/initialized"},session=s)[0],202)
        return s
    def devices(self,token,session):
        status,_,r=self.req(token,{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_devices","arguments":{}}},session=session)
        self.assertEqual(status,200)
        return json.loads(r["result"]["content"][0]["text"])["devices"]
    def native(self,token,ok=True):
        p=subprocess.run([str(BIN),"heartbeat",str(self.port)],input=token+"\n",capture_output=True,text=True,timeout=12)
        self.assertEqual(p.returncode==0,ok,p.stderr)
        self.assertNotIn(token,p.stdout+p.stderr)
        return json.loads(p.stdout) if ok else None
    def test_native_reconnect_and_revocation(self):
        self.start()
        s=self.init(self.a)
        self.assertFalse(self.devices(self.a,s)[0]["online"])
        self.assertEqual(self.native(self.x)["sequence"],1)
        self.assertEqual(self.native(self.x)["os"],"linux")
        self.assertTrue(self.devices(self.a,s)[0]["online"])
        self.native(self.a,False)
        self.cli("state-revoke",str(self.root),"linux",ok=False)
        self.stop()
        self.start()
        s=self.init(self.a)
        self.assertFalse(self.devices(self.a,s)[0]["online"])
        self.assertEqual(self.req(self.x,{"api_version":1,"sequence":2,"os":"linux","runtime_version":"0.4.0-beta"},"/device/heartbeat")[0],409)
        self.assertEqual(self.native(self.x)["sequence"],3)
        self.assertEqual(self.devices(self.a,s)[0]["runtime_version"],VERSION)
        self.stop()
        self.cli("state-revoke",str(self.root),"linux")
        self.start()
        self.native(self.x,False)
        self.assertEqual(self.devices(self.a,self.init(self.a)),[])
        self.assertEqual(self.native(self.y)["sequence"],1)
        self.assertEqual([d["device_id"] for d in self.devices(self.b,self.init(self.b))],["android"])
    def test_registry_fails_closed(self):
        path=self.root/"registry.json"
        self.cli("state-init",str(self.root),data=self.config,ok=False)
        self.cli("state-pair",str(self.root),data={"id":"other","owner":"b","token_sha256":digest(self.x)},ok=False)
        self.cli("state-pair",str(self.root),data={"id":"other","owner":"unknown","token_sha256":digest(secrets.token_hex(32))},ok=False)
        original=path.read_text()
        self.assertNotIn(self.x,original)
        self.assertNotIn(self.y,original)
        path.chmod(0o644)
        self.cli("serve","0",str(self.root),ok=False)
        path.chmod(0o600)
        path.rename(self.root/"backup.json")
        path.symlink_to(self.root/"backup.json")
        self.cli("serve","0",str(self.root),ok=False)
        path.unlink()
        (self.root/"backup.json").rename(path)
        path.write_text("{broken")
        self.cli("serve","0",str(self.root),ok=False)
if __name__=="__main__":unittest.main()
