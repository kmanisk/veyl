#!/usr/bin/env python3
"""Disposable loopback-only connector test; no production credentials or devices."""
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import subprocess
import sys
import unittest

BIN=Path(sys.argv.pop(1)).resolve()
class Connector(unittest.TestCase):
    def setUp(self):
        self.a,self.b,self.x,self.y=[secrets.token_hex(32) for _ in range(4)]
        h=lambda v:hashlib.sha256(v.encode()).hexdigest()
        config={"users":[{"id":"a","token_sha256":h(self.a)},{"id":"b","token_sha256":h(self.b)}],"devices":[{"id":"linux","owner":"a","token_sha256":h(self.x)},{"id":"android","owner":"b","token_sha256":h(self.y)}]}
        self.p=subprocess.Popen([str(BIN),"preview","0"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(self.stop)
        self.p.stdin.write(json.dumps(config))
        self.p.stdin.close()
        line=self.p.stdout.readline()
        self.assertTrue(line.startswith("CONNECTOR_PREVIEW 127.0.0.1:"),line)
        self.port=int(line.rsplit(":",1)[1])
    def stop(self):
        self.p.terminate()
        try:self.p.wait(timeout=3)
        except subprocess.TimeoutExpired:self.p.kill();self.p.wait()
        self.p.stdout.close();self.p.stderr.close()
    def req(self,token,msg,route="/mcp",session=None,headers=None,method="POST"):
        h={"Authorization":"Bearer "+token,"Content-Type":"application/json","Accept":"application/json, text/event-stream"}
        if session:h["Mcp-Session-Id"]=session
        if headers:h.update(headers)
        c=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        try:
            c.request(method,route,body=json.dumps(msg),headers=h)
            r=c.getresponse();raw=r.read()
            return r.status,r.getheader("Mcp-Session-Id"),json.loads(raw) if raw else None
        finally:c.close()
    def init(self,token):
        status,s,_=self.req(token,{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}})
        self.assertEqual(status,200)
        self.assertEqual(self.req(token,{"jsonrpc":"2.0","method":"notifications/initialized"},session=s)[0],202)
        return s
    def tool(self,token,s,name,args):
        r=self.req(token,{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":args}},session=s)
        self.assertEqual(r[0],200)
        return r[2]
    def beat(self,token,seq=1,os="linux",version="0.4.0-beta",api=1):
        return self.req(token,{"api_version":api,"sequence":seq,"os":os,"runtime_version":version},"/device/heartbeat")[0]
    def test_owner_isolation_and_upgrade(self):
        a=self.init(self.a);b=self.init(self.b)
        def view(token,s):
            return json.loads(self.tool(token,s,"list_devices",{})["result"]["content"][0]["text"])["devices"]
        catalog=lambda token,s:self.req(token,{"jsonrpc":"2.0","id":2,"method":"tools/list"},session=s)[2]["result"]["tools"]
        original_catalog=catalog(self.a,a)
        self.assertEqual({t["name"] for t in original_catalog},{"list_devices","device_health"})
        self.assertFalse(view(self.a,a)[0]["online"])
        self.assertIsNone(view(self.a,a)[0]["runtime_version"])
        self.assertEqual(self.beat(self.x),200)
        self.assertEqual(self.beat(self.y,os="android"),200)
        self.assertEqual([d["device_id"] for d in view(self.a,a)],["linux"])
        self.assertEqual([d["device_id"] for d in view(self.b,b)],["android"])
        self.assertTrue(view(self.a,a)[0]["online"])
        self.assertEqual(self.tool(self.a,a,"device_health",{"device_id":"android"})["error"]["code"],-32602)
        self.assertEqual(self.req(self.b,{"jsonrpc":"2.0","id":3,"method":"tools/list"},session=a)[0],404)
        self.assertEqual(self.beat(self.x,2,version="0.5.0"),200)
        self.assertEqual(view(self.a,a)[0]["runtime_version"],"0.5.0")
        self.assertEqual(catalog(self.a,a),original_catalog)
        self.assertEqual(self.beat(self.x,2),409)
        self.assertEqual(self.beat(self.x,3,api=2),400)
        self.assertEqual(self.tool(self.a,a,"exec_command",{})["error"]["code"],-32602)
    def test_transport_and_role_separation(self):
        self.assertEqual(self.beat(self.a),401)
        self.assertEqual(self.req(self.x,{"jsonrpc":"2.0","id":1,"method":"initialize"})[0],401)
        self.assertEqual(self.req(self.a,{},headers={"Host":"evil.invalid"})[0],403)
        self.assertEqual(self.req(self.a,{},headers={"Origin":"https://evil.invalid"})[0],403)
        self.assertEqual(self.req(self.a,{"data":"x"*17000})[0],413)
        self.assertEqual(self.req("0"*64,{})[0],401)
        a=self.init(self.a)
        self.assertEqual(self.req(self.b,{},session=a,method="DELETE")[0],404)
        self.assertEqual(self.req(self.a,{},session=a,method="DELETE")[0],204)
        self.assertEqual(self.req(self.a,{"jsonrpc":"2.0","id":1,"method":"tools/list"},session=a)[0],404)
if __name__=="__main__":unittest.main()
