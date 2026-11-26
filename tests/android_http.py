#!/usr/bin/env python3
"""Native Android HTTP acceptance. Uses disposable private state, no public route."""
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
import unittest

BIN=Path(sys.argv.pop(1)).resolve()
ALL="platform_info,read_file,list_directory,file_info"

class NativeHttp(unittest.TestCase):
    def setUp(self):
        self.name="veyl-android-test-"+secrets.token_hex(8)
        self.root=Path.home()/self.name
        self.addCleanup(self.cleanup)
        self.cli("android-init",self.name)
        self.a=json.loads(self.cli("android-add-client",self.name,"a",ALL))["token"]
        self.b=json.loads(self.cli("android-add-client",self.name,"b","platform_info,list_directory"))["token"]
        (self.root/"workspaces/a/hello.txt").write_text("private a")
        (self.root/"workspaces/b/hello.txt").write_text("private b")
        self.assertEqual((self.root/"clients/a.json").stat().st_mode & 0o777,0o600)
        self.assertNotIn(self.a,(self.root/"clients/a.json").read_text())
        self.start()

    def cli(self,*args):
        p=subprocess.run([str(BIN),*args],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        return p.stdout

    def start(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1",0))
            self.port=s.getsockname()[1]
        self.process=subprocess.Popen([str(BIN),"android-serve",self.name,str(self.port)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(100):
            if self.process.poll() is not None:
                self.fail(self.process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1",self.port),timeout=.1): pass
                return
            except OSError: time.sleep(.05)
        self.fail("server startup timed out")

    def stop(self):
        p=getattr(self,"process",None)
        if p is not None:
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            p.stderr.close()
            self.process=None

    def cleanup(self):
        self.stop()
        if self.root.is_dir() and not self.root.is_symlink(): shutil.rmtree(self.root)

    def request(self,token,body=None,session=None,method="POST",headers=None,path="/mcp"):
        h={"Content-Type":"application/json","Accept":"application/json, text/event-stream"}
        if token is not None:h["Authorization"]="Bearer "+token
        if session is not None:h["Mcp-Session-Id"]=session
        if headers:h.update(headers)
        conn=http.client.HTTPConnection("127.0.0.1",self.port,timeout=5)
        try:
            conn.request(method,path,body=json.dumps(body) if body is not None else None,headers=h)
            r=conn.getresponse()
            raw=r.read()
            return r.status,r.getheader("Mcp-Session-Id"),json.loads(raw) if raw else None
        finally:conn.close()

    def msg(self,method,params=None,id=1):
        r={"jsonrpc":"2.0","method":method}
        if id is not None:r["id"]=id
        if params is not None:r["params"]=params
        return r

    def initialize(self,token):
        r=self.request(token,self.msg("initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"native-test","version":"1"}}))
        self.assertEqual(r[0],200,r)
        self.assertEqual(r[2]["result"]["protocolVersion"],"2025-11-25")
        self.assertEqual(len(r[1]),64)
        session=r[1]
        self.assertEqual(self.request(token,self.msg("tools/list"),session)[2]["error"]["code"],-32000)
        self.assertEqual(self.request(token,self.msg("notifications/initialized",id=None),session)[0],202)
        return session

    def call(self,token,session,name,args):
        r=self.request(token,self.msg("tools/call",{"name":name,"arguments":args}),session)
        self.assertEqual(r[0],200,r)
        return r[2]

    def test_authentication_and_transport_bounds(self):
        self.assertEqual(self.request(None,self.msg("tools/list"))[0],401)
        self.assertEqual(self.request("0"*64,self.msg("tools/list"))[0],401)
        self.assertEqual(self.request(self.a,self.msg("tools/list"),headers={"Host":"evil.invalid"})[0],403)
        self.assertEqual(self.request(self.a,self.msg("tools/list"),headers={"Origin":"https://evil.invalid"})[0],403)
        self.assertEqual(self.request(self.a,self.msg("tools/list"),path="/mcp?token=bad")[0],404)
        self.assertEqual(self.request(self.a,self.msg("tools/list"))[0],400)
        self.assertEqual(self.request(self.a,{"oversize":"x"*70000})[0],413)
        self.assertEqual(self.request(self.a,method="GET")[0],405)
        self.assertEqual(self.request(self.a,self.msg("tools/list"),headers={"Content-Type":"text/plain"})[0],415)
        self.assertEqual(self.request(self.a,self.msg("tools/list"),headers={"Mcp-Protocol-Version":"wrong"})[0],400)
        s=self.initialize(self.a)
        self.assertEqual(self.request(self.a,session=s,method="DELETE")[0],204)
        self.assertEqual(self.request(self.a,self.msg("tools/list"),s)[0],404)

    def test_per_client_tools_roots_and_sessions(self):
        a=self.initialize(self.a)
        b=self.initialize(self.b)
        names=lambda token,s:{t["name"] for t in self.request(token,self.msg("tools/list"),s)[2]["result"]["tools"]}
        self.assertEqual(names(self.a,a),set(ALL.split(",")))
        self.assertEqual(names(self.b,b),{"platform_info","list_directory"})
        self.assertEqual(self.request(self.b,self.msg("tools/list"),a)[0],404)
        self.assertEqual(self.request(self.b,session=a,method="DELETE")[0],404)
        self.assertEqual(self.call(self.a,a,"read_file",{"path":"hello.txt"})["result"]["content"][0]["text"],"private a")
        self.assertEqual(self.call(self.b,b,"read_file",{"path":"hello.txt"})["error"]["code"],-32602)
        for name in ("exec_command","write_file","rewind","android-add-client"):
            self.assertEqual(self.call(self.a,a,name,{})["error"]["code"],-32602)
        for path in ("../b/hello.txt","../../clients/a.json",str(self.root/"clients/a.json")):
            self.assertTrue(self.call(self.a,a,"read_file",{"path":path})["result"]["isError"])
        link=self.root/"workspaces/a/escape"
        link.symlink_to(self.root/"clients/a.json")
        self.assertTrue(self.call(self.a,a,"read_file",{"path":"escape"})["result"]["isError"])
        # Android Python may omit os.link; Termux coreutils creates the real inode alias.
        subprocess.run(["ln",str(self.root/"clients/a.json"),str(self.root/"workspaces/a/hard")],check=True,capture_output=True)
        self.assertEqual((self.root/"workspaces/a/hard").stat().st_nlink,2)
        self.assertTrue(self.call(self.a,a,"read_file",{"path":"hard"})["result"]["isError"])

    def test_audited_mutation_and_fail_closed(self):
        import hashlib
        h=lambda text:hashlib.sha256(text.encode()).hexdigest()
        self.stop()
        self.c=json.loads(self.cli("android-add-client",self.name,"c",ALL+",write_file,apply_patch"))["token"]
        self.start()
        c=self.initialize(self.c)
        a=self.initialize(self.a)
        directory=self.root/"workspaces/c"
        journal=self.root/"audit/c"
        self.assertEqual(self.call(self.a,a,"write_file",{})["error"]["code"],-32602)
        def write(path,content,expected):
            return self.call(self.c,c,"write_file",{"path":path,"content":content,"expected_sha256":expected})["result"]
        def patch(path,old,new,expected):
            return self.call(self.c,c,"apply_patch",{"path":path,"old":old,"new":new,"expected_sha256":expected})["result"]
        self.assertFalse(write("new.txt","alpha",None)["isError"])
        self.assertEqual((directory/"new.txt").read_text(),"alpha")
        self.assertTrue(write("new.txt","overwrite",None)["isError"])
        self.assertFalse(patch("new.txt","alpha","beta",h("alpha"))["isError"])
        self.assertTrue(write("new.txt","wrong",h("alpha"))["isError"])
        self.assertFalse(write("new.txt","gamma",h("beta"))["isError"])
        self.assertEqual((directory/"new.txt").read_text(),"gamma")
        for path in ("../a/hello.txt","../../clients/a.json","/sdcard/example",".hidden"):
            self.assertTrue(write(path,"denied",None)["isError"])
        (directory/"escape").symlink_to(self.root/"clients/a.json")
        self.assertTrue(write("escape","denied",None)["isError"])
        self.assertTrue(write("escape","denied",h("gamma"))["isError"])
        subprocess.run(["ln",str(directory/"new.txt"),str(directory/"hard")],check=True)
        self.assertTrue(write("hard","denied",h("gamma"))["isError"])
        (directory/"hard").unlink()
        self.assertEqual((directory/"new.txt").read_text(),"gamma")
        self.assertEqual((self.root/"workspaces/a/hello.txt").read_text(),"private a")
        records=list(journal.iterdir())
        self.assertGreaterEqual(len(records),20)
        self.assertEqual(len(records)%2,0)
        for record in records:
            self.assertEqual(record.stat().st_mode & 0o777,0o600)
            data=json.loads(record.read_text())
            self.assertEqual(data["client"],"c")
            self.assertNotIn(self.c,record.read_text())
            self.assertNotIn('"gamma"',record.read_text())
        self.assertTrue(any(json.loads(r.read_text()).get("status")=="success" for r in records))
        self.stop()
        self.start()
        c=self.initialize(self.c)
        self.assertFalse(write("after-restart.txt","durable",None)["isError"])
        # Simulate interrupted durable mutation without deleting a real record.
        orphan=journal/("f"*64+".intent")
        orphan.write_text(json.dumps({"id":"f"*64,"client":"c","phase":"intent"}))
        orphan.chmod(0o600)
        self.assertTrue(write("blocked.txt","blocked",None)["isError"])
        self.assertFalse((directory/"blocked.txt").exists())
        # A competing server must not be able to admit mutations on this state.
        p=subprocess.run([str(BIN),"android-serve",self.name,"7449"],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(p.returncode,0)

    def test_restart_and_local_revocation(self):
        s=self.initialize(self.a)
        self.stop()
        self.start()
        self.assertEqual(self.request(self.a,self.msg("tools/list"),s)[0],404)
        self.initialize(self.a)
        self.stop()
        path=self.root/"clients/a.json"
        doc=json.loads(path.read_text())
        doc["enabled"]=False
        path.write_text(json.dumps(doc))
        self.start()
        self.assertEqual(self.request(self.a,self.msg("tools/list"))[0],401)
        self.initialize(self.b)
        self.stop()
        doc["enabled"]=True
        doc["tools"]=["platform_info"]
        path.write_text(json.dumps(doc))
        self.start()
        a=self.initialize(self.a)
        self.assertEqual(self.call(self.a,a,"read_file",{"path":"hello.txt"})["error"]["code"],-32602)

    def test_corrupt_or_unsafe_policy_fails_closed(self):
        self.stop()
        path=self.root/"clients/a.json"
        original=path.read_text()
        for content,mode in ((original,0o644),("{}",0o600)):
            path.write_text(content)
            path.chmod(mode)
            p=subprocess.run([str(BIN),"android-serve",self.name,str(self.port)],capture_output=True,text=True,timeout=5)
            self.assertNotEqual(p.returncode,0)
            self.assertNotIn(self.a,p.stderr)
        path.write_text(original)
        path.chmod(0o600)
        path.rename(path.with_suffix(".bak"))
        path.symlink_to(path.with_suffix(".bak"))
        p=subprocess.run([str(BIN),"android-serve",self.name,str(self.port)],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(p.returncode,0)

if __name__=="__main__":
    unittest.main()
