#!/usr/bin/env python3
"""Disposable Linux integration probes. This file is not an AGY acceptance oracle."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import ssl
import copy
import json
import os
from pathlib import Path
import pty
import select
import socketserver
import subprocess
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
            self.reply(200,{"BackendState":"Running","Self":{"DNSName":TAIL["hostname"]+"."},"CertDomains":[TAIL["hostname"]]})
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

    def test_monitor_pairing_views_and_keyboard(self):
        self.start()
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
            sent=False
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
                if b"Veyl / health" in result and not sent:
                    os.write(terminal,b"2\nq\n")
                    sent=True
            self.assertIn(b"Veyl / clients",result)
            self.assertIn(b'"primary"',result)
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
