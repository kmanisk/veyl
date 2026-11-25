#!/usr/bin/env python3
"""Local regression for per-client upstream workspace projection."""
import json
import os
from pathlib import Path
import subprocess
import unittest

import product_features as pf

PEER = r"""
import json, pathlib, sys, os, time
for line in sys.stdin:
    req = json.loads(line)
    if "id" not in req:
        continue
    method = req["method"]
    if method == "initialize":
        result = {"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"workspace-fixture","version":"1"}}
    elif method == "tools/list":
        result = {"tools":[{"name":n,"inputSchema":{"type":"object"}} for n in ("analyze","inspect_python_pyc","inspect_rust_binary")]}
    elif method == "tools/call":
        args = req["params"]["arguments"]
        time.sleep(args.get("delay",0))
        p = pathlib.Path(args.get("path", args.get("root", "/not-provided")))
        answer = {"path":str(p), "visible":p.exists(),"workspace":pathlib.Path("/workspace").exists()}
        if p.is_dir():
            answer["files"] = sorted(str(q.relative_to(p)) for q in p.rglob("*") if q.is_file())
            sample = p/"sample.txt"
        else:
            sample = p
        if sample.is_file():
            answer["content"] = sample.read_text()
            try:
                sample.write_text("modified")
                answer["readonly"] = False
            except OSError:
                answer["readonly"] = True
        answer["outside_visible"] = pathlib.Path(args.get("outside", "/no-file")).exists()
        answer["net_namespace"] = os.readlink("/proc/self/ns/net")
        result = {"content":[{"type":"text","text":json.dumps(answer)}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc":"2.0","id":req["id"],"result":result}),flush=True)
"""

class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.f = f = pf.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.scope = f.workspace/"project"
        self.scope.mkdir()
        self.sample = self.scope/"sample.txt"
        self.sample.write_text("original")
        (self.scope/".hidden").write_text("hidden")
        self.outside = f.base/"outside.txt"
        self.outside.write_text("outside")
        (self.scope/"symlink.txt").symlink_to(self.outside)
        (f.workspace/"other.txt").write_text("other project")
        parent = f.base/"upstream-bundles"
        parent.mkdir(mode=0o700)
        f.doc["mcp_servers"] = {}
        for name in ("rea","rust-anything"):
            bundle = parent/name
            bundle.mkdir(mode=0o700)
            script = bundle/"server.py"
            script.write_text(PEER)
            script.chmod(0o600)
            f.doc["mcp_servers"][name] = {"transport":"stdio","command":"/usr/bin/python3","args":["/upstream/bundle/server.py"],"runtime_bundle":True}
        for c in f.doc["clients"]:
            c["allowed_servers"] = ["rea","rust-anything"]
            c["allowed_server_tools"] = {"rea":["inspect_python_pyc","inspect_rust_binary"],"rust-anything":["analyze"]}
        f.doc["clients"][0]["upstream_workspace_roots"] = {"rea":str(self.scope),"rust-anything":str(self.scope)}
        f.write_config()
        f.start()
        self.session = f.connect()
        self.other = f.connect(token=pf.OTHER_TOKEN)

    def call(self, tool, args, *, other=False):
        return self.f.call(tool,args,self.other if other else self.session,token=pf.OTHER_TOKEN if other else pf.TOKEN)

    def answer(self, tool, args, *, other=False):
        r = self.call(tool,args,other=other)
        self.assertFalse(r.get("isError",False),r)
        return json.loads(r["content"][0]["text"])

    def test_file_projection_and_client_isolation(self):
        args = {"path":str(self.sample),"outside":str(self.outside)}
        r = self.answer("rea__inspect_python_pyc",args)
        self.assertEqual(r["path"],"/workspace/sample.txt")
        self.assertEqual(r["content"],"original")
        self.assertTrue(r["readonly"])
        self.assertFalse(r["outside_visible"])
        self.assertEqual(self.sample.read_text(),"original")
        r = self.answer("rea__inspect_python_pyc",args,other=True)
        self.assertFalse(r["visible"])
        self.assertFalse(r["workspace"])
        r = self.answer("rea__inspect_rust_binary",{"path":"/workspace/sample.txt"})
        self.assertEqual(r["content"],"original")

    def test_tree_and_escape_denials(self):
        r = self.answer("rust-anything__analyze",{"root":str(self.scope)})
        self.assertEqual(r["path"],"/workspace")
        self.assertEqual(r["files"],["sample.txt"])
        self.assertTrue(r["readonly"])
        for path in (str(self.outside), str(self.f.workspace/"other.txt"),
                     "../outside.txt", ".hidden", "symlink.txt"):
            self.assertTrue(self.call("rea__inspect_python_pyc",{"path":path})["isError"],path)
        hard = self.scope/"hard.txt"
        os.link(self.outside,hard)
        self.assertTrue(self.call("rea__inspect_python_pyc",{"path":"hard.txt"})["isError"])
        self.assertTrue(self.call("rust-anything__analyze",{"root":"."})["isError"])
        self.assertEqual(self.outside.read_text(),"outside")

    def test_scoped_timeout_budget(self):
        args = {"path":str(self.sample),"delay":4.5}
        self.assertEqual(self.answer("rea__inspect_python_pyc",args)["content"],"original")
        self.assertTrue(self.call("rea__inspect_python_pyc",args,other=True)["isError"])

    def test_operator_revoke_and_regrant(self):
        self.f.cli("mcp-servers","unworkspace","primary","rea")
        r = self.answer("rea__inspect_python_pyc",{"path":str(self.sample)})
        self.assertFalse(r["workspace"])
        self.assertFalse(r["visible"])
        self.f.cli("mcp-servers","workspace","primary","rea",str(self.scope))
        self.assertEqual(self.answer("rea__inspect_python_pyc",{"path":str(self.sample)})["content"],"original")
        result = subprocess.run([pf.BIN,"mcp-servers","workspace","primary","rea",str(self.f.base),"--config",self.f.config],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.answer("rea__inspect_python_pyc",{"path":str(self.sample)})["content"],"original")

if __name__ == "__main__":
    unittest.main()
