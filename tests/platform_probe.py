#!/usr/bin/env python3
"""Native platform bootstrap smoke test; Python 3 standard library only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BIN = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path(os.environ["MCP_GATEWAY_BIN"]).resolve()

def run(*args, input=None):
    return subprocess.run([str(BIN), *map(str,args)], input=input, text=True,
                          capture_output=True, timeout=10)

def rpc(*args):
    requests = [
        {"jsonrpc":"2.0","id":0,"method":"tools/list"},
        {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"native-platform-probe","version":"1"},"capabilities":{}}},
        {"jsonrpc":"2.0","method":"notifications/initialized"},
        {"jsonrpc":"2.0","id":2,"method":"tools/list"},
        {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"platform_info","arguments":{}}},
        {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec_command","arguments":{"command":"exit 99"}}},
        {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"hello.txt"}}},
        {"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../outside.txt"}}},
        {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"platform_info","arguments":{"unexpected":True}}},
        {"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_directory","arguments":{}}},
        {"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"file_info","arguments":{"path":"hello.txt"}}},
        {"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"file_info","arguments":{"path":"escape"}}},
        {"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":".."}}},
        {"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"list_directory","arguments":{"recursive":True}}},
    ]
    result=run("platform-probe",*args,input="".join(json.dumps(x)+"\n" for x in requests))
    if result.returncode:
        raise AssertionError(result.stderr)
    replies=[json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies)==13, replies
    return {x["id"]:x for x in replies}

class PlatformProbe(unittest.TestCase):
    def test_protocol_and_denials(self):
        info=run("platform")
        self.assertEqual(info.returncode,0,info.stderr)
        data=json.loads(info.stdout)
        r=rpc()
        self.assertEqual(r[0]["error"]["code"],-32000)
        self.assertEqual(r[1]["result"]["protocolVersion"],"2025-11-25")
        self.assertEqual([t["name"] for t in r[2]["result"]["tools"]],["platform_info"])
        self.assertEqual(json.loads(r[3]["result"]["content"][0]["text"]),data)
        for i in (4,5,6,8,9,10,11,12):
            self.assertEqual(r[i]["error"]["code"],-32602)
        self.assertTrue(r[7]["result"]["isError"])
        if data["os"] != "linux":
            with tempfile.TemporaryDirectory() as path:
                self.assertNotEqual(run("--root",path).returncode,0)
            self.assertNotEqual(run("http","--listen","127.0.0.1:7339","--config","unused").returncode,0)

    def test_optional_workspace(self):
        data=json.loads(run("platform").stdout)
        if data["os"]=="android":
            with tempfile.TemporaryDirectory(prefix="veyl-platform-",dir=Path.home()) as directory:
                root=Path(directory)
                root.chmod(0o700)
                (root/"hello.txt").write_text("native Android canary",encoding="utf8")
                (root/"escape").symlink_to("hello.txt")
                (root/".hidden").write_text("hidden",encoding="utf8")
                r=rpc("--root",root)
                self.assertEqual({t["name"] for t in r[2]["result"]["tools"]},{"platform_info","read_file","list_directory","file_info"})
                self.assertEqual(r[5]["result"]["content"][0]["text"],"native Android canary")
                self.assertFalse(r[5]["result"]["isError"])
                self.assertTrue(r[6]["result"]["isError"])
                listing=json.loads(r[8]["result"]["content"][0]["text"])
                self.assertEqual([e["name"] for e in listing["entries"]],["hello.txt"])
                self.assertEqual(listing["omitted"],2)
                metadata=json.loads(r[9]["result"]["content"][0]["text"])
                self.assertEqual(metadata["size"],len("native Android canary"))
                for i in (10,11,12):
                    self.assertTrue(r[i]["result"]["isError"])
                alias=root/"alias"
                alias.symlink_to(root,target_is_directory=True)
                self.assertNotEqual(run("platform-probe","--root",alias).returncode,0)
        else:
            with tempfile.TemporaryDirectory() as directory:
                r=run("platform-probe","--root",directory)
                self.assertNotEqual(r.returncode,0)
                self.assertFalse(r.stdout)

if __name__=="__main__":
    unittest.main()
