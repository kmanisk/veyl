#!/usr/bin/env python3
"""An independently authored multifile Node provider on the real stdio sandbox."""
import json
import os
from pathlib import Path
import unittest
import product_features as pf

HELPER = """
export function sum(values) { return values.reduce((a,b) => a+b,0); }
"""
SERVER = """
import { createInterface } from 'node:readline';
import { existsSync, writeFileSync } from 'node:fs';
import { sum } from './helper.mjs';
const lines = createInterface({input:process.stdin});
for await (const line of lines) {
    const req=JSON.parse(line);
    if (req.id===undefined) continue;
    let result;
    if(req.method==='initialize') result={protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'custom-bundle',version:'1'}};
    else if(req.method==='tools/list') result={tools:[{name:'sum',inputSchema:{type:'object'}},{name:'hidden',inputSchema:{type:'object'}}]};
    else if(req.method==='tools/call') {
        let readOnly=false;
        try {writeFileSync('/upstream/bundle/overwrite','unsafe');}
        catch {readOnly=true;}
        const args=req.params.arguments;
        result={content:[{type:'text',text:JSON.stringify({value:sum(args.values),readOnly,configVisible:existsSync(args.config),home:process.env.HOME})}]};
    } else result={};
    console.log(JSON.stringify({jsonrpc:'2.0',id:req.id,result}));
}
"""

class RuntimeBundle(unittest.TestCase):
    def setUp(self):
        self.f=f=pf.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        parent=f.base/"upstream-bundles"
        parent.mkdir(mode=0o700)
        self.bundle=parent/"custom"
        self.bundle.mkdir(mode=0o700)
        for name,code in (("helper.mjs",HELPER),("server.mjs",SERVER)):
            path=self.bundle/name
            path.write_text(code)
            path.chmod(0o600)
        f.doc["clients"][0]["tools"] += ["mcp_info","mcp_test"]
        f.write_config()
        f.cli("mcp-servers","add-bundle","custom","/usr/bin/node","/upstream/bundle/server.mjs")
        f.doc=json.loads(f.config.read_text())
        f.doc["clients"][0]["allowed_servers"]=["custom"]
        f.doc["clients"][0]["allowed_server_tools"]={"custom":["sum"]}
        f.write_config()
        f.start()
        self.session=f.connect()

    def probe(self):
        info=self.f.call("mcp_info",{"name":"custom"},self.session)
        self.assertFalse(info["isError"],info)
        fp=json.loads(info["content"][0]["text"])["provider_fingerprint"]
        r=self.f.call("mcp_test",{"name":"custom","provider_fingerprint":fp},self.session)
        self.assertFalse(r["isError"],r)
        return json.loads(r["content"][0]["text"])

    def test_generic_bundle_grants_and_confinement(self):
        self.assertEqual(self.probe()["health"],"ready")
        _,reply=self.f.rpc("tools/list",self.session,pf.TOKEN)
        names={t["name"] for t in reply["result"]["tools"]}
        self.assertIn("custom__sum",names)
        self.assertNotIn("custom__hidden",names)
        args={"values":[2,4,7],"config":str(self.f.config)}
        r=self.f.call("custom__sum",args,self.session)
        self.assertFalse(r.get("isError",False),r)
        self.assertEqual(json.loads(r["content"][0]["text"]),{"value":13,"readOnly":True,"configVisible":False,"home":"/tmp"})
        self.assertFalse((self.bundle/"overwrite").exists())
        self.assertTrue(self.f.call("custom__hidden",args,self.session)["isError"])
        other=self.f.connect(token=pf.OTHER_TOKEN)
        self.assertTrue(self.f.call("custom__sum",args,other,token=pf.OTHER_TOKEN)["isError"])

    def test_bundle_aliases_rejected(self):
        sentinel=self.f.base/"private-canary.txt"
        sentinel.write_text("not part of extension")
        sentinel.chmod(0o600)
        alias=self.bundle/"alias"
        alias.symlink_to(sentinel)
        self.assertEqual(self.probe()["health"],"unavailable")
        alias.unlink()
        os.link(sentinel,alias)
        self.assertEqual(self.probe()["health"],"unavailable")
        alias.unlink()
        self.assertEqual(self.probe()["health"],"ready")
        self.assertEqual(sentinel.read_text(),"not part of extension")

if __name__=="__main__":
    unittest.main()
