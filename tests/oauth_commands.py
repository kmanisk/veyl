#!/usr/bin/env python3
"""Explicit OAuth dynamic commands in the actual native workspace sandbox."""
import json
import os
import subprocess
import unittest
import oauth_jobs as jobs

class OAuthCommands(jobs.OAuthJobs):
    def setup_args(self):
        return super().setup_args()+["--workspace-commands"]
    def launch_jobs(self,action="setup",env=None):
        args=self.setup_args() if action=="setup" else self.onboarding_args("run",self.profile)+["--workspace-jobs","--workspace-commands"]
        self.launch(args,env=env)
        self.config=self.profile/"clients.json"
    def test_commands_scope_and_recovery(self):
        self.launch_jobs()
        client,a=self.authorize()
        _,b=self.authorize(client)
        at,bt=a["access_token"],b["access_token"]
        sa,sb=self.connect(at),self.connect(bt)
        status,_,body=self.rpc(at,"tools/list",sa)
        self.assertEqual(status,200,body)
        catalog={t["name"]:t for t in json.loads(body)["result"]["tools"]}
        self.assertIn("exec_command",catalog)
        self.assertIn("task_run",catalog)
        self.assertNotIn("process_start",catalog)
        self.assertEqual(catalog["task_run"]["inputSchema"]["properties"]["wait_seconds"]["maximum"],2)
        result=self.call(at,sa,"exec_command",{"command":"printf command-canary > created.txt; cat created.txt","cwd":".","request_id":"exec-one"})
        self.assertEqual(result["exit_code"],0,result)
        self.assertEqual(result["stdout"],"command-canary")
        self.assertEqual((self.root/"created.txt").read_text(),"command-canary")
        self.assertEqual(result["resource_ceilings"],{"cpu_percent":100,"memory_bytes":268435456})
        result=self.call(at,sa,"exec_command",{"argv":["/usr/bin/cat",str(self.base/"outside.txt")]})
        self.assertNotEqual(result["exit_code"],0)
        self.assertNotIn("outside-denied-canary",json.dumps(result))
        result=self.call(at,sa,"exec_command",{"argv":["/usr/bin/cat","escape.txt"]})
        self.assertNotEqual(result["exit_code"],0)
        result=self.call(at,sa,"exec_command",{"argv":["/usr/bin/python3","-c","import socket; socket.socket()"]})
        self.assertNotEqual(result["exit_code"],0)
        for arg in ({"cwd":str(self.base)},{"cwd":".."},{"cwd":"nested"},{"ephemeral_worktree":True},{"timeout_seconds":301},{"wait_seconds":3},{"cpu_percent":101},{"memory_bytes":268435457},{"max_output_bytes":65537}):
            self.call(at,sa,"task_run",{"command":"true",**arg},False)
        self.call(at,sa,"process_start",{"profile":"pwd"},False)
        alias=self.root/"alias"
        os.link(self.base/"outside.txt",alias)
        self.call(at,sa,"task_run",{"command":"true","wait_seconds":0},False)
        alias.unlink()
        params={"argv":["sleep","15"],"timeout_seconds":20,"wait_seconds":0,"request_id":"same"}
        ja=self.call(at,sa,"task_run",params)["job_id"]
        self.assertEqual(self.call(at,sa,"task_run",params)["job_id"],ja)
        self.call(at,sa,"task_run",dict(params,argv=["sleep","14"]),False)
        jb=self.call(bt,sb,"task_run",params)["job_id"]
        self.assertNotEqual(ja,jb)
        for tool in ("job_logs","job_status","job_cancel"):
            self.call(bt,sb,tool,{"job_id":ja},False)
        self.assertNotIn(ja,json.dumps(self.call(bt,sb,"list_jobs",{})))
        at=self.f.capture_tokens(self.f.refresh(client,a["refresh_token"]))["access_token"]
        self.f.cleanup_server()
        self.launch_jobs("run")
        sa=self.connect(at)
        self.assertIn(ja,json.dumps(self.call(at,sa,"list_jobs",{})))
        self.assertTrue(self.cli("revoke",{"client_id":client,"confirm":True})["revoked"])
        self.assertEqual(self.rpc(at,"tools/list",sa)[0],401)
        headers=self.pair_dashboard()
        for job in (ja,jb):
            status,_,body=self.f.request("POST","/dashboard/api/jobs/cancel",{"client":"oauth-preview","job_id":job,"confirm":True},admin=True,headers=headers)
            self.assertEqual(status,200,body)
        self.assertEqual((self.base/"outside.txt").read_text(),"outside-denied-canary")
    def test_commands_explicit_and_scope_unavailable(self):
        env=dict(os.environ,HOME=str(self.base))
        args=self.onboarding_args("setup",self.profile,self.root)+["--workspace-commands"]
        for command in (args,self.setup_args()+["--funnel"]):
            r=subprocess.run(command,capture_output=True,text=True,timeout=5,env=env)
            self.assertNotEqual(r.returncode,0)
            self.assertFalse(self.profile.exists())
        self.launch_jobs()
        _,issued=self.authorize()
        token=issued["access_token"]
        self.f.cleanup_server()
        r=subprocess.run(self.onboarding_args("run",self.profile)+["--workspace-jobs"],capture_output=True,text=True,timeout=5,env=env)
        self.assertNotEqual(r.returncode,0)
        self.launch_jobs("run",env=dict(env,XDG_RUNTIME_DIR=str(self.base/"missing-runtime")))
        session=self.connect(token)
        status,_,body=self.rpc(token,"tools/list",session)
        self.assertEqual(status,200,body)
        names={t["name"] for t in json.loads(body)["result"]["tools"]}
        self.assertNotIn("exec_command",names)
        self.assertNotIn("task_run",names)
        self.call(token,session,"exec_command",{"command":"true"},False)
        self.call(token,session,"task_run",{"command":"true"},False)

if __name__=="__main__":
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(OAuthCommands) if n.startswith("test_commands_")]
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(OAuthCommands(n) for n in names)).wasSuccessful())
