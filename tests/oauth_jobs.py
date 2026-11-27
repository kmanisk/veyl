#!/usr/bin/env python3
"""Real isolated OAuth named jobs, owner separation and local operator recovery."""
import json
import os
import subprocess
import time
import unittest
import oauth_native as native

preview=native.preview

class OAuthJobs(native.NativeOAuth):
    def setUp(self):
        super().setUp()
        old=(preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL)
        def restore():
            preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL=old
        self.addCleanup(restore)
        preview.ORIGIN,preview.HOST,preview.RESOURCE,preview.LOCAL="https://veyl.example","veyl.example","https://veyl.example/mcp","oauth-preview"
        self.profile=self.base/"job-profile"
        self.definitions=self.base/"job-profiles.json"
        self.profiles={
            "pwd":{"executable":"/usr/bin/pwd","args":[],"timeout_seconds":4},
            "sleep":{"executable":"/usr/bin/sleep","args":["20"],"timeout_seconds":25},
            "escape":{"executable":"/usr/bin/cat","args":["escape.txt"],"timeout_seconds":4},
        }
        self.definitions.write_text(json.dumps({"job_profiles":self.profiles}))
        self.definitions.chmod(0o600)
    def setup_args(self):
        return self.onboarding_args("setup",self.profile,self.root)+["--workspace-jobs","--job-profiles",str(self.definitions)]
    def launch_jobs(self,action="setup"):
        args=self.setup_args() if action=="setup" else self.onboarding_args("run",self.profile)+["--workspace-jobs"]
        self.launch(args)
        self.config=self.profile/"clients.json"
    def authorize(self,client=None):
        client=client or self.f.register()
        handle=self.f.pending(client)
        info=self.cli("inspect",{"request":handle})
        self.assertTrue(info["eligible"])
        self.assertTrue(info["native_scope"]["workspace_jobs"])
        self.assertEqual(set(info["native_scope"]["job_profiles"]),set(self.profiles))
        args=self.exact("approve",handle,info)
        args.pop("action")
        self.cli("approve",args,success=False)
        self.cli("approve",dict(args,scope_fingerprint="0"*64),success=False)
        args["scope_fingerprint"]=info["scope_fingerprint"]
        self.assertTrue(self.cli("approve",args)["approved"])
        return client,self.f.capture_tokens(self.f.exchange(client,self.delivered(handle)))
    def call(self,token,session,name,args,ok=True):
        status,_,body=self.rpc(token,"tools/call",session,{"name":name,"arguments":args})
        self.assertEqual(status,200,body)
        result=json.loads(body)["result"]
        self.assertEqual(not result.get("isError",False),ok,(name,result))
        value=result["content"][0]["text"]
        return json.loads(value) if ok else value
    def test_jobs_family_boundary_and_operator_recovery(self):
        self.launch_jobs()
        client,a=self.authorize()
        _,b=self.authorize(client)
        at,bt=a["access_token"],b["access_token"]
        sa,sb=self.connect(at),self.connect(bt)
        status,_,body=self.rpc(at,"tools/list",sa)
        self.assertEqual(status,200)
        names={t["name"] for t in json.loads(body)["result"]["tools"]}
        self.assertEqual(names,{"read_file","run_command","job_start","job_status","job_logs","job_cancel","list_jobs","job_wait"})
        self.call(at,sa,"exec_command",{"command":"pwd"},False)
        self.call(at,sa,"run_command",{"argv":["/usr/bin/uname"]},False)
        self.call(at,sa,"job_start",{"profile":"unknown"},False)
        self.call(at,sa,"job_wait",{"job_id":"a"*32,"timeout_seconds":60},False)
        result=self.call(at,sa,"run_command",{"profile":"pwd"})
        self.assertEqual(result["exit_code"],0,result)
        self.assertEqual(result["resource_ceilings"],{"cpu_percent":100,"memory_bytes":268435456},result)
        self.assertEqual(result["logs"]["stdout"].strip(),str(self.root))
        escaped=self.call(at,sa,"run_command",{"profile":"escape"})
        self.assertNotEqual(escaped["exit_code"],0)
        self.assertNotIn("outside-denied-canary",json.dumps(escaped))
        alias=self.root/"hardlink.txt"
        os.link(self.base/"outside.txt",alias)
        self.call(at,sa,"job_start",{"profile":"pwd"},False)
        alias.unlink()
        fifo=self.root/"blocked-fifo"
        os.mkfifo(fifo)
        self.call(at,sa,"job_start",{"profile":"pwd"},False)
        fifo.unlink()
        # Same request key and same registration, different grant family:
        # no cross-family deduplication, enumeration, logs or cancellation.
        params={"profile":"sleep","request_id":"shared-id"}
        ja=self.call(at,sa,"job_start",params)["job_id"]
        self.assertEqual(self.call(at,sa,"job_start",params)["job_id"],ja)
        jb=self.call(bt,sb,"job_start",params)["job_id"]
        self.assertNotEqual(ja,jb)
        for name in ("job_status","job_logs","job_cancel"):
            self.call(bt,sb,name,{"job_id":ja},False)
        self.assertNotIn(ja,json.dumps(self.call(bt,sb,"list_jobs",{})))
        self.assertIn(ja,json.dumps(self.call(at,sa,"list_jobs",{})))
        renewed=self.f.capture_tokens(self.f.refresh(client,a["refresh_token"]))
        at=renewed["access_token"]
        self.assertEqual(self.call(at,sa,"job_status",{"job_id":ja})["job_id"],ja)
        self.f.cleanup_server()
        self.launch_jobs("run")
        sa,sb=self.connect(at),self.connect(bt)
        self.assertIn(ja,json.dumps(self.call(at,sa,"list_jobs",{})))
        self.call(bt,sb,"job_status",{"job_id":ja},False)
        # Revocation denies new operations. The authenticated LOCAL
        # operator still sees and can cancel all jobs in the profile.
        self.assertTrue(self.cli("revoke",{"client_id":client,"confirm":True})["revoked"])
        self.assertEqual(self.rpc(at,"tools/list",sa)[0],401)
        headers=self.pair_dashboard()
        status,_,body=self.f.request("GET","/dashboard/api/jobs?client=oauth-preview",admin=True,headers=headers)
        self.assertEqual(status,200,body)
        self.assertIn(ja,body.decode())
        self.assertIn(jb,body.decode())
        for job in (ja,jb):
            status,_,body=self.f.request("POST","/dashboard/api/jobs/cancel",{"client":"oauth-preview","job_id":job,"confirm":True},admin=True,headers=headers)
            self.assertEqual(status,200,body)
            self.assertIn(json.loads(body)["state"],("canceled","completed","timed_out"))
    def test_jobs_require_local_explicit_valid_profile(self):
        for extra in (["--funnel"],):
            result=subprocess.run(self.setup_args()+extra,capture_output=True,text=True,timeout=10,env=dict(os.environ,HOME=str(self.base)))
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(self.profile.exists())
        self.profiles["bad"]={"executable":"/usr/bin/sh","args":[],"timeout_seconds":3,"interactive":True}
        self.definitions.write_text(json.dumps({"job_profiles":self.profiles}))
        result=subprocess.run(self.setup_args(),capture_output=True,text=True,timeout=10,env=dict(os.environ,HOME=str(self.base)))
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.profile.exists())
        del self.profiles["bad"]
        self.definitions.write_text(json.dumps({"job_profiles":self.profiles}))
        self.launch_jobs()
        self.f.cleanup_server()
        result=subprocess.run(self.onboarding_args("run",self.profile),capture_output=True,text=True,timeout=10,env=dict(os.environ,HOME=str(self.base)))
        self.assertNotEqual(result.returncode,0)

    def test_jobs_no_scope_does_not_fall_back_to_unconfined_execution(self):
        self.launch_jobs()
        client,issued=self.authorize()
        token=issued["access_token"]
        session=self.connect(token)
        finished=self.call(token,session,"run_command",{"profile":"pwd"})
        self.assertEqual(finished["resource_ceilings"],{"cpu_percent":100,"memory_bytes":268435456})
        self.f.cleanup_server()
        # Scope detection must refuse a noncanonical runtime directory.
        env=dict(os.environ,HOME=str(self.base),XDG_RUNTIME_DIR=str(self.base/"missing-runtime"))
        self.launch(self.onboarding_args("run",self.profile)+["--workspace-jobs"],env=env)
        session=self.connect(token)
        status,_,body=self.rpc(token,"tools/list",session)
        self.assertEqual(status,200,body)
        names={t["name"] for t in json.loads(body)["result"]["tools"]}
        self.assertNotIn("run_command",names)
        self.assertNotIn("job_start",names)
        self.assertIn("job_status",names)
        self.call(token,session,"run_command",{"profile":"pwd"},False)
        self.call(token,session,"job_start",{"profile":"pwd"},False)
        self.assertEqual(self.call(token,session,"job_status",{"job_id":finished["job_id"]})["exit_code"],0)
        handle=self.f.pending(client)
        info=self.cli("inspect",{"request":handle})
        self.assertFalse(info["eligible"])
        data=self.exact("approve",handle,info)
        data.pop("action")
        data["scope_fingerprint"]=info["scope_fingerprint"]
        self.cli("approve",data,success=False)
        data.pop("scope_fingerprint")
        self.assertTrue(self.cli("deny",data)["denied"])
        self.delivered(handle,denied=True)
        self.assertTrue(self.cli("revoke",{"client_id":client,"confirm":True})["revoked"])

if __name__=="__main__":
    names=[n for n in unittest.defaultTestLoader.getTestCaseNames(OAuthJobs) if n.startswith("test_jobs_")]
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(OAuthJobs(n) for n in names)).wasSuccessful())
