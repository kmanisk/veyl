#!/usr/bin/env python3
"""TimeShift integration: real authenticated gateway and protected disposable state."""
import hashlib
import json
import os
import unittest
from pathlib import Path
import product_features as pf
import upstream_workspace_jobs as fixture

REWIND = {"rewind", "rewind_restore", "rewind_clear"}


class TimeShift(unittest.TestCase):
    def setUp(self):
        case = fixture.WorkspaceJobs()
        case.setUp()
        self.addCleanup(case.doCleanups)
        self.f = f = case.f
        f.stop(case.process)
        for client in f.doc["clients"]:
            client["tools"] += sorted(REWIND)
        f.write_config()
        self.process = f.start()
        self.session = f.connect()
        self.other = f.connect(pf.OTHER_TOKEN)
        self.path = "project/example.txt"
        self.file = f.workspace / self.path
        self.file.write_text("first version\n")
        self.file.chmod(0o640)
        self.store = f.config.parent / "timeshift" / hashlib.sha256(str(f.config).encode()).hexdigest() / hashlib.sha256(b"primary").hexdigest()

    def call(self, name, args, *, other=False):
        return self.f.call(name, args, self.other if other else self.session,
                           token=pf.OTHER_TOKEN if other else pf.TOKEN)

    def ok(self, name, args, *, other=False):
        result = self.call(name, args, other=other)
        self.assertFalse(result["isError"], result)
        return json.loads(result["content"][0]["text"])

    def denied(self, name, args, *, other=False):
        self.assertTrue(self.call(name,args,other=other)["isError"])

    def history(self, path=None, *, other=False):
        return self.ok("rewind", {"path":path or self.path,"action":"list"},other=other)

    def write(self, value, path=None, overwrite=True):
        return self.ok("write_file",{"path":path or self.path,"content":value,"overwrite":overwrite})

    def restore(self, checkpoint, confirm=True, *, other=False):
        return self.call("rewind_restore",{"path":self.path,"checkpoint":checkpoint,"confirm":confirm},other=other)

    def test_signed_checkpoint_restore_restart_and_clear(self):
        _, reply = self.f.rpc("tools/list",self.session)
        names = {t["name"] for t in reply["result"]["tools"]}
        self.assertEqual(len(names), 94)
        self.assertTrue(REWIND <= names)
        self.write("second version\n")
        records = self.history()["checkpoints"]
        self.assertEqual(len(records),1)
        record = records[0]
        checkpoint = record["checkpoint"]
        self.assertEqual(record["before_sha256"],hashlib.sha256(b"first version\n").hexdigest())
        self.assertEqual(record["after_sha256"],hashlib.sha256(b"second version\n").hexdigest())
        self.assertEqual(self.store.stat().st_mode & 0o777,0o700)
        self.assertEqual((self.store/"key").stat().st_mode & 0o777,0o600)
        self.assertEqual((self.store/(checkpoint+".json")).stat().st_mode & 0o777,0o600)
        self.f.stop(self.process)
        self.process = self.f.start()
        self.session = self.f.connect()
        preview = self.ok("rewind",{"path":self.path,"action":"preview","checkpoint":checkpoint})
        self.assertEqual(preview["before"],"first version\n")
        self.assertEqual(preview["current"],"second version\n")
        self.assertTrue(preview["restorable"])
        self.assertTrue(self.restore(checkpoint,False)["isError"])
        self.assertFalse(self.restore(checkpoint)["isError"])
        self.assertEqual(self.file.read_text(),"first version\n")
        self.assertEqual(self.file.stat().st_mode & 0o777,0o640)
        self.assertTrue(self.restore(checkpoint)["isError"])
        records = self.history()["checkpoints"]
        self.assertEqual(len(records),2)
        redo = next(r["checkpoint"] for r in records if r["checkpoint"] != checkpoint)
        self.assertFalse(self.restore(redo)["isError"])
        self.assertEqual(self.file.read_text(),"second version\n")
        self.denied("rewind_clear",{"path":self.path,"checkpoint":checkpoint,"confirm":False})
        self.ok("rewind_clear",{"path":self.path,"checkpoint":checkpoint,"confirm":True})
        self.assertFalse((self.store/(checkpoint+".json")).exists())
        self.assertEqual(self.file.read_text(),"second version\n")
        audit = self.f.audit.read_text()
        self.assertNotIn("first version",audit)
        self.assertNotIn("second version",audit)

    def test_patch_edit_conflict_and_cross_client(self):
        self.ok("apply_patch",{"path":self.path,"expected_sha256":hashlib.sha256(b"first version\n").hexdigest(),"old":"first","new":"second"})
        self.ok("edit_file",{"path":self.path,"target":"second","replacement":"third"})
        records = self.history()["checkpoints"]
        self.assertEqual(len(records),2)
        id = next(r["checkpoint"] for r in records if r["after_sha256"]==hashlib.sha256(b"third version\n").hexdigest())
        self.assertEqual(self.history(other=True)["checkpoints"],[])
        self.denied("rewind",{"path":self.path,"action":"preview","checkpoint":id},other=True)
        self.assertTrue(self.restore(id,other=True)["isError"])
        self.denied("rewind_clear",{"path":self.path,"checkpoint":id,"confirm":True},other=True)
        self.file.write_text("outside edit\n")
        self.assertFalse(self.ok("rewind",{"path":self.path,"action":"preview","checkpoint":id})["restorable"])
        self.assertTrue(self.restore(id)["isError"])
        self.assertEqual(self.file.read_text(),"outside edit\n")
        self.denied("rewind",{"path":"../outside","action":"list"})
        self.denied("rewind",{"path":str(self.f.config),"action":"list"})

    def test_created_file_is_not_deleted_and_hardlinks_denied(self):
        path = "project/new.txt"
        self.write("new",path,False)
        r = self.history(path)["checkpoints"][0]
        self.assertTrue(r["created_file"])
        self.assertFalse(self.ok("rewind",{"path":path,"action":"preview","checkpoint":r["checkpoint"]})["restorable"])
        self.denied("rewind_restore",{"path":path,"checkpoint":r["checkpoint"],"confirm":True})
        self.assertEqual((self.f.workspace/path).read_text(),"new")
        hard = self.file.with_name("hard.txt")
        os.link(self.file,hard)
        self.denied("write_file",{"path":self.path,"content":"changed","overwrite":True})
        self.assertEqual(hard.read_text(),"first version\n")
        hard.unlink()
        symlink = self.file.with_name("link.txt")
        symlink.symlink_to(self.file)
        self.denied("write_file",{"path":"project/link.txt","content":"changed","overwrite":True})

    def test_tampering_and_store_quota(self):
        self.write("second")
        record = self.history()["checkpoints"][0]
        id = record["checkpoint"]
        record_path = self.store/(id+".json")
        old = record_path.read_bytes()
        changed = json.loads(old)
        changed["payload"] = changed["payload"].replace("first version","tampered")
        record_path.write_text(json.dumps(changed))
        self.denied("rewind",{"path":self.path,"action":"preview","checkpoint":id})
        self.assertTrue(self.restore(id)["isError"])
        self.assertEqual(self.file.read_text(),"second")
        record_path.write_bytes(old)
        for i in range(63):
            self.write(f"version {i}")
        self.assertEqual(self.history()["retained"],64)
        self.denied("write_file",{"path":self.path,"content":"overflow","overwrite":True})
        self.assertEqual(self.file.read_text(),"version 62")
        self.ok("rewind_clear",{"path":self.path,"checkpoint":id,"confirm":True})
        self.write("after clear")

    def test_historical_restore_and_stale_guard(self):
        self.write("second")
        first = self.history()["checkpoints"][0]["checkpoint"]
        self.write("third")
        preview = self.ok("rewind",{"path":self.path,"action":"preview","checkpoint":first})
        self.assertTrue(preview["restorable"])
        self.assertNotEqual(preview["current_checkpoint"],first)
        self.assertEqual(preview["diff"]["remove"],"third")
        self.assertEqual(preview["diff"]["insert"],"first version\n")
        args = {"path":self.path,"checkpoint":first,"current_checkpoint":preview["current_checkpoint"],"confirm":True}
        self.write("fourth")
        self.denied("rewind_restore",args)
        self.assertEqual(self.file.read_text(),"fourth")
        preview = self.ok("rewind",{"path":self.path,"action":"preview","checkpoint":first})
        args["current_checkpoint"] = preview["current_checkpoint"]
        self.ok("rewind_restore",args)
        self.assertEqual(self.file.read_text(),"first version\n")

    def test_crash_stage_cleanup_and_preview_scope(self):
        self.write("second")
        id = self.history()["checkpoints"][0]["checkpoint"]
        temp = self.store/(".mcp-publish-"+"a"*32)
        temp.write_text("interrupted")
        temp.chmod(0o600)
        self.assertEqual(len(self.history()["checkpoints"]),1)
        self.assertFalse(temp.exists())
        hard = self.file.with_name("hard.txt")
        os.link(self.file,hard)
        self.denied("rewind",{"path":self.path,"action":"preview","checkpoint":id})
        hard.unlink()
        parent = self.file.parent
        saved = parent.with_name("old-project")
        parent.rename(saved)
        parent.mkdir()
        self.file.write_text("replacement")
        try:
            self.denied("rewind",{"path":self.path,"action":"preview","checkpoint":id})
            self.assertTrue(self.restore(id)["isError"])
        finally:
            self.file.unlink()
            parent.rmdir()
            saved.rename(parent)
        self.assertTrue(self.ok("rewind",{"path":self.path,"action":"preview","checkpoint":id})["restorable"])

    def test_operator_retention_is_bounded_and_persistent(self):
        headers = self.f.pair()
        def set_limit(limit, confirm=True):
            return self.f.request(self.f.admin, "POST", "/api/dashboard/clients/grants",
                                  {"client":"primary","timeshift_retention_count":limit,
                                   "confirm":confirm}, **headers)
        before = json.loads(self.f.config.read_text())["clients"]
        self.assertEqual(set_limit(0)[0],400)
        self.assertEqual(set_limit(257)[0],400)
        self.assertEqual(set_limit(2,False)[0],403)
        self.write("second")
        checkpoint = self.history()["checkpoints"][0]["checkpoint"]
        self.write("third")
        status, _, body = set_limit(1)
        self.assertEqual(status,200,body)
        after = json.loads(self.f.config.read_text())["clients"]
        self.assertEqual(after[1],before[1])
        self.assertEqual(after[0]["timeshift_retention_count"],1)
        self.assertEqual({k:v for k,v in after[0].items() if k!="timeshift_retention_count"},before[0])
        self.assertEqual(self.history()["retained"],2)
        self.assertEqual(self.history()["limit"],1)
        self.denied("write_file",{"path":self.path,"content":"overflow","overwrite":True})
        self.assertEqual(set_limit(2)[0],200)
        self.ok("rewind_clear",{"path":self.path,"checkpoint":checkpoint,"confirm":True})
        self.write("fourth")
        self.f.stop(self.process)
        self.process = self.f.start()
        self.session = self.f.connect()
        self.assertEqual(self.history()["limit"],2)
        self.assertEqual(self.history()["retained"],2)

    def test_missing_signing_key_fails_closed(self):
        self.write("second")
        checkpoint = self.history()["checkpoints"][0]["checkpoint"]
        (self.store/"key").unlink()
        self.denied("write_file",{"path":self.path,"content":"third","overwrite":True})
        self.assertTrue(self.restore(checkpoint)["isError"])
        self.assertEqual(self.file.read_text(),"second")

    def test_explicit_standard_timeshift_grants(self):
        # Operator revokes restore/clear but retains capture/history.
        self.f.stop(self.process)
        self.f.doc["clients"][0]["tools"] = sorted(set(self.f.doc["clients"][0]["tools"]) - {"rewind_restore","rewind_clear"})
        self.f.write_config()
        self.process = self.f.start()
        self.session = self.f.connect()
        self.write("scoped edit")
        id = self.history()["checkpoints"][0]["checkpoint"]
        self.assertTrue(self.restore(id)["isError"])
        self.denied("rewind_clear",{"path":self.path,"checkpoint":id,"confirm":True})
        _, reply = self.f.rpc("tools/list",self.session)
        self.assertEqual({t["name"] for t in reply["result"]["tools"]} & REWIND,{"rewind"})
        # Standard file access must never expose the store.
        self.denied("read_file",{"path":str(self.store/"key")})


if __name__ == "__main__":
    unittest.main()
