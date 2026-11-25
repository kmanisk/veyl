#!/usr/bin/env python3
"""Operator-only provider folder editor, without changing native client roots."""
import json
import subprocess
import unittest

import product_features as pf
import upstream_workspace_jobs as fixture


class FolderEditor(unittest.TestCase):
    def setUp(self):
        self.case = case = fixture.WorkspaceJobs()
        case.setUp()
        self.addCleanup(case.doCleanups)
        self.f = f = case.f
        f.stop(case.process)
        self.projects = f.base / "projects"
        self.projects.mkdir(mode=0o700)
        self.shared = self.projects / "shared"
        self.shared.mkdir(mode=0o700)
        self.project = self.projects / "actual-project"
        self.project.mkdir(mode=0o700)
        self.sample = self.project / "sample.txt"
        self.sample.write_text("provider-only")
        for client in f.doc["clients"]:
            client["root"] = str(self.shared)
        f.write_config()
        self.process = f.start()
        self.session = f.connect()
        self.headers = f.pair()

    def api(self, action, provider, root=None, *, headers=None, confirm=True):
        data = {"action": action, "id": provider, "client": "primary", "confirm": confirm}
        if root is not None:
            data["root"] = str(root)
        return self.f.request(self.f.admin, "POST", "/api/dashboard/servers", data,
                              **(self.headers if headers is None else headers))

    def answer(self, provider, args, session=None, token=pf.TOKEN):
        r = self.f.call(provider, args, session or self.session, token=token)
        self.assertFalse(r.get("isError", False), r)
        return json.loads(r["content"][0]["text"])

    def test_folder_parent_grant_and_revoke(self):
        f = self.f
        before = json.loads(f.config.read_text())["clients"]
        # Previous scoped command must still deny a parent outside native roots.
        self.assertEqual(self.api("workspace", "rea", self.projects)[0], 400)
        self.assertEqual(self.api("workspace-folder", "rea", self.projects, confirm=False)[0], 403)
        missing_csrf = {k: v for k, v in self.headers.items() if k != "X-CSRF-Token"}
        self.assertEqual(self.api("workspace-folder", "rea", self.projects, headers=missing_csrf)[0], 403)
        wrong_origin = dict(self.headers, Origin="https://invalid.example")
        self.assertEqual(self.api("workspace-folder", "rea", self.projects, headers=wrong_origin)[0], 403)
        for root in (f.base, f.config.parent):
            self.assertEqual(self.api("workspace-folder", "rea", root)[0], 400)
        self.assertEqual(self.api("workspace-folder", "node-utils", self.projects)[0], 400)
        f.cli("mcp-servers", "workspace-folder", "primary", "rea", str(self.projects))
        status, _, body = self.api("workspace-folder", "rust-anything", self.projects)
        self.assertEqual(status, 200, body)
        after = json.loads(f.config.read_text())["clients"]
        for field in ("root", "extra_roots", "mode", "tools", "allowed_server_tools"):
            self.assertEqual([c.get(field) for c in before], [c.get(field) for c in after])
        self.assertEqual(after[1], before[1])
        self.case.assert_inventory(self.session)
        for tool, args in (("rea__inspect_python_pyc", {"path":str(self.sample)}),
                           ("rust-anything__analyze", {"root":str(self.project)})):
            result = self.answer(tool,args)
            self.assertEqual(result["content"], "provider-only")
            self.assertTrue(result["readonly"])
        self.assertTrue(f.call("read_file", {"path":str(self.sample)}, self.session)["isError"])
        other = f.connect(pf.OTHER_TOKEN)
        self.assertFalse(self.answer("rea__inspect_python_pyc", {"path":str(self.sample)}, other, pf.OTHER_TOKEN)["visible"])
        state = json.loads(f.request(f.admin,"GET","/api/dashboard/status",**self.headers)[2])
        grants = next(c for c in state["clients"] if c["id"] == "primary")["upstream_workspaces"]
        self.assertEqual(grants["rea"], {"root":str(self.projects),"provider_only":True})
        self.assertEqual(self.api("unworkspace","rea")[0],200)
        self.assertFalse(self.answer("rea__inspect_python_pyc",{"path":str(self.sample)})["visible"])
        self.assertEqual(self.answer("rust-anything__analyze",{"root":str(self.project)})["content"],"provider-only")

    def test_persistent_folder_identity_and_recovery(self):
        f = self.f
        # Use a separate folder so the native primary root remains available.
        f.cli("mcp-servers","workspace-folder","primary","rea",str(self.project))
        saved = self.project.with_name("project-saved")
        f.stop(self.process)
        self.project.rename(saved)
        self.project.mkdir(mode=0o700)
        self.sample.write_text("replacement")
        self.process = f.start()
        self.session = f.connect()
        try:
            self.case.assert_inventory(self.session)
            self.assertTrue(f.call("rea__inspect_python_pyc",{"path":str(self.sample)},self.session)["isError"])
            # Stale provider grants must not lock operator out of revocation.
            f.cli("mcp-servers","unworkspace","primary","rea")
            self.assertFalse(self.answer("rea__inspect_python_pyc",{"path":str(self.sample)})["visible"])
        finally:
            self.sample.unlink()
            self.project.rmdir()
            saved.rename(self.project)
        f.cli("mcp-servers","workspace-folder","primary","rea",str(self.project))
        self.assertEqual(self.answer("rea__inspect_python_pyc",{"path":str(self.sample)})["content"],"provider-only")


if __name__ == "__main__":
    unittest.main()
