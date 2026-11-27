#!/usr/bin/env python3
"""Additional independent synthetic control-plane and re-consent regressions."""
import os
import shlex
import json
import unittest
from oauth_yolo_lifecycle import OAuthYoloLifecycle

class CrossGateway(OAuthYoloLifecycle):
    def test_native_state_is_masked(self):
        paths = []
        for rel in (".local/state/veyl", ".local/state/mcp-gateway", ".config/mcp-gateway", ".veyl-update-backups"):
            directory = self.base / rel
            directory.mkdir(parents=True, mode=0o700)
            path = directory / "synthetic.json"
            path.write_text("synthetic-native-policy")
            path.chmod(0o600)
            paths.append(path)
        self.start_managed(first=True)
        _, issued = self.authorize_client(approve_mode="yolo")
        token = issued["access_token"]
        session = self.connect(token)
        for path in paths:
            self.assertTrue(self.call_tool(token, session, "read_file", {"path": str(path)}).get("isError"), str(path))
            self.assertTrue(self.call_tool(token, session, "write_file", {"path": str(path), "content": "blocked"}).get("isError"), str(path))
        command = " && ".join("test ! -e " + shlex.quote(str(path)) for path in paths) + " && printf masked"
        result = self.call_tool(token, session, "exec_command", {"command": command, "timeout_seconds": 8})
        self.assertFalse(result.get("isError"), result)
        payload = json.loads(result["content"][0]["text"])
        if payload["state"] == "running":
            payload = json.loads(self.call_tool(token, session, "job_wait", {"job_id": payload["job_id"], "timeout_seconds": 2})["content"][0]["text"])
        self.assertEqual(payload["exit_code"], 0, payload)
        self.assertEqual(payload["stdout"], "masked", payload)
        self.assertTrue(all(path.read_text() == "synthetic-native-policy" for path in paths))
        self.stop_funnel()

    def test_reconsent_never_revives_old_yolo(self):
        self.start_managed(first=True)
        client, old = self.authorize_client(approve_mode="yolo")
        token = old["access_token"]
        session = self.connect(token)
        self.assertIn("write_file", self.tools_list(token, session))
        self.reauthorize_client(client, approve_mode="standard")
        self.assertEqual(sorted(self.tools_list(token, session)), ["read_file"])
        fresh, _ = self.reauthorize_client(client, approve_mode="yolo")
        self.assertIn("write_file", self.tools_list(fresh["access_token"], self.connect(fresh["access_token"])))
        status, _, body = self.rpc(token, "tools/list", session)
        if status != 401:
            self.assertEqual(status, 200, body)
            self.assertEqual([t["name"] for t in json.loads(body)["result"]["tools"]], ["read_file"])
        self.stop_funnel()

if __name__ == "__main__":
    suite = unittest.TestSuite(CrossGateway(name) for name in ("test_native_state_is_masked", "test_reconsent_never_revives_old_yolo"))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
