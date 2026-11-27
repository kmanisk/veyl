#!/usr/bin/env python3
"""Real MCP round trips against the isolated managed OAuth fixture."""

import json
import shlex
import unittest

from oauth_yolo_lifecycle import OAuthYoloLifecycle


class UnifiedOAuth(OAuthYoloLifecycle):
    def test_native_oauth_execution_and_downgrade(self):
        self.start_managed(first=True)
        self.outside.write_text("oauth-host-file")
        client, standard = self.authorize_client()
        token = standard["access_token"]
        session = self.connect(token)
        self.assertNotIn("exec_command", self.tools_list(token, session))
        self.assertTrue(self.call_tool(token, session, "read_file",
                                      {"path": str(self.outside)})["isError"])

        native_id, native = self.authorize_client("yolo")
        token = native["access_token"]
        session = self.connect(token)
        self.assertIn("goal_create", self.tools_list(token, session))
        result = self.call_tool(token, session, "exec_command", {
            "command": "cat " + shlex.quote(str(self.outside)), "timeout_seconds": 5})
        self.assertFalse(result["isError"], result)
        job = json.loads(result["content"][0]["text"])
        self.assertEqual(job["exit_code"], 0, job)
        self.assertEqual(job["stdout"], "oauth-host-file")
        goal = self.call_tool(token, session, "goal_create", {
            "description": "OAuth-owned goal", "request_id": "first",
            "acceptance_criteria": [{"description": "Check native execution"}]})
        self.assertFalse(goal["isError"], goal)
        self.assertIn("OAuth-owned goal", goal["content"][0]["text"])
        native_client = native_id["client_id"] if isinstance(native_id, dict) else native_id
        result = self.execute([str(self.veyl), "mode", "standard", native_client, "--managed"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("exec_command", self.tools_list(token, session))


if __name__ == "__main__":
    suite = unittest.TestSuite([UnifiedOAuth("test_native_oauth_execution_and_downgrade")])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
