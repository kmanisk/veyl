#!/usr/bin/env python3
"""Managed direct OAuth lifecycle; disposable LocalAPI, no public route.

Run with the exact candidate mcp-gateway binary argument.
"""
import hashlib
import json
import os
import subprocess
import unittest

import oauth_funnel as funnel

class ManagedLogin(funnel.Funnel):
    def setUp(self):
        super().setUp()
        self.managed = self.base / ".veyl-login"
        self.profile = self.managed / "profile"
        self.env = dict(os.environ, HOME=str(self.base))
        self.veyl = funnel.native.BIN.with_name("veyl")

    def login_args(self, first=False):
        args = [str(self.veyl), "login", "--yes", "--no-ui",
                "--funnel-socket", str(self.socket_path)]
        if first:
            args += ["--root", str(self.root)]
        return args

    def execute(self, args, **kwargs):
        return subprocess.run(args, env=self.env, text=True, capture_output=True,
                              timeout=25, **kwargs)

    def start_managed(self, first=False):
        self.launch(self.login_args(first))
        self.config = self.profile / "clients.json"
        self.wait_for(lambda: len(self.daemon.snapshot()["Foreground"]) == 2)
        self.assertEqual(json.loads(self.config.read_text())["clients"][0]["mode"], "standard")

    def authorize_managed(self):
        client = self.f.register()
        handle = self.f.pending(client)
        info = self.cli("inspect", {"request": handle})
        self.assertTrue(info["eligible"], info)
        self.assertEqual(info["native_scope"]["mode"], "standard")
        args = self.exact("approve", handle, info)
        args.pop("action")
        self.assertTrue(self.cli("approve", args)["approved"])
        issued = self.f.capture_tokens(self.f.exchange(client, self.delivered(handle)))
        return client, issued

    def logout(self):
        result = self.execute([str(self.veyl), "logout", "--yes"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("revoked", result.stdout)
        self.assertFalse((self.managed / ".logout-pending").exists())
        self.assertFalse((self.managed / "control.sock").exists())
        self.wait_for(lambda: self.daemon.snapshot() == self.daemon.initial)
        state = json.loads((self.profile / "oauth/oauth-state.json").read_text())["payload"]
        self.assertEqual(state["families"], [])
        self.assertEqual(state["registry"]["clients"], [])
        self.assertIsNone(state["interrupted"])
        self.assertEqual(state["audit"][-1]["operation"], "revoke")
        self.assertEqual((self.root / "canary.txt").read_text(), "native-read-canary")

    def test_login_live_logout_reconnect(self):
        refused = self.execute([str(self.veyl), "login", "--no-ui",
            "--root", str(self.root), "--funnel-socket", str(self.socket_path)], input="n\n")
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse(self.managed.exists())
        self.start_managed(first=True)
        duplicate = self.execute(self.login_args())
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("already running", duplicate.stderr)
        self.assertEqual(self.daemon.posts, 1)
        _, issued = self.authorize_managed()
        access = issued["access_token"]
        session = self.connect(access)
        self.assertIn("native-read-canary", json.dumps(self.read(access, session, "canary.txt")))
        self.logout()
        self.f.proc.wait(timeout=10)
        self.assertEqual(self.f.proc.returncode, 0)
        self.f.cleanup_server()
        self.start_managed()
        self.assertEqual(self.rpc(access, "initialize", params=funnel.native.INIT)[0], 401)
        _, fresh = self.authorize_managed()
        token = fresh["access_token"]
        self.assertIn("native-read-canary", json.dumps(self.read(token, self.connect(token), "canary.txt")))
        self.stop_funnel()

    def test_offline_logout_and_pending_intent(self):
        self.start_managed(first=True)
        _, issued = self.authorize_managed()
        self.stop_funnel()
        marker = self.managed / ".logout-pending"
        marker.touch(mode=0o600)
        marker.chmod(0o600)
        # Model a crash after durable revoke intent publication. This is a
        # disposable fixture, not an instruction to edit production state.
        state_path = self.profile / "oauth/oauth-state.json"
        state = json.loads(state_path.read_text())
        state["payload"]["interrupted"] = "revoke"
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        state["sha256"] = hashlib.sha256(canonical(state["payload"]).encode()).hexdigest()
        state_path.write_text(canonical(state))
        refused = self.execute(self.login_args())
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("Logout was interrupted", refused.stderr)
        self.logout()
        self.start_managed()
        self.assertEqual(self.rpc(issued["access_token"], "initialize",
                                  params=funnel.native.INIT)[0], 401)
        self.stop_funnel()

if __name__ == "__main__":
    suite = unittest.TestSuite([ManagedLogin(name) for name in (
        "test_login_live_logout_reconnect", "test_offline_logout_and_pending_intent")])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
