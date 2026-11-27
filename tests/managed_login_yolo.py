#!/usr/bin/env python3
"""Broad native YOLO must not reach the separate managed OAuth control plane."""
import json
import os
import shlex
import socket
import subprocess
import unittest

import dynamic_jobs as dynamic
import product_features as product


class ManagedStateIsolation(dynamic.DynamicJobs):
    def test_managed_state_boundary(self):
        f = self.f
        managed = f.base / ".veyl-login"
        managed.mkdir(mode=0o700)
        secret = managed / "synthetic.json"
        secret.write_text("managed-control-plane-canary")
        secret.chmod(0o600)
        control = socket.socket(socket.AF_UNIX)
        self.addCleanup(control.close)
        control.bind(str(managed / "control.sock"))
        (managed / "control.sock").chmod(0o600)
        control.listen(1)
        outside = f.base / "outside.txt"
        outside.write_text("ordinary-broad-file")
        subprocess.run([product.BIN, "mode", "yolo", "primary", "--config", f.config],
                       env=dict(os.environ, HOME=str(f.base)), check=True,
                       capture_output=True, timeout=10)
        self.assertEqual(f.call("read_file", {"path": str(outside)}, self.session)
                         ["content"][0]["text"], "ordinary-broad-file")
        self.assertTrue(f.call("read_file", {"path": str(secret)}, self.session)["isError"])
        self.assertTrue(f.call("write_file", {"path": str(secret), "content": "bad"},
                               self.session)["isError"])
        command = ("test -e " + shlex.quote(str(outside)) + " && test ! -e "
                   + shlex.quote(str(secret)) + " && test ! -e "
                   + shlex.quote(str(managed / "control.sock")) + " && printf masked")
        result = self.call("exec_command", {"command": command, "timeout_seconds": 8})
        self.assertEqual(result["exit_code"], 0, result)
        self.assertEqual(result["stdout"], "masked")
        self.assertEqual(secret.read_text(), "managed-control-plane-canary")


if __name__ == "__main__":
    suite = unittest.TestSuite([ManagedStateIsolation("test_managed_state_boundary")])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
