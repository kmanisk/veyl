#!/usr/bin/env python3
"""Exercise public writable admission and real aggregate ENOSPC in a private mount namespace.

Never mounts anything in the operator's host namespace. The bounded fixture is
only 1 MiB and uses the existing fake Funnel daemon (no public ingress).
"""
import os
import pathlib
import subprocess
import sys
import unittest
import json

PARENT_MOUNT = "VEYL_TEST_PARENT_MOUNT_NS"
PARENT_USER = "VEYL_TEST_PARENT_USER_NS"

# Re-exec before importing the fixture: its legacy CLI parser consumes argv[1].
if __name__ == "__main__" and "--private-namespace" not in sys.argv:
    env = dict(os.environ)
    env[PARENT_MOUNT] = os.readlink("/proc/self/ns/mnt")
    env[PARENT_USER] = os.readlink("/proc/self/ns/user")
    os.execve("/usr/bin/unshare", [
        "/usr/bin/unshare", "--user", "--map-current-user", "--mount",
        "--propagation", "private", "--keep-caps", "--",
        sys.executable, "-B", __file__, *sys.argv[1:], "--private-namespace",
    ], env)

import oauth_funnel as funnel

class BoundedWorkspace(funnel.Funnel):
    def test_bounded_filesystem(self):
        for name, key in (("mnt", PARENT_MOUNT), ("user", PARENT_USER)):
            self.assertIn(key, os.environ)
            self.assertNotEqual(os.readlink("/proc/self/ns/" + name), os.environ[key])
        self.assertNotEqual(os.geteuid(), 0)
        # The fixture's parent and all mounts are private in the new namespace.
        for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines():
            fields = line.split(" - ", 1)[0].split()[6:]
            self.assertFalse(any(x.startswith(("shared:", "master:")) for x in fields))
        mount = ["/usr/bin/mount", "-t", "tmpfs", "-o",
                 f"size=1m,nr_inodes=64,mode=0700,uid={os.getuid()},gid={os.getgid()},nosuid,nodev",
                 "tmpfs", str(self.root)]
        subprocess.run(mount, check=True, timeout=5)
        self.addCleanup(lambda: subprocess.run(["/usr/bin/umount", str(self.root)], check=True, timeout=5))
        self.addCleanup(self.f.cleanup_server)
        (self.root / "canary.txt").write_text("native-read-canary")
        stats = os.statvfs(self.root)
        self.assertEqual(stats.f_blocks * stats.f_frsize, 1024 * 1024)
        self.assertEqual(stats.f_files, 64)
        self.launch(self.command(extra=["--workspace-tools"]))
        self.config = self.profile / "clients.json"
        self.wait_for(lambda: len(self.daemon.snapshot()["Foreground"]) == 2)
        client = self.f.register()
        handle = self.f.pending(client)
        info = self.cli("inspect", {"request": handle})
        self.assertTrue(info["eligible"], info)
        self.assertEqual(info["native_scope"]["bounded_workspace"]["backend"], "tmpfs")
        args = self.exact("approve", handle, info)
        args.pop("action")
        self.cli("approve", args, success=False)
        args["scope_fingerprint"] = info["scope_fingerprint"]
        self.assertTrue(self.cli("approve", args)["approved"])
        token = self.f.capture_tokens(self.f.exchange(client, self.delivered(handle)))["access_token"]
        session = self.connect(token)
        def write(name, value):
            status, _, body = self.rpc(token, "tools/call", session, {
                "name":"write_file","arguments":{"path":name,"content":value}})
            self.assertEqual(status, 200, body)
            return json.loads(body)["result"]
        # Bounded individual writes must eventually hit the aggregate cap.
        count = 0
        for i in range(32):
            name = f"block-{i}.txt"
            result = write(name, "x" * 65536)
            if result.get("isError"):
                break
            count += 1
            self.assertEqual((self.root / name).stat().st_size, 65536)
        self.assertGreaterEqual(count, 8)
        self.assertLess(count, 32)
        self.assertLess(os.statvfs(self.root).f_bavail * stats.f_frsize, 65536)
        self.assertEqual((self.base / "outside.txt").read_text(), "outside-denied-canary")
        self.stop_funnel()

if __name__ == "__main__":
    suite = unittest.TestSuite([BoundedWorkspace("test_bounded_filesystem")])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
