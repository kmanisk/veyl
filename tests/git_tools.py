#!/usr/bin/env python3
"""End-to-end and security acceptance suite for the 12 structured Git tools."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import product_features as pf


def git(cwd: Path, *args: str) -> str:
    r = subprocess.run(["/usr/bin/git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return r.stdout.strip()


class GitToolsTests(unittest.TestCase):
    def setUp(self):
        self.f = pf.ProductFeatures()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        state = self.f.base / "private-state"
        state.mkdir(mode=0o700)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        self.f.audit = state / "audit.jsonl"
        self.f.audit.touch(mode=0o600)
        self.f.config = state / "clients.json"
        self.f.doc["audit_log"] = str(self.f.audit)
        self.f.doc["job_state_dir"] = str(jobs)
        self.f.doc["job_profiles"] = {"probe": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 8, "max_output_bytes": 128}}
        self.repo = Path(self.f.doc["clients"][0]["root"])
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.name", "Test")
        git(self.repo, "config", "user.email", "test@example.com")
        (self.repo / "a.txt").write_text("hello\n")
        git(self.repo, "add", "a.txt")
        git(self.repo, "commit", "-m", "initial")

    def start(self, tools, broad=False):
        self.f.doc["policy_version"] = 4
        for client in self.f.doc["clients"]:
            client["mode"] = "standard"
            client["disabled"] = False
        primary = self.f.doc["clients"][0]
        primary["tools"] = tools
        self.f.write_config()
        if broad:
            self.f.cli("mode", "yolo", primary["id"], "--confirm-native")
        proc = self.f.start()
        self.addCleanup(self.f.stop, proc)
        return self.f.connect(token=pf.TOKEN)

    def call(self, session, name, args, error=False):
        res = self.f.call(name, args, session, token=pf.TOKEN)
        self.assertEqual(res.get("isError", False), error, f"{name}({args}) -> {res}")
        text = res["content"][0]["text"]
        return text if error else json.loads(text)

    def test_all_local_git_tools_end_to_end_and_hook_safety(self):
        marker = self.f.base / "hook-executed.marker"
        hooks = self.repo / ".git/hooks"
        hooks.mkdir(exist_ok=True)
        for hook in ("pre-commit", "post-checkout"):
            p = hooks / hook
            p.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
            p.chmod(0o755)
        git(self.repo, "config", "core.fsmonitor", f"touch {marker}")
        git(self.repo, "config", "diff.external", f"touch {marker}; true")

        all_git = [
            "git_status", "git_diff", "git_log", "git_add", "git_commit",
            "git_branch", "git_checkout", "git_restore", "git_stash",
            "git_reset", "git_pull", "git_push",
        ]
        sess = self.start(all_git)

        st = self.call(sess, "git_status", {})
        self.assertIn("main", st["output"])

        (self.repo / "a.txt").write_text("hello\nworld\n")
        (self.repo / "b.txt").write_text("new file\n")
        diff_unstaged = self.call(sess, "git_diff", {"file": "a.txt"})
        self.assertIn("+world", diff_unstaged["output"])

        self.call(sess, "git_add", {"files": ["a.txt"]})
        diff_staged = self.call(sess, "git_diff", {"staged": True})
        self.assertIn("+world", diff_staged["output"])

        c1 = self.call(sess, "git_commit", {"message": "second commit", "stage_all": True})
        self.assertEqual(c1["message"], "second commit")
        log = self.call(sess, "git_log", {"count": 5})
        self.assertGreaterEqual(len(log["commits"]), 2)
        self.assertIn("second commit", log["commits"][0])

        self.call(sess, "git_branch", {"action": "create-and-switch", "name": "feature/x"})
        branches = self.call(sess, "git_branch", {"action": "list"})
        self.assertIn("feature/x", branches["output"])
        self.call(sess, "git_checkout", {"branch": "main"})

        (self.repo / "a.txt").write_text("stashed edit\n")
        self.call(sess, "git_stash", {"action": "push", "message": "wip"})
        stashes = self.call(sess, "git_stash", {"action": "list"})
        self.assertIn("wip", stashes["output"])
        self.call(sess, "git_stash", {"action": "pop"})
        self.assertEqual((self.repo / "a.txt").read_text(), "stashed edit\n")

        self.call(sess, "git_restore", {"files": ["a.txt"]}, error=True)
        self.call(sess, "git_restore", {"files": ["a.txt"], "confirm": True})
        self.assertEqual((self.repo / "a.txt").read_text(), "hello\nworld\n")

        (self.repo / "a.txt").write_text("dirty\n")
        self.call(sess, "git_reset", {"mode": "hard"}, error=True)
        self.call(sess, "git_reset", {"mode": "hard", "confirm": True})
        self.assertEqual((self.repo / "a.txt").read_text(), "hello\nworld\n")

        self.call(sess, "git_pull", {"confirm": True}, error=True)
        self.call(sess, "git_push", {"confirm": True}, error=True)

        for bad in (
            ("git_diff", {"file": "../outside"}),
            ("git_add", {"files": ["--all"]}),
            ("git_add", {"files": [":(top)secret"]}),
            ("git_branch", {"action": "create", "name": "-evil"}),
            ("git_push", {"remote": "ext::sh", "confirm": True}),
        ):
            self.call(sess, bad[0], bad[1], error=True)

        self.assertFalse(marker.exists(), "Git hook or external helper unexpectedly executed!")

    def test_standard_exact_grants_and_yolo_git_preset(self):
        sess = self.start(["git_status"])
        self.call(sess, "git_status", {})
        for denied in ("git_diff", "git_log", "git_add", "git_commit"):
            self.call(sess, denied, {} if denied != "git_commit" else {"message": "x"}, error=True)

        yolo_sess = self.start(["read_file"], broad=True)
        listed = {t["name"] for t in self.f.rpc("tools/list", yolo_sess, pf.TOKEN)[1]["result"]["tools"]}
        self.assertTrue({"git_status", "git_diff", "git_log"}.issubset(listed))
        self.assertTrue({"git_add", "git_commit", "git_reset", "git_push", "git_pull"} <= listed)

    def test_broad_yolo_remote_push_and_pull_loopback_http(self):
        backend = Path("/usr/lib/git-core/git-http-backend")
        if not backend.is_file():
            self.skipTest("git-http-backend unavailable")
        bare = self.f.base / "remote.git"
        git(self.f.base, "init", "--bare", str(bare))
        git(bare, "config", "http.receivepack", "true")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self_h):
                self_h.cgi(b"")

            def do_POST(self_h):
                length = int(self_h.headers.get("Content-Length", "0"))
                self_h.cgi(self_h.rfile.read(length))

            def cgi(self_h, body):
                path_info, _, qs = self_h.path.partition("?")
                env = {
                    "GIT_PROJECT_ROOT": str(bare.parent),
                    "GIT_HTTP_EXPORT_ALL": "1",
                    "PATH_INFO": path_info,
                    "QUERY_STRING": qs,
                    "REQUEST_METHOD": self_h.command,
                    "CONTENT_TYPE": self_h.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": str(len(body)),
                    "PATH": "/usr/bin:/bin",
                }
                res = subprocess.run([str(backend)], input=body, env=env, capture_output=True)
                raw = res.stdout
                head, _, payload = raw.partition(b"\r\n\r\n")
                if not payload and b"\n\n" in raw:
                    head, _, payload = raw.partition(b"\n\n")
                status = 200
                headers = {}
                for line in head.decode("latin1").splitlines():
                    if line.lower().startswith("status:"):
                        status = int(line.split()[1])
                    elif ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()
                self_h.send_response(status)
                for k, v in headers.items():
                    self_h.send_header(k, v)
                self_h.end_headers()
                self_h.wfile.write(payload)

            def log_message(self_h, *_args):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_port}/remote.git"
        git(self.repo, "remote", "add", "origin", url)

        sess = self.start(["git_push", "git_pull", "git_log"], broad=True)
        self.call(sess, "git_push", {"remote": "origin", "branch": "main"}, error=True)
        pushed = self.call(sess, "git_push", {"remote": "origin", "branch": "main", "set_upstream": True, "confirm": True})
        self.assertEqual(pushed["remote"], "origin")
        self.assertIn("initial", git(bare, "log", "--oneline", "main"))

        other = self.f.base / "other-clone"
        git(self.f.base, "clone", str(bare), str(other))
        git(other, "config", "user.name", "Other")
        git(other, "config", "user.email", "other@example.com")
        (other / "remote.txt").write_text("from remote\n")
        git(other, "add", "remote.txt")
        git(other, "commit", "-m", "remote commit")
        git(other, "push", "origin", "main")

        self.call(sess, "git_pull", {"remote": "origin", "branch": "main"}, error=True)
        pulled = self.call(sess, "git_pull", {"remote": "origin", "branch": "main", "confirm": True})
        self.assertEqual(pulled["remote"], "origin")
        self.assertTrue((self.repo / "remote.txt").is_file())


if __name__ == "__main__":
    unittest.main()
