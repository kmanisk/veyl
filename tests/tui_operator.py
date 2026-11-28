#!/usr/bin/env python3
"""Paired monitor in a disposable tmux PTY. Capture rendered terminal frames."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
import unittest

import product_features as product


class OperatorMonitor(unittest.TestCase):
    def test_views_resize_and_actions(self):
        f = product.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.doc.update(policy_version=4, default_mode="standard", job_state_dir=str(f.base / "jobs"),
                     job_profiles={"long":{"executable":"/usr/bin/sleep","args":["45"],"timeout_seconds":60}})
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False)
        f.doc["clients"][0]["tools"] += ["job_start","job_cancel","job_status"]
        f.write_config()
        f.start()
        session = f.connect()
        job = f.call("job_start", {"profile":"long"}, session)
        self.assertFalse(job["isError"], job)
        job = json.loads(job["content"][0]["text"])["job_id"]
        goal = subprocess.run([product.BIN, "goal", "create", "--client", "primary", "--config", f.config],
            input=json.dumps({"description":"Resize-safe roadmap","request_id":"pty-run",
                              "acceptance_criteria":[{"description":"Keep the selected row"}]}),
            capture_output=True,text=True,check=True,timeout=8)
        goal = json.loads(goal.stdout)["id"]
        tmux = ["tmux","-S",str(f.base / "tmux.sock"),"-f","/dev/null"]
        self.addCleanup(lambda: subprocess.run(tmux + ["kill-server"],capture_output=True,timeout=5))
        def cmd(*args):
            return subprocess.check_output(tmux + list(args), text=True, timeout=6, stderr=subprocess.STDOUT)
        open_monitor = [product.BIN, "tui", "--listen", f"127.0.0.1:{f.admin}", "--client", "primary"]
        pair = [product.BIN, "dashboard", "pair", "--config", f.config]
        cmd("new-session","-d","-x","124","-y","32","-s","operator",
            shlex.join(map(str, pair)) + " | " + shlex.join(map(str, open_monitor)))
        def frame():
            return cmd("capture-pane","-pt","operator")
        def until(*fragments):
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                text = frame()
                if all(fragment in text for fragment in fragments):
                    return text
                time.sleep(.07)
            self.fail(f"Missing {fragments!r} from terminal:\n{text}")
        def keys(*values):
            cmd("send-keys","-t","operator",*values)
        def save(name, text):
            directory = os.environ.get("VEYL_TUI_FRAMES")
            if directory:
                (Path(directory) / (name + ".txt")).write_text(text)
        baseline = bool(os.environ.get("VEYL_TUI_BASELINE"))
        until("Activity")
        keys("2")
        wide = until(job, "running") if baseline else until(job[:8], "sleep")
        if not baseline:
            self.assertNotIn(job, wide)
        save("jobs-124", wide)
        cmd("resize-window","-t","operator","-x","54","-y","21")
        narrow = until(job if baseline else job[:8])
        save("jobs-54", narrow)
        if not baseline:
            self.assertIn("sleep", narrow)
            self.assertIn("s Sort", narrow)
            self.assertIn("q Quit", narrow)
            keys("Enter")
            until(job[:18])
            cmd("resize-window","-t","operator","-x","23","-y","8")
            until("resize terminal")
            cmd("resize-window","-t","operator","-x","124","-y","32")
            until(job)
            keys("Escape")
            until("Veyl / jobs")
        cmd("resize-window","-t","operator","-x","124","-y","32")
        for index, label in [(1,"activity"),(3,"health"),(4,"clients"),(5,"skills"),(6,"upstreams"),(7,"integrations")]:
            keys(str(index))
            until("Veyl / " + label)
        keys("8")
        until("Resize-safe roadmap")
        keys("Enter")
        save("goals-124", until("Keep the selected row"))
        if not baseline:
            keys("Escape")
            until("Veyl / goals")
            keys("P")
            until("paused")
            keys("R")
            until("running")
            keys("C","y")
            until("cancelled")
            self.assertEqual(json.loads(f.cli("goal","get",goal))["state"],"cancelled")
            keys("4")
            until("Veyl / clients", "Bearer")
            keys("Y","y")
            until("yolo")
            self.assertIn("\tyolo\t", f.cli("mode","list"))
            keys("S","y")
            until("standard")
            deadline = time.monotonic() + 6
            while "\tyolo\t" in f.cli("mode","list"):
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.08)
            keys("2")
            until(job[:8])
            keys("x","y")
            until("canceled")
        keys("q")


if __name__ == "__main__":
    unittest.main(verbosity=2)
