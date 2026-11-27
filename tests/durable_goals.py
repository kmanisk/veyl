#!/usr/bin/env python3
"""Durable goals exercise real MCP permissions, restart, and operator routes."""

import json
import subprocess
import time
import unittest

import product_features as product


class DurableGoals(unittest.TestCase):
    def setUp(self):
        self.f = f = product.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.doc.update(policy_version=4, job_state_dir=str(f.base / "jobs"), job_profiles={
            "health": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 4},
        })
        tools = ["goal_" + name for name in ("create", "get", "list", "update", "checkpoint",
                                              "next", "pause", "resume", "complete", "cancel")]
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False, tools=tools)
        f.write_config()
        subprocess.run([product.BIN, "mode", "yolo", "primary", "--confirm-native", "--config", f.config],
                       capture_output=True, check=True, timeout=5)
        self.gateway = f.start()
        self.session = f.connect()
        self.other = f.connect(product.OTHER_TOKEN)

    def call(self, name, args, *, other=False, fail=False):
        result = self.f.call(name, args, self.other if other else self.session,
                             product.OTHER_TOKEN if other else product.TOKEN)
        self.assertEqual(result["isError"], fail, result)
        return result if fail else json.loads(result["content"][0]["text"])

    def test_goal_progress_and_cross_session_handoff(self):
        f = self.f
        create = {"request_id": "prepare", "description": "Verify durable goals",
                  "acceptance_criteria": [{"description": "Observe job output"}],
                  "roadmap": [{"id": "verify", "description": "Verify",
                               "subtasks": [{"id": "build", "description": "Run command"}]}]}
        first = self.call("goal_create", create)
        gid = {"goal_id": first["id"]}
        self.assertEqual(self.call("goal_create", create)["id"], first["id"])
        self.call("goal_create", dict(create, description="Different"), fail=True)
        self.call("goal_get", gid, other=True, fail=True)
        self.assertEqual(self.call("goal_list", {}, other=True)["goals"], [])
        self.assertEqual(self.call("goal_next", gid)["task"]["id"], "build")
        self.call("goal_complete", dict(gid, revision=1), fail=True)
        self.call("goal_update", dict(gid, revision=1, jobs=["a" * 32]), fail=True)
        job = self.call("exec_command", {"command": "printf verified", "timeout_seconds": 5})
        second = self.call("goal_update", dict(gid, revision=1, state="running", active_task="build",
                                               jobs=[job["job_id"]], decisions=["Reuse runner"]))
        self.call("goal_update", dict(gid, revision=1, progress="stale"), fail=True)
        handoff = {"completed_work": "Command ran", "outstanding_work": "Record evidence",
                   "test_results": "Exit 0", "next_action": "Read linked job logs", "jobs": [job["job_id"]]}
        third = self.call("goal_checkpoint", dict(gid, revision=second["revision"], handoff=handoff))
        headers = f.pair()
        status, _, body = f.request(f.admin, "GET", "/api/dashboard/goals?" +
                                    f"goal_id={first['id']}&job_id={job['job_id']}", **headers)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["stdout"], "verified")
        status, _, body = f.request(f.admin, "POST", "/api/dashboard/goals",
                                    dict(gid, action="pause", revision=third["revision"]), **headers)
        self.assertEqual(status, 200, body)
        self.assertIsNone(self.call("goal_next", gid)["task"])
        f.stop(self.gateway)
        self.gateway = f.start()
        self.session = f.connect()
        next_step = self.call("goal_next", gid)
        self.assertEqual(next_step["checkpoint"]["handoff"], dict(handoff, files=[], commits=[]))
        self.assertEqual(next_step["state"], "paused")
        resumed = self.call("goal_resume", dict(gid, revision=next_step["revision"]))
        complete = self.call("goal_update", dict(gid, revision=resumed["revision"], active_task="",
            roadmap=[{"id": "verify", "description": "Verify", "completed": True}],
            acceptance_criteria=[{"description": "Observe job output", "evidence": "Job exit 0 and stdout verified"}]))
        final = self.call("goal_complete", dict(gid, revision=complete["revision"]))
        self.assertEqual(final["state"], "completed")
        self.assertIsNotNone(final["completed_at"])
        token = f.cli("dashboard", "pair")
        monitor = subprocess.run([product.BIN, "monitor", "--listen", f"127.0.0.1:{f.admin}",
                                  "--view", "goals"], input=token, capture_output=True, text=True, timeout=8)
        self.assertEqual(monitor.returncode, 0, monitor.stderr)
        self.assertIn(first["id"], monitor.stdout)
        cli = json.loads(f.cli("goal", "get", first["id"]))
        self.assertEqual(cli["revision"], final["revision"])

    def test_corrupt_and_interrupted_storage(self):
        args = {"request_id": "corruption", "description": "Protect interrupted goal state",
                "acceptance_criteria": [{"description": "Check corruption detection"}]}
        goal = self.call("goal_create", args)
        path = self.f.config.parent / ("." + self.f.config.name + ".goals") / "goals.json"
        before = path.read_text()
        (path.parent / ".stage-interrupted").write_text("partial")
        self.assertEqual(self.call("goal_get", {"goal_id": goal["id"]})["revision"], 1)
        path.write_text('{"version":1,"version":1,"goals":{}}')
        self.call("goal_create", args, fail=True)
        self.assertIn('"version":1,"version":1', path.read_text())
        path.write_text(before)
        cancelled = self.call("goal_cancel", {"goal_id": goal["id"], "revision": 1})
        self.assertEqual(cancelled["state"], "cancelled")

    def test_long_native_job_survives_gateway_restart(self):
        args = {"command": "printf ready; sleep 900", "wait_seconds": 0, "request_id": "long-build"}
        started = self.call("task_run", args)
        jid = {"job_id": started["job_id"]}
        until = time.monotonic() + 6
        while "ready" not in self.call("job_logs", jid)["stdout"]:
            self.assertLess(time.monotonic(), until)
            time.sleep(.05)
        self.f.stop(self.gateway)
        self.gateway = self.f.start()
        self.session = self.f.connect()
        replay = self.call("task_run", args)
        self.assertEqual(replay["job_id"], started["job_id"])
        self.assertTrue(replay["idempotent_replay"])
        status = self.call("job_cancel", jid)
        self.assertEqual(status["state"], "canceled", status)


if __name__ == "__main__":
    unittest.main()
