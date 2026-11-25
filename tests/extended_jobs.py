#!/usr/bin/env python3
"""Real HTTP, kernel-sandbox and systemd acceptance for operator-approved extended jobs.

Requires a working unprivileged systemd user manager and existing Veyl isolation.
No production credentials, state, listener, or service are used.
"""
import json
import time
import unittest

import product_features as product


class ExtendedJobs(unittest.TestCase):
    def setUp(self):
        self.f = f = product.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        state = f.base / "private-state"
        state.mkdir(mode=0o700)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        f.config = state / "clients.json"
        f.audit = state / "audit.jsonl"
        f.audit.touch(mode=0o600)
        f.doc.update(
            policy_version=3, audit_log=str(f.audit), job_state_dir=str(jobs),
            job_profiles={
                "extended": {"executable": "/usr/bin/sh",
                             "args": ["-c", "printf ready; sleep 30; printf done"],
                             "timeout_seconds": 86400, "extended_runtime": True,
                             "max_output_bytes": 4096},
                "complete": {"executable": "/usr/bin/sh",
                             "args": ["-c", "printf completed"],
                             "timeout_seconds": 7200, "extended_runtime": True},
                "short": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 5},
            },
        )
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False, tools=[
                "read_file", "job_start", "job_status", "job_logs", "job_cancel",
                "job_wait", "exec_command", "task_run", "run_command",
            ])
        f.doc["clients"][0]["job_runtime_limit_seconds"] = 86400
        f.write_config()
        self.process = f.start()
        self.session = f.connect()
        self.other = f.connect(product.OTHER_TOKEN)

    def call(self, tool, args, *, other=False, error=False):
        result = self.f.call(tool, args, self.other if other else self.session,
                             product.OTHER_TOKEN if other else product.TOKEN)
        self.assertEqual(result["isError"], error, result)
        return result if error else json.loads(result["content"][0]["text"])

    def await_state(self, job, states, seconds=5):
        deadline = time.monotonic() + seconds
        while True:
            status = self.call("job_status", {"job_id": job})
            if status["state"] in states:
                return status
            self.assertLess(time.monotonic(), deadline, status)
            time.sleep(.05)

    def test_extended_profile_completion_and_dynamic_budget_not_expanded(self):
        self.call("exec_command", {"command": "true", "timeout_seconds": 301}, error=True)
        for name in ("exec_command", "task_run"):
            self.call(name, {"command": "true", "extended_runtime": True}, error=True)
            self.call(name, {"command": "true", "timeout_seconds": 301}, other=True, error=True)
        self.call("job_start", {"profile": "complete"}, other=True, error=True)
        self.call("task_run", {"command": "true", "timeout_seconds": 86401}, error=True)
        for session, token, expected in ((self.session, product.TOKEN, 86400),
                                         (self.other, product.OTHER_TOKEN, 300)):
            _, listing = self.f.rpc("tools/list", session, token)
            task = next(t for t in listing["result"]["tools"] if t["name"] == "task_run")
            self.assertEqual(task["inputSchema"]["properties"]["timeout_seconds"]["maximum"], expected)
        result = self.call("job_start", {"profile": "complete", "request_id": "extended-complete"})
        job = result["job_id"]
        self.addCleanup(self.call, "job_cancel", {"job_id": job})
        self.assertEqual(result["timeout_seconds"], 7200)
        terminal = self.await_state(job, {"completed", "failed", "timed_out"})
        self.assertEqual(terminal["exit_code"], 0, terminal)
        self.assertEqual(terminal["resource_ceilings"]["memory_bytes"], 268435456)
        self.assertEqual(self.call("job_logs", {"job_id": job})["stdout"], "completed")
        replay = self.call("job_start", {"profile": "complete", "request_id": "extended-complete"})
        self.assertEqual(replay["job_id"], job)
        self.assertTrue(replay["idempotent_replay"])
        # Caller-selected tasks use the exact same signed runner, but only
        # when the local operator assigned the client a larger budget.
        args = {"command": "printf arbitrary-task", "timeout_seconds": 7200,
                "wait_seconds": 0, "request_id": "long-task"}
        dynamic = self.call("task_run", args)
        self.addCleanup(self.call, "job_cancel", {"job_id": dynamic["job_id"]})
        self.assertEqual(dynamic["timeout_seconds"], 7200)
        done = self.await_state(dynamic["job_id"], {"completed", "failed"})
        self.assertEqual(done["exit_code"], 0, done)
        self.assertEqual(self.call("job_logs", {"job_id": dynamic["job_id"]})["stdout"], "arbitrary-task")
        # Runtime limit reduction is effective on the next admission,
        # even in the session which discovered the larger schema.
        self.f.doc["clients"][0].pop("job_runtime_limit_seconds")
        self.f.write_config()
        self.call("task_run", {"command": "true", "timeout_seconds": 301}, error=True)
        self.call("job_start", {"profile": "complete"}, error=True)

    def test_24h_budget_session_recovery_restart_and_cancel(self):
        args = {"profile": "extended", "request_id": "extended-recover"}
        result = self.call("job_start", args)
        job = result["job_id"]
        self.addCleanup(self.call, "job_cancel", {"job_id": job})
        self.assertEqual(result["timeout_seconds"], 86400)
        running = self.await_state(job, {"running"})
        self.assertEqual(running["resource_ceilings"]["cpu_percent"], 100)
        self.assertIsInstance(running["live_elapsed_ms"], int)
        self.session = self.f.connect()
        self.call("job_status", {"job_id": job}, other=True, error=True)
        self.call("job_cancel", {"job_id": job}, other=True, error=True)
        self.assertEqual(self.call("job_start", args)["job_id"], job)
        deadline = time.monotonic() + 4
        while True:
            log = self.call("job_logs", {"job_id": job, "stdout_offset": 0, "stderr_offset": 0})
            if log["stdout"] == "ready":
                break
            self.assertLess(time.monotonic(), deadline, log)
            time.sleep(.05)
        # A runner admitted by the old HTTP instance must not be duplicated.
        self.f.stop(self.process)
        self.process = self.f.start()
        self.session = self.f.connect()
        self.other = self.f.connect(product.OTHER_TOKEN)
        recovered = self.call("job_status", {"job_id": job})
        self.assertEqual(recovered["state"], "uncertain", recovered)
        self.assertEqual(recovered["timeout_seconds"], 86400)
        self.assertEqual(self.call("job_start", args)["job_id"], job)
        self.call("job_cancel", {"job_id": job})
        final = self.await_state(job, {"canceled", "completed", "failed", "timed_out"})
        self.assertEqual(final["state"], "canceled", final)
        self.assertTrue(final["cancel_requested"])
        self.assertEqual(self.call("job_logs", {"job_id": job})["stdout"], "ready")


if __name__ == "__main__":
    unittest.main()
