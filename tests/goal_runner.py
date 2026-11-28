#!/usr/bin/env python3
"""Black-box goal controller and signed-job runs using a local test adapter."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

BIN = Path(os.environ["MCP_GATEWAY_BIN"]).resolve()

ADAPTER = """#!/usr/bin/python3
import json, pathlib, sys, time
context = json.loads(''.join(sys.argv[1:]))
iteration = context['iteration']
with pathlib.Path('attempts').open('a') as stream: stream.write(str(iteration) + '\\n')
objective = context['objective']
plan = [
    {'id': 'fix', 'description': 'Correct the failed implementation', 'completed': False},
    {'id': 'verify', 'description': 'Verify the real fixture', 'completed': False},
]
if objective == 'wait': time.sleep(30)
if objective == 'recover':
    time.sleep(3)
    iteration = 3
if objective == 'fail':
    print('synthetic failed verification', file=sys.stderr)
    sys.exit(1)
if objective == 'stagnant':
    print(json.dumps({'progress': 'No observable change'}))
    sys.exit(0)
if objective == 'budget' or iteration == 1:
    print(json.dumps({'progress': 'Initialized roadmap', 'roadmap': plan}))
elif iteration == 2:
    print('test failed; expected repaired bytes', file=sys.stderr)
    sys.exit(1)
else:
    pathlib.Path('result').write_text('corrected')
    assert pathlib.Path('result').read_text() == 'corrected'
    for item in plan: item['completed'] = True
    criteria = context['acceptance_criteria']
    criteria[0]['evidence'] = 'File contains corrected after reading it back'
    print(json.dumps({'progress': 'Corrected and verified', 'roadmap': plan, 'acceptance_criteria': criteria,
        'checkpoint': {'completed_work':'corrected fixture','outstanding_work':'none',
            'test_results':'file read verified','next_action':'complete'}}))
"""


class GoalRunner(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix="veyl-goal-runner-")
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.env = dict(os.environ, HOME=str(self.home), XDG_RUNTIME_DIR=str(self.root / "no-manager"))
        self.adapter = self.root / "adapter"
        self.adapter.write_text(ADAPTER)
        self.adapter.chmod(0o700)
        self.cli("init", "--root", self.workspace)

    def cli(self, *args, success=True, timeout=25):
        result = subprocess.run([BIN, *args], env=self.env, capture_output=True, text=True, timeout=timeout)
        self.assertEqual(result.returncode == 0, success, (args, result.stdout, result.stderr))
        return result

    def create(self, objective):
        result = self.cli("goal", "create", objective, "--criterion", "Verify the expected fixture")
        return json.loads(result.stdout)["id"]

    def get(self, goal):
        return json.loads(self.cli("goal", "get", goal).stdout)

    def authorize(self):
        self.cli("mode", "yolo", "dev", "--yes")

    def args(self, goal, action="run"):
        return ["goal", action, goal, "--runner", self.adapter, "--confirm-runner"]

    def launch(self, goal):
        process = subprocess.Popen([BIN, *self.args(goal)], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            for handle in (process.stdout, process.stderr):
                handle.close()
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail(process.communicate()[1])
            result = subprocess.run([BIN, "goal", "get", goal], env=self.env, capture_output=True, text=True)
            if result.returncode == 0:
                active = json.loads(result.stdout).get("execution", {}).get("active")
                if active and active["job_id"] and (self.workspace / "attempts").exists():
                    return process, active["job_id"]
            time.sleep(.08)
        self.fail("Expected an attached durable job")

    def test_01_correction_and_completion_require_explicit_runner_and_yolo(self):
        goal = self.create("correct")
        self.assertEqual(goal, self.create("correct"))
        self.assertIn("confirm-runner", self.cli("goal", "run", goal, "--runner", self.adapter, success=False).stderr)
        self.assertIn("static YOLO", self.cli(*self.args(goal), success=False).stderr)
        self.assertFalse((self.workspace / "attempts").exists())
        self.authorize()
        result = json.loads(self.cli(*self.args(goal)).stdout)
        self.assertEqual(result["state"], "completed")
        self.assertEqual([x["outcome"] for x in result["execution"]["history"]], ["progress", "failed", "completed"])
        self.assertEqual(len(set(result["jobs"])), 3)
        self.assertEqual((self.workspace / "attempts").read_text().splitlines(), ["1", "2", "3"])
        self.assertEqual(result["checkpoints"][-1]["handoff"]["test_results"], "file read verified")
        self.assertEqual(result["acceptance_criteria"][0]["evidence"], "File contains corrected after reading it back")
        self.assertEqual(self.get(goal), result)

    def test_02_limits_and_explicit_retry(self):
        self.authorize()
        goal = self.create("budget")
        outcome = json.loads(self.cli(*self.args(goal), "--iterations", "1").stdout)
        self.assertEqual(outcome["state"], "paused")
        self.assertIn("budget", outcome["execution"]["stop_reason"])
        self.assertEqual(json.loads(self.cli(*self.args(goal)).stdout), outcome)
        second = json.loads(self.cli(*self.args(goal, "retry"), "--iterations", "1").stdout)
        self.assertEqual([t["number"] for t in second["execution"]["history"]], [1, 2])
        goal = self.create("fail")
        outcome = json.loads(self.cli(*self.args(goal), "--retries", "1").stdout)
        self.assertEqual(len(outcome["jobs"]), 2)
        self.assertIn("retry budget", outcome["execution"]["stop_reason"])
        goal = self.create("stagnant")
        outcome = json.loads(self.cli(*self.args(goal)).stdout)
        self.assertEqual(len(outcome["jobs"]), 3)
        self.assertIn("no verifiable progress", outcome["execution"]["stop_reason"])

    def test_deadline_stops_the_active_turn(self):
        self.authorize()
        goal = self.create("wait")
        started = time.monotonic()
        outcome = json.loads(self.cli(*self.args(goal), "--seconds", "2").stdout)
        self.assertLess(time.monotonic() - started, 12)
        self.assertEqual(outcome["state"], "paused")
        self.assertEqual(len(outcome["jobs"]), 1)
        self.assertEqual(outcome["execution"]["history"][-1]["outcome"], "timed_out")
        self.assertIn("time limit", outcome["execution"]["stop_reason"])
        self.assertEqual(self.get(goal), outcome)

    def test_03_restart_reconciles_without_a_duplicate_launch(self):
        self.authorize()
        goal = self.create("recover")
        process, job = self.launch(goal)
        self.assertIn("already owns", self.cli(*self.args(goal), success=False).stderr)
        process.send_signal(signal.SIGKILL)
        process.communicate(timeout=5)
        result = json.loads(self.cli(*self.args(goal)).stdout)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["jobs"], [job], result)
        self.assertEqual((self.workspace / "attempts").read_text(), "1\n")

    def test_04_detached_pause_retry_and_cancel(self):
        self.authorize()
        goal = self.create("wait")
        process, job = self.launch(goal)
        process.kill()
        process.communicate(timeout=5)
        paused = json.loads(self.cli("goal", "pause", goal).stdout)
        self.assertEqual(paused["state"], "paused")
        self.assertEqual(paused["jobs"], [job])
        reconciled = json.loads(self.cli(*self.args(goal)).stdout)
        self.assertEqual(reconciled["execution"]["history"][-1]["outcome"], "paused")
        self.assertEqual((self.workspace / "attempts").read_text(), "1\n")
        self.cli("goal", "resume", goal)
        resumed, next_job = self.launch(goal)
        self.assertNotEqual(job, next_job)
        self.assertEqual(json.loads(self.cli("goal", "cancel", goal).stdout)["state"], "cancelled")
        output, error = resumed.communicate(timeout=12)
        self.assertEqual(resumed.returncode, 0, error)
        self.assertEqual(json.loads(output)["execution"]["history"][-1]["outcome"], "cancelled")


if __name__ == "__main__":
    unittest.main(verbosity=2)
