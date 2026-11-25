#!/usr/bin/env python3
"""Verify caller-selected commands use the real sandbox and durable job runner."""

from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import struct
import subprocess
import termios
import time
import unittest

import product_features as product


class DynamicJobs(unittest.TestCase):
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
            job_profiles={"probe": {"executable": "/usr/bin/true", "args": [],
                                    "timeout_seconds": 8, "max_output_bytes": 128}},
        )
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False, tools=[
                "read_file", "exec_command", "task_run", "job_start",
                "job_status", "job_logs", "job_wait", "job_cancel",
            ])
        f.write_config()
        f.start()
        self.session = f.connect()
        self.other = f.connect(product.OTHER_TOKEN)

    def call(self, tool, args, other=False, error=False):
        result = self.f.call(tool, args, self.other if other else self.session,
                             product.OTHER_TOKEN if other else product.TOKEN)
        self.assertEqual(result["isError"], error, result)
        return result if error else json.loads(result["content"][0]["text"])

    def end(self, job, other=False):
        deadline = time.monotonic() + 10
        while True:
            status = self.call("job_status", {"job_id": job}, other)
            if status["state"] not in ("starting", "running", "uncertain"):
                return status
            self.assertLess(time.monotonic(), deadline, status)
            time.sleep(.03)

    def test_mode_confinement_and_durable_retry(self):
        f = self.f
        outside = f.base / "outside.txt"
        outside.write_text("synthetic")
        command = "test ! -e " + shlex.quote(str(outside)) + " && printf standard"
        standard = self.call("exec_command", {"command": command, "timeout_seconds": 6})
        self.assertEqual(standard["exit_code"], 0, standard)
        self.assertEqual(standard["stdout"], "standard")
        self.assertEqual(self.call("job_status", {"job_id": standard["job_id"]})["exit_code"], 0)
        self.call("exec_command", {"command": "true", "cwd": str(f.base)}, error=True)

        subprocess.run([product.BIN, "mode", "yolo", "primary", "--config", f.config],
                       env=dict(os.environ, HOME=str(f.base)), check=True, capture_output=True, timeout=10)
        command = ("test -e " + shlex.quote(str(outside)) + " && test ! -e "
                   + shlex.quote(str(f.config)) + " && printf masked")
        broad = self.call("exec_command", {"command": command, "timeout_seconds": 8})
        self.assertEqual(broad["exit_code"], 0, broad)
        self.assertEqual(broad["stdout"], "masked")

        args = {"command": "printf start; sleep 1; printf done", "wait_seconds": 0,
                "timeout_seconds": 8, "request_id": "same"}
        with ThreadPoolExecutor(max_workers=2) as pool:
            calls = list(pool.map(lambda _: self.call("task_run", args), range(2)))
        self.assertEqual(calls[0]["job_id"], calls[1]["job_id"])
        self.assertEqual(sum(bool(x.get("idempotent_replay")) for x in calls), 1)
        job = calls[0]["job_id"]
        self.assertEqual(calls[0]["task_id"], job)
        self.call("task_run", dict(args, command="printf different"), error=True)
        self.call("job_status", {"job_id": job}, other=True, error=True)
        other = self.call("task_run", dict(args, command="printf other"), other=True)
        self.assertNotEqual(other["job_id"], job)
        self.assertEqual(self.end(other["job_id"], other=True)["exit_code"], 0)
        self.assertEqual(self.end(job)["exit_code"], 0)
        self.assertEqual(self.call("job_logs", {"job_id": job})["stdout"], "startdone")
        self.session = f.connect()
        replay = self.call("task_run", args)
        self.assertEqual(replay["job_id"], job)
        self.assertTrue(replay["idempotent_replay"])
        for invalid in ({"command": "true", "argv": ["true"]},
                        {"argv": ["true", 42]}, {"command": "true", "request_id": "../bad"},
                        {"command": "true", "timeout_seconds": 0},
                        {"command": "true", "unknown": True}):
            self.call("task_run", invalid, error=True)

    def test_ephemeral_worktree_isolates_and_cleans_up(self):
        repo = self.f.workspace
        self.call("task_run", {"command": "true", "ephemeral_worktree": True}, error=True)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c",
                        "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "initial"], check=True)
        args = {"command": "pwd; printf isolated > result.txt", "ephemeral_worktree": True,
                "request_id": "worktree-isolation", "timeout_seconds": 8}
        result = self.call("task_run", args)
        self.assertEqual(result["exit_code"], 0, result)
        self.assertTrue(result["ephemeral_worktree"])
        self.assertTrue(result["worktree_cleaned"])
        self.assertFalse((repo / "result.txt").exists())
        self.assertFalse(Path(result["stdout"].strip()).exists())
        self.assertTrue(self.call("task_run", args)["idempotent_replay"])
        self.call("task_run", dict(args, ephemeral_worktree=False), error=True)
        subprocess.run(["git", "-C", str(repo), "worktree", "list", "--porcelain"],
                       check=True, capture_output=True, text=True)
        self.call("exec_command", {"command": "true", "ephemeral_worktree": True}, error=True)

    def test_live_terminal_command_and_elapsed(self):
        f = self.f
        monitor = Path(os.environ.get("VEYL_MONITOR_BIN", "target/debug/veyl-monitor")).resolve()
        cmd = [str(monitor), "--listen", f"127.0.0.1:{f.admin}"]
        token = f.cli("dashboard", "pair").encode()
        read_fd, write_fd = os.pipe()
        pid, terminal = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            fcntl.ioctl(1, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 160, 0, 0))
            os.close(write_fd)
            os.dup2(read_fd, 0)
            os.close(read_fd)
            os.execv(cmd[0], cmd)
        os.close(read_fd)
        screen_data = bytearray()
        def screen_until(predicate, seconds=7):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                ready, _, _ = select.select([terminal], [], [], .2)
                if ready:
                    chunk = os.read(terminal, 32768)
                    if not chunk:
                        break
                    screen_data.extend(chunk)
                    screen = screen_data.rsplit(b"\x1b[H\x1b[2J", 1)[-1]
                    result = predicate(screen)
                    if result:
                        return result
            self.fail("Live monitor did not reach expected state: " + repr(bytes(screen_data.rsplit(b"\x1b[H\x1b[2J", 1)[-1])[:6000]))
        try:
            os.write(write_fd, token)
            os.close(write_fd)
            screen_until(lambda s: b"Veyl / activity" in s and b"COMMAND / SUMMARY" in s and b"No active MCP call" in s)
            os.write(terminal, b"t")
            screen_until(lambda s: b"y confirms" in s)
            os.write(terminal, b"y")
            screen_until(lambda s: b"LOCAL TRACE ON" in s)
            def running_elapsed(screen):
                for line in screen.splitlines():
                    if b"exec_command" in line and b"RUNNING" in line and b"printf LIVE_PREVIEW" in line:
                        found = re.search(rb"\b(\d+)ms\b|\b(\d+)\.(\d{3})s\b", line)
                        if found:
                            return int(found[1]) if found[1] else int(found[2])*1000 + int(found[3])
                return None
            with ThreadPoolExecutor(max_workers=1) as pool:
                call = pool.submit(self.call, "exec_command", {
                    "command": "printf LIVE_PREVIEW; sleep 3", "timeout_seconds": 8})
                screen_until(lambda s: b"MCP running: 1 | exec_command" in s)
                first = screen_until(running_elapsed)
                second = screen_until(lambda s: (v if (v := running_elapsed(s)) and v > first else None))
                self.assertGreater(second, first)
                completed = call.result(timeout=10)
                self.assertEqual(completed["exit_code"], 0)
            screen_until(lambda s: b"No active MCP call" in s)
            job_id = completed["job_id"].encode()
            os.write(terminal, b"\r")
            screen_until(lambda s: b"Activity details - command / target" in s and
                         b"Requested shell command:" in s and b"printf LIVE_PREVIEW; sleep 3" in s)
            os.write(terminal, b"d")
            screen_until(lambda s: b"Details & Parameters" in s and b"local_trace" in s and b"printf LIVE_PREVIEW" in s)
            os.write(terminal, b"d")
            screen_until(lambda s: b"Activity details - command / target" in s and b"Requested shell command:" in s)
            os.write(terminal, b"\x1b")
            screen_until(lambda s: b"Veyl / activity" in s and b"COMMAND / SUMMARY" in s)
            os.write(terminal, b"2")
            screen_until(lambda s: b"Veyl / jobs" in s and job_id in s and b"printf LIVE_PREVIEW" in s)
            os.write(terminal, b"\r")
            screen_until(lambda s: b"Details & Parameters" in s and b"local_trace" in s and b"printf LIVE_PREVIEW" in s)
            os.write(terminal, b"\x1b")
            screen_until(lambda s: b"Veyl / jobs" in s and job_id in s)
            os.write(terminal, b"t")
            screen_until(lambda s: b"Veyl / jobs" in s and job_id in s and b"LOCAL TRACE ON" not in s and b"LIVE_PREVIEW" not in s)
            os.write(terminal, b"1")
            screen_until(lambda s: b"Run supervised command" in s and b"LIVE_PREVIEW" not in s)
            os.write(terminal, b"\r")
            screen_until(lambda s: b"Activity details - command / target" in s and
                         b"Command unavailable" in s and b"LIVE_PREVIEW" not in s)
            os.write(terminal, b"\x1b")
            screen_until(lambda s: b"Veyl / activity" in s and b"COMMAND / SUMMARY" in s)
            for _ in range(3):
                self.call("job_status", {"job_id": completed["job_id"]})
            os.write(terminal, b"/job_status\r")
            screen_until(lambda s: b"Veyl / activity" in s and b"Filter: job_status" in s and b"selected 1" in s and s.count(b"job_status") >= 4)
            os.write(terminal, b"jj")
            screen_until(lambda s: b"Veyl / activity" in s and b"Filter: job_status" in s and b"selected 3" in s)
            os.write(terminal, b"\r")
            screen_until(lambda s: b"Activity details - command / target" in s and b"job_status" in s and b"No shell command" in s)
            os.write(terminal, b"jjj\x1b")
            screen_until(lambda s: b"Veyl / activity" in s and b"Filter: job_status" in s and b"selected 3" in s)
            os.write(terminal, b"q")
        finally:
            os.close(terminal)
            found, _ = os.waitpid(pid, os.WNOHANG)
            if not found:
                os.kill(pid, 15)
                os.waitpid(pid, 0)

    def test_detached_job_elapsed(self):
        job = self.call("task_run", {"command": "sleep 2", "wait_seconds": 0,
                                    "timeout_seconds": 8})["job_id"]
        self.addCleanup(self.call, "job_cancel", {"job_id": job})
        deadline = time.monotonic() + 1.5
        while True:
            first = self.call("job_status", {"job_id": job})
            if first["state"] == "running":
                break
            self.assertLess(time.monotonic(), deadline, first)
            time.sleep(.02)
        self.assertIsInstance(first.get("live_elapsed_ms"), int)
        time.sleep(.2)
        self.session = self.f.connect()
        second = self.call("job_status", {"job_id": job})
        self.assertEqual(second["state"], "running")
        self.assertGreater(second["live_elapsed_ms"], first["live_elapsed_ms"])
        self.assertNotIn("execution_duration_ms", second)
        self.call("job_status", {"job_id": job}, other=True, error=True)
        final = self.end(job)
        self.assertEqual(final["exit_code"], 0, final)
        self.assertGreaterEqual(final["execution_duration_ms"], second["live_elapsed_ms"])
        self.assertNotIn("live_elapsed_ms", final)

    def test_profile_request_id_conflict(self):
        a = self.call("job_start", {"profile": "probe", "request_id": "profile-key"})
        b = self.call("job_start", {"profile": "probe", "request_id": "profile-key"})
        self.assertEqual(a["job_id"], b["job_id"])
        self.assertTrue(b["idempotent_replay"])
        self.call("task_run", {"command": "true", "request_id": "profile-key"}, error=True)
        other = self.call("job_start", {"profile": "probe", "request_id": "profile-key"}, other=True)
        self.assertNotEqual(a["job_id"], other["job_id"])
        self.assertEqual(self.end(a["job_id"])["exit_code"], 0)
        self.assertEqual(self.end(other["job_id"], other=True)["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
