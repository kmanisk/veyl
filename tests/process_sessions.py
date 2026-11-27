#!/usr/bin/env python3
"""Operator-candidate HTTP tests with synthetic state, Bubblewrap and user scopes."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import time
import unittest

import dynamic_jobs
import product_features as product


class ProcessSessionBoundary(unittest.TestCase):
    setUp = dynamic_jobs.DynamicJobs.setUp
    call = dynamic_jobs.DynamicJobs.call
    end = dynamic_jobs.DynamicJobs.end

    def test_closed_stdin_independent_output_offsets_and_owner(self):
        started = self.call("task_run", {
            "command": "if read line; then printf unexpected; else printf abcdef; printf XYZ >&2; fi",
            "timeout_seconds": 8, "wait_seconds": 0,
        })
        job = started["job_id"]
        status = self.end(job)
        self.assertEqual(status["exit_code"], 0, status)
        self.call("job_logs", {"job_id": job}, other=True, error=True)
        first = self.call("job_logs", {"job_id": job, "stdout_offset": 0,
                                        "stderr_offset": 0, "max_bytes": 2})
        self.assertEqual((first["stdout"], first["stderr"]), ("ab", "XY"))
        self.assertEqual((first["next_stdout_offset"], first["next_stderr_offset"]), (2, 2))
        second = self.call("job_logs", {"job_id": job, "stdout_offset": 2,
                                         "stderr_offset": 0, "max_bytes": 8})
        self.assertEqual((second["stdout"], second["stderr"]), ("cdef", "XYZ"))
        self.assertEqual((second["next_stdout_offset"], second["next_stderr_offset"]), (6, 3))
        self.assertTrue(second["ended"])

    def test_session_input_is_not_advertised_or_callable(self):
        _, listing = self.f.rpc("tools/list", self.session, product.TOKEN)
        names = {tool["name"] for tool in listing["result"]["tools"]}
        self.assertNotIn("process_start", names)
        self.assertNotIn("process_input", names)
        self.call("process_input", {"job_id": "0" * 32, "data": "x"}, error=True)



class ProcessSessions(unittest.TestCase):
    call = dynamic_jobs.DynamicJobs.call
    end = dynamic_jobs.DynamicJobs.end

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
        f.doc.update(policy_version=4, audit_log=str(f.audit), job_state_dir=str(jobs),
                     job_profiles={
                         "shell": {"executable": "/usr/bin/sh", "args": ["-s"],
                                   "timeout_seconds": 86400, "extended_runtime": True,
                                   "interactive": True, "max_output_bytes": 65536},
                         "backpressure": {"executable": "/usr/bin/sh",
                                          "args": ["-c", "printf ready; sleep 25"],
                                          "timeout_seconds": 30, "interactive": True},
                         "echo": {"executable": "/usr/bin/cat", "args": [],
                                  "timeout_seconds": 30, "interactive": True},
                         "pty_shell": {"executable": "/usr/bin/bash",
                                       "args": ["--noprofile", "--norc", "-i"],
                                       "timeout_seconds": 30, "interactive": True,
                                       "pty": True, "max_output_bytes": 65536},
                         "closed": {"executable": "/usr/bin/true", "args": [],
                                    "timeout_seconds": 2},
                     })
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False, job_runtime_limit_seconds=86400,
                          tools=["process_start", "process_input", "process_resize", "shell_status", "shell_reset",
                                 "job_start", "job_status", "job_logs", "job_cancel"])
        f.write_config()
        self.gateway = f.start()
        self.session = f.connect()
        self.other = f.connect(product.OTHER_TOKEN)

    def start(self, profile="shell", timeout=30, transport="pipe", **params):
        receipt = self.call("process_start", dict(profile=profile, timeout_seconds=timeout, **params))
        self.assertEqual(receipt["transport"], transport, receipt)
        job = receipt["job_id"]
        self.addCleanup(self.cancel_if_active, job)
        self.await_result(lambda: self.call("job_status", {"job_id": job}),
                          lambda status: status["state"] == "running", seconds=5)
        return job

    def cancel_if_active(self, job):
        self.call("job_cancel", {"job_id": job})

    def await_result(self, query, condition, seconds=6):
        deadline = time.monotonic() + seconds
        while True:
            value = query()
            if condition(value):
                return value
            self.assertLess(time.monotonic(), deadline, value)
            time.sleep(.04)

    def send(self, job, seq, data=None, status="accepted", **params):
        arguments = {"job_id": job, "sequence": seq}
        arguments.update({"eof": True} if data is None else {"data": data})
        value = self.call("process_input", arguments, **params)
        if not params.get("error"):
            self.assertEqual(value["status"], status, value)
        return value

    def logs(self, job, **offsets):
        return self.call("job_logs", dict(job_id=job, **offsets))

    def mode(self, name, client="primary"):
        flags = ["--confirm-native"] if name == "yolo" else []
        subprocess.run([product.BIN, "mode", name, client, "--config", self.f.config, *flags],
                       env=dict(os.environ, HOME=str(self.f.base)), check=True,
                       capture_output=True, timeout=10)

    def edit_client(self, change):
        change(self.f.doc["clients"][0])
        # Same atomic replacement semantics as a local operator update.
        pending = self.f.config.with_name("fixture-next.json")
        pending.touch(mode=0o600)
        pending.write_text(json.dumps(self.f.doc))
        pending.replace(self.f.config)

    def test_shell_cwd_environment_restart_and_exactly_once(self):
        (self.f.workspace / "nested").mkdir(mode=0o700)
        job = self.start(timeout=86400, request_id="persistent")
        self.assertEqual(self.call("job_status", {"job_id": job})["timeout_seconds"], 86400)
        one = "cd nested; export VEYL_VAR=SESSION_ONLY_CANARY; f() { printf function; }; printf begin; printf ERR >&2\n"
        self.assertEqual(self.send(job, 0, one)["next_sequence"], 1)
        self.send(job, 0, one, "sequence_consumed")
        self.send(job, 3, "printf bad\n", "out_of_order")
        self.await_result(lambda: self.logs(job), lambda output: output["stdout"] == "begin")
        self.session = self.f.connect()
        self.assertEqual(self.call("process_input", {"job_id": job})["next_sequence"], 1)
        self.f.stop(self.gateway)
        self.gateway = self.f.start()
        self.session = self.f.connect()
        self.other = self.f.connect(product.OTHER_TOKEN)
        replay = self.call("process_start", {"profile": "shell", "request_id": "persistent"})
        self.assertEqual(replay["job_id"], job)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(self.call("process_input", {"job_id": job})["next_sequence"], 1)
        self.send(job, 1, """printf "|%s|%s|" "${PWD##*/}" "$VEYL_VAR"; f\n""")
        eof = self.send(job, 2)
        self.assertTrue(eof["stdin_closed"])
        self.assertEqual(self.end(job)["exit_code"], 0)
        logs = self.logs(job, stdout_offset=5, stderr_offset=1)
        self.assertEqual(logs["stdout"], "|nested|SESSION_ONLY_CANARY|function")
        self.assertEqual(logs["stderr"], "RR")
        self.assertTrue(logs["ended"])
        self.send(job, 3, "unreachable", error=True)
        receipt = (self.f.config.parent / "jobs" / job / "receipt.json").read_bytes()
        audit = self.f.audit.read_bytes()
        self.assertIn(b"process_input", audit)
        for value in (b"SESSION_ONLY_CANARY", product.TOKEN.encode(), product.OTHER_TOKEN.encode()):
            self.assertNotIn(value, audit)
            self.assertNotIn(value, receipt)

    def test_concurrent_ownership_revocation_and_reset(self):
        job = self.start()
        second = self.start(profile="echo")
        self.send(job, 0, "printf foreign\n", other=True, error=True)
        self.call("job_status", {"job_id": job}, other=True, error=True)
        self.call("job_logs", {"job_id": job}, other=True, error=True)
        self.call("job_cancel", {"job_id": job}, other=True, error=True)
        self.call("shell_reset", {"job_id": job}, other=True, error=True)
        def raced_input(index):
            session = self.f.connect()
            result = self.f.call("process_input", {"job_id": job, "sequence": 0,
                                                    "data": f"printf value{index}\n"}, session)
            self.assertFalse(result["isError"], result)
            return json.loads(result["content"][0]["text"])["status"]
        with ThreadPoolExecutor(max_workers=3) as pool:
            raced = list(pool.map(raced_input, range(3)))
        self.assertCountEqual(raced, ["accepted", "sequence_consumed", "sequence_consumed"])
        self.send(second, 0, "independent\n")
        self.await_result(lambda: self.logs(second), lambda logs: logs["stdout"] == "independent\n")
        self.await_result(lambda: self.logs(job), lambda logs: logs["stdout"] in ("value0", "value1", "value2"))
        self.edit_client(lambda c: c.update(deny_tools=["process_input"]))
        self.send(job, 1, "printf denied\n", error=True)
        _, listing = self.f.rpc("tools/list", self.session, product.TOKEN)
        self.assertNotIn("process_input", {tool["name"] for tool in listing["result"]["tools"]})
        self.edit_client(lambda c: c.update(deny_tools=["process_start"]))
        self.send(job, 1, "printf denied\n", error=True)
        self.edit_client(lambda c: c.pop("deny_tools"))
        original = self.f.doc["clients"][0]["root"]
        replacement = self.f.base / "replacement"
        replacement.mkdir(mode=0o700)
        if self.f.doc["clients"][1]["root"] == original:
            self.f.doc["clients"][1]["root"] = str(replacement)
        self.edit_client(lambda c: c.update(root=str(replacement)))
        self.send(job, 1, "printf denied\n", error=True)
        self.edit_client(lambda c: c.update(root=original))
        self.mode("yolo")
        self.send(job, 1, "printf denied\n", error=True)
        self.mode("standard")
        self.assertEqual(self.call("process_input", {"job_id": job})["next_sequence"], 1)
        fresh = self.call("shell_reset", {"job_id": job})["job_id"]
        self.addCleanup(self.cancel_if_active, fresh)
        self.assertNotEqual(fresh, job)
        self.assertEqual(self.call("shell_reset", {"job_id": job})["job_id"], fresh)
        self.assertEqual(self.end(job)["state"], "canceled")
        self.await_result(lambda: self.call("job_status", {"job_id": fresh}),
                          lambda status: status["state"] == "running")
        self.assertEqual(self.call("process_input", {"job_id": fresh})["next_sequence"], 0)
        self.send(fresh, 0)
        self.assertEqual(self.end(fresh)["exit_code"], 0)

    def test_backpressure_input_limits_timeout_and_group_cleanup(self):
        self.call("job_start", {"profile": "shell"}, error=True)
        self.call("process_start", {"profile": "closed"}, error=True)
        self.call("process_start", {"profile": "shell", "timeout_seconds": 86401}, error=True)
        blocked = self.start(profile="backpressure")
        self.send(blocked, 0, "é" * 2049, error=True)
        found = False
        for seq in range(64):
            value = self.call("process_input", {"job_id": blocked, "sequence": seq, "data": "a" * 4096})
            if value["status"] == "backpressure":
                self.assertEqual(value["next_sequence"], seq)
                self.assertEqual(self.call("process_input", {"job_id": blocked})["next_sequence"], seq)
                found = True
                break
            self.assertEqual(value["status"], "accepted", value)
        self.assertTrue(found, "Real OS pipe did not backpressure")
        self.assertEqual(self.call("job_cancel", {"job_id": blocked})["state"], "canceled")
        timed = self.start(timeout=2)
        self.send(timed, 0, "sleep 30 & wait\n")
        self.assertEqual(self.end(timed)["state"], "timed_out")
        killed = self.start()
        marker = self.f.workspace / "unexpected"
        self.send(killed, 0, "(sleep 2; touch unexpected) & printf staged; wait\n")
        self.await_result(lambda: self.logs(killed), lambda logs: logs["stdout"] == "staged")
        self.assertEqual(self.call("job_cancel", {"job_id": killed})["state"], "canceled")
        time.sleep(2.1)
        self.assertFalse(marker.exists(), "Canceled descendant survived")

    def test_resize_and_shell_status(self):
        pty = self.start(profile="pty_shell", transport="pty")
        pipe = self.start(profile="echo")
        initial = self.call("shell_status", {"job_id": pty})
        self.assertEqual((initial["pty"], initial["rows"], initial["cols"], initial["sequence"]),
                         (True, 24, 80, 0))
        resized = self.call("process_resize", {"job_id": pty, "rows": 35, "cols": 100})
        self.assertEqual(resized, {"job_id": pty, "resized": True, "pty": True, "rows": 35, "cols": 100})
        self.send(pty, 0, "stty size </dev/tty\n")
        self.await_result(lambda: self.logs(pty), lambda logs: "35 100" in logs["stdout"])
        status = self.call("shell_status", {"job_id": pty})
        self.assertEqual((status["rows"], status["cols"], status["sequence"], status["stdin_closed"]),
                         (35, 100, 1, False))
        listing = self.call("shell_status", {})
        self.assertEqual(listing["count"], 2)
        self.assertFalse(listing["truncated"])
        self.assertEqual({entry["job_id"] for entry in listing["sessions"]}, {pty, pipe})
        self.call("process_resize", {"job_id": pipe, "rows": 20, "cols": 80}, error=True)
        for rows, cols in ((0, 80), (513, 80), (24, 0), (24, 513)):
            self.call("process_resize", {"job_id": pty, "rows": rows, "cols": cols}, error=True)
        self.call("shell_status", {"job_id": pty}, other=True, error=True)
        self.call("process_resize", {"job_id": pty, "rows": 20, "cols": 80}, other=True, error=True)
        ordinary = self.call("job_start", {"profile": "closed"})["job_id"]
        self.call("shell_status", {"job_id": ordinary}, error=True)
        self.edit_client(lambda client: client.update(deny_tools=["process_resize", "shell_status"]))
        self.call("process_resize", {"job_id": pty, "rows": 20, "cols": 80}, error=True)
        self.call("shell_status", {}, error=True)
        self.edit_client(lambda client: client.pop("deny_tools"))

    def test_kernel_pty_terminal_state_and_hangup(self):
        for mode in ("standard", "yolo"):
            with self.subTest(mode=mode):
                self.mode(mode)
                job = self.start(profile="pty_shell", transport="pty")
                first = ("test -t 0 && test -t 1 && test -t 2 && "
                         "stty size </dev/tty && printf 'TERM_%s\n' OK; "
                         "export VPTY=retained; printf 'OUT_%s\n' ERR >&2\n")
                self.send(job, 0, first)
                joined = self.await_result(lambda: self.logs(job),
                                           lambda logs: "OUT_ERR" in logs["stdout"])
                self.assertIn("24 80", joined["stdout"], joined)
                self.assertIn("TERM_OK", joined["stdout"], joined)
                self.assertEqual(joined["stderr"], "", joined)
                self.session = self.f.connect()
                self.assertEqual(self.call("process_input", {"job_id": job})["next_sequence"], 1)
                self.send(job, 1, """printf 'VALUE_%s\n' "$VPTY"\n""")
                self.await_result(lambda: self.logs(job), lambda logs: "VALUE_retained" in logs["stdout"])
                eof = self.send(job, 2, status="hangup")
                self.assertTrue(eof["stdin_closed"])
                self.assertIn(self.end(job)["state"], ("completed", "canceled"))
        self.mode("standard")
        job = self.start(profile="pty_shell", transport="pty")
        self.send(job, 0, "(sleep 2; touch pty-escape) & printf 'STAGE_%s\n' PTY; wait\n")
        self.await_result(lambda: self.logs(job), lambda logs: "STAGE_PTY" in logs["stdout"])
        self.assertEqual(self.call("job_cancel", {"job_id": job})["state"], "canceled")
        time.sleep(2.1)
        self.assertFalse((self.f.workspace / "pty-escape").exists())

    def channel_identity(self, job):
        state = self.f.config.parent
        key = (state / "jobs" / ".receipt-key").read_bytes()
        receipt = json.loads((state / "jobs" / job / "receipt.json").read_bytes())
        nonce = receipt["launch_nonce"]
        stdin_key = hmac.digest(key, f"veyl/stdin/v1/{job}/{nonce}".encode(), "sha256")
        endpoint = "veyl.stdin." + hmac.digest(stdin_key, b"endpoint/v1", "sha256").hex()
        return stdin_key, endpoint

    def test_runner_rejects_expired_and_stale_signed_requests(self):
        job = self.start()
        key, endpoint = self.channel_identity(job)
        old_revision = hashlib.sha256(self.f.config.read_bytes()).digest()

        def delayed_packet(revision, age, expires):
            nonce = os.urandom(16)
            deadline = (time.monotonic_ns() // 1_000_000) + age
            body = nonce + struct.pack(">QQQ", 0, deadline, expires) + revision
            body += b"\x01printf unexpected\n"
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as peer:
                peer.bind(b"\0veyl.stdin.reply." + nonce.hex().encode())
                peer.settimeout(1)
                peer.connect("\0" + endpoint)
                peer.send(hmac.digest(key, body, "sha256") + body)
                reply = peer.recv(100)
            self.assertEqual(reply[:32], hmac.digest(key, reply[32:], "sha256"))
            self.assertEqual(reply[32:48], nonce)
            self.assertEqual(struct.unpack(">Q", reply[48:56])[0], 0)
            self.assertEqual(reply[57], 7, "Runner did not refuse a stale admission")

        delayed_packet(old_revision, -500, int(time.time()) + 60)
        delayed_packet(old_revision, 500, int(time.time()) - 1)
        self.edit_client(lambda client: client.update(deny_tools=["process_input"]))
        delayed_packet(old_revision, 500, int(time.time()) + 60)
        self.edit_client(lambda client: client.pop("deny_tools"))
        self.assertEqual(self.call("process_input", {"job_id": job})["next_sequence"], 0)
        self.send(job, 0, "printf admitted\n")
        self.send(job, 1)
        self.assertEqual(self.end(job)["exit_code"], 0)
        self.assertEqual(self.logs(job)["stdout"], "admitted")

    def test_yolo_preset_adds_native_interactive_grants(self):
        self.edit_client(lambda client: client.update(tools=["job_status", "job_cancel"]))
        self.mode("yolo")
        _, listing = self.f.rpc("tools/list", self.session, product.TOKEN)
        names = {tool["name"] for tool in listing["result"]["tools"]}
        self.assertTrue({"task_run", "process_start", "process_resize", "shell_status"} <= names)
        job = self.start()
        self.assertEqual(self.call("job_cancel", {"job_id": job})["state"], "canceled")
        self.mode("standard")
        self.call("process_start", {"profile": "shell"}, error=True)

    def test_native_descriptor_hygiene_and_forged_datagrams(self):
        self.mode("yolo")
        job = self.start()
        state = self.f.config.parent
        code = ("import os,socket; assert os.path.exists(" + repr(str(state / "clients.json")) + ");"
                "[print(os.readlink('/proc/self/fd/'+f)) for f in os.listdir('/proc/self/fd') if "
                "os.path.exists('/proc/self/fd/'+f)];"
                "socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); print('native ready')")
        command = "python3 -c " + shlex.quote(code) + "\n"
        self.send(job, 0, command)
        _, endpoint = self.channel_identity(job)
        self.assertIn("@" + endpoint, Path("/proc/net/unix").read_text())
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as attacker:
            attacker.settimeout(.4)
            attacker.bind("\0veyl.input.fixture." + job)
            sent = attacker.sendto(b"x" * 200, "\0" + endpoint)
            self.assertEqual(sent, 200)
            with self.assertRaises(socket.timeout):
                attacker.recv(512)
        output = self.await_result(lambda: self.logs(job),
                                   lambda logs: "native ready" in logs["stdout"])
        self.assertNotIn("socket:[", output["stdout"], output)
        self.assertNotIn("AssertionError", output["stderr"], output)
        self.assertEqual(self.call("process_input", {"job_id": job})["next_sequence"], 1)
        self.send(job, 1, "printf real\n")
        self.await_result(lambda: self.logs(job), lambda logs: "real" in logs["stdout"])
        self.send(job, 2)
        self.assertEqual(self.end(job)["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
