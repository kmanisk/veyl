#!/usr/bin/env python3
"""Explicit OAuth interactive pipe and PTY process sessions in the offline workspace sandbox."""
import fcntl
import hashlib
import hmac
import json
import os
import shlex
import socket
import struct
import subprocess
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

import oauth_jobs as jobs


class OAuthInteractive(jobs.OAuthJobs):
    def setUp(self):
        super().setUp()
        self.profiles = {
            "pwd": {"executable": "/usr/bin/pwd", "args": [], "timeout_seconds": 4},
            "shell": {
                "executable": "/usr/bin/sh",
                "args": ["-s"],
                "timeout_seconds": 60,
                "interactive": True,
                "max_output_bytes": 65536,
            },
            "pty_shell": {
                "executable": "/usr/bin/bash",
                "args": ["--noprofile", "--norc", "-i"],
                "timeout_seconds": 60,
                "interactive": True,
                "pty": True,
                "max_output_bytes": 65536,
            },
            "backpressure": {
                "executable": "/usr/bin/sh",
                "args": ["-c", "printf ready; sleep 25"],
                "timeout_seconds": 30,
                "interactive": True,
            },
        }
        self.definitions.write_text(json.dumps({"job_profiles": self.profiles}))
        self.definitions.chmod(0o600)

    def setup_args(self):
        return super().setup_args() + ["--workspace-interactive"]

    def launch_jobs(self, action="setup", env=None):
        args = (
            self.setup_args()
            if action == "setup"
            else self.onboarding_args("run", self.profile)
            + ["--workspace-jobs", "--workspace-interactive"]
        )
        self.launch(args, env=env)
        self.config = self.profile / "clients.json"

    def authorize(self, client=None):
        client = client or self.f.register()
        handle = self.f.pending(client)
        info = self.cli("inspect", {"request": handle})
        self.assertTrue(info["eligible"], info)
        self.assertTrue(info["native_scope"]["workspace_jobs"])
        self.assertTrue(info["native_scope"]["workspace_interactive"])
        self.assertEqual(
            set(info["native_scope"]["job_profiles"]), set(self.profiles)
        )
        args = self.exact("approve", handle, info)
        args.pop("action")
        self.cli("approve", args, success=False)
        self.cli("approve", dict(args, scope_fingerprint="0" * 64), success=False)
        args["scope_fingerprint"] = info["scope_fingerprint"]
        self.assertTrue(self.cli("approve", args)["approved"])
        return client, self.f.capture_tokens(
            self.f.exchange(client, self.delivered(handle))
        )

    def await_result(self, query, condition, seconds=6):
        deadline = time.monotonic() + seconds
        while True:
            value = query()
            if condition(value):
                return value
            self.assertLess(time.monotonic(), deadline, value)
            time.sleep(0.04)

    def start_session(self, token, session, profile="shell", transport="pipe", **params):
        started = self.call(
            token, session, "process_start", dict(profile=profile, **params)
        )
        self.assertEqual(started["transport"], transport, started)
        job = started["job_id"]
        self.await_result(
            lambda: self.call(token, session, "job_status", {"job_id": job}),
            lambda status: status["state"] == "running",
        )
        return job

    def send(self, token, session, job, seq, data=None, status="accepted", ok=True):
        args = {"job_id": job, "sequence": seq}
        args.update({"eof": True} if data is None else {"data": data})
        value = self.call(token, session, "process_input", args, ok=ok)
        if ok:
            self.assertEqual(value["status"], status, value)
        return value

    def end(self, token, session, job):
        return self.await_result(
            lambda: self.call(token, session, "job_status", {"job_id": job}),
            lambda status: status["state"]
            in ("completed", "failed", "canceled", "timed_out"),
        )

    def channel_identity(self, job):
        key = (self.profile / "jobs" / ".receipt-key").read_bytes()
        receipt = json.loads((self.profile / "jobs" / job / "receipt.json").read_bytes())
        nonce = receipt["launch_nonce"]
        stdin_key = hmac.digest(
            key, f"veyl/stdin/v1/{job}/{nonce}".encode(), "sha256"
        )
        endpoint = (
            "veyl.stdin."
            + hmac.digest(stdin_key, b"endpoint/v1", "sha256").hex()
        )
        return stdin_key, endpoint

    def test_interactive_opt_in_guards_and_fail_closed(self):
        env = dict(os.environ, HOME=str(self.base))
        # Refused without --workspace-jobs or with --funnel.
        missing_jobs = (
            self.onboarding_args("setup", self.profile, self.root)
            + ["--workspace-interactive"]
        )
        for cmd in (missing_jobs, self.setup_args() + ["--funnel"]):
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5, env=env)
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(self.profile.exists())

        # Refused when non-interactive profile only, or extended_runtime / over-limit.
        bad_defs = self.base / "bad-profiles.json"
        for candidate in (
            {"pwd": {"executable": "/usr/bin/pwd", "args": [], "timeout_seconds": 4}},
            {
                "ext": {
                    "executable": "/usr/bin/sh",
                    "args": ["-s"],
                    "timeout_seconds": 301,
                    "interactive": True,
                }
            },
            {
                "mem": {
                    "executable": "/usr/bin/sh",
                    "args": ["-s"],
                    "timeout_seconds": 30,
                    "interactive": True,
                    "memory_bytes": 268435457,
                }
            },
            {
                "untrusted": {
                    "executable": str(self.root / "custom.sh"),
                    "args": [],
                    "timeout_seconds": 30,
                    "interactive": True,
                }
            },
        ):
            bad_defs.write_text(json.dumps({"job_profiles": candidate}))
            bad_defs.chmod(0o600)
            cmd = (
                self.onboarding_args("setup", self.profile, self.root)
                + ["--workspace-jobs", "--workspace-interactive", "--job-profiles", str(bad_defs)]
            )
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5, env=env)
            self.assertNotEqual(r.returncode, 0, candidate)
            self.assertFalse(self.profile.exists())

        # Valid interactive setup, then refuse restart without matching --workspace-interactive.
        self.launch_jobs()
        client, issued = self.authorize()
        token = issued["access_token"]
        self.f.cleanup_server()
        r = subprocess.run(
            self.onboarding_args("run", self.profile) + ["--workspace-jobs"],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
        self.assertNotEqual(r.returncode, 0)

        # Unavailable XDG_RUNTIME_DIR must hide/fail-closed interactive tools and consent.
        self.launch_jobs(
            "run", env=dict(env, XDG_RUNTIME_DIR=str(self.base / "missing-runtime"))
        )
        session = self.connect(token)
        status, _, body = self.rpc(token, "tools/list", session)
        self.assertEqual(status, 200, body)
        names = {t["name"] for t in json.loads(body)["result"]["tools"]}
        self.assertFalse(
            names
            & {
                "process_start",
                "process_input",
                "process_resize",
                "shell_status",
                "shell_reset",
            }
        )
        self.call(token, session, "process_start", {"profile": "shell"}, False)
        handle = self.f.pending(client)
        info = self.cli("inspect", {"request": handle})
        self.assertFalse(info["eligible"])
        deny = self.exact("approve", handle, info)
        deny.pop("action")
        self.cli("approve", dict(deny, scope_fingerprint=info["scope_fingerprint"]), success=False)
        self.cli("deny", deny)

    def test_interactive_kernel_resource_ceilings(self):
        self.launch_jobs()
        _, issued = self.authorize()
        token = issued["access_token"]
        session = self.connect(token)
        job = self.start_session(token, session, profile="backpressure")
        try:
            receipt = json.loads((self.profile / "jobs" / job / "receipt.json").read_bytes())
            pid = receipt["runner"]["pid"]
            from pathlib import Path
            membership = Path(f"/proc/{pid}/cgroup").read_text()
            relative = next(line[3:] for line in membership.splitlines() if line.startswith("0::"))
            cgroup = Path("/sys/fs/cgroup") / relative.lstrip("/")
            self.assertEqual((cgroup / "memory.max").read_text().strip(), "268435456")
            self.assertEqual((cgroup / "memory.swap.max").read_text().strip(), "0")
            tasks = int((cgroup / "pids.max").read_text().strip())
            self.assertGreater(tasks, 0)
            self.assertLessEqual(tasks, 128)
        finally:
            self.call(token, session, "job_cancel", {"job_id": job})

    def test_interactive_runner_fails_closed_when_grant_publication_is_locked(self):
        self.launch_jobs()
        _, issued = self.authorize()
        token = issued["access_token"]
        session = self.connect(token)
        lock = self.profile / "oauth" / ".oauth-admission-lock"
        # A cooperating state writer excludes new runner admissions. Hold it
        # across a real detached launch, not just a mocked grant check.
        with lock.open("r+b") as gate:
            fcntl.flock(gate, fcntl.LOCK_EX | fcntl.LOCK_NB)
            job = self.call(
                token, session, "process_start",
                {"profile": "backpressure", "request_id": "locked-launch"},
            )["job_id"]
            denied = self.end(token, session, job)
            self.assertEqual(denied["state"], "failed", denied)
            self.assertEqual(denied["stdout_bytes"], 0, denied)
            receipt = json.loads(
                (self.profile / "jobs" / job / "receipt.json").read_bytes()
            )
            self.assertIsNone(receipt["child"], receipt)
        # The same approved profile actually executes once the lock is free.
        admitted = self.start_session(
            token, session, profile="backpressure", request_id="unlocked-launch"
        )
        self.await_result(
            lambda: self.call(token, session, "job_logs", {"job_id": admitted}),
            lambda logs: logs["stdout"] == "ready",
        )
        self.call(token, session, "job_cancel", {"job_id": admitted})

    def test_interactive_pipe_pty_family_refresh_restart_and_revocation(self):
        self.launch_jobs()
        client, a = self.authorize()
        _, b = self.authorize(client)
        at, bt = a["access_token"], b["access_token"]
        sa, sb = self.connect(at), self.connect(bt)

        status, _, body = self.rpc(at, "tools/list", sa)
        self.assertEqual(status, 200, body)
        catalog = {t["name"]: t for t in json.loads(body)["result"]["tools"]}
        self.assertTrue(
            {
                "read_file",
                "run_command",
                "job_start",
                "job_status",
                "job_logs",
                "job_cancel",
                "list_jobs",
                "job_wait",
                "process_start",
                "process_input",
                "process_resize",
                "shell_status",
                "shell_reset",
            }
            <= set(catalog)
        )
        self.assertNotIn("exec_command", catalog)
        self.assertNotIn("task_run", catalog)
        self.assertEqual(
            catalog["process_start"]["inputSchema"]["properties"]["timeout_seconds"]["maximum"],
            300,
        )

        # Profile separation & limits.
        self.call(at, sa, "job_start", {"profile": "shell"}, False)
        self.call(at, sa, "process_start", {"profile": "pwd"}, False)
        self.call(
            at, sa, "process_start", {"profile": "shell", "timeout_seconds": 301}, False
        )

        # Pipe shell with state, sequencing, replay protection, and offline sandbox.
        (self.root / "nested").mkdir(mode=0o700)
        ja = self.start_session(at, sa, profile="shell", request_id="oauth-shell-a")
        first = (
            "cd nested; export OAUTH_SESSION_CANARY=STDIN_SECRET_1; "
            "f() { printf fn_ok; }; printf begin; printf ERR >&2\n"
        )
        self.assertEqual(self.send(at, sa, ja, 0, first)["next_sequence"], 1)
        self.send(at, sa, ja, 0, first, status="sequence_consumed")
        self.send(at, sa, ja, 3, "printf bad\n", status="out_of_order")
        self.await_result(
            lambda: self.call(at, sa, "job_logs", {"job_id": ja}),
            lambda logs: logs["stdout"] == "begin",
        )
        self.assertEqual(
            self.call(at, sa, "process_input", {"job_id": ja})["next_sequence"], 1
        )

        # Cross-family isolation under the same OAuth client registration.
        self.call(bt, sb, "process_input", {"job_id": ja, "sequence": 1, "data": "x"}, False)
        self.call(bt, sb, "process_resize", {"job_id": ja, "rows": 24, "cols": 80}, False)
        self.call(bt, sb, "shell_status", {"job_id": ja}, False)
        self.call(bt, sb, "shell_reset", {"job_id": ja}, False)
        self.assertEqual(self.call(bt, sb, "shell_status", {})["count"], 0)
        jb = self.start_session(bt, sb, profile="shell", request_id="oauth-shell-a")
        self.assertNotEqual(ja, jb)

        # Concurrent sequence race on b's session: exactly 1 accepted.
        def race(index):
            sess = self.connect(bt)
            res = self.call(
                bt,
                sess,
                "process_input",
                {"job_id": jb, "sequence": 0, "data": f"printf r{index}\n"},
            )
            return res["status"]

        with ThreadPoolExecutor(max_workers=3) as pool:
            raced = list(pool.map(race, range(3)))
        self.assertCountEqual(raced, ["accepted", "sequence_consumed", "sequence_consumed"])

        # Hardlink and FIFO checks still fail closed for new interactive launches.
        alias = self.root / "alias.txt"
        os.link(self.base / "outside.txt", alias)
        self.call(at, sa, "process_start", {"profile": "shell"}, False)
        alias.unlink()
        fifo = self.root / "blocked-fifo"
        os.mkfifo(fifo)
        self.call(at, sa, "process_start", {"profile": "shell"}, False)
        fifo.unlink()

        # Offline sandbox & no host secret exposure inside interactive shell.
        probe = (
            "cat escape.txt 2>&1; python3 -c "
            + shlex.quote("import socket; socket.socket()")
            + " 2>&1; printf END_SANDBOX\n"
        )
        self.send(at, sa, ja, 1, probe)
        out = self.await_result(
            lambda: self.call(at, sa, "job_logs", {"job_id": ja}),
            lambda logs: "END_SANDBOX" in logs["stdout"],
        )
        self.assertNotIn("outside-denied-canary", json.dumps(out))

        # Refresh token keeps OAuth family ownership; survives gateway restart.
        at = self.f.capture_tokens(self.f.refresh(client, a["refresh_token"]))[
            "access_token"
        ]
        self.f.cleanup_server()
        self.launch_jobs("run")
        sa = self.connect(at)
        sb = self.connect(bt)
        replay = self.call(
            at, sa, "process_start", {"profile": "shell", "request_id": "oauth-shell-a"}
        )
        self.assertEqual(replay["job_id"], ja)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(
            self.call(at, sa, "process_input", {"job_id": ja})["next_sequence"], 2
        )
        self.send(
            at,
            sa,
            ja,
            2,
            """printf "|%s|%s|" "${PWD##*/}" "$OAUTH_SESSION_CANARY"; f\n""",
        )
        eof = self.send(at, sa, ja, 3, None)
        self.assertTrue(eof["stdin_closed"])
        self.assertEqual(self.end(at, sa, ja)["exit_code"], 0)
        logs = self.call(at, sa, "job_logs", {"job_id": ja})
        self.assertIn("|nested|STDIN_SECRET_1|fn_ok", logs["stdout"])
        self.assertEqual(logs["stderr"], "ERR")

        # PTY session, resize, bounds, shell_reset, and backpressure.
        pty = self.start_session(at, sa, profile="pty_shell", transport="pty")
        self.assertEqual(
            self.call(at, sa, "process_resize", {"job_id": pty, "rows": 38, "cols": 110}),
            {"job_id": pty, "resized": True, "pty": True, "rows": 38, "cols": 110},
        )
        self.send(at, sa, pty, 0, "stty size </dev/tty\n")
        self.await_result(
            lambda: self.call(at, sa, "job_logs", {"job_id": pty}),
            lambda logs: "38 110" in logs["stdout"],
        )
        self.call(at, sa, "process_resize", {"job_id": pty, "rows": 0, "cols": 80}, False)
        self.call(at, sa, "process_resize", {"job_id": pty, "rows": 513, "cols": 80}, False)
        self.call(at, sa, "process_resize", {"job_id": jb, "rows": 24, "cols": 80}, False)
        self.send(at, sa, pty, 1, "é" * 2049, ok=False)
        status_info = self.call(at, sa, "shell_status", {"job_id": pty})
        self.assertEqual((status_info["rows"], status_info["cols"]), (38, 110))

        # Backpressure bounded input/pipe test on OAuth session.
        bp = self.start_session(at, sa, profile="backpressure")
        saw_bp = False
        for seq in range(64):
            resp = self.call(
                at, sa, "process_input", {"job_id": bp, "sequence": seq, "data": "a" * 4096}
            )
            if resp["status"] == "backpressure":
                saw_bp = True
                break
            self.assertEqual(resp["status"], "accepted", resp)
        self.assertTrue(saw_bp)
        self.call(at, sa, "job_cancel", {"job_id": bp})

        # shell_reset creates a fresh family-scoped session.
        fresh = self.call(bt, sb, "shell_reset", {"job_id": jb})["job_id"]
        self.assertNotEqual(fresh, jb)
        self.assertEqual(self.end(bt, sb, jb)["state"], "canceled")
        self.await_result(
            lambda: self.call(bt, sb, "job_status", {"job_id": fresh}),
            lambda s: s["state"] == "running",
        )
        self.call(at, sa, "shell_status", {"job_id": fresh}, False)

        # Forged datagram to runner abstract socket must be ignored cleanly.
        stdin_key, endpoint = self.channel_identity(pty)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as attacker:
            attacker.settimeout(0.3)
            attacker.bind("\0veyl.oauth.attacker." + pty)
            attacker.sendto(b"x" * 200, "\0" + endpoint)
            with self.assertRaises(socket.timeout):
                attacker.recv(256)

        # Revoke OAuth client and confirm BOTH HTTP 401 and runner-side OAuth rejection
        # even when clients.json revision is valid and packet is signed!
        old_revision = hashlib.sha256(self.config.read_bytes()).digest()
        self.assertTrue(self.cli("revoke", {"client_id": client, "confirm": True})["revoked"])
        self.assertEqual(self.rpc(at, "tools/list", sa)[0], 401)
        self.assertEqual(self.rpc(bt, "tools/list", sb)[0], 401)

        nonce = os.urandom(16)
        deadline = (time.monotonic_ns() // 1_000_000) + 500
        expires = int(time.time()) + 60
        body = nonce + struct.pack(">QQQ", 1, deadline, expires) + old_revision
        body += b"\x01printf after_revoke\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as peer:
            peer.bind(b"\0veyl.stdin.reply." + nonce.hex().encode())
            peer.settimeout(1)
            peer.connect("\0" + endpoint)
            peer.send(hmac.digest(stdin_key, body, "sha256") + body)
            reply = peer.recv(100)
        self.assertEqual(reply[:32], hmac.digest(stdin_key, reply[32:], "sha256"))
        self.assertEqual(reply[57], 7, "Runner accepted packet after OAuth revocation")

        # Local dashboard operator can still list and cancel active interactive OAuth jobs.
        headers = self.pair_dashboard()
        status, _, body = self.f.request(
            "GET", "/dashboard/api/jobs?client=oauth-preview", admin=True, headers=headers
        )
        self.assertEqual(status, 200, body)
        for job in (pty, fresh):
            self.assertIn(job, body.decode())
            c_status, _, c_body = self.f.request(
                "POST",
                "/dashboard/api/jobs/cancel",
                {"client": "oauth-preview", "job_id": job, "confirm": True},
                admin=True,
                headers=headers,
            )
            self.assertEqual(c_status, 200, c_body)

        # Durable audit recorded interactive operations without leaking stdin or tokens.
        audit = (self.profile / "audit" / "events.jsonl").read_bytes()
        for tool_name in (
            b"process_start",
            b"process_input",
            b"process_resize",
            b"shell_status",
            b"shell_reset",
            b"job_cancel",
        ):
            self.assertIn(tool_name, audit)
        for secret in (b"STDIN_SECRET_1", at.encode(), bt.encode()):
            self.assertNotIn(secret, audit)
        # Also verify restart with --workspace-interactive on a non-interactive profile fails.
        self.assertEqual((self.base / "outside.txt").read_text(), "outside-denied-canary")


if __name__ == "__main__":
    names = [
        n
        for n in unittest.defaultTestLoader.getTestCaseNames(OAuthInteractive)
        if n.startswith("test_interactive_")
    ]
    raise SystemExit(
        not unittest.TextTestRunner(verbosity=2)
        .run(unittest.TestSuite(OAuthInteractive(n) for n in names))
        .wasSuccessful()
    )
