#!/usr/bin/env python3
"""Direct OAuth onboarding UX, genuine per-connection Broad YOLO, mode switching,
escalation re-auth, immediate downgrade, and individual vs all-client logout tests.

Run with the exact candidate mcp-gateway binary argument.
"""
import json
import os
import shlex
import subprocess
import unittest
import urllib.parse
from pathlib import Path

import oauth_funnel as funnel
import oauth_managed_login as managed


class OAuthYoloLifecycle(managed.ManagedLogin):
    def setUp(self):
        super().setUp()
        self.workdir = self.base / "external_work"
        self.workdir.mkdir()
        self.outside = self.workdir / "host_note.txt"
        self.ssh_dir = self.base / ".ssh"
        self.ssh_dir.mkdir(mode=0o700)
        self.ssh_secret = self.ssh_dir / "id_ed25519"
        self.ssh_secret.write_text("private-ssh-canary")
        self.ssh_secret.chmod(0o600)
        self.bashrc = self.base / ".bashrc"
        self.bashrc.write_text("# readonly canary\n")
        self.bashrc.chmod(0o644)

    def authorize_client(self, approve_mode=None, use_inspected_mode=False):
        client = self.f.register()
        handle = self.f.pending(client)
        inspect_req = {"request": handle}
        if approve_mode is not None:
            inspect_req["mode"] = approve_mode
        info = self.cli("inspect", inspect_req)
        self.assertTrue(info["eligible"], info)
        self.assertTrue(info.get("supports_yolo"), info)
        expected_mode = approve_mode or ("yolo" if use_inspected_mode else "standard")
        if approve_mode is not None:
            self.assertEqual(info["mode"], approve_mode, info)
            self.assertEqual(info["native_scope"]["mode"], approve_mode, info)
        args = self.exact("approve", handle, info)
        args.pop("action")
        chosen_mode = info["mode"] if use_inspected_mode or approve_mode else "standard"
        args["mode"] = chosen_mode
        args["scope_fingerprint"] = info["scope_fingerprint"]
        self.assertEqual(chosen_mode, expected_mode)
        self.assertTrue(self.cli("approve", args)["approved"])
        issued = self.f.capture_tokens(self.f.exchange(client, self.delivered(handle)))
        return client, issued

    def reauthorize_client(self, client, approve_mode=None):
        handle = self.f.pending(client)
        inspect_req = {"request": handle}
        if approve_mode is not None:
            inspect_req["mode"] = approve_mode
        info = self.cli("inspect", inspect_req)
        args = self.exact("approve", handle, info)
        args.pop("action")
        args["mode"] = info["mode"]
        args["scope_fingerprint"] = info["scope_fingerprint"]
        self.assertTrue(self.cli("approve", args)["approved"])
        return self.f.capture_tokens(self.f.exchange(client, self.delivered(handle))), info

    def tools_list(self, token, session):
        status, _, body = self.rpc(token, "tools/list", session)
        self.assertEqual(status, 200, body)
        return {t["name"]: t for t in json.loads(body)["result"]["tools"]}

    def call_tool(self, token, session, name, arguments):
        status, _, body = self.rpc(
            token, "tools/call", session, {"name": name, "arguments": arguments}
        )
        self.assertEqual(status, 200, body)
        return json.loads(body)["result"]

    def test_tailscale_guidance_and_cwd_default(self):
        # Missing tailscaled socket gives actionable prerequisite guidance.
        bad = self.execute(
            [
                str(self.veyl),
                "login",
                "--yes",
                "--no-ui",
                "--root",
                str(self.root),
                "--funnel-socket",
                str(self.base / "missing-tailscaled.sock"),
            ]
        )
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("Tailscaled socket unavailable", bad.stderr)
        self.assertIn("tailscaled", bad.stderr)

        # Non-TTY login without --root defaults cleanly to CWD.
        self.start_managed_from_cwd()
        cfg = json.loads(self.config.read_text())
        self.assertEqual(Path(cfg["clients"][0]["root"]).resolve(), self.root.resolve())
        self.logout()

    def start_managed_from_cwd(self):
        old_cwd = os.getcwd()
        os.chdir(self.root)
        try:
            self.launch(
                [
                    str(self.veyl),
                    "login",
                    "--yes",
                    "--no-ui",
                    "--funnel-socket",
                    str(self.socket_path),
                ]
            )
        finally:
            os.chdir(old_cwd)
        self.config = self.profile / "clients.json"
        self.wait_for(lambda: len(self.daemon.snapshot()["Foreground"]) == 2)

    def test_standard_default_yolo_isolation_and_broad_protections(self):
        self.start_managed(first=True)

        # Remote registration metadata cannot supply/elevate mode.
        status, _, reg_err = self.f.request(
            "POST",
            "/oauth/register",
            {
                "client_name": "Attacker",
                "redirect_uris": [funnel.native.preview.CALLBACK],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "mcp",
                "mode": "yolo",
            },
        )
        self.assertEqual(status, 400, reg_err)

        # Standard connection defaults to Standard even when inspected cleanly.
        client_a, tok_a = self.authorize_client()
        at = tok_a["access_token"]
        sess_a = self.connect(at)
        tools_a = self.tools_list(at, sess_a)
        self.assertEqual(sorted(tools_a.keys()), ["read_file"])
        self.assertTrue(
            self.call_tool(at, sess_a, "write_file", {"path": "x.txt", "content": "nope"}).get(
                "isError"
            )
        )

        # Cross-mode fingerprint substitution must fail.
        client_b = self.f.register()
        handle_b = self.f.pending(client_b)
        info_std = self.cli("inspect", {"request": handle_b})
        self.assertEqual(info_std["mode"], "standard")
        info_yolo = self.cli("inspect", {"request": handle_b, "mode": "yolo"})
        self.assertEqual(info_yolo["mode"], "yolo")
        self.assertNotEqual(info_std["scope_fingerprint"], info_yolo["scope_fingerprint"])
        bad_approve = self.exact("approve", handle_b, info_yolo)
        bad_approve.pop("action")
        bad_approve["mode"] = "yolo"
        bad_approve["scope_fingerprint"] = info_std["scope_fingerprint"]
        self.cli("approve", bad_approve, success=False)

        # Explicit local YOLO approval with matching YOLO scope_fingerprint succeeds.
        ok_approve = self.exact("approve", handle_b, info_yolo)
        ok_approve.pop("action")
        ok_approve["mode"] = "yolo"
        ok_approve["scope_fingerprint"] = info_yolo["scope_fingerprint"]
        self.assertTrue(self.cli("approve", ok_approve)["approved"])
        tok_b = self.f.capture_tokens(self.f.exchange(client_b, self.delivered(handle_b)))
        bt = tok_b["access_token"]
        sess_b = self.connect(bt)

        # Per-connection isolation: client A stays Standard while client B has genuine BroadYolo.
        self.assertEqual(sorted(self.tools_list(at, sess_a).keys()), ["read_file"])
        tools_b = self.tools_list(bt, sess_b)
        for expected in ("read_file", "write_file", "edit_file", "exec_command", "task_run", "git_status"):
            self.assertIn(expected, tools_b)
        self.assertNotIn("process_start", tools_b)

        # Genuine BroadYolo works outside workspace root (failing-old negative control for broad.rs mask check!).
        wr = self.call_tool(bt, sess_b, "write_file", {"path": str(self.outside), "content": "yolo-ok"})
        self.assertFalse(wr.get("isError", False), wr)
        rd = self.call_tool(bt, sess_b, "read_file", {"path": str(self.outside)})
        self.assertEqual(rd["content"][0]["text"], "yolo-ok")

        # Protected paths (managed .veyl-login state + ~/.ssh + readonly ~/.bashrc) remain enforced.
        for forbidden in (
            str(self.profile / "clients.json"),
            str(self.profile / "oauth/oauth-state.json"),
            str(self.managed / "control.sock"),
            str(self.ssh_secret),
        ):
            self.assertTrue(
                self.call_tool(bt, sess_b, "read_file", {"path": forbidden}).get("isError"),
                forbidden,
            )
            self.assertTrue(
                self.call_tool(
                    bt, sess_b, "write_file", {"path": forbidden, "content": "tamper"}
                ).get("isError"),
                forbidden,
            )
        self.assertTrue(
            self.call_tool(
                bt, sess_b, "write_file", {"path": str(self.bashrc), "content": "pwnd"}
            ).get("isError")
        )

        # Sandboxed exec_command in BroadYolo masks ~/.veyl-login and ~/.ssh cleanly and sees cgroup limits.
        cmd = (
            f"test -e {shlex.quote(str(self.outside))} && "
            f"test ! -e {shlex.quote(str(self.profile / 'clients.json'))} && "
            f"test ! -e {shlex.quote(str(self.ssh_secret))} && "
            f"printf broad-exec-ok"
        )
        exec_res = self.call_tool(
            bt,
            sess_b,
            "exec_command",
            {"command": cmd, "cwd": str(self.workdir), "timeout_seconds": 10},
        )
        self.assertFalse(exec_res.get("isError", False), exec_res)
        payload = json.loads(exec_res["content"][0]["text"])
        if payload["state"] == "running":
            payload = json.loads(
                self.call_tool(
                    bt, sess_b, "job_wait", {"job_id": payload["job_id"], "timeout_seconds": 2}
                )["content"][0]["text"]
            )
        self.assertEqual(payload["exit_code"], 0, payload)
        self.assertEqual(payload["stdout"], "broad-exec-ok", payload)
        ceilings = payload.get("resource_ceilings", {})
        self.assertEqual(ceilings.get("cpu_percent"), 100, payload)
        self.assertEqual(ceilings.get("memory_bytes"), 268435456, payload)

        # FULL mode is strictly disallowed for managed OAuth.
        full_refused = self.execute([str(self.veyl), "mode", "full", client_b, "--confirm-full"])
        self.assertNotEqual(full_refused.returncode, 0)

        # Verify persisted mode across restart.
        self.stop_funnel()
        listed = self.execute([str(self.veyl), "mode"])
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn(f"{client_a}\tstandard", listed.stdout)
        self.assertIn(f"{client_b}\tyolo", listed.stdout)

        self.start_managed(first=False)
        sess_b2 = self.connect(bt)
        self.assertIn("write_file", self.tools_list(bt, sess_b2))

        # Escalating Standard -> YOLO via `veyl mode yolo` revokes Standard tokens (fresh auth required).
        esc = self.execute([str(self.veyl), "mode", "yolo", client_a])
        self.assertEqual(esc.returncode, 0, esc.stderr)
        self.assertIn("reauthorization_required=true", esc.stdout)
        self.assertEqual(self.rpc(at, "tools/list", sess_a)[0], 401)
        status, _, _ = self.f.refresh(client_a, tok_a["refresh_token"])
        self.assertEqual(status, 400)

        # Fresh OAuth authorize after escalation inspects YOLO by default and mints working YOLO token.
        tok_a2, esc_info = self.reauthorize_client(client_a)
        self.assertEqual(esc_info["mode"], "yolo")
        at2 = tok_a2["access_token"]
        sess_a2 = self.connect(at2)
        job_a = self.call_tool(
            at2,
            sess_a2,
            "exec_command",
            {"command": "printf isolated-a", "timeout_seconds": 8},
        )
        self.assertFalse(job_a.get("isError", False), job_a)
        job_a_id = json.loads(job_a["content"][0]["text"])["job_id"]
        # Cross-family job isolation: client B cannot inspect client A's YOLO job.
        self.assertTrue(
            self.call_tool(bt, sess_b2, "job_status", {"job_id": job_a_id}).get("isError")
        )

        # Downgrading client B -> Standard via dashboard/oauth CLI mode action immediately denies elevated ops!
        down = self.cli("mode", {"client_id": client_b, "mode": "standard", "confirm": True})
        self.assertTrue(down["ok"], down)
        self.assertEqual(down["mode"], "standard")
        self.assertEqual(sorted(self.tools_list(bt, sess_b2).keys()), ["read_file"])
        self.assertTrue(
            self.call_tool(
                bt, sess_b2, "write_file", {"path": str(self.outside), "content": "blocked"}
            ).get("isError")
        )
        self.assertTrue(
            self.call_tool(
                bt, sess_b2, "exec_command", {"command": "printf nope", "timeout_seconds": 5}
            ).get("isError")
        )
        # Refreshing downgraded client B must still only yield Standard access.
        refreshed_b = self.f.capture_tokens(self.f.refresh(client_b, tok_b["refresh_token"]))
        sess_b3 = self.connect(refreshed_b["access_token"])
        self.assertEqual(sorted(self.tools_list(refreshed_b["access_token"], sess_b3).keys()), ["read_file"])

        # Ambiguous logout with >1 registered clients fails without --client or --all.
        ambig = self.execute([str(self.veyl), "logout", "--yes"])
        self.assertNotEqual(ambig.returncode, 0)
        self.assertIn("Multiple OAuth clients", ambig.stderr)

        # Individual client logout while live revokes ONLY client A and keeps B & route alive.
        one = self.execute([str(self.veyl), "logout", "--client", client_a, "--yes"])
        self.assertEqual(one.returncode, 0, one.stderr)
        self.assertEqual(self.rpc(at2, "initialize", params=funnel.native.INIT)[0], 401)
        self.assertEqual(len(self.daemon.snapshot()["Foreground"]), 2)
        self.assertIn(
            "native-read-canary",
            json.dumps(self.read(refreshed_b["access_token"], sess_b3, "canary.txt")),
        )

        # Explicit --all logout revokes remaining client B and stops managed route.
        all_out = self.execute([str(self.veyl), "logout", "--all", "--yes"])
        self.assertEqual(all_out.returncode, 0, all_out.stderr)
        self.wait_for(lambda: self.daemon.snapshot() == self.daemon.initial)
        state = json.loads((self.profile / "oauth/oauth-state.json").read_text())["payload"]
        self.assertEqual(state["registry"]["clients"], [])
        self.assertEqual(state["families"], [])

    def test_offline_single_vs_all_client_logout(self):
        self.start_managed(first=True)
        client_a, _ = self.authorize_client()
        client_b, _ = self.authorize_client(approve_mode="yolo")
        self.stop_funnel()

        res_single = self.execute([str(self.veyl), "logout", "--client", client_a, "--yes"])
        self.assertEqual(res_single.returncode, 0, res_single.stderr)
        state = json.loads((self.profile / "oauth/oauth-state.json").read_text())["payload"]
        remaining_ids = [c["client_id"] for c in state["registry"]["clients"]]
        self.assertEqual(remaining_ids, [client_b])

        res_all = self.execute([str(self.veyl), "logout", "--all", "--yes"])
        self.assertEqual(res_all.returncode, 0, res_all.stderr)
        state = json.loads((self.profile / "oauth/oauth-state.json").read_text())["payload"]
        self.assertEqual(state["registry"]["clients"], [])
        self.assertEqual(state["families"], [])


if __name__ == "__main__":
    suite = unittest.TestSuite(
        [
            OAuthYoloLifecycle(name)
            for name in (
                "test_tailscale_guidance_and_cwd_default",
                "test_standard_default_yolo_isolation_and_broad_protections",
                "test_offline_single_vs_all_client_logout",
            )
        ]
    )
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
