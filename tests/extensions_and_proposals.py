#!/usr/bin/env python3
"""E2E and security acceptance suite for Phase C2 extensions, skills validation, upstream inspection, and inert proposals."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import product_features as pf


class ExtensionsAndProposalsTests(unittest.TestCase):
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
        self.f.doc["job_profiles"] = {
            "probe": {
                "executable": "/usr/bin/true",
                "args": [],
                "timeout_seconds": 8,
                "max_output_bytes": 128,
            }
        }
        self.repo = Path(self.f.doc["clients"][0]["root"])
        self.state = state

    def start(self, tools, broad=False):
        self.f.doc["policy_version"] = 3
        for client in self.f.doc["clients"]:
            client["mode"] = "standard"
            client["disabled"] = False
        primary = self.f.doc["clients"][0]
        primary["tools"] = tools
        self.f.write_config()
        if broad:
            self.f.cli("mode", "yolo", primary["id"])
        proc = self.f.start()
        self.addCleanup(self.f.stop, proc)
        return self.f.connect(token=pf.TOKEN)

    def call(self, session, name, arguments=None, error=False):
        res = self.f.call(name, arguments or {}, session)
        if error:
            self.assertTrue(res["isError"], f"{name} unexpectedly succeeded: {res}")
            return res["content"][0]["text"]
        self.assertFalse(res["isError"], f"{name} unexpectedly failed: {res}")
        return json.loads(res["content"][0]["text"])

    def test_marketplace_search_skills_validate_and_inert_proposals(self):
        skills_dir = self.f.base / "managed-skills"
        skills_dir.mkdir(mode=0o700)
        ok_skill = skills_dir / "clean-skill"
        ok_skill.mkdir()
        (ok_skill / "SKILL.md").write_text("---\nname: clean-skill\ndescription: Clean operator skill\n---\nInstructions.\n")

        bad_proj = self.repo / ".agents/skills/broken-skill"
        bad_proj.mkdir(parents=True)
        (bad_proj / "SKILL.md").write_text("no frontmatter\n")

        self.f.doc["skills_dir"] = str(skills_dir)
        self.f.doc["clients"][0]["skills"] = ["clean-skill"]

        tools = [
            "extensions_search",
            "extensions_list",
            "extensions_info",
            "skills_validate",
            "extensions_propose_add",
            "extensions_propose_remove",
            "mcp_propose_add",
            "mcp_propose_update",
            "mcp_propose_remove",
            "mcp_propose_disable",
            "skills_propose_add",
            "skills_propose_remove",
        ]
        sess = self.start(tools)

        search = self.call(sess, "extensions_search", {"query": "context7", "limit": 5})
        self.assertGreater(search["count"], 0)
        self.assertEqual(search["entries"][0]["id"], "npm-upstash-context7-mcp")

        info = self.call(sess, "extensions_info", {"query": "clean-skill"})
        self.assertEqual(info["count"], 1)
        self.assertEqual(info["entries"][0]["key"], "skill:clean-skill")

        validated = self.call(sess, "skills_validate")
        self.assertFalse(validated["ok"])
        by_key = {r["key"]: r for r in validated["results"]}
        self.assertTrue(by_key["skill:clean-skill"]["valid"])
        self.assertFalse(by_key["skill:broken-skill"]["valid"])

        config_before = self.f.config.read_bytes()
        prop_ids = []
        for tool, args in [
            ("extensions_propose_add", {"source": "https://example.invalid/ext", "selection": ["mcp:demo"]}),
            ("extensions_propose_remove", {"name": "mcp:demo"}),
            ("mcp_propose_add", {"source": "https://example.invalid/mcp", "name": "demo"}),
            ("mcp_propose_update", {"name": "demo", "source": "https://example.invalid/mcp-v2"}),
            ("mcp_propose_remove", {"name": "demo"}),
            ("mcp_propose_disable", {"name": "demo"}),
            ("skills_propose_add", {"source": "/nonexistent/local/skill", "scope": "user"}),
            ("skills_propose_remove", {"name": "clean-skill"}),
        ]:
            res = self.call(sess, tool, args)
            self.assertEqual(res["status"], "pending_operator_review")
            self.assertTrue(res["operator_review_required"])
            self.assertTrue(res["inert"])
            prop_ids.append(res["id"])
        self.assertEqual(self.f.config.read_bytes(), config_before)

        prop_dir = self.state / "proposals"
        for pid in prop_ids:
            p = prop_dir / f"{pid}.json"
            self.assertTrue(p.is_file())
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

        # Operator state validation must continue to pass cleanly with queued proposals.
        subprocess.run(
            [str(pf.BIN), "state", "check", "--state-root", str(self.state), "--config", str(self.f.config)],
            check=True,
            capture_output=True,
            text=True,
        )

        # Dashboard can inspect and dismiss queued proposals cleanly.
        dash_headers = self.f.pair()
        st, hdrs, raw = self.f.request(
            self.f.admin, "GET", "/api/dashboard/requests",
            **dash_headers,
        )
        self.assertEqual(st, 200, raw)
        listed = json.loads(raw)
        self.assertEqual(listed["count"], len(prop_ids))

        st, _, raw = self.f.request(
            self.f.admin, "POST", "/api/dashboard/requests",
            {"confirm": True, "action": "dismiss", "id": prop_ids[0]},
            **dash_headers,
        )
        self.assertEqual(st, 200, raw)
        self.assertTrue(json.loads(raw)["dismissed"])

    def test_mcp_info_fingerprint_binding_and_probe(self):
        script = self.f.base / "fake_mcp.py"
        script.write_text(
            """#!/usr/bin/env python3
import json, sys
for line in sys.stdin:
    req = json.loads(line)
    m = req.get("method")
    if m == "initialize":
        resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "demo", "version": "1.0"}}}
    elif m == "tools/list":
        resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"tools": [{"name": "echo", "description": "Echo", "inputSchema": {"type": "object", "properties": {}}}]}}
    elif "id" in req:
        resp = {"jsonrpc": "2.0", "id": req["id"], "result": {}}
    else:
        continue
    sys.stdout.write(json.dumps(resp) + "\\n")
    sys.stdout.flush()
"""
        )
        script.chmod(0o755)
        self.f.doc["mcp_servers"] = {
            "demo": {"transport": "stdio", "command": "/usr/bin/python3", "args": [str(script)], "enabled": True},
            "other": {"transport": "stdio", "command": "/usr/bin/python3", "args": [str(script)], "enabled": True},
        }
        self.f.doc["clients"][0]["allowed_servers"] = ["demo"]
        self.f.doc["clients"][0]["allowed_server_tools"] = {"demo": ["echo"]}

        sess = self.start(["mcp_list", "mcp_status", "mcp_info", "mcp_test"])
        listed = self.call(sess, "mcp_list")
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["providers"][0]["id"], "demo")

        status = self.call(sess, "mcp_status")
        self.assertEqual(status["count"], 1)

        # Ungranted server cannot be inspected or tested.
        self.call(sess, "mcp_info", {"name": "other"}, error=True)

        info = self.call(sess, "mcp_info", {"name": "demo"})
        fp = info["provider_fingerprint"]
        self.assertEqual(len(fp), 64)

        # Stale/wrong fingerprint must fail closed before probing upstream.
        wrong_fp = ("0" if fp[0] != "0" else "1") + fp[1:]
        err = self.call(sess, "mcp_test", {"name": "demo", "provider_fingerprint": wrong_fp}, error=True)
        self.assertIn("PROVIDER_FINGERPRINT_CHANGED", err)

        tested = self.call(sess, "mcp_test", {"name": "demo", "provider_fingerprint": fp})
        self.assertEqual(tested["health"], "ready")
        self.assertIn("echo", tested["tools"])

    def test_yolo_preset_excludes_extension_management_tools(self):
        sess = self.start(["read_file"], broad=True)
        tools_resp = self.f.request(
            self.f.mcp,
            "POST",
            "/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            Authorization="Bearer " + pf.TOKEN,
            **{"Mcp-Session-Id": sess},
        )
        self.assertEqual(tools_resp[0], 200)
        tools = {t["name"] for t in json.loads(tools_resp[2])["result"]["tools"]}
        for protected in ("mcp_test", "mcp_list", "mcp_info", "extensions_propose_add", "skills_propose_add"):
            self.assertNotIn(protected, tools)


if __name__ == "__main__":
    unittest.main()
