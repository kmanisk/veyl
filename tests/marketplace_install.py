#!/usr/bin/env python3
"""Independent E2E, adversarial archive, rollback, recovery, and real-provider suite for the Veyl marketplace installer."""
import hashlib
import base64
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import py_compile
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import product_features as pf


def sri_sha512(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_tgz(entries: list[tuple[str, bytes | str, str]]) -> bytes:
    """Build custom .tar.gz with explicit file/dir/symlink/hardlink members."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body, kind in entries:
            ti = tarfile.TarInfo(name=name)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = str(body)
                tf.addfile(ti)
            elif kind == "hardlink":
                ti.type = tarfile.LNKTYPE
                ti.linkname = str(body)
                tf.addfile(ti)
            else:
                raw = body.encode() if isinstance(body, str) else body
                ti.type = tarfile.REGTYPE
                ti.size = len(raw)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(raw))
    return buf.getvalue()


def make_whl(entries: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            raw = body.encode() if isinstance(body, str) else body
            zf.writestr(name, raw)
    return buf.getvalue()


NODE_MCP_INDEX = """
import { createInterface } from 'node:readline';
import { add } from 'mini-dep';
const rl = createInterface({ input: process.stdin });
for await (const line of rl) {
  const req = JSON.parse(line);
  if (req.id === undefined) continue;
  let result = {};
  if (req.method === 'initialize') {
    result = { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'node-demo', version: '__VER__' } };
  } else if (req.method === 'tools/list') {
    result = { tools: [{ name: 'ping', inputSchema: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } } } }] };
  } else if (req.method === 'tools/call') {
    const a = req.params.arguments || {};
    result = { content: [{ type: 'text', text: JSON.stringify({ sum: add(a.a || 0, a.b || 0), ver: '__VER__' }) }] };
  }
  console.log(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }));
}
"""

PY_MCP_SERVER = """
import json, sys
for line in sys.stdin:
    req = json.loads(line)
    if 'id' not in req:
        continue
    m = req.get('method')
    if m == 'initialize':
        res = {'protocolVersion': '2025-11-25', 'capabilities': {'tools': {}}, 'serverInfo': {'name': 'py-demo', 'version': '1.0.0'}}
    elif m == 'tools/list':
        res = {'tools': [{'name': 'echo_py', 'inputSchema': {'type': 'object', 'properties': {'msg': {'type': 'string'}}}}]}
    elif m == 'tools/call':
        res = {'content': [{'type': 'text', 'text': 'PY:' + str(req['params'].get('arguments', {}).get('msg', ''))}]}
    else:
        res = {}
    print(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': res}), flush=True)
"""


class MarketplaceInstallerTests(unittest.TestCase):
    def setUp(self):
        self.f = f = pf.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.state = f.base / "private-state"
        self.state.mkdir(mode=0o700)
        jobs = self.state / "jobs"
        jobs.mkdir(mode=0o700)
        f.audit = self.state / "audit.jsonl"
        f.audit.touch(mode=0o600)
        self.skills_dir = f.base / "managed-skills"
        self.skills_dir.mkdir(mode=0o700)
        f.config = self.state / "clients.json"
        f.doc.update(
            policy_version=4,
            audit_log=str(f.audit),
            job_state_dir=str(jobs),
            skills_dir=str(self.skills_dir),
            job_profiles={
                "probe": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 8, "max_output_bytes": 128}
            },
        )
        for c in f.doc["clients"]:
            c.update(mode="standard", disabled=False, tools=["read_file", "skills_list", "skills_read", "mcp_servers_list", "mcp_servers_call"])
        f.write_config()
        f.cli("mode", "yolo", "primary", "--confirm-native")
        f.start()
        self.headers = f.pair()

    def wait_op(self, op_id: str, timeout: float = 20.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st, _, body = self.f.request(self.f.admin, "GET", "/api/dashboard/marketplace/state", **self.headers)
            self.assertEqual(st, 200, body)
            data = json.loads(body)
            for op in data["operations"]:
                if op["op_id"] == op_id and op["done"]:
                    return op
            time.sleep(0.1)
        self.fail(f"Marketplace operation {op_id} timed out")

    def test_auth_csrf_confirm_and_negative_inputs(self):
        # Unauthenticated rejected: without Origin -> 403, with valid Origin & no session -> 401
        self.assertEqual(self.f.request(self.f.admin, "GET", "/api/dashboard/marketplace/state")[0], 401)
        self.assertEqual(self.f.request(self.f.admin, "POST", "/api/dashboard/marketplace/install", {"id": "rea", "confirm": True})[0], 403)
        self.assertEqual(self.f.request(self.f.admin, "POST", "/api/dashboard/marketplace/install", {"id": "rea", "confirm": True}, Origin=f"http://127.0.0.1:{self.f.admin}")[0], 401)
        # Missing confirm -> 403
        self.assertEqual(self.f.request(self.f.admin, "POST", "/api/dashboard/marketplace/install", {"id": "rea"}, **self.headers)[0], 403)
        self.assertEqual(self.f.request(self.f.admin, "POST", "/api/dashboard/clients/grants", {"client": "primary", "tools": ["read_file"]}, **self.headers)[0], 403)
        # Wrong Origin -> 403
        bad_origin = dict(self.headers, Origin="http://evil.example")
        self.assertEqual(self.f.request(self.f.admin, "POST", "/api/dashboard/marketplace/install", {"id": "rea", "confirm": True}, **bad_origin)[0], 403)
        # Disallow non-loopback HTTP & localhost hostname
        for bad_url in ("http://example.com/evil.tgz", "http://localhost:8080/evil.tgz"):
            st, _, body = self.f.request(
                self.f.admin,
                "POST",
                "/api/dashboard/marketplace/install",
                {"id": "badhttp", "kind": "npm", "entrypoint": "index.js", "url": bad_url, "sha256": "0" * 64, "confirm": True},
                **self.headers,
            )
            self.assertEqual(st, 200, body)
            op = self.wait_op(json.loads(body)["op_id"])
            self.assertEqual(op["phase"], "failed", op)

    def test_malicious_archives_hooks_integrity_rollback_and_cancellation(self):
        files: dict[str, bytes] = {}
        slow_release = threading.Event()
        slow_started = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/slow.tgz":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    slow_started.set()
                    chunk = b"\x1f\x8b" + b"\x00" * 1024
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    slow_release.wait(timeout=5)
                    return
                if self.path in files:
                    payload = files[self.path]
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_port
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(lambda: (slow_release.set(), srv.shutdown(), srv.server_close(), t.join(timeout=2)))
        base_url = f"http://127.0.0.1:{port}"

        # 1. Traversal, absolute path, symlink, hardlink, lifecycle hook, integrity mismatch
        trav_tgz = make_tgz([("package/../../evil.txt", b"pwn", "file"), ("package/package.json", '{"name":"x","version":"1.0.0","bin":"index.js"}', "file"), ("package/index.js", "x", "file")])
        sym_tgz = make_tgz([("package/link", "/etc/passwd", "symlink"), ("package/package.json", '{"name":"x","version":"1.0.0"}', "file")])
        hlink_tgz = make_tgz([("package/a", "x", "file"), ("package/b", "package/a", "hardlink")])
        hook_tgz = make_tgz([("package/package.json", '{"name":"evilpkg","version":"1.0.0","scripts":{"postinstall":"touch /tmp/pwn"}}', "file"), ("package/index.js", "", "file")])

        files["/trav.tgz"] = trav_tgz
        files["/sym.tgz"] = sym_tgz
        files["/hlink.tgz"] = hlink_tgz
        files["/hook.tgz"] = hook_tgz

        for path_name, tgz in (("/trav.tgz", trav_tgz), ("/sym.tgz", sym_tgz), ("/hlink.tgz", hlink_tgz), ("/hook.tgz", hook_tgz)):
            st, _, b = self.f.request(
                self.f.admin,
                "POST",
                "/api/dashboard/marketplace/install",
                {"id": "badpkg", "kind": "npm", "entrypoint": "index.js", "url": base_url + path_name, "sha256": sha256_hex(tgz), "confirm": True},
                **self.headers,
            )
            self.assertEqual(st, 200, b)
            op = self.wait_op(json.loads(b)["op_id"])
            self.assertEqual(op["phase"], "failed", f"{path_name} unexpectedly succeeded: {op}")
            self.assertFalse((self.state / "upstream-bundles/badpkg").exists())

        # Integrity mismatch
        st, _, b = self.f.request(
            self.f.admin,
            "POST",
            "/api/dashboard/marketplace/install",
            {"id": "badsum", "kind": "npm", "entrypoint": "index.js", "url": base_url + "/hook.tgz", "sha256": "f" * 64, "confirm": True},
            **self.headers,
        )
        self.assertEqual(st, 200)
        op = self.wait_op(json.loads(b)["op_id"])
        self.assertEqual(op["phase"], "failed")
        self.assertIn("mismatch", (op.get("error") or "").lower())

        # 2. Loopback mock npm registry with dependency closure (v1 -> valid, v2 -> fails probe & rolls back to v1!)
        dep_tgz = make_tgz([
            ("package/package.json", '{"name":"mini-dep","version":"1.0.0"}', "file"),
            ("package/index.js", "export function add(a, b) { return a + b; }\n", "file"),
        ])
        v1_tgz = make_tgz([
            ("package/package.json", '{"name":"node-demo","version":"1.0.0","type":"module","bin":{"node-demo":"index.js"},"dependencies":{"mini-dep":"^1.0.0"}}', "file"),
            ("package/index.js", NODE_MCP_INDEX.replace("__VER__", "1.0.0"), "file"),
        ])
        v2_broken_tgz = make_tgz([
            ("package/package.json", '{"name":"node-demo","version":"2.0.0","type":"module","bin":{"node-demo":"index.js"},"dependencies":{"mini-dep":"^1.0.0"}}', "file"),
            ("package/index.js", "process.exit(1);\n", "file"),
        ])
        files["/mini-dep-1.0.0.tgz"] = dep_tgz
        files["/node-demo-1.0.0.tgz"] = v1_tgz
        files["/node-demo-2.0.0.tgz"] = v2_broken_tgz
        files["/mini-dep"] = json.dumps({
            "name": "mini-dep",
            "versions": {"1.0.0": {"name": "mini-dep", "version": "1.0.0", "dist": {"tarball": base_url + "/mini-dep-1.0.0.tgz", "integrity": sri_sha512(dep_tgz)}}}
        }).encode()
        files["/node-demo/1.0.0"] = json.dumps({
            "name": "node-demo",
            "version": "1.0.0",
            "dependencies": {"mini-dep": "^1.0.0"},
            "dist": {"tarball": base_url + "/node-demo-1.0.0.tgz", "integrity": sri_sha512(v1_tgz)},
        }).encode()
        files["/node-demo/2.0.0"] = json.dumps({
            "name": "node-demo",
            "version": "2.0.0",
            "dependencies": {"mini-dep": "^1.0.0"},
            "dist": {"tarball": base_url + "/node-demo-2.0.0.tgz", "integrity": sri_sha512(v2_broken_tgz)},
        }).encode()

        # Install v1 via loopback mock npm registry with dependency closure (mini-dep -> node-demo)
        st, _, b = self.f.request(
            self.f.admin, "POST", "/api/dashboard/marketplace/install",
            {"id": "nodedemo", "kind": "npm", "package": "node-demo", "version": "1.0.0", "registry_url": base_url, "confirm": True},
            **self.headers,
        )
        self.assertEqual(st, 200, b)
        op_node = self.wait_op(json.loads(b)["op_id"])
        self.assertEqual(op_node["phase"], "ready", op_node)
        st_ng, _, ngb = self.f.request(
            self.f.admin, "POST", "/api/dashboard/clients/grants",
            {"client": "primary", "allowed_server_tools": {"nodedemo": ["ping"]}, "confirm": True},
            **self.headers,
        )
        self.assertEqual(st_ng, 200, ngb)
        sess_n = self.f.connect()
        call_n = self.f.call("nodedemo__ping", {"a": 19, "b": 23}, sess_n)
        self.assertFalse(call_n.get("isError", False), call_n)
        self.assertEqual(json.loads(call_n["content"][0]["text"]), {"sum": 42, "ver": "1.0.0"})

        # Failed v2 update automatically rolls back to v1.0.0 cleanly!
        st, _, b = self.f.request(
            self.f.admin, "POST", "/api/dashboard/marketplace/install",
            {"id": "nodedemo", "kind": "npm", "package": "node-demo", "version": "2.0.0", "registry_url": base_url, "update": True, "confirm": True},
            **self.headers,
        )
        self.assertEqual(st, 200, b)
        op_node_fail = self.wait_op(json.loads(b)["op_id"])
        self.assertEqual(op_node_fail["phase"], "failed", op_node_fail)
        self.assertIn("rolled back", (op_node_fail.get("error") or "").lower())
        call_n2 = self.f.call("nodedemo__ping", {"a": 5, "b": 7}, sess_n)
        self.assertFalse(call_n2.get("isError", False), call_n2)
        self.assertEqual(json.loads(call_n2["content"][0]["text"]), {"sum": 12, "ver": "1.0.0"})

        whl_bytes = make_whl({
            "py_demo/__init__.py": "",
            "py_demo/server.py": PY_MCP_SERVER,
            "py_demo-1.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: py-demo\nVersion: 1.0.0\n",
            "py_demo-1.0.0.dist-info/entry_points.txt": "[console_scripts]\npy-demo = py_demo.server:main\n",
        })
        # Adjust PY_MCP_SERVER to expose main() function!
        whl_bytes = make_whl({
            "py_demo/__init__.py": "",
            "py_demo/server.py": "def main():\n" + "\n".join("    " + ln for ln in PY_MCP_SERVER.splitlines()) + "\n",
            "py_demo-1.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: py-demo\nVersion: 1.0.0\n",
            "py_demo-1.0.0.dist-info/entry_points.txt": "[console_scripts]\npy-demo = py_demo.server:main\n",
        })
        files["/py_demo-1.0.0-py3-none-any.whl"] = whl_bytes
        files["/pypi/py-demo/1.0.0/json"] = json.dumps({
            "info": {"name": "py-demo", "version": "1.0.0", "requires_dist": []},
            "urls": [{"filename": "py_demo-1.0.0-py3-none-any.whl", "packagetype": "bdist_wheel", "url": base_url + "/py_demo-1.0.0-py3-none-any.whl", "digests": {"sha256": sha256_hex(whl_bytes)}}],
        }).encode()
        st, _, b = self.f.request(
            self.f.admin, "POST", "/api/dashboard/marketplace/install",
            {"id": "pydemo", "kind": "pypi", "version": "1.0.0", "registry_url": base_url, "entrypoint": "py-demo", "confirm": True},
            **self.headers,
        )
        # Note for pypi: req.entrypoint was pkg_name fallback when not in catalog, wait: parse_req uses req.entrypoint as pkg AND stage_pypi uses req.entrypoint as preferred "mod:func"! If no ':' in req.entrypoint, find_console_script parses entry_points.txt! Brilliant!
        self.assertEqual(st, 200, b)
        op_py = self.wait_op(json.loads(b)["op_id"])
        self.assertEqual(op_py["phase"], "ready", op_py)

        # Grant pydemo tool to primary via bulk client grant API and call it over MCP!
        st, _, gb = self.f.request(
            self.f.admin, "POST", "/api/dashboard/clients/grants",
            {"client": "primary", "allowed_server_tools": {"pydemo": ["echo_py"]}, "confirm": True},
            **self.headers,
        )
        self.assertEqual(st, 200, gb)
        sess = self.f.connect()
        call_res = self.f.call("pydemo__echo_py", {"msg": "verified-wheel"}, sess)
        self.assertFalse(call_res.get("isError", False), call_res)
        self.assertEqual(call_res["content"][0]["text"], "PY:verified-wheel")

        # Simulate failed update rollback on pydemo (broken wheel crashes on probe -> rolls back to v1.0.0 cleanly!)
        bad_whl = make_whl({
            "py_demo/__init__.py": "",
            "py_demo/server.py": "import sys\ndef main(): sys.exit(1)\n",
            "py_demo-2.0.0.dist-info/entry_points.txt": "[console_scripts]\npy-demo = py_demo.server:main\n",
        })
        files["/py_demo-2.0.0-py3-none-any.whl"] = bad_whl
        files["/pypi/py-demo/2.0.0/json"] = json.dumps({
            "info": {"name": "py-demo", "version": "2.0.0", "requires_dist": []},
            "urls": [{"filename": "py_demo-2.0.0-py3-none-any.whl", "packagetype": "bdist_wheel", "url": base_url + "/py_demo-2.0.0-py3-none-any.whl", "digests": {"sha256": sha256_hex(bad_whl)}}],
        }).encode()
        st, _, b = self.f.request(
            self.f.admin, "POST", "/api/dashboard/marketplace/install",
            {"id": "pydemo", "kind": "pypi", "version": "2.0.0", "registry_url": base_url, "entrypoint": "py-demo", "update": True, "confirm": True},
            **self.headers,
        )
        op_upd = self.wait_op(json.loads(b)["op_id"])
        self.assertEqual(op_upd["phase"], "failed", op_upd)
        self.assertIn("rolled back", (op_upd.get("error") or "").lower())
        # Verify v1.0.0 still works intact after failed update rollback!
        call_after = self.f.call("pydemo__echo_py", {"msg": "still-alive"}, sess)
        self.assertFalse(call_after.get("isError", False), call_after)
        self.assertEqual(call_after["content"][0]["text"], "PY:still-alive")

        # Test slow download cancellation + staging cleanup
        st, _, b = self.f.request(
            self.f.admin, "POST", "/api/dashboard/marketplace/install",
            {"id": "slowpkg", "kind": "binary", "url": base_url + "/slow.tgz", "sha256": "0" * 64, "confirm": True},
            **self.headers,
        )
        slow_op = json.loads(b)["op_id"]
        self.assertTrue(slow_started.wait(timeout=3))
        st_c, _, _ = self.f.request(
            self.f.admin, "POST", "/api/dashboard/marketplace/cancel",
            {"op_id": slow_op, "confirm": True},
            **self.headers,
        )
        self.assertEqual(st_c, 200)
        slow_release.set()
        op_c = self.wait_op(slow_op)
        self.assertEqual(op_c["phase"], "cancelled", op_c)
        self.assertFalse((self.state / "upstream-bundles/slowpkg").exists())

        # Test skill install (guidance-only SKILL.md, script ignored & never run)
        skill_tgz = make_tgz([
            ("skills/demo-skill/SKILL.md", "---\nname: demo-skill\ndescription: Guidance skill\n---\nOnly guidance.\n", "file"),
            ("skills/demo-skill/scripts/untrusted.sh", "#!/bin/sh\ntouch /tmp/never-run\n", "file"),
        ])
        files["/skill.tgz"] = skill_tgz
        st, _, b = self.f.request(
            self.f.admin, "POST", "/api/dashboard/marketplace/install",
            {"id": "skill-demo", "kind": "skill", "entrypoint": "demo-skill", "url": base_url + "/skill.tgz", "sha256": sha256_hex(skill_tgz), "confirm": True},
            **self.headers,
        )
        op_sk = self.wait_op(json.loads(b)["op_id"])
        self.assertEqual(op_sk["phase"], "ready", op_sk)
        self.assertTrue((self.skills_dir / "demo-skill/SKILL.md").is_file())
        self.assertFalse((self.skills_dir / "demo-skill/scripts").exists())

        # Crash recovery: simulate leftover .journal-*.json + .backup-pydemo and verify recover restores backup cleanly!
        backup_dir = self.state / "upstream-bundles/.backup-pydemo"
        if backup_dir.exists():
            backup_dir.rmdir()
        backup_dir.mkdir(mode=0o700)
        (backup_dir / "canary.txt").write_text("from-backup")
        (backup_dir / "canary.txt").chmod(0o600)
        journal_path = self.state / "upstream-installs/.journal-op-crashed.json"
        journal_path.write_text(json.dumps({
            "op_id": "op-crashed", "id": "pydemo", "kind": "pypi", "phase": "swapping",
            "is_skill": False, "skill_name": None, "had_previous_bundle": True,
            "previous_server": json.loads(self.f.config.read_text())["mcp_servers"]["pydemo"],
            "previous_receipt": json.loads((self.state / "upstream-installs/pydemo.json").read_text()),
            "started_at": 1,
        }))
        st_rec, _, _ = self.f.request(self.f.admin, "POST", "/api/dashboard/marketplace/recover", {"confirm": True}, **self.headers)
        self.assertEqual(st_rec, 200)
        self.assertFalse(journal_path.exists())
        self.assertFalse(backup_dir.exists())
        self.assertEqual((self.state / "upstream-bundles/pydemo/canary.txt").read_text(), "from-backup")

        # Uninstall cleans bundle + server + client grants
        st_u, _, _ = self.f.request(self.f.admin, "POST", "/api/dashboard/marketplace/uninstall", {"id": "pydemo", "confirm": True}, **self.headers)
        self.assertEqual(st_u, 200)
        self.assertFalse((self.state / "upstream-bundles/pydemo").exists())
        self.assertNotIn("pydemo", json.loads(self.f.config.read_text()).get("mcp_servers", {}))
        # Also verify state layout remains valid after install/uninstall under Broad YOLO!
        chk = self.f.cli("state", "check", "--state-root", str(self.state))
        self.assertIn("layout=valid", chk)

    def test_real_rea_and_rust_anything_end_to_end(self):
        # Install real Rust Anything v4.1.0 from official GitHub release + real REA 6.10.1 from npm!
        st1, _, b1 = self.f.request(self.f.admin, "POST", "/api/dashboard/marketplace/install", {"id": "rust-anything", "confirm": True}, **self.headers)
        self.assertEqual(st1, 200, b1)
        op_rust = self.wait_op(json.loads(b1)["op_id"], timeout=60.0)
        self.assertEqual(op_rust["phase"], "ready", op_rust)

        st2, _, b2 = self.f.request(self.f.admin, "POST", "/api/dashboard/marketplace/install", {"id": "rea", "confirm": True}, **self.headers)
        self.assertEqual(st2, 200, b2)
        op_rea = self.wait_op(json.loads(b2)["op_id"], timeout=90.0)
        self.assertEqual(op_rea["phase"], "ready", op_rea)

        # Grant explicit tools on both real providers + verify Broad YOLO state layout passes!
        chk = self.f.cli("state", "check", "--state-root", str(self.state))
        self.assertIn("layout=valid", chk)
        st_g, _, gb = self.f.request(
            self.f.admin, "POST", "/api/dashboard/clients/grants",
            {
                "client": "primary",
                "allowed_server_tools": {
                    "rust-anything": ["analyze"],
                    "rea": ["inspect_python_pyc"],
                },
                "confirm": True,
            },
            **self.headers,
        )
        self.assertEqual(st_g, 200, gb)

        # Create real pyc + py test fixture inside bundles to call through Bubblewrap
        rust_bundle = self.state / "upstream-bundles/rust-anything"
        (rust_bundle / "sample.py").write_text("def add(a, b):\n    return a + b\n")
        (rust_bundle / "sample.py").chmod(0o600)
        rea_bundle = self.state / "upstream-bundles/rea"
        (rea_bundle / "sample.py").write_text("def veyl_real_canary(x):\n    return x + 1\n")
        (rea_bundle / "sample.py").chmod(0o600)
        py_compile.compile(str(rea_bundle / "sample.py"), cfile=str(rea_bundle / "sample.pyc"), dfile="sample.py", doraise=True)
        (rea_bundle / "sample.pyc").chmod(0o600)

        sess = self.f.connect()
        r_rust = self.f.call("rust-anything__analyze", {"root": "/upstream/bundle"}, sess)
        self.assertFalse(r_rust.get("isError", False), r_rust)
        self.assertEqual(r_rust["structuredContent"]["language"], "python", r_rust)

        r_rea = self.f.call("rea__inspect_python_pyc", {"path": "/upstream/bundle/sample.pyc", "detail": "complete"}, sess)
        self.assertFalse(r_rea.get("isError", False), r_rea)
        self.assertIn("veyl_real_canary", json.dumps(r_rea), r_rea)

        # Configure REA families cleanly + verify uninstall leaves zero leftovers
        st_cfg, _, cb = self.f.request(
            self.f.admin, "POST", "/api/dashboard/marketplace/configure",
            {"id": "rea", "tool_families": "artifact", "confirm": True},
            **self.headers,
        )
        self.assertEqual(st_cfg, 200, cb)
        self.assertEqual(json.loads(cb)["probe"]["health"], "ready")

    def test_browser_marketplace_ui_and_live_preview_reload(self):
        import shutil
        browser = os.environ.get("VEYL_TEST_BROWSER") or shutil.which("brave") or shutil.which("chromium")
        if not browser:
            self.skipTest("Chromium/Brave browser binary unavailable")
        pair_out = subprocess.check_output(
            [pf.BIN, "dashboard", "pair", "--config", str(self.f.config)],
            text=True,
            timeout=5,
        )
        token = None
        for line in pair_out.splitlines():
            if line.startswith("PAIRING_TOKEN="):
                token = line.split("=", 1)[1].strip()
        self.assertTrue(token, pair_out)
        url = f"http://127.0.0.1:{self.f.admin}/dashboard/login#pair={token}"
        script = r"""
import {spawn} from "node:child_process";
import {mkdtemp, readFile, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import assert from "node:assert/strict";
const [browser, url] = process.argv.slice(1);
const profile = await mkdtemp(join(tmpdir(), "veyl-mkt-cdp-"));
const child = spawn(browser, ["--headless","--incognito","--ozone-platform=headless",
  "--disable-gpu","--disable-background-networking","--disable-component-update",
  "--disable-extensions","--no-proxy-server","--password-store=basic","--no-first-run",
  "--no-default-browser-check","--remote-debugging-port=0","--user-data-dir="+profile,"about:blank"], {stdio:"ignore"});
const delay = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, timeout=8000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    try { const v = await fn(); if (v) return v; } catch {}
    await delay(100);
  }
  throw Error("Browser assertion timeout");
}
let ws;
try {
  const port = await until(async () => Number((await readFile(join(profile,"DevToolsActivePort"),"utf8")).split("\n")[0]));
  const page = await until(async () => (await (await fetch("http://127.0.0.1:"+port+"/json/list")).json()).find(p => p.type === "page"));
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let sid = 0; const pending = new Map();
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      const {res, rej, t} = pending.get(m.id); pending.delete(m.id); clearTimeout(t);
      if (m.error) rej(Error("CDP failed")); else res(m.result);
    }
  };
  const send = (method, params={}) => new Promise((res, rej) => {
    const id = ++sid;
    const t = setTimeout(() => { pending.delete(id); rej(Error("CDP timeout")); }, 4000);
    pending.set(id, {res, rej, t}); ws.send(JSON.stringify({id, method, params}));
  });
  const ev = async expr => {
    const r = await send("Runtime.evaluate", {expression: expr, returnByValue: true});
    if (r.exceptionDetails) throw Error("JS error: " + JSON.stringify(r.exceptionDetails));
    return r.result.value;
  };
  await send("Page.navigate", {url});
  await until(() => ev("!document.querySelector('#dashboard')?.hidden"));
  await ev("document.querySelector('nav a[href=\"#marketplace\"]').click()");
  await until(() => ev("document.querySelectorAll('#verified-providers article').length >= 5"));
  assert.ok(await ev("!!document.querySelector('#verified-providers article[data-recipe=rea]')"));
  assert.ok(await ev("!!document.querySelector('#verified-providers article[data-recipe=rust-anything]')"));
  assert.ok(await ev("Array.from(document.querySelectorAll('#verified-providers article[data-recipe=rust-anything] button')).some(b => b.textContent === 'Install')"));
  assert.ok(await ev("Array.from(document.querySelectorAll('#catalog-cards article[data-entry=rea] button')).some(b => b.textContent === 'Install')"));
  await ev("document.querySelector('nav a[href=\"#clients\"]').click()");
  await until(() => ev("document.querySelectorAll('#native-grant-grid input[type=checkbox]').length === 81"));
  await ev("document.querySelector('#grant-all-safe').click()");
  assert.equal(await ev("document.querySelectorAll('#native-grant-grid input[type=checkbox]:checked').length"), 78);
  assert.equal(await ev("Array.from(document.querySelectorAll('#native-grant-grid input[type=checkbox]')).filter(b=>b.value.startsWith('rewind') && b.checked).length"),0);
  await ev("document.querySelector('nav a[href=\"#servers\"]').click()");
  assert.ok(await ev("!!document.querySelector('#upstream-bulk-card') && !!document.querySelector('#server-add')"));
  console.log("BROWSER_MARKETPLACE_UI_PASS");
} finally {
  if (ws) ws.close();
  child.kill("SIGTERM");
  await rm(profile, {recursive: true, force: true});
}
"""
        cdp = subprocess.run(
            ["node", "--input-type=module", "-e", script, browser, url],
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(cdp.returncode, 0, cdp.stdout + "\n" + cdp.stderr)
        self.assertIn("BROWSER_MARKETPLACE_UI_PASS", cdp.stdout)


if __name__ == "__main__":
    unittest.main()
