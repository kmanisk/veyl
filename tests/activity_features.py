#!/usr/bin/env python3
"""Actual concurrent HTTP calls and transport cleanup against a disposable gateway."""

from concurrent.futures import ThreadPoolExecutor
import json
import socket
import struct
import time
import unittest

import product_features as product


class ActivityFeatures(unittest.TestCase):
    def setUp(self):
        f = self.f = product.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        state = f.base / "jobs"
        state.mkdir(mode=0o700)
        f.doc.update(
            policy_version=3, job_state_dir=str(state),
            job_profiles={
                "sleep": {"executable": "/usr/bin/sleep", "args": ["20"],
                          "timeout_seconds": 22, "max_output_bytes": 256},
            },
        )
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False)
        f.doc["clients"][0]["tools"].extend([
            "job_start", "job_status", "job_logs", "job_wait", "job_cancel", "system_info",
        ])
        f.write_config()
        f.start()
        self.session = f.connect()
        self.admin = f.pair()
        self.assertEqual(f.request(f.admin, "GET", "/api/dashboard/activity")[0], 401)
        self.assertEqual(f.request(f.mcp, "GET", "/api/dashboard/activity")[0], 404)

    def call(self, tool, args):
        return self.f.call(tool, args, self.session)

    def get_admin(self, route):
        status, _, body = self.f.request(self.f.admin, "GET", "/api/dashboard/" + route, **self.admin)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def await_view(self, predicate, timeout=2):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            value = self.get_admin("activity")
            if predicate(value):
                return value
            time.sleep(.02)
        self.fail(f"activity did not settle: {value}")

    def start_job(self):
        result = self.call("job_start", {"profile": "sleep"})
        self.assertFalse(result["isError"], result)
        job = json.loads(result["content"][0]["text"])["job_id"]
        self.addCleanup(self.call, "job_cancel", {"job_id": job})
        return job

    def wait_http(self, job):
        return self.f.request(self.f.mcp, "POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "job_wait", "arguments": {"job_id": job, "timeout_seconds": 9},
            },
        }, Authorization="Bearer " + product.TOKEN, **{"Mcp-Session-Id": self.session})

    def test_identical_active_calls_and_other_operations_on_the_same_job(self):
        job = self.start_job()
        with ThreadPoolExecutor(max_workers=2) as pool:
            waiting = [pool.submit(self.wait_http, job) for _ in range(2)]
            view = self.await_view(lambda v: v["active_calls"] == 2)
            self.assertEqual(self.get_admin("status")["active_calls"], 2)
            ids = {row["call_id"] for row in view["events"] if row["status"] == "running"}
            self.assertEqual(len(ids), 2)
            time.sleep(.09)
            self.assertFalse(self.call("job_logs", {"job_id": job})["isError"])
            self.assertEqual(self.get_admin("activity")["active_calls"], 2)
            canceled = self.call("job_cancel", {"job_id": job})
            self.assertFalse(canceled["isError"], canceled)
            for result in waiting:
                self.assertEqual(result.result(timeout=4)[0], 200)
        view = self.await_view(lambda v: not v["active_calls"])
        matched = [row for row in view["events"] if row["call_id"] in ids]
        self.assertEqual(len(matched), 2)
        self.assertTrue(all(row["tool"] == "job_wait" and row["status"] == "success"
                            and row["duration_ms"] >= 80 for row in matched))
        relevant = [row for row in view["events"] if row["tool"] in
                    {"job_start", "job_logs", "job_cancel", "job_wait"}]
        self.assertEqual(len({row["call_id"] for row in relevant}), 5)
        receipt = json.loads(canceled["content"][0]["text"])
        self.assertEqual(receipt["state"], "canceled")
        self.assertGreaterEqual(receipt["execution_duration_ms"], 80)
        self.assertNotIn("execution_duration_ms", view["events"][0])

    def test_timeout_and_disconnect_clear_active_calls(self):
        job = self.start_job()
        address = ("127.0.0.1", self.f.mcp)
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name":"job_wait", "arguments":{"job_id":job, "timeout_seconds":9},
        }}
        body = json.dumps(request).encode()
        headers = (
            f"POST /mcp HTTP/1.1\r\nHost: {address[0]}:{address[1]}\r\n"
            f"Authorization: Bearer {product.TOKEN}\r\nMcp-Session-Id: {self.session}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode()
        with socket.create_connection(address, timeout=3) as peer:
            peer.sendall(headers + body)
            running = self.await_view(lambda v: v["active_calls"] == 1)
            call_id = running["events"][0]["call_id"]
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        disconnected = self.await_view(lambda v: v["active_calls"] == 0)
        row = next(row for row in disconnected["events"] if row["call_id"] == call_id)
        self.assertEqual(row["status"], "canceled")
        self.assertEqual(self.wait_http(job)[0], 408)
        completed = self.await_view(lambda v: not v["active_calls"])
        timed_out = [row for row in completed["events"] if row["status"] == "timed_out"]
        self.assertEqual(len(timed_out), 1)
        self.assertGreaterEqual(timed_out[0]["duration_ms"], 4800)
        receipt = self.call("job_status", {"job_id": job})
        self.assertEqual(json.loads(receipt["content"][0]["text"])["state"], "running")

    def test_summary_redaction_and_trace_access(self):
        canary = "Bearer synthetic-credential-in-arg"
        route = "/api/dashboard/trace"
        status, _, _ = self.f.request(self.f.admin, "POST", route,
                                      {"enabled": True, "confirm": True}, **self.admin)
        self.assertEqual(status, 200)
        self.call("system_info", {"command": canary, "path": "/mcp/" + canary})
        self.f.rpc("tools/call", self.session, params={"name": canary, "arguments": {}})
        value = self.get_admin("activity?funnel=1")
        self.assertEqual(value["active_calls"], 0)
        self.assertTrue(all(row["status"] == "failure" for row in value["events"]))
        self.assertNotIn(canary, json.dumps(value))
        self.assertNotIn(canary, json.dumps(self.get_admin("audit")))
        self.assertNotIn(canary, self.f.audit.read_text())
        self.assertNotIn(canary, json.dumps(self.get_admin("trace?metadata=1")))
        trace = self.get_admin("trace")["events"]
        self.assertEqual(len(trace), 1)
        self.assertEqual(trace[0]["arguments"]["command"], canary)
        self.assertTrue(any(row["call_id"] == trace[0]["call_id"] for row in value["events"]))


if __name__ == "__main__":
    unittest.main()
