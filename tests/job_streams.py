#!/usr/bin/env python3
"""Regression: independent job log byte cursors must never skip delayed streams."""

import json
import time
import unittest

import product_features as product


class JobStreams(unittest.TestCase):
    def test_independent_streams_and_byte_offsets(self):
        f = product.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        state = f.base / "jobs"
        state.mkdir(mode=0o700)
        gate = f.workspace / "continue"
        code = (
            "import os,time,pathlib,sys\n"
            "os.write(1,b'abcde')\n"
            "deadline=time.monotonic()+5\n"
            "while not pathlib.Path(sys.argv[1]).exists():\n"
            " if time.monotonic()>deadline: raise RuntimeError('gate timeout')\n"
            " time.sleep(.02)\n"
            "os.write(2,b'late')\n"
            "os.write(1,bytes([255,90]))\n"
        )
        f.doc.update(
            policy_version=3, job_state_dir=str(state),
            job_profiles={"streams": {"executable": "/usr/bin/python3",
                                      "args": ["-c", code, str(gate)],
                                      "timeout_seconds": 8, "max_output_bytes": 128}},
        )
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False)
        f.doc["clients"][0]["tools"].extend(["job_start", "job_status", "job_logs", "job_cancel"])
        f.write_config()
        f.start()
        session = f.connect()
        def call(tool, args):
            result = f.call(tool, args, session)
            self.assertFalse(result["isError"], result)
            return json.loads(result["content"][0]["text"])

        job = call("job_start", {"profile": "streams"})["job_id"]
        self.addCleanup(f.call, "job_cancel", {"job_id": job}, session)
        deadline = time.monotonic() + 3
        while True:
            first = call("job_logs", {"job_id": job, "stdout_offset": 0, "stderr_offset": 0})
            if first["stdout"] == "abcde":
                break
            self.assertLess(time.monotonic(), deadline, first)
            time.sleep(.02)
        self.assertEqual(first["stderr"], "")
        self.assertEqual((first["next_stdout_offset"], first["next_stderr_offset"]), (5, 0))
        gate.touch()
        deadline = time.monotonic() + 5
        while True:
            status = call("job_status", {"job_id": job})
            if status["state"] not in ("starting", "running"):
                break
            self.assertLess(time.monotonic(), deadline, status)
            time.sleep(.02)
        self.assertEqual(status["exit_code"], 0, status)
        page = call("job_logs", {"job_id": job, "stdout_offset": 5, "stderr_offset": 0, "max_bytes": 2})
        self.assertEqual(page["stdout"], "\ufffdZ")
        self.assertEqual(page["stderr"], "la")
        self.assertEqual((page["next_stdout_offset"], page["next_stderr_offset"]), (7, 2))
        last = call("job_logs", {"job_id": job, "stdout_offset": 7, "stderr_offset": 2, "max_bytes": 2})
        self.assertEqual(last["stdout"], "")
        self.assertEqual(last["stderr"], "te")
        self.assertEqual((last["next_stdout_offset"], last["next_stderr_offset"]), (7, 4))
        self.assertTrue(last["ended"])
        legacy = call("job_logs", {"job_id": job, "offset": 5})
        self.assertEqual(legacy["next_offset"], 7)
        for invalid in ({"offset": 0, "stdout_offset": 0}, {"stderr_offset": -1}, {"stdout_offset": "0"}):
            self.assertTrue(f.call("job_logs", {"job_id": job, **invalid}, session)["isError"])
        other = f.connect(product.OTHER_TOKEN)
        self.assertTrue(f.call("job_logs", {"job_id": job, "stdout_offset": 0}, other, product.OTHER_TOKEN)["isError"])


if __name__ == "__main__":
    unittest.main()
