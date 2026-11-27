#!/usr/bin/env python3
"""Guard verification uses tiny disposable processes, never Cargo."""
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import guarded_cargo as guard


class GuardTests(unittest.TestCase):
    def test_preflight_does_not_spawn(self):
        with patch.object(guard.subprocess, "Popen") as spawn:
            self.assertEqual(guard.supervise(["unused"], {}, (), lambda _: guard.START_FREE - 1), 75)
            spawn.assert_not_called()

    def test_low_space_terminates_owned_process(self):
        values = iter((guard.START_FREE, guard.STOP_FREE - 1))
        self.assertEqual(guard.supervise(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            os.environ.copy(), (), lambda _: next(values)), 75)

    def test_exit_code_propagated(self):
        self.assertEqual(guard.supervise(
            [sys.executable, "-c", "raise SystemExit(7)"], os.environ.copy(),
            (), lambda _: guard.START_FREE), 7)

    def test_shared_lock_refuses_second_invocation(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            (home / "Projects/veyl/target").mkdir(parents=True)
            state = home / ".local/share/veyl-development"
            state.mkdir(parents=True)
            with (state / "guarded-cargo.lock").open("w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(guard.Path, "home", return_value=home), \
                     patch.object(guard, "supervise") as spawn:
                    self.assertEqual(guard.main(["test"]), 75)
                    spawn.assert_not_called()

    def test_scratch_and_shared_build_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            target = home / "Projects/veyl/target"
            target.mkdir(parents=True)
            (home / ".local/share/veyl-development").mkdir(parents=True)
            scratch_paths = []

            def inspect(command, env, paths):
                self.assertEqual(command, ["cargo", "test", "--offline", "--locked", "-j", "1"])
                self.assertEqual(env["CARGO_TARGET_DIR"], str(target))
                self.assertEqual(env["CARGO_INCREMENTAL"], "0")
                self.assertEqual(env["CARGO_PROFILE_TEST_DEBUG"], "0")
                scratch = Path(env["TMPDIR"])
                self.assertEqual(scratch.parent, target)
                self.assertTrue(scratch.is_dir())
                self.assertIn(target, paths)
                scratch_paths.append(scratch)
                return 0

            with patch.object(guard.Path, "home", return_value=home), \
                 patch.object(guard, "supervise", side_effect=inspect):
                self.assertEqual(guard.main(["test"]), 0)
            self.assertFalse(scratch_paths[0].exists())

    def test_override_denied(self):
        for flag in ("-j4", "--jobs=4", "--target-dir=/tmp", "--config=foo"):
            with self.subTest(flag=flag):
                self.assertEqual(guard.main(["test", flag]), 2)


if __name__ == "__main__":
    unittest.main()
