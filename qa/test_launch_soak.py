"""Launcher ownership and venv-path regressions; no real soak in these tests."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import launch_soak


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / ".test-data"
        self.root.mkdir()
        self.python = self.root / "runtime" / "bin" / "python"
        self.python.parent.mkdir(parents=True)
        self.python.symlink_to(sys.executable)
        self.args = argparse.Namespace(python=self.python, data_root=self.root / "run",
                                       control_dir=self.root / "control", duration=1.0,
                                       interval=1.0, restart_every=0)

    def dispatch(self):
        child = SimpleNamespace(pid=os.getpid())
        with patch.object(launch_soak.subprocess, "Popen", return_value=child) as popen:
            with patch.object(launch_soak, "start_ticks", return_value=123456):
                metadata = launch_soak.launch(self.args)
        return metadata, popen

    def test_selected_venv_symlink_is_preserved_and_io_is_detached(self):
        metadata, popen = self.dispatch()
        command = popen.call_args.args[0]
        self.assertEqual(command[0], str(self.python))
        self.assertNotEqual(command[0], str(self.python.resolve()))
        self.assertEqual(command[1], "-I")
        self.assertIn("--selected-runtime", command)
        self.assertEqual(command[command.index("--python") + 1], str(self.python))
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.STDOUT)
        self.assertIsInstance(popen.call_args.kwargs["stdout"].name, int)
        self.assertEqual(metadata["log_path"], str(self.args.control_dir / "controller.log"))
        self.assertEqual(metadata["start_ticks"], 123456)
        self.assertEqual(json.loads((self.args.control_dir / "launch.json").read_text()), metadata)
        self.assertEqual(list(self.args.data_root.iterdir()), [])
        for path, mode in ((self.args.control_dir, 0o700), (self.args.data_root, 0o700),
                           (self.args.control_dir / "controller.log", 0o600),
                           (self.args.control_dir / "launch.json", 0o600)):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

    def test_repeated_launch_cannot_reuse_owned_paths(self):
        self.dispatch()
        with patch.object(launch_soak.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "reuse"):
                launch_soak.launch(self.args)
            popen.assert_not_called()

    def test_existing_empty_data_or_control_is_rejected(self):
        for field in ("data_root", "control_dir"):
            with self.subTest(field=field):
                existing = getattr(self.args, field)
                existing.mkdir()
                try:
                    with self.assertRaisesRegex(ValueError, "reuse"):
                        launch_soak.launch(self.args)
                    other = self.args.control_dir if field == "data_root" else self.args.data_root
                    self.assertFalse(other.exists())
                finally:
                    existing.rmdir()

    def test_control_cannot_be_within_data_or_own_its_parent(self):
        for data, control in ((self.root / "run", self.root / "run" / "control"),
                              (self.root / "control" / "run", self.root / "control")):
            with self.subTest(data=data):
                self.args.data_root, self.args.control_dir = data, control
                with self.assertRaisesRegex(ValueError, "outside"):
                    launch_soak.launch(self.args)
                self.assertFalse(data.exists())
                self.assertFalse(control.exists())

    def test_symlinked_qa_location_and_outside_test_data_are_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.python.parent, target_is_directory=True)
        for data in (alias / "run", Path(self.temporary.name) / "ordinary-run"):
            self.args.data_root = data
            with self.assertRaisesRegex(ValueError, "beneath"):
                launch_soak.launch(self.args)
            self.assertFalse(self.args.control_dir.exists())

    def test_invalid_budgets_are_rejected_before_reservation(self):
        for field, value in (("duration", float("nan")), ("duration", 0),
                              ("interval", float("inf")), ("interval", .01),
                              ("restart_every", -1)):
            old = getattr(self.args, field)
            setattr(self.args, field, value)
            try:
                with self.assertRaisesRegex(ValueError, "Invalid"):
                    launch_soak.launch(self.args)
                self.assertFalse(self.args.control_dir.exists())
            finally:
                setattr(self.args, field, old)

    def test_spawn_failure_records_error_and_keeps_paths_reserved(self):
        with patch.object(launch_soak.subprocess, "Popen", side_effect=OSError("fixture spawn failed")):
            with self.assertRaises(OSError):
                launch_soak.launch(self.args)
        error = json.loads((self.args.control_dir / "launch-error.json").read_text())
        self.assertEqual(error, {"status": "DISPATCH_FAILED", "type": "OSError", "pid": None})
        with self.assertRaisesRegex(ValueError, "reuse"):
            launch_soak.launch(self.args)


if __name__ == "__main__":
    unittest.main()
