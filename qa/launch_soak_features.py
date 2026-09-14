#!/usr/bin/env python3
"""Detach the separate HTML-feature soak harness and record its process identity.

The data root and control directory must be new, separate directories below
a .test-data component. Use a native Linux filesystem for private 0700/0600
permissions. The launcher returns after dispatch; report.json in the data root
is the completion result. No recurring task or global daemon is installed.

Example (a short check, not a long soak):
  python3 qa/launch_soak_features.py --python /path/to/runtime-linux/bin/python \
    --data-root /tmp/.test-data/soak-new --control-dir /tmp/.test-data/control-new \
    --duration 1 --interval 1 --restart-every 0
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile


def absolute_path(value: Path) -> Path:
    # Resolving the executable's final symlink would bypass its venv prefix.
    return Path(os.path.abspath(value.expanduser()))


def new_test_path(value: Path) -> Path:
    path = absolute_path(value)
    if ".test-data" not in path.parts[:-1] or path.resolve() != path:
        raise ValueError("Directories must be beneath .test-data without symbolic links")
    if path.exists():
        raise ValueError("Refusing to reuse an existing data or control directory")
    return path


def require_private(path: Path, mode: int) -> None:
    path.chmod(mode)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
        raise ValueError("Private POSIX permissions are unavailable; use a native Linux filesystem")


def atomic_json(path: Path, value: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".launch-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def start_ticks(pid: int) -> int:
    fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[19])


def launch(args: argparse.Namespace) -> dict:
    if sys.platform != "linux":
        raise ValueError("This launcher requires Linux and procfs")
    if (not math.isfinite(args.duration) or not 1 <= args.duration <= 86400 or
            not math.isfinite(args.interval) or not .1 <= args.interval <= 3600 or
            not 0 <= args.restart_every <= 10000):
        raise ValueError("Invalid duration, interval or restart count")
    python = absolute_path(args.python)
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("The selected Python executable is unavailable")
    data_root, control_dir = new_test_path(args.data_root), new_test_path(args.control_dir)
    if data_root == control_dir or data_root in control_dir.parents or control_dir in data_root.parents:
        raise ValueError("Control directory must be outside and separate from the data root")
    harness = Path(__file__).resolve().with_name("soak_features.py")
    if not harness.is_file():
        raise ValueError("The separate soak_features.py harness is missing")
    command = [str(python), "-I", str(harness), "--python", str(python),
               "--data-root", str(data_root), "--duration", str(args.duration),
               "--interval", str(args.interval), "--restart-every", str(args.restart_every),
               "--selected-runtime"]
    # mkdir without exist_ok is the ownership reservation, including races
    # between separate launchers targeting the same empty data directory.
    control_dir.mkdir(parents=True, mode=0o700)
    require_private(control_dir, 0o700)
    child = None
    try:
        data_root.mkdir(parents=True, mode=0o700)
        require_private(data_root, 0o700)
        log_path = control_dir / "controller.log"
        metadata = {"status": "STARTING", "harness_profile": "html-copies-v1", "created_at": datetime.now(timezone.utc).isoformat(),
                    "launcher_pid": os.getpid(), "pid": None, "start_ticks": None,
                    "argv": command, "data_root": str(data_root), "control_dir": str(control_dir),
                    "log_path": str(log_path), "report_path": str(data_root / "report.json")}
        atomic_json(control_dir / "launch.json", metadata)
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "ab", buffering=0) as output:
            require_private(log_path, 0o600)
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=subprocess.STDOUT, start_new_session=True,
                                     close_fds=True, cwd=harness.parent.parent)
            metadata.update(status="DISPATCHED", pid=child.pid, start_ticks=start_ticks(child.pid),
                            session_id=os.getsid(child.pid))
            atomic_json(control_dir / "launch.json", metadata)
        return metadata
    except BaseException as exc:
        # No detached process should be left without its launch record when
        # dispatch fails. A running harness handles TERM and closes its backend.
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
        try:
            atomic_json(control_dir / "launch-error.json",
                        {"status": "DISPATCH_FAILED", "type": type(exc).__name__,
                         "pid": child.pid if child is not None else None})
        except OSError:
            pass
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--interval", type=float, required=True)
    parser.add_argument("--restart-every", type=int, required=True)
    parser.add_argument("--control-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        metadata = launch(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"status": "LAUNCH_FAILED", "type": type(exc).__name__,
                          "message": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(metadata, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
