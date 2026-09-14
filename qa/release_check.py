#!/usr/bin/env python3
"""Install a release in a fresh native Linux directory and preserve QA evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    archive = args.archive.resolve()
    report_path = args.report.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {"status": "RUNNING", "archive": str(archive)}
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME"):
        environment.pop(key, None)
    try:
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        expected = archive.with_suffix(archive.suffix + ".sha256").read_text().split()[0]
        assert digest == expected, "Archive checksum mismatch"
        report["sha256"] = digest
        destination = Path(tempfile.mkdtemp(prefix="cheker-linux-release-"))
        report["extraction_root"] = str(destination)
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            names = set()
            for member in members:
                path = PurePosixPath(member.name)
                assert path.parts and path.parts[0] == "mcp-integrity-guard"
                assert not path.is_absolute() and ".." not in path.parts
                assert member.name not in names, "Duplicate archive entry"
                names.add(member.name)
                assert member.isfile() or member.isdir(), "Archive contains special entry"
                assert not member.mode & 0o022, "Archive contains writable shared permissions"
                assert not any(part in {"data-linux", "runtime-linux", "api-token", "approval-key.pem"}
                               for part in path.parts), "Private state in release"
            previous_umask = os.umask(0o077)
            try:
                # Python's data filter deliberately ignores directory modes.
                bundle.extractall(destination, filter="data")
            finally:
                os.umask(previous_umask)
        app = destination / "mcp-integrity-guard"
        assert stat.S_IMODE(app.stat().st_mode) == 0o700, "Extracted directory permissions"
        report["members"] = len(members)
        report["app"] = str(app)
        # Check both acceptance and detection of an accidental changed artifact.
        verifier = ["python3", "-I", "verify-release.py"]
        subprocess.run(verifier, cwd=app, env=environment, check=True, capture_output=True, timeout=30)
        sample = app / "examples" / "document-safe.txt"
        original = sample.read_bytes()
        try:
            sample.write_bytes(original + b"\nQA checksum change\n")
            changed = subprocess.run(verifier, cwd=app, env=environment, capture_output=True, timeout=30)
            assert changed.returncode == 2, "Changed artifact accepted"
        finally:
            sample.write_bytes(original)
        report["checksum_change_rejected"] = True
        log = report_path.with_suffix(".install.log")
        with log.open("wb") as output:
            installed = subprocess.run(["bash", "install-linux.sh"], cwd=app, env=environment,
                                       stdout=output, stderr=subprocess.STDOUT, timeout=600)
        report["install_log"] = str(log)
        assert installed.returncode == 0, "Clean installation failed; inspect install log"
        runtime = app / "runtime-linux" / "bin" / "python"
        subprocess.run([str(runtime), "-I", "-m", "pip", "check"], cwd=app,
                       env=environment, check=True, capture_output=True, timeout=60)
        diagnostic = subprocess.run([str(runtime), "-I", "-m", "integrity_guard.diagnostics"],
                                    cwd=app, env=environment, check=True, capture_output=True, timeout=30)
        report["diagnostics"] = json.loads(diagnostic.stdout)
        report["runtime"] = str(runtime)
        assert stat.S_IMODE((app / "data-linux").stat().st_mode) == 0o700
        report["status"] = "PASSED"
    except Exception as exc:
        report["status"] = "FAILED"
        report["error"] = {"type": type(exc).__name__, "detail": str(exc)[:500]}
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
