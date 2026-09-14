"""Explicit HTML text copies: scan the original, transform, then scan exact bytes.

Transformation is distinct from authorization. Stored operations never contain
the output body, and historical records cannot be used to retrieve a copy.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone

from .core import ConflictError
from .reports import MAX_FILE_SIZE, worker_environment
from .sanitize_protocol import (MAX_WORKER_OUTPUT, SanitizationRejected,
                                SanitizeProtocolError, validate_sanitize_output)
from .worker_process import run_worker

PROFILE = "html-text-v1"
_PRIVATE_KEY = re.compile(br"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")


class SanitizationStorageError(RuntimeError):
    """No output may be delivered when its registration cannot be completed."""


def _complete(report: dict, data: bytes) -> bool:
    return (report.get("analysis_complete") is True and
            report.get("sha256") == hashlib.sha256(data).hexdigest() and
            report.get("size_bytes") == len(data) and
            report.get("extraction", {}).get("truncated") is False)


def _filename(value: str) -> str:
    return Path(value.replace("\\", "/")).name[:180] or "document.html"


class Sanitizer:
    def __init__(self, reports, data_dir: Path, protected_token: str = ""):
        self.reports, self.store = reports, reports.store
        self.data_dir = Path(data_dir).resolve()
        self._protected_token = protected_token.encode("ascii")
        with reports.lock:
            reports.db.execute("CREATE TABLE IF NOT EXISTS sanitizations "
                               "(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, metadata TEXT NOT NULL)")
            reports.db.execute("CREATE INDEX IF NOT EXISTS sanitizations_created "
                               "ON sanitizations(created_at DESC,id DESC)")
            reports.db.commit()

    def list(self, limit=50, offset=0):
        if type(limit) is not int or type(offset) is not int or not 1 <= limit <= 100 or offset < 0:
            raise ValueError("Invalid pagination")
        with self.reports.lock:
            rows = self.reports.db.execute("SELECT metadata FROM sanitizations "
                                          "ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?",
                                          (limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, id):
        with self.reports.lock:
            row = self.reports.db.execute("SELECT metadata FROM sanitizations WHERE id=?", (id,)).fetchone()
        if row is None:
            raise KeyError(id)
        return json.loads(row[0])

    def _sensitive(self, data):
        return bool(_PRIVATE_KEY.search(data) or self._protected_token and self._protected_token in data)

    def _finish(self, metadata, output=None, output_report=None):
        # This is a record of the decision for this request, never a reusable
        # authorization. Recheck policy while serializing audit and registration.
        with self.store.lock:
            if output is not None and (not output_report or
                    self.store.get_policy()["version"] != output_report.get("policy_version")):
                metadata.update(delivery_status="DENIED", reason="POLICY_CHANGED")
                output = None
            try:
                self.store.append_audit("FILE_SANITIZATION_RECORDED", None, dict(metadata))
                with self.reports.lock:
                    self.reports.db.execute("INSERT INTO sanitizations(id,created_at,metadata) VALUES (?,?,?)",
                                            (metadata["id"], metadata["created_at"], json.dumps(metadata)))
                    self.reports.db.commit()
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                with self.reports.lock:
                    self.reports.db.rollback()
                raise SanitizationStorageError("Copia non consegnata: registrazione non completata") from exc
        delivery = None
        if output is not None and metadata["delivery_status"] == "ALLOWED":
            delivery = {"encoding": "base64", "media_type": "text/plain;charset=utf-8",
                        "data_base64": base64.b64encode(output).decode("ascii")}
        return dict(metadata, delivery=delivery)

    @staticmethod
    def _metadata(filename, data, input_report):
        return {"id": str(uuid.uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
                "profile": PROFILE, "transformation_status": "FAILED", "delivery_status": "DENIED",
                "reason": "INPUT_INCOMPLETE", "input_filename": filename,
                "output_filename": Path(filename).stem[:160] + ".sanitized.txt",
                "input_sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
                "output_sha256": None, "input_size_bytes": len(data) if data is not None else None,
                "output_size_bytes": None, "input_report_id": input_report["id"],
                "output_report_id": None, "omitted_counts": {}}

    def sanitize(self, data: bytes, filename: str, source_path=None, expected_sha256=None):
        if expected_sha256 is not None:
            if not isinstance(expected_sha256, str) or not re.fullmatch("[0-9a-f]{64}", expected_sha256):
                raise ValueError("Invalid expected SHA-256")
            if hashlib.sha256(data).hexdigest() != expected_sha256:
                raise ConflictError("Il file è cambiato: SHA-256 diverso da quello atteso")
        filename = _filename(filename)
        original = self.reports.scan(data, filename, source_path)
        metadata = self._metadata(filename, data, original)
        if not _complete(original, data):
            return self._finish(metadata)
        if Path(filename).suffix.lower() not in {".html", ".htm"}:
            metadata["reason"] = "UNSUPPORTED_TRANSFORMATION"
            return self._finish(metadata)
        if self._sensitive(data):
            metadata["reason"] = "SENSITIVE_CONTENT"
            return self._finish(metadata)
        if not self.reports.slots.acquire(blocking=False):
            metadata["reason"] = "WORKERS_BUSY"
            return self._finish(metadata)
        try:
            raw = run_worker([sys.executable, "-I", "-m", "integrity_guard.sanitize_worker"],
                             input=data, timeout=12, env=worker_environment(), max_output=MAX_WORKER_OUTPUT)
            transformed = validate_sanitize_output(raw, data)
        except SanitizationRejected as exc:
            metadata["reason"] = exc.code
            return self._finish(metadata)
        except (SanitizeProtocolError, ValueError, OSError, RuntimeError, subprocess.TimeoutExpired):
            metadata["reason"] = "TRANSFORMATION_INCOMPLETE"
            return self._finish(metadata)
        finally:
            self.reports.slots.release()
        output = transformed["data"]
        metadata.update(transformation_status="SANITIZED", reason="OUTPUT_INCOMPLETE",
                        output_sha256=transformed["output_sha256"], output_size_bytes=len(output),
                        omitted_counts=transformed["omitted_counts"])
        try:
            result = self.reports.scan(output, metadata["output_filename"])
        except RuntimeError:
            metadata["reason"] = "WORKERS_BUSY"
            return self._finish(metadata)
        metadata["output_report_id"] = result["id"]
        if not _complete(result, output):
            return self._finish(metadata)
        if result.get("verdict") != "VALID" or result.get("status") != "ALLOWED" or result.get("findings"):
            metadata["reason"] = "OUTPUT_REQUIRES_REVIEW"
            return self._finish(metadata)
        if self._sensitive(output):
            metadata["reason"] = "SENSITIVE_CONTENT"
            return self._finish(metadata)
        metadata.update(delivery_status="ALLOWED", reason="COPY_PASSED_CHECKS")
        return self._finish(metadata, output, result)

    def sanitize_path(self, supplied_path, expected_sha256=None):
        path = Path(os.path.abspath(Path(supplied_path).expanduser()))
        try:
            data = self._snapshot(path)
        except (OSError, ValueError):
            report = self.reports.record_failure(path.name, str(path),
                "Percorso non disponibile o non consentito per la copia", "SANITIZATION_SOURCE_UNAVAILABLE")
            metadata = self._metadata(_filename(path.name), None, report)
            metadata["reason"] = "SOURCE_UNAVAILABLE"
            return self._finish(metadata)
        return self.sanitize(data, path.name, str(path), expected_sha256)

    def _snapshot(self, path):
        # Open each directory without following symlinks; a hard-linked source
        # could alias private state, so this text-delivery route rejects it.
        if sys.platform != "linux" or path.is_relative_to(self.data_dir) or len(path.parts) > 128:
            raise ValueError("Path unavailable")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            with os.fdopen(os.open(path.name, flags, dir_fd=descriptor), "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE_SIZE:
                    raise ValueError("Source unavailable")
                data = stream.read(MAX_FILE_SIZE + 1)
                after = os.fstat(stream.fileno())
            with os.fdopen(os.open(path.name, flags, dir_fd=descriptor), "rb") as stream:
                current = os.fstat(stream.fileno())
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                      value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
            if (len(data) > MAX_FILE_SIZE or identity(before) != identity(after) or
                    identity(after) != identity(current) or path.resolve(strict=True) != path or
                    identity(path.stat()) != identity(current)):
                raise ValueError("Source changed")
            return data
        finally:
            os.close(descriptor)
