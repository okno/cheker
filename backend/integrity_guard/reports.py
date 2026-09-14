"""Bounded file scanning with persistent reports, and safe snapshot reads."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .scan_protocol import validate_worker_report
from .worker_process import run_worker

MAX_FILE_SIZE = 10 * 1024**2
VERDICTS = {"VALID", "INFECTED", "CORRUPTED", "REVIEW_REQUIRED", "UNSCANNABLE"}
CORRUPTION_CODES = {"EXTRACTION_FAILED", "INVALID_DOCX", "INVALID_PDF", "TEXT_ENCODING", "BINARY_CONTENT",
                    "MALFORMED_JSON", "MALFORMED_YAML", "MALFORMED_XML", "MALFORMED_TOML"}


def worker_environment() -> dict[str, str]:
    """Parsers inherit neither application credentials nor Python import overrides."""
    environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if value := os.environ.get(name):
                environment[name] = value
        environment["PATH"] = str(Path(sys.executable).parent)
    else:
        environment["PATH"] = "/usr/bin:/bin"
    return environment


def classify_report(report: dict) -> str:
    """An operational verdict, never an assertion of universal safety/virus status."""
    findings = report.get("findings", [])
    failures = [f for f in findings if f.get("category") == "ANALYSIS_FAILURE" or
                f.get("rule_id") == "SCAN_INCOMPLETE"]
    if failures or not report.get("analysis_complete", True) or report.get("extraction", {}).get("truncated"):
        return "CORRUPTED" if report.get("failure_kind") == "MALFORMED" or any(
            f.get("rule_id") in CORRUPTION_CODES or f.get("failure_kind") == "MALFORMED" or f.get("error_kind") == "CORRUPTED"
            for f in failures) else "UNSCANNABLE"
    meaningful = [f for f in findings if f.get("severity") in {"HIGH", "CRITICAL"} and
                  f.get("category") not in {"PROMPT_HINT", "PROMPT_STRUCTURE", "PROMPT_REFERENCE", "UNICODE_ANOMALY", "ANALYSIS_FAILURE"}]
    if meaningful:
        return "INFECTED"
    if findings or report.get("status") != "ALLOWED":
        return "REVIEW_REQUIRED"
    return "VALID"


def read_snapshot(path: Path) -> bytes:
    path = path.expanduser().absolute()
    if path.is_symlink():
        raise ValueError("Symbolic links are not accepted")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Only regular files can be scanned")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Only regular files can be scanned")
        if before.st_size > MAX_FILE_SIZE:
            raise ValueError("File exceeds the 10 MiB limit")
        data = f.read(MAX_FILE_SIZE + 1)
        after = os.fstat(f.fileno())
    # Compare handles from the same API: Windows stat and fstat can disagree
    # about ctime/file-id representation even for an unchanged regular file.
    with os.fdopen(os.open(path, flags), "rb") as current_file:
        current = os.fstat(current_file.fileno())
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if len(data) > MAX_FILE_SIZE or key(before) != key(after) or key(after) != key(current):
        raise ValueError("File changed while being read; retry")
    return data


class Reports:
    def __init__(self, data_dir: Path, store):
        self.store = store
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(2)
        self.db = sqlite3.connect(data_dir / "scans.sqlite3", check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, report TEXT NOT NULL)")
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(scans)")}
        for column in ("verdict", "sha256", "filename", "source_path", "status"):
            if column not in columns:
                self.db.execute(f"ALTER TABLE scans ADD COLUMN {column} TEXT")
        for id, encoded in self.db.execute("SELECT id, report FROM scans WHERE verdict IS NULL").fetchall():
            report = json.loads(encoded)
            report["verdict"] = classify_report(report)
            self.db.execute("UPDATE scans SET report=?,verdict=?,sha256=?,filename=?,source_path=?,status=? WHERE id=?",
                            (json.dumps(report), report["verdict"], report.get("sha256", ""), report["filename"],
                             report.get("source_path"), report["status"], id))
        self.db.execute("CREATE INDEX IF NOT EXISTS scans_created ON scans(created_at DESC)")
        self.db.execute("CREATE INDEX IF NOT EXISTS scans_verdict ON scans(verdict)")
        self.db.execute("CREATE INDEX IF NOT EXISTS scans_sha ON scans(sha256)")
        self.db.commit()

    def close(self):
        self.db.close()

    @staticmethod
    def _where(verdict="ALL", query=""):
        if verdict != "ALL" and verdict not in VERDICTS:
            raise ValueError("Invalid verdict filter")
        where, parameters = [], []
        if verdict != "ALL":
            where.append("verdict=?")
            parameters.append(verdict)
        if query:
            text = "%" + query[:300].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(filename LIKE ? ESCAPE '\\' OR source_path LIKE ? ESCAPE '\\' OR sha256 LIKE ? ESCAPE '\\')")
            parameters.extend([text, text, text])
        return (" WHERE " + " AND ".join(where) if where else ""), parameters

    def list(self, limit=100, offset=0, verdict="ALL", query=""):
        where, values = self._where(verdict, query)
        if not 1 <= limit <= 500 or offset < 0:
            raise ValueError("Invalid pagination")
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute(
                "SELECT report FROM scans" + where + " ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?",
                (*values, limit, offset))]

    def stats(self, verdict="ALL", query=""):
        where, values = self._where(verdict, query)
        with self.lock:
            result = dict(self.db.execute("SELECT verdict,count(*) FROM scans GROUP BY verdict").fetchall())
            count, unique, blocked, last = self.db.execute(
                "SELECT count(*),count(DISTINCT NULLIF(sha256,'')),coalesce(sum(status='BLOCKED'),0),max(created_at) FROM scans").fetchone()
            matched = self.db.execute("SELECT count(*) FROM scans" + where, values).fetchone()[0]
        return {"analyzed": count, "infected": result.get("INFECTED", 0), "corrupted": result.get("CORRUPTED", 0),
                "valid": result.get("VALID", 0), "review_required": result.get("REVIEW_REQUIRED", 0),
                "unscannable": result.get("UNSCANNABLE", 0), "blocked": blocked, "unique_files": unique,
                "last_scan_at": last, "matched": matched}

    def get(self, id):
        with self.lock:
            row = self.db.execute("SELECT report FROM scans WHERE id=?", (id,)).fetchone()
        if not row:
            raise KeyError(id)
        return json.loads(row[0])

    def count(self):
        with self.lock:
            return self.db.execute("SELECT count(*) FROM scans").fetchone()[0]

    def scan(self, data: bytes, filename: str, source_path: str | None = None):
        if len(data) > MAX_FILE_SIZE:
            return self.record_failure(filename, source_path, "File exceeds the 10 MiB limit", "INPUT_SIZE_LIMIT")
        if not self.slots.acquire(blocking=False):
            raise RuntimeError("Two scans are already running; retry shortly")
        start = time.perf_counter()
        try:
            filename = Path(filename.replace("\\", "/")).name[:180] or "document.txt"
            output = run_worker([sys.executable, "-I", "-m", "integrity_guard.scan_worker", filename],
                                input=data, timeout=12, env=worker_environment())
            report = validate_worker_report(json.loads(output,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite worker value"))), data)
            report["filename"] = filename
        except (subprocess.TimeoutExpired, RuntimeError, ValueError, OSError) as exc:
            report = {"filename": filename, "sha256": hashlib.sha256(data).hexdigest(),
                      "status": "BLOCKED", "risk_score": 100, "severity": "HIGH",
                      "findings": [{"rule_id": "SCAN_INCOMPLETE", "title": "Analisi non completata",
                                    "severity": "HIGH", "category": "EXTRACTION", "evidence": type(exc).__name__,
                                    "location": "file", "layer": "extraction"}],
                      "extraction": {"format": Path(filename).suffix, "characters": 0, "segments": 0, "truncated": True},
                      "rules_version": "unknown", "limitations": ["Analisi interrotta: il contenuto non viene autorizzato."]}
        finally:
            self.slots.release()
        report["id"] = str(uuid.uuid4())
        report["created_at"] = datetime.now(timezone.utc).isoformat()
        report["duration_ms"] = round((time.perf_counter() - start) * 1000)
        report["size_bytes"] = len(data)
        report["source_path"] = source_path
        policy = self.store.get_policy()
        # Incomplete extraction always remains BLOCKED, regardless of thresholds.
        incomplete = (not report.get("analysis_complete", True) or report["extraction"].get("truncated", False) or
                      any(f.get("category") == "ANALYSIS_FAILURE" or f.get("rule_id") == "SCAN_INCOMPLETE"
                          for f in report["findings"]))
        if not incomplete:
            score = report["risk_score"]
            report["status"] = ("BLOCKED" if score >= policy["scan_block_score"] else
                                "QUARANTINED" if score >= policy["scan_quarantine_score"] else
                                "FLAGGED" if score >= policy["scan_flag_score"] else "ALLOWED")
        report["analysis_complete"] = not incomplete and report.get("analysis_complete", True)
        report["policy_version"] = policy["version"]
        report["verdict"] = classify_report(report)
        # A weak prompt hint or unresolved anomaly still requires human review.
        if report["verdict"] != "VALID" and report["status"] == "ALLOWED":
            report["status"] = "FLAGGED"
        return self._persist(report)

    def _persist(self, report):
        with self.lock:
            self.db.execute("INSERT INTO scans(id,created_at,report,verdict,sha256,filename,source_path,status) VALUES (?,?,?,?,?,?,?,?)",
                            (report["id"], report["created_at"], json.dumps(report), report["verdict"], report.get("sha256", ""),
                             report["filename"], report.get("source_path"), report["status"]))
            self.db.commit()
        self.store.append_audit("FILE_SCANNED", None,
                                {"scan_id": report["id"], "filename": report["filename"], "sha256": report["sha256"],
                                 "status": report["status"], "risk_score": report["risk_score"], "verdict": report["verdict"]})
        return report

    def record_failure(self, filename, source_path, reason, code, sha256=None):
        report = {"id": str(uuid.uuid4()), "filename": Path(filename).name[:180], "source_path": str(source_path) if source_path else None,
                  "sha256": sha256 or "", "status": "BLOCKED", "risk_score": 100, "severity": "HIGH",
                  "analysis_complete": False, "verdict": "UNSCANNABLE", "duration_ms": 0,
                  "created_at": datetime.now(timezone.utc).isoformat(), "rules_version": "not-run",
                  "policy_version": self.store.get_policy()["version"],
                  "findings": [{"rule_id": code, "title": "File non analizzabile", "severity": "HIGH",
                                "category": "ANALYSIS_FAILURE", "evidence": str(reason)[:300],
                                "location": "file", "layer": "METADATA"}],
                  "extraction": {"format": Path(filename).suffix, "characters": 0, "segments": 0, "truncated": True},
                  "limitations": ["File non consegnato all’agente: analisi incompleta."]}
        return self._persist(report)
