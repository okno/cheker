"""Opt-in directory scanning and bounded background reconciliation.

This is a sidecar inventory, not a filesystem access filter: another process can read
an unscanned or subsequently modified file. Agents must request a fresh scan/gate
before use. Watched roots grant read authority only; this module never executes,
moves, edits, deletes or sanitizes source files. Reports and its index are local data.

Linux traversal uses directory descriptors and O_NOFOLLOW; source reads use an
anchored /proc/self/fd path with reports.read_snapshot. This prevents descendant
symlink replacement from redirecting a scan outside its explicitly selected root.
Platforms without /proc use a conservative path-checked fallback with a narrower
race guarantee. Every pass has entry, byte and duration limits. A limited pass is
reported PARTIAL; a large tree is never represented as fully covered.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import sqlite3
import stat
import sys
import threading
import time
import uuid
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .reports import MAX_FILE_SIZE, read_snapshot

MAX_ENTRIES = 2000
MAX_ROOTS = 64
MAX_DEPTH = 64
MAX_BYTES_PER_PASS = 128 * 1024 * 1024
MAX_PASS_SECONDS = 60.0
MAX_WATCHES = 256
DEBOUNCE_SECONDS = 0.75
RECONCILE_SECONDS = 30.0
_PRIVATE_NAMES = {"api-token", "approval-key.pem", "audit-head.json", ".store.lock", "integrity.sqlite3",
                  "integrity.sqlite3-wal", "integrity.sqlite3-shm", "scans.sqlite3",
                  "scans.sqlite3-wal", "scans.sqlite3-shm", "filewatch.sqlite3",
                  "filewatch.sqlite3-wal", "filewatch.sqlite3-shm"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _signature(value: os.stat_result) -> str:
    return json.dumps([value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns])


class _Events(FileSystemEventHandler):
    def __init__(self, owner: "FileWatch", root_id: str):
        self.owner, self.root_id = owner, root_id

    def on_any_event(self, event) -> None:
        if event.event_type in {"created", "modified", "deleted", "moved"}:
            self.owner._dirty(self.root_id)


class FileWatch:
    """One background coordinator, at most two scan jobs, persisted explicit roots."""

    def __init__(self, reports, data_dir: Path):
        self.reports = reports
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._excluded = {self.data_dir}
        store_dir = getattr(getattr(reports, "store", None), "data_dir", None)
        if store_dir is not None:
            self._excluded.add(Path(store_dir).resolve())
        self._lock = threading.RLock()
        self._slots = threading.BoundedSemaphore(2)
        self._stripes = [threading.Lock() for _ in range(128)]
        self._active: dict[str, str] = {}
        self._generation = 0
        self._idle = threading.Condition(self._lock)
        self._pending: dict[str, float] = {}
        self._last_reconcile: dict[str, float] = {}
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._observer = None
        self._watches: dict[tuple[str, str], Any] = {}
        self._cursors: dict[str, dict] = {}
        self._closed = False
        self._db = sqlite3.connect(self.data_dir / "filewatch.sqlite3", check_same_thread=False, timeout=20)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS roots (id TEXT PRIMARY KEY, path TEXT UNIQUE NOT NULL,
                recursive INTEGER NOT NULL, enabled INTEGER NOT NULL, device TEXT NOT NULL,
                inode TEXT NOT NULL, files_seen INTEGER NOT NULL DEFAULT 0, last_scan_at TEXT,
                error TEXT, last_job TEXT, cycle_id TEXT, cycle_context TEXT);
            CREATE TABLE IF NOT EXISTS file_index (path TEXT PRIMARY KEY, signature TEXT NOT NULL,
                sha256 TEXT, report_id TEXT, status TEXT NOT NULL, error TEXT,
                retry_after REAL NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, context TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS root_files (root_id TEXT NOT NULL, path TEXT NOT NULL,
                generation TEXT NOT NULL, PRIMARY KEY(root_id,path));
            CREATE TABLE IF NOT EXISTS walk_dirs (root_id TEXT NOT NULL, cycle_id TEXT NOT NULL,
                relative_path TEXT NOT NULL, device TEXT NOT NULL, inode TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'PENDING', error TEXT,
                PRIMARY KEY(root_id,cycle_id,relative_path));
        """)
        if "context" not in {row[1] for row in self._db.execute("PRAGMA table_info(file_index)")}:
            self._db.execute("ALTER TABLE file_index ADD COLUMN context TEXT NOT NULL DEFAULT ''")
        root_columns = {row[1] for row in self._db.execute("PRAGMA table_info(roots)")}
        for column in ("cycle_id", "cycle_context"):
            if column not in root_columns:
                self._db.execute(f"ALTER TABLE roots ADD COLUMN {column} TEXT")
        self._db.commit()

    def _context(self) -> str:
        from .extractor_registry import registry_fingerprint
        policy_version = None
        store = getattr(self.reports, "store", None)
        if store is not None and hasattr(store, "get_policy"):
            policy_version = store.get_policy()["version"]
        package = Path(__file__).parent
        rules_digest = hashlib.sha256((package / "rules.json").read_bytes()).hexdigest()
        engine = hashlib.sha256()
        for name in ("scanner.py", "extraction.py", "reports.py", "scan_protocol.py",
                     "scan_worker.py", "worker_process.py", "linux_sandbox.py"):
            engine.update(name.encode() + b"\0" + (package / name).read_bytes() + b"\0")
        dependencies = {name: importlib.metadata.version(name)
                        for name in ("pypdf", "PyYAML", "json5", "defusedxml", "pydantic")}
        return json.dumps({"policy_version": policy_version, "rules_sha256": rules_digest,
                           "engine_sha256": engine.hexdigest(), "dependencies": dependencies,
                           "extractor_registry_sha256": registry_fingerprint(),
                           "python": list(sys.version_info[:3]), "unicode": unicodedata.unidata_version,
                           "cache_version": 3}, sort_keys=True)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def _audit(self, event: str, details: dict) -> None:
        store = getattr(self.reports, "store", None)
        if store is not None and hasattr(store, "append_audit"):
            store.append_audit(event, None, details)

    def _root(self, root_id: str) -> dict:
        row = self._db.execute("SELECT * FROM roots WHERE id=?", (root_id,)).fetchone()
        if row is None:
            raise KeyError(root_id)
        return dict(row)

    def _public(self, root: dict) -> dict:
        return {"id": root["id"], "path": root["path"], "recursive": bool(root["recursive"]),
                "enabled": bool(root["enabled"]), "files_seen": root["files_seen"],
                "last_scan_at": root["last_scan_at"], "error": root["error"],
                "last_job": json.loads(root["last_job"]) if root["last_job"] else None}

    def list_roots(self) -> list[dict]:
        with self._lock:
            return [self._public(dict(row)) for row in self._db.execute("SELECT * FROM roots ORDER BY path")]

    def _excluded_path(self, path: Path) -> bool:
        return path.name in _PRIVATE_NAMES or any(_within(path, excluded) for excluded in self._excluded)

    def add_root(self, path: Path, recursive: bool = False) -> dict:
        if type(recursive) is not bool:
            raise ValueError("recursive must be a boolean")
        path = Path(os.path.abspath(Path(path).expanduser()))
        try:
            if path.resolve(strict=True) != path or path.is_symlink():
                raise ValueError("Watched roots and their ancestors cannot be symbolic links")
            metadata = path.stat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("Watched root must be an existing directory")
        except (OSError, RuntimeError) as exc:
            raise ValueError("Watched root is unavailable") from exc
        if self._excluded_path(path):
            raise ValueError("Application state and signing keys cannot be watched")
        with self._lock:
            existing = self._db.execute("SELECT * FROM roots WHERE path=?", (str(path),)).fetchone()
            if existing:
                if bool(existing["recursive"]) != recursive:
                    raise ValueError("This root already exists with another recursive setting; remove and add it explicitly")
                return self._public(dict(existing))
            if self._db.execute("SELECT COUNT(*) FROM roots").fetchone()[0] >= MAX_ROOTS:
                raise ValueError(f"At most {MAX_ROOTS} explicit roots can be watched")
            root_id = str(uuid.uuid4())
            self._audit("FILE_WATCH_ROOT_ADDED", {"root_id": root_id, "path": str(path), "recursive": recursive})
            self._db.execute("INSERT INTO roots(id,path,recursive,enabled,device,inode) VALUES (?,?,?,1,?,?)",
                             (root_id, str(path), int(recursive), str(metadata.st_dev), str(metadata.st_ino)))
            self._db.commit()
            result = self._public(self._root(root_id))
        self._dirty(root_id)
        return result

    def remove_root(self, root_id: str) -> None:
        with self._lock:
            root = self._root(root_id)
            self._audit("FILE_WATCH_ROOT_REMOVED", {"root_id": root_id, "path": root["path"]})
            self._db.execute("DELETE FROM roots WHERE id=?", (root_id,))
            self._db.execute("DELETE FROM root_files WHERE root_id=?", (root_id,))
            self._db.execute("DELETE FROM walk_dirs WHERE root_id=?", (root_id,))
            if root_id not in self._active:
                self._close_cursor(root_id)
            self._db.execute("DELETE FROM file_index WHERE path NOT IN (SELECT path FROM root_files)")
            self._db.commit()
            self._pending.pop(root_id, None)
            self._last_reconcile.pop(root_id, None)
            self._remove_watches(root_id)

    def set_enabled(self, root_id: str, enabled: bool) -> dict:
        if type(enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        with self._lock:
            root = self._root(root_id)
            self._audit("FILE_WATCH_ROOT_ENABLED" if enabled else "FILE_WATCH_ROOT_DISABLED", {"root_id": root_id, "path": root["path"]})
            self._db.execute("UPDATE roots SET enabled=? WHERE id=?", (int(enabled), root_id))
            self._db.commit()
            if not enabled:
                self._pending.pop(root_id, None)
                self._remove_watches(root_id)
            result = self._public(self._root(root_id))
        if enabled:
            self._dirty(root_id)
        return result

    def _dirty(self, root_id: str) -> None:
        with self._lock:
            if root_id not in self._pending:
                self._pending[root_id] = time.monotonic() + DEBOUNCE_SECONDS
            # Do not postpone indefinitely while a stream of writes is active.
        self._wake.set()

    def _remove_watches(self, root_id: str) -> None:
        for key in list(self._watches):
            if key[0] == root_id:
                watch = self._watches.pop(key)
                if self._observer is not None:
                    try:
                        self._observer.unschedule(watch)
                    except KeyError:
                        pass

    def _watch_directory(self, root: dict, path: Path) -> None:
        if not root["enabled"]:
            return
        key = (root["id"], str(path))
        with self._lock:
            if self._observer is None or key in self._watches or len(self._watches) >= MAX_WATCHES:
                return
            try:
                if path.is_symlink() or path.resolve(strict=True) != path or self._excluded_path(path):
                    return
                # Each individual watch is non-recursive; bounded traversal decides
                # which descendants may be watched. Reconciliation covers watch loss.
                self._watches[key] = self._observer.schedule(_Events(self, root["id"]), str(path), recursive=False)
            except (OSError, RuntimeError):
                pass  # Periodic reconciliation remains active.

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            if self._closed:
                raise RuntimeError("File watcher is closed")
            self._stop.clear()
            self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="filewatch-scan")
            try:
                self._observer = Observer()
                self._observer.start()
            except (OSError, RuntimeError):
                self._observer = None
            self._thread = threading.Thread(target=self._run, name="filewatch-reconcile", daemon=True)
            for root in self.list_roots():
                if root["enabled"]:
                    self._pending[root["id"]] = time.monotonic() + DEBOUNCE_SECONDS
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._generation += 1
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
        observer = self._observer
        if observer is not None:
            observer.stop()
            observer.join(timeout=5)
        executor = self._executor
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
        with self._idle:
            if not self._idle.wait_for(lambda: not self._active, timeout=15):
                raise RuntimeError("File scan is still finishing; retry shutdown after the bounded scanner returns")
            self._thread = None
            self._executor = None
            self._observer = None
            self._watches.clear()
            for root_id in list(self._cursors):
                self._close_cursor(root_id)

    def close(self) -> None:
        if self._closed:
            return
        self.stop()
        with self._lock:
            self._db.close()
            self._closed = True

    def _run(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            with self._lock:
                roots = [dict(row) for row in self._db.execute("SELECT * FROM roots WHERE enabled=1")]
                for root in roots:
                    root_id = root["id"]
                    if root_id in self._active:
                        continue
                    due = self._pending.get(root_id)
                    reconcile = now - self._last_reconcile.get(root_id, 0) >= RECONCILE_SECONDS
                    if (due is not None and now >= due) or (due is None and reconcile):
                        if len(self._active) >= 2:
                            break
                        self._pending.pop(root_id, None)
                        self._last_reconcile[root_id] = now
                        # Reserve before submitting to avoid an unbounded work queue.
                        reservation = str(uuid.uuid4())
                        self._active[root_id] = reservation
                        if self._executor is not None:
                            future = self._executor.submit(self._scheduled_scan, root_id, reservation)
                            future.add_done_callback(lambda future, id=root_id, token=reservation: self._cancelled_future(id, token) if future.cancelled() else None)
            self._wake.wait(timeout=0.25)
            self._wake.clear()

    def _cancelled_future(self, root_id: str, reservation: str) -> None:
        with self._idle:
            if self._active.get(root_id) == reservation:
                self._active.pop(root_id, None)
                self._idle.notify_all()

    def _scheduled_scan(self, root_id: str, reservation: str) -> None:
        try:
            self._scan_root(root_id, automatic=True, reserved=True)
        except (KeyError, RuntimeError, sqlite3.Error):
            pass
        finally:
            # A completed job may already have been followed by a new manual
            # scan. Only release this dispatcher's own still-pending reservation.
            self._cancelled_future(root_id, reservation)
            self._wake.set()

    def scan_root(self, root_id: str) -> dict:
        """Run one bounded pass; explicitly requested scans may run on disabled roots."""
        return self._scan_root(root_id, automatic=False, reserved=False)

    def _error(self, job: dict, path: Path | str, code: str, message: str) -> None:
        if len(job["errors"]) < 100:
            job["errors"].append({"path": str(path), "code": code, "message": message})
        job["error_count"] += 1

    def _close_cursor(self, root_id: str) -> None:
        cursor = self._cursors.pop(root_id, None)
        if cursor is not None:
            try:
                cursor["iterator"].close()
            finally:
                if cursor["fd"] is not None:
                    os.close(cursor["fd"])

    def _cycle(self, root: dict, job: dict) -> None:
        """Persist the directory work queue; retain only one iterator per root.

An application restart resumes unfinished directories from their beginning, then
continues fairly across bounded passes. The persistent content index suppresses
repeat reports. No unstable filesystem readdir cookie is treated as trustworthy.
"""
        with self._lock:
            current = self._root(root["id"])
            pending = self._db.execute("SELECT COUNT(*) FROM walk_dirs WHERE root_id=? AND cycle_id=? AND state='PENDING'",
                                       (root["id"], current["cycle_id"])).fetchone()[0]
            last_job = json.loads(current["last_job"]) if current["last_job"] else {}
            finalized = (not pending and last_job.get("cycle_id") == current["cycle_id"]
                         and last_job.get("cycle_complete") is True)
            context = job["analysis_context"]
            # A drained queue may still need its final coverage result published,
            # for example after interruption immediately after the last failure.
            if not current["cycle_id"] or finalized or current["cycle_context"] != context:
                self._close_cursor(root["id"])
                cycle_id = str(uuid.uuid4())
                self._db.execute("DELETE FROM walk_dirs WHERE root_id=?", (root["id"],))
                self._db.execute("INSERT INTO walk_dirs(root_id,cycle_id,relative_path,device,inode) VALUES (?,?,?,?,?)",
                                 (root["id"], cycle_id, ".", root["device"], root["inode"]))
                self._db.execute("UPDATE roots SET cycle_id=?,cycle_context=? WHERE id=?", (cycle_id, context, root["id"]))
                self._db.commit()
                job["continuation"] = False
            else:
                cycle_id = current["cycle_id"]
                job["continuation"] = True
            root["cycle_id"] = cycle_id
            job["cycle_id"] = cycle_id
            job["cycle_complete"] = False

    def _open_cursor(self, root: dict, queued: dict) -> dict:
        relative = Path(queued["relative_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Invalid persisted directory queue path")
        directory = Path(root["path"]) / relative
        if directory.resolve(strict=True) != directory or directory.is_symlink() or self._excluded_path(directory):
            raise ValueError("Directory became a link or excluded location")
        anchored = sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir()
        descriptor = None
        if anchored:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            descriptor = os.open(root["path"], flags)
            try:
                first = os.fstat(descriptor)
                if (str(first.st_dev), str(first.st_ino)) != (root["device"], root["inode"]):
                    raise ValueError("Root identity changed")
                for part in relative.parts:
                    child = os.open(part, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                opened = os.fstat(descriptor)
                if (str(opened.st_dev), str(opened.st_ino)) != (queued["device"], queued["inode"]):
                    raise ValueError("Queued directory identity changed")
                iterator = os.scandir(descriptor)
            except Exception:
                os.close(descriptor)
                raise
        else:
            opened = directory.stat()
            if (str(opened.st_dev), str(opened.st_ino)) != (queued["device"], queued["inode"]):
                raise ValueError("Queued directory identity changed")
            iterator = os.scandir(directory)
        return {"relative": queued["relative_path"], "path": directory, "cycle_id": root["cycle_id"],
                "iterator": iterator, "fd": descriptor, "pending": None, "failed": False,
                "identity": (str(opened.st_dev), str(opened.st_ino))}

    def _finish_directory(self, root: dict, relative: str, failed: bool = False, reason: str | None = None) -> None:
        self._close_cursor(root["id"])
        with self._lock:
            self._db.execute("UPDATE walk_dirs SET state=?,error=? WHERE root_id=? AND cycle_id=? AND relative_path=?",
                             ("FAILED" if failed else "DONE", reason, root["id"], root["cycle_id"], relative))
            self._db.commit()

    def _entries(self, root: dict, job: dict) -> Iterator[tuple[Path, Path, os.stat_result]]:
        path = Path(root["path"])
        try:
            if path.is_symlink() or path.resolve(strict=True) != path:
                raise ValueError("Root or ancestor became a symbolic link")
            current = path.stat()
            if (str(current.st_dev), str(current.st_ino)) != (root["device"], root["inode"]):
                raise ValueError("Root directory identity changed; explicitly register it again")
        except (OSError, RuntimeError) as exc:
            raise ValueError("Watched directory is unavailable") from exc
        private_identities = set()
        for excluded in self._excluded:
            for name in _PRIVATE_NAMES:
                try:
                    private = (excluded / name).stat()
                    private_identities.add((private.st_dev, private.st_ino))
                except OSError:
                    pass
        visited = 0
        directory_attempts = 0
        deadline = time.monotonic() + MAX_PASS_SECONDS
        while True:
            cursor = self._cursors.get(root["id"])
            if cursor is not None and cursor["cycle_id"] != root["cycle_id"]:
                self._close_cursor(root["id"])
                cursor = None
            if cursor is None:
                with self._lock:
                    queued = self._db.execute("SELECT * FROM walk_dirs WHERE root_id=? AND cycle_id=? AND state='PENDING' ORDER BY rowid LIMIT 1",
                                              (root["id"], root["cycle_id"])).fetchone()
                if queued is None:
                    # Completion consumes no traversal budget. Report the final
                    # failed directories before a later scan starts a new cycle.
                    job["cycle_complete"] = True
                    return
                if time.monotonic() >= deadline or directory_attempts >= MAX_ENTRIES:
                    job["limited"] = True
                    self._error(job, path, "PASS_LIMIT", "Directory traversal work budget reached; continuation is retained")
                    return
                try:
                    directory_attempts += 1
                    cursor = self._open_cursor(root, dict(queued))
                    self._cursors[root["id"]] = cursor
                except (OSError, ValueError, RuntimeError):
                    self._finish_directory(root, queued["relative_path"], True, "Directory changed or is unreadable")
                    job["failed"] += 1
                    self._error(job, path / queued["relative_path"], "DIRECTORY_UNREADABLE", "Queued directory changed or cannot be opened without following links")
                    continue
            if time.monotonic() >= deadline:
                job["limited"] = True
                self._error(job, path, "PASS_LIMIT", "Directory traversal work budget reached; continuation is retained")
                return
            directory = cursor["path"]
            try:
                current = directory.stat()
                if directory.resolve(strict=True) != directory or (str(current.st_dev), str(current.st_ino)) != cursor["identity"]:
                    raise ValueError("Directory changed")
            except (OSError, RuntimeError, ValueError):
                self._finish_directory(root, cursor["relative"], True, "Directory identity changed while a pass was paused")
                job["failed"] += 1
                self._error(job, directory, "DIRECTORY_CHANGED", "Directory identity changed while a pass was paused")
                continue
            self._watch_directory(root, directory)
            # A byte/time-limited pass retains its yielded but unprocessed file.
            # It is cleared only when the caller resumes after processing it.
            if cursor["pending"] is not None:
                if visited >= MAX_ENTRIES:
                    job["limited"] = True
                    self._error(job, path, "ENTRY_LIMIT", "Entry budget reached; the pending file is retained for continuation")
                    return
                visited += 1
                job["entries_seen"] = visited
                yield cursor["pending"]
                cursor["pending"] = None
                continue
            if visited >= MAX_ENTRIES:
                job["limited"] = True
                self._error(job, path, "ENTRY_LIMIT", f"Processed {MAX_ENTRIES} entries; continuation retains the next directory position")
                return
            try:
                entry = next(cursor["iterator"])
            except StopIteration:
                self._finish_directory(root, cursor["relative"], cursor["failed"], "Some entries were unavailable" if cursor["failed"] else None)
                continue
            except OSError:
                self._finish_directory(root, cursor["relative"], True, "Directory enumeration failed")
                job["failed"] += 1
                self._error(job, directory, "DIRECTORY_UNREADABLE", "Directory enumeration failed")
                continue
            visited += 1
            job["entries_seen"] = visited
            candidate = directory / entry.name
            if self._excluded_path(candidate):
                job["skipped"] += 1
                continue
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                cursor["failed"] = True
                job["failed"] += 1
                self._error(job, candidate, "FILE_UNAVAILABLE", "Directory entry became unavailable")
                continue
            if (metadata.st_dev, metadata.st_ino) in private_identities or stat.S_ISLNK(metadata.st_mode):
                job["skipped"] += 1
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if not root["recursive"]:
                    job["skipped"] += 1
                    continue
                relative = candidate.relative_to(path)
                if len(relative.parts) > MAX_DEPTH:
                    cursor["failed"] = True
                    job["failed"] += 1
                    self._error(job, candidate, "DEPTH_LIMIT", "Directory depth limit reached")
                    continue
                with self._lock:
                    self._db.execute("INSERT OR IGNORE INTO walk_dirs(root_id,cycle_id,relative_path,device,inode) VALUES (?,?,?,?,?)",
                                     (root["id"], root["cycle_id"], str(relative), str(metadata.st_dev), str(metadata.st_ino)))
                    self._db.commit()
            elif stat.S_ISREG(metadata.st_mode):
                anchored_path = Path(f"/proc/self/fd/{cursor['fd']}") / entry.name if cursor["fd"] is not None else candidate
                cursor["pending"] = (candidate, anchored_path, metadata)
                yield cursor["pending"]
                cursor["pending"] = None
            else:
                job["skipped"] += 1

    def _cached_failure(self, path: Path, metadata: os.stat_result, code: str, message: str, retry: bool, context: str) -> dict:
        result = None
        record_failure = getattr(self.reports, "record_failure", None)
        if record_failure is not None:
            result = record_failure(filename=path.name, source_path=str(path), reason=message, code=code, sha256=None)
        self._audit("FILE_WATCH_ERROR", {"path": str(path), "code": code, "reason": message})
        row = {"path": str(path), "signature": _signature(metadata), "sha256": None,
               "report_id": result.get("id") if result else None, "status": "BLOCKED", "error": code,
               "retry_after": time.time() + 3.0 if retry else 0.0, "updated_at": _now(), "context": context}
        self._save_index(row)
        return row

    def _save_index(self, row: dict) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO file_index(path,signature,sha256,report_id,status,error,retry_after,updated_at,context) VALUES (:path,:signature,:sha256,:report_id,:status,:error,:retry_after,:updated_at,:context)", row)
            self._db.commit()

    def _scan_file(self, path: Path, anchored_path: Path, metadata: os.stat_result, job: dict) -> None:
        key = str(path)
        stripe = self._stripes[int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % len(self._stripes)]
        with stripe:
            with self._lock:
                value = self._db.execute("SELECT * FROM file_index WHERE path=?", (key,)).fetchone()
                cached = dict(value) if value else None
            if cached and cached["context"] == job["analysis_context"] and cached["signature"] == _signature(metadata) and (not cached["retry_after"] or time.time() < cached["retry_after"]):
                job["unchanged"] += 1
                if cached["error"]:
                    job["failed"] += 1
                    self._error(job, path, cached["error"], "File remains unscannable; the previous failure is retained")
                job["statuses"][cached["status"]] = job["statuses"].get(cached["status"], 0) + 1
                return
            if metadata.st_size > MAX_FILE_SIZE:
                row = self._cached_failure(path, metadata, "FILE_TOO_LARGE", "File exceeds the configured 10 MiB scan limit", False, job["analysis_context"])
                job["failed"] += 1
                self._error(job, path, "FILE_TOO_LARGE", "File exceeds the configured 10 MiB scan limit")
                if row["report_id"]:
                    job["report_ids"].append(row["report_id"])
                return
            try:
                data = read_snapshot(anchored_path)
                # Descriptor anchoring protects what was read. Also reject a
                # pathname that was moved or redirected during the snapshot so
                # the report is never presented as analysis of another location.
                if path.resolve(strict=True) != path or path.is_symlink():
                    raise ValueError("Source pathname changed during scanning")
                job["bytes_read"] += len(data)
                digest = hashlib.sha256(data).hexdigest()
                if cached and cached["context"] == job["analysis_context"] and not cached["error"] and cached["sha256"] == digest:
                    cached.update(signature=_signature(metadata), updated_at=_now())
                    self._save_index(cached)
                    job["unchanged"] += 1
                    job["statuses"][cached["status"]] = job["statuses"].get(cached["status"], 0) + 1
                    return
                report = self.reports.scan(data, path.name, source_path=key)
                if report.get("sha256") != digest or report.get("status") not in {"ALLOWED", "FLAGGED", "QUARANTINED", "BLOCKED"}:
                    raise ValueError("Scanner result does not identify the inspected content")
                self._save_index({"path": key, "signature": _signature(metadata), "sha256": digest,
                                  "report_id": report["id"], "status": report["status"], "error": None,
                                  "retry_after": 0.0, "updated_at": _now(), "context": job["analysis_context"]})
                job["scanned"] += 1
                job["report_ids"].append(report["id"])
                job["statuses"][report["status"]] = job["statuses"].get(report["status"], 0) + 1
            except Exception:
                message = "File could not be read consistently or the scanner was unavailable"
                row = self._cached_failure(path, metadata, "SCAN_UNAVAILABLE", message, True, job["analysis_context"])
                job["failed"] += 1
                self._error(job, path, "SCAN_UNAVAILABLE", message)
                if row["report_id"]:
                    job["report_ids"].append(row["report_id"])

    def _scan_root(self, root_id: str, automatic: bool, reserved: bool) -> dict:
        start = time.monotonic()
        job = {"id": str(uuid.uuid4()), "root_id": root_id, "status": "RUNNING", "started_at": _now(),
               "completed_at": None, "files_seen": 0, "scanned": 0, "unchanged": 0, "skipped": 0,
               "failed": 0, "removed": 0, "limited": False, "report_ids": [], "errors": [],
               "error_count": 0, "bytes_read": 0, "entries_seen": 0, "statuses": {}, "duration_ms": 0}
        with self._lock:
            root = self._root(root_id)
            if (root_id in self._active and not reserved) or not self._slots.acquire(blocking=False):
                job.update(status="BUSY", completed_at=_now())
                return job
            self._active[root_id] = job["id"]
            generation = self._generation
        complete = True
        try:
            job["analysis_context"] = self._context()
            self._cycle(root, job)
            entries = self._entries(root, job)
            try:
                for path, anchored_path, metadata in entries:
                    with self._lock:
                        current = self._db.execute("SELECT enabled FROM roots WHERE id=?", (root_id,)).fetchone()
                    if current is None or generation != self._generation or (automatic and (not current[0] or self._stop.is_set())):
                        complete = False
                        job["status"] = "CANCELLED"
                        break
                    expected_bytes = metadata.st_size if metadata.st_size <= MAX_FILE_SIZE else 0
                    if time.monotonic() - start > MAX_PASS_SECONDS or job["bytes_read"] + expected_bytes > MAX_BYTES_PER_PASS:
                        complete = False
                        job["limited"] = True
                        self._error(job, root["path"], "PASS_LIMIT", "Pass duration or byte budget reached; remaining files were not scanned")
                        break
                    job["files_seen"] += 1
                    with self._lock:
                        self._db.execute("INSERT OR REPLACE INTO root_files(root_id,path,generation) VALUES (?,?,?)", (root_id, str(path), job["cycle_id"]))
                        self._db.commit()
                    self._scan_file(path, anchored_path, metadata, job)
            finally:
                entries.close()
            if job["limited"] or job["failed"]:
                complete = False
        except Exception:
            complete = False
            job["failed"] += 1
            self._error(job, root["path"], "ROOT_UNAVAILABLE", "Watched root changed, is unavailable, or could not be scanned safely")
        finally:
            job["completed_at"] = _now()
            job["duration_ms"] = round((time.monotonic() - start) * 1000)
            try:
                with self._lock:
                    current = self._db.execute("SELECT error,enabled FROM roots WHERE id=?", (root_id,)).fetchone()
                    if current is not None:
                        cycle_id = job.get("cycle_id")
                        pending = self._db.execute("SELECT COUNT(*) FROM walk_dirs WHERE root_id=? AND cycle_id=? AND state='PENDING'", (root_id, cycle_id)).fetchone()[0]
                        failed_dirs = self._db.execute("SELECT COUNT(*) FROM walk_dirs WHERE root_id=? AND cycle_id=? AND state='FAILED'", (root_id, cycle_id)).fetchone()[0]
                        cycle_files = self._db.execute("SELECT COUNT(*) FROM root_files WHERE root_id=? AND generation=?", (root_id, cycle_id)).fetchone()[0]
                        failed_files = self._db.execute("SELECT COUNT(*) FROM root_files r JOIN file_index f ON r.path=f.path WHERE r.root_id=? AND r.generation=? AND f.error IS NOT NULL", (root_id, cycle_id)).fetchone()[0]
                        cycle_complete = bool(job.get("cycle_complete")) and pending == 0
                        job.update(cycle_complete=cycle_complete, pending_directories=pending,
                                   cycle_files_seen=cycle_files, cycle_error_count=failed_dirs + failed_files)
                        complete = cycle_complete and not failed_dirs and not failed_files and not job["failed"] and not job["limited"]
                        if job["status"] == "RUNNING":
                            job["status"] = "COMPLETED" if complete else "PARTIAL" if cycle_files or job["limited"] else "FAILED"
                        if cycle_complete and not failed_dirs:
                            job["removed"] = self._db.execute("SELECT COUNT(*) FROM root_files WHERE root_id=? AND generation!=?", (root_id, cycle_id)).fetchone()[0]
                            self._db.execute("DELETE FROM root_files WHERE root_id=? AND generation!=?", (root_id, cycle_id))
                            self._db.execute("DELETE FROM file_index WHERE path NOT IN (SELECT path FROM root_files)")
                        if job["status"] == "CANCELLED":
                            error = "Scan paused; unfinished directory traversal is retained"
                        elif pending and job["limited"]:
                            error = f"Continuation pending: {cycle_files} files inspected; {pending} directories unfinished"
                        elif job["error_count"] or failed_dirs or failed_files:
                            error = f"{max(job['error_count'], failed_dirs + failed_files)} scan issue(s); coverage is incomplete"
                        else:
                            error = None
                        self._db.execute("UPDATE roots SET files_seen=?,last_scan_at=?,error=?,last_job=? WHERE id=?",
                                         (cycle_files, job["completed_at"], error, json.dumps(job), root_id))
                        self._db.commit()
                        if error != current["error"]:
                            try:
                                self._audit("FILE_WATCH_COVERAGE_CHANGED", {"root_id": root_id, "path": root["path"], "error": error, "status": job["status"]})
                            except (ValueError, RuntimeError):
                                pass
                        if job["limited"] and not cycle_complete and current["enabled"] and self.running:
                            self._dirty(root_id)
                    else:
                        self._close_cursor(root_id)
                        if job["status"] == "RUNNING":
                            job["status"] = "CANCELLED"
            finally:
                with self._idle:
                    if self._active.get(root_id) == job["id"]:
                        self._active.pop(root_id, None)
                    self._idle.notify_all()
                self._slots.release()
        return job
