"""Cross-platform filesystem watch with debounce and periodic reconciliation."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class Monitor:
    def __init__(self, store, debounce: float = 0.45, reconcile: float = 5.0):
        self.store = store
        self.debounce = debounce
        self.reconcile = reconcile
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._observer = None
        self._thread = None
        self._directories = set()
        self._dirty = {}
        self.errors = []

    def _record_error(self, message):
        with self._lock:
            self.errors = (self.errors + [str(message)[:300]])[-10:]

    def status(self):
        return {"running": bool(self._thread and self._thread.is_alive()),
                "paths": self.store.source_paths(), "errors": list(self.errors)}

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return self.status()
            self._stop.clear()
            self._directories.clear()
            self._observer = Observer()
            owner = self

            class Handler(FileSystemEventHandler):
                def on_any_event(self, event):
                    if event.event_type not in {"modified", "created", "deleted", "moved"}:
                        return
                    with owner._lock:
                        for path in (event.src_path, getattr(event, "dest_path", "")):
                            if path:
                                owner._dirty[str(Path(path).absolute())] = time.monotonic()

            self._handler = Handler()
            self._sync_watches()
            self._observer.start()
            self._thread = threading.Thread(target=self._run, name="integrity-monitor", daemon=True)
            self._thread.start()
            return self.status()

    def _sync_watches(self):
        for source in self.store.source_paths():
            parent = str(Path(source).parent)
            if parent not in self._directories and Path(parent).is_dir():
                try:
                    self._observer.schedule(self._handler, parent, recursive=False)
                    self._directories.add(parent)
                except OSError as exc:
                    self._record_error(f"Watch unavailable: {type(exc).__name__}")

    def _run(self):
        next_reconcile = 0.0
        while not self._stop.wait(0.2):
            try:
                now = time.monotonic()
                self._sync_watches()
                sources = set(self.store.source_paths())
                with self._lock:
                    due = {p for p, t in self._dirty.items() if now - t >= self.debounce}
                    for path in due:
                        self._dirty.pop(path, None)
                if now >= next_reconcile:
                    due |= sources
                    next_reconcile = now + self.reconcile
                due &= sources
                # Project once per cycle, then refresh each due source once.
                # Repeated projections would reverify the whole inventory for
                # every source as well as repeat the audit anchor scan.
                representatives = {}
                if due:
                    for component in self.store.list_components():
                        if component["source_path"] in due:
                            representatives.setdefault(component["source_path"], component["id"])
                for path in due:
                    if path in representatives:
                        try:
                            self.store.refresh(representatives[path])
                        except Exception as exc:
                            self._record_error(f"Refresh failed: {type(exc).__name__}")
            except Exception as exc:
                self._record_error(f"Monitor cycle failed: {type(exc).__name__}")

    def stop(self):
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._thread:
            self._thread.join(timeout=5)
        return self.status()
