"""Bounded worker transport; it does not grant filesystem or network sandboxing.

Captured stdout stays within max_output; reads use fixed-size chunks and the final
bytes conversion makes one bounded copy. The cap counts stdout and stderr together.
Diagnostics are never reflected verbatim
into exceptions because a compromised parser could print document secrets there.
"""
from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import threading
import time
from contextlib import suppress
from typing import Sequence

_CHUNK = 64 * 1024
_POLL = 0.05
_CLEANUP_TIMEOUT = 2.0


class _WindowsJob:
    """Keep descendants inside a kill-on-close Job Object on supported Windows."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IOCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                         "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IOCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "Cannot create scanner process job")
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            self.close()
            raise OSError(error, "Cannot configure scanner process job")

    def attach(self, process):
        import ctypes
        if not self.kernel.AssignProcessToJobObject(self.handle, process._handle):
            raise OSError(ctypes.get_last_error(), "Cannot contain scanner process in job")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def _kill_tree(process, job):
    if job is not None:
        job.close()
    elif os.name == "posix":
        # Every POSIX worker starts its own session/process group. This also
        # releases inherited pipe handles held by ordinary worker descendants.
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        with suppress(ProcessLookupError):
            process.kill()


def _close(stream):
    if stream is not None:
        with suppress(OSError, ValueError):
            stream.close()


def _run_posix(process, data: bytes, command, timeout, deadline, max_output):
    output = bytearray()
    total = position = 0
    source = memoryview(data)
    tree_cleaned = False
    with selectors.DefaultSelector() as selector:
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        if data:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            _close(process.stdin)

        def finished(stream):
            selector.unregister(stream)
            _close(stream)

        while selector.get_map():
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            if process.poll() is not None and not tree_cleaned:
                _kill_tree(process, None)
                tree_cleaned = True
            for key, _ in selector.select(min(remaining, _POLL)):
                if key.data == "stdin":
                    try:
                        written = os.write(key.fd, source[position:position + _CHUNK])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        # Match communicate(): an early close of stdin does not
                        # hide a nonzero exit or prevent draining diagnostics.
                        finished(key.fileobj)
                        continue
                    position += written
                    if position >= len(source):
                        finished(key.fileobj)
                else:
                    try:
                        chunk = os.read(key.fd, _CHUNK)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        finished(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > max_output:
                        raise RuntimeError("Scanner worker exceeded combined output limit")
                    if key.data == "stdout":
                        output.extend(chunk)
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        process.wait(timeout=remaining)
    return output


def _run_windows(process, data: bytes, command, timeout, deadline, max_output, job):
    """Synchronous Windows pipes are drained by three bounded I/O threads."""
    lock = threading.Lock()
    wake = threading.Event()
    stopping = threading.Event()
    state = {"total": 0, "readers": 0, "writer_done": False, "error": None}
    output = bytearray()

    def fail(error):
        with lock:
            if state["error"] is None and not stopping.is_set():
                state["error"] = error
        wake.set()

    def reader(stream, keep):
        try:
            while not stopping.is_set():
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                with lock:
                    state["total"] += len(chunk)
                    if state["total"] > max_output:
                        if state["error"] is None:
                            state["error"] = RuntimeError("Scanner worker exceeded combined output limit")
                        wake.set()
                        break
                    if keep:
                        output.extend(chunk)
        except OSError as exc:
            fail(exc)
        finally:
            _close(stream)
            with lock:
                state["readers"] += 1
            wake.set()

    def writer():
        try:
            view = memoryview(data)
            position = 0
            while position < len(view) and not stopping.is_set():
                written = process.stdin.write(view[position:position + _CHUNK])
                if not written:
                    raise OSError("Scanner input pipe made no progress")
                position += written
        except BrokenPipeError:
            pass
        except OSError as exc:
            fail(exc)
        finally:
            _close(process.stdin)
            with lock:
                state["writer_done"] = True
            wake.set()

    threads = [threading.Thread(target=reader, args=(process.stdout, True), name="integrity-worker-stdout", daemon=True),
               threading.Thread(target=reader, args=(process.stderr, False), name="integrity-worker-stderr", daemon=True),
               threading.Thread(target=writer, name="integrity-worker-stdin", daemon=True)]
    started = []
    try:
        for thread in threads:
            thread.start()
            started.append(thread)
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            with lock:
                error = state["error"]
                complete = state["readers"] == 2 and state["writer_done"]
            if error is not None:
                raise error
            if process.poll() is not None:
                # Closing the job releases inherited handles of descendants even
                # when the worker itself exited before closing all its pipes.
                job.close()
                if complete:
                    break
            wake.wait(min(remaining, _POLL))
            wake.clear()
    finally:
        stopping.set()
        _kill_tree(process, job)
        # Killing every job member closes all opposite pipe ends, releasing
        # synchronous reads and writes before the threads are joined.
        join_deadline = time.perf_counter() + _CLEANUP_TIMEOUT
        for thread in started:
            thread.join(max(0, join_deadline - time.perf_counter()))
        if any(thread.is_alive() for thread in started):
            raise RuntimeError("Scanner pipe threads could not be stopped")
    return output


def run_worker(command: Sequence[str], *, input: bytes, env: dict,
               timeout: float = 12, max_output: int = 4 * 1024**2) -> bytes:
    """Run a worker with bounded streams, exact supplied environment, and deadline.

    stdout and stderr count toward one limit; only stdout is returned. Nonzero
    exit, overflow or transport failure never returns a partial successful result.
    Existing parser sandbox/resource flags remain the caller's responsibility.
    """
    if not isinstance(input, bytes) or not isinstance(env, dict):
        raise ValueError("Worker input must be bytes and env must be a mapping")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Worker timeout must be positive and finite")
    if isinstance(max_output, bool) or not isinstance(max_output, int) or max_output < 0:
        raise ValueError("Worker output limit must be a nonnegative integer")
    deadline = time.perf_counter() + timeout
    job = _WindowsJob() if os.name == "nt" else None
    process = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0, env=dict(env), close_fds=True, start_new_session=os.name == "posix",
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        if job is not None:
            job.attach(process)
            output = _run_windows(process, input, command, timeout, deadline, max_output, job)
        else:
            output = _run_posix(process, input, command, timeout, deadline, max_output)
        if process.returncode != 0:
            raise RuntimeError(f"Scanner worker exited with code {process.returncode}")
        return bytes(output)
    finally:
        if process is not None:
            _kill_tree(process, job)
            for stream in (process.stdin, process.stdout, process.stderr):
                _close(stream)
            try:
                process.wait(timeout=_CLEANUP_TIMEOUT)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Scanner process could not be reaped") from exc
        if job is not None:
            job.close()
