"""Real subprocess regressions for the parent scanner transport boundary."""
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import tracemalloc
from pathlib import Path

import pytest

from integrity_guard.worker_process import run_worker


def command(code):
    return [sys.executable, "-u", "-c", code]


def minimal_env(**values):
    result = dict(values)
    # Windows Python needs the OS installation path for selected loader behavior.
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        result["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return result


@pytest.fixture
def child_processes(monkeypatch):
    import integrity_guard.worker_process as module
    original = subprocess.Popen
    children = []
    initial_threads = {t.ident for t in threading.enumerate() if t.name.startswith("integrity-worker-")}

    def observed(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(module.subprocess, "Popen", observed)
    yield children
    for child in children:
        assert child.poll() is not None, f"Worker {child.pid} remained alive"
        if os.name == "posix":
            with pytest.raises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
    assert {t.ident for t in threading.enumerate() if t.name.startswith("integrity-worker-")} == initial_threads


def test_success_returns_exact_stdout_and_ignores_small_stderr(child_processes):
    result = run_worker(command("import sys; data=sys.stdin.buffer.read(); sys.stderr.write('diagnostic'); sys.stdout.buffer.write(data[::-1])"),
                        input=b"original\x00bytes\r\n", env=minimal_env(), timeout=3)
    assert result == b"\n\rsetyb\x00lanigiro"


def test_large_input_and_simultaneous_output_do_not_deadlock(child_processes):
    payload = b"0123456789abcdef" * (512 * 1024)  # 8 MiB already owned by caller.
    script = "import sys,hashlib; sys.stdout.buffer.write(b'P'*65536); sys.stdout.buffer.flush(); data=sys.stdin.buffer.read(); sys.stdout.buffer.write(hashlib.sha256(data).hexdigest().encode())"
    result = run_worker(command(script), input=payload, env=minimal_env(), timeout=5, max_output=128 * 1024)
    assert result == b"P" * 65536 + hashlib.sha256(payload).hexdigest().encode()


@pytest.mark.parametrize("descriptor", [1, 2])
def test_stream_flood_is_stopped_before_parent_memory_grows(descriptor, child_processes):
    script = f"import os\nchunk=b'x'*65536\nwhile True: os.write({descriptor},chunk)"
    tracemalloc.start()
    started = time.perf_counter()
    try:
        with pytest.raises(RuntimeError, match="output limit"):
            run_worker(command(script), input=b"", env=minimal_env(), timeout=5, max_output=65536)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert time.perf_counter() - started < 4
    assert peak < 8 * 1024**2, "Output was buffered without enforcing the live cap"


def test_stdout_and_stderr_share_one_limit(child_processes):
    script = "import os; os.write(1,b'x'*30000); os.write(2,b'y'*30000)"
    with pytest.raises(RuntimeError, match="output limit"):
        run_worker(command(script), input=b"", env=minimal_env(), timeout=3, max_output=50000)
    assert run_worker(command(script), input=b"", env=minimal_env(), timeout=3, max_output=60000) == b"x" * 30000


def test_hung_worker_is_killed_and_reaped(child_processes):
    started = time.perf_counter()
    with pytest.raises(subprocess.TimeoutExpired):
        run_worker(command("import time; time.sleep(30)"), input=b"", env=minimal_env(), timeout=.3)
    assert time.perf_counter() - started < 3


def test_closed_output_pipes_do_not_disable_wall_timeout(child_processes):
    with pytest.raises(subprocess.TimeoutExpired):
        run_worker(command("import os,time; os.close(1); os.close(2); time.sleep(30)"),
                   input=b"", env=minimal_env(), timeout=.3)


def test_worker_not_reading_large_input_times_out_without_writer_leak(child_processes):
    with pytest.raises(subprocess.TimeoutExpired):
        run_worker(command("import time; time.sleep(30)"), input=b"x" * (8 * 1024**2), env=minimal_env(), timeout=.3)


def test_nonzero_exit_discards_output_and_diagnostics(child_processes):
    secret = "SECRET_SHOULD_NOT_BE_REFLECTED"
    with pytest.raises(RuntimeError, match="code 7") as caught:
        run_worker(command(f"import sys; print('partial success'); sys.stderr.write('{secret}'); sys.exit(7)"),
                   input=b"", env=minimal_env(), timeout=3)
    assert secret not in str(caught.value)
    assert "partial success" not in str(caught.value)


def test_only_explicit_environment_is_passed(monkeypatch, child_processes):
    monkeypatch.setenv("MCP_PARENT_TEST_SECRET", "parent-only-secret")
    script = "import os,json; print(json.dumps({'secret':os.environ.get('MCP_PARENT_TEST_SECRET'),'allowed':os.environ.get('ALLOWED')}))"
    response = run_worker(command(script), input=b"", env=minimal_env(ALLOWED="explicit"), timeout=3)
    assert json.loads(response) == {"secret": None, "allowed": "explicit"}


def test_empty_output_can_use_zero_output_budget(child_processes):
    assert run_worker(command("pass"), input=b"", env=minimal_env(), timeout=3, max_output=0) == b""
    with pytest.raises(RuntimeError, match="output limit"):
        run_worker(command("print('x')"), input=b"", env=minimal_env(), timeout=3, max_output=0)


def test_missing_executable_raises_oserror_without_resources():
    with pytest.raises(OSError):
        run_worker(["/unavailable-integrity-guard-test-worker"], input=b"", env=minimal_env(), timeout=1)


@pytest.mark.parametrize("timeout,limit", [(0, 1), (-1, 1), (float("nan"), 1), (float("inf"), 1), (1, -1), (1, True)])
def test_invalid_limits_fail_before_process_creation(timeout, limit, child_processes):
    with pytest.raises(ValueError):
        run_worker(command("pass"), input=b"", env=minimal_env(), timeout=timeout, max_output=limit)
    assert child_processes == []


@pytest.mark.skipif(os.name != "posix", reason="Linux process-group lifecycle assertion")
def test_inherited_pipe_descendant_is_terminated_when_worker_exits(tmp_path, child_processes, monkeypatch, record_property):
    import signal
    import integrity_guard.worker_process as module

    pid_path = tmp_path / "descendant.pid"
    descendant = "import time; time.sleep(30)"
    script = "import subprocess,sys,pathlib; p=subprocess.Popen([sys.executable,'-c'," + repr(descendant) + "]); pathlib.Path(" + repr(str(pid_path)) + ").write_text(str(p.pid)); print('complete')"
    started = time.perf_counter()
    evidence = {"kill_calls": [], "observations": []}
    original_killpg = os.killpg

    def process_state(pid):
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            return {"pid": pid, "start_ticks": None, "state": "ABSENT"}
        return {"pid": pid, "start_ticks": int(fields[19]), "state": fields[0]}

    def observed_killpg(pgid, sig):
        event = {"pgid": pgid, "signal": int(sig)}
        try:
            event["descendant"] = process_state(int(pid_path.read_text()))
        except (OSError, ValueError, IndexError) as exc:
            event["observation_error"] = type(exc).__name__
        event["seconds"] = time.perf_counter() - started
        evidence["kill_calls"].append(event)
        # Observation never substitutes for, or suppresses, the actual signal.
        try:
            result = original_killpg(pgid, sig)
        except ProcessLookupError:
            event["result"] = "group_absent"
            raise
        event["result"] = "signal_sent"
        return result

    monkeypatch.setattr(module.os, "killpg", observed_killpg)
    try:
        result = run_worker(command(script), input=b"", env=minimal_env(), timeout=3)
        returned = time.perf_counter()
        evidence["worker_return_seconds"] = returned - started
        assert result == b"complete\n"
        assert child_processes[0].stdout.closed and child_processes[0].stderr.closed
        pid = int(pid_path.read_text())
        signals = [event for event in evidence["kill_calls"]
                   if event["pgid"] == child_processes[0].pid
                   and event["signal"] == signal.SIGKILL and event.get("result") == "signal_sent"]
        assert signals, evidence
        identity = signals[0]["descendant"]
        assert identity["pid"] == pid and identity["state"] not in {"ABSENT", "Z"}, evidence
        while True:
            state = process_state(pid)
            state["seconds_after_return"] = time.perf_counter() - returned
            evidence["observations"].append(state)
            assert state["seconds_after_return"] <= 2, evidence
            if state["state"] == "ABSENT":
                break
            assert state["start_ticks"] == identity["start_ticks"], evidence
            # A zombie is no longer running and cannot retain inherited pipes.
            if state["state"] == "Z":
                break
            time.sleep(min(0.01, max(0, 2 - state["seconds_after_return"])))
    finally:
        encoded = json.dumps(evidence, sort_keys=True)
        (tmp_path / "lifecycle-observation.json").write_text(encoded)
        record_property("lifecycle_observation", encoded)


@pytest.mark.skipif(os.name != "nt", reason="Windows job-object lifecycle assertion")
def test_windows_job_terminates_descendant_holding_output_pipes(tmp_path, child_processes):
    import ctypes
    from ctypes import wintypes

    pid_path = tmp_path / "descendant.pid"
    descendant = "import time; time.sleep(30)"
    script = "import subprocess,sys,pathlib; p=subprocess.Popen([sys.executable,'-c'," + repr(descendant) + "]); pathlib.Path(" + repr(str(pid_path)) + ").write_text(str(p.pid)); print('complete')"
    result = run_worker(command(script), input=b"", env=minimal_env(), timeout=3)
    assert result.splitlines() == [b"complete"]
    pid = int(pid_path.read_text())
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if handle:
        try:
            assert kernel.WaitForSingleObject(handle, 2000) == 0, "Worker descendant survived job closure"
        finally:
            kernel.CloseHandle(handle)
    else:
        assert ctypes.get_last_error() == 87, "Unexpected error checking worker descendant"


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="Linux descriptor accounting")
def test_repeated_runs_leave_no_open_pipe_descriptors(child_processes):
    before = len(list(Path("/proc/self/fd").iterdir()))
    for _ in range(5):
        assert run_worker(command("print('ok')"), input=b"", env=minimal_env(), timeout=3) == b"ok\n"
    assert len(list(Path("/proc/self/fd").iterdir())) == before
