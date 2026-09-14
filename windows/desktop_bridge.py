"""Private stdio bridge between the Windows window and its Linux engine.

Only READY contains the session credential; it is sent through the parent's
anonymous pipe, never through a URL, command-line argument or log file.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time
import zipfile


ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "linux"
DATA = ROOT / "data-linux"
PYTHON = ENGINE / "runtime-linux/bin/python"


def emit(kind: str, **values) -> None:
    print(json.dumps({"kind": kind, **values}, ensure_ascii=True), flush=True)


def run_logged(command: list[str], log, timeout: int = 600) -> None:
    child = subprocess.Popen(command, cwd=ENGINE, stdin=subprocess.DEVNULL,
                             stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            readable, _, _ = select.select([sys.stdin], [], [], 0.2)
            if readable and (not (line := sys.stdin.readline()) or line.strip() == "STOP"):
                raise SystemExit(0)
            if time.monotonic() > deadline:
                raise RuntimeError("Preparazione del motore scaduta. Consulta logs/installazione.log.")
        if child.returncode:
            raise RuntimeError("Preparazione del motore non completata. Consulta logs/installazione.log.")
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)


def verify_installed() -> None:
    wheel, = (ENGINE / "wheels").glob("mcp_integrity_guard-*.whl")
    distribution = importlib.metadata.distribution("mcp-integrity-guard")
    with zipfile.ZipFile(wheel) as archive:
        members = [name for name in archive.namelist() if name.startswith("integrity_guard/") and not name.endswith("/")]
        if not members:
            raise RuntimeError("Il pacchetto del motore non contiene moduli verificabili.")
        for name in members:
            installed = Path(distribution.locate_file(name))
            if hashlib.sha256(installed.read_bytes()).digest() != hashlib.sha256(archive.read(name)).digest():
                raise RuntimeError("Il motore installato non corrisponde al pacchetto. Reinstalla Cheker in una nuova cartella.")


def prepare() -> None:
    emit("progress", message="Controllo il pacchetto Linux…")
    if sys.version_info < (3, 11):
        raise RuntimeError("Serve Python 3.11 o successivo nella distribuzione WSL.")
    logs = ROOT / "logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    with (logs / "installazione.log").open("ab") as log:
        run_logged([sys.executable, "-I", str(ENGINE / "verify-release.py")], log, 30)
        if not (ENGINE / ".desktop-installed").exists():
            emit("progress", message="Primo avvio: preparo il motore Linux. Può richiedere qualche minuto…")
            run_logged(["bash", str(ENGINE / "install-linux.sh")], log)
            (ENGINE / ".desktop-installed").write_text("1\n", encoding="ascii")
    # Re-exec once under the installed interpreter; all imports then come from
    # the packaged environment rather than the distribution's global Python.
    os.execv(str(PYTHON), [str(PYTHON), "-I", str(ROOT / "desktop_bridge.py"), "--installed"])


def serve() -> None:
    from integrity_guard.connection import read_token, verify_listener
    verify_installed()
    emit("progress", message="Verifico le protezioni del motore…")
    diagnostic = subprocess.run([str(PYTHON), "-I", "-m", "integrity_guard.diagnostics"],
                                capture_output=True, text=True, timeout=30)
    if diagnostic.returncode:
        raise RuntimeError("Le protezioni Linux richieste non sono disponibili. Aggiorna WSL 2 e riprova.")
    DATA.mkdir(mode=0o700, exist_ok=True)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    child = None
    log = (ROOT / "logs/servizio.log").open("ab")
    try:
        emit("progress", message="Avvio la dashboard locale…")
        child = subprocess.Popen([str(PYTHON), "-I", "-m", "integrity_guard", "--data-dir", str(DATA),
                                  "serve", "--ui-dir", str(ENGINE / "ui"), "--port", str(port)],
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        deadline = time.monotonic() + 45
        token = None
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError("Il motore non si è avviato. Consulta logs/servizio.log.")
            token = read_token(DATA / "api-token")
            if token and verify_listener(url, token, timeout=0.5):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("Il motore non risponde entro il tempo previsto.")
        emit("ready", url=url, token=token, engine_pid=child.pid)
        while child.poll() is None:
            readable, _, _ = select.select([sys.stdin], [], [], 0.5)
            if readable:
                line = sys.stdin.readline()
                if not line or line.strip() == "STOP":
                    return
        raise RuntimeError("Il motore si è arrestato. Chiudi e riapri Cheker.")
    finally:
        if child and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        log.close()


def main() -> int:
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    lock = None
    try:
        if "--installed" not in sys.argv:
            prepare()
        lock = (ROOT / ".desktop.lock").open("a")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        serve()
        return 0
    except BlockingIOError:
        emit("error", message="Cheker è già aperto con questa cartella dati.")
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        emit("error", message=str(exc))
    except Exception:
        emit("error", message="Avvio non completato. Verifica Python 3.11+, python3-venv e la cartella del pacchetto.")
    finally:
        if lock:
            lock.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
