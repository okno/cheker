"""Loopback-only administrative API and locally served SOC dashboard."""

from __future__ import annotations

import hmac
import os
import secrets
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .core import ConflictError, GuardStore
from .connection import proof
from .monitor import Monitor
from .filewatch import FileWatch
from .reports import MAX_FILE_SIZE, Reports, read_snapshot
from .sanitizer import Sanitizer, SanitizationStorageError


def ensure_token(data_dir: Path) -> str:
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = data_dir / "api-token"
    try:
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        token = token_path.read_text(encoding="ascii").strip()
        if len(token) < 32:
            raise ValueError("Invalid api-token file; restore it or remove it to rotate")
        return token
    token = secrets.token_urlsafe(48)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(token)
    return token


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Source(StrictModel):
    path: str = Field(min_length=1, max_length=4096)


class WatchedRoot(Source):
    recursive: bool = False


class SanitizationSource(Source):
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class Approval(StrictModel):
    canonical_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: int = Field(ge=1)
    approver: str = Field(min_length=1, max_length=120)
    note: str = Field(default="", max_length=2000)


class Reason(StrictModel):
    reason: str = Field(min_length=1, max_length=2000)


Action = Literal["ALLOW", "WARN", "REQUIRE_REAPPROVAL", "QUARANTINE", "BLOCK"]


class Policy(StrictModel):
    version: int = Field(ge=1)
    format_only_action: Action
    semantic_change_action: Action
    security_change_action: Action
    unapproved_action: Action
    scan_block_score: int = Field(ge=1, le=100)
    scan_quarantine_score: int = Field(ge=1, le=100)
    scan_flag_score: int = Field(ge=1, le=100)


class Watch(StrictModel):
    enabled: bool


class Gate(StrictModel):
    component_id: str = Field(min_length=1, max_length=128)
    canonical_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    version: int | None = Field(default=None, ge=1)


class SecurityBoundary:
    """Authenticate before parsing uploads; protect against hostile browser origins."""

    def __init__(self, app, token: str):
        self.app, self.token = app, token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        origin = headers.get(b"origin", b"").decode("latin-1")
        host = headers.get(b"host", b"").decode("latin-1")
        if origin and origin not in {f"http://{host}", "http://localhost:5173", "http://127.0.0.1:5173"}:
            return await JSONResponse({"detail": "Origin not allowed"}, 403)(scope, receive, send)
        if scope["path"].startswith("/api/") and scope["path"] != "/api/health":
            supplied = headers.get(b"authorization", b"").decode("latin-1")
            if not hmac.compare_digest(supplied.encode(), ("Bearer " + self.token).encode()):
                return await JSONResponse({"detail": "Authentication required"}, 401)(scope, receive, send)
        limit = MAX_FILE_SIZE + 1024**2
        try:
            if int(headers.get(b"content-length", b"0")) > limit:
                return await JSONResponse({"detail": "Request exceeds 11 MiB"}, 413)(scope, receive, send)
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length"}, 400)(scope, receive, send)
        consumed = 0

        async def limited_receive():
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > limit:
                    raise HTTPException(413, "Request exceeds 11 MiB")
            return message

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"), (b"cache-control", b"no-store"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
                ]
            await send(message)

        await self.app(scope, limited_receive, secure_send)


def create_app(data_dir: Path | str | None = None, ui_dir: Path | str | None = None,
               token: str | None = None, start_monitor: bool = True) -> FastAPI:
    data_dir = Path(data_dir or os.environ.get("MCP_GUARD_DATA", Path.cwd() / "data")).absolute()
    data_dir.mkdir(parents=True, exist_ok=True)
    token = token or ensure_token(data_dir)
    store = GuardStore(data_dir)
    reports = Reports(data_dir, store)
    sanitizer = Sanitizer(reports, data_dir, token)
    monitor = Monitor(store)
    filewatch = FileWatch(reports, data_dir)
    if sys.platform == "linux":
        from .linux_sandbox import probe_capabilities
        scanner_capabilities = probe_capabilities()
    else:
        scanner_capabilities = {"available": False, "error": "Filesystem and network confinement requires Linux"}

    @asynccontextmanager
    async def lifespan(app):
        if start_monitor:
            monitor.start()
            filewatch.start()
        yield
        filewatch.close()
        monitor.stop()
        reports.close()
        store.close()

    app = FastAPI(title="MCP Integrity Guard", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.reports, app.state.monitor = store, reports, monitor
    app.state.filewatch = filewatch
    app.state.sanitizer = sanitizer
    app.add_middleware(SecurityBoundary, token=token)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])

    @app.exception_handler(ConflictError)
    async def conflict(_, exc):
        return JSONResponse({"detail": str(exc)}, 409)

    @app.exception_handler(KeyError)
    async def missing(_, exc):
        return JSONResponse({"detail": "Requested record does not exist"}, 404)

    @app.exception_handler(ValueError)
    async def invalid(_, exc):
        return JSONResponse({"detail": str(exc)}, 400)

    @app.exception_handler(OSError)
    async def io_error(_, exc):
        return JSONResponse({"detail": f"File unavailable: {type(exc).__name__}"}, 400)

    @app.exception_handler(SanitizationStorageError)
    async def sanitization_storage_error(_, exc):
        return JSONResponse({"detail": "Copia non consegnata: registrazione non completata"}, 503)

    @app.get("/api/health")
    def health(request: Request, nonce: str = ""):
        result = {"status": "ok", "version": __version__}
        if nonce:
            if len(nonce) != 64 or any(ch not in "0123456789abcdef" for ch in nonce):
                raise HTTPException(400, "Invalid listener challenge")
            server = request.scope.get("server")
            if not server:
                raise HTTPException(503, "Listener endpoint is unavailable")
            result["proof"] = proof(token, nonce, server[0], server[1])
        return result

    @app.get("/api/status")
    def status():
        components = store.list_components()
        return {"components": len(components),
                "approved": sum(c["state"] == "APPROVED" for c in components),
                "pending": sum(c["state"] in {"PENDING_APPROVAL", "REAPPROVAL_REQUIRED"} for c in components),
                "blocked": sum(c["state"] in {"BLOCKED", "QUARANTINED", "REVOKED"} for c in components),
                "scans": reports.count(), "audit_valid": store.verify_audit(fast=True)["valid"],
                "monitor_running": monitor.status()["running"], "policy_version": store.get_policy()["version"],
                "enforcement_mode": "integration-gate", "data_dir": str(data_dir),
                "scanner_sandbox": scanner_capabilities}

    @app.get("/api/components")
    def components():
        return store.list_components()

    @app.post("/api/components/discover")
    def discover(body: Source):
        return store.discover(Path(body.path))

    @app.get("/api/components/{id}")
    def component(id: str):
        return store.get_component(id)

    @app.post("/api/components/{id}/refresh")
    def refresh(id: str):
        return store.refresh(id)

    @app.post("/api/components/{id}/approve")
    def approve(id: str, body: Approval):
        return store.approve(id, body.canonical_hash, body.version, body.approver.strip(), body.note)

    @app.post("/api/components/{id}/revoke")
    def revoke(id: str, body: Reason):
        return store.revoke(id, body.reason)

    @app.post("/api/components/{id}/quarantine")
    def quarantine(id: str, body: Reason):
        return store.quarantine(id, body.reason)

    @app.get("/api/components/{id}/history")
    def history(id: str):
        return store.history(id)

    @app.get("/api/components/{id}/approval")
    def approval(id: str):
        return store.approval(id)

    @app.post("/api/gate")
    def gate(body: Gate):
        return store.gate(body.component_id, body.canonical_hash, body.version)

    @app.post("/api/scan")
    async def scan(file: UploadFile = File(...)):
        try:
            data = await file.read(MAX_FILE_SIZE + 1)
            return await run_in_threadpool(reports.scan, data, file.filename or "file.txt")
        except RuntimeError as exc:
            raise HTTPException(429, str(exc)) from exc
        finally:
            await file.close()

    @app.post("/api/scan/path")
    def scan_path(body: Source):
        path = Path(body.path).expanduser().absolute()
        try:
            data = read_snapshot(path)
        except (ValueError, OSError) as exc:
            code = "INPUT_SIZE_LIMIT" if "limit" in str(exc) else "SOURCE_UNAVAILABLE"
            return reports.record_failure(path.name, str(path), type(exc).__name__ + ": file non leggibile o non consentito", code)
        try:
            return reports.scan(data, path.name, str(path))
        except RuntimeError as exc:
            raise HTTPException(429, str(exc)) from exc

    @app.get("/api/scans")
    def scans(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
              verdict: str = "ALL", query: str = Query("", max_length=300)):
        return reports.list(limit, offset, verdict, query)

    @app.get("/api/scan/stats")
    def scan_stats(verdict: str = "ALL", query: str = Query("", max_length=300)):
        return reports.stats(verdict, query)

    @app.get("/api/scans/{id}")
    def report(id: str):
        return reports.get(id)

    @app.post("/api/sanitizations/html")
    async def sanitize_html(file: UploadFile = File(...), expected_sha256: str | None = Form(
            default=None, pattern=r"^[0-9a-f]{64}$")):
        try:
            data = await file.read(MAX_FILE_SIZE + 1)
            return await run_in_threadpool(sanitizer.sanitize, data, file.filename or "document.html",
                                          None, expected_sha256)
        except SanitizationStorageError:
            raise
        except RuntimeError as exc:
            raise HTTPException(429, "Due analisi sono già in corso; riprova tra poco") from exc
        finally:
            await file.close()

    @app.post("/api/sanitizations/html/path")
    def sanitize_html_path(body: SanitizationSource):
        try:
            return sanitizer.sanitize_path(body.path, body.expected_sha256)
        except SanitizationStorageError:
            raise
        except RuntimeError as exc:
            raise HTTPException(429, "Due analisi sono già in corso; riprova tra poco") from exc

    @app.get("/api/sanitizations")
    def sanitizations(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return sanitizer.list(limit, offset)

    @app.get("/api/sanitizations/{id}")
    def sanitization(id: str):
        return sanitizer.get(id)

    @app.get("/api/policy")
    def policy():
        return store.get_policy()

    @app.put("/api/policy")
    def save_policy(body: Policy):
        return store.set_policy(body.model_dump())

    @app.get("/api/audit")
    def audit():
        return store.audit_events()

    @app.get("/api/audit/verify")
    def verify():
        return store.verify_audit()

    @app.get("/api/audit/export")
    def export():
        return JSONResponse({"verification": store.verify_audit(), "events": store.audit_events(limit=1000000)},
                            headers={"Content-Disposition": 'attachment; filename="integrity-audit.json"'})

    @app.get("/api/monitor")
    def monitor_status():
        return monitor.status()

    @app.post("/api/monitor")
    def set_monitor(body: Watch):
        result = monitor.start() if body.enabled else monitor.stop()
        store.append_audit("MONITOR_CHANGED", None, {"enabled": body.enabled})
        return result

    @app.get("/api/filewatch")
    def filewatch_status():
        return {"running": filewatch.running, "roots": filewatch.list_roots()}

    @app.post("/api/filewatch")
    def set_filewatch(body: Watch):
        if body.enabled:
            filewatch.start()
        else:
            filewatch.stop()
        return filewatch_status()

    @app.post("/api/filewatch/roots")
    def add_watched_root(body: WatchedRoot):
        return filewatch.add_root(Path(body.path), body.recursive)

    @app.delete("/api/filewatch/roots/{id}")
    def remove_watched_root(id: str):
        filewatch.remove_root(id)
        return {"removed": id}

    @app.put("/api/filewatch/roots/{id}")
    def update_watched_root(id: str, body: Watch):
        return filewatch.set_enabled(id, body.enabled)

    @app.post("/api/filewatch/roots/{id}/scan")
    def scan_watched_root(id: str):
        try:
            return filewatch.scan_root(id)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc

    if ui_dir and Path(ui_dir).is_dir():
        ui_dir = Path(ui_dir).absolute()
        assets = ui_dir / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/")
        def index():
            return FileResponse(ui_dir / "index.html")

        @app.get("/favicon.svg")
        def favicon():
            if not (ui_dir / "favicon.svg").is_file():
                raise HTTPException(404)
            return FileResponse(ui_dir / "favicon.svg")

    return app
