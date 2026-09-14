"""Command line operations and explicit pre-use enforcement."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _positive(value):
    return type(value) is int and value >= 1


def _validated_scan(result, data):
    from .mcp_server import verified_summary
    if not isinstance(result, dict):
        raise ValueError("Invalid report")
    digest = hashlib.sha256(data).hexdigest() if data is not None else result.get("sha256")
    size = len(data) if data is not None else result.get("size_bytes", 0)
    if type(size) is not int or not 0 <= size <= 10 * 1024**2:
        raise ValueError("Invalid report size")
    if "size_bytes" in result and type(result["size_bytes"]) is not int:
        raise ValueError("Invalid report size type")
    if not _hash(digest) and not (digest == "" and result.get("status") == "BLOCKED" and
                                 result.get("verdict") == "UNSCANNABLE" and result.get("analysis_complete") is False):
        raise ValueError("Invalid report digest")
    summary = verified_summary(result, digest, size)
    if summary["verdict"] == "VALID" and (summary["severity"] != "INFO" or result.get("failure_kind") or
                                          result.get("error") or result.get("errors")):
        raise ValueError("Contradictory report")
    return summary


def _result_code(args, result, data=None):
    if args.command in {"scan", "guarded-read"}:
        summary = _validated_scan(result, data)
        return (0 if summary["status"] == "ALLOWED" and summary["verdict"] == "VALID" and
                summary["analysis_complete"] is True else 3), summary
    if args.command == "gate":
        if (not isinstance(result, dict) or type(result.get("allowed")) is not bool or
                not _hash(result.get("component_id")) or result["component_id"] != args.component_id or not _positive(result.get("version")) or
                not all(_hash(result.get(key)) for key in ("canonical_hash", "raw_hash", "semantic_fingerprint")) or
                not isinstance(result.get("reason"), str)):
            raise ValueError("Invalid gate report")
        allowed = result["allowed"]
        if not isinstance(result.get("action"), str) or result["action"] not in ({"ALLOW"} if allowed else {"BLOCK", "QUARANTINE", "REQUIRE_REAPPROVAL"}):
            raise ValueError("Contradictory gate report")
        if allowed and ((args.canonical_hash is not None and result["canonical_hash"] != args.canonical_hash) or
                        (args.version is not None and result["version"] != args.version)):
            raise ValueError("Stale gate report")
        return (0 if allowed else 3), result
    if args.command == "verify-audit":
        if (not isinstance(result, dict) or type(result.get("valid")) is not bool or
                type(result.get("checked")) is not int or result["checked"] < 0 or not _hash(result.get("head_hash")) or
                (result["checked"] == 0 and result["head_hash"] != "0" * 64) or
                (result["valid"] and result.get("error"))):
            raise ValueError("Invalid audit report")
        return (0 if result["valid"] else 3), result
    if not isinstance(result, list):
        raise ValueError("Invalid component collection")
    for component in result:
        if (not isinstance(component, dict) or not _hash(component.get("id")) or
                not _positive(component.get("version")) or not isinstance(component.get("state"), str) or
                not all(_hash(component.get(key)) for key in ("canonical_hash", "raw_hash", "semantic_fingerprint"))):
            raise ValueError("Invalid component report")
    return 0, result


def _emit(args, result, data=None):
    code, summary = _result_code(args, result, data)
    if args.command == "guarded-read":
        if code == 0:
            if not isinstance(data, bytes):
                raise ValueError("Missing snapshot")
            # Return the exact immutable bytes scanned, never a second path read.
            sys.stdout.buffer.write(data)
        else:
            print(json.dumps(summary, ensure_ascii=True), file=sys.stderr)
    else:
        print(json.dumps(result, ensure_ascii=True, indent=2))
    sys.exit(code)


def _online(args, connection):
    from .connection import multipart_snapshot
    if args.command == "guarded-read":
        from .reports import read_snapshot
        data = read_snapshot(args.path)
        payload, content_type = multipart_snapshot(data, args.path.name)
        return connection.request("POST", "/api/scan", payload, content_type), data
    endpoints = {
        "discover": ("/api/components/discover", "POST", {"path": str(getattr(args, "path", ""))}),
        "list": ("/api/components", "GET", None),
        "verify-audit": ("/api/audit/verify", "GET", None),
        "gate": ("/api/gate", "POST", {"component_id": getattr(args, "component_id", ""),
                 "canonical_hash": getattr(args, "canonical_hash", None), "version": getattr(args, "version", None)}),
        "scan": ("/api/scan/path", "POST", {"path": str(getattr(args, "path", ""))}),
    }
    route, method, body = endpoints[args.command]
    payload = json.dumps(body, ensure_ascii=True, allow_nan=False).encode("ascii") if body is not None else None
    return connection.request(method, route, payload), None


def main():
    parser = argparse.ArgumentParser(description="MCP Integrity Guard — trust the content, not the name")
    parser.add_argument("--data-dir", type=Path, default=Path.cwd() / "data")
    parser.add_argument("--api-url", default="http://127.0.0.1:8765",
                        help="Use running local app when available")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Start loopback administrative app")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--ui-dir", type=Path)
    serve.add_argument("--open", action="store_true", help="Open dashboard with session token")
    discover = sub.add_parser("discover")
    discover.add_argument("path", type=Path)
    sub.add_parser("list")
    sub.add_parser("verify-audit")
    for name in ("scan", "guarded-read"):
        p = sub.add_parser(name)
        p.add_argument("path", type=Path)
    gate = sub.add_parser("gate", help="Fresh approval check; exit 3 when denied")
    gate.add_argument("component_id")
    gate.add_argument("--hash", dest="canonical_hash")
    gate.add_argument("--version", type=int)
    args = parser.parse_args()
    if hasattr(args, "path"):
        args.path = args.path.expanduser().absolute()
    if args.command == "serve":
        from .api import create_app, ensure_token
        import uvicorn
        token = ensure_token(args.data_dir)
        app = create_app(args.data_dir, args.ui_dir, token)
        if args.open:
            import threading
            import webbrowser
            import time
            from .connection import verify_listener
            def open_ready():
                address = f"http://127.0.0.1:{args.port}"
                for _ in range(30):
                    try:
                        if verify_listener(address, token, timeout=.5):
                            webbrowser.open(address + "/#token=" + token)
                            return
                    except RuntimeError:
                        return
                    time.sleep(.3)
            threading.Thread(target=open_ready, daemon=True).start()
        print(f"MCP Integrity Guard: http://127.0.0.1:{args.port}")
        print(f"Data: {args.data_dir.absolute()}")
        uvicorn.run(app, host="127.0.0.1", port=args.port,
                    log_level="info", access_log=False)
        return
    from .connection import TransportError, VerifiedConnection, loopback_address, read_token
    from .core import GuardStore
    from .reports import Reports, read_snapshot
    store = None
    try:
        loopback_address(args.api_url)
        token = read_token(args.data_dir / "api-token")
        if token is not None:
            with VerifiedConnection(args.api_url, token) as connection:
                if connection.connect():
                    result, data = _online(args, connection)
                    _emit(args, result, data)
                    return
        # Only an absent listener reaches the exclusive offline store. Errors
        # opening the store, including an existing owner, remain JSON errors.
        store = GuardStore(args.data_dir)
        data = None
        if args.command == "discover":
            result = store.discover(args.path)
        elif args.command == "list":
            result = store.list_components()
        elif args.command == "verify-audit":
            result = store.verify_audit()
        elif args.command == "gate":
            result = store.gate(args.component_id, args.canonical_hash, args.version)
        else:
            data = read_snapshot(args.path)
            reports = Reports(args.data_dir, store)
            try:
                result = reports.scan(data, args.path.name, str(args.path))
            finally:
                reports.close()
        _emit(args, result, data)
    except (ValueError, TypeError, KeyError, OSError, RuntimeError, sqlite3.Error) as exc:
        # Never print server error bodies, source text, credentials or tracebacks.
        message = str(exc) if isinstance(exc, TransportError) else "Operazione non completata: file, rapporto o archivio locale non verificabile"
        print(json.dumps({"error": message}, ensure_ascii=True), file=sys.stderr)
        sys.exit(2)
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    main()
