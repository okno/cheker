"""Linux MCP stdio file reader, pinned to protocol 2025-11-25.

All file authority comes from explicit command-line roots. The running local admin
API scans the exact immutable bytes delivered by read_file. No other MCP server or
source file is executed. stdout is reserved exclusively for newline JSON-RPC.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import math
import os
import re
import secrets
import stat
import sys
import time
import uuid
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .connection import proof

PROTOCOL_VERSION = "2025-11-25"
MAX_MESSAGE_BYTES = 64 * 1024
MAX_SCAN_BYTES = 10 * 1024 * 1024
MAX_READ_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
API_TIMEOUT = 20.0
MAX_REQUESTS = 10_000
READ_FORMATS = {".txt", ".md", ".json", ".json5", ".yaml", ".yml", ".toml", ".csv", ".html", ".xml",
                ".py", ".js", ".ts", ".sh", ".ps1", ".htm"}
PRIVATE_NAMES = {"api-token", "approval-key.pem", "audit-head.json", ".store.lock", "integrity.sqlite3",
                 "integrity.sqlite3-wal", "integrity.sqlite3-shm", "scans.sqlite3", "scans.sqlite3-wal",
                 "scans.sqlite3-shm", "filewatch.sqlite3", "filewatch.sqlite3-wal", "filewatch.sqlite3-shm"}
STATUS = {"ALLOWED", "FLAGGED", "QUARANTINED", "BLOCKED"}
VERDICT = {"VALID", "INFECTED", "CORRUPTED", "REVIEW_REQUIRED", "UNSCANNABLE"}
SEVERITY = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


class GuardError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class RpcError(ValueError):
    def __init__(self, code: int, message: str):
        self.code = code
        super().__init__(message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def strict_json(data: bytes):
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON value")))
    count = 0
    def visit(item, depth=0):
        nonlocal count
        count += 1
        if count > 20_000 or depth > 32:
            raise ValueError("JSON structural limit")
        if isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("Non-finite JSON value")
        elif isinstance(item, dict):
            for key, child in item.items():
                key.encode("utf-8")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
    visit(value)
    return value


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class LocalScanner:
    """Prove possession of the token before sending it on the same TCP connection."""

    def __init__(self, api_url: str, token: str):
        parsed = urlsplit(api_url)
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise ValueError("API URL must be a literal HTTP loopback address with no path or credentials")
        port = parsed.port if parsed.port is not None else 80
        if not 1 <= port <= 65535:
            raise ValueError("API port must be between 1 and 65535")
        self.host, self.port = parsed.hostname, port
        self.token = token

    def _read(self, connection, response, limit, deadline):
        if response.status != 200 or not response.getheader("Content-Type", "").lower().startswith("application/json"):
            raise GuardError("API_UNAVAILABLE", "The local scanner did not return a usable JSON report")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > limit):
            raise GuardError("API_RESPONSE_LIMIT", "The local scanner response exceeded its limit")
        chunks, received = [], 0
        while received <= limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GuardError("API_TIMEOUT", "The local scanner did not finish in time")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read(min(64 * 1024, limit + 1 - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
        if received > limit:
            raise GuardError("API_RESPONSE_LIMIT", "The local scanner response exceeded its limit")
        try:
            return strict_json(b"".join(chunks))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise GuardError("API_INVALID_REPORT", "The local scanner response could not be verified") from exc

    def scan(self, data: bytes, filename: str) -> dict:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=API_TIMEOUT)
        deadline = time.monotonic() + API_TIMEOUT
        try:
            nonce = secrets.token_hex(32)
            connection.request("GET", "/api/health?nonce=" + nonce, headers={"Accept": "application/json"})
            response = connection.getresponse()
            health = self._read(connection, response, 4096, deadline)
            received = health.get("proof") if isinstance(health, dict) else None
            if not isinstance(received, str) or not re.fullmatch(r"[a-f0-9]{64}", received) or not hmac.compare_digest(received, proof(self.token, nonce, self.host, self.port)):
                raise GuardError("API_IDENTITY_FAILED", "Local scanner identity could not be verified; credentials were not sent")
            proven_socket = connection.sock
            if proven_socket is None or response.will_close:
                raise GuardError("API_IDENTITY_FAILED", "The verified connection closed before authentication")
            connection.auto_open = 0
            # Preserve ordinary filenames and format markers (.env included),
            # while preventing MIME header injection by using only ASCII atoms.
            safe_filename = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name)
            if len(safe_filename) > 180:
                safe_filename = safe_filename[:150] + Path(safe_filename).suffix[:20]
            safe_filename = safe_filename or "file.bin"
            boundary = "mcpguard-" + secrets.token_hex(24)
            header = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe_filename}\"\r\n"
                      "Content-Type: application/octet-stream\r\n\r\n").encode("ascii")
            body = header + data + f"\r\n--{boundary}--\r\n".encode("ascii")
            if connection.sock is not proven_socket:
                raise GuardError("API_IDENTITY_FAILED", "The verified connection changed before authentication")
            connection.sock.settimeout(max(0.1, deadline - time.monotonic()))
            connection.request("POST", "/api/scan", body=body,
                               headers={"Authorization": "Bearer " + self.token, "Accept": "application/json",
                                        "Content-Type": "multipart/form-data; boundary=" + boundary,
                                        "Content-Length": str(len(body))})
            return self._read(connection, connection.getresponse(), MAX_RESPONSE_BYTES, deadline)
        except GuardError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise GuardError("API_UNAVAILABLE", "Start the local MCP Integrity Guard application before using this tool") from exc
        finally:
            connection.close()


def verified_summary(report: dict, digest: str, size: int) -> dict:
    """Return source-free metadata only: findings evidence never crosses into MCP."""
    try:
        if not isinstance(report, dict) or report["sha256"] != digest:
            raise ValueError("hash")
        report_id = str(uuid.UUID(report["id"]))
        if report["status"] not in STATUS or report["verdict"] not in VERDICT or report["severity"] not in SEVERITY:
            raise ValueError("classification")
        if type(report["analysis_complete"]) is not bool or type(report["risk_score"]) is not int or not 0 <= report["risk_score"] <= 100:
            raise ValueError("values")
        if type(report["policy_version"]) is not int or report["policy_version"] < 1:
            raise ValueError("policy")
        if report.get("size_bytes", size) != size:
            raise ValueError("size")
        findings = report["findings"]
        if not isinstance(findings, list) or len(findings) > 1024 or any(not isinstance(f, dict) for f in findings):
            raise ValueError("findings")
        extraction = report["extraction"]
        if not isinstance(extraction, dict) or type(extraction.get("truncated")) is not bool:
            raise ValueError("extraction")
        if report["verdict"] == "VALID" and (report["status"] != "ALLOWED" or not report["analysis_complete"]
                or findings or report["risk_score"] != 0 or extraction["truncated"]):
            raise ValueError("inconsistent verdict")
        return {"report_id": report_id, "sha256": digest, "size_bytes": size, "status": report["status"],
                "verdict": report["verdict"], "severity": report["severity"], "risk_score": report["risk_score"],
                "analysis_complete": report["analysis_complete"] and not extraction["truncated"],
                "policy_version": report["policy_version"], "findings_count": len(findings)}
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise GuardError("API_INVALID_REPORT", "The scan report did not prove analysis of these exact bytes") from exc


class GuardedReader:
    def __init__(self, roots: list[Path], data_dir: Path, api_url: str = "http://127.0.0.1:8765"):
        if not sys.platform.startswith("linux"):
            raise ValueError("The guarded stdio reader currently requires Linux or WSL")
        self.data_dir = Path(os.path.abspath(Path(data_dir).expanduser()))
        if self.data_dir.resolve(strict=True) != self.data_dir:
            raise ValueError("Application data path cannot contain symbolic links")
        token_path = self.data_dir / "api-token"
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(token_path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("API token is not a regular file")
            token = stream.read(257).decode("ascii").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token):
            raise ValueError("API token is unavailable or invalid")
        self.scanner = LocalScanner(api_url, token)
        self._token = token.encode("ascii")
        if not roots or len(roots) > 32:
            raise ValueError("Specify between one and 32 explicit roots")
        self.roots = []
        for value in roots:
            root = Path(os.path.abspath(Path(value).expanduser()))
            if root.resolve(strict=True) != root or not root.is_dir() or _within(root, self.data_dir):
                raise ValueError("Roots must be existing non-symlink directories outside application data")
            metadata = root.stat()
            self.roots.append((root, (metadata.st_dev, metadata.st_ino)))
        self.roots.sort(key=lambda item: len(item[0].parts), reverse=True)
        self._calls = deque()

    def _private_ids(self):
        identities = set()
        for name in PRIVATE_NAMES:
            try:
                value = (self.data_dir / name).stat()
                identities.add((value.st_dev, value.st_ino))
            except OSError:
                pass
        return identities

    def snapshot(self, supplied_path: str):
        if not isinstance(supplied_path, str) or not supplied_path or len(supplied_path.encode("utf-8")) > 4096 or "\0" in supplied_path:
            raise GuardError("INVALID_PATH", "Use an absolute file path within an explicitly configured root")
        value = Path(supplied_path)
        if not value.is_absolute():
            raise GuardError("INVALID_PATH", "An absolute file path is required")
        path = Path(os.path.abspath(value))
        permitted = next(((root, identity) for root, identity in self.roots if _within(path, root)), None)
        if permitted is None or _within(path, self.data_dir) or any(part in PRIVATE_NAMES for part in path.parts):
            raise GuardError("PATH_DENIED", "The path is outside allowed roots or contains protected application data")
        root, identity = permitted
        parts = path.relative_to(root).parts
        if not parts or len(parts) > 64:
            raise GuardError("PATH_DENIED", "Only regular files within the configured root can be inspected")
        descriptor = None
        try:
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != identity or root.resolve(strict=True) != root:
                raise GuardError("ROOT_CHANGED", "The configured root changed; restart with explicitly verified roots")
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            with os.fdopen(os.open(parts[-1], flags, dir_fd=descriptor), "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) in self._private_ids():
                    raise GuardError("PATH_DENIED", "Special files and protected application data cannot be inspected")
                if before.st_size > MAX_SCAN_BYTES:
                    raise GuardError("FILE_TOO_LARGE", "File exceeds the 10 MiB scan limit")
                data = stream.read(MAX_SCAN_BYTES + 1)
                after = os.fstat(stream.fileno())
            with os.fdopen(os.open(parts[-1], flags, dir_fd=descriptor), "rb") as current:
                final = os.fstat(current.fileno())
            if len(data) > MAX_SCAN_BYTES or _identity(before) != _identity(after) or _identity(after) != _identity(final):
                raise GuardError("SOURCE_CHANGED", "The source changed during inspection; retry after it is stable")
            if path.resolve(strict=True) != path or (path.stat().st_dev, path.stat().st_ino) != (final.st_dev, final.st_ino):
                raise GuardError("SOURCE_CHANGED", "The source pathname changed during inspection")
            if self._token in data or re.search(br"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", data):
                raise GuardError("SENSITIVE_CONTENT", "Credential material cannot be returned through this reader")
            return data, _identity(final)
        except GuardError:
            raise
        except (OSError, ValueError, RuntimeError) as exc:
            raise GuardError("PATH_DENIED", "The source is unavailable, changed, or contains a symbolic link") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def call(self, name: str, arguments: dict) -> dict:
        if name not in {"scan_file", "read_file"}:
            raise GuardError("UNKNOWN_TOOL", "Only scan_file and read_file are available")
        if not isinstance(arguments, dict) or set(arguments) != {"path"} or not isinstance(arguments["path"], str):
            raise GuardError("INVALID_ARGUMENTS", "Exactly one string argument named path is required")
        now = time.monotonic()
        while self._calls and self._calls[0] < now - 60:
            self._calls.popleft()
        if len(self._calls) >= 60:
            raise GuardError("RATE_LIMIT", "At most 60 file tool calls per minute are permitted")
        self._calls.append(now)
        path = arguments["path"]
        data, identity = self.snapshot(path)
        if name == "read_file" and (Path(path).suffix.lower() not in READ_FORMATS or len(data) > MAX_READ_BYTES):
            raise GuardError("SCAN_ONLY", "Use scan_file for this format or size; read_file supports UTF-8 text up to 256 KiB")
        digest = hashlib.sha256(data).hexdigest()
        summary = verified_summary(self.scanner.scan(data, Path(path).name), digest, len(data))
        allowed = summary["verdict"] == "VALID" and summary["status"] == "ALLOWED" and summary["analysis_complete"]
        result = {"allowed": allowed, "report": summary}
        if name == "read_file" and allowed:
            try:
                content = data.decode("utf-8")
            except UnicodeError as exc:
                raise GuardError("TEXT_DECODING_FAILED", "This reader only delivers UTF-8 text") from exc
            if any(ord(character) < 32 and character not in "\t\r\n" for character in content):
                raise GuardError("BINARY_CONTENT", "Non-text control bytes cannot be delivered")
            current, current_identity = self.snapshot(path)
            if current_identity != identity or hashlib.sha256(current).hexdigest() != digest:
                raise GuardError("SOURCE_CHANGED", "The source changed after scanning; no file content was delivered")
            result["text"] = content
        return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, separators=(",", ":"))}],
                "structuredContent": result, "isError": not allowed}


TOOL_SCHEMA = {"type": "object", "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 4096,
                "description": "Absolute Linux path inside an explicitly configured root"}},
               "required": ["path"], "additionalProperties": False}
TOOLS = [{"name": "scan_file", "description": "Scan exact file bytes and return a source-free security report; protected paths and symlinks are denied.",
          "inputSchema": TOOL_SCHEMA, "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}},
         {"name": "read_file", "description": "Return UTF-8 file content only after a fresh exact-byte scan is VALID and ALLOWED. Maximum 256 KiB; PDF/DOCX are scan-only.",
          "inputSchema": TOOL_SCHEMA, "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}}]


class StdioServer:
    def __init__(self, reader: GuardedReader):
        self.reader = reader
        self.state = "NEW"
        self.seen = set()
        self.closed = False

    def handle(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str) or set(message) - {"jsonrpc", "id", "method", "params"}:
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid JSON-RPC request"}}
        method = message["method"]
        params = message.get("params", {})
        if "id" not in message:
            if method == "notifications/initialized" and self.state == "INITIALIZING" and isinstance(params, dict) and not set(params) - {"_meta"}:
                self.state = "READY"
            return None
        request_id = message["id"]
        if not ((isinstance(request_id, str) and 0 < len(request_id) <= 128) or (type(request_id) is int and abs(request_id) <= 2**53 - 1)):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request identifier"}}
        response = {"jsonrpc": "2.0", "id": request_id}
        try:
            key = (type(request_id).__name__, request_id)
            if key in self.seen:
                raise RpcError(-32600, "Request identifiers must be unique within the session")
            self.seen.add(key)
            if len(self.seen) > MAX_REQUESTS:
                self.closed = True
                raise RpcError(-32000, "Session request limit reached; reconnect")
            if not isinstance(params, dict):
                raise RpcError(-32602, "params must be an object")
            if method == "ping":
                if set(params) - {"_meta"}:
                    raise RpcError(-32602, "ping does not accept arguments")
                result = {}
            elif method == "initialize":
                if self.state != "NEW":
                    raise RpcError(-32600, "The session is already initialized")
                if set(params) - {"protocolVersion", "capabilities", "clientInfo", "_meta"} or not isinstance(params.get("protocolVersion"), str) or not 1 <= len(params["protocolVersion"]) <= 40 or not isinstance(params.get("capabilities"), dict):
                    raise RpcError(-32602, "Invalid initialization parameters")
                client = params.get("clientInfo")
                if not isinstance(client, dict) or any(not isinstance(client.get(key), str) or not 1 <= len(client[key]) <= 200 for key in ("name", "version")):
                    raise RpcError(-32602, "Client name and version are required")
                self.state = "INITIALIZING"
                result = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "mcp-integrity-guard-reader", "version": __version__},
                          "instructions": "Only explicitly configured roots are readable. Denied reports contain no source text."}
            elif self.state != "READY":
                raise RpcError(-32002, "Initialize the session and send notifications/initialized first")
            elif method == "tools/list":
                if set(params) - {"_meta"}:
                    raise RpcError(-32602, "This fixed tool list has no pagination cursor")
                result = {"tools": TOOLS}
            elif method == "tools/call":
                if set(params) - {"name", "arguments", "_meta"} or not isinstance(params.get("name"), str) or params["name"] not in {"scan_file", "read_file"}:
                    raise RpcError(-32602, "Unknown tool or malformed tool request")
                try:
                    result = self.reader.call(params["name"], params.get("arguments", {}))
                except GuardError as exc:
                    payload = {"allowed": False, "error": {"code": exc.code, "message": str(exc)}}
                    result = {"content": [{"type": "text", "text": json.dumps(payload)}], "structuredContent": payload, "isError": True}
            else:
                raise RpcError(-32601, "Method not found")
            response["result"] = result
        except RpcError as exc:
            response["error"] = {"code": exc.code, "message": str(exc)}
        except Exception:
            response["error"] = {"code": -32603, "message": "Internal error; no file content was delivered"}
        return response

    def run(self, source, destination):
        while not self.closed:
            line = source.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_MESSAGE_BYTES:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Message exceeds 64 KiB limit"}}
                self.closed = True
            else:
                try:
                    message = strict_json(line)
                    response = self.handle(message)
                except (ValueError, UnicodeError, RecursionError):
                    response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON"}}
            if response is not None:
                destination.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
                destination.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description="MCP Integrity Guard: Linux stdio file reader")
    parser.add_argument("--root", type=Path, action="append", required=True, help="Explicit allowed directory; repeat for multiple roots")
    parser.add_argument("--data-dir", type=Path, required=True, help="Existing application data directory containing api-token")
    parser.add_argument("--api-url", default="http://127.0.0.1:8765", help="Literal HTTP loopback admin API URL")
    args = parser.parse_args(argv)
    try:
        reader = GuardedReader(args.root, args.data_dir, args.api_url)
        StdioServer(reader).run(sys.stdin.buffer, sys.stdout.buffer)
        return 0
    except BrokenPipeError:
        return 0
    except (OSError, ValueError, RuntimeError):
        print("MCP Integrity Guard could not initialize. Check explicit roots, Linux support and the running application's data directory.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
