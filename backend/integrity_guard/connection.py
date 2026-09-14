"""One proven TCP connection per local operation; no proxies or redirects.

Only an initially refused connection means the application is absent. A listener
that fails authentication is an error, never permission to use an offline store.
This boundary cannot defend against an administrator who can read the token.
"""
from __future__ import annotations

import errno
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import stat
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class TransportError(RuntimeError):
    """A source-free and credential-free message safe for CLI stderr."""


def proof(token: str, nonce: str, host: str, port: int) -> str:
    """Bind a fresh challenge to the real listening endpoint, never a Host header.

Endpoint binding prevents relaying a proof from another local port/address in
the same network namespace. It is not TLS or protection from network-namespace
forwarders. Version 1 proofs, lacking the endpoint, are intentionally rejected.
"""
    address = ipaddress.ip_address(host).compressed
    if (address not in {"127.0.0.1", "::1"} or type(port) is not int or not 1 <= port <= 65535 or
            not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{64}", nonce)):
        raise ValueError("Invalid listener proof endpoint or nonce")
    message = ("mcp-integrity-guard-health-v2\0" + address + "\0" + str(port) + "\0" + nonce).encode("ascii")
    return hmac.new(token.encode("ascii"), message, hashlib.sha256).hexdigest()


def loopback_address(url: str) -> tuple[str, int]:
    try:
        if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) >= 127 for c in url):
            raise ValueError
        parsed = urlsplit(url)
        port = parsed.port if parsed.port is not None else 80
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or
                parsed.username is not None or parsed.password is not None or parsed.path not in {"", "/"} or
                parsed.query or parsed.fragment or not 1 <= port <= 65535):
            raise ValueError
        return parsed.hostname, port
    except (ValueError, TypeError, AttributeError) as exc:
        raise TransportError("--api-url deve essere un indirizzo HTTP loopback letterale, senza credenziali o percorso") from exc


def read_token(path: Path) -> str | None:
    """Read one bounded regular token file without following its final symlink."""
    try:
        if path.is_symlink():
            raise TransportError("File del token locale non valido")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TransportError("Impossibile leggere il token locale") from exc
    try:
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise TransportError("File del token locale non valido")
            raw = stream.read(258)
        if len(raw) > 257:
            raise ValueError
        token = raw.decode("ascii").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token):
            raise ValueError
        return token
    except (ValueError, OSError) as exc:
        raise TransportError("File del token locale non valido") from exc


def _strict_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("Non-finite JSON value")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
        count = 0
        def visit(item, depth=0):
            nonlocal count
            count += 1
            if depth > 64 or count > 100_000:
                raise ValueError("JSON structural limit")
            if isinstance(item, str):
                item.encode("utf-8")
            elif isinstance(item, float) and not math.isfinite(item):
                raise ValueError("Non-finite JSON number")
            elif isinstance(item, dict):
                for key, child in item.items():
                    key.encode("utf-8")
                    visit(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    visit(child, depth + 1)
        visit(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise TransportError("Risposta JSON del servizio locale non verificabile") from exc


def multipart_snapshot(data: bytes, filename: str) -> tuple[bytes, str]:
    """Build a single part with an ASCII basename; input bytes are unmodified."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename.replace("\\", "/")).name)
    if len(safe) > 180:
        safe = safe[:150] + Path(safe).suffix[:20]
    safe = safe or "file.bin"
    boundary = "mcpguard-" + secrets.token_hex(24)
    prefix = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe}\"\r\n"
              "Content-Type: application/octet-stream\r\n\r\n").encode("ascii")
    return prefix + data + f"\r\n--{boundary}--\r\n".encode("ascii"), "multipart/form-data; boundary=" + boundary


class VerifiedConnection:
    """Prove the listener, then make one authenticated request on that socket.

Responses require a single Content-Length and application/json content type.
Ambiguous framing is rejected. A wall-clock watchdog bounds slow headers/body.
"""
    def __init__(self, url: str, token: str, timeout: float = 30.0):
        host, port = loopback_address(url)
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token):
            raise TransportError("Token locale non valido")
        if not math.isfinite(timeout) or not 0 < timeout <= 120:
            raise ValueError("Invalid transport timeout")
        self._token = token
        self._host, self._port = host, port
        self._http = http.client.HTTPConnection(host, port, timeout=timeout)
        self._timeout = timeout
        self._socket = None
        self._timer = None
        self._deadline = 0.0
        self._used = False
        self._expired = threading.Event()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _abort(self):
        self._expired.set()
        sock = self._socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _remaining(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0 or self._expired.is_set():
            raise TransportError("Tempo limite del servizio locale superato")
        if self._socket is not None:
            self._socket.settimeout(remaining)

    def _read(self, response, limit):
        if response.status != 200:
            raise TransportError(f"Il servizio locale ha rifiutato la richiesta (HTTP {response.status})")
        lengths = response.headers.get_all("Content-Length", [])
        types = response.headers.get_all("Content-Type", [])
        if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]) or
                response.headers.get_all("Transfer-Encoding") or len(types) != 1 or
                types[0].split(";", 1)[0].strip().lower() != "application/json" or
                response.headers.get("Content-Encoding", "identity").lower() != "identity"):
            raise TransportError("Formato HTTP del servizio locale non verificabile")
        size = int(lengths[0])
        if size > limit:
            raise TransportError("Risposta del servizio locale troppo grande")
        result = bytearray()
        while len(result) < size:
            self._remaining()
            chunk = response.read1(min(65536, size - len(result)))
            if not chunk:
                raise TransportError("Risposta del servizio locale incompleta")
            result.extend(chunk)
        self._remaining()
        return _strict_json(bytes(result))

    def connect(self) -> bool:
        """Return False only when the initial local TCP connection was refused."""
        if self._socket is not None or self._used:
            raise TransportError("Connessione locale già utilizzata")
        try:
            self._http.connect()
        except OSError as exc:
            self.close()
            if isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED:
                return False
            raise TransportError("Connessione al servizio locale non disponibile") from exc
        self._socket = self._http.sock
        self._http.auto_open = 0  # send() must never reconnect after authentication.
        self._deadline = time.monotonic() + self._timeout
        self._timer = threading.Timer(self._timeout, self._abort)
        self._timer.daemon = True
        self._timer.start()
        try:
            nonce = secrets.token_hex(32)
            self._http.request("GET", "/api/health?nonce=" + nonce, headers={"Accept": "application/json"})
            response = self._http.getresponse()
            health = self._read(response, 4096)
            received = health.get("proof") if isinstance(health, dict) else None
            if (not isinstance(received, str) or not re.fullmatch(r"[a-f0-9]{64}", received) or
                    not hmac.compare_digest(received, proof(self._token, nonce, self._host, self._port))):
                raise TransportError("Identità del servizio locale non verificata; token non inviato")
            if self._http.sock is not self._socket or response.will_close:
                raise TransportError("La connessione verificata è stata chiusa; token non inviato")
            return True
        except TransportError:
            self.close()
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            self.close()
            raise TransportError("Identità del servizio locale non verificata; token non inviato") from exc

    def request(self, method: str, route: str, payload: bytes | None = None,
                content_type: str = "application/json"):
        if (method not in {"GET", "POST"} or not re.fullmatch(r"/api/[a-z0-9/-]+", route) or
                any(c in content_type for c in "\r\n") or self._socket is None or
                self._http.sock is not self._socket or self._used):
            raise TransportError("Richiesta locale non valida o connessione non verificata")
        self._used = True
        try:
            self._remaining()
            self._http.request(method, route, body=payload, headers={"Authorization": "Bearer " + self._token,
                               "Accept": "application/json", "Content-Type": content_type})
            return self._read(self._http.getresponse(), MAX_RESPONSE_BYTES)
        except TransportError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise TransportError("Richiesta al servizio locale interrotta o non verificabile") from exc
        finally:
            self.close()

    def close(self):
        if self._timer is not None:
            self._timer.cancel()
        self._http.close()
        self._socket = None


def verify_listener(url: str, token: str, timeout: float = 1.0) -> bool:
    """Probe for browser readiness only; it cannot authorize a different socket."""
    with VerifiedConnection(url, token, timeout) as connection:
        return connection.connect()
