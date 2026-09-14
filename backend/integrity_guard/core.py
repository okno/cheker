"""Persistent, content-bound MCP approvals and an explicit pre-use integration gate.

The gate reads a stable file snapshot at decision time. It does not execute commands,
intercept another process, lock a file across external use, or attest to an executable's
bytes: consumers must bind the returned hashes/version to the exact content they use.
Local administrators with the signing key can forge trust; protect the application
account, data directory and backups. Audit signatures plus an external signed head
checkpoint detect edits/truncation while that checkpoint and key remain trustworthy.
A crash between the SQLite commit and checkpoint write fails closed until investigated.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import MAX_CONFIG_BYTES, canonical_bytes, parse_config, redact, semantic_diff, sha256


class ConflictError(ValueError):
    """Requested content/version is stale, or persisted trust evidence is invalid."""


@dataclass(frozen=True)
class _AuditEvidence:
    changes: int
    data_version: int
    schema_version: int
    temp_schema_version: int
    database: tuple
    wal: tuple | None
    checkpoint: bytes
    key: bytes


DEFAULT_POLICY = {"version": 1, "format_only_action": "REQUIRE_REAPPROVAL",
                  "semantic_change_action": "REQUIRE_REAPPROVAL", "security_change_action": "BLOCK",
                  "unapproved_action": "BLOCK", "scan_block_score": 80,
                  "scan_quarantine_score": 60, "scan_flag_score": 25}
ACTIONS = {"ALLOW", "WARN", "REQUIRE_REAPPROVAL", "QUARANTINE", "BLOCK"}
LIFECYCLE = ("DISCOVERED", "VERSION_CHANGED", "SOURCE_UNAVAILABLE", "APPROVED", "REVOKED", "QUARANTINED")
# Caps include the root config and inherited server/global metadata. A compact
# source may otherwise fan out into gigabytes of hashes, analysis and snapshots.
MAX_DISCOVERY_COMPONENTS = 256
MAX_EXPANDED_CANONICAL_BYTES = 8 * 1024 * 1024
MAX_COMPONENT_IDENTITY_BYTES = 4096
MAX_DISCOVERY_SECONDS = 10.0
COLLECTION_KINDS = {"tools": "tool", "resources": "resource", "prompts": "prompt"}


class _DiscoveryBudget:
    def __init__(self):
        self.deadline = time.perf_counter() + MAX_DISCOVERY_SECONDS
        self._scanner = None

    def remaining(self) -> float:
        value = self.deadline - time.perf_counter()
        if value <= 0:
            raise ValueError("Configuration exceeds discovery time limit")
        return value

    def analyze(self, text: str, *, timeout: float) -> list[dict]:
        # Rule compilation is substantial; rebuilding it for every inherited
        # component can exhaust the budget on an ordinary catalog of 100 tools.
        if self._scanner is None:
            from .scanner import Scanner
            self._scanner = Scanner(max_input_size=16_000_000, timeout=min(3.0, self.remaining()))
        self._scanner.timeout = min(3.0, timeout, self.remaining())
        return self._scanner.scan_bytes(text.encode("utf-8"), "configuration.txt")["findings"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _source_snapshot(path: Path) -> bytes:
    """Reject non-regular/oversized files and detect concurrent writes using fstat/stat."""
    try:
        initial = path.stat()
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError("Configuration source is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Configuration source is not a regular file")
            if before.st_size > MAX_CONFIG_BYTES:
                raise ValueError("Configuration exceeds 4 MiB limit")
            data = stream.read(MAX_CONFIG_BYTES + 1)
            after = os.fstat(stream.fileno())
        # On Windows stat() and fstat() can expose different ctime/file-id
        # representations. Reopen the pathname and compare fstat to fstat so a
        # legitimate write is not mistaken for a concurrent source replacement.
        with os.fdopen(os.open(path, flags), "rb") as current_stream:
            current = os.fstat(current_stream.fileno())
    except (OSError, RuntimeError) as exc:
        raise ValueError("Configuration source is unavailable") from exc
    identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if len(data) > MAX_CONFIG_BYTES:
        raise ValueError("Configuration exceeds 4 MiB limit")
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise ConflictError("Configuration changed while being read; retry")
    return data


def _standalone_kind(document: dict) -> str | None:
    return "tool" if "inputSchema" in document else "resource" if "uri" in document else "prompt" if "messages" in document else None


def _component_display(locator: list[str], content: Any, source: str) -> tuple[str, str]:
    """Derive display identity identically for discovery and verified snapshots."""
    if not isinstance(locator, list) or not all(isinstance(part, str) for part in locator):
        raise ValueError("Invalid component locator")
    if locator == ["config"]:
        return Path(source).name, "config"
    if len(locator) == 2 and locator[0] in {"mcpServers", "servers"}:
        return locator[1], "server"
    if (len(locator) == 2 or len(locator) == 4 and locator[0] in {"mcpServers", "servers"}) and locator[-2] in COLLECTION_KINDS:
        return str(content["definition"].get("name") or locator[-1]), COLLECTION_KINDS[locator[-2]]
    if len(locator) == 2 and locator[0] in COLLECTION_KINDS.values():
        definition = content["definition"]
        kind = _standalone_kind(definition)
        if kind != locator[0]:
            raise ValueError("Invalid standalone component kind")
        return str(definition.get("name") or definition.get("uri") or Path(source).stem), kind
    raise ValueError("Unknown component locator")


def _components(document: Any, source: str) -> list[dict]:
    """Discover common MCP config and exported list formats without contacting servers.

All root fields are bound by the config component. Child definitions inherit root
metadata and the containing server's connection metadata; a raw-source version also
invalidates children on any other observed source edit. Named identities are stable
across object ordering. Duplicate identities are rejected, never silently overwritten.
"""
    result: list[dict] = []
    seen: set[str] = set()

    def add(locator: list[str], content: Any) -> None:
        name, kind = _component_display(locator, content, source)
        if len(result) >= MAX_DISCOVERY_COMPONENTS:
            raise ValueError("Configuration exceeds component count limit")
        if len(canonical_bytes({"name": name, "locator": locator})) > MAX_COMPONENT_IDENTITY_BYTES:
            raise ValueError("Configuration component identity exceeds size limit")
        marker = _json(locator)
        if marker in seen:
            raise ValueError("Duplicate MCP component identity")
        seen.add(marker)
        component_id = sha256(canonical_bytes({"source": source, "locator": locator}))
        result.append({"id": component_id, "name": name, "kind": kind, "locator": locator, "content": content})

    add(["config"], document)
    if isinstance(document, list):
        document = {"tools": document}
    if not isinstance(document, dict):
        return result
    collections = set(COLLECTION_KINDS)
    global_meta = {k: v for k, v in document.items() if k not in collections | {"mcpServers", "servers"}}

    def children(container: dict, prefix: list[str], connection: dict | None) -> None:
        for plural in COLLECTION_KINDS:
            values = container.get(plural)
            if values is None:
                continue
            if isinstance(values, dict):
                entries = [(str(key), value) for key, value in values.items()]
            elif isinstance(values, list):
                entries = []
                for index, value in enumerate(values):
                    if not isinstance(value, dict):
                        raise ValueError(f"MCP {plural} entries must be objects")
                    identity = value.get("name") or value.get("uri") or value.get("id")
                    if identity is None:
                        # A positional identity is explicit for unnamed definitions.
                        identity = f"index:{index}"
                    entries.append((str(identity), value))
            else:
                raise ValueError(f"MCP {plural} must be a list or object")
            for identity, value in entries:
                if not isinstance(value, dict):
                    raise ValueError(f"MCP {plural} entries must be objects")
                content = {"definition": value, "configuration": global_meta}
                if connection is not None:
                    content["server"] = connection
                add(prefix + [plural, identity], content)

    children(document, [], None)
    for field in ("mcpServers", "servers"):
        servers = document.get(field)
        if servers is None:
            continue
        if isinstance(servers, dict):
            entries = list(servers.items())
        elif isinstance(servers, list):
            entries = []
            for item in servers:
                if not isinstance(item, dict) or not (item.get("name") or item.get("id")):
                    raise ValueError("MCP server list entries need a name or id")
                entries.append((str(item.get("name") or item["id"]), item))
        else:
            raise ValueError("MCP servers must be an object or list")
        for name, server in entries:
            if not isinstance(server, dict):
                raise ValueError("MCP server definition must be an object")
            prefix = [field, str(name)]
            connection = {k: v for k, v in server.items() if k not in collections}
            add(prefix, {"definition": server, "configuration": global_meta})
            children(server, prefix, connection)
    # Standalone exported definitions (inputSchema, messages, or uri).
    if not any(key in document for key in collections | {"mcpServers", "servers"}):
        kind = _standalone_kind(document)
        if kind:
            name = str(document.get("name") or document.get("uri") or Path(source).stem)
            add([kind, name], {"definition": document})
    return result


def _remote_shell_argument(text: str) -> bool:
    """Equivalent ordered indicators without quadratic greedy backtracking."""
    for line in text.split("\n"):
        command = re.search(r"(?:^|[;&|\s])(?:curl|wget)\b", line)
        if command:
            pipe = line.find("|", command.end())
            if pipe >= 0 and line.find("sh", pipe + 1) >= 0:
                return True
    return False


def config_findings(content: Any, *, canonical: bytes | None = None, timeout: float = 3.0,
                    analyze=None) -> list[dict]:
    """Explain observed risk indicators, without asserting that a command is malware."""
    findings: list[dict] = []
    deadline = time.perf_counter() + timeout

    def remaining():
        value = deadline - time.perf_counter()
        if value <= 0:
            raise ValueError("Configuration exceeds analysis time limit")
        return value

    def emit(rule: str, title: str, severity: str, path: str, evidence: str) -> None:
        if len(findings) < 128:
            findings.append({"rule_id": rule, "title": title, "severity": severity, "category": "CONFIGURATION_RISK",
                             "evidence": evidence, "location": path, "layer": "STATIC_CONFIG"})

    def walk(value: Any, path: str = "") -> None:
        remaining()
        if len(path) > 4096:
            raise ValueError("Configuration exceeds analysis path limit")
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else key
                lower = key.lower()
                if lower in {"command", "executable"} and isinstance(child, str):
                    executable = re.split(r"[/\\]", child)[-1].lower()
                    if executable in {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
                        emit("CFG-SHELL", "Server launches a command shell", "HIGH", child_path, "Shell execution increases command injection and capability risk.")
                if lower in {"url", "endpoint", "uri"} and isinstance(child, str) and child.lower().startswith("http://"):
                    emit("CFG-HTTP", "Unencrypted HTTP endpoint", "HIGH", child_path, "The configured HTTP transport provides no TLS protection.")
                if lower in {"image", "containerimage"} and isinstance(child, str) and "@sha256:" not in child:
                    emit("CFG-IMAGE", "Container image is not pinned to a digest", "MEDIUM", child_path, "A tag can resolve to different executable content without a configuration edit.")
                if lower in {"env", "environment", "headers", "auth", "authentication"} and isinstance(child, dict) and child:
                    emit("CFG-CREDENTIALS", "Sensitive configuration values are stored inline", "MEDIUM", child_path, "Values are hashed and masked in API output; source files and local snapshots remain sensitive.")
                if lower in {"allowed_paths", "allowedpaths", "paths", "roots", "mounts", "volumes"}:
                    items = child if isinstance(child, list) else [child]
                    if any(isinstance(item, str) and (item in {"/", "*", "**"} or re.fullmatch(r"[A-Za-z]:[/\\]?", item) or item.startswith("/:")) for item in items):
                        emit("CFG-ROOTFS", "Broad filesystem access", "HIGH", child_path, "The configured path includes a filesystem root or unrestricted wildcard.")
                if lower in {"privileged", "hostnetwork"} and child is True:
                    emit("CFG-PRIVILEGED", "Elevated container capabilities", "CRITICAL", child_path, "The configuration enables privileged execution or host networking.")
                if lower in {"args", "arguments"} and isinstance(child, list):
                    if "--privileged" in child or "--network=host" in child:
                        emit("CFG-PRIVILEGED", "Elevated container arguments", "CRITICAL", child_path, "Command arguments request privileged execution or host networking.")
                    if any(isinstance(item, str) and _remote_shell_argument(item) for item in child):
                        emit("CFG-REMOTE-SHELL", "Remote content piped to a shell", "CRITICAL", child_path, "An argument appears to download content and execute it through a shell.")
                walk(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    walk(content)
    from .scanner import analyze_text
    # Scan descriptions, schemas and metadata as data. Evidence is deliberately
    # replaced: arbitrary credentials embedded inside a matched snippet cannot be
    # reliably masked through field-name redaction after JSON is flattened.
    text = (canonical if canonical is not None else canonical_bytes(content)).decode("utf-8")
    if len(text) > 4_000_000:
        raise ValueError("Configuration exceeds text analysis size limit")
    analyzed = (analyze or analyze_text)(text, timeout=min(3.0, remaining()))
    remaining()
    if any(finding.get("category") == "ANALYSIS_FAILURE" for finding in analyzed):
        raise ValueError("Configuration analysis did not complete within inspection limits")
    for finding in analyzed:
        findings.append({**finding, "evidence": "Scanner matched this rule in configuration content; inspect the redacted definition.",
                         "location": "configuration", "layer": "CONFIG_" + finding.get("layer", "TEXT_ANALYSIS")})
        if len(findings) >= 256:
            break
    return findings


class GuardStore:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.data_dir.chmod(0o700)
        except OSError:
            pass
        self._process_lock = None
        self._closed = False
        lock_stream = (self.data_dir / ".store.lock").open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                if lock_stream.seek(0, os.SEEK_END) == 0:
                    lock_stream.write(b"0")
                    lock_stream.flush()
                lock_stream.seek(0)
                msvcrt.locking(lock_stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._process_lock = lock_stream
        except OSError as exc:
            lock_stream.close()
            raise ConflictError("Trust database is already open in another instance; use the running application API") from exc
        self.lock = threading.RLock()
        self._lock = self.lock
        self._audit_batch = False
        self._pending_audit_head = None
        self._audit_cache = None
        self.db_path = self.data_dir / "integrity.sqlite3"
        self._checkpoint_path = self.data_dir / "audit-head.json"
        key_path = self.data_dir / "approval-key.pem"
        if not key_path.exists():
            if self.db_path.exists():
                raise ConflictError("Signing key missing for existing trust database")
            key = Ed25519PrivateKey.generate()
            encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
            descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        try:
            self._key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            if not isinstance(self._key, Ed25519PrivateKey):
                raise ValueError("Wrong signing key type")
        except Exception as exc:
            raise ConflictError("Signing key cannot be loaded") from exc
        self.public_key = base64.b64encode(self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        self._db = sqlite3.connect(self.db_path, check_same_thread=False, timeout=20)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS components (id TEXT PRIMARY KEY, source_path TEXT NOT NULL, locator TEXT NOT NULL, record TEXT NOT NULL, content TEXT NOT NULL, source_valid INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS versions (component_id TEXT NOT NULL, version INTEGER NOT NULL, record TEXT NOT NULL, content TEXT NOT NULL, PRIMARY KEY(component_id,version));
            CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, component_id TEXT NOT NULL, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        self._db.commit()
        self._database_identity = self._audit_file_identity(self.db_path)[:2]
        if not self._db.execute("SELECT 1 FROM settings WHERE key='policy'").fetchone():
            if self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]:
                raise ConflictError("Policy missing for existing trust database")
            self._save_policy(DEFAULT_POLICY)
            self._db.commit()
        if not self._checkpoint_path.exists() and not self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]:
            self._write_checkpoint(0, "0" * 64)

    def close(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        try:
            if hasattr(self, "_db"):
                with self.lock:
                    self._audit_cache = None
                    self._db.close()
        finally:
            stream = getattr(self, "_process_lock", None)
            if stream is not None:
                try:
                    if os.name == "nt":
                        import msvcrt
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                finally:
                    stream.close()
                    self._process_lock = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _sign(self, value: Any) -> str:
        return base64.b64encode(self._key.sign(canonical_bytes(value))).decode("ascii")

    def _check_signature(self, value: Any, signature: str) -> bool:
        try:
            self._key.public_key().verify(base64.b64decode(signature, validate=True), canonical_bytes(value))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    def _write_checkpoint(self, sequence: int, head_hash: str) -> bytes:
        payload = {"sequence": sequence, "head_hash": head_hash}
        document = {**payload, "signature": self._sign(payload)}
        encoded = _json(document).encode("utf-8")
        temporary = self.data_dir / f".audit-head-{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._checkpoint_path)
        finally:
            temporary.unlink(missing_ok=True)
        return encoded

    @staticmethod
    def _audit_file_identity(path: Path, *, optional: bool = False) -> tuple | None:
        try:
            value = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            if optional:
                return None
            raise
        if not stat.S_ISREG(value.st_mode):
            raise ValueError("Audit evidence is not a regular file")
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                value.st_ctime_ns, value.st_mode)

    def _checkpoint_bytes(self) -> bytes:
        if self._checkpoint_path.is_symlink():
            raise ValueError("Audit checkpoint cannot be a symbolic link")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(self._checkpoint_path, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > 4096:
                raise ValueError("Audit checkpoint is invalid or exceeds 4 KiB")
            encoded = stream.read(4097)
            after = os.fstat(stream.fileno())
        # Compare handles from the same API: Windows stat and fstat can expose
        # different file-id/ctime representations for the same regular file.
        with os.fdopen(os.open(self._checkpoint_path, flags), "rb") as current_stream:
            current = os.fstat(current_stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                                  value.st_ctime_ns, stat.S_IFMT(value.st_mode))
        if (len(encoded) > 4096 or self._checkpoint_path.is_symlink()
                or identity(before) != identity(after) or identity(after) != identity(current)):
            raise ValueError("Audit checkpoint changed while being read")
        return encoded

    def _audit_evidence(self) -> _AuditEvidence:
        """A cache guard, not proof of integrity by itself; never rely on mtime alone."""
        changes = self._db.total_changes
        version = self._db.execute("PRAGMA data_version").fetchone()[0]
        # Schema versions can be manually reset through PRAGMA. Check the
        # actual schema on every hit, including temporary shadows/triggers.
        self._assert_audit_schema()
        database = self._audit_file_identity(self.db_path)
        if database[:2] != self._database_identity:
            raise ValueError("Trust database file was replaced while open")
        evidence = _AuditEvidence(
            changes, version, self._db.execute("PRAGMA main.schema_version").fetchone()[0],
            self._db.execute("PRAGMA temp.schema_version").fetchone()[0], database,
            self._audit_file_identity(Path(str(self.db_path) + "-wal"), optional=True),
            self._checkpoint_bytes(),
            self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        )
        if changes != self._db.total_changes or version != self._db.execute("PRAGMA data_version").fetchone()[0]:
            raise ValueError("Audit database changed while evidence was read")
        return evidence

    def _assert_audit_schema(self) -> None:
        # Prefix advancement assumes INSERT appends one row to this real table.
        # Views, virtual tables, temporary shadows and triggers break that
        # assumption even if SQLite reports exactly one affected row.
        # Match SQLite's ASCII case-insensitive identifier resolution, including
        # temporary objects whose spelling differs from the main table name.
        row = self._db.execute("SELECT type,sql FROM main.sqlite_master WHERE name COLLATE NOCASE='audit'").fetchone()
        shadow = self._db.execute("SELECT 1 FROM temp.sqlite_master WHERE name COLLATE NOCASE='audit'").fetchone()
        triggers = self._db.execute("SELECT 1 FROM main.sqlite_master WHERE type='trigger' AND tbl_name COLLATE NOCASE='audit' UNION ALL SELECT 1 FROM temp.sqlite_master WHERE type='trigger' AND tbl_name COLLATE NOCASE='audit'").fetchone()
        columns = [tuple(row) for row in self._db.execute("PRAGMA main.table_xinfo('audit')")]
        expected = [(0, 'sequence', 'INTEGER', 0, None, 1, 0), (1, 'document', 'TEXT', 1, None, 0, 0)]
        if (row is None or row['type'] != 'table' or not row['sql'].lstrip().upper().startswith('CREATE TABLE')
                or shadow is not None or triggers is not None or columns != expected):
            raise ValueError("Audit table schema does not permit trusted append-only updates")

    def _verify_audit_full(self) -> tuple[dict, _AuditEvidence | None]:
        """Verify every event and ensure the surrounding evidence did not change."""
        previous = "0" * 64
        checked = 0
        self._audit_cache = None
        try:
            before = self._audit_evidence()
            for row in self._db.execute("SELECT sequence,document FROM audit ORDER BY sequence"):
                event = json.loads(row["document"])
                expected_sequence = checked + 1
                payload = {k: event[k] for k in ("sequence", "timestamp", "event_type", "component_id", "details", "previous_hash")}
                expected_hash = sha256(canonical_bytes(payload))
                if row["sequence"] != expected_sequence or event["sequence"] != expected_sequence:
                    raise ValueError("Audit sequence gap")
                if event["previous_hash"] != previous or event["hash"] != expected_hash:
                    raise ValueError("Audit hash chain mismatch")
                if not self._check_signature({"hash": expected_hash, "sequence": expected_sequence}, event["signature"]):
                    raise ValueError("Audit signature mismatch")
                previous = expected_hash
                checked += 1
            checkpoint = json.loads(before.checkpoint)
            payload = {"sequence": checkpoint["sequence"], "head_hash": checkpoint["head_hash"]}
            if not self._check_signature(payload, checkpoint["signature"]):
                raise ValueError("Audit checkpoint signature mismatch")
            if payload != {"sequence": checked, "head_hash": previous}:
                raise ValueError("Audit checkpoint mismatch or log truncation")
            if before != self._audit_evidence():
                raise ValueError("Audit evidence changed during verification")
            return {"valid": True, "checked": checked, "head_hash": previous}, before
        except (OSError, ValueError, KeyError, TypeError, RecursionError, sqlite3.Error) as exc:
            return {"valid": False, "checked": checked, "head_hash": previous, "error": str(exc)[:200]}, None

    def verify_audit(self, *, fast: bool = False) -> dict:
        """Explicit calls verify every event; fast calls may reuse unchanged proof.

        Cache hits require matching connection/external-write counters, DB/WAL
        identities and nanosecond metadata, actual bounded checkpoint bytes and
        the loaded verification key. Pending transactions never use this public
        cache path. Invalid results are never cached.
        """
        with self.lock:
            if fast and self._audit_cache is not None and not self._db.in_transaction:
                evidence, result = self._audit_cache
                try:
                    if evidence == self._audit_evidence():
                        return dict(result)
                except (OSError, ValueError, TypeError, sqlite3.Error):
                    pass
            result, evidence = self._verify_audit_full()
            if result["valid"] and evidence is not None and not self._db.in_transaction:
                self._audit_cache = (evidence, dict(result))
            return result

    def _assert_audit(self) -> None:
        if not self.verify_audit(fast=True)["valid"]:
            raise ConflictError("Audit integrity verification failed; trust operations are blocked")

    def _begin_verified_update(self) -> tuple[dict, _AuditEvidence]:
        """Pin SQLite's writer state before trusting a cached prefix for append."""
        fresh = not self._db.in_transaction
        if fresh:
            self._db.execute("BEGIN IMMEDIATE")
        evidence = self._audit_evidence()
        if fresh and self._audit_cache is not None and self._audit_cache[0] == evidence:
            return dict(self._audit_cache[1]), evidence
        result, evidence = self._verify_audit_full()
        if not result["valid"] or evidence is None:
            raise ConflictError("Audit integrity verification failed; trust operations are blocked")
        return result, evidence

    def append_audit(self, event_type: str, component_id: str | None, details: dict) -> dict:
        with self.lock:
            try:
                if self._audit_batch:
                    row = self._db.execute("SELECT sequence,document FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
                    sequence = row["sequence"] + 1 if row else 1
                    previous = json.loads(row["document"])["hash"] if row else "0" * 64
                else:
                    prefix, evidence = self._begin_verified_update()
                    sequence, previous = prefix["checked"] + 1, prefix["head_hash"]
                payload = {"sequence": sequence, "timestamp": _now(), "event_type": event_type,
                           "component_id": component_id, "details": redact(details), "previous_hash": previous}
                digest = sha256(canonical_bytes(payload))
                event = {**payload, "hash": digest, "signature": self._sign({"hash": digest, "sequence": sequence})}
                expected_changes = self._db.total_changes + 1
                self._db.execute("INSERT INTO audit(sequence,document) VALUES (?,?)", (sequence, _json(event)))
                if self._db.total_changes != expected_changes:
                    raise ConflictError("Unexpected database mutation during audit append")
                if self._audit_batch:
                    self._pending_audit_head = (sequence, digest)
                    return event
                self._audit_cache = None
                self._db.commit()
                committed = self._audit_evidence()
                encoded_checkpoint = self._write_checkpoint(sequence, digest)
                completed = self._audit_evidence()
                # A known insert may advance proof only after durable commit and
                # checkpoint success, with no intervening writes or key changes.
                if (completed.changes == expected_changes and completed.data_version == evidence.data_version
                        and committed.changes == completed.changes and committed.data_version == completed.data_version
                        and committed.schema_version == completed.schema_version == evidence.schema_version
                        and committed.temp_schema_version == completed.temp_schema_version == evidence.temp_schema_version
                        and committed.database == completed.database and committed.wal == completed.wal
                        and committed.key == completed.key == evidence.key
                        and committed.checkpoint == evidence.checkpoint
                        and completed.checkpoint == encoded_checkpoint):
                    result = {"valid": True, "checked": sequence, "head_hash": digest}
                    self._audit_cache = (completed, result)
                else:
                    self._assert_audit()
                return event
            except BaseException:
                self._audit_cache = None
                if not self._audit_batch:
                    self._db.rollback()
                raise

    @contextmanager
    def _atomic_updates(self):
        """Commit one discovery/revocation batch and then its signed checkpoint.

        The store lock excludes other writers. Failed analysis rolls back every
        component/version/audit row; only the separate source revocation commits.
        A crash after commit but before checkpoint still fails closed on reopen.
        """
        if self._audit_batch:
            raise RuntimeError("Nested trust database batches are unsupported")
        try:
            _, before = self._begin_verified_update()
            original_cache = self._audit_cache
            self._audit_batch = True
            self._pending_audit_head = None
            yield
            # Mixed batches may modify more than their new audit suffix. Keep
            # proof only for an unchanged refresh; changed batches are fully
            # verified on next use, rather than trusting arbitrary row updates.
            changed = self._db.total_changes != before.changes
            self._audit_cache = None
            self._db.commit()
            head = self._pending_audit_head
            if head is not None:
                self._write_checkpoint(*head)
            elif not changed and original_cache is not None and self._audit_evidence() == before:
                self._audit_cache = original_cache
        except BaseException:
            self._audit_cache = None
            self._db.rollback()
            raise
        finally:
            self._audit_batch = False
            self._pending_audit_head = None

    def audit_events(self, limit: int = 200) -> list[dict]:
        with self.lock:
            if limit < 1:
                return []
            return [json.loads(row[0]) for row in self._db.execute(
                "SELECT document FROM audit ORDER BY sequence DESC LIMIT ?", (min(limit, 100_000),))]

    def _save_policy(self, policy: dict) -> None:
        self._db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES ('policy',?)",
                         (_json({"policy": policy, "signature": self._sign(policy)}),))

    def get_policy(self) -> dict:
        with self.lock:
            try:
                value = json.loads(self._db.execute("SELECT value FROM settings WHERE key='policy'").fetchone()[0])
                if not self._check_signature(value["policy"], value["signature"]):
                    raise ValueError("signature")
                for row in self._db.execute("SELECT document FROM audit ORDER BY sequence DESC"):
                    event = json.loads(row[0])
                    if event["event_type"] == "POLICY_CHANGED":
                        if event["details"].get("policy") != value["policy"]:
                            raise ValueError("Policy does not match signed history")
                        return value["policy"]
                if value["policy"] != DEFAULT_POLICY:
                    raise ValueError("Policy history is missing")
                return value["policy"]
            except (TypeError, KeyError, ValueError) as exc:
                raise ConflictError("Policy integrity verification failed") from exc

    def set_policy(self, values: dict) -> dict:
        with self.lock:
            self._assert_audit()
            old = self.get_policy()
            if "version" in values and values["version"] != old["version"]:
                raise ConflictError("Policy changed; reload the current version before editing")
            unknown = set(values) - set(DEFAULT_POLICY)
            if unknown:
                raise ValueError("Unknown policy fields")
            policy = {**old, **values, "version": old["version"] + 1}
            for field in ("format_only_action", "semantic_change_action", "security_change_action", "unapproved_action"):
                if policy[field] not in ACTIONS:
                    raise ValueError("Invalid policy action")
            scores = [policy[k] for k in ("scan_flag_score", "scan_quarantine_score", "scan_block_score")]
            if any(type(score) is not int or not 0 <= score <= 100 for score in scores) or not scores[0] < scores[1] < scores[2]:
                raise ValueError("Scan thresholds must increase and be integers from 0 to 100")
            self._save_policy(policy)
            for row in self._db.execute("SELECT * FROM components").fetchall():
                record = json.loads(row["record"])
                if record["state"] == "APPROVED":
                    record.update(state="REAPPROVAL_REQUIRED", action="REQUIRE_REAPPROVAL", approved_at=None,
                                  approved_by=None, approval_id=None, updated_at=_now())
                    self._db.execute("UPDATE components SET record=? WHERE id=?", (_json(record), row["id"]))
            self.append_audit("POLICY_CHANGED", None, {"old_version": old["version"], "policy": policy})
            return policy

    def _row(self, component_id: str) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM components WHERE id=?", (component_id,)).fetchone()
        if row is None:
            raise KeyError(component_id)
        return row

    def _invalid_public(self, row: sqlite3.Row) -> dict:
        """A typed, read-only diagnostic view; never publish corrupt private content."""
        try:
            record = json.loads(row["record"])
            if not isinstance(record, dict):
                record = {}
        except (ValueError, TypeError, RecursionError):
            record = {}
        def diagnostic(key: str) -> str:
            value = record.get(key)
            return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else ""
        version = record.get("version")
        return {"id": row["id"] if isinstance(row["id"], str) else "", "name": "Unverified snapshot", "kind": "unknown",
                "source_path": row["source_path"] if isinstance(row["source_path"], str) else "",
                "state": "BLOCKED", "action": "BLOCK",
                "severity": "HIGH", "snapshot_valid": False, "source_valid": False,
                "source_error": "Stored snapshot integrity could not be verified",
                "version": version if type(version) is int and 0 < version <= 2**53 - 1 else 0,
                "raw_hash": diagnostic("raw_hash"), "canonical_hash": diagnostic("canonical_hash"),
                "semantic_fingerprint": diagnostic("semantic_fingerprint"),
                "approved_at": None, "approved_by": None, "approval_id": None,
                "previous_version": None, "updated_at": "", "changes": [], "content": None,
                "findings": [{"rule_id": "SNAPSHOT_INTEGRITY_FAILED", "title": "Stored snapshot integrity failed",
                              "severity": "HIGH", "category": "INTEGRITY", "layer": "CONTENT_TRUST",
                              "evidence": "The stored snapshot cannot establish a usable content version."}]}

    def _snapshot_anchors(self, component_ids: set[str]) -> dict[str, dict]:
        """Collect latest signed version anchors in one pass, bounded by requested IDs."""
        anchors = {}
        if component_ids:
            for row in self._db.execute("SELECT document FROM audit ORDER BY sequence DESC"):
                event = json.loads(row[0])
                component_id = event["component_id"]
                if component_id in component_ids and component_id not in anchors and event["event_type"] in {"DISCOVERED", "VERSION_CHANGED"}:
                    anchors[component_id] = event["details"]
                    if len(anchors) == len(component_ids):
                        break
        return anchors

    @staticmethod
    def _public_record(record: dict) -> dict:
        """Validate presentation types without treating display state as authorization."""
        strings = ("id", "name", "kind", "source_path", "state", "action", "severity", "raw_hash",
                   "canonical_hash", "semantic_fingerprint", "updated_at")
        nullable_strings = ("approved_at", "approved_by", "approval_id")
        if any(not isinstance(record[key], str) for key in strings):
            raise ValueError("Invalid public string field")
        if any(record[key] is not None and not isinstance(record[key], str) for key in nullable_strings):
            raise ValueError("Invalid public approval field")
        for key in ("version", "previous_version"):
            value = record[key]
            if key == "previous_version" and value is None:
                continue
            if type(value) is not int or not 0 < value <= 2**53 - 1:
                raise ValueError("Invalid public version")
        for key, fields, values in (("findings", ("rule_id", "title", "severity", "category", "layer"), ("evidence",)),
                                    ("changes", ("path", "severity", "category"), ("old", "new"))):
            if not isinstance(record[key], list):
                raise ValueError("Invalid public collection")
            for item in record[key]:
                if (not isinstance(item, dict) or any(not isinstance(item[field], str) for field in fields)
                        or any(field not in item for field in values)):
                    raise ValueError("Invalid public collection item")
                if key == "findings":
                    if "line" in item and item["line"] is not None and (type(item["line"]) is not int or not 0 <= item["line"] <= 2**53 - 1):
                        raise ValueError("Invalid public finding line")
                    if "encoding" in item and item["encoding"] is not None and not isinstance(item["encoding"], str):
                        raise ValueError("Invalid public finding encoding")
        public = {key: record[key] for key in strings + nullable_strings + ("version", "previous_version", "findings", "changes")}
        for key in ("source_error", "change_type"):
            if key in record:
                if not isinstance(record[key], str):
                    raise ValueError("Invalid public diagnostic field")
                public[key] = record[key]
        _json(public)  # Reject non-finite values even in arbitrary finding evidence.
        return public

    def _project_components(self, component_ids: list[str] | None = None) -> list[dict]:
        """Project persisted snapshots without reading sources, mutating trust or gating.

        Audit verification and anchor collection happen once per batch, followed by
        one canonicalization per row: O(audit events + snapshot bytes). Evidence is
        checked around the complete read, so a changing batch is never shown valid.
        snapshot_valid attests only to the persisted snapshot, not current source
        availability or authorization; the pre-use gate remains authoritative.
        """
        before = None
        try:
            before = self._audit_evidence()
            self._assert_audit()
        except (ValueError, OSError, TypeError, sqlite3.Error):
            before = None
        if component_ids is None:
            rows = self._db.execute("SELECT * FROM components ORDER BY source_path,id").fetchall()
        else:
            placeholders = ",".join("?" for _ in component_ids)
            found = {row["id"]: row for row in self._db.execute(
                f"SELECT * FROM components WHERE id IN ({placeholders})", component_ids)} if component_ids else {}
            rows = [found[component_id] for component_id in component_ids]
        if before is None:
            return [self._invalid_public(row) for row in rows]
        try:
            anchors = self._snapshot_anchors({row["id"] for row in rows})
            result = []
            for row in rows:
                try:
                    record, content = self._validate_snapshot(row, anchors=anchors)
                    record = self._public_record(record)
                    record.update(content=redact(content), source_valid=bool(row["source_valid"]), snapshot_valid=True)
                    result.append(record)
                except (ValueError, TypeError, KeyError, RecursionError):
                    result.append(self._invalid_public(row))
            if before != self._audit_evidence():
                raise ConflictError("Snapshot evidence changed during projection")
            return result
        except (ValueError, OSError, TypeError, KeyError, RecursionError, sqlite3.Error):
            return [self._invalid_public(row) for row in rows]

    def get_component(self, component_id: str) -> dict:
        with self.lock:
            return self._project_components([component_id])[0]

    def list_components(self) -> list[dict]:
        with self.lock:
            return self._project_components()

    def source_paths(self) -> list[str]:
        with self.lock:
            return [row[0] for row in self._db.execute("SELECT DISTINCT source_path FROM components ORDER BY source_path")]

    def _validate_snapshot(self, row: sqlite3.Row, *, anchors: dict[str, dict] | None = None) -> tuple[dict, Any]:
        """Bind row identity, private content and version metadata to signed history."""
        try:
            record = json.loads(row["record"])
            content = json.loads(row["content"])
            locator = json.loads(row["locator"])
            expected_id = sha256(canonical_bytes({"source": row["source_path"], "locator": locator}))
            if row["id"] != record["id"] or row["id"] != expected_id or record["source_path"] != row["source_path"]:
                raise ValueError("identity")
            canonical = canonical_bytes(content)
            if record["canonical_hash"] != sha256(canonical) or record["semantic_fingerprint"] != sha256(b"mcp-integrity-semantic-v1\0" + canonical):
                raise ValueError("fingerprint")
            if type(record["version"]) is not int or record["version"] < 1:
                raise ValueError("version")
            if (record["name"], record["kind"]) != _component_display(locator, content, row["source_path"]):
                raise ValueError("display identity")
            anchor = (self._snapshot_anchors({row["id"]}) if anchors is None else anchors)[row["id"]]
            if any(anchor.get(key) != record[key] for key in ("version", "raw_hash", "canonical_hash", "semantic_fingerprint")):
                raise ValueError("signed history")
            return record, content
        except (TypeError, ValueError, KeyError, AttributeError, RecursionError) as exc:
            raise ConflictError("Stored component identity or snapshot failed integrity verification") from exc

    def _persist(self, entry: dict, source: str, budget: _DiscoveryBudget, *, anchors: dict[str, dict] | None = None) -> None:
        component_id = entry["id"]
        previous = self._db.execute("SELECT * FROM components WHERE id=?", (component_id,)).fetchone()
        fingerprints = entry["fingerprints"]
        old = self._validate_snapshot(previous, anchors=anchors)[0] if previous else None
        if previous and previous["source_valid"] and all(old[k] == fingerprints[k] for k in fingerprints):
            if old["name"] != entry["name"] or old["kind"] != entry["kind"]:
                raise ConflictError("Stored component display identity failed integrity verification")
            # Detect snapshot corruption even before approval verification.
            if sha256(canonical_bytes(json.loads(previous["content"]))) != fingerprints["canonical_hash"]:
                raise ConflictError("Stored component snapshot failed integrity verification")
            return
        policy = self.get_policy()
        if old:
            changes = semantic_diff(json.loads(previous["content"]), entry["content"])
            if not changes:
                category = "FORMAT_ONLY_CHANGE" if previous["source_valid"] else "SOURCE_RESTORED"
                changes = [{"path": "$source", "old": old["raw_hash"], "new": fingerprints["raw_hash"],
                            "severity": "INFO" if previous["source_valid"] else "HIGH", "category": category}]
            security = any(change["category"] in {"SECURITY_RELEVANT_CHANGE", "SOURCE_RESTORED"} for change in changes)
            category = "SECURITY_RELEVANT_CHANGE" if security else "SEMANTIC_CHANGE" if old["canonical_hash"] != fingerprints["canonical_hash"] else "FORMAT_ONLY_CHANGE"
            action = policy["security_change_action" if security else "semantic_change_action" if category == "SEMANTIC_CHANGE" else "format_only_action"]
            state = "BLOCKED" if action == "BLOCK" else "QUARANTINED" if action == "QUARANTINE" else "REAPPROVAL_REQUIRED"
            if old["state"] in {"REVOKED", "QUARANTINED"}:
                state = old["state"]
                action = "QUARANTINE" if state == "QUARANTINED" else "BLOCK"
            severity = "HIGH" if security else "MEDIUM" if category == "SEMANTIC_CHANGE" else "INFO"
        else:
            changes, action, state, severity, category = [], policy["unapproved_action"], "PENDING_APPROVAL", "INFO", "DISCOVERED"
        now = _now()
        record = {"id": component_id, "name": entry["name"], "kind": entry["kind"], "source_path": source,
                  "state": state, "version": old["version"] + 1 if old else 1,
                  **fingerprints, "approved_at": None, "approved_by": None, "approval_id": None,
                  "previous_version": old["version"] if old else None, "action": action, "severity": severity,
                  "changes": changes, "findings": config_findings(entry["content"], canonical=entry["canonical"],
                                                                   timeout=budget.remaining(), analyze=budget.analyze),
                  "updated_at": now, "change_type": category}
        budget.remaining()
        if old and old["approval_id"]:
            record["findings"].append({"rule_id": "MCP-0042", "title": "Post-approval content mutation", "severity": "HIGH",
                                       "category": "INTEGRITY", "evidence": "Observed source content differs from the approved version.",
                                       "location": source, "layer": "CONTENT_TRUST"})
        if old and (entry["kind"] in {"server", "config"} or any(change["path"].startswith(("server", "configuration")) for change in changes)):
            record["findings"].append({"rule_id": "MCP-0052", "title": "Protected configuration changed", "severity": severity,
                                       "category": "CONFIG_WRITE", "evidence": "Configuration or inherited server metadata changed.",
                                       "location": source, "layer": "CONTENT_TRUST"})
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        record["severity"] = max([record["severity"]] + [finding["severity"] for finding in record["findings"]], key=lambda level: severity_rank.get(level, 4))
        self._db.execute("INSERT OR REPLACE INTO components(id,source_path,locator,record,content,source_valid) VALUES (?,?,?,?,?,1)",
                         (component_id, source, _json(entry["locator"]), _json(record), _json(entry["content"])))
        self._db.execute("INSERT INTO versions(component_id,version,record,content) VALUES (?,?,?,?)",
                         (component_id, record["version"], _json(record), _json(entry["content"])))
        self.append_audit("VERSION_CHANGED" if old else "DISCOVERED", component_id,
                          {"version": record["version"], **fingerprints, "change_type": category, "changes": changes,
                           "state": state, "source_path": source})

    def _unavailable(self, source: str, reason: str, keep_ids: set[str] | None = None) -> None:
        for row in self._db.execute("SELECT * FROM components WHERE source_path=?", (source,)).fetchall():
            if keep_ids is not None and row["id"] in keep_ids:
                continue
            if not row["source_valid"]:
                continue
            record = json.loads(row["record"])
            record.update(state="BLOCKED", action="BLOCK", severity="HIGH", approved_at=None, approved_by=None,
                          approval_id=None, updated_at=_now(), source_error=reason)
            record["findings"] = [{"rule_id": "SOURCE_UNAVAILABLE", "title": reason, "severity": "HIGH", "category": "INTEGRITY",
                                   "evidence": "The current source cannot establish a usable content version.", "location": source, "layer": "CONTENT_TRUST"}]
            self._db.execute("UPDATE components SET source_valid=0,record=? WHERE id=?", (_json(record), row["id"]))
            self.append_audit("SOURCE_UNAVAILABLE", row["id"], {"reason": reason, "version": record["version"]})

    def discover(self, path: Path) -> list[dict]:
        with self.lock:
            self._assert_audit()
            budget = _DiscoveryBudget()
            try:
                source = os.path.abspath(Path(path).expanduser())
                raw = _source_snapshot(Path(source))
                document = parse_config(raw, source, timeout=budget.remaining())
                entries = _components(document, source)
                expanded = 0
                raw_hash = sha256(raw)
                # Establish all fanout limits before running any risk analysis or
                # persisting a candidate. Reuse these bytes for hashes/analysis.
                for entry in entries:
                    budget.remaining()
                    canonical = canonical_bytes(entry["content"])
                    expanded += len(canonical) + len(canonical_bytes({"name": entry["name"], "locator": entry["locator"]}))
                    if len(canonical) > MAX_CONFIG_BYTES or expanded > MAX_EXPANDED_CANONICAL_BYTES:
                        raise ValueError("Configuration exceeds expanded canonical content limit")
                    entry["canonical"] = canonical
                    entry["fingerprints"] = {"raw_hash": raw_hash, "canonical_hash": sha256(canonical),
                                             "semantic_fingerprint": sha256(b"mcp-integrity-semantic-v1\0" + canonical)}
                with self._atomic_updates():
                    anchors = self._snapshot_anchors({entry["id"] for entry in entries})
                    for entry in entries:
                        budget.remaining()
                        self._persist(entry, source, budget, anchors=anchors)
                    self._unavailable(source, "Component is no longer present in its source", {entry["id"] for entry in entries})
                    budget.remaining()
            except ConflictError:
                raise
            except Exception as exc:
                if "source" in locals():
                    with self._atomic_updates():
                        self._unavailable(source, "Configuration is missing, invalid, or exceeds inspection limits")
                raise ValueError("Configuration is missing, invalid, or exceeds inspection limits") from exc
            return self._project_components([entry["id"] for entry in entries])

    def refresh(self, component_id: str) -> dict:
        with self.lock:
            source = self._row(component_id)["source_path"]
            try:
                observed = self.discover(Path(source))
                for component in observed:
                    if component["id"] == component_id:
                        return component
            except ValueError as exc:
                if isinstance(exc, ConflictError):
                    raise
                # Any failed reload must invalidate all trust in this source, even
                # if a trusted adapter or risk analyzer failed after parsing.
                self._unavailable(source, "Configuration could not be safely reloaded")
            return self.get_component(component_id)

    def _approval_valid(self, row: sqlite3.Row) -> bool:
        try:
            self._validate_snapshot(row)
            record = json.loads(row["record"])
            if not row["source_valid"] or record["state"] != "APPROVED" or not record["approval_id"]:
                return False
            approval_row = self._db.execute("SELECT document FROM approvals WHERE id=?", (record["approval_id"],)).fetchone()
            document = json.loads(approval_row[0])
            payload = {k: v for k, v in document.items() if k not in {"signature", "public_key", "verified"}}
            if not self._check_signature(payload, document["signature"]):
                return False
            if document["public_key"] != self.public_key:
                return False
            if sha256(canonical_bytes(json.loads(row["content"]))) != record["canonical_hash"]:
                return False
            expected = {"component_id": record["id"], "content_hash": record["canonical_hash"], "raw_hash": record["raw_hash"],
                        "semantic_fingerprint": record["semantic_fingerprint"], "version": record["version"],
                        "policy_version": self.get_policy()["version"], "approval_id": record["approval_id"],
                        "source_path": row["source_path"]}
            if any(document[key] != value for key, value in expected.items()):
                return False
            # Signed lifecycle history prevents restoring an old approval after revoke,
            # source loss, or reversion by editing only current component records.
            for audit_row in self._db.execute("SELECT document FROM audit ORDER BY sequence DESC"):
                event = json.loads(audit_row[0])
                if event["component_id"] == record["id"] and event["event_type"] in LIFECYCLE:
                    return event["event_type"] == "APPROVED" and event["details"].get("approval_id") == record["approval_id"]
            return False
        except (ValueError, KeyError, TypeError, IndexError):
            return False

    def approve(self, component_id: str, canonical_hash: str, version: int, approver: str, note: str = "") -> dict:
        with self.lock:
            self._assert_audit()
            if not isinstance(approver, str) or not approver.strip() or len(approver) > 200 or not isinstance(note, str) or len(note) > 2000:
                raise ValueError("Approver is required (max 200 characters); note max 2000")
            current = self.refresh(component_id)
            if not current["source_valid"]:
                raise ConflictError("Current source is unavailable; approval denied")
            if type(version) is not int or version != current["version"] or canonical_hash != current["canonical_hash"]:
                raise ConflictError("Content or version changed; inspect the current version before approving")
            approval_id = str(uuid.uuid4())
            timestamp = _now()
            payload = {"approval_id": approval_id, "component_id": component_id, "content_hash": canonical_hash,
                       "raw_hash": current["raw_hash"], "semantic_fingerprint": current["semantic_fingerprint"],
                       "version": version, "timestamp": timestamp, "approver": approver.strip(),
                       "policy_version": self.get_policy()["version"], "source_path": current["source_path"], "note": redact(note)}
            document = {**payload, "signature": self._sign(payload), "public_key": self.public_key}
            row = self._row(component_id)
            record = json.loads(row["record"])
            record.update(state="APPROVED", action="ALLOW", approved_at=timestamp, approved_by=approver.strip(),
                          approval_id=approval_id, updated_at=timestamp)
            self._db.execute("INSERT INTO approvals(id,component_id,document) VALUES (?,?,?)", (approval_id, component_id, _json(document)))
            self._db.execute("UPDATE components SET record=? WHERE id=?", (_json(record), component_id))
            self._db.execute("UPDATE versions SET record=? WHERE component_id=? AND version=?", (_json(record), component_id, version))
            self.append_audit("APPROVED", component_id, {"approval_id": approval_id, "version": version, "canonical_hash": canonical_hash,
                                                       "approver": approver.strip(), "policy_version": payload["policy_version"]})
            return self.get_component(component_id)

    def _set_state(self, component_id: str, state: str, reason: str) -> dict:
        with self.lock:
            self._assert_audit()
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
                raise ValueError("A reason is required (max 2000 characters)")
            row = self._row(component_id)
            record = json.loads(row["record"])
            record.update(state=state, action="QUARANTINE" if state == "QUARANTINED" else "BLOCK", approved_at=None,
                          approved_by=None, approval_id=None, updated_at=_now())
            self._db.execute("UPDATE components SET record=? WHERE id=?", (_json(record), component_id))
            self.append_audit(state, component_id, {"reason": redact(reason), "version": record["version"]})
            return self.get_component(component_id)

    def revoke(self, component_id: str, reason: str) -> dict:
        return self._set_state(component_id, "REVOKED", reason)

    def quarantine(self, component_id: str, reason: str) -> dict:
        return self._set_state(component_id, "QUARANTINED", reason)

    def history(self, component_id: str) -> list[dict]:
        with self.lock:
            self._assert_audit()
            self._row(component_id)
            anchors = {}
            for row in self._db.execute("SELECT document FROM audit ORDER BY sequence"):
                event = json.loads(row[0])
                if event["component_id"] == component_id and event["event_type"] in {"DISCOVERED", "VERSION_CHANGED"}:
                    anchors[event["details"]["version"]] = event["details"]
            result = []
            for row in self._db.execute("SELECT version,record,content FROM versions WHERE component_id=? ORDER BY version DESC", (component_id,)):
                try:
                    record = json.loads(row["record"])
                    content = json.loads(row["content"])
                    canonical = canonical_bytes(content)
                    anchor = anchors[row["version"]]
                    if record["id"] != component_id or record["version"] != row["version"]:
                        raise ValueError("identity")
                    if any(anchor[key] != record[key] for key in ("raw_hash", "canonical_hash", "semantic_fingerprint")):
                        raise ValueError("history")
                    if sha256(canonical) != record["canonical_hash"] or sha256(b"mcp-integrity-semantic-v1\0" + canonical) != record["semantic_fingerprint"]:
                        raise ValueError("content")
                except (ValueError, TypeError, KeyError) as exc:
                    raise ConflictError("Historical snapshot failed integrity verification") from exc
                record["content"] = redact(content)
                result.append(record)
            if len(result) != len(anchors):
                raise ConflictError("Historical snapshots are missing")
            return result

    def approval(self, component_id: str) -> dict:
        with self.lock:
            row = self._row(component_id)
            record = json.loads(row["record"])
            approval_id = record["approval_id"]
            if not approval_id:
                raise KeyError("No current approval")
            found = self._db.execute("SELECT document FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if found is None:
                raise ConflictError("Approval record missing")
            document = json.loads(found[0])
            document["verified"] = self.verify_audit()["valid"] and self._approval_valid(row)
            return document

    def gate(self, component_id: str, canonical_hash: str | None = None, version: int | None = None) -> dict:
        with self.lock:
            current = self.get_component(component_id)
            allowed = False
            action = "BLOCK"
            try:
                self._assert_audit()
                current = self.refresh(component_id)
                if not current["source_valid"]:
                    reason = "Current source is unavailable or invalid"
                elif canonical_hash is not None and canonical_hash != current["canonical_hash"]:
                    reason = "Requested content hash is stale"
                elif version is not None and version != current["version"]:
                    reason = "Requested version is stale"
                elif self._approval_valid(self._row(component_id)):
                    allowed, action, reason = True, "ALLOW", "Exact current content version has a valid signed approval"
                else:
                    action = current["action"] if current["action"] in {"BLOCK", "QUARANTINE", "REQUIRE_REAPPROVAL"} else "REQUIRE_REAPPROVAL"
                    reason = "Explicit approval for this content version and current policy is required"
                self.append_audit("GATE_ALLOWED" if allowed else "GATE_DENIED", component_id,
                                  {"version": current["version"], "canonical_hash": current["canonical_hash"], "reason": reason})
            except (ValueError, OSError, sqlite3.Error):
                allowed, action, reason = False, "BLOCK", "Integrity or source verification failed"
            return {"allowed": allowed, "action": action, "reason": reason, "component_id": component_id,
                    "canonical_hash": current["canonical_hash"], "raw_hash": current["raw_hash"],
                    "semantic_fingerprint": current["semantic_fingerprint"], "version": current["version"]}
