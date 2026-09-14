"""Strict, bounded configuration adapters and deterministic content fingerprints.

Canonical form is application-specific JSON, not RFC 8785: NFC strings, normalized
line endings, sorted keys, finite numbers and explicit tagged TOML temporal values.
Raw hashes remain authoritative for version transitions; Unicode or newline
normalization can therefore never silently preserve an approval. No interpolation,
shell evaluation, custom YAML constructors or .env variable expansion is performed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import time
import unicodedata
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Callable

from json5.lib import _convert as _convert_json5_ast
from json5.parser import Parser as _JSON5Parser
import yaml
import tomllib

MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 100_000
MAX_KEY_PATH_CHARS = 4096
MAX_PARSE_SECONDS = 3.0
_PARSE_DEADLINE: ContextVar[float | None] = ContextVar("configuration_parse_deadline", default=None)


def _check_parse_budget() -> None:
    deadline = _PARSE_DEADLINE.get()
    if deadline is not None and time.perf_counter() >= deadline:
        raise ValueError("Configuration exceeds parsing time limit")


def _json_structure(text: str, *, json5_format: bool = False) -> None:
    """Reject excessive or unfinished nesting before allocating a parser tree.

    Quotes, escapes and JSON5 comments are skipped lexically, never interpreted.
    Full syntax and duplicate-key checks remain the selected parser's job.
    """
    stack: list[str] = []
    quote = None
    comment = None
    escaped = False
    separators = 0
    index = 0
    while index < len(text):
        if index % 4096 == 0:
            _check_parse_budget()
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if comment == "line":
            if char in "\r\n\u2028\u2029":
                comment = None
        elif comment == "block":
            if char == "*" and following == "/":
                comment = None
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == '"' or json5_format and char == "'":
            quote = char
        elif json5_format and char == "/" and following in ("/", "*"):
            comment = "line" if following == "/" else "block"
            index += 1
        elif char in "[{":
            stack.append(char)
            if len(stack) > MAX_DEPTH:
                raise ValueError("Configuration exceeds JSON depth limit")
        elif char in "]}":
            expected = "[" if char == "]" else "{"
            if not stack or stack.pop() != expected:
                raise ValueError("Invalid configuration structure")
        elif char in ",:":
            separators += 1
            if separators > MAX_NODES * 2:
                raise ValueError("Configuration exceeds JSON structural limits")
        index += 1
    if stack or quote or comment == "block":
        raise ValueError("Invalid configuration structure")
    _check_parse_budget()


class _BoundedJSON5Parser(_JSON5Parser):
    """Deadline checks in the pinned pure-Python parser's terminal transitions.

    A 256 KiB JSON5 string takes multiple seconds in the upstream combinator
    parser. Instance-local checks avoid monkeypatching its globals or leaking a
    timer/thread when discovery runs in the HTTP server's thread pool.
    """
    def __init__(self, *args, **kwargs):
        self._transitions = 0
        super().__init__(*args, **kwargs)

    def _tick(self):
        self._transitions += 1
        if self._transitions >= 1024:
            self._transitions = 0
            _check_parse_budget()

    def _succeed(self, value, newpos=None):
        self._tick()
        return super()._succeed(value, newpos)

    def _fail(self):
        self._tick()
        return super()._fail()


def _json5(text: str) -> Any:
    # Use the pinned library's parser/AST conversion without changing its grammar.
    # An incompatible library update fails closed through parse_config.
    parser = _BoundedJSON5Parser(text, "<configuration>")
    ast, error, _ = parser.parse(global_vars={"_strict": True, "_consume_trailing": True})
    if error:
        raise ValueError("Invalid configuration syntax or value")
    _check_parse_budget()
    return _convert_json5_ast(ast, object_hook=None, parse_float=None, parse_int=None,
                             parse_constant=None, object_pairs_hook=_pairs, allow_duplicate_keys=False)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            raise ValueError("Configuration object keys must be strings")
        normalized = unicodedata.normalize("NFC", key).replace("\r\n", "\n").replace("\r", "\n")
        if normalized in result:
            raise ValueError("Duplicate or Unicode-equivalent configuration key")
        result[normalized] = value
    return result


class StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML with duplicate-key rejection, including merged mappings."""

    def forward(self, length=1):
        advanced = getattr(self, "_budget_advanced", 0) + length
        if advanced >= 4096:
            _check_parse_budget()
            advanced = 0
        self._budget_advanced = advanced
        return super().forward(length)


def _yaml_mapping(loader: StrictSafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    if any(key.tag == "tag:yaml.org,2002:merge" for key, _ in node.value):
        raise ValueError("Unsupported YAML merge keys")
    return _pairs([(loader.construct_object(k, deep=deep), loader.construct_object(v, deep=deep)) for k, v in node.value])


StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _yaml_mapping)


def _yaml(text: str) -> Any:
    """Preflight parser events before construction; aliases and merges are forbidden.

SafeLoader alone prevents object execution but does not prevent exponential merge
expansion. Streaming event checks cap depth/nodes without constructing alias graphs.
"""
    depth = 0
    count = 0
    for event in yaml.parse(text, Loader=StrictSafeLoader):
        _check_parse_budget()
        count += 1
        if count > MAX_NODES:
            raise ValueError("Configuration exceeds YAML structural limits")
        if isinstance(event, yaml.events.AliasEvent):
            raise ValueError("Unsupported YAML aliases")
        if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("Configuration exceeds YAML depth limit")
        elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
            depth -= 1
    return yaml.load(text, Loader=StrictSafeLoader)


def normalize(value: Any, *, _depth: int = 0, _seen: set[int] | None = None, _path_chars: int = 0,
              _budget: list[int] | None = None) -> Any:
    if _seen is None:
        _seen = set()
    if _budget is None:
        _budget = [MAX_NODES]
    _budget[0] -= 1
    if _budget[0] % 1024 == 0:
        _check_parse_budget()
    if _budget[0] < 0 or _depth > MAX_DEPTH:
        raise ValueError("Configuration exceeds structural limits")
    if _path_chars > MAX_KEY_PATH_CHARS:
        raise ValueError("Configuration exceeds key path limit")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
            raise ValueError("Unpaired Unicode surrogate in configuration")
        return text
    if isinstance(value, int):
        if value.bit_length() > 4096:
            raise ValueError("Configuration integer is too large")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite configuration number")
        # Preserve float vs integer and signed zero: consumers can distinguish them.
        return value
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        # A tagged list avoids silently collapsing a typed TOML date into a string.
        # Raw version binding prevents trust reuse even if a user authors this tag.
        return {"$integrity_type": type(value).__name__, "$value": value.isoformat()}
    if isinstance(value, (dict, list, tuple)):
        identity = id(value)
        if identity in _seen:
            raise ValueError("Cyclic configuration aliases are forbidden")
        _seen.add(identity)
        try:
            visit = lambda x, extra: normalize(x, _depth=_depth + 1, _seen=_seen, _budget=_budget,
                                               _path_chars=_path_chars + extra)
            if isinstance(value, dict):
                pairs = _pairs(list(value.items()))
                return {key: visit(pairs[key], len(key) + 1) for key in sorted(pairs)}
            return [visit(item, len(str(index)) + 2) for index, item in enumerate(value)]
        finally:
            _seen.remove(identity)
    raise ValueError(f"Unsupported configuration value type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(normalize(value), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def hashes(raw: bytes, value: Any) -> dict[str, str]:
    canonical = canonical_bytes(value)
    return {"raw_hash": sha256(raw), "canonical_hash": sha256(canonical),
            "semantic_fingerprint": sha256(b"mcp-integrity-semantic-v1\0" + canonical)}


def _decode(raw: bytes) -> str:
    # A BOM is required for non-UTF-8 to avoid lossy heuristic decoding.
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encoding = "utf-32"
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    else:
        encoding = "utf-8-sig"
    try:
        return raw.decode(encoding)
    except UnicodeError as exc:
        raise ValueError("Configuration must be UTF-8 or BOM-marked UTF-16/32") from exc


def _env(text: str) -> dict:
    """Parse one assignment per line. Multiline quoted values are deliberately refused."""
    pairs = []
    for number, raw_line in enumerate(text.splitlines(), 1):
        _check_parse_budget()
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not match:
            raise ValueError(f"Invalid .env assignment on line {number}")
        name, value = match.groups()
        if value.startswith(('"', "'")):
            quote = value[0]
            end = None
            escaped = False
            for index in range(1, len(value)):
                if value[index] == quote and not escaped:
                    end = index
                    break
                escaped = value[index] == "\\" and not escaped
            if end is None or (value[end + 1:].strip() and not value[end + 1:].strip().startswith("#")):
                raise ValueError(f"Unsupported or unterminated .env quoted value on line {number}")
            inner = value[1:end]
            if quote == '"':
                inner = re.sub(r'\\([nrt"\\])', lambda m: {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}[m[1]], inner)
            value = inner
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
        pairs.append((name, value))
    return {"environment": _pairs(pairs)}


def _json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite configuration number")))


ADAPTERS: dict[str, Callable[[str], Any]] = {
    ".json": _json,
    ".json5": _json5,
    ".yaml": _yaml,
    ".yml": _yaml,
    ".toml": tomllib.loads,
    ".env": _env,
}


def register_adapter(extension: str, parser: Callable[[str], Any]) -> None:
    """Register trusted application code only; untrusted files never load adapters."""
    if not extension.startswith("."):
        raise ValueError("Adapter extension must start with a period")
    ADAPTERS[extension.lower()] = parser


def parse_config(raw: bytes, path: Path | str, *, timeout: float = MAX_PARSE_SECONDS) -> Any:
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("Configuration exceeds 4 MiB limit")
    path = Path(path)
    suffix = ".env" if path.name == ".env" or path.name.startswith(".env.") else path.suffix.lower()
    parser = ADAPTERS.get(suffix)
    if parser is None:
        raise ValueError("Unsupported configuration format")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Configuration parsing time limit must be positive and finite")
    deadline = time.perf_counter() + min(timeout, MAX_PARSE_SECONDS)
    parent_deadline = _PARSE_DEADLINE.get()
    token = _PARSE_DEADLINE.set(min(deadline, parent_deadline) if parent_deadline is not None else deadline)
    try:
        text = _decode(raw)
        if suffix in {".json", ".json5"}:
            _json_structure(text, json5_format=suffix == ".json5")
        result = normalize(parser(text))
        _check_parse_budget()
    except (RecursionError, OverflowError) as exc:
        raise ValueError("Configuration exceeds parsing limits") from exc
    except Exception as exc:
        if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError):
            # Do not surface parser diagnostics: they can quote credential values.
            if str(exc).startswith(("Duplicate", "Configuration", "Non-finite", "Unsupported", "Invalid .env", "Cyclic", "Unpaired")):
                raise
        raise ValueError("Invalid configuration syntax or value") from exc
    finally:
        _PARSE_DEADLINE.reset(token)
    if not isinstance(result, (dict, list)):
        raise ValueError("Configuration root must be an object or array")
    return result


_SECRET = re.compile(r"secret|password|passwd|token|api[_-]?key|authorization|cookie|credential|private[_-]?key", re.I)
_CONTEXT = {"env", "environment", "environmentvariables", "headers", "auth", "authentication"}


def sensitive_path(path: str) -> bool:
    parts = re.split(r"[./\[\]]+", path.lower())
    return bool(_SECRET.search(path)) or any(part in _CONTEXT for part in parts)


def redact(value: Any, path: str = "") -> Any:
    """Mask credential-named fields and every env/header/auth value, including diffs.

This is structural best-effort masking; arbitrary secrets embedded in prose cannot
be recognized reliably. Sources and private SQLite snapshots are local sensitive data.
"""
    if isinstance(value, dict):
        return {k: redact(v, f"{path}.{k}" if path else k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, path) for v in value]
    if sensitive_path(path) and value is not None:
        return "[REDACTED]"
    if isinstance(value, str):
        value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
        value = re.sub(r"(?i)([?&](?:token|key|api_key|secret|password|access_token)=)[^&#\s]+", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", value)
    return value


_SECURITY = {"command", "args", "arguments", "env", "environment", "cwd", "workingdirectory", "executable",
             "url", "endpoint", "headers", "auth", "authentication", "capabilities", "inputschema", "outputschema",
             "schema", "allowed_paths", "allowedpaths", "path", "paths", "uri", "image", "docker", "transport",
             "description", "prompt", "prompts", "template", "instructions", "permissions", "tools", "resources"}


def semantic_diff(old: Any, new: Any, limit: int = 256) -> list[dict]:
    """Conservative structural diff: strings are never interpreted as executable code."""
    changes: list[dict] = []
    missing = object()

    def add(path: str, before: Any, after: Any) -> None:
        if len(changes) >= limit:
            return
        tokens = set(re.split(r"[./\[\]]+", path.lower()))
        security = bool(tokens & _SECURITY) or sensitive_path(path)
        changes.append({"path": path or "$", "old": None if before is missing else redact(before, path),
                        "new": None if after is missing else redact(after, path),
                        "severity": "HIGH" if security else "MEDIUM",
                        "category": "SECURITY_RELEVANT_CHANGE" if security else "SEMANTIC_CHANGE",
                        "operation": "add" if before is missing else "remove" if after is missing else "replace"})

    def walk(before: Any, after: Any, path: str) -> None:
        if len(changes) >= limit:
            return
        if isinstance(before, dict) and isinstance(after, dict):
            for key in sorted(set(before) | set(after)):
                a, b = before.get(key, missing), after.get(key, missing)
                child = f"{path}.{key}" if path else key
                if a is missing or b is missing:
                    add(child, a, b)
                else:
                    walk(a, b, child)
        elif isinstance(before, list) and isinstance(after, list):
            for index in range(max(len(before), len(after))):
                a = before[index] if index < len(before) else missing
                b = after[index] if index < len(after) else missing
                if a is missing or b is missing:
                    add(f"{path}[{index}]", a, b)
                else:
                    walk(a, b, f"{path}[{index}]")
        elif type(before) is not type(after) or canonical_bytes(before) != canonical_bytes(after):
            add(path, before, after)

    walk(old, new, "")
    if len(changes) == limit:
        changes.append({"path": "$", "old": None, "new": "Diff output reached its limit; full content hashes include every field.",
                        "severity": "HIGH", "category": "SECURITY_RELEVANT_CHANGE", "operation": "truncated"})
    return changes
