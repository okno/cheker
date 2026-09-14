"""Frozen registry of extractors explicitly packaged as trusted application code.

No document, filename, environment variable, entry point or user directory loads
plugins. The static trusted_extractors bootstrap is called in each new process;
production workers initialize it after confinement and before reading input.
Registration describes code, not authorization: callers must validate Extraction
results and retain the common Budget and worker boundaries.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .extraction import Budget, Extraction

Handler = Callable[[bytes, str, "Budget"], "Extraction"]
MAX_EXTRACTORS = 64
MAX_SOURCE_BYTES = 4 * 1024**2
MAX_PACKAGE_FILES = 256
MAX_PACKAGE_BYTES = 4 * 1024**2
MAX_PACKAGE_ENTRIES = 1024
MAX_PACKAGE_DEPTH = 16
_PACKAGE = "integrity_guard"
_FORMAT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_EXTENSION = re.compile(r"\.[a-z0-9][a-z0-9_+-]{0,31}\Z")
_DEPENDENCY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_MESSAGES = {
    "INVALID_METADATA": "Extractor registration metadata is invalid.",
    "BUILTIN_COLLISION": "An extractor cannot replace a built-in format.",
    "DUPLICATE": "Extractor format or extension is already registered.",
    "FROZEN": "Extractor registry is frozen.",
    "NOT_FROZEN": "Extractor registry must be frozen before use.",
    "SOURCE_UNAVAILABLE": "Trusted extractor source cannot be identified or read.",
    "DEPENDENCY_UNAVAILABLE": "Extractor dependency version cannot be identified.",
    "LIMIT": "Extractor registry exceeds its registration limit.",
    "PACKAGE_LIMIT": "Trusted extractor package exceeds its source inventory limits.",
    "BOOTSTRAP_FAILED": "Trusted extractor bootstrap could not complete.",
}


class ExtractorRegistryError(ValueError):
    """Fixed, identifiable diagnostics contain no document or loader error text."""

    def __init__(self, code: str):
        self.code = code if code in _MESSAGES else "INVALID_METADATA"
        super().__init__(_MESSAGES[self.code])


@dataclass(frozen=True)
class RegisteredExtractor:
    format: str
    extensions: tuple[str, ...]
    version: str
    handler: Handler
    dependencies: tuple[str, ...]


def _extension(value: str) -> str:
    if not isinstance(value, str):
        raise ExtractorRegistryError("INVALID_METADATA")
    value = value.lower()
    value = value if value.startswith(".") else "." + value
    if not _EXTENSION.fullmatch(value):
        raise ExtractorRegistryError("INVALID_METADATA")
    return value


def _version(value) -> str:
    if (not isinstance(value, str) or not 0 < len(value) <= 128 or not value.isascii()
            or any(ord(char) < 33 or ord(char) > 126 for char in value)):
        raise ExtractorRegistryError("INVALID_METADATA")
    return value


def _builtin_formats() -> set[str]:
    # Delayed to avoid a circular import when extraction integrates lookup.
    from .extraction import TEXT_FORMATS
    return set(TEXT_FORMATS) | {"docx", "pdf"}


def _source_file(module, package_root: Path) -> Path:
    try:
        name = module.__name__
        raw = Path(module.__file__)
        if (not name.startswith(_PACKAGE + ".") or not raw.is_absolute() or raw.suffix != ".py"
                or raw.is_symlink()):
            raise ValueError
        source = raw.resolve(strict=True)
        source.relative_to(package_root)
        if source != raw or not source.is_file():
            raise ValueError
        return source
    except (AttributeError, TypeError, ValueError, OSError, RuntimeError):
        raise ExtractorRegistryError("SOURCE_UNAVAILABLE") from None


def _identity(value) -> tuple:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _source_hash(path: Path, cache: dict[Path, str], *, dir_fd=None) -> str:
    if path in cache:
        return cache[path]
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        target = path if dir_fd is None else path.name
        with os.fdopen(os.open(target, flags, dir_fd=dir_fd), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SOURCE_BYTES:
                raise ValueError
            data = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
        current = os.stat(target, dir_fd=dir_fd, follow_symlinks=False)
        if (len(data) > MAX_SOURCE_BYTES or len(data) != before.st_size or _identity(before) != _identity(after)
                or _identity(after) != _identity(current)):
            raise ValueError
    except (OSError, ValueError, RuntimeError):
        raise ExtractorRegistryError("SOURCE_UNAVAILABLE") from None
    digest = hashlib.sha256(data).hexdigest()
    cache[path] = digest
    return digest


def _package_sources(package_root: Path, cache: dict[Path, str]) -> dict:
    """Hash packaged helpers/resources using bounded no-follow Linux traversal.

    A second metadata pass rejects changes to selected sources or their directory
    inventory during collection. These checks do not support hot code replacement;
    applications must restart after installing a new trusted package.
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)

    def collect(read_sources: bool):
        states, files = {}, []
        entries_seen = total_bytes = 0

        def visit(descriptor, relative: Path, depth: int):
            nonlocal entries_seen, total_bytes
            if depth > MAX_PACKAGE_DEPTH:
                raise ExtractorRegistryError("PACKAGE_LIMIT")
            before = os.fstat(descriptor)
            if not stat.S_ISDIR(before.st_mode):
                raise ExtractorRegistryError("SOURCE_UNAVAILABLE")
            states[relative.as_posix()] = _identity(before)
            directory_path = package_root / relative
            if _identity(directory_path.stat(follow_symlinks=False)) != _identity(before):
                raise ExtractorRegistryError("SOURCE_UNAVAILABLE")
            entries = []
            # scandir(fd) internally duplicates an fd, which the scanner's
            # seccomp policy intentionally forbids. Enumerate the verified path
            # instead; child opens remain anchored to the no-follow descriptor.
            with os.scandir(directory_path) as iterator:
                for entry in iterator:
                    if entry.name == "__pycache__" or entry.name.endswith(".pyc"):
                        continue
                    entries_seen += 1
                    if entries_seen > MAX_PACKAGE_ENTRIES:
                        raise ExtractorRegistryError("PACKAGE_LIMIT")
                    entries.append((entry.name, entry.stat(follow_symlinks=False)))
            for name, observed in sorted(entries):
                item = relative / name
                if stat.S_ISDIR(observed.st_mode):
                    child = os.open(name, flags, dir_fd=descriptor)
                    try:
                        if _identity(os.fstat(child)) != _identity(observed):
                            raise ExtractorRegistryError("SOURCE_UNAVAILABLE")
                        visit(child, item, depth + 1)
                    finally:
                        os.close(child)
                elif not stat.S_ISREG(observed.st_mode):
                    raise ExtractorRegistryError("SOURCE_UNAVAILABLE")
                elif item.suffix.lower() in {".py", ".json"}:
                    total_bytes += observed.st_size
                    if len(files) >= MAX_PACKAGE_FILES or total_bytes > MAX_PACKAGE_BYTES:
                        raise ExtractorRegistryError("PACKAGE_LIMIT")
                    states[item.as_posix()] = _identity(observed)
                    record = {"file": item.as_posix()}
                    if read_sources:
                        record["sha256"] = _source_hash(package_root / item, cache, dir_fd=descriptor)
                    files.append(record)
            if (_identity(before) != _identity(os.fstat(descriptor))
                    or _identity(before) != _identity(directory_path.stat(follow_symlinks=False))):
                raise ExtractorRegistryError("SOURCE_UNAVAILABLE")

        root = os.open(package_root, flags)
        try:
            visit(root, Path(), 0)
        finally:
            os.close(root)
        return states, sorted(files, key=lambda record: record["file"]), total_bytes

    try:
        first, sources, size = collect(True)
        second, _, _ = collect(False)
        if first != second:
            raise ExtractorRegistryError("SOURCE_UNAVAILABLE")
    except ExtractorRegistryError:
        raise
    except (OSError, ValueError, TypeError, NotImplementedError, RuntimeError):
        raise ExtractorRegistryError("SOURCE_UNAVAILABLE") from None
    return {"files": sources, "total_size_bytes": size}


def _dependency_versions(names: tuple[str, ...], cache: dict[str, str]) -> dict[str, str]:
    versions = {}
    for name in names:
        try:
            if name not in cache:
                cache[name] = _version(importlib.metadata.version(name))
            versions[name] = cache[name]
        except Exception:
            raise ExtractorRegistryError("DEPENDENCY_UNAVAILABLE") from None
    return versions


class ExtractorRegistry:
    """An isolated registry; only get_registry() owns the per-process singleton."""

    def __init__(self):
        self._package_root = Path(__file__).resolve().parent
        self._records: dict[str, RegisteredExtractor] = {}
        self._extensions: dict[str, RegisteredExtractor] = {}
        self._frozen = False
        self._lock = threading.RLock()

    def _handler_file(self, handler: Handler) -> Path:
        try:
            if (not inspect.isfunction(handler) or inspect.iscoroutinefunction(handler)
                    or inspect.isgeneratorfunction(handler) or handler.__qualname__ != handler.__name__):
                raise ValueError
            parameters = list(inspect.signature(handler, follow_wrapped=False).parameters.values())
            if len(parameters) != 3 or any(parameter.kind not in {
                    inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD} for parameter in parameters):
                raise ValueError
            module = sys.modules[handler.__module__]
            if getattr(module, handler.__name__, None) is not handler:
                raise ValueError
            path = _source_file(module, self._package_root)
            if Path(handler.__code__.co_filename).resolve(strict=True) != path:
                raise ValueError
            return path
        except ExtractorRegistryError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError, OSError, RuntimeError):
            raise ExtractorRegistryError("SOURCE_UNAVAILABLE") from None

    def register_extractor(self, format: str, extensions, version: str,
                           handler: Handler, dependencies=()) -> RegisteredExtractor:
        """Register one packaged module-level handler; never import it from a name."""
        with self._lock:
            if self._frozen:
                raise ExtractorRegistryError("FROZEN")
            if len(self._records) >= MAX_EXTRACTORS:
                raise ExtractorRegistryError("LIMIT")
            if not isinstance(format, str) or not _FORMAT.fullmatch(format.lower()):
                raise ExtractorRegistryError("INVALID_METADATA")
            format = format.lower()
            version = _version(version)
            if not isinstance(extensions, (list, tuple)) or not 0 < len(extensions) <= 32:
                raise ExtractorRegistryError("INVALID_METADATA")
            normalized = tuple(sorted(_extension(extension) for extension in extensions))
            if len(set(normalized)) != len(normalized):
                raise ExtractorRegistryError("DUPLICATE")
            if not isinstance(dependencies, (list, tuple)) or len(dependencies) > 32:
                raise ExtractorRegistryError("INVALID_METADATA")
            names = []
            for name in dependencies:
                if not isinstance(name, str) or len(name) > 100 or not _DEPENDENCY.fullmatch(name):
                    raise ExtractorRegistryError("INVALID_METADATA")
                names.append(re.sub(r"[-_.]+", "-", name).lower())
            if len(set(names)) != len(names):
                raise ExtractorRegistryError("DUPLICATE")
            names = tuple(sorted(names))
            builtins = _builtin_formats()
            if format in builtins or any(extension[1:] in builtins for extension in normalized):
                raise ExtractorRegistryError("BUILTIN_COLLISION")
            if format in self._records or any(extension in self._extensions for extension in normalized):
                raise ExtractorRegistryError("DUPLICATE")
            _source_hash(self._handler_file(handler), {})
            _dependency_versions(names, {})
            record = RegisteredExtractor(format, normalized, version, handler, names)
            self._records[format] = record
            self._extensions.update({extension: record for extension in normalized})
            return record

    def freeze(self) -> ExtractorRegistry:
        with self._lock:
            if not self._frozen:
                self._manifest()
                self._frozen = True
            return self

    def lookup(self, extension: str) -> RegisteredExtractor | None:
        with self._lock:
            self._require_frozen()
            if not isinstance(extension, str) or extension == "":
                return None
            try:
                normalized = _extension(extension)
            except ExtractorRegistryError:
                return None
            return self._extensions.get(normalized)

    def _require_frozen(self):
        if not self._frozen:
            raise ExtractorRegistryError("NOT_FROZEN")

    def _manifest(self) -> dict:
        try:
            from . import trusted_extractors
        except Exception:
            raise ExtractorRegistryError("SOURCE_UNAVAILABLE") from None
        hashes, dependencies = {}, {}
        package_root = Path(__file__).resolve().parent
        package_sources = _package_sources(self._package_root, hashes)

        def describe_module(module):
            path = _source_file(module, package_root)
            return {"module": module.__name__, "file": path.relative_to(package_root).as_posix(),
                    "sha256": _source_hash(path, hashes)}

        descriptors = []
        for record in sorted(self._records.values(), key=lambda item: item.format):
            path = self._handler_file(record.handler)
            descriptors.append({"format": record.format, "extensions": list(record.extensions), "version": record.version,
                                "handler": {"module": record.handler.__module__, "qualname": record.handler.__qualname__,
                                            "file": path.relative_to(self._package_root).as_posix(),
                                            "sha256": _source_hash(path, hashes)},
                                "dependencies": _dependency_versions(record.dependencies, dependencies)})
        return {"schema_version": 1, "registry": describe_module(sys.modules[__name__]),
                "bootstrap": describe_module(trusted_extractors), "extractors": descriptors,
                "package_sources": package_sources}

    def descriptors(self) -> dict:
        """Fresh, deterministic metadata; missing sources/dependencies are errors."""
        with self._lock:
            self._require_frozen()
            return self._manifest()

    def fingerprint(self) -> str:
        """Hash current code and declared dependency versions, without loading plugins."""
        manifest = self.descriptors()
        return hashlib.sha256(json.dumps(manifest, sort_keys=True, ensure_ascii=True,
                                         separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


_PROCESS_REGISTRY: ExtractorRegistry | None = None
_PROCESS_LOCK = threading.RLock()


def get_registry() -> ExtractorRegistry:
    """Run the static packaged bootstrap once per process, publishing only a frozen registry."""
    global _PROCESS_REGISTRY
    with _PROCESS_LOCK:
        if _PROCESS_REGISTRY is None:
            registry = ExtractorRegistry()
            try:
                from . import trusted_extractors
                trusted_extractors.register_all(registry)
                registry.freeze()
            except ExtractorRegistryError:
                raise
            except Exception:
                raise ExtractorRegistryError("BOOTSTRAP_FAILED") from None
            _PROCESS_REGISTRY = registry
        return _PROCESS_REGISTRY


def lookup_extractor(extension: str) -> RegisteredExtractor | None:
    return get_registry().lookup(extension)


def registry_fingerprint() -> str:
    return get_registry().fingerprint()
