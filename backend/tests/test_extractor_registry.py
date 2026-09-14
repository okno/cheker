"""Isolated registry contracts; no plugin is installed into the process singleton."""
import builtins
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import types

import pytest

from integrity_guard import extractor_registry as module
from integrity_guard.extraction import Budget, Extraction, ExtractionError, TEXT_FORMATS
from integrity_guard.extractor_registry import ExtractorRegistry, ExtractorRegistryError


HANDLER_SOURCE = '''from integrity_guard.extraction import Extraction
def parse(data, filename, budget):
    result = Extraction("fixture")
    budget.add(result, data.decode("utf-8"), location="fixture:text")
    return result
'''


@pytest.fixture
def fixture_handler(tmp_path, monkeypatch):
    """Load only fixed test code and scope its package root to an isolated registry."""
    root = tmp_path / "fixture_package"
    root.mkdir()
    created = []

    def make(source=HANDLER_SOURCE):
        index = len(created)
        path = root / ("handler" + str(index) + ".py")
        path.write_text(source, encoding="utf-8")
        name = "integrity_guard._registry_test_handler" + str(index)
        handler_module = types.ModuleType(name)
        handler_module.__file__ = str(path)
        exec(compile(source, str(path), "exec"), handler_module.__dict__)
        monkeypatch.setitem(sys.modules, name, handler_module)
        registry = ExtractorRegistry()
        # There is deliberately no production argument for an arbitrary package path.
        registry._package_root = root
        created.append(handler_module)
        return registry, handler_module.parse, path

    return make


def register(registry, handler, **overrides):
    args = {"format": "fixture", "extensions": ["fixture"], "version": "1.0.0",
            "handler": handler, "dependencies": ()}
    args.update(overrides)
    return registry.register_extractor(**args)


def test_functional_handler_preserves_common_budget(fixture_handler):
    registry, handler, _ = fixture_handler()
    record = register(registry, handler)
    assert registry.freeze() is registry
    assert registry.lookup(".FIXTURE") is record
    budget = Budget(5, max_chars=100)
    result = record.handler(b"Meeting notes.", "notes.fixture", budget)
    assert isinstance(result, Extraction)
    assert result.format == "fixture" and result.segments[0].text == "Meeting notes."
    assert result.characters == budget.characters == 14
    assert budget.segments == len(result.segments) == 1
    with pytest.raises(ExtractionError, match="budget"):
        record.handler(b"Too much text", "notes.fixture", Budget(5, max_chars=1))
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler, format="later", extensions=["later"])
    assert error.value.code == "FROZEN"


def test_case_and_order_normalization_is_deterministic(fixture_handler, monkeypatch):
    registry, handler, _ = fixture_handler()
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "2.0")
    record = register(registry, handler, format="FIXTURE", extensions=[".ZZ", "Fixture"],
                      dependencies=["Z_package", "a.package"])
    registry.freeze()
    assert record.format == "fixture"
    assert record.extensions == (".fixture", ".zz")
    assert record.dependencies == ("a-package", "z-package")
    assert registry.lookup("ZZ") is record
    assert registry.lookup(".fixture") is record
    assert registry.descriptors()["extractors"][0]["dependencies"] == {"a-package": "2.0", "z-package": "2.0"}


@pytest.mark.parametrize("extension", ["", ".", "unknown", ".unknown", "*.xlsx", "dir/file.xlsx", ".bad space", None, 3])
def test_lookup_unrecognized_extension_returns_none(extension):
    assert ExtractorRegistry().freeze().lookup(extension) is None


@pytest.mark.parametrize("operation", ["lookup", "descriptors", "fingerprint"])
def test_read_operations_require_freeze(operation):
    registry = ExtractorRegistry()
    with pytest.raises(ExtractorRegistryError) as error:
        getattr(registry, operation)("fixture") if operation == "lookup" else getattr(registry, operation)()
    assert error.value.code == "NOT_FROZEN"


@pytest.mark.parametrize("builtin", sorted(TEXT_FORMATS | {"pdf", "docx"}))
def test_every_builtin_name_and_extension_is_reserved(fixture_handler, builtin):
    registry, handler, _ = fixture_handler()
    for options in ({"format": builtin.upper()}, {"extensions": ["." + builtin.upper()]}):
        with pytest.raises(ExtractorRegistryError) as error:
            register(registry, handler, **options)
        assert error.value.code == "BUILTIN_COLLISION"
    assert registry.freeze().descriptors()["extractors"] == []


@pytest.mark.parametrize("options,code", [
    ({"format": ""}, "INVALID_METADATA"),
    ({"format": "../package"}, "INVALID_METADATA"),
    ({"format": 1}, "INVALID_METADATA"),
    ({"version": ""}, "INVALID_METADATA"),
    ({"version": "two words"}, "INVALID_METADATA"),
    ({"version": "line\nbreak"}, "INVALID_METADATA"),
    ({"version": "a" * 129}, "INVALID_METADATA"),
    ({"extensions": "fixture"}, "INVALID_METADATA"),
    ({"extensions": []}, "INVALID_METADATA"),
    ({"extensions": ["*"]}, "INVALID_METADATA"),
    ({"extensions": ["*.fixture"]}, "INVALID_METADATA"),
    ({"extensions": ["dir/fixture"]}, "INVALID_METADATA"),
    ({"extensions": [" "]}, "INVALID_METADATA"),
    ({"extensions": [None]}, "INVALID_METADATA"),
    ({"extensions": ["fixture", ".FIXTURE"]}, "DUPLICATE"),
    ({"dependencies": "pypdf"}, "INVALID_METADATA"),
    ({"dependencies": ["package>=2"]}, "INVALID_METADATA"),
    ({"dependencies": ["package/path"]}, "INVALID_METADATA"),
    ({"dependencies": [""]}, "INVALID_METADATA"),
    ({"dependencies": ["same-package", "Same.Package"]}, "DUPLICATE"),
])
def test_metadata_rejected_without_partial_registration(fixture_handler, options, code):
    registry, handler, _ = fixture_handler()
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler, **options)
    assert error.value.code == code
    assert registry.freeze().descriptors()["extractors"] == []


@pytest.mark.parametrize("second", [{"format": "FIXTURE", "extensions": ["other"]},
                                    {"format": "other", "extensions": [".FIXTURE"]}])
def test_registered_formats_and_extensions_cannot_be_overridden(fixture_handler, second):
    registry, handler, _ = fixture_handler()
    first = register(registry, handler)
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler, **second)
    assert error.value.code == "DUPLICATE"
    assert registry.freeze().lookup("fixture") is first
    assert len(registry.descriptors()["extractors"]) == 1


def test_registration_count_is_bounded(fixture_handler, monkeypatch):
    registry, handler, _ = fixture_handler()
    monkeypatch.setattr(module, "MAX_EXTRACTORS", 1)
    register(registry, handler)
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler, format="second", extensions=["second"])
    assert error.value.code == "LIMIT"


@pytest.mark.parametrize("source", [
    "async def parse(data, filename, budget):\n    return None\n",
    "def parse(data, filename, budget):\n    yield data\n",
    "def parse(data, filename):\n    return None\n",
    "def parse(data, filename, *, budget):\n    return None\n",
    "def parse(data, filename, budget, *extra):\n    return None\n",
    "parse = lambda data, filename, budget: None\n",
    "def factory():\n    def nested(data, filename, budget):\n        return None\n    return nested\nparse = factory()\n",
])
def test_handler_must_be_module_level_sync_function_with_three_arguments(fixture_handler, source):
    registry, handler, _ = fixture_handler(source)
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler)
    assert error.value.code == "SOURCE_UNAVAILABLE"


@pytest.mark.parametrize("replacement", [len, object(), "integrity_guard.user_plugin.parse"])
def test_handler_strings_and_other_callable_types_never_load_plugins(fixture_handler, replacement):
    registry, _, _ = fixture_handler()
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, replacement)
    assert error.value.code == "SOURCE_UNAVAILABLE"


def test_user_path_cannot_register_in_production_registry(fixture_handler):
    _, handler, _ = fixture_handler()
    with pytest.raises(ExtractorRegistryError) as error:
        register(ExtractorRegistry(), handler)
    assert error.value.code == "SOURCE_UNAVAILABLE"


def test_handler_source_must_match_loaded_code_and_module_binding(fixture_handler, monkeypatch):
    registry, handler, path = fixture_handler()
    handler_module = sys.modules[handler.__module__]
    monkeypatch.setattr(handler_module, "parse", None)
    with pytest.raises(ExtractorRegistryError):
        register(registry, handler)
    monkeypatch.setattr(handler_module, "parse", handler)
    other = path.with_name("other.py")
    other.write_bytes(path.read_bytes())
    monkeypatch.setattr(handler_module, "__file__", str(other))
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler)
    assert error.value.code == "SOURCE_UNAVAILABLE"


def test_missing_source_and_oversized_source_are_fixed_errors(fixture_handler, monkeypatch):
    registry, handler, path = fixture_handler()
    monkeypatch.setattr(module, "MAX_SOURCE_BYTES", 1)
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler)
    assert error.value.code == "SOURCE_UNAVAILABLE"
    path.unlink()
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler)
    assert error.value.code == "SOURCE_UNAVAILABLE"
    assert str(path) not in str(error.value)


def test_dependency_must_be_installed_and_versioned(fixture_handler, monkeypatch):
    registry, handler, _ = fixture_handler()

    def missing(name):
        raise importlib.metadata.PackageNotFoundError("private source text")

    monkeypatch.setattr(importlib.metadata, "version", missing)
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler, dependencies=["required-package"])
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert "private source text" not in str(error.value)
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "")
    with pytest.raises(ExtractorRegistryError) as error:
        register(registry, handler, dependencies=["required-package"])
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert registry.freeze().descriptors()["extractors"] == []


def test_manifest_identifies_registry_bootstrap_actual_handler_and_dependencies(fixture_handler, monkeypatch):
    registry, handler, path = fixture_handler()
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "9.2.1")
    register(registry, handler, dependencies=["fixture-dependency"])
    registry.freeze()
    manifest = registry.descriptors()
    package_root = Path(module.__file__).parent
    assert manifest["schema_version"] == 1
    for name in ("registry", "bootstrap"):
        source = package_root / manifest[name]["file"]
        assert manifest[name]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert manifest[name]["module"].startswith("integrity_guard.")
    item = manifest["extractors"][0]
    assert item["handler"] == {"module": handler.__module__, "qualname": "parse", "file": path.name,
                               "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    assert item["dependencies"] == {"fixture-dependency": "9.2.1"}
    expected = hashlib.sha256(json.dumps(manifest, sort_keys=True, ensure_ascii=True,
                                        separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()
    assert registry.fingerprint() == expected
    manifest["extractors"][0]["extensions"].append(".unregistered")
    assert registry.lookup("unregistered") is None
    assert registry.fingerprint() == expected


def test_handler_source_and_dependency_changes_invalidate_fingerprint(fixture_handler, monkeypatch):
    registry, handler, path = fixture_handler()
    version = ["1.0.0"]
    monkeypatch.setattr(importlib.metadata, "version", lambda name: version[0])
    register(registry, handler, dependencies=["fixture-dependency"])
    registry.freeze()
    original = registry.fingerprint()
    path.write_bytes(path.read_bytes() + b"\n# Updated packaged extractor.\n")
    changed_source = registry.fingerprint()
    assert changed_source != original
    version[0] = "1.0.1"
    assert registry.fingerprint() not in {original, changed_source}


@pytest.mark.parametrize("component", ["registry", "bootstrap"])
def test_static_bootstrap_and_registry_hashes_are_in_context(component, monkeypatch):
    registry = ExtractorRegistry().freeze()
    original = registry.fingerprint()
    path = Path(module.__file__).parent / registry.descriptors()[component]["file"]
    actual_hash = module._source_hash

    def alternate_hash(source, cache, **kwargs):
        return "0" * 64 if source == path else actual_hash(source, cache, **kwargs)

    monkeypatch.setattr(module, "_source_hash", alternate_hash)
    assert registry.fingerprint() != original


def test_dependency_failure_after_freeze_does_not_reuse_old_descriptor(fixture_handler, monkeypatch):
    registry, handler, _ = fixture_handler()
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "1.0")
    register(registry, handler, dependencies=["fixture-dependency"])
    registry.freeze()
    registry.fingerprint()
    monkeypatch.setattr(importlib.metadata, "version", lambda name: None)
    with pytest.raises(ExtractorRegistryError) as error:
        registry.fingerprint()
    assert error.value.code == "DEPENDENCY_UNAVAILABLE"


def test_source_failure_after_freeze_does_not_reuse_old_descriptor(fixture_handler):
    registry, handler, path = fixture_handler()
    register(registry, handler)
    registry.freeze()
    registry.fingerprint()
    path.unlink()
    with pytest.raises(ExtractorRegistryError) as error:
        registry.fingerprint()
    assert error.value.code == "SOURCE_UNAVAILABLE"


def test_bootstrap_import_failure_has_fixed_diagnostic(monkeypatch):
    registry = ExtractorRegistry().freeze()
    original = builtins.__import__

    def unavailable(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and "trusted_extractors" in fromlist:
            raise ImportError("Private package path")
        return original(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", unavailable)
    with pytest.raises(ExtractorRegistryError) as error:
        registry.descriptors()
    assert error.value.code == "SOURCE_UNAVAILABLE"
    assert "Private package path" not in str(error.value)


def test_packaged_helper_change_invalidates_fingerprint_without_handler_version_change(fixture_handler):
    registry, handler, path = fixture_handler()
    helper = path.parent / "helper.py"
    helper.write_text('OUTPUT_LABEL = "first"\n', encoding="utf-8")
    register(registry, handler)
    registry.freeze()
    before = registry.descriptors()
    fingerprint = registry.fingerprint()
    helper.write_text('OUTPUT_LABEL = "second"\n', encoding="utf-8")
    after = registry.descriptors()
    assert before["extractors"] == after["extractors"]
    assert before["package_sources"] != after["package_sources"]
    assert registry.fingerprint() != fingerprint


def test_package_inventory_covers_nested_python_and_json_and_ignores_bytecode(fixture_handler):
    registry, handler, path = fixture_handler()
    nested = path.parent / "helpers"
    nested.mkdir()
    helper = nested / "helper.py"
    helper.write_text("VALUE = 3\n", encoding="utf-8")
    config = nested / "settings.json"
    config.write_text('{"label":"example"}\n', encoding="utf-8")
    (nested / "helper.pyc").write_bytes(b"not a source")
    cache = path.parent / "__pycache__"
    cache.mkdir()
    (cache / "unused.py").write_bytes(b"not part of package sources")
    register(registry, handler)
    registry.freeze()
    expected = sorted([path, helper, config])
    sources = registry.descriptors()["package_sources"]
    assert sources["files"] == [{"file": item.relative_to(path.parent).as_posix(),
                                  "sha256": hashlib.sha256(item.read_bytes()).hexdigest()} for item in expected]
    assert sources["total_size_bytes"] == sum(item.stat().st_size for item in expected)
    original = registry.fingerprint()
    config.write_text('{"label":"changed"}\n', encoding="utf-8")
    assert registry.fingerprint() != original


@pytest.mark.parametrize("limit", ["files", "bytes", "entries", "depth"])
def test_package_inventory_limits_fail_closed(fixture_handler, monkeypatch, limit):
    registry, handler, path = fixture_handler()
    register(registry, handler)
    if limit == "files":
        monkeypatch.setattr(module, "MAX_PACKAGE_FILES", 1)
        (path.parent / "helper.py").write_text("VALUE = 1\n")
    elif limit == "bytes":
        monkeypatch.setattr(module, "MAX_PACKAGE_BYTES", path.stat().st_size - 1)
    elif limit == "entries":
        monkeypatch.setattr(module, "MAX_PACKAGE_ENTRIES", 1)
        (path.parent / "metadata.txt").write_text("extra entry")
    else:
        monkeypatch.setattr(module, "MAX_PACKAGE_DEPTH", 0)
        (path.parent / "helpers").mkdir()
    with pytest.raises(ExtractorRegistryError) as error:
        registry.freeze()
    assert error.value.code == "PACKAGE_LIMIT"


@pytest.mark.parametrize("target", ["file", "directory", "fifo"])
def test_package_inventory_rejects_links_and_nonregular_sources(fixture_handler, tmp_path, target):
    registry, handler, path = fixture_handler()
    register(registry, handler)
    if target == "file":
        outside = tmp_path / "outside.py"
        outside.write_text("PRIVATE_VALUE = 1\n")
        (path.parent / "helper.py").symlink_to(outside)
    elif target == "directory":
        (path.parent / "helpers").symlink_to(tmp_path, target_is_directory=True)
    else:
        os.mkfifo(path.parent / "helper.py")
    with pytest.raises(ExtractorRegistryError) as error:
        registry.freeze()
    assert error.value.code == "SOURCE_UNAVAILABLE"


def test_package_source_change_during_collection_is_rejected(fixture_handler, monkeypatch):
    registry, handler, path = fixture_handler()
    helper = path.parent / "helper.py"
    helper.write_text("VALUE = 1\n")
    register(registry, handler)
    original = module._source_hash

    def changing(source, cache, **kwargs):
        digest = original(source, cache, **kwargs)
        if source == helper:
            source.write_text("VALUE = 2000\n")
        return digest

    monkeypatch.setattr(module, "_source_hash", changing)
    with pytest.raises(ExtractorRegistryError) as error:
        registry.freeze()
    assert error.value.code == "SOURCE_UNAVAILABLE"


def run_fresh_process(code):
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stderr == b""
    return json.loads(result.stdout)


def test_static_bootstrap_runs_once_and_never_discovers_entrypoints_in_new_process():
    result = run_fresh_process('''
import importlib.metadata, json
from integrity_guard import trusted_extractors
from integrity_guard.extractor_registry import get_registry, lookup_extractor, registry_fingerprint
count = []
original = trusted_extractors.register_all
def bootstrap(registry):
    count.append(True)
    return original(registry)
def forbidden(*args, **kwargs):
    raise AssertionError("No automatic discovery")
trusted_extractors.register_all = bootstrap
importlib.metadata.entry_points = forbidden
first, second = get_registry(), get_registry()
unknown = [lookup_extractor(ext) for ext in ("xlsx", "pptx", "eml", "msg", "rtf", "odt")]
print(json.dumps({"same": first is second, "calls": len(count), "extractors": first.descriptors()["extractors"],
                  "unknown": unknown, "fingerprint": registry_fingerprint()}))
''')
    assert result["same"] is True and result["calls"] == 1
    assert result["extractors"] == [] and result["unknown"] == [None] * 6
    assert len(result["fingerprint"]) == 64


def test_failed_bootstrap_is_not_published_and_error_does_not_reflect_loader_text():
    result = run_fresh_process('''
import json
from integrity_guard import trusted_extractors
from integrity_guard.extractor_registry import get_registry, ExtractorRegistryError
original = trusted_extractors.register_all
def broken(registry):
    raise RuntimeError("Untrusted loader details")
trusted_extractors.register_all = broken
try:
    get_registry()
except ExtractorRegistryError as error:
    failure = {"code": error.code, "message": str(error)}
trusted_extractors.register_all = original
print(json.dumps({"failure": failure, "extractors": get_registry().descriptors()["extractors"]}))
''')
    assert result["failure"]["code"] == "BOOTSTRAP_FAILED"
    assert "Untrusted loader details" not in result["failure"]["message"]
    assert result["extractors"] == []


def test_fresh_process_manifest_matches_current_static_package():
    result = run_fresh_process('''
import json
from integrity_guard.extractor_registry import get_registry
print(json.dumps(get_registry().descriptors()))
''')
    assert result == ExtractorRegistry().freeze().descriptors()
