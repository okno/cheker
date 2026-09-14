"""Inventory verification is read-only, batched, and consistent with snapshot denial."""
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from integrity_guard import core
from integrity_guard.api import create_app
from integrity_guard.core import ConflictError, GuardStore
from integrity_guard.monitor import Monitor


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "config_findings", lambda *args, **kwargs: [])
    guard = GuardStore(tmp_path / "state")
    yield guard
    guard.close()


def discovered(store, tmp_path, name="mcp.json", count=2):
    path = tmp_path / name
    path.write_text(json.dumps({"tools": {f"tool-{i}": {"name": f"Reader {i}", "description": "Read local notes"}
                                        for i in range(count)}}))
    return path, store.discover(path)


def approved(store, tmp_path):
    path, items = discovered(store, tmp_path)
    item = next(item for item in items if item["kind"] == "tool")
    return path, store.approve(item["id"], item["canonical_hash"], item["version"], "reviewer")


def saved_evidence(store):
    tables = {table: [tuple(row) for row in store._db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
              for table in ("components", "versions", "approvals", "audit", "settings")}
    return tables, store._checkpoint_path.read_bytes()


def assert_invalid(item):
    assert item["snapshot_valid"] is False
    assert item["source_valid"] is False
    assert item["state"] == "BLOCKED" and item["action"] == "BLOCK"
    assert item["approved_at"] is None and item["approved_by"] is None and item["approval_id"] is None
    assert item["content"] is None
    assert item["findings"][0]["rule_id"] == "SNAPSHOT_INTEGRITY_FAILED"
    for field in ("id", "name", "kind", "source_path", "raw_hash", "canonical_hash", "semantic_fingerprint", "updated_at"):
        assert isinstance(item[field], str)
    assert type(item["version"]) is int
    assert 0 <= item["version"] <= 2**53 - 1


@pytest.mark.parametrize("field,value", [
    ("content", "{}"), ("id", "other"), ("source_path", "elsewhere"), ("raw_hash", "changed"),
    ("canonical_hash", "changed"), ("semantic_fingerprint", "changed"), ("version", 12),
    ("name", "changed"), ("kind", "changed"), ("locator", '["tools","other"]'),
])
def test_invalid_snapshot_blocks_projection_and_gate_without_rewriting_evidence(store, tmp_path, field, value):
    _, item = approved(store, tmp_path)
    if field in {"content", "locator"}:
        store._db.execute(f"UPDATE components SET {field}=? WHERE id=?", (value, item["id"]))
    else:
        record = json.loads(store._row(item["id"])["record"])
        record[field] = value
        store._db.execute("UPDATE components SET record=? WHERE id=?", (json.dumps(record), item["id"]))
    store._db.commit()
    evidence = saved_evidence(store)
    for _ in range(2):
        assert_invalid(store.get_component(item["id"]))
        rows = store.list_components()
        assert_invalid(next(row for row in rows if row["id"] == item["id"]))
        assert all(row["snapshot_valid"] for row in rows if row["id"] != item["id"])
    assert not store.gate(item["id"])["allowed"]
    with pytest.raises(ConflictError):
        store.refresh(item["id"])
    assert saved_evidence(store) == evidence
    assert store.verify_audit()["valid"]


@pytest.mark.parametrize("record", ["{", "null", "[]", '{"version":true}',
    '{"id":{},"source_path":null,"name":[],"kind":{},"version":1e100,"canonical_hash":{},"raw_hash":[]}',
    '{"version":99999999999999999999999999999,"semantic_fingerprint":null}',
])
def test_malformed_record_projects_typed_safe_placeholder(store, tmp_path, record):
    _, item = approved(store, tmp_path)
    store._db.execute("UPDATE components SET record=? WHERE id=?", (record, item["id"]))
    store._db.commit()
    evidence = saved_evidence(store)
    assert_invalid(store.get_component(item["id"]))
    assert not store.gate(item["id"])["allowed"]
    assert saved_evidence(store) == evidence


@pytest.mark.parametrize("field,value", [
    ("state", {}), ("action", None), ("severity", []), ("approved_by", {}),
    ("approved_at", []), ("approval_id", False), ("updated_at", {}),
    ("previous_version", False), ("findings", {}), ("findings", [None]),
    ("findings", [{"rule_id": "test", "title": {}, "severity": "HIGH", "category": "INTEGRITY", "layer": "test", "evidence": "safe"}]),
    ("findings", [{"rule_id": "test", "title": "Test", "severity": "HIGH", "category": "INTEGRITY", "layer": "test", "evidence": "safe", "line": {}}]),
    ("findings", [{"rule_id": "test", "title": "Test", "severity": "HIGH", "category": "INTEGRITY", "layer": "test", "evidence": float("nan")}]),
    ("findings", [{"rule_id": "test", "title": "Test", "severity": "HIGH", "category": "INTEGRITY", "layer": "test", "evidence": "safe", "encoding": {}}]),
    ("changes", {}), ("changes", [None]),
    ("changes", [{"path": {}, "severity": "HIGH", "category": "INTEGRITY", "old": None, "new": None}]),
    ("source_error", {}), ("change_type", []),
])
def test_valid_fingerprints_with_malformed_display_fields_use_safe_placeholder(store, tmp_path, field, value):
    _, item = approved(store, tmp_path)
    record = json.loads(store._row(item["id"])["record"])
    record[field] = value
    store._db.execute("UPDATE components SET record=? WHERE id=?", (json.dumps(record), item["id"]))
    store._db.commit()
    evidence = saved_evidence(store)
    assert_invalid(store.get_component(item["id"]))
    assert_invalid(next(row for row in store.list_components() if row["id"] == item["id"]))
    assert saved_evidence(store) == evidence
    assert not store.gate(item["id"])["allowed"]


def test_projection_detects_invalid_snapshot_after_restart(store, tmp_path):
    _, item = approved(store, tmp_path)
    store._db.execute("UPDATE components SET content='{}' WHERE id=?", (item["id"],))
    store._db.commit()
    directory = store.data_dir
    store.close()
    reopened = GuardStore(directory)
    try:
        assert_invalid(reopened.get_component(item["id"]))
    finally:
        reopened.close()


def test_projection_does_not_read_source_or_call_gate(store, tmp_path, monkeypatch):
    path, item = approved(store, tmp_path)
    path.unlink()
    monkeypatch.setattr(core, "_source_snapshot", lambda *_: pytest.fail("Inventory read source"))
    monkeypatch.setattr(store, "gate", lambda *_: pytest.fail("Inventory called gate"))
    evidence = saved_evidence(store)
    assert store.get_component(item["id"])["snapshot_valid"] is True
    assert all(row["snapshot_valid"] for row in store.list_components())
    assert saved_evidence(store) == evidence


def test_stale_gate_request_does_not_invalidate_current_snapshot(store, tmp_path):
    _, item = approved(store, tmp_path)
    assert not store.gate(item["id"], "0" * 64, item["version"])["allowed"]
    current = store.get_component(item["id"])
    assert current["snapshot_valid"] is True and current["source_valid"] is True
    assert current["state"] == "APPROVED"
    assert store.gate(item["id"])["allowed"]


def test_unverifiable_audit_projects_all_snapshots_blocked(store, tmp_path):
    _, item = approved(store, tmp_path)
    store._checkpoint_path.write_text("{}")
    evidence = saved_evidence(store)
    for row in store.list_components():
        assert_invalid(row)
    assert_invalid(store.get_component(item["id"]))
    assert saved_evidence(store) == evidence


def test_evidence_change_during_projection_invalidates_entire_batch(store, tmp_path, monkeypatch):
    _, item = approved(store, tmp_path)
    original = store._snapshot_anchors

    def changed(ids):
        result = original(ids)
        store._db.execute("UPDATE components SET content='{}' WHERE id=?", (item["id"],))
        store._db.commit()
        return result

    monkeypatch.setattr(store, "_snapshot_anchors", changed)
    for row in store.list_components():
        assert_invalid(row)


@pytest.mark.parametrize("document", [
    {"tools": {"stable": {"name": "Displayed"}}},
    {"tools": [{"description": "Unnamed"}]},
    {"resources": [{"uri": "file:///notes"}]},
    {"prompts": [{"id": "prompt-id"}]},
    {"mcpServers": {"local": {"tools": {"stable": {"name": "Displayed"}}}}},
    {"servers": [{"name": "local", "prompts": [{"name": "Summary"}]}]},
    {"inputSchema": {}}, {"uri": "file:///notes"}, {"messages": []},
    [{"name": "Exported"}], {"plain": "configuration"},
])
def test_display_identity_derivation_matches_discovery(store, tmp_path, document):
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(document))
    items = store.discover(path)
    assert items and all(item["snapshot_valid"] for item in items)
    assert [(item["id"], item["name"], item["kind"]) for item in items] == [
        (item["id"], item["name"], item["kind"]) for item in core._components(document, str(path))]


@pytest.mark.parametrize("count", [1, 100])
def test_projection_and_rediscovery_scan_audit_in_batches(store, tmp_path, count):
    path, items = discovered(store, tmp_path, count=count)
    store.list_components()  # Populate the existing audit evidence cache.
    queries = []
    store._db.set_trace_callback(queries.append)
    try:
        assert len(store.list_components()) == count + 1
        scans = [query for query in queries if query == "SELECT document FROM audit ORDER BY sequence DESC"]
        assert len(scans) == 1
        queries.clear()
        assert len(store.discover(path)) == len(items)
        scans = [query for query in queries if query == "SELECT document FROM audit ORDER BY sequence DESC"]
        assert len(scans) == 2  # Existing version validation, then returned projection.
    finally:
        store._db.set_trace_callback(None)


def test_monitor_projects_inventory_once_for_all_due_sources():
    rows = [{"id": f"id-{source}-{item}", "source_path": source} for source in ("a", "b", "c") for item in range(3)]
    calls, refreshed = [], []
    fake = SimpleNamespace(source_paths=lambda: ["a", "b", "c"],
                           list_components=lambda: calls.append(1) or rows, refresh=refreshed.append)
    monitor = Monitor(fake)
    waits = iter((False, True))
    monitor._stop = SimpleNamespace(wait=lambda _: next(waits))
    monitor._sync_watches = lambda: None
    monitor._run()
    assert len(calls) == 1
    assert set(refreshed) == {"id-a-0", "id-b-0", "id-c-0"}


def test_api_gate_detail_list_and_counters_agree_after_snapshot_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "config_findings", lambda *args, **kwargs: [])
    monkeypatch.setattr("integrity_guard.linux_sandbox.probe_capabilities", lambda: {"available": True})
    token = "projection-test-" + "x" * 48
    app = create_app(tmp_path / "api-state", token=token, start_monitor=False)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": "Bearer " + token}) as client:
        store = app.state.store
        items = []
        for index in range(3):
            path = tmp_path / f"configuration-{index}.json"
            path.write_text(json.dumps({"project": f"sample-{index}"}))
            component = store.discover(path)[0]
            items.append(store.approve(component["id"], component["canonical_hash"], component["version"], "reviewer"))
        item = items[0]
        store._db.execute("UPDATE components SET content='{}' WHERE id=?", (item["id"],))
        store._db.commit()
        evidence = saved_evidence(store)
        assert client.post("/api/gate", json={"component_id": item["id"]}).json()["allowed"] is False
        assert_invalid(client.get(f"/api/components/{item['id']}").json())
        rows = client.get("/api/components").json()
        assert_invalid(next(row for row in rows if row["id"] == item["id"]))
        status = client.get("/api/status").json()
        assert status["components"] == len(rows) == 3
        assert status["approved"] == 2 and status["blocked"] == 1
        assert status["audit_valid"] is True
        assert saved_evidence(store) == evidence
