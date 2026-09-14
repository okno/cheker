import json
import sqlite3

from integrity_guard.core import GuardStore
from integrity_guard.reports import Reports, classify_report


def report(index=0, severity=None, category=None):
    findings = [{"severity": severity, "category": category, "rule_id": category}] if severity else []
    return {"id": f"report-{index}", "filename": f"file-{index}.txt", "created_at": f"2026-09-14T12:{index % 60:02}:00Z",
            "status": "ALLOWED" if not findings else "FLAGGED", "risk_score": 0 if not findings else 20,
            "sha256": f"{index:064x}", "findings": findings, "extraction": {"truncated": False}}


def test_verdicts_never_claim_uninspected_safe():
    assert classify_report(report()) == "VALID"
    assert classify_report(report(severity="HIGH", category="PROMPT_INJECTION")) == "INFECTED"
    assert classify_report(report(severity="LOW", category="PROMPT_HINT")) == "REVIEW_REQUIRED"
    corrupt = report(severity="CRITICAL", category="ANALYSIS_FAILURE")
    corrupt["findings"][0]["rule_id"] = "INVALID_PDF"
    assert classify_report(corrupt) == "CORRUPTED"
    corrupt["findings"][0]["rule_id"] = "OCR_REQUIRED"
    assert classify_report(corrupt) == "UNSCANNABLE"
    assert classify_report(dict(report(), analysis_complete=False)) == "UNSCANNABLE"


def test_registry_migrates_legacy_and_counts_beyond_first_page(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    db = sqlite3.connect(state / "scans.sqlite3")
    db.execute("CREATE TABLE scans(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,report TEXT NOT NULL)")
    for index in range(121):
        item = report(index)
        db.execute("INSERT INTO scans VALUES(?,?,?)", (item["id"], item["created_at"], json.dumps(item)))
    db.commit()
    db.close()
    store = GuardStore(state)
    registry = Reports(state, store)
    try:
        stats = registry.stats()
        assert stats["analyzed"] == stats["valid"] == stats["unique_files"] == 121
        assert len(registry.list()) == 100
        assert len(registry.list(offset=100)) == 21
        assert registry.stats(query="file-120")["matched"] == 1
        assert len(registry.list(query="file-120")) == 1
        assert registry.stats(query="%")["matched"] == 0  # literal, not SQL wildcard
        assert registry.list(verdict="INFECTED") == []
        failure = registry.record_failure("too-large.pdf", "/samples/too-large.pdf", "size limit", "INPUT_SIZE_LIMIT")
        assert failure["verdict"] == "UNSCANNABLE"
        assert registry.stats()["unscannable"] == 1
        assert registry.stats()["analyzed"] == 122
        assert registry.stats()["unique_files"] == 121
    finally:
        registry.close()
        store.close()
